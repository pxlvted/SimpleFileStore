import { parentPort, workerData } from 'node:worker_threads';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import yauzl from 'yauzl';
import { signatures } from './signatures.js';

const limits = workerData.limits;
let scannedBytes = 0;
const findings = [];
const maxPrefixSize = 32774;
const maxNestedArchiveDepth = 5;
let temporaryDirectory;
let temporaryFileSequence = 0;

function inspectChunk(chunk, state, countBytes = true) {
  if (countBytes) {
    scannedBytes += chunk.length;
    if (scannedBytes > limits.maxArchiveUncompressed + limits.maxScanFileSize) {
      throw new Error('Inspection byte limit exceeded');
    }
  }
  if (state.prefix.length < maxPrefixSize) {
    state.prefix = Buffer.concat([state.prefix, chunk.subarray(0, maxPrefixSize - state.prefix.length)]);
  }
  const combined = Buffer.concat([state.tail, chunk]);
  for (const signature of signatures) {
    if (combined.indexOf(signature.bytes) !== -1) {
      findings.push({ status: signature.severity, reason: signature.name });
    }
  }
  state.tail = combined.subarray(Math.max(0, combined.length - 128));
}

function inspectChunkedStream(stream) {
  return new Promise((resolve, reject) => {
    const state = { tail: Buffer.alloc(0), prefix: Buffer.alloc(0) };
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(state.prefix);
    };
    stream.on('data', (chunk) => {
      try {
        inspectChunk(chunk, state);
      } catch (error) {
        stream.destroy(error);
      }
    });
    stream.once('error', finish);
    stream.once('end', () => finish());
  });
}

function archiveTypeIsNested(prefix) {
  return ['zip', '7z', 'rar', 'gzip', 'bzip2', 'xz', 'tar', 'iso', 'cab', 'zstd', 'lz4']
    .includes(detectType(prefix));
}

function nestedArchiveTypeIsSupported(type) {
  return ['zip', 'gzip', 'tar', 'iso'].includes(type);
}

class ArchiveEntryInspector {
  constructor(fileName) {
    this.fileName = fileName;
    this.state = { tail: Buffer.alloc(0), prefix: Buffer.alloc(0) };
    this.pending = [];
    this.archiveType = null;
    this.filePath = null;
    this.fileHandle = null;
    this.fileOffset = 0;
  }

  async writeChunk(chunk) {
    let offset = 0;
    while (offset < chunk.length) {
      const { bytesWritten } = await this.fileHandle.write(
        chunk,
        offset,
        chunk.length - offset,
        this.fileOffset
      );
      if (bytesWritten === 0) throw new Error('Unable to write nested archive data');
      offset += bytesWritten;
      this.fileOffset += bytesWritten;
    }
  }

  async consume(chunk) {
    inspectChunk(chunk, this.state);
    if (this.fileHandle) {
      await this.writeChunk(chunk);
      return;
    }

    this.pending.push(chunk);
    if (!this.archiveType && archiveTypeIsNested(this.state.prefix)) {
      this.archiveType = detectType(this.state.prefix);
      if (!limits.nestedArchivesEnabled || !nestedArchiveTypeIsSupported(this.archiveType)) {
        throw new Error('Nested archives are not supported for safe inspection');
      }
      this.filePath = path.join(temporaryDirectory, `nested-${temporaryFileSequence++}`);
      this.fileHandle = await fs.promises.open(this.filePath, 'w');
      for (const bufferedChunk of this.pending) await this.writeChunk(bufferedChunk);
      this.pending = [];
    } else if (this.state.prefix.length >= maxPrefixSize) {
      this.pending = [];
    }
  }

  async finish() {
    if (this.fileHandle) {
      await this.fileHandle.close();
      this.fileHandle = null;
    }
    return {
      fileName: this.fileName,
      filePath: this.filePath,
      type: this.archiveType
    };
  }

  async abort() {
    if (this.fileHandle) {
      await this.fileHandle.close();
      this.fileHandle = null;
    }
    if (this.filePath) {
      await fs.promises.unlink(this.filePath).catch((error) => {
        if (error.code !== 'ENOENT') throw error;
      });
    }
  }
}

async function inspectArchiveEntryStream(stream, fileName) {
  const inspector = new ArchiveEntryInspector(fileName);
  try {
    for await (const chunk of stream) await inspector.consume(chunk);
    return await inspector.finish();
  } catch (error) {
    await inspector.abort();
    throw error;
  }
}

function openZip(filePath) {
  return new Promise((resolve, reject) => {
    yauzl.open(filePath, {
      lazyEntries: true,
      decodeStrings: true,
      validateEntrySizes: true,
      strictFileNames: true
    }, (error, zipfile) => error ? reject(error) : resolve(zipfile));
  });
}

function readZipEntry(zipfile, entry) {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (error, stream) => {
      if (error) return reject(error);
      inspectArchiveEntryStream(stream, entry.fileName).then(resolve, reject);
    });
  });
}

async function inspectZip(filePath, depth = 0) {
  const zipfile = await openZip(filePath);
  return new Promise((resolve, reject) => {
    let entries = 0;
    let totalSize = 0;
    let failed = false;
    const fail = (error) => {
      if (failed) return;
      failed = true;
      zipfile.close();
      reject(error);
    };
    zipfile.on('error', fail);
    zipfile.on('end', () => {
      if (!failed) resolve();
    });
    zipfile.on('entry', async (entry) => {
      if (failed) return;
      entries += 1;
      if (entries > limits.maxArchiveEntries) return fail(new Error('Archive entry count limit exceeded'));
      const fileName = entry.fileName.replace(/\\/g, '/');
      if (fileName.startsWith('/') || /^[a-zA-Z]:/.test(fileName) || fileName.split('/').includes('..')) {
        return fail(new Error('Unsafe archive path'));
      }
      const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
      if ((unixMode & 0o170000) === 0o120000) return fail(new Error('Archive contains a symbolic link'));
      if ((entry.generalPurposeBitFlag & 1) !== 0) return fail(new Error('Encrypted archive entries cannot be inspected'));
      const uncompressed = entry.uncompressedSize;
      const compressed = entry.compressedSize;
      totalSize += uncompressed;
      if (uncompressed > limits.maxArchiveEntry || totalSize > limits.maxArchiveUncompressed) {
        return fail(new Error('Archive expansion size limit exceeded'));
      }
      if (uncompressed > 0 && (compressed === 0 || uncompressed / compressed > limits.maxArchiveRatio)) {
        return fail(new Error('Archive compression ratio limit exceeded'));
      }
      if (fileName.endsWith('/')) {
        zipfile.readEntry();
        return;
      }
      try {
        const nestedEntry = await readZipEntry(zipfile, entry);
        await inspectNestedEntry(nestedEntry, depth);
        zipfile.readEntry();
      } catch (error) {
        fail(error);
      }
    });
    zipfile.readEntry();
  });
}

function isUnsafeArchivePath(fileName) {
  const normalized = fileName.replace(/\\/g, '/');
  return !normalized || normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized)
    || normalized.split('/').includes('..');
}

class StreamReader {
  constructor(stream, maxBytes) {
    this.iterator = stream[Symbol.asyncIterator]();
    this.maxBytes = maxBytes;
    this.totalReceived = 0;
    this.buffer = Buffer.alloc(0);
    this.bufferOffset = 0;
    this.ended = false;
  }

  async readChunk(maxLength) {
    const chunks = [];
    let length = 0;
    while (length < maxLength) {
      if (this.bufferOffset < this.buffer.length) {
        const take = Math.min(maxLength - length, this.buffer.length - this.bufferOffset);
        chunks.push(this.buffer.subarray(this.bufferOffset, this.bufferOffset + take));
        this.bufferOffset += take;
        length += take;
        continue;
      }
      if (this.ended) break;
      const next = await this.iterator.next();
      if (next.done) {
        this.ended = true;
        break;
      }
      this.buffer = Buffer.from(next.value);
      this.bufferOffset = 0;
      this.totalReceived += this.buffer.length;
      if (this.totalReceived > this.maxBytes) throw new Error('Archive expansion size limit exceeded');
    }
    if (length === 0) return null;
    return chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, length);
  }

  async readExact(length) {
    const chunks = [];
    let remaining = length;
    while (remaining > 0) {
      const chunk = await this.readChunk(remaining);
      if (!chunk) throw new Error('Truncated archive');
      chunks.push(chunk);
      remaining -= chunk.length;
    }
    return chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, length);
  }

  async consume(length, callback) {
    let remaining = length;
    while (remaining > 0) {
      const chunk = await this.readChunk(Math.min(64 * 1024, remaining));
      if (!chunk) throw new Error('Truncated archive');
      await callback(chunk);
      remaining -= chunk.length;
    }
  }

  async drainZeroPadding() {
    while (true) {
      const chunk = await this.readChunk(64 * 1024);
      if (!chunk) return;
      if (chunk.some((byte) => byte !== 0)) throw new Error('Invalid data after TAR end marker');
    }
  }
}

function parseTarNumber(field) {
  if (field[0] & 0x80) throw new Error('Unsupported TAR numeric encoding');
  const value = field.toString('ascii').replace(/\0.*$/, '').trim();
  if (!value) return 0;
  if (!/^[0-7]+$/.test(value)) throw new Error('Invalid TAR numeric field');
  const number = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(number)) throw new Error('Invalid TAR numeric field');
  return number;
}

function tarString(field) {
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? field.length : end).toString('utf8');
}

function parsePaxRecords(buffer) {
  const records = {};
  let offset = 0;
  while (offset < buffer.length) {
    const space = buffer.indexOf(0x20, offset);
    if (space === -1) throw new Error('Invalid TAR extended header');
    const recordLength = Number.parseInt(buffer.subarray(offset, space).toString('ascii'), 10);
    if (!Number.isInteger(recordLength) || recordLength <= space - offset + 1
      || offset + recordLength > buffer.length || buffer[offset + recordLength - 1] !== 0x0a) {
      throw new Error('Invalid TAR extended header');
    }
    const record = buffer.subarray(space + 1, offset + recordLength - 1).toString('utf8');
    const separator = record.indexOf('=');
    if (separator <= 0) throw new Error('Invalid TAR extended header');
    records[record.slice(0, separator)] = record.slice(separator + 1);
    offset += recordLength;
  }
  return records;
}

function verifyTarHeader(header) {
  const expected = parseTarNumber(header.subarray(148, 156));
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (actual !== expected) throw new Error('Invalid TAR header checksum');
}

async function inspectTar(stream, compressedSize = null, depth = 0) {
  const maxArchiveBytes = limits.maxArchiveUncompressed + limits.maxArchiveEntries * 1024 + 1024;
  const reader = new StreamReader(stream, maxArchiveBytes);
  let entries = 0;
  let totalSize = 0;
  let longName = null;
  let localPax = {};
  let globalPax = {};
  let sawHeader = false;
  let sawEnd = false;
  while (true) {
    const header = await reader.readChunk(512);
    if (!header) break;
    if (header.length !== 512) throw new Error('Truncated TAR header');
    if (header.every((byte) => byte === 0)) {
      await reader.drainZeroPadding();
      sawEnd = true;
      break;
    }
    verifyTarHeader(header);
    sawHeader = true;
    entries += 1;
    if (entries > limits.maxArchiveEntries) throw new Error('Archive entry count limit exceeded');

    const rawName = tarString(header.subarray(0, 100));
    const prefix = tarString(header.subarray(345, 500));
    let fileName = prefix ? `${prefix}/${rawName}` : rawName;
    const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    const headerSize = parseTarNumber(header.subarray(124, 136));
    const attributes = { ...globalPax, ...localPax };
    if (attributes.path !== undefined) fileName = attributes.path;
    if (attributes.size !== undefined
      && (!/^\d+$/.test(attributes.size) || !Number.isSafeInteger(Number(attributes.size)))) {
      throw new Error('Invalid TAR extended header size');
    }
    const size = attributes.size === undefined ? headerSize : Number(attributes.size);
    localPax = {};

    if (type === 'x' || type === 'g' || type === 'L' || type === 'K') {
      if (size > Math.min(limits.maxArchiveEntry, 1024 * 1024)) {
        throw new Error('TAR metadata entry is too large');
      }
      const metadata = await reader.readExact(size);
      await reader.readExact((512 - (size % 512)) % 512);
      if (type === 'x') localPax = parsePaxRecords(metadata);
      else if (type === 'g') globalPax = { ...globalPax, ...parsePaxRecords(metadata) };
      else if (type === 'L') longName = tarString(metadata);
      else if (type === 'K') throw new Error('TAR hard links are not supported');
      continue;
    }
    if (longName !== null) {
      fileName = longName;
      longName = null;
    }
    if (isUnsafeArchivePath(fileName)) throw new Error(`Unsafe archive path: ${fileName}`);
    if (size > limits.maxArchiveEntry) throw new Error('Archive entry size limit exceeded');
    totalSize += size;
    if (totalSize > limits.maxArchiveUncompressed) throw new Error('Archive expansion size limit exceeded');
    if (compressedSize !== null && totalSize > 0
      && (compressedSize === 0 || totalSize / compressedSize > limits.maxArchiveRatio)) {
      throw new Error('Archive compression ratio limit exceeded');
    }

    if (type === '1' || type === '2') throw new Error('TAR links are not supported');
    if (type !== '0' && type !== '7' && type !== '5') throw new Error('Unsupported TAR entry type');
    if (type === '5' && size !== 0) throw new Error('Invalid TAR directory entry');
    if (type === '0' || type === '7') {
      const inspector = new ArchiveEntryInspector(fileName);
      let nestedEntry;
      try {
        await reader.consume(size, (chunk) => inspector.consume(chunk));
        nestedEntry = await inspector.finish();
      } catch (error) {
        await inspector.abort();
        throw error;
      }
      await inspectNestedEntry(nestedEntry, depth);
    } else {
      await reader.readExact(size);
    }
    await reader.readExact((512 - (size % 512)) % 512);
  }
  if (!sawHeader && !sawEnd) throw new Error('Invalid TAR archive');
  if (compressedSize !== null && totalSize > 0
    && (compressedSize === 0 || totalSize / compressedSize > limits.maxArchiveRatio)) {
    throw new Error('Archive compression ratio limit exceeded');
  }
}

async function readAt(handle, position, length) {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(buffer, offset, length - offset, position + offset);
    if (bytesRead === 0) throw new Error('Truncated ISO archive');
    offset += bytesRead;
  }
  return buffer;
}

function bothEndian32(buffer, offset) {
  const little = buffer.readUInt32LE(offset);
  const big = buffer.readUInt32BE(offset + 4);
  if (little !== big) throw new Error('Invalid ISO archive field');
  return little;
}

function bothEndian16(buffer, offset) {
  const little = buffer.readUInt16LE(offset);
  const big = buffer.readUInt16BE(offset + 2);
  if (little !== big) throw new Error('Invalid ISO archive field');
  return little;
}

function isoName(buffer, joliet) {
  if (buffer.length === 1 && (buffer[0] === 0 || buffer[0] === 1)) return null;
  if (joliet) {
    if (buffer.length % 2 !== 0) throw new Error('Invalid ISO Joliet filename');
    let name = '';
    for (let offset = 0; offset < buffer.length; offset += 2) {
      name += String.fromCharCode(buffer.readUInt16BE(offset));
    }
    return name.replace(/;\d+$/, '').replace(/\.$/, '');
  }
  return buffer.toString('ascii').replace(/;\d+$/, '').replace(/\.$/, '');
}

function validateIsoSystemUse(record, nameLength) {
  const start = 33 + nameLength + (nameLength % 2 === 0 ? 1 : 0);
  for (let offset = start; offset + 4 <= record.length;) {
    const signature = record.toString('ascii', offset, offset + 2);
    if (signature === '\0\0') return;
    const length = record[offset + 2];
    if (length < 4 || offset + length > record.length) throw new Error('Invalid ISO system-use entry');
    if (signature === 'SL' || signature === 'CE') throw new Error('ISO symbolic links are not supported');
    if (signature === 'PX' && length >= 12) {
      const mode = record.readUInt32LE(offset + 4);
      if ((mode & 0xf000) === 0xa000) throw new Error('ISO symbolic links are not supported');
    }
    offset += length;
  }
}

async function inspectIso(filePath, fileSize, depth = 0) {
  const handle = await fs.promises.open(filePath, 'r');
  try {
    let primary = null;
    let joliet = null;
    let terminated = false;
    for (let sector = 16; sector < 80; sector += 1) {
      const descriptor = await readAt(handle, sector * 2048, 2048);
      if (descriptor.toString('ascii', 1, 6) !== 'CD001' || descriptor[6] !== 1) {
        throw new Error('Invalid ISO volume descriptor');
      }
      if (descriptor[0] === 255) {
        terminated = true;
        break;
      }
      if (descriptor[0] === 1 && !primary) primary = descriptor;
      if (descriptor[0] === 2 && descriptor[88] === 0x25 && descriptor[89] === 0x2f
        && [0x40, 0x43, 0x45].includes(descriptor[90]) && !joliet) {
        joliet = descriptor;
      }
    }
    if (!terminated || (!primary && !joliet)) throw new Error('Unsupported ISO archive');
    const descriptor = joliet || primary;
    const volumeSectors = bothEndian32(descriptor, 80);
    const volumeBytes = volumeSectors * 2048;
    if (!Number.isSafeInteger(volumeBytes) || volumeBytes > fileSize || volumeBytes < 18 * 2048) {
      throw new Error('Invalid ISO volume size');
    }
    if (bothEndian16(descriptor, 128) !== 2048) throw new Error('Unsupported ISO block size');
    const rootLength = descriptor[156];
    if (rootLength < 34 || 156 + rootLength > descriptor.length) throw new Error('Invalid ISO root directory');
    const rootRecord = descriptor.subarray(156, 156 + rootLength);
    const rootExtent = bothEndian32(rootRecord, 2);
    const rootSize = bothEndian32(rootRecord, 10);
    const directories = [{ extent: rootExtent, size: rootSize, name: '' }];
    const visited = new Set();
    let entries = 0;
    let totalSize = 0;
    while (directories.length) {
      const directory = directories.pop();
      const key = `${directory.extent}:${directory.size}`;
      if (visited.has(key)) throw new Error('ISO directory cycle detected');
      visited.add(key);
      if (directory.size > limits.maxArchiveEntry) throw new Error('ISO directory size limit exceeded');
      const start = directory.extent * 2048;
      if (!Number.isSafeInteger(start) || start + directory.size > volumeBytes) throw new Error('Invalid ISO directory extent');
      const data = await readAt(handle, start, directory.size);
      let offset = 0;
      while (offset < data.length) {
        const recordLength = data[offset];
        if (recordLength === 0) {
          offset = Math.min(data.length, Math.ceil((offset + 1) / 2048) * 2048);
          continue;
        }
        if (recordLength < 34 || offset + recordLength > data.length) throw new Error('Invalid ISO directory record');
        const record = data.subarray(offset, offset + recordLength);
        const nameLength = record[32];
        if (33 + nameLength > record.length) throw new Error('Invalid ISO filename');
        validateIsoSystemUse(record, nameLength);
        const name = isoName(record.subarray(33, 33 + nameLength), Boolean(joliet));
        if (name !== null) {
          entries += 1;
          if (entries > limits.maxArchiveEntries) throw new Error('Archive entry count limit exceeded');
          if (!name || name.includes('/') || isUnsafeArchivePath(name)) {
            throw new Error(`Unsafe archive path: ${name}`);
          }
          const flags = record[25];
          if (flags & 0x80) throw new Error('ISO multi-extent files are not supported');
          const extent = bothEndian32(record, 2);
          const size = bothEndian32(record, 10);
          if (size > limits.maxArchiveEntry) throw new Error('Archive entry size limit exceeded');
          const dataStart = extent * 2048;
          if (!Number.isSafeInteger(dataStart) || dataStart + size > volumeBytes) {
            throw new Error('Invalid ISO file extent');
          }
          const entryPath = directory.name ? `${directory.name}/${name}` : name;
          if (flags & 0x02) {
            directories.push({ extent, size, name: entryPath });
          } else {
            totalSize += size;
            if (totalSize > limits.maxArchiveUncompressed) throw new Error('Archive expansion size limit exceeded');
            const inspector = new ArchiveEntryInspector(entryPath);
            let nestedEntry;
            try {
              for (let position = 0; position < size; position += 64 * 1024) {
                const chunk = await readAt(handle, dataStart + position, Math.min(64 * 1024, size - position));
                await inspector.consume(chunk);
              }
              nestedEntry = await inspector.finish();
            } catch (error) {
              await inspector.abort();
              throw error;
            }
            await inspectNestedEntry(nestedEntry, depth);
          }
        }
        offset += recordLength;
      }
    }
  } finally {
    await handle.close();
  }
}

function detectType(prefix) {
  if (prefix.length >= 2 && prefix[0] === 0x4d && prefix[1] === 0x5a) return 'executable';
  if (prefix.length >= 4 && prefix.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) return 'zip';
  if (prefix.length >= 4 && prefix.subarray(0, 4).equals(Buffer.from([0x25, 0x50, 0x44, 0x46]))) return 'pdf';
  if (prefix.length >= 8 && prefix.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (prefix.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]))) return '7z';
  if (prefix.subarray(0, 4).toString('ascii') === 'Rar!') return 'rar';
  if (prefix.subarray(0, 4).toString('ascii') === 'MSCF') return 'cab';
  if (prefix.subarray(0, 2).equals(Buffer.from([0x1f, 0x8b]))) return 'gzip';
  if (prefix.subarray(0, 3).toString('ascii') === 'BZh') return 'bzip2';
  if (prefix.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]))) return 'xz';
  if (prefix.subarray(0, 4).equals(Buffer.from([0x28, 0xb5, 0x2f, 0xfd]))) return 'zstd';
  if (prefix.subarray(0, 4).equals(Buffer.from([0x04, 0x22, 0x4d, 0x18]))) return 'lz4';
  if (prefix.length >= maxPrefixSize && [1, 2].includes(prefix[32768])
    && prefix.subarray(32769, 32774).toString('ascii') === 'CD001') return 'iso';
  if (prefix.length >= 262 && prefix.subarray(257, 262).toString('ascii') === 'ustar') return 'tar';
  return 'unknown';
}

async function inspectNestedArchive(filePath, type, depth) {
  if (depth > maxNestedArchiveDepth) throw new Error('Nested archive depth limit exceeded');
  const stat = await fs.promises.stat(filePath);
  if (type === 'zip') {
    await inspectZip(filePath, depth);
  } else if (type === 'tar') {
    await inspectTar(fs.createReadStream(filePath), null, depth);
  } else if (type === 'iso') {
    await inspectIso(filePath, stat.size, depth);
  } else if (type === 'gzip') {
    const archiveStream = fs.createReadStream(filePath);
    await inspectTar(archiveStream.pipe(zlib.createGunzip()), stat.size, depth);
  } else {
    throw new Error('Nested archives are not supported for safe inspection');
  }
}

async function inspectNestedEntry(entry, depth) {
  if (!entry.filePath) return;
  try {
    await inspectNestedArchive(entry.filePath, entry.type, depth + 1);
  } finally {
    await fs.promises.unlink(entry.filePath);
  }
}

async function main() {
  const stat = await fs.promises.stat(workerData.filePath);
  if (!stat.isFile() || stat.size > limits.maxScanFileSize) {
    return { status: 'UNSCANNABLE', reason: 'File exceeds the configured scan limit' };
  }
  temporaryDirectory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'simple-file-store-scan-'));
  try {
    return await scanFile(stat);
  } finally {
    await fs.promises.rm(temporaryDirectory, { recursive: true, force: true });
    temporaryDirectory = undefined;
  }
}

async function scanFile(stat) {
  const stream = fs.createReadStream(workerData.filePath, { highWaterMark: 64 * 1024 });
  const prefix = await inspectChunkedStream(stream);
  const type = detectType(prefix);
  const extension = path.extname(workerData.fileName).toLowerCase();
  if (type === 'executable' && !['.exe', '.dll', '.com', '.scr', '.msi'].includes(extension)) {
    findings.push({ status: 'SUSPICIOUS', reason: 'Executable content does not match the filename extension' });
  }
  const isZipByName = extension === '.zip';
  if (type === 'zip' || isZipByName) {
    if (type !== 'zip') return { status: 'UNSCANNABLE', reason: 'ZIP extension does not contain a supported ZIP archive' };
    try {
      await inspectZip(workerData.filePath);
    } catch (error) {
      return { status: 'UNSCANNABLE', reason: error.message || 'Archive could not be inspected' };
    }
  } else if (type === 'iso' || extension === '.iso') {
    if (type !== 'iso') return { status: 'UNSCANNABLE', reason: 'ISO extension does not contain a supported ISO image' };
    try {
      await inspectIso(workerData.filePath, stat.size);
    } catch (error) {
      return { status: 'UNSCANNABLE', reason: error.message || 'ISO archive could not be inspected' };
    }
  } else if (type === 'tar' || extension === '.tar' || workerData.fileName.toLowerCase().endsWith('.tar.gz')) {
    const isTarGzip = workerData.fileName.toLowerCase().endsWith('.tar.gz');
    if (isTarGzip && type !== 'gzip') {
      return { status: 'UNSCANNABLE', reason: 'TAR.GZ extension does not contain a supported gzip archive' };
    }
    if (!isTarGzip && type === 'gzip') {
      return { status: 'UNSCANNABLE', reason: 'Gzip files are supported only when they contain a TAR archive' };
    }
    try {
      const archiveStream = fs.createReadStream(workerData.filePath);
      await inspectTar(isTarGzip ? archiveStream.pipe(zlib.createGunzip()) : archiveStream, isTarGzip ? stat.size : null);
    } catch (error) {
      return { status: 'UNSCANNABLE', reason: error.message || 'TAR archive could not be inspected' };
    }
  } else if (['7z', 'rar', 'gzip', 'bzip2', 'xz', 'tar', 'cab', 'zstd', 'lz4'].includes(type)
    || ['.7z', '.rar', '.gz', '.tgz', '.bz2', '.xz', '.cab', '.arj', '.ace', '.zst', '.lz4', '.lzh', '.deb']
      .includes(extension)) {
    return { status: 'UNSCANNABLE', reason: 'This archive format is not supported for safe inspection' };
  }
  if (findings.some((finding) => finding.status === 'INFECTED')) {
    return { status: 'INFECTED', reason: findings.find((finding) => finding.status === 'INFECTED').reason };
  }
  if (findings.length) return { status: 'SUSPICIOUS', reason: findings[0].reason };
  return { status: 'SCAN_PASSED', reason: 'No configured suspicious patterns or blocking conditions were found' };
}

main().then((result) => parentPort.postMessage(result)).catch((error) => {
  parentPort.postMessage({ status: 'SCAN_FAILED', reason: error.message || 'Scanner failed' });
});
