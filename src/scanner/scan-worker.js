import { parentPort, workerData } from 'node:worker_threads';
import fs from 'node:fs';
import path from 'node:path';
import yauzl from 'yauzl';
import { signatures } from './signatures.js';

const limits = workerData.limits;
let scannedBytes = 0;
const findings = [];

function inspectChunkedStream(stream) {
  return new Promise((resolve, reject) => {
    let tail = Buffer.alloc(0);
    let prefix = Buffer.alloc(0);
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(prefix);
    };
    stream.on('data', (chunk) => {
      scannedBytes += chunk.length;
      if (scannedBytes > limits.maxArchiveUncompressed + limits.maxScanFileSize) {
        stream.destroy(new Error('Inspection byte limit exceeded'));
        return;
      }
      if (prefix.length < 512) prefix = Buffer.concat([prefix, chunk.subarray(0, 512 - prefix.length)]);
      const combined = Buffer.concat([tail, chunk]);
      for (const signature of signatures) {
        if (combined.indexOf(signature.bytes) !== -1) {
          findings.push({ status: signature.severity, reason: signature.name });
        }
      }
      tail = combined.subarray(Math.max(0, combined.length - 128));
    });
    stream.once('error', finish);
    stream.once('end', () => finish());
  });
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
      inspectChunkedStream(stream).then(resolve, reject);
    });
  });
}

async function inspectZip(filePath) {
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
        const prefix = await readZipEntry(zipfile, entry);
        if (['zip', '7z', 'rar', 'gzip', 'bzip2', 'xz', 'tar', 'cab', 'zstd', 'lz4'].includes(detectType(prefix))) {
          throw new Error('Nested archives are not supported for safe inspection');
        }
        zipfile.readEntry();
      } catch (error) {
        fail(error);
      }
    });
    zipfile.readEntry();
  });
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
  if (prefix.length >= 262 && prefix.subarray(257, 262).toString('ascii') === 'ustar') return 'tar';
  return 'unknown';
}

async function main() {
  const stat = await fs.promises.stat(workerData.filePath);
  if (!stat.isFile() || stat.size > limits.maxScanFileSize) {
    return { status: 'UNSCANNABLE', reason: 'File exceeds the configured scan limit' };
  }
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
  } else if (['7z', 'rar', 'gzip', 'bzip2', 'xz', 'tar', 'cab', 'zstd', 'lz4'].includes(type)
    || ['.7z', '.rar', '.gz', '.tgz', '.tar', '.bz2', '.xz', '.cab', '.iso', '.arj', '.ace', '.zst', '.lz4', '.lzh', '.deb']
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
