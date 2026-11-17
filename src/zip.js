import { Readable } from 'node:stream';
import fs from 'node:fs';

const UINT32_MAX = 0xffffffff;
const UINT16_MAX = 0xffff;
const crcTable = Uint32Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  return crc >>> 0;
});

function dosDateTime(timestamp) {
  const date = new Date(timestamp);
  const year = Math.max(1980, Math.min(2107, date.getUTCFullYear()));
  return {
    date: ((year - 1980) << 9) | ((date.getUTCMonth() + 1) << 5) | date.getUTCDate(),
    time: (date.getUTCHours() << 11) | (date.getUTCMinutes() << 5) | (date.getUTCSeconds() >> 1)
  };
}

function localHeader(name, modifiedAt, directory) {
  const header = Buffer.alloc(30 + name.length);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(directory ? 0x0800 : 0x0808, 6);
  header.writeUInt16LE(0, 8);
  const dateTime = dosDateTime(modifiedAt);
  header.writeUInt16LE(dateTime.time, 10);
  header.writeUInt16LE(dateTime.date, 12);
  header.writeUInt32LE(0, 14);
  header.writeUInt16LE(0, 18);
  header.writeUInt16LE(0, 22);
  header.writeUInt16LE(name.length, 26);
  name.copy(header, 30);
  return header;
}

function centralHeader(entry) {
  const header = Buffer.alloc(46 + entry.name.length);
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(20, 6);
  header.writeUInt16LE(entry.directory ? 0x0800 : 0x0808, 8);
  header.writeUInt16LE(0, 10);
  header.writeUInt16LE(entry.time, 12);
  header.writeUInt16LE(entry.date, 14);
  header.writeUInt32LE(entry.crc, 16);
  header.writeUInt32LE(entry.size, 20);
  header.writeUInt32LE(entry.size, 24);
  header.writeUInt16LE(entry.name.length, 28);
  header.writeUInt32LE(entry.directory ? 0x10 : 0, 38);
  header.writeUInt32LE(entry.offset, 42);
  entry.name.copy(header, 46);
  return header;
}

export function validateZipEntries(entries) {
  if (entries.length > UINT16_MAX) throw new RangeError('Folder contains too many items to archive');
  let estimatedSize = 22;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const size = entry.directory ? 0 : entry.size;
    if (name.length > UINT16_MAX || !Number.isSafeInteger(size) || size < 0 || size > UINT32_MAX) {
      throw new RangeError('Folder is too large to archive');
    }
    estimatedSize += (entry.directory ? 76 : 92) + 2 * name.length + size;
    if (estimatedSize > UINT32_MAX) throw new RangeError('Folder is too large to archive');
  }
}

async function* zipChunks(entries) {
  const centralEntries = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const directory = Boolean(entry.directory);
    const { date, time } = dosDateTime(entry.modifiedAt);
    const localOffset = offset;
    const header = localHeader(name, entry.modifiedAt, directory);
    offset += header.length;
    yield header;

    let crc = 0xffffffff;
    let size = 0;
    if (!directory) {
      for await (const chunk of fs.createReadStream(entry.filePath)) {
        size += chunk.length;
        if (size > UINT32_MAX) throw new RangeError('Folder is too large to archive');
        for (const byte of chunk) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
        offset += chunk.length;
        yield chunk;
      }
      if (size !== entry.size) throw new Error('A file changed while the folder was being archived');
      crc = (crc ^ 0xffffffff) >>> 0;
      const descriptor = Buffer.alloc(16);
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(crc, 4);
      descriptor.writeUInt32LE(size, 8);
      descriptor.writeUInt32LE(size, 12);
      offset += descriptor.length;
      yield descriptor;
    }

    centralEntries.push({ name, date, time, directory, crc, size, offset: localOffset });
  }

  const centralOffset = offset;
  for (const entry of centralEntries) {
    const header = centralHeader(entry);
    offset += header.length;
    yield header;
  }
  const centralSize = offset - centralOffset;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(centralEntries.length, 8);
  end.writeUInt16LE(centralEntries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(centralOffset, 16);
  yield end;
}

export function createZipStream(entries) {
  validateZipEntries(entries);
  return Readable.from(zipChunks(entries));
}
