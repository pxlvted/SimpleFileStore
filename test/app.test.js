import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import zlib from 'node:zlib';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let child;
let baseUrl;
let dataDirectory;
let serverOutput = '';

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZip(name, content) {
  const fileName = Buffer.from(name);
  const uncompressed = Buffer.from(content);
  const compressed = zlib.deflateRawSync(uncompressed);
  const checksum = crc32(uncompressed);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(checksum, 14);
  local.writeUInt32LE(compressed.length, 18);
  local.writeUInt32LE(uncompressed.length, 22);
  local.writeUInt16LE(fileName.length, 26);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(checksum, 16);
  central.writeUInt32LE(compressed.length, 20);
  central.writeUInt32LE(uncompressed.length, 24);
  central.writeUInt16LE(fileName.length, 28);
  const localRecord = Buffer.concat([local, fileName, compressed]);
  const centralRecord = Buffer.concat([central, fileName]);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralRecord.length, 12);
  end.writeUInt32LE(localRecord.length, 16);
  return Buffer.concat([localRecord, centralRecord, end]);
}

function makeTar(name, content) {
  const fileName = Buffer.from(name);
  const data = Buffer.from(content);
  const header = Buffer.alloc(512);
  fileName.copy(header, 0, 0, 100);
  header.write('0000644\0', 100, 'ascii');
  header.write('0000000\0', 108, 'ascii');
  header.write('0000000\0', 116, 'ascii');
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
  header.write('00000000000\0', 136, 'ascii');
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.write('ustar\0', 257, 'ascii');
  header.write('00', 263, 'ascii');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return Buffer.concat([header, data, Buffer.alloc((512 - (data.length % 512)) % 512), Buffer.alloc(1024)]);
}

function makeIso(name, content) {
  const data = Buffer.from(content);
  const image = Buffer.alloc(22 * 2048);
  function writeBothEndian32(buffer, offset, value) {
    buffer.writeUInt32LE(value, offset);
    buffer.writeUInt32BE(value, offset + 4);
  }
  function record(nameBytes, extent, size, directory = false) {
    const length = 33 + nameBytes.length + (nameBytes.length % 2 === 0 ? 1 : 0);
    const result = Buffer.alloc(length);
    result[0] = length;
    writeBothEndian32(result, 2, extent);
    writeBothEndian32(result, 10, size);
    result[25] = directory ? 2 : 0;
    result.writeUInt16LE(1, 28);
    result.writeUInt16BE(1, 30);
    result[32] = nameBytes.length;
    nameBytes.copy(result, 33);
    return result;
  }

  const primary = image.subarray(16 * 2048, 17 * 2048);
  primary[0] = 1;
  primary.write('CD001', 1, 'ascii');
  primary[6] = 1;
  writeBothEndian32(primary, 80, 22);
  primary.writeUInt16LE(2048, 128);
  primary.writeUInt16BE(2048, 130);
  record(Buffer.from([0]), 20, 2048, true).copy(primary, 156);

  const terminator = image.subarray(17 * 2048, 18 * 2048);
  terminator[0] = 255;
  terminator.write('CD001', 1, 'ascii');
  terminator[6] = 1;

  const fileName = Buffer.from(`${name};1`, 'ascii');
  const directory = Buffer.concat([
    record(Buffer.from([0]), 20, 2048, true),
    record(Buffer.from([1]), 20, 2048, true),
    record(fileName, 21, data.length)
  ]);
  directory.copy(image, 20 * 2048);
  data.copy(image, 21 * 2048);
  return image;
}

async function unusedPort() {
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, '127.0.0.1', resolve));
  const { port } = listener.address();
  await new Promise((resolve) => listener.close(resolve));
  return port;
}

async function waitForServer() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Test server exited with ${child.exitCode}`);
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) return;
    } catch { }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Test server did not start in time');
}

function request(pathname, options = {}, session) {
  const headers = new Headers(options.headers || {});
  if (typeof options.body === 'string' && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (session?.cookie) headers.set('Cookie', session.cookie);
  if (options.method && options.method !== 'GET' && session?.csrf) headers.set('X-CSRF-Token', session.csrf);
  return fetch(`${baseUrl}${pathname}`, { ...options, headers });
}

async function json(response) {
  return response.json();
}

async function createSession(username) {
  const password = 'correct horse battery staple';
  const registration = await request('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  assert.equal(registration.status, 201);
  const login = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  assert.equal(login.status, 200);
  const result = await json(login);
  return { cookie: login.headers.get('set-cookie').split(';')[0], csrf: result.csrfToken };
}

async function waitForStatus(session, fileId, expected, folderId = null) {
  let lastStatus = 'not listed';
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const route = folderId ? `/api/files?folderId=${encodeURIComponent(folderId)}` : '/api/files';
    const response = await request(route, {}, session);
    const files = await json(response);
    const found = files.files.find((entry) => entry.id === fileId);
    if (found?.status === expected) return found;
    if (found) lastStatus = found.status;
    if (found && ['SCAN_FAILED', 'UNSCANNABLE', 'SUSPICIOUS', 'INFECTED'].includes(found.status)
      && found.status !== expected) {
      throw new Error(`Expected ${expected}, got ${found.status}: ${found.detection}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`File did not reach ${expected}; last status ${lastStatus}\n${serverOutput}`);
}

before(async () => {
  dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'simple-file-store-test-'));
  const port = await unusedPort();
  baseUrl = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['src/server.js'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      PORT: String(port),
      HOST: '127.0.0.1',
      DATA_DIRECTORY: dataDirectory,
      SESSION_SECRET: crypto.randomBytes(48).toString('hex'),
      WHITELISTFEATURE: 'TRUE',
      WHITELIST: 'alice,bob',
      COOKIE_SECURE: 'false',
      MAX_FILE_SIZE_MB: '2',
      MAX_STORAGE_MB: '1',
      MAX_GLOBAL_STAGING_MB: '8',
      MAX_SCAN_FILE_SIZE_MB: '2',
      MAX_ARCHIVE_UNCOMPRESSED_MB: '4',
      MAX_ARCHIVE_ENTRY_MB: '2'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', (chunk) => { serverOutput += chunk.toString(); });
  child.stderr.on('data', (chunk) => { serverOutput += chunk.toString(); });
  await waitForServer();
});

after(async () => {
  if (child && child.exitCode === null) {
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
  }
  if (dataDirectory) await fs.rm(dataDirectory, { recursive: true, force: true });
});

test('authentication, isolated storage, scanning, editing, and quarantine', { timeout: 60000 }, async () => {
  const denied = await request('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'mallory', password: 'correct horse battery staple' })
  });
  assert.equal(denied.status, 403);

  const alice = await createSession('alice');
  const csrfRejected = await request('/api/folders', {
    method: 'POST',
    body: JSON.stringify({ name: 'No token' })
  }, { cookie: alice.cookie });
  assert.equal(csrfRejected.status, 403);
  const folderResponse = await request('/api/folders', {
    method: 'POST',
    body: JSON.stringify({ name: 'Documents' })
  }, alice);
  assert.equal(folderResponse.status, 201);
  const folder = await json(folderResponse);

  const form = new FormData();
  form.append('folderId', folder.id);
  form.append('file', new Blob(['first version'], { type: 'text/plain' }), 'notes.txt');
  const uploadResponse = await request('/api/upload', { method: 'POST', body: form }, alice);
  assert.equal(uploadResponse.status, 202);
  const uploaded = await json(uploadResponse);
  const passedFile = await waitForStatus(alice, uploaded.id, 'SCAN_PASSED', folder.id);
  assert.equal(passedFile.folderId, folder.id);

  const uploadedDirectoryResponse = await request('/api/folders', {
    method: 'POST',
    body: JSON.stringify({ name: 'Photos', parentId: folder.id })
  }, alice);
  assert.equal(uploadedDirectoryResponse.status, 201);
  const uploadedDirectory = await json(uploadedDirectoryResponse);
  const nestedUploadForm = new FormData();
  nestedUploadForm.append('folderId', uploadedDirectory.id);
  nestedUploadForm.append('file', new Blob(['nested file']), 'photo.txt');
  const nestedUploadResponse = await request('/api/upload', { method: 'POST', body: nestedUploadForm }, alice);
  assert.equal(nestedUploadResponse.status, 202);
  const nestedUpload = await json(nestedUploadResponse);
  const nestedPassedFile = await waitForStatus(alice, nestedUpload.id, 'SCAN_PASSED', uploadedDirectory.id);
  assert.equal(nestedPassedFile.folderId, uploadedDirectory.id);

  const download = await request(`/api/files/${uploaded.id}/download`, {}, alice);
  assert.equal(download.status, 200);
  assert.equal(await download.text(), 'first version');

  const edit = await request(`/api/files/${uploaded.id}/content`, {
    method: 'PUT',
    body: JSON.stringify({ content: 'edited version' })
  }, alice);
  assert.equal(edit.status, 202);
  await waitForStatus(alice, uploaded.id, 'SCAN_PASSED', folder.id);
  const editedDownload = await request(`/api/files/${uploaded.id}/download`, {}, alice);
  assert.equal(await editedDownload.text(), 'edited version');

  const eicar = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
  const boundarySample = Buffer.concat([Buffer.alloc(64 * 1024 - 10, 0x41), eicar]);
  const infectedForm = new FormData();
  infectedForm.append('file', new Blob([boundarySample]), 'sample.txt');
  const infectedUpload = await request('/api/upload', { method: 'POST', body: infectedForm }, alice);
  assert.equal(infectedUpload.status, 202);
  const infected = await json(infectedUpload);
  const infectedFile = await waitForStatus(alice, infected.id, 'INFECTED');
  assert.match(infectedFile.detection, /EICAR/);
  const blockedDownload = await request(`/api/files/${infected.id}/download`, {}, alice);
  assert.equal(blockedDownload.status, 404);

  const safeZipForm = new FormData();
  safeZipForm.append('file', new Blob([makeZip('inside.txt', 'safe archive content')]), 'archive.zip');
  const safeZipUpload = await request('/api/upload', { method: 'POST', body: safeZipForm }, alice);
  assert.equal(safeZipUpload.status, 202);
  const safeZip = await json(safeZipUpload);
  await waitForStatus(alice, safeZip.id, 'SCAN_PASSED');

  const safeTarForm = new FormData();
  safeTarForm.append('file', new Blob([makeTar('inside.txt', 'safe TAR content')]), 'archive.tar');
  const safeTarUpload = await request('/api/upload', { method: 'POST', body: safeTarForm }, alice);
  assert.equal(safeTarUpload.status, 202);
  await waitForStatus(alice, (await json(safeTarUpload)).id, 'SCAN_PASSED');

  const unsafeTarForm = new FormData();
  unsafeTarForm.append('file', new Blob([makeTar('../outside.txt', 'unsafe TAR path')]), 'unsafe.tar');
  const unsafeTarUpload = await request('/api/upload', { method: 'POST', body: unsafeTarForm }, alice);
  assert.equal(unsafeTarUpload.status, 202);
  const unsafeTar = await waitForStatus(alice, (await json(unsafeTarUpload)).id, 'UNSCANNABLE');
  assert.match(unsafeTar.detection, /outside\.txt/);

  const safeTarGzipForm = new FormData();
  safeTarGzipForm.append('file', new Blob([zlib.gzipSync(makeTar('inside.txt', 'safe TAR.GZ content'))]), 'archive.tar.gz');
  const safeTarGzipUpload = await request('/api/upload', { method: 'POST', body: safeTarGzipForm }, alice);
  assert.equal(safeTarGzipUpload.status, 202);
  await waitForStatus(alice, (await json(safeTarGzipUpload)).id, 'SCAN_PASSED');

  const safeIsoForm = new FormData();
  safeIsoForm.append('file', new Blob([makeIso('INSIDE.TXT', 'safe ISO content')]), 'archive.iso');
  const safeIsoUpload = await request('/api/upload', { method: 'POST', body: safeIsoForm }, alice);
  assert.equal(safeIsoUpload.status, 202);
  await waitForStatus(alice, (await json(safeIsoUpload)).id, 'SCAN_PASSED');

  const archiveInfectedForm = new FormData();
  archiveInfectedForm.append('file', new Blob([zlib.gzipSync(makeTar('eicar.txt', eicar))]), 'infected.tar.gz');
  const archiveInfectedUpload = await request('/api/upload', { method: 'POST', body: archiveInfectedForm }, alice);
  assert.equal(archiveInfectedUpload.status, 202);
  const archiveInfected = await waitForStatus(alice, (await json(archiveInfectedUpload)).id, 'INFECTED');
  assert.match(archiveInfected.detection, /EICAR/);

  const unsafeZipForm = new FormData();
  unsafeZipForm.append('file', new Blob([makeZip('../outside.txt', 'unsafe path')]), 'unsafe.zip');
  const unsafeZipUpload = await request('/api/upload', { method: 'POST', body: unsafeZipForm }, alice);
  assert.equal(unsafeZipUpload.status, 202);
  const unsafeZip = await json(unsafeZipUpload);
  const rejectedZip = await waitForStatus(alice, unsafeZip.id, 'UNSCANNABLE');
  assert.match(rejectedZip.detection, /outside\.txt/);

  const bombZipForm = new FormData();
  bombZipForm.append('file', new Blob([makeZip('large.txt', Buffer.alloc(1024 * 1024, 65))]), 'large.zip');
  const bombZipUpload = await request('/api/upload', { method: 'POST', body: bombZipForm }, alice);
  assert.equal(bombZipUpload.status, 202);
  const bombZip = await json(bombZipUpload);
  const rejectedBomb = await waitForStatus(alice, bombZip.id, 'UNSCANNABLE');
  assert.match(rejectedBomb.detection, /compression ratio limit/);

  const bulkTrash = await request('/api/files/bulk-trash', {
    method: 'POST',
    body: JSON.stringify({ ids: [safeZip.id, unsafeZip.id] })
  }, alice);
  assert.equal(bulkTrash.status, 200);
  assert.equal((await json(bulkTrash)).count, 2);

  const nestedFolderResponse = await request('/api/folders', {
    method: 'POST',
    body: JSON.stringify({ name: 'Nested', parentId: folder.id })
  }, alice);
  const nestedFolder = await json(nestedFolderResponse);
  const cycleMove = await request(`/api/folders/${folder.id}`, {
    method: 'PATCH',
    body: JSON.stringify({ parentId: nestedFolder.id })
  }, alice);
  assert.equal(cycleMove.status, 400);

  const bob = await createSession('bob');
  const searchUsers = await json(await request('/api/users/search?q=bo', {}, alice));
  assert.deepEqual(searchUsers.users.map((user) => user.username), ['bob']);

  const fileShare = await request(`/api/shares/file/${uploaded.id}`, {
    method: 'POST',
    body: JSON.stringify({ username: 'bob', permissions: { canEdit: false } })
  }, alice);
  assert.equal(fileShare.status, 201);
  const fileShareResult = await json(fileShare);
  assert.equal(fileShareResult.permissions.canEdit, false);
  const directSharedFiles = await json(await request('/api/files?mode=shared', {}, bob));
  assert.ok(directSharedFiles.files.some((entry) => entry.id === uploaded.id && entry.ownerUsername === 'alice'));
  const sharedFileDownload = await request(`/api/files/${uploaded.id}/download`, {}, bob);
  assert.equal(sharedFileDownload.status, 200);
  assert.equal(await sharedFileDownload.text(), 'edited version');
  const deniedSharedEdit = await request(`/api/files/${uploaded.id}/content`, {
    method: 'PUT',
    body: JSON.stringify({ content: 'unauthorized' })
  }, bob);
  assert.equal(deniedSharedEdit.status, 403);

  const readonlyFolderShare = await request(`/api/shares/folder/${folder.id}`, {
    method: 'POST',
    body: JSON.stringify({ username: 'bob', permissions: {} })
  }, alice);
  assert.equal(readonlyFolderShare.status, 201);
  const readonlyForm = new FormData();
  readonlyForm.append('folderId', folder.id);
  readonlyForm.append('file', new Blob(['not allowed']), 'readonly.txt');
  const deniedSharedUpload = await request('/api/upload', { method: 'POST', body: readonlyForm }, bob);
  assert.equal(deniedSharedUpload.status, 403);
  const deniedSharedDelete = await request(`/api/files/${uploaded.id}`, { method: 'DELETE' }, bob);
  assert.equal(deniedSharedDelete.status, 403);
  const deniedSharedFolderCreate = await request('/api/folders', {
    method: 'POST',
    body: JSON.stringify({ name: 'No permission', parentId: folder.id })
  }, bob);
  assert.equal(deniedSharedFolderCreate.status, 403);

  const folderShare = await request(`/api/shares/folder/${folder.id}`, {
    method: 'POST',
    body: JSON.stringify({ username: 'bob', permissions: { canAdd: true, canRemove: true, canEdit: true } })
  }, alice);
  assert.equal(folderShare.status, 201);
  const folderShareResult = await json(folderShare);
  const sharedRoots = await json(await request('/api/files?mode=shared', {}, bob));
  assert.ok(sharedRoots.folders.some((entry) => entry.id === folder.id));
  const bobFolderContents = await json(await request(`/api/files?folderId=${folder.id}`, {}, bob));
  assert.ok(bobFolderContents.files.some((entry) => entry.id === uploaded.id));
  assert.equal(bobFolderContents.currentOwnerId, (await json(await request('/api/files?folderId=' + folder.id, {}, alice))).currentOwnerId);
  const collaboratorFolderResponse = await request('/api/folders', {
    method: 'POST',
    body: JSON.stringify({ name: 'Added by Bob', parentId: folder.id })
  }, bob);
  assert.equal(collaboratorFolderResponse.status, 201);
  const collaboratorFolder = await json(collaboratorFolderResponse);
  const ownerFolderList = await json(await request(`/api/files?folderId=${folder.id}`, {}, alice));
  assert.ok(ownerFolderList.folders.some((entry) => entry.id === collaboratorFolder.id && entry.isOwner));

  const sharedUploadForm = new FormData();
  sharedUploadForm.append('folderId', folder.id);
  sharedUploadForm.append('file', new Blob(['added by bob']), 'bob-added.txt');
  const sharedUpload = await request('/api/upload', { method: 'POST', body: sharedUploadForm }, bob);
  assert.equal(sharedUpload.status, 202);
  const bobAdded = await json(sharedUpload);
  await waitForStatus(alice, bobAdded.id, 'SCAN_PASSED', folder.id);

  const bobEdit = await request(`/api/files/${uploaded.id}/content`, {
    method: 'PUT',
    body: JSON.stringify({ content: 'edited by bob' })
  }, bob);
  assert.equal(bobEdit.status, 202);
  await waitForStatus(alice, uploaded.id, 'SCAN_PASSED', folder.id);
  const blockedEdit = await request(`/api/files/${uploaded.id}/content`, {
    method: 'PUT',
    body: JSON.stringify({ content: eicar.toString('ascii') })
  }, bob);
  assert.equal(blockedEdit.status, 202);
  await waitForStatus(alice, uploaded.id, 'SCAN_PASSED', folder.id);
  const afterBlockedEdit = await request(`/api/files/${uploaded.id}/download`, {}, alice);
  assert.equal(await afterBlockedEdit.text(), 'edited by bob');
  const ownerStorage = await json(await request('/api/storage', {}, alice));
  const recipientStorage = await json(await request('/api/storage', {}, bob));
  assert.ok(ownerStorage.used >= Buffer.byteLength('edited by bob') + Buffer.byteLength('added by bob'));
  assert.equal(recipientStorage.used, 0);

  const removeSharedFile = await request(`/api/files/${bobAdded.id}`, { method: 'DELETE' }, bob);
  assert.equal(removeSharedFile.status, 200);
  const revoked = await request(`/api/shares/${folderShareResult.id}`, { method: 'DELETE' }, alice);
  assert.equal(revoked.status, 200);
  const deniedAfterRevoke = await request(`/api/files/${folder.id}/path`, {}, bob);
  assert.equal(deniedAfterRevoke.status, 404);
  const stillDirectlyShared = await request(`/api/files/${uploaded.id}/download`, {}, bob);
  assert.equal(stillDirectlyShared.status, 200);
  const revokeFileShare = await request(`/api/shares/${fileShareResult.id}`, { method: 'DELETE' }, alice);
  assert.equal(revokeFileShare.status, 200);
  const deniedAfterFileRevoke = await request(`/api/files/${uploaded.id}/download`, {}, bob);
  assert.equal(deniedAfterFileRevoke.status, 404);

  const crossUserDownload = await request(`/api/files/${uploaded.id}/download`, {}, bob);
  assert.equal(crossUserDownload.status, 404);
  const crossUserMove = await request(`/api/files/${uploaded.id}`, {
    method: 'PATCH',
    body: JSON.stringify({ starred: true })
  }, bob);
  assert.equal(crossUserMove.status, 404);

  const usageResponse = await request('/api/storage', {}, alice);
  assert.equal(usageResponse.status, 200);
  const usage = await json(usageResponse);
  assert.ok(usage.used >= Buffer.byteLength('edited version') + boundarySample.length);

  const deleteFolder = await request(`/api/folders/${folder.id}`, { method: 'DELETE' }, alice);
  assert.equal(deleteFolder.status, 200);
  const restore = await request(`/api/files/${uploaded.id}/restore`, { method: 'POST', body: '{}' }, alice);
  assert.equal(restore.status, 200);
  const restoredRoot = await json(await request('/api/files', {}, alice));
  assert.ok(restoredRoot.files.some((entry) => entry.id === uploaded.id && entry.folderId === null));
  const emptyTrash = await request('/api/trash/empty', { method: 'POST', body: '{}' }, alice);
  assert.equal(emptyTrash.status, 200);

  const largeForm = new FormData();
  largeForm.append('file', new Blob([Buffer.alloc(700 * 1024, 66)]), 'large.txt');
  const largeUpload = await request('/api/upload', { method: 'POST', body: largeForm }, alice);
  assert.equal(largeUpload.status, 202);
  await waitForStatus(alice, (await json(largeUpload)).id, 'SCAN_PASSED');
  const overQuotaForm = new FormData();
  overQuotaForm.append('file', new Blob([Buffer.alloc(400 * 1024, 67)]), 'over-quota.txt');
  const overQuota = await request('/api/upload', { method: 'POST', body: overQuotaForm }, alice);
  assert.equal(overQuota.status, 507);
});

test('whitelist can be disabled to allow registration and login without a whitelist', { timeout: 15000 }, async () => {
  const disabledDataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'simple-file-store-no-whitelist-'));
  const port = await unusedPort();
  const url = `http://127.0.0.1:${port}`;
  const disabledServer = spawn(process.execPath, ['src/server.js'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(port),
      HOST: '127.0.0.1',
      DATA_DIRECTORY: disabledDataDirectory,
      SESSION_SECRET: crypto.randomBytes(48).toString('hex'),
      WHITELISTFEATURE: 'FALSE',
      WHITELIST: '',
      HTTPS_ENABLED: 'false',
      COOKIE_SECURE: 'false'
    },
    stdio: 'ignore'
  });

  try {
    let healthy = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (disabledServer.exitCode !== null) throw new Error(`Test server exited with ${disabledServer.exitCode}`);
      try {
        const response = await fetch(`${url}/healthz`);
        if (response.ok) {
          healthy = true;
          break;
        }
      } catch { }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(healthy, true, 'Test server did not start in time');

    const page = await fetch(`${url}/`);
    const css = await fetch(`${url}/styles.css`);
    const javascript = await fetch(`${url}/app.js`);
    const contentSecurityPolicy = page.headers.get('content-security-policy');
    assert.equal(page.status, 200);
    assert.equal(css.status, 200);
    assert.equal(javascript.status, 200);
    assert.equal(page.headers.get('strict-transport-security'), null);
    assert.doesNotMatch(contentSecurityPolicy, /upgrade-insecure-requests/);
    assert.match(contentSecurityPolicy, /default-src 'self'/);
    assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(page.headers.get('x-frame-options'), 'SAMEORIGIN');

    const tooShortRegistration = await fetch(`${url}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'short-password-user', password: '1234567' })
    });
    assert.equal(tooShortRegistration.status, 400);

    const credentials = { username: 'unlisted-user', password: '12345678' };
    const registration = await fetch(`${url}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    assert.equal(registration.status, 201);

    const login = await fetch(`${url}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const me = await fetch(`${url}/api/auth/me`, { headers: { Cookie: cookie } });
    assert.equal(me.status, 200);
    assert.equal((await me.json()).username, credentials.username);
  } finally {
    if (disabledServer.exitCode === null) {
      disabledServer.kill('SIGTERM');
      await new Promise((resolve) => disabledServer.once('exit', resolve));
    }
    await fs.rm(disabledDataDirectory, { recursive: true, force: true });
  }
});

test('numeric limits accept unlimited and values above previous ceilings', { timeout: 30000 }, async () => {
  const unlimitedDataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'simple-file-store-unlimited-'));
  const highFileLimitConfig = spawnSync(process.execPath, [
    '--input-type=module',
    '-e',
    `import(${JSON.stringify(pathToFileURL(path.join(root, 'src', 'config.js')).href)})`
  ], {
    cwd: unlimitedDataDirectory,
    env: {
      ...process.env,
      NODE_ENV: 'production',
      SESSION_SECRET: crypto.randomBytes(48).toString('hex'),
      WHITELISTFEATURE: 'FALSE',
      PORT: '3000',
      SESSION_MAX_AGE_HOURS: '24',
      MAX_FILE_SIZE_MB: '2049',
      MAX_STORAGE_MB: '0',
      MAX_CONCURRENT_UPLOADS: '3',
      MAX_GLOBAL_STAGING_MB: '0',
      MAX_GLOBAL_QUARANTINE_MB: '0',
      SCAN_CONCURRENCY: '1',
      SCAN_TIMEOUT_SECONDS: '120',
      MAX_SCAN_FILE_SIZE_MB: '0',
      QUARANTINE_RETENTION_DAYS: '0',
      MAX_ARCHIVE_ENTRIES: '100001',
      MAX_ARCHIVE_UNCOMPRESSED_MB: '0',
      MAX_ARCHIVE_ENTRY_MB: '0',
      MAX_ARCHIVE_COMPRESSION_RATIO: '10001'
    }
  });
  assert.equal(highFileLimitConfig.status, 0, highFileLimitConfig.stderr.toString());

  const port = await unusedPort();
  const url = `http://127.0.0.1:${port}`;
  const unlimitedServer = spawn(process.execPath, ['src/server.js'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(port),
      HOST: '127.0.0.1',
      DATA_DIRECTORY: unlimitedDataDirectory,
      SESSION_SECRET: crypto.randomBytes(48).toString('hex'),
      WHITELISTFEATURE: 'FALSE',
      WHITELIST: '',
      COOKIE_SECURE: 'false',
      SESSION_MAX_AGE_HOURS: '0',
      MAX_FILE_SIZE_MB: '0',
      MAX_STORAGE_MB: '0',
      MAX_CONCURRENT_UPLOADS: '0',
      MAX_GLOBAL_STAGING_MB: '0',
      MAX_GLOBAL_QUARANTINE_MB: '0',
      SCAN_CONCURRENCY: '0',
      SCAN_TIMEOUT_SECONDS: '0',
      MAX_SCAN_FILE_SIZE_MB: '0',
      QUARANTINE_RETENTION_DAYS: '0',
      MAX_ARCHIVE_ENTRIES: '100001',
      MAX_ARCHIVE_UNCOMPRESSED_MB: '0',
      MAX_ARCHIVE_ENTRY_MB: '0',
      MAX_ARCHIVE_COMPRESSION_RATIO: '10001'
    },
    stdio: 'ignore'
  });

  try {
    let healthy = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (unlimitedServer.exitCode !== null) {
        throw new Error(`Test server exited with ${unlimitedServer.exitCode}`);
      }
      try {
        const response = await fetch(`${url}/healthz`);
        if (response.ok) {
          healthy = true;
          break;
        }
      } catch { }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(healthy, true, 'Test server did not start with the configured limits');

    const credentials = { username: 'unlimited-user', password: '12345678' };
    const registration = await fetch(`${url}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    assert.equal(registration.status, 201);
    const login = await fetch(`${url}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    assert.equal(login.status, 200);
    const loginResult = await login.json();
    const cookie = login.headers.get('set-cookie').split(';')[0];
    assert.doesNotMatch(login.headers.get('set-cookie'), /Max-Age=/);

    const storage = await fetch(`${url}/api/storage`, { headers: { Cookie: cookie } });
    assert.equal(storage.status, 200);
    assert.deepEqual(await storage.json(), { used: 0, limit: null, remaining: null });

    const form = new FormData();
    form.append('file', new Blob(['unlimited upload']), 'unlimited.txt');
    const upload = await fetch(`${url}/api/upload`, {
      method: 'POST',
      headers: { Cookie: cookie, 'X-CSRF-Token': loginResult.csrfToken },
      body: form
    });
    assert.equal(upload.status, 202);
    const uploaded = await upload.json();
    let scanPassed = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const listing = await fetch(`${url}/api/files`, { headers: { Cookie: cookie } });
      const files = await listing.json();
      if (files.files.some((file) => file.id === uploaded.id && file.status === 'SCAN_PASSED')) {
        scanPassed = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(scanPassed, true, 'Uploaded file did not pass scanning');
  } finally {
    if (unlimitedServer.exitCode === null) {
      unlimitedServer.kill('SIGTERM');
      await new Promise((resolve) => unlimitedServer.once('exit', resolve));
    }
    await fs.rm(unlimitedDataDirectory, { recursive: true, force: true });
  }
});
