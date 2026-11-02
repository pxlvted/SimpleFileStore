import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { Worker } from 'node:worker_threads';
import Busboy from 'busboy';
import express from 'express';
import helmet from 'helmet';
import config from './config.js';
import db, { audit } from './db.js';

for (const directory of [
  config.dataDirectory, config.storageDirectory, config.stagingDirectory,
  config.quarantineDirectory, config.temporaryDirectory, config.logDirectory
]) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
}

const app = express();
if (config.trustProxy) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], objectSrc: ["'none'"], baseUri: ["'none'"],
      frameAncestors: ["'none'"], formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '2mb', strict: true }));
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

const tokenDigest = (token) => crypto.createHmac('sha256', config.sessionSecret).update(token).digest('hex');
const id = () => crypto.randomUUID();
const now = () => Date.now();
const safeName = (value) => typeof value === 'string'
  && value.length > 0 && value.length <= 255
  && !/[\/\\\0-\x1f\x7f]/.test(value)
  && value !== '.' && value !== '..';
const EDITABLE_EXTENSIONS = new Set(['.txt', '.md', '.json', '.html', '.css', '.js', '.xml', '.csv', '.yaml', '.yml', '.log']);
const loginAttempts = new Map();
let activeUploads = 0;
let activeUploadReservation = 0;
let activeScans = 0;
let quarantineReservedBytes = 0;

const error = (status, message) => Object.assign(new Error(message), { status });
const getCookie = (request, key) => {
  const cookies = request.headers.cookie || '';
  for (const pair of cookies.split(';')) {
    const [name, ...value] = pair.trim().split('=');
    if (name === key) {
      try { return decodeURIComponent(value.join('=')); }
      catch { return ''; }
    }
  }
  return '';
};
const setSessionCookie = (res, token, maxAge) => {
  const flags = [`session=${encodeURIComponent(token)}`, 'HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${maxAge}`];
  if (config.cookieSecure) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
};
const clearSessionCookie = (res) => {
  const flags = ['session=', 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=0'];
  if (config.cookieSecure) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
};

function authenticate(req, res, next) {
  const token = getCookie(req, 'session');
  if (!token || token.length > 256) return next(error(401, 'Authentication required'));
  const session = db.prepare(`
    SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, u.username
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?
  `).get(tokenDigest(token));
  if (!session || session.expires_at <= now()) {
    if (session) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(session.token_hash);
    clearSessionCookie(res);
    return next(error(401, 'Authentication required'));
  }
  if (!config.whitelist.has(session.username.toLowerCase())) {
    db.prepare('DELETE FROM sessions WHERE token_hash=?').run(session.token_hash);
    clearSessionCookie(res);
    return next(error(403, 'Account is not currently authorized'));
  }
  req.user = { id: session.user_id, username: session.username };
  req.session = session;
  next();
}

function csrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const supplied = req.get('x-csrf-token') || '';
  const expected = req.session?.csrf_token || '';
  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);
  if (!a.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return next(error(403, 'Invalid request token'));
  }
  next();
}

function requireAuth(req, res, next) {
  authenticate(req, res, (authError) => {
    if (authError) return next(authError);
    csrf(req, res, next);
  });
}

function passwordHash(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
      (err, derived) => err ? reject(err) : resolve(derived));
  });
}

function recordLoginAttempt(key) {
  const current = loginAttempts.get(key);
  const time = now();
  if (!current || time - current.startedAt > 15 * 60 * 1000) {
    loginAttempts.set(key, { startedAt: time, count: 1 });
    return false;
  }
  current.count += 1;
  return current.count > 10;
}

function verifyOwnership(table, objectId, userId) {
  if (!/^[0-9a-f-]{36}$/i.test(objectId || '')) throw error(404, 'Item not found');
  const row = db.prepare(`SELECT id FROM ${table} WHERE id=? AND user_id=?`).get(objectId, userId);
  if (!row) throw error(404, 'Item not found');
  return row;
}

function validateFolder(userId, folderId) {
  if (folderId === null || folderId === undefined || folderId === '') return null;
  const folder = db.prepare('SELECT id FROM folders WHERE id=? AND user_id=? AND deleted_at IS NULL')
    .get(folderId, userId);
  if (!folder) throw error(400, 'Folder not found');
  return folder.id;
}

function fullPermissions() {
  return { canRead: true, canAdd: true, canRemove: true, canEdit: true };
}

function sharePermissions(row) {
  return {
    canRead: Boolean(row.can_read),
    canAdd: Boolean(row.can_add),
    canRemove: Boolean(row.can_remove),
    canEdit: Boolean(row.can_edit)
  };
}

function activeOwner(ownerId) {
  const owner = db.prepare('SELECT username FROM users WHERE id=?').get(ownerId);
  return owner && config.whitelist.has(owner.username.toLowerCase()) ? owner : null;
}

function getFolderAccess(userId, folderId) {
  const folder = db.prepare('SELECT * FROM folders WHERE id=? AND deleted_at IS NULL').get(folderId);
  if (!folder) throw error(404, 'Folder not found');
  if (folder.user_id === userId) return { folder, ownerId: folder.user_id, isOwner: true, permissions: fullPermissions() };
  const shares = db.prepare(`WITH RECURSIVE ancestors(id, depth) AS (
      SELECT id, 0 FROM folders WHERE id=?
      UNION ALL SELECT f.parent_id, ancestors.depth + 1
      FROM folders f JOIN ancestors ON f.id=ancestors.id
      WHERE f.parent_id IS NOT NULL AND ancestors.depth < 100
    )
    SELECT s.*, ancestors.depth, owner.username AS owner_username
    FROM ancestors JOIN shares s ON s.resource_type='folder' AND s.resource_id=ancestors.id
    JOIN users owner ON owner.id=s.owner_id
    WHERE s.recipient_id=? AND s.owner_id=? ORDER BY ancestors.depth ASC`).all(folderId, userId, folder.user_id);
  const activeShares = shares.filter((share) => config.whitelist.has(share.owner_username.toLowerCase()));
  if (!activeShares.length) throw error(404, 'Folder not found');
  const permissions = activeShares.reduce((combined, share) => {
    const granted = sharePermissions(share);
    for (const key of Object.keys(combined)) combined[key] ||= granted[key];
    return combined;
  }, { canRead: false, canAdd: false, canRemove: false, canEdit: false });
  return { folder, ownerId: folder.user_id, isOwner: false, permissions };
}

function getFileAccess(userId, fileId) {
  const file = db.prepare('SELECT * FROM files WHERE id=? AND deleted_at IS NULL').get(fileId);
  if (!file) throw error(404, 'File not found');
  if (file.user_id === userId) return { file, ownerId: file.user_id, isOwner: true, permissions: fullPermissions() };
  const grants = [];
  const direct = db.prepare(`SELECT s.*, 0 AS depth, owner.username AS owner_username
    FROM shares s JOIN users owner ON owner.id=s.owner_id
    WHERE s.resource_type='file' AND s.resource_id=? AND s.recipient_id=? AND s.owner_id=?`)
    .all(fileId, userId, file.user_id);
  grants.push(...direct);
  if (file.folder_id) {
    const inherited = db.prepare(`WITH RECURSIVE ancestors(id, depth) AS (
        SELECT id, 0 FROM folders WHERE id=?
        UNION ALL SELECT f.parent_id, ancestors.depth + 1
        FROM folders f JOIN ancestors ON f.id=ancestors.id
        WHERE f.parent_id IS NOT NULL AND ancestors.depth < 100
      )
      SELECT s.*, ancestors.depth, owner.username AS owner_username
      FROM ancestors JOIN shares s ON s.resource_type='folder' AND s.resource_id=ancestors.id
      JOIN users owner ON owner.id=s.owner_id
      WHERE s.recipient_id=? AND s.owner_id=?`).all(file.folder_id, userId, file.user_id);
    grants.push(...inherited);
  }
  const activeGrants = grants.filter((grant) => config.whitelist.has(grant.owner_username.toLowerCase()));
  if (!activeGrants.length) throw error(404, 'File not found');
  const permissions = activeGrants.reduce((combined, grant) => {
    const granted = sharePermissions(grant);
    for (const key of Object.keys(combined)) combined[key] ||= granted[key];
    return combined;
  }, { canRead: false, canAdd: false, canRemove: false, canEdit: false });
  return { file, ownerId: file.user_id, isOwner: false, permissions };
}

function ensurePermission(access, permission) {
  if (!access.permissions[permission]) throw error(403, 'You do not have permission to perform this action');
}

function sharedFolderRoot(userId, folderId) {
  return db.prepare(`WITH RECURSIVE ancestors(id, depth) AS (
      SELECT id, 0 FROM folders WHERE id=?
      UNION ALL SELECT f.parent_id, ancestors.depth + 1
      FROM folders f JOIN ancestors ON f.id=ancestors.id
      WHERE f.parent_id IS NOT NULL AND ancestors.depth < 100
    )
    SELECT ancestors.id FROM ancestors JOIN shares s
      ON s.resource_type='folder' AND s.resource_id=ancestors.id
    WHERE s.recipient_id=? ORDER BY ancestors.depth ASC LIMIT 1`).get(folderId, userId);
}

function storageUsage(userId) {
  return db.prepare('SELECT COALESCE(SUM(size), 0) AS size FROM files WHERE user_id=?').get(userId).size;
}

function removeQuarantineForFile(fileId) {
  const records = db.prepare('SELECT storage_key FROM quarantine_records WHERE file_id=?').all(fileId);
  for (const record of records) {
    fs.rmSync(path.join(config.quarantineDirectory, record.storage_key), { force: true });
  }
  db.prepare('DELETE FROM quarantine_records WHERE file_id=?').run(fileId);
}

app.get('/healthz', (_req, res, next) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'ok' });
  } catch (err) { next(err); }
});

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const password = req.body?.password;
    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) throw error(400, 'Username must be 3–32 letters, numbers, dots, dashes, or underscores');
    if (!config.whitelist.has(username.toLowerCase())) throw error(403, 'Registration is not available for this username');
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) {
      throw error(400, 'Password must be at least 12 characters');
    }
    const salt = crypto.randomBytes(16);
    const hash = await passwordHash(password, salt);
    const userId = id();
    try {
      db.prepare('INSERT INTO users (id, username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(userId, username, hash.toString('hex'), salt.toString('hex'), now());
    } catch (insertError) {
      if (insertError.code === 'SQLITE_CONSTRAINT_UNIQUE') throw error(409, 'An account for this username already exists');
      throw insertError;
    }
    audit(userId, 'account_registered');
    res.status(201).json({ success: true });
  } catch (err) { next(err); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const providedPassword = req.body?.password;
    const validPasswordLength = typeof providedPassword === 'string' && providedPassword.length <= 1024;
    const password = validPasswordLength ? providedPassword : '';
    const attemptKey = `${req.ip}:${username.slice(0, 40).toLowerCase()}`;
    if (recordLoginAttempt(attemptKey)) throw error(429, 'Too many login attempts. Try again later.');
    const user = db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE').get(username);
    const salt = user ? Buffer.from(user.password_salt, 'hex') : Buffer.alloc(16);
    const expectedHash = user ? Buffer.from(user.password_hash, 'hex') : Buffer.alloc(64);
    const actual = await passwordHash(password, salt);
    const valid = crypto.timingSafeEqual(actual, expectedHash)
      && validPasswordLength
      && Boolean(user && config.whitelist.has(user.username.toLowerCase()));
    if (!valid) {
      audit(user?.id, 'login_failed');
      throw error(401, 'Invalid username or password');
    }
    loginAttempts.delete(attemptKey);
    const previousToken = getCookie(req, 'session');
    if (previousToken && previousToken.length <= 256) {
      db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenDigest(previousToken));
    }
    const token = crypto.randomBytes(32).toString('base64url');
    const csrfToken = crypto.randomBytes(32).toString('base64url');
    const expiresAt = now() + config.sessionMaxAgeHours * 60 * 60 * 1000;
    db.prepare('INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(tokenDigest(token), user.id, csrfToken, expiresAt, now());
    setSessionCookie(res, token, config.sessionMaxAgeHours * 3600);
    audit(user.id, 'login_succeeded');
    res.json({ username: user.username, csrfToken });
  } catch (err) { next(err); }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ username: req.user.username, csrfToken: req.session.csrf_token });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash=?').run(req.session.token_hash);
  audit(req.user.id, 'logout');
  clearSessionCookie(res);
  res.json({ success: true });
});

app.get('/api/storage', requireAuth, (req, res) => {
  const used = storageUsage(req.user.id);
  res.json({ used, limit: config.maxStorage, remaining: Math.max(0, config.maxStorage - used) });
});

app.get('/api/users/search', requireAuth, (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 32) : '';
  if (query.length < 1) return res.json({ users: [] });
  const users = db.prepare(`SELECT id, username FROM users
    WHERE id<>? AND username LIKE ? ESCAPE '\\' COLLATE NOCASE
    ORDER BY username COLLATE NOCASE LIMIT 20`)
    .all(req.user.id, `${query.replace(/[\\%_]/g, '\\$&')}%`)
    .filter((user) => config.whitelist.has(user.username.toLowerCase()))
    .map(({ username }) => ({ username }));
  res.json({ users });
});

app.get('/api/shares/:type/:id', requireAuth, (req, res, next) => {
  try {
    const type = req.params.type;
    if (!['file', 'folder'].includes(type)) throw error(400, 'Invalid share type');
    const table = type === 'file' ? 'files' : 'folders';
    const active = db.prepare(`SELECT id FROM ${table} WHERE id=? AND user_id=? AND deleted_at IS NULL`)
      .get(req.params.id, req.user.id);
    if (!active) throw error(404, 'Item not found');
    const shares = db.prepare(`SELECT s.id, u.username, s.can_read, s.can_add, s.can_remove, s.can_edit, s.created_at
      FROM shares s JOIN users u ON u.id=s.recipient_id
      WHERE s.owner_id=? AND s.resource_type=? AND s.resource_id=? ORDER BY u.username COLLATE NOCASE`)
      .all(req.user.id, type, req.params.id);
    res.json({
      shares: shares.map((share) => ({
        id: share.id,
        username: share.username,
        permissions: sharePermissions(share),
        createdAt: share.created_at
      }))
    });
  } catch (err) { next(err); }
});

app.post('/api/shares/:type/:id', requireAuth, (req, res, next) => {
  try {
    const type = req.params.type;
    if (!['file', 'folder'].includes(type)) throw error(400, 'Invalid share type');
    const table = type === 'file' ? 'files' : 'folders';
    const active = db.prepare(`SELECT id FROM ${table} WHERE id=? AND user_id=? AND deleted_at IS NULL`)
      .get(req.params.id, req.user.id);
    if (!active) throw error(404, 'Item not found');
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const recipient = db.prepare('SELECT id, username FROM users WHERE username=? COLLATE NOCASE').get(username);
    if (!recipient || !config.whitelist.has(recipient.username.toLowerCase())) {
      throw error(404, 'Choose an existing, currently authorized user');
    }
    if (recipient.id === req.user.id) throw error(400, 'You cannot share an item with yourself');
    const requested = req.body?.permissions || {};
    const permissions = {
      can_read: 1,
      can_add: type === 'folder' && requested.canAdd === true ? 1 : 0,
      can_remove: requested.canRemove === true ? 1 : 0,
      can_edit: requested.canEdit === true ? 1 : 0
    };
    const shareId = id();
    db.prepare(`INSERT INTO shares (id, owner_id, recipient_id, resource_type, resource_id,
      can_read, can_add, can_remove, can_edit, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(resource_type, resource_id, recipient_id) DO UPDATE SET
        can_read=excluded.can_read, can_add=excluded.can_add, can_remove=excluded.can_remove,
        can_edit=excluded.can_edit, created_at=excluded.created_at`)
      .run(shareId, req.user.id, recipient.id, type, req.params.id, 1,
        permissions.can_add, permissions.can_remove, permissions.can_edit, now());
    const saved = db.prepare('SELECT * FROM shares WHERE resource_type=? AND resource_id=? AND recipient_id=?')
      .get(type, req.params.id, recipient.id);
    audit(req.user.id, 'item_shared', `${type}:${req.params.id} with ${recipient.username}`);
    res.status(201).json({
      id: saved.id,
      username: recipient.username,
      permissions: sharePermissions(saved)
    });
  } catch (err) { next(err); }
});

app.delete('/api/shares/:shareId', requireAuth, (req, res, next) => {
  try {
    const share = db.prepare('SELECT * FROM shares WHERE id=? AND owner_id=?').get(req.params.shareId, req.user.id);
    if (!share) throw error(404, 'Share not found');
    db.prepare('DELETE FROM shares WHERE id=? AND owner_id=?').run(share.id, req.user.id);
    audit(req.user.id, 'share_revoked', `${share.resource_type}:${share.resource_id}`);
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.get('/api/files', requireAuth, (req, res) => {
  const mode = req.query.mode || 'folder';
  const folderId = req.query.folderId || null;
  const userId = req.user.id;
  let files;
  let folders = [];
  let ownerId = userId;
  const fileDto = (file) => {
    const access = file.user_id === userId
      ? { isOwner: true, permissions: fullPermissions() }
      : getFileAccess(userId, file.id);
    return {
      id: file.id, folderId: file.folder_id, name: file.name, size: file.size, status: file.status,
      detection: file.detection, starred: Boolean(file.starred), createdAt: file.created_at,
      modifiedAt: file.modified_at, deletedAt: file.deleted_at, lastAccessedAt: file.last_accessed_at,
      isOwner: access.isOwner, ownerId: file.user_id, permissions: access.permissions,
      ownerUsername: db.prepare('SELECT username FROM users WHERE id=?').get(file.user_id)?.username || ''
    };
  };
  const folderDto = (folder) => {
    const access = folder.user_id === userId
      ? { isOwner: true, permissions: fullPermissions() }
      : getFolderAccess(userId, folder.id);
    return {
      id: folder.id, name: folder.name, parentId: folder.parent_id, createdAt: folder.created_at,
      isOwner: access.isOwner, isSharedRoot: Boolean(folder.is_shared_root),
      ownerId: folder.user_id, permissions: access.permissions,
      ownerUsername: db.prepare('SELECT username FROM users WHERE id=?').get(folder.user_id)?.username || ''
    };
  };
  if (mode === 'trash') {
    files = db.prepare('SELECT * FROM files WHERE user_id=? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC').all(userId);
  } else if (mode === 'starred') {
    files = db.prepare('SELECT * FROM files WHERE user_id=? AND deleted_at IS NULL AND starred=1 ORDER BY modified_at DESC').all(userId);
  } else if (mode === 'recent') {
    files = db.prepare('SELECT * FROM files WHERE user_id=? AND deleted_at IS NULL ORDER BY COALESCE(last_accessed_at, modified_at) DESC LIMIT 100').all(userId);
  } else if (mode === 'shared') {
    const roots = db.prepare(`SELECT s.*, f.name, f.size, f.status, f.detection, f.folder_id, f.created_at,
        f.modified_at, f.deleted_at, f.last_accessed_at, f.user_id AS resource_owner_id,
        u.username AS owner_username
      FROM shares s JOIN files f ON s.resource_type='file' AND f.id=s.resource_id
      JOIN users u ON u.id=s.owner_id
      WHERE s.recipient_id=? AND f.deleted_at IS NULL
      UNION ALL
      SELECT s.*, d.name, 0 AS size, 'FOLDER' AS status, NULL AS detection, d.parent_id AS folder_id,
        d.created_at, d.created_at AS modified_at, d.deleted_at, NULL AS last_accessed_at,
        d.user_id AS resource_owner_id, u.username AS owner_username
      FROM shares s JOIN folders d ON s.resource_type='folder' AND d.id=s.resource_id
      JOIN users u ON u.id=s.owner_id
      WHERE s.recipient_id=? AND d.deleted_at IS NULL`).all(userId, userId)
      .filter((root) => config.whitelist.has(root.owner_username.toLowerCase()));
    files = roots.filter((root) => root.resource_type === 'file').map((root) => ({
      id: root.resource_id, user_id: root.resource_owner_id, folder_id: root.folder_id, name: root.name,
      size: root.size, status: root.status, detection: root.detection, starred: 0,
      created_at: root.created_at, modified_at: root.modified_at, deleted_at: root.deleted_at,
      last_accessed_at: root.last_accessed_at
    }));
    folders = roots.filter((root) => root.resource_type === 'folder').map((root) => ({
      id: root.resource_id, user_id: root.resource_owner_id, parent_id: null,
      name: root.name, created_at: root.created_at, is_shared_root: true
    }));
  } else if (typeof req.query.q === 'string' && req.query.q.trim()) {
    const query = `%${req.query.q.trim().replace(/[\\%_]/g, '\\$&')}%`;
    const sharedOwners = db.prepare('SELECT DISTINCT owner_id FROM shares WHERE recipient_id=?').all(userId)
      .map((row) => row.owner_id).filter((owner) => activeOwner(owner));
    const owners = [...new Set([userId, ...sharedOwners])];
    files = owners.flatMap((owner) => db.prepare(`SELECT * FROM files WHERE user_id=? AND deleted_at IS NULL
      AND (name LIKE ? ESCAPE '\\' OR lower(name) LIKE lower(?) OR folder_id IN
      (SELECT id FROM folders WHERE user_id=? AND name LIKE ? ESCAPE '\\'))
      ORDER BY modified_at DESC LIMIT 500`).all(owner, query, query, owner, query))
      .filter((file) => {
        try { return getFileAccess(userId, file.id).permissions.canRead; }
        catch { return false; }
      });
    folders = owners.flatMap((owner) => db.prepare(`SELECT * FROM folders WHERE user_id=? AND deleted_at IS NULL
      AND name LIKE ? ESCAPE '\\' ORDER BY name LIMIT 500`).all(owner, query))
      .filter((folder) => {
        try { return getFolderAccess(userId, folder.id).permissions.canRead; }
        catch { return false; }
      });
  } else {
    const parentId = folderId ? folderId : null;
    if (parentId) {
      const access = getFolderAccess(userId, parentId);
      ensurePermission(access, 'canRead');
      ownerId = access.ownerId;
    }
    folders = db.prepare(`SELECT * FROM folders WHERE user_id=? AND parent_id IS ? AND deleted_at IS NULL ORDER BY name COLLATE NOCASE`)
      .all(ownerId, parentId);
    files = db.prepare(`SELECT * FROM files WHERE user_id=? AND folder_id IS ? AND deleted_at IS NULL ORDER BY name COLLATE NOCASE`)
      .all(ownerId, parentId);
    if (parentId && ownerId !== userId) {
      folders = folders.filter((folder) => {
        try { return getFolderAccess(userId, folder.id).permissions.canRead; }
        catch { return false; }
      });
      files = files.filter((file) => {
        try { return getFileAccess(userId, file.id).permissions.canRead; }
        catch { return false; }
      });
    }
  }
  const currentAccess = folderId && mode === 'folder' ? getFolderAccess(userId, folderId) : null;
  res.json({
    folders: folders.map(folderDto),
    files: files.map(fileDto),
    currentPermissions: currentAccess?.permissions || fullPermissions(),
    currentOwnerId: currentAccess?.ownerId || userId,
    currentFolder: currentAccess ? { id: currentAccess.folder.id, name: currentAccess.folder.name } : null
  });
});

app.post('/api/folders', requireAuth, (req, res, next) => {
  try {
    const { name } = req.body || {};
    if (!safeName(name)) throw error(400, 'Invalid folder name');
    let ownerId = req.user.id;
    let parentId = null;
    if (req.body.parentId) {
      const access = getFolderAccess(req.user.id, req.body.parentId);
      ensurePermission(access, 'canAdd');
      ownerId = access.ownerId;
      parentId = validateFolder(ownerId, req.body.parentId);
    }
    const folderId = id();
    db.prepare('INSERT INTO folders (id, user_id, parent_id, name, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(folderId, ownerId, parentId, name, now());
    audit(req.user.id, 'folder_created', `${name} (owner ${ownerId})`);
    res.status(201).json({ id: folderId, name, parentId, ownerId });
  } catch (err) { next(err); }
});

app.get('/api/folders/all', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, name, parent_id, user_id FROM folders WHERE deleted_at IS NULL')
    .all().filter((folder) => {
      if (folder.user_id === req.user.id) return true;
      try { return getFolderAccess(req.user.id, folder.id).permissions.canAdd; }
      catch { return false; }
    });
  const byId = new Map(rows.map((folder) => [folder.id, folder]));
  const folders = rows.map((folder) => {
    const names = [folder.name];
    let parentId = folder.parent_id;
    let depth = 0;
    while (parentId && byId.has(parentId) && depth < 100) {
      const parent = byId.get(parentId);
      names.unshift(parent.name);
      parentId = parent.parent_id;
      depth += 1;
    }
    return {
      id: folder.id, name: folder.name, parentId: folder.parent_id,
      path: names.join(' / '), ownerId: folder.user_id
    };
  });
  res.json({ folders });
});

app.patch('/api/folders/:id', requireAuth, (req, res, next) => {
  try {
    verifyOwnership('folders', req.params.id, req.user.id);
    const updates = req.body || {};
    if (Object.hasOwn(updates, 'name')) {
      if (!safeName(updates.name)) throw error(400, 'Invalid folder name');
      db.prepare('UPDATE folders SET name=? WHERE id=? AND user_id=? AND deleted_at IS NULL')
        .run(updates.name, req.params.id, req.user.id);
    }
    if (Object.hasOwn(updates, 'parentId')) {
      const parentId = validateFolder(req.user.id, updates.parentId);
      if (parentId) {
        const cycle = db.prepare(`WITH RECURSIVE descendants(id) AS (
          SELECT id FROM folders WHERE id=? AND user_id=?
          UNION ALL SELECT f.id FROM folders f JOIN descendants d ON f.parent_id=d.id WHERE f.user_id=?
        ) SELECT id FROM descendants WHERE id=?`).get(req.params.id, req.user.id, req.user.id, parentId);
        if (cycle) throw error(400, 'A folder cannot be moved into itself or one of its descendants');
      }
      db.prepare('UPDATE folders SET parent_id=? WHERE id=? AND user_id=? AND deleted_at IS NULL')
        .run(parentId, req.params.id, req.user.id);
    }
    if (!Object.hasOwn(updates, 'name') && !Object.hasOwn(updates, 'parentId')) {
      throw error(400, 'No folder change was provided');
    }
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.get('/api/folders/:id/path', requireAuth, (req, res, next) => {
  try {
    const folders = [];
    let currentId = req.params.id;
    const access = getFolderAccess(req.user.id, currentId);
    ensurePermission(access, 'canRead');
    const sharedRoot = access.isOwner ? null : sharedFolderRoot(req.user.id, currentId)?.id;
    while (currentId) {
      const folder = db.prepare('SELECT id, name, parent_id FROM folders WHERE id=? AND user_id=? AND deleted_at IS NULL')
        .get(currentId, access.ownerId);
      if (!folder) throw error(404, 'Folder not found');
      folders.unshift({ id: folder.id, name: folder.name });
      if (currentId === sharedRoot) break;
      currentId = folder.parent_id;
      if (folders.length > 100) throw error(400, 'Folder path is too deep');
    }
    res.json({ folders });
  } catch (err) { next(err); }
});

app.delete('/api/folders/:id', requireAuth, (req, res, next) => {
  try {
    verifyOwnership('folders', req.params.id, req.user.id);
    const timestamp = now();
    db.transaction(() => {
      db.prepare(`WITH RECURSIVE tree(id) AS (
        SELECT id FROM folders WHERE id=? AND user_id=?
        UNION ALL SELECT f.id FROM folders f JOIN tree t ON f.parent_id=t.id WHERE f.user_id=?
      ) UPDATE files SET deleted_at=? WHERE user_id=? AND folder_id IN (SELECT id FROM tree) AND deleted_at IS NULL`)
        .run(req.params.id, req.user.id, req.user.id, timestamp, req.user.id);
      db.prepare(`WITH RECURSIVE tree(id) AS (
        SELECT id FROM folders WHERE id=? AND user_id=?
        UNION ALL SELECT f.id FROM folders f JOIN tree t ON f.parent_id=t.id WHERE f.user_id=?
      ) UPDATE folders SET deleted_at=? WHERE id IN (SELECT id FROM tree)`)
        .run(req.params.id, req.user.id, req.user.id, timestamp);
    })();
    audit(req.user.id, 'folder_trashed', req.params.id);
    res.json({ success: true });
  } catch (err) { next(err); }
});

function startScanWorker(job, file) {
  const stagingPath = path.join(config.stagingDirectory, job.staging_key);
  const worker = new Worker(new URL('./scanner/scan-worker.js', import.meta.url), {
    workerData: {
      filePath: stagingPath,
      fileName: file.name,
      limits: {
        maxScanFileSize: config.maxScanFileSize,
        maxArchiveEntries: config.maxArchiveEntries,
        maxArchiveUncompressed: config.maxArchiveUncompressed,
        maxArchiveEntry: config.maxArchiveEntry,
        maxArchiveRatio: config.maxArchiveRatio
      }
    },
    resourceLimits: { maxOldGenerationSizeMb: 96, maxYoungGenerationSizeMb: 24 }
  });
  return new Promise((resolve) => {
    let complete = false;
    const timeout = setTimeout(() => {
      if (!complete) {
        complete = true;
        worker.terminate().finally(() => resolve({ status: 'SCAN_FAILED', reason: 'Scan timed out' }));
      }
    }, config.scanTimeoutMs);
    worker.once('message', (result) => {
      if (complete) return;
      complete = true;
      clearTimeout(timeout);
      worker.terminate().finally(() => resolve(result));
    });
    worker.once('error', (workerError) => {
      if (complete) return;
      complete = true;
      clearTimeout(timeout);
      resolve({ status: 'SCAN_FAILED', reason: workerError.message || 'Scanner worker failed' });
    });
    worker.once('exit', (code) => {
      if (complete) return;
      complete = true;
      clearTimeout(timeout);
      resolve({ status: 'SCAN_FAILED', reason: `Scanner worker exited unexpectedly (${code})` });
    });
  });
}

async function processScan(job) {
  const file = db.prepare('SELECT * FROM files WHERE id=? AND user_id=?').get(job.file_id, job.user_id);
  if (!file) {
    await fs.promises.rm(path.join(config.stagingDirectory, job.staging_key), { force: true });
    db.prepare('DELETE FROM scan_jobs WHERE id=?').run(job.id);
    return;
  }
  const result = await startScanWorker(job, file);
  const stagePath = path.join(config.stagingDirectory, job.staging_key);
  const priorStorageKey = file.storage_key;
  if (!db.prepare('SELECT id FROM files WHERE id=?').get(file.id)) {
    await fs.promises.rm(stagePath, { force: true });
    db.prepare('DELETE FROM scan_jobs WHERE id=?').run(job.id);
    return;
  }
  if (result.status === 'SCAN_PASSED') {
    const storageKey = id();
    const destinationDirectory = path.join(config.storageDirectory, job.user_id);
    await fs.promises.mkdir(destinationDirectory, { recursive: true, mode: 0o700 });
    await fs.promises.rename(stagePath, path.join(destinationDirectory, storageKey));
    const stillExists = db.prepare('SELECT id FROM files WHERE id=?').get(file.id);
    if (!stillExists) {
      await fs.promises.rm(path.join(destinationDirectory, storageKey), { force: true });
    } else {
      db.prepare(`UPDATE files SET storage_key=?, status='SCAN_PASSED', size=?, detection=NULL, modified_at=? WHERE id=?`)
        .run(storageKey, fs.statSync(path.join(destinationDirectory, storageKey)).size, now(), file.id);
      if (priorStorageKey) await fs.promises.rm(path.join(destinationDirectory, priorStorageKey), { force: true });
      audit(job.user_id, 'scan_passed', file.name);
    }
  } else {
    const status = ['SUSPICIOUS', 'INFECTED', 'SCAN_FAILED', 'UNSCANNABLE'].includes(result.status)
      ? result.status
      : 'SCAN_FAILED';
    const quarantineKey = id();
    const stageSize = await fs.promises.stat(stagePath).then((stat) => stat.size, () => 0);
    const quarantinedBytes = db.prepare('SELECT COALESCE(SUM(size), 0) AS size FROM quarantine_records').get().size;
    if (quarantinedBytes + quarantineReservedBytes + stageSize <= config.maxGlobalQuarantine) {
      quarantineReservedBytes += stageSize;
      try {
        await fs.promises.rename(stagePath, path.join(config.quarantineDirectory, quarantineKey));
        const stillExists = db.prepare('SELECT id FROM files WHERE id=?').get(file.id);
        if (stillExists) {
          db.prepare(`INSERT INTO quarantine_records (id, file_id, user_id, original_name, reason, storage_key, size, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(id(), file.id, job.user_id, file.name, `${status}: ${result.reason || 'Inspection did not pass'}`.slice(0, 500), quarantineKey, stageSize, now());
        } else {
          await fs.promises.rm(path.join(config.quarantineDirectory, quarantineKey), { force: true });
        }
      } catch (quarantineError) {
        await fs.promises.rm(stagePath, { force: true });
        await fs.promises.rm(path.join(config.quarantineDirectory, quarantineKey), { force: true });
        throw quarantineError;
      } finally {
        quarantineReservedBytes -= stageSize;
      }
    } else {
      await fs.promises.rm(stagePath, { force: true });
    }
    if (job.is_edit && priorStorageKey) {
      db.prepare('UPDATE files SET status=?, size=?, detection=NULL WHERE id=?')
        .run(job.previous_status || 'SCAN_PASSED', job.previous_size ?? file.size, file.id);
    } else {
      db.prepare('UPDATE files SET status=?, detection=? WHERE id=?')
        .run(status, `${status}: ${result.reason || 'Inspection did not pass'}`.slice(0, 500), file.id);
    }
    audit(job.user_id, 'scan_blocked', `${file.name}: ${status}`);
  }
  db.prepare('UPDATE scan_jobs SET state=?, updated_at=?, error=? WHERE id=?')
    .run(result.status === 'SCAN_PASSED' ? 'done' : 'blocked', now(), result.reason || null, job.id);
}

async function scanQueueTick() {
  while (activeScans < config.scanConcurrency) {
    const job = db.prepare(`SELECT * FROM scan_jobs WHERE state='queued' ORDER BY created_at LIMIT 1`).get();
    if (!job) return;
    const changed = db.prepare(`UPDATE scan_jobs SET state='scanning', updated_at=? WHERE id=? AND state='queued'`)
      .run(now(), job.id).changes;
    if (!changed) continue;
    db.prepare(`UPDATE files SET status='SCANNING' WHERE id=? AND status='PENDING_SCAN'`).run(job.file_id);
    activeScans += 1;
    processScan(job).catch((scanError) => {
      const file = db.prepare('SELECT storage_key, size FROM files WHERE id=?').get(job.file_id);
      if (job.is_edit && file?.storage_key) {
        db.prepare('UPDATE files SET status=?, size=?, detection=NULL WHERE id=?')
          .run(job.previous_status || 'SCAN_PASSED', job.previous_size ?? file.size, job.file_id);
      } else {
        db.prepare(`UPDATE files SET status='SCAN_FAILED', detection=? WHERE id=?`)
          .run(`Scanner error: ${String(scanError.message).slice(0, 300)}`, job.file_id);
      }
      fs.rm(path.join(config.stagingDirectory, job.staging_key), { force: true }).catch(() => {});
      db.prepare(`UPDATE scan_jobs SET state='failed', updated_at=?, error=? WHERE id=?`)
        .run(now(), String(scanError.message).slice(0, 300), job.id);
      audit(job.user_id, 'scan_error', scanError.message);
    }).finally(() => {
      activeScans -= 1;
      void scanQueueTick();
    });
  }
}

function collectUpload(req, userId) {
  return new Promise((resolve, reject) => {
    let bb;
    try {
      bb = Busboy({ headers: req.headers, limits: { files: 1, fields: 4, fileSize: config.maxFileSize } });
    } catch { return reject(error(400, 'Invalid multipart upload')); }
    const fields = {};
    const writes = [];
    let receivedFile = false;
    let fileError = null;
    const stagingKey = `${id()}.upload`;
    const stagingPath = path.join(config.stagingDirectory, stagingKey);
    bb.on('field', (name, value) => { fields[name] = value; });
    bb.on('file', (_field, stream, info) => {
      receivedFile = true;
      const originalName = path.basename(String(info.filename || '').replace(/\\/g, '/')).normalize('NFC');
      if (!safeName(originalName)) {
        fileError = error(400, 'Invalid filename');
        stream.resume();
        return;
      }
      let size = 0;
      const meter = new Transform({
        transform(chunk, _encoding, callback) {
          size += chunk.length;
          if (size > config.maxFileSize) return callback(error(413, 'File exceeds the configured size limit'));
          callback(null, chunk);
        }
      });
      stream.once('limit', () => { fileError = error(413, 'File exceeds the configured size limit'); });
      writes.push(pipeline(stream, meter, fs.createWriteStream(stagingPath, { flags: 'wx', mode: 0o600 }))
        .then(() => ({ name: originalName, size, stagingKey })));
    });
    bb.once('filesLimit', () => { fileError = error(400, 'Only one file may be uploaded per request'); });
    bb.once('error', (err) => reject(err));
    bb.once('close', async () => {
      try {
        const uploaded = await Promise.all(writes);
        if (fileError) throw fileError;
        if (!receivedFile || uploaded.length !== 1) throw error(400, 'Select a file to upload');
        resolve({ ...uploaded[0], folderId: fields.folderId || null });
      } catch (err) {
        await fs.promises.rm(stagingPath, { force: true });
        reject(err);
      }
    });
    req.pipe(bb);
    req.once('aborted', () => {
      fileError = error(400, 'Upload was interrupted');
      bb.destroy(fileError);
    });
  });
}

app.post('/api/upload', requireAuth, async (req, res, next) => {
  let upload;
  let acquiredSlot = false;
  let ownerId = req.user.id;
  try {
    if (activeUploads >= config.maxConcurrentUploads) throw error(429, 'Too many concurrent uploads');
    const pendingBytes = db.prepare(`SELECT COALESCE(SUM(f.size), 0) AS size FROM scan_jobs j JOIN files f ON f.id=j.file_id
      WHERE j.state IN ('queued','scanning')`).get().size;
    if (pendingBytes + activeUploadReservation + config.maxFileSize > config.maxGlobalStaging) {
      throw error(507, 'Upload staging capacity is currently full');
    }
    activeUploads += 1;
    activeUploadReservation += config.maxFileSize;
    acquiredSlot = true;
    upload = await collectUpload(req, req.user.id);
    let folderId = null;
    if (upload.folderId) {
      const access = getFolderAccess(req.user.id, upload.folderId);
      ensurePermission(access, 'canAdd');
      ownerId = access.ownerId;
      folderId = validateFolder(ownerId, upload.folderId);
    }
    const fileId = id();
    const jobId = id();
    db.transaction(() => {
      const used = storageUsage(ownerId);
      if (used + upload.size > config.maxStorage) throw error(507, 'Storage quota exceeded');
      db.prepare(`INSERT INTO files (id, user_id, folder_id, name, size, status, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?, 'PENDING_SCAN', ?, ?)`)
        .run(fileId, ownerId, folderId, upload.name, upload.size, now(), now());
      db.prepare(`INSERT INTO scan_jobs (id, file_id, user_id, staging_key, state, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'queued', ?, ?)`)
        .run(jobId, fileId, ownerId, upload.stagingKey, now(), now());
    })();
    audit(req.user.id, 'file_uploaded', `${upload.name} (owner ${ownerId})`);
    res.status(202).json({ id: fileId, name: upload.name, size: upload.size, status: 'PENDING_SCAN' });
    void scanQueueTick();
  } catch (err) {
    if (upload?.stagingKey) await fs.promises.rm(path.join(config.stagingDirectory, upload.stagingKey), { force: true });
    next(err);
  } finally {
    if (acquiredSlot) {
      activeUploads -= 1;
      activeUploadReservation -= config.maxFileSize;
    }
  }
});

app.get('/api/files/:id/download', requireAuth, async (req, res, next) => {
  try {
    const access = getFileAccess(req.user.id, req.params.id);
    ensurePermission(access, 'canRead');
    const { file, ownerId } = access;
    if (file.status !== 'SCAN_PASSED' || !file.storage_key) throw error(404, 'File not found or not available');
    const fullPath = path.join(config.storageDirectory, ownerId, file.storage_key);
    await fs.promises.access(fullPath, fs.constants.R_OK);
    db.prepare('UPDATE files SET last_accessed_at=? WHERE id=?').run(now(), file.id);
    const encodedName = encodeURIComponent(file.name).replace(/[!'()*]/g, (character) =>
      `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodedName}`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    await pipeline(fs.createReadStream(fullPath), res);
  } catch (err) {
    if (res.headersSent) return res.destroy(err);
    next(err);
  }
});

app.get('/api/files/:id/content', requireAuth, (req, res, next) => {
  try {
    const access = getFileAccess(req.user.id, req.params.id);
    ensurePermission(access, 'canRead');
    const { file, ownerId } = access;
    if (file.status !== 'SCAN_PASSED' || !file.storage_key) throw error(404, 'File not found or not available');
    if (!EDITABLE_EXTENSIONS.has(path.extname(file.name).toLowerCase())) throw error(415, 'This file format is not supported by the text editor');
    if (file.size > 1024 * 1024) throw error(413, 'Files larger than 1 MB cannot be edited in the browser');
    const fullPath = path.join(config.storageDirectory, ownerId, file.storage_key);
    const content = fs.readFileSync(fullPath);
    if (content.includes(0)) throw error(415, 'Binary files cannot be edited');
    res.json({ id: file.id, name: file.name, content: content.toString('utf8') });
  } catch (err) { next(err); }
});

app.put('/api/files/:id/content', requireAuth, async (req, res, next) => {
  let stagingKey;
  try {
    const access = getFileAccess(req.user.id, req.params.id);
    ensurePermission(access, 'canEdit');
    const { file, ownerId } = access;
    if (file.status !== 'SCAN_PASSED' || !file.storage_key) throw error(404, 'File not found or not available');
    if (!EDITABLE_EXTENSIONS.has(path.extname(file.name).toLowerCase())) throw error(415, 'This file format is not supported by the text editor');
    const content = req.body?.content;
    if (typeof content !== 'string') throw error(400, 'File content must be text');
    const buffer = Buffer.from(content, 'utf8');
    if (buffer.length > Math.min(config.maxFileSize, 1024 * 1024)) throw error(413, 'Edited file exceeds the 1 MB editor limit');
    stagingKey = `${id()}.edit`;
    await fs.promises.writeFile(path.join(config.stagingDirectory, stagingKey), buffer, { flag: 'wx', mode: 0o600 });
    const jobId = id();
    db.transaction(() => {
      const currentAccess = getFileAccess(req.user.id, file.id);
      ensurePermission(currentAccess, 'canEdit');
      const currentFile = db.prepare(`SELECT * FROM files WHERE id=? AND user_id=? AND status='SCAN_PASSED'
        AND deleted_at IS NULL`).get(file.id, ownerId);
      if (!currentFile || currentFile.storage_key !== file.storage_key) {
        throw error(409, 'This file changed while the edit was being prepared');
      }
      const used = storageUsage(ownerId);
      if (used - currentFile.size + buffer.length > config.maxStorage) {
        throw error(507, 'Owner storage quota exceeded');
      }
      const activeJob = db.prepare(`SELECT id FROM scan_jobs WHERE file_id=? AND state IN ('queued','scanning')`)
        .get(file.id);
      if (activeJob) throw error(409, 'This file already has a scan in progress');
      db.prepare(`INSERT INTO scan_jobs (id, file_id, user_id, staging_key, state, created_at, updated_at, is_edit, previous_status, previous_size)
        VALUES (?, ?, ?, ?, 'queued', ?, ?, 1, ?, ?)`)
        .run(jobId, file.id, ownerId, stagingKey, now(), now(), currentFile.status, currentFile.size);
      db.prepare(`UPDATE files SET status='PENDING_SCAN', size=? WHERE id=?`).run(buffer.length, file.id);
    })();
    audit(req.user.id, 'file_edit_submitted', `${file.name} (owner ${ownerId})`);
    res.status(202).json({ status: 'PENDING_SCAN' });
    void scanQueueTick();
  } catch (err) {
    if (stagingKey) await fs.promises.rm(path.join(config.stagingDirectory, stagingKey), { force: true });
    next(err);
  }
});

app.patch('/api/files/:id', requireAuth, (req, res, next) => {
  try {
    const access = getFileAccess(req.user.id, req.params.id);
    if (typeof req.body?.starred === 'boolean') {
      if (!access.isOwner) throw error(403, 'Only the owner can change file stars');
      db.prepare('UPDATE files SET starred=? WHERE id=? AND user_id=?')
        .run(req.body.starred ? 1 : 0, req.params.id, access.ownerId);
    } else if (Object.hasOwn(req.body || {}, 'folderId')) {
      ensurePermission(access, 'canRemove');
      let folderId = null;
      if (req.body.folderId) {
        const destination = getFolderAccess(req.user.id, req.body.folderId);
        ensurePermission(destination, 'canAdd');
        if (destination.ownerId !== access.ownerId) throw error(400, 'Files can only be moved within their owner’s storage');
        folderId = validateFolder(access.ownerId, req.body.folderId);
      }
      db.prepare('UPDATE files SET folder_id=? WHERE id=? AND user_id=? AND deleted_at IS NULL')
        .run(folderId, req.params.id, access.ownerId);
      audit(req.user.id, 'file_moved', `${access.file.name} (owner ${access.ownerId})`);
    } else {
      throw error(400, 'No supported file change was provided');
    }
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.delete('/api/files/:id', requireAuth, (req, res, next) => {
  try {
    const file = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
    if (!file) throw error(404, 'File not found');
    if (req.query.permanent === 'true') {
      if (file.user_id !== req.user.id) throw error(403, 'Only the owner can permanently delete a file');
      if (file.storage_key) fs.rmSync(path.join(config.storageDirectory, file.user_id, file.storage_key), { force: true });
      removeQuarantineForFile(file.id);
      db.prepare('DELETE FROM scan_jobs WHERE file_id=?').run(file.id);
      db.prepare('DELETE FROM shares WHERE owner_id=? AND resource_type=\'file\' AND resource_id=?').run(file.user_id, file.id);
      db.prepare('DELETE FROM files WHERE id=? AND user_id=?').run(file.id, file.user_id);
      audit(req.user.id, 'file_permanently_deleted', file.name);
    } else {
      const access = getFileAccess(req.user.id, file.id);
      ensurePermission(access, 'canRemove');
      db.prepare('UPDATE files SET deleted_at=? WHERE id=? AND user_id=?').run(now(), file.id, access.ownerId);
      audit(req.user.id, 'file_trashed', file.name);
    }
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.post('/api/files/bulk-trash', requireAuth, (req, res, next) => {
  try {
    const ids = req.body?.ids;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 100
      || ids.some((fileId) => !/^[0-9a-f-]{36}$/i.test(fileId))
      || new Set(ids).size !== ids.length) {
      throw error(400, 'Select between 1 and 100 valid files');
    }
    const accessList = ids.map((fileId) => {
      const access = getFileAccess(req.user.id, fileId);
      ensurePermission(access, 'canRemove');
      return access;
    });
    db.transaction(() => {
      for (const access of accessList) {
        db.prepare('UPDATE files SET deleted_at=? WHERE id=? AND user_id=? AND deleted_at IS NULL')
          .run(now(), access.file.id, access.ownerId);
      }
    })();
    audit(req.user.id, 'files_trashed', `${ids.length} files`);
    res.json({ success: true, count: ids.length });
  } catch (err) { next(err); }
});

app.post('/api/files/:id/restore', requireAuth, (req, res, next) => {
  try {
    const file = db.prepare('SELECT * FROM files WHERE id=? AND user_id=? AND deleted_at IS NOT NULL')
      .get(req.params.id, req.user.id);
    if (!file) throw error(404, 'Trashed file not found');
    if (file.status === 'QUARANTINED') throw error(409, 'Quarantined files cannot be restored');
    const activeFolder = file.folder_id && db.prepare('SELECT id FROM folders WHERE id=? AND user_id=? AND deleted_at IS NULL')
      .get(file.folder_id, req.user.id) ? file.folder_id : null;
    if (file.status === 'SCAN_PASSED' && file.storage_key) {
      db.prepare('UPDATE files SET deleted_at=NULL, folder_id=? WHERE id=?').run(activeFolder, file.id);
    } else {
      const activeJob = db.prepare('SELECT id FROM scan_jobs WHERE file_id=? AND state IN (\'queued\',\'scanning\')')
        .get(file.id);
      if (activeJob && ['PENDING_SCAN', 'SCANNING'].includes(file.status)) {
        db.prepare('UPDATE files SET deleted_at=NULL, folder_id=? WHERE id=?').run(activeFolder, file.id);
      } else if (file.storage_key) {
        const stagingKey = `${id()}.restore`;
        const source = path.join(config.storageDirectory, req.user.id, file.storage_key);
        const destination = path.join(config.stagingDirectory, stagingKey);
        fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
        db.transaction(() => {
          db.prepare(`UPDATE files SET deleted_at=NULL, folder_id=?, status='PENDING_SCAN' WHERE id=?`)
            .run(activeFolder, file.id);
          db.prepare(`INSERT INTO scan_jobs (id, file_id, user_id, staging_key, state, created_at, updated_at, is_edit, previous_status)
            VALUES (?, ?, ?, ?, 'queued', ?, ?, 1, 'PENDING_SCAN')`)
            .run(id(), file.id, req.user.id, stagingKey, now(), now());
        })();
        void scanQueueTick();
      } else {
        throw error(409, 'This file has no safely restorable copy');
      }
    }
    audit(req.user.id, 'file_restored', file.name);
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.post('/api/trash/empty', requireAuth, async (req, res, next) => {
  try {
    const files = db.prepare('SELECT * FROM files WHERE user_id=? AND deleted_at IS NOT NULL').all(req.user.id);
    const folders = db.prepare('SELECT id FROM folders WHERE user_id=? AND deleted_at IS NOT NULL').all(req.user.id);
    for (const file of files) {
      if (file.storage_key) await fs.promises.rm(path.join(config.storageDirectory, req.user.id, file.storage_key), { force: true });
      removeQuarantineForFile(file.id);
      const jobs = db.prepare('SELECT staging_key FROM scan_jobs WHERE file_id=?').all(file.id);
      for (const job of jobs) await fs.promises.rm(path.join(config.stagingDirectory, job.staging_key), { force: true });
    }
    db.transaction(() => {
      for (const file of files) {
        db.prepare(`DELETE FROM shares WHERE owner_id=? AND resource_type='file' AND resource_id=?`)
          .run(req.user.id, file.id);
      }
      for (const folder of folders) {
        db.prepare(`DELETE FROM shares WHERE owner_id=? AND resource_type='folder' AND resource_id=?`)
          .run(req.user.id, folder.id);
      }
      db.prepare('DELETE FROM files WHERE user_id=? AND deleted_at IS NOT NULL').run(req.user.id);
      db.prepare('DELETE FROM folders WHERE user_id=? AND deleted_at IS NOT NULL').run(req.user.id);
    })();
    audit(req.user.id, 'trash_emptied');
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.use(express.static(path.resolve('public'), { index: 'index.html', fallthrough: true, maxAge: '1h' }));
app.use((req, _res, next) => next(error(404, `Not found: ${req.path}`)));
app.use((err, req, res, _next) => {
  const status = Number.isInteger(err.status) ? err.status : 500;
  if (status >= 500) console.error(`${new Date().toISOString()} ${req.method} ${req.path}:`, err);
  if (!res.headersSent) res.status(status).json({ error: status >= 500 ? 'An internal error occurred' : err.message });
});

db.prepare(`UPDATE files SET status='PENDING_SCAN' WHERE status='SCANNING'`).run();
db.prepare(`UPDATE scan_jobs SET state='queued', updated_at=? WHERE state='scanning'`).run(now());
db.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).run(now());
const server = app.listen(config.port, config.host, () => {
  console.log(`Simple File Store listening on ${config.host}:${config.port}`);
  void scanQueueTick();
});
const queueTimer = setInterval(() => { void scanQueueTick(); }, 1000);
queueTimer.unref();
const sessionCleanup = setInterval(() => {
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now());
  db.prepare('DELETE FROM audit_log WHERE created_at < ?').run(now() - 90 * 86400000);
  const cutoff = now() - config.quarantineRetentionDays * 86400000;
  const expiredQuarantine = db.prepare('SELECT id, storage_key FROM quarantine_records WHERE created_at < ?').all(cutoff);
  for (const record of expiredQuarantine) {
    fs.rmSync(path.join(config.quarantineDirectory, record.storage_key), { force: true });
    db.prepare('DELETE FROM quarantine_records WHERE id=?').run(record.id);
  }
}, 60 * 60 * 1000);
sessionCleanup.unref();

for (const directory of [config.stagingDirectory, config.temporaryDirectory]) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isFile()) {
      const known = directory === config.stagingDirectory
        ? db.prepare(`SELECT id FROM scan_jobs WHERE staging_key=? AND state IN ('queued','scanning')`).get(entry.name)
        : null;
      if (!known) fs.rmSync(path.join(directory, entry.name), { force: true });
    }
  }
}

const knownQuarantine = new Set(db.prepare('SELECT storage_key FROM quarantine_records').all().map((row) => row.storage_key));
for (const entry of fs.readdirSync(config.quarantineDirectory, { withFileTypes: true })) {
  if (entry.isFile() && !knownQuarantine.has(entry.name)) {
    fs.rmSync(path.join(config.quarantineDirectory, entry.name), { force: true });
  }
}
for (const user of db.prepare('SELECT id FROM users').all()) {
  const userDirectory = path.join(config.storageDirectory, user.id);
  if (!fs.existsSync(userDirectory)) continue;
  const knownStorage = new Set(db.prepare('SELECT storage_key FROM files WHERE user_id=? AND storage_key IS NOT NULL').all(user.id)
    .map((row) => row.storage_key));
  for (const entry of fs.readdirSync(userDirectory, { withFileTypes: true })) {
    if (entry.isFile() && !knownStorage.has(entry.name)) fs.rmSync(path.join(userDirectory, entry.name), { force: true });
  }
}

const loginAttemptCleanup = setInterval(() => {
  for (const [key, attempt] of loginAttempts) {
    if (now() - attempt.startedAt > 15 * 60 * 1000) loginAttempts.delete(key);
  }
}, 15 * 60 * 1000);
loginAttemptCleanup.unref();

process.once('SIGTERM', () => server.close(() => { db.close(); process.exit(0); }));
process.once('SIGINT', () => server.close(() => { db.close(); process.exit(0); }));
