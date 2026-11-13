import Database from 'better-sqlite3';
import fs from 'node:fs';
import config from './config.js';

fs.mkdirSync(config.dataDirectory, { recursive: true, mode: 0o700 });
const db = new Database(config.databasePath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    otp_secret TEXT,
    otp_pending_secret TEXT,
    otp_last_counter INTEGER,
    trash_delete_otp_required INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS login_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id TEXT REFERENCES folders(id),
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    deleted_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS folders_user_parent ON folders(user_id, parent_id);
  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id TEXT REFERENCES folders(id),
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    storage_key TEXT,
    status TEXT NOT NULL,
    detection TEXT,
    starred INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    modified_at INTEGER NOT NULL,
    last_accessed_at INTEGER,
    deleted_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS files_user_folder ON files(user_id, folder_id);
  CREATE INDEX IF NOT EXISTS files_user_status ON files(user_id, status);
  CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('file', 'folder')),
    resource_id TEXT NOT NULL,
    can_read INTEGER NOT NULL DEFAULT 1,
    can_add INTEGER NOT NULL DEFAULT 0,
    can_remove INTEGER NOT NULL DEFAULT 0,
    can_edit INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    UNIQUE(resource_type, resource_id, recipient_id)
  );
  CREATE INDEX IF NOT EXISTS shares_recipient ON shares(recipient_id, resource_type);
  CREATE INDEX IF NOT EXISTS shares_owner ON shares(owner_id);
  CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    staging_key TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    error TEXT,
    is_edit INTEGER NOT NULL DEFAULT 0,
    previous_status TEXT,
    previous_size INTEGER
  );
  CREATE INDEX IF NOT EXISTS scan_jobs_state ON scan_jobs(state, created_at);
  CREATE TABLE IF NOT EXISTS quarantine_records (
    id TEXT PRIMARY KEY,
    file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    reason TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    event TEXT NOT NULL,
    detail TEXT,
    created_at INTEGER NOT NULL
  );
`);

if (!db.pragma('table_info(quarantine_records)').some((column) => column.name === 'size')) {
  db.exec('ALTER TABLE quarantine_records ADD COLUMN size INTEGER NOT NULL DEFAULT 0');
}
if (!db.pragma('table_info(scan_jobs)').some((column) => column.name === 'previous_size')) {
  db.exec('ALTER TABLE scan_jobs ADD COLUMN previous_size INTEGER');
}
for (const [column, definition] of [
  ['otp_secret', 'TEXT'],
  ['otp_pending_secret', 'TEXT'],
  ['otp_last_counter', 'INTEGER'],
  ['trash_delete_otp_required', 'INTEGER NOT NULL DEFAULT 0']
]) {
  if (!db.pragma('table_info(users)').some((entry) => entry.name === column)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
  }
}

export function audit(userId, event, detail = '') {
  db.prepare('INSERT INTO audit_log (user_id, event, detail, created_at) VALUES (?, ?, ?, ?)')
    .run(userId || null, event, String(detail).slice(0, 500), Date.now());
}

export default db;
