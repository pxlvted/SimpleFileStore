import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';

function integer(name, fallback, min, max) {
  const raw = process.env[name];
  const value = raw === undefined || raw === '' ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function boolean(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  if (raw.toLowerCase() === 'true') return true;
  if (raw.toLowerCase() === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

const environment = process.env.NODE_ENV || 'development';
const isDevelopment = environment === 'development';
const dataDirectory = path.resolve(process.env.DATA_DIRECTORY || (isDevelopment ? './data' : '/app/data'));
const configuredSecret = process.env.SESSION_SECRET || '';
const sessionSecret = isDevelopment
  && (!configuredSecret || configuredSecret.includes('replace-with-'))
  ? crypto.randomBytes(48).toString('hex')
  : configuredSecret;
if (sessionSecret.length < 32 || sessionSecret.includes('replace-with-')) {
  throw new Error('SESSION_SECRET must contain at least 32 non-placeholder characters');
}

const whitelist = new Set(
  (process.env.WHITELIST || (isDevelopment ? 'developer' : ''))
    .split(',')
    .map((username) => username.trim().toLowerCase())
    .filter(Boolean)
);
if (whitelist.size === 0) throw new Error('WHITELIST must contain at least one username');

const config = {
  environment,
  port: integer('PORT', 3000, 1, 65535),
  host: process.env.HOST || (isDevelopment ? '127.0.0.1' : '0.0.0.0'),
  sessionSecret,
  whitelist,
  sessionMaxAgeHours: integer('SESSION_MAX_AGE_HOURS', 24, 1, 720),
  cookieSecure: boolean('COOKIE_SECURE', !isDevelopment),
  trustProxy: boolean('TRUST_PROXY', false),
  dataDirectory,
  databasePath: path.join(dataDirectory, 'database.sqlite'),
  storageDirectory: path.join(dataDirectory, 'storage'),
  stagingDirectory: path.join(dataDirectory, 'staging'),
  quarantineDirectory: path.join(dataDirectory, 'quarantine'),
  temporaryDirectory: path.join(dataDirectory, 'temporary'),
  logDirectory: path.join(dataDirectory, 'logs'),
  maxFileSize: integer('MAX_FILE_SIZE_MB', 100, 1, 2048) * 1024 * 1024,
  maxStorage: integer('MAX_STORAGE_MB', 5000, 1, 1048576) * 1024 * 1024,
  maxConcurrentUploads: integer('MAX_CONCURRENT_UPLOADS', 3, 1, 32),
  maxGlobalStaging: integer('MAX_GLOBAL_STAGING_MB', 300, 1, 1048576) * 1024 * 1024,
  maxGlobalQuarantine: integer('MAX_GLOBAL_QUARANTINE_MB', 1000, 1, 1048576) * 1024 * 1024,
  scanConcurrency: integer('SCAN_CONCURRENCY', 1, 1, 8),
  scanTimeoutMs: integer('SCAN_TIMEOUT_SECONDS', 120, 1, 3600) * 1000,
  maxScanFileSize: integer('MAX_SCAN_FILE_SIZE_MB', 100, 1, 2048) * 1024 * 1024,
  quarantineRetentionDays: integer('QUARANTINE_RETENTION_DAYS', 7, 1, 3650),
  maxArchiveEntries: integer('MAX_ARCHIVE_ENTRIES', 1000, 1, 100000),
  maxArchiveUncompressed: integer('MAX_ARCHIVE_UNCOMPRESSED_MB', 500, 1, 1048576) * 1024 * 1024,
  maxArchiveEntry: integer('MAX_ARCHIVE_ENTRY_MB', 100, 1, 1048576) * 1024 * 1024,
  maxArchiveRatio: integer('MAX_ARCHIVE_COMPRESSION_RATIO', 100, 1, 10000)
};

if (config.maxArchiveEntry > config.maxArchiveUncompressed) {
  throw new Error('MAX_ARCHIVE_ENTRY_MB cannot exceed MAX_ARCHIVE_UNCOMPRESSED_MB');
}

export default config;
