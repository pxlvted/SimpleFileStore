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

function limit(name, fallback, multiplier = 1) {
  const raw = process.env[name];
  const value = raw === undefined || raw === '' ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer (0 means unlimited)`);
  }
  if (value === 0) return Infinity;
  const scaledValue = value * multiplier;
  if (!Number.isSafeInteger(scaledValue)) {
    throw new Error(`${name} is too large to represent`);
  }
  return scaledValue;
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

const whitelistFeature = boolean('WHITELISTFEATURE', true);
const whitelist = new Set(
  (process.env.WHITELIST || (isDevelopment ? 'developer' : ''))
    .split(',')
    .map((username) => username.trim().toLowerCase())
    .filter(Boolean)
);
if (whitelistFeature && whitelist.size === 0) {
  throw new Error('WHITELIST must contain at least one username when WHITELISTFEATURE is enabled');
}

const config = {
  environment,
  httpsEnabled: boolean('HTTPS_ENABLED', false),
  port: integer('PORT', 3000, 1, 65535),
  host: process.env.HOST || (isDevelopment ? '127.0.0.1' : '0.0.0.0'),
  sessionSecret,
  whitelistFeature,
  whitelist,
  sessionMaxAgeMs: limit('SESSION_MAX_AGE_HOURS', 24, 60 * 60 * 1000),
  cookieSecure: boolean('COOKIE_SECURE', !isDevelopment),
  trustProxy: boolean('TRUST_PROXY', false),
  dataDirectory,
  databasePath: path.join(dataDirectory, 'database.sqlite'),
  storageDirectory: path.join(dataDirectory, 'storage'),
  stagingDirectory: path.join(dataDirectory, 'staging'),
  quarantineDirectory: path.join(dataDirectory, 'quarantine'),
  temporaryDirectory: path.join(dataDirectory, 'temporary'),
  logDirectory: path.join(dataDirectory, 'logs'),
  maxFileSize: limit('MAX_FILE_SIZE_MB', 100, 1024 * 1024),
  maxStorage: limit('MAX_STORAGE_MB', 5000, 1024 * 1024),
  maxConcurrentUploads: limit('MAX_CONCURRENT_UPLOADS', 3),
  maxGlobalStaging: limit('MAX_GLOBAL_STAGING_MB', 300, 1024 * 1024),
  maxGlobalQuarantine: limit('MAX_GLOBAL_QUARANTINE_MB', 1000, 1024 * 1024),
  scanConcurrency: limit('SCAN_CONCURRENCY', 1),
  scanTimeoutMs: limit('SCAN_TIMEOUT_SECONDS', 120, 1000),
  maxScanFileSize: limit('MAX_SCAN_FILE_SIZE_MB', 100, 1024 * 1024),
  quarantineRetentionMs: limit('QUARANTINE_RETENTION_DAYS', 7, 24 * 60 * 60 * 1000),
  maxArchiveEntries: limit('MAX_ARCHIVE_ENTRIES', 1000),
  maxArchiveUncompressed: limit('MAX_ARCHIVE_UNCOMPRESSED_MB', 500, 1024 * 1024),
  maxArchiveEntry: limit('MAX_ARCHIVE_ENTRY_MB', 100, 1024 * 1024),
  maxArchiveRatio: limit('MAX_ARCHIVE_COMPRESSION_RATIO', 100),
  nestedArchivesEnabled: boolean('NESTED_ARCHIVES_ENABLED', false)
};

export default config;
