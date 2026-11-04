# Simple File Store

A lightweight private file store built with Node.js, SQLite, a custom vanilla-JavaScript interface, and one Docker Compose application service. SQLite, the scan queue, and scan workers all run inside the application container; persistent user data lives in a named volume.

## What it provides

- Whitelist-gated registration, scrypt password hashes, SQLite-backed sessions, CSRF checks, and login rate limiting.
- Private folders, file uploads/downloads, text editing, search, recent/starred views, Trash, and per-user storage quotas.
- Owner-controlled file and folder sharing with registered-user search, read/add/remove/edit permissions, access revocation, and a “Shared with me” view.
- Collaborator-created files and folders inside a shared folder remain owned by the folder owner and count against that owner's storage quota.
- Streaming upload staging. A file cannot be downloaded or edited until its scan completes successfully.
- A persistent SQLite scan queue processed by memory-limited Node.js worker threads.
- A local EICAR test signature and a small executable-header heuristic. ZIP files are streamed through a bounded inspection path that rejects unsafe paths, symlinks, encryption, excessive expansion/entry counts/ratios, and nested archives.
- Security headers, same-origin cookies, a read-only container root, a non-root process, dropped capabilities, and a health check.

The scanner is deliberately small. `SCAN_PASSED` means only that this application's configured checks found no blocking condition. It is not a professional antivirus product and cannot guarantee that a file is safe. Unsupported archive formats and archives that exceed inspection limits remain inaccessible. Currently, ZIP is the only archive format inspected; other recognized archive formats fail closed.

## Sharing files and folders

Select **Share** on a file or folder you own, search for a registered username, select the recipient, then choose the permissions:

- **Read** is always enabled so recipients can view shared items and download files.
- **Add files and folders** is available for folders only.
- **Remove files** lets the recipient move shared files to the owner's Trash; only the owner can permanently delete them.
- **Edit text files** lets the recipient edit supported text files. Updates are scanned before the new version is made available.

The **Shared with me** navigation lists items shared directly with the signed-in user. Folder shares apply to their contents. Recipients can add content only when granted that permission. Added files and folders are stored as the owner's data, use the owner's quota, and remain under the owner's control. Owners can review or revoke access from the Share dialog. Permissions from multiple overlapping shares are additive.

## Requirements

- Node.js 20 or newer. Docker Engine and Docker Compose are optional.
- A reverse proxy with HTTPS for remote access. The application serves HTTP internally.

## Run locally with Node.js

Docker is not needed for local development. Install dependencies and start the app:

```sh
npm ci
npm start
```

Open <http://127.0.0.1:3000> and create an account with the username `developer` and a password of at least 12 characters. By default, the development server listens only on your computer, stores its database and files in `./data`, and uses a temporary session secret. You can register additional usernames by setting `WHITELIST` before starting, for example `WHITELIST=alice,bob`.

These defaults apply when `NODE_ENV` is unset or set to `development`, unless you override individual values. If you have a `.env` copied from `.env.example`, it contains production settings for Docker; for local development, set `NODE_ENV=development`, `HOST=127.0.0.1`, `DATA_DIRECTORY=./data`, `COOKIE_SECURE=false`, and `WHITELIST=developer` in that file. Keep Docker's `DATA_DIRECTORY=/app/data` when running Compose.

## Install

1. Copy `.env.example` to `.env`.
2. Set `WHITELIST` to comma-separated usernames permitted to register, and keep `WHITELISTFEATURE=TRUE` to enforce it. Set `WHITELISTFEATURE=FALSE` to allow any valid username to register and sign in.
3. Generate a unique session secret:

   ```sh
   openssl rand -hex 48
   ```

4. Put the generated value in `SESSION_SECRET`. Keep `.env` private and do not commit it.
5. Keep `COOKIE_SECURE=true` when HTTPS is terminated by your reverse proxy. For local-only HTTP testing, set it to `false`.
6. Start the single application service:

   ```sh
   docker compose up -d --build
   ```

The service binds to `127.0.0.1:3000` by default. Change `HOST_PORT` to select another host port. With `WHITELISTFEATURE=TRUE`, only usernames in `WHITELIST` can register or continue using an existing account; removing a username revokes access but leaves its files in the volume. With `WHITELISTFEATURE=FALSE`, the whitelist is ignored.

Useful commands:

```sh
docker compose ps
docker compose logs -f app
docker compose restart app
docker compose down
docker compose up -d --build
```

`docker compose down` does not remove the named volume. Do not use `docker compose down -v` unless you intend to delete all application data.

## Reverse proxy example

The Compose port is bound to loopback, so the app is not directly exposed to the network. A Caddy site can forward HTTPS requests to it:

```caddyfile
files.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

Set `COOKIE_SECURE=true`. Leave `TRUST_PROXY=false` unless the app is reached exclusively through a trusted proxy and you need Express to use forwarded client-IP headers for rate limiting. The app trusts one proxy hop when that setting is enabled; do not expose the container port publicly in that configuration.

## Configuration

All configuration is read at startup; restart the service after changing `.env`.

| Variable | Purpose |
|---|---|
| `PORT`, `HOST` | Internal listener (Compose expects port 3000). |
| `SESSION_SECRET` | Required random secret, at least 32 characters. |
| `WHITELISTFEATURE` | `TRUE` (default) enforces `WHITELIST`; `FALSE` disables whitelist checks. |
| `WHITELIST` | Case-insensitive allowed registration/login usernames when whitelist enforcement is enabled. |
| `SESSION_MAX_AGE_HOURS`, `COOKIE_SECURE`, `TRUST_PROXY` | Session and proxy behavior. |
| `DATA_DIRECTORY` | Persistent database, file, staging, quarantine, and log root. |
| `MAX_FILE_SIZE_MB`, `MAX_STORAGE_MB` | Per-file and per-user storage limits. Trash and pending uploads count toward storage. |
| `MAX_CONCURRENT_UPLOADS`, `MAX_GLOBAL_STAGING_MB` | Upload concurrency and aggregate staging bound. |
| `MAX_GLOBAL_QUARANTINE_MB`, `QUARANTINE_RETENTION_DAYS` | Quarantine storage bound and retention. |
| `SCAN_CONCURRENCY`, `SCAN_TIMEOUT_SECONDS`, `MAX_SCAN_FILE_SIZE_MB` | Scanner workers, timeout, and accepted inspection size. |
| `MAX_ARCHIVE_ENTRIES`, `MAX_ARCHIVE_UNCOMPRESSED_MB`, `MAX_ARCHIVE_ENTRY_MB`, `MAX_ARCHIVE_COMPRESSION_RATIO` | ZIP inspection limits. |
| `HOST_PORT`, `CONTAINER_MEMORY_LIMIT`, `CONTAINER_CPU_LIMIT` | Compose host port and container resource bounds. |

The example `SESSION_SECRET` is a placeholder and intentionally prevents startup until replaced. Scanner and archive inspection cannot be disabled through environment configuration.

## Backups and recovery

The named volume contains the SQLite database and all files. Stop the service before copying it to get a consistent snapshot:

```sh
docker compose stop app
docker run --rm -v simplefilestore_app_data:/source:ro -v "$PWD:/backup" alpine \
  tar -czf /backup/simple-file-store-data.tar.gz -C /source .
docker compose start app
```

Compose may prefix the volume name with the project directory. Find the exact name with `docker volume ls` and substitute it for `simplefilestore_app_data`. Store backups encrypted and separately from the server.

To restore, stop the application, keep a copy of the current volume, and extract the archive into the same named volume:

```sh
docker compose stop app
docker run --rm -v simplefilestore_app_data:/destination -v "$PWD:/backup" alpine \
  sh -c 'tar -xzf /backup/simple-file-store-data.tar.gz -C /destination'
docker compose start app
```

For an online SQLite-only snapshot, use SQLite's backup API rather than copying only `database.sqlite` while the service is running. A full stopped-volume backup also preserves staged scan jobs and quarantined data. Rebuilding or recreating the app container does not delete the named volume.

## Development and tests

Requires Node.js 20 or newer:

```sh
npm ci
npm test
npm start
```

For local development, create a `.env` with a random `SESSION_SECRET`, `WHITELIST`, and `COOKIE_SECURE=false`. The tests start an isolated local server and use harmless text and the standard EICAR test signature; they do not use real malware.

## Important limitations

- This is private file storage, not a guarantee of malware detection. The built-in signature set is intentionally tiny and is not an antivirus database.
- ZIP is the only archive format that is inspected. Unsupported/encrypted/malformed archives, nested ZIPs, and limit violations fail closed instead of being made available.
- The text editor accepts the documented text extensions up to 1 MiB. Edited bytes are rescanned before replacing the prior accessible version.
- HTML and script files are always downloaded as attachments with `nosniff`; uploaded content is not served as active same-origin web content.
- There are no public sharing links or account recovery flow. Configure the whitelist and keep volume backups before deployment.
