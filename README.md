# Simple File Store

A self-hosted file store for uploading, organizing, searching, editing, and sharing files with other registered users.

## Run locally

Requires Node.js 20 or newer.

```sh
npm ci
npm start
```

Open <http://127.0.0.1:3000> and sign in as `developer` with a password of at least 12 characters. Local files and the database are stored in `./data`.

Run the tests with `npm test`.

## Run with Docker Compose

Set these values in a `.env` file:

```env
SESSION_SECRET=replace-this-with-a-long-random-secret
WHITELIST=your-username
```

Generate a secret with `openssl rand -hex 48`, then start the app:

```sh
docker compose up -d
```

The app is available on port `3012`. Its data is kept in `/DATA/AppData/$AppID/data`. Set `WHITELIST` to the usernames allowed to register. The Compose setup requires HTTPS for remote access; set `COOKIE_SECURE=false` only for local HTTP testing.

To stop the app without deleting its data:

```sh
docker compose down
```

## Features and limits

- Private folders, uploads, downloads, search, trash, and storage quotas.
- Share files and folders with registered users and choose their permissions.
- Files are checked before they can be downloaded or edited. The built-in checks are limited and do not guarantee a file is safe; ZIP is the only archive format inspected.
- There are no public sharing links or account recovery.

Back up the app's data directory regularly. Use a reverse proxy with HTTPS when making the app available remotely.
