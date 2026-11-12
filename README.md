# Simple File Store

A self-hosted file store for uploading, organizing, searching, editing, and sharing files with others.

## Run locally

Requires Node.js 20 or newer.

```sh
npm ci
npm start
```

## Run with Docker Compose

Set these values in a `.env` file:

```env
SESSION_SECRET=replace-this-with-a-long-random-secret
WHITELIST=your-username
```

```sh
docker compose up -d
```

set `COOKIE_SECURE=false` for local HTTP
