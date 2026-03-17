# Hive OAuth Example — Node.js

Express implementation of the Hive API v2 OAuth 2.0 Authorization Code Flow with PKCE.

## Setup

```bash
cd examples/node
cp .env.example .env
```

Fill in your Hive OAuth credentials in `.env`.

## Install

```bash
npm install
```

## Run

In one terminal, start the OAuth server:

```bash
npm run server
```

In another terminal, serve the UI:

```bash
npm run ui
```

Open http://localhost:3000.

## Redirect URI

Register the following in your Hive OAuth Application:

```
http://localhost:4000/callback
```
