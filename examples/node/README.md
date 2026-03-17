# Hive OAuth Example (Node.js)

A simple OAuth 2.0 example showing how a basic UI connects to Hive's OAuth server and initiates the Authorization Code flow.

## Setup

Copy the environment file:

```bash
cp .env.example .env
```

Fill in your Hive OAuth credentials.

## Install

```bash
npm install
```

## Run

In one terminal, start the UI:

```bash
npm run ui
```

In another terminal, start the OAuth server:

```bash
npm run server
```

## Open

```text
http://localhost:3000
```

## Redirect URI

Make sure your Hive OAuth Application includes:

```text
http://localhost:4000/callback
```
