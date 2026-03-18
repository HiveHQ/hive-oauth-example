# Hive OAuth Example — Python

Flask implementation of the Hive API v2 OAuth 2.0 Authorization Code Flow with PKCE.

## Requirements

Python 3.10+

## Setup

```bash
cd examples/python
cp .env.example .env
```

Fill in your Hive OAuth credentials in `.env`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

In one terminal, start the OAuth server:

```bash
python server/app.py
```

In another terminal, serve the UI:

```bash
python -m http.server 3000 --directory ui
```

Open http://localhost:3000.

## Redirect URI

Register the following in your Hive OAuth Application:

```
http://localhost:4000/callback
```
