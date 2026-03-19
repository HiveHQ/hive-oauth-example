# Hive OAuth 2.0 Example

![Hive OAuth Example Banner](https://s3.us-east-1.amazonaws.com/hive.public/hive_oauth_example_banner.png)

Reference implementations of the OAuth 2.0 authorization code flow with PKCE for Hive API v2.
Each example includes a minimal UI to trigger the flow and a backend server to handle the token exchange securely.

## Available examples

- [`examples/python`](examples/python) — Flask server + static HTML UI
- [`examples/node`](examples/node) — Express server + static HTML UI

## Documentation

For detailed documentation on the Hive API v2 OAuth 2.0 authorization code flow with PKCE, see the [Hive API developer documentation](https://hivealive.notion.site/Hive-API-Beta-Documentation-30473434b83b805d8853c696e6ec6875).

## How it works

The flow involves two servers: your backend (port 4000) and a simple static file server for the UI (port 3000). The browser only ever talks to your backend — the `client_secret` and token response never touch the browser directly.

```mermaid
sequenceDiagram
    actor User
    participant UI as UI (port 3000)
    participant Server as Your Server (port 4000)
    participant Hive

    User->>UI: Click "Connect to Hive"
    UI->>Server: GET /auth/start
    Server->>Server: Generate code_verifier + code_challenge (PKCE)
    Server->>Server: Save verifier and state to session
    Server->>Hive: Redirect user with client_id, scope, code_challenge

    Hive->>User: Show login / authorization screen
    User->>Hive: Approve access

    Hive->>Server: Redirect to /callback?code=AUTH_CODE
    Server->>Server: Validate state matches session
    Server->>Hive: POST /token (code + code_verifier + client_secret)
    Hive->>Server: Return access_token
    Server->>Server: Save token to session
    Server->>UI: Redirect to /callback.html?status=success

    UI->>Server: GET /auth/result
    Server->>UI: Return token response from session
    UI->>User: Display token details
```

## Why a server?

The token exchange requires a `client_secret` which must never be exposed in client-side code. The server handles the exchange and stores the token in a session — the browser only receives a success/error status via the redirect URL.
