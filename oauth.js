/**
 * oauth.js — Hive API v2 OAuth 2.0 Authorization Code Flow with PKCE
 *
 * This file handles the two main steps of the OAuth flow:
 *
 *   1. AUTHORIZATION — Redirect the user to Hive's authorization endpoint.
 *      Before redirecting, we generate a PKCE code verifier + challenge and
 *      save the verifier in sessionStorage so we can use it in step 2.
 *
 *   2. TOKEN EXCHANGE — After Hive redirects back to our callback URL with
 *      an authorization code, we exchange that code (+ the saved verifier)
 *      for an access token.
 */

import { generateCodeVerifier, generateCodeChallenge } from "./pkce.js";

// ---------------------------------------------------------------------------
// Configuration — replace these values with your own app's credentials.
// ---------------------------------------------------------------------------

const CONFIG = {
  // Your OAuth application's client ID and client secret, issued by Hive.
  clientId: "U0YZzvhKNBtCD0ol6U1aoWi11EKeBDe2B4AObmik",
  clientSecret:
    "yIcUHQ1skjwwJO9iOQzSML4Z2Fe04I7kLYmrirlEzIK9k3OigCN5HyVHBDRBZF16RAWlLYnZwkcd9pWb8LZp90c63fsqRGI1BcjIxq4rOXM8CeNCR2XVdQ7e5LmD0pty",

  // Where Hive should redirect after the user authorizes (or denies) access.
  // Must exactly match one of the redirect URIs registered on your application.
  redirectUri: "http://localhost:9123/callback.html",

  // Hive API v2 OAuth endpoints.
  // authorizationEndpoint: "https://app.hive.co/oauth/api/authorize/",
  // tokenEndpoint: "https://app.hive.co/oauth/api/token/",

  authorizationEndpoint: "https://local.hive.co/oauth/api/authorize/",
  tokenEndpoint: "https://local.hive.co/api/v2/oauth/token/",

  // The scopes your application needs. Space-separated.
  scope: "events:write orders:write contacts:write segments:write",
};

// ---------------------------------------------------------------------------
// Step 1: Start the authorization flow
// ---------------------------------------------------------------------------

/**
 * Kicks off the OAuth authorization code flow with PKCE.
 *
 * Call this when the user clicks "Connect to Hive". It will:
 *   1. Generate a PKCE code verifier and challenge.
 *   2. Save the verifier to sessionStorage (we need it later for token exchange).
 *   3. Build the authorization URL with all required parameters.
 *   4. Redirect the browser to Hive's authorization page.
 */
export async function startAuthFlow() {
  // Generate the PKCE pair. The verifier is our secret; the challenge is its hash.
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Persist the verifier across the redirect. We'll read it back in the callback.
  // sessionStorage is scoped to the current tab and cleared when the tab closes.
  sessionStorage.setItem("pkce_code_verifier", codeVerifier);

  // Generate a random `state` value to protect against CSRF attacks.
  // We send it with the authorization request and verify it matches when
  // Hive redirects back to our callback URL.
  const state = generateState();
  sessionStorage.setItem("oauth_state", state);

  // Build the authorization URL query string.
  const params = new URLSearchParams({
    response_type: "code", // We want an authorization code back.
    client_id: CONFIG.clientId,
    redirect_uri: CONFIG.redirectUri,
    scope: CONFIG.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256", // SHA-256 is the only method we support.
  });

  // Send the user to Hive's authorization page.
  window.location.href = `${CONFIG.authorizationEndpoint}?${params}`;
}

// ---------------------------------------------------------------------------
// Step 2: Handle the callback and exchange the code for a token
// ---------------------------------------------------------------------------

/**
 * Handles the callback after Hive redirects back to our app.
 *
 * Reads the `code` and `state` from the URL, verifies state, then POSTs to
 * Hive's token endpoint to exchange the authorization code for an access token.
 *
 * @returns {Promise<Object>} The token response from Hive (access_token, etc.)
 * @throws {Error} If state is invalid, or the token request fails.
 */
export async function handleCallback() {
  const params = new URLSearchParams(window.location.search);

  // If Hive returned an error (e.g. user denied access), surface it immediately.
  if (params.has("error")) {
    throw new Error(
      `Authorization error: ${params.get("error")} — ${params.get("error_description") ?? ""}`,
    );
  }

  const code = params.get("code");
  const returnedState = params.get("state");

  if (!code) {
    throw new Error("No authorization code found in the callback URL.");
  }

  // Verify the state parameter matches what we sent. This protects against
  // cross-site request forgery (CSRF) attacks.
  const savedState = sessionStorage.getItem("oauth_state");
  if (!savedState || returnedState !== savedState) {
    throw new Error("State mismatch — possible CSRF attack. Aborting.");
  }

  // Retrieve the code verifier we saved before the redirect.
  const codeVerifier = sessionStorage.getItem("pkce_code_verifier");
  if (!codeVerifier) {
    throw new Error(
      "No code verifier found in sessionStorage. Did you start the flow from index.html?",
    );
  }

  // Exchange the authorization code for an access token.
  // We send the original code verifier; Hive hashes it and checks it matches
  // the code challenge we sent in step 1.
  const response = await fetch(CONFIG.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: CONFIG.redirectUri,
      client_id: CONFIG.clientId,
      client_secret: CONFIG.clientSecret,
      code_verifier: codeVerifier, // PKCE: proves we initiated the request.
    }),
  });

  // Clean up sensitive values from storage now that we're done with them.
  sessionStorage.removeItem("pkce_code_verifier");
  sessionStorage.removeItem("oauth_state");

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(
      `Token request failed (${response.status}): ${error.error_description ?? error.error ?? "Unknown error"}`,
    );
  }

  return response.json();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generates a random state string for CSRF protection.
 * @returns {string}
 */
function generateState() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
