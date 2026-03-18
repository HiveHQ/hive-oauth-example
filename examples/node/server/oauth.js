import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const CONFIG = {
  clientId: process.env.HIVE_CLIENT_ID,
  clientSecret: process.env.HIVE_CLIENT_SECRET,
  authorizationUrl: process.env.HIVE_AUTHORIZATION_URL,
  tokenUrl: process.env.HIVE_TOKEN_URL,
  redirectUri: process.env.HIVE_REDIRECT_URI,
  scope: process.env.HIVE_SCOPE,
};

// Generate a cryptographically random base64url string.
function randomString(byteLength) {
  return crypto.randomBytes(byteLength).toString("base64url");
}

// Derive the code challenge by hashing the verifier with SHA-256.
// The challenge is sent to Hive upfront; the verifier is sent later during
// token exchange so Hive can verify they match.
function createCodeChallenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

// Build the Hive authorization URL with all required OAuth + PKCE parameters.
// Returns the URL to redirect the user to, plus the state and codeVerifier
// which must be saved in the session for use in the callback.
export function buildAuthorizationUrl() {
  const codeVerifier = randomString(64);
  const codeChallenge = createCodeChallenge(codeVerifier);
  const state = randomString(32); // Random value to protect against CSRF attacks.

  const query = new URLSearchParams({
    response_type: "code",
    client_id: CONFIG.clientId,
    redirect_uri: CONFIG.redirectUri,
    scope: CONFIG.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  return {
    authorizationUrl: `${CONFIG.authorizationUrl}?${query.toString()}`,
    state,
    codeVerifier,
  };
}

// Exchange the authorization code for an access token.
// The client_secret stays here on the server — it is never exposed to the browser.
export async function exchangeCodeForToken({ code, codeVerifier }) {
  const response = await fetch(CONFIG.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: CONFIG.redirectUri,
      client_id: CONFIG.clientId,
      client_secret: CONFIG.clientSecret,
      code_verifier: codeVerifier,
    }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error_description || data.error || `HTTP ${response.status}`,
    );
  }

  return data;
}
