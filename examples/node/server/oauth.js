import crypto from "crypto";

const CONFIG = {
  clientId: process.env.HIVE_CLIENT_ID,
  clientSecret: process.env.HIVE_CLIENT_SECRET,
  authorizationUrl: process.env.HIVE_AUTHORIZATION_URL,
  tokenUrl: process.env.HIVE_TOKEN_URL,
  redirectUri: process.env.HIVE_REDIRECT_URI,
  scope: process.env.HIVE_SCOPE,
};

function randomString(byteLength) {
  return crypto.randomBytes(byteLength).toString("base64url");
}

function createCodeChallenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

export function buildAuthorizationUrl() {
  const codeVerifier = randomString(64);
  const codeChallenge = createCodeChallenge(codeVerifier);
  const state = randomString(32);

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

export async function exchangeCodeForToken({ code, codeVerifier }) {
  const response = await fetch(CONFIG.tokenUrl, {
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

export function sanitizeTokenResponse(tokenResponse) {
  const accessToken = tokenResponse.access_token || "";
  const refreshToken = tokenResponse.refresh_token || "";

  return {
    token_type: tokenResponse.token_type || null,
    expires_in: tokenResponse.expires_in || null,
    scope: tokenResponse.scope || null,
    access_token_preview: accessToken ? `${accessToken.slice(0, 12)}...` : null,
    refresh_token_preview: refreshToken
      ? `${refreshToken.slice(0, 12)}...`
      : null,
  };
}
