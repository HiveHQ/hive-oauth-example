/**
 * pkce.js — PKCE (Proof Key for Code Exchange) helpers
 *
 * PKCE is a security extension to OAuth 2.0 that prevents authorization
 * code interception attacks. It works by having the client generate a random
 * secret (the "code verifier"), then sending a hashed version of it (the
 * "code challenge") with the authorization request. Later, when exchanging
 * the code for a token, the client sends the original verifier — the server
 * hashes it and confirms it matches what was sent earlier.
 *
 * No dependencies — uses the browser's built-in Web Crypto API.
 */

/**
 * Generates a cryptographically random code verifier.
 *
 * The verifier is a random string between 43–128 characters (per RFC 7636).
 * We use 64 random bytes encoded as base64url, giving us 86 characters.
 *
 * @returns {string} A base64url-encoded random string.
 */
export function generateCodeVerifier() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(64));
  return base64urlEncode(randomBytes);
}

/**
 * Derives the code challenge from the verifier using SHA-256.
 *
 * The challenge is sent in the authorization request so the server can
 * store it. Later, the server hashes the verifier we send during token
 * exchange and checks that it matches this challenge.
 *
 * @param {string} verifier - The code verifier string.
 * @returns {Promise<string>} A base64url-encoded SHA-256 hash of the verifier.
 */
export async function generateCodeChallenge(verifier) {
  const encoded = new TextEncoder().encode(verifier);
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  return base64urlEncode(new Uint8Array(hashBuffer));
}

/**
 * Encodes a Uint8Array as a base64url string (no padding, URL-safe).
 *
 * base64url replaces `+` with `-` and `/` with `_`, and strips `=` padding.
 * This makes it safe to use in URLs without percent-encoding.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function base64urlEncode(bytes) {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
