import dotenv from "dotenv";
import express from "express";
import session from "express-session";
import cors from "cors";
import { buildAuthorizationUrl, exchangeCodeForToken } from "./oauth.js";

dotenv.config();

const app = express();
const UI_ORIGIN = "http://localhost:3000";
const PORT = 4000;

// Allow the UI (served on port 3000) to make credentialed requests to this server.
app.use(cors({ origin: UI_ORIGIN, credentials: true }));

// Session is used to persist the PKCE verifier and state across the redirect to
// Hive and back. The token response is also stored here so the UI can fetch it.
app.use(
  session({
    secret: "hive-oauth-example-session",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: false },
  }),
);

// Step 1: Start the OAuth flow.
// Generates PKCE values and state, saves them to the session, then redirects
// the user to Hive's authorization page.
app.get("/auth/start", (req, res) => {
  const { authorizationUrl, state, codeVerifier } = buildAuthorizationUrl();

  req.session.oauthState = state;
  req.session.codeVerifier = codeVerifier;
  req.session.authResult = null;

  res.redirect(authorizationUrl);
});

// Step 2: Handle the redirect back from Hive.
// Validates state, exchanges the authorization code for a token, and redirects
// back to the UI with the result status.
app.get("/callback", async (req, res) => {
  const { error, error_description, code, state } = req.query;

  const redirectError = (message) => {
    const params = new URLSearchParams({ status: "error", message });
    res.redirect(`${UI_ORIGIN}/callback.html?${params.toString()}`);
  };

  if (error) return redirectError(error_description || error);
  if (!code) return redirectError("Missing authorization code.");
  if (!req.session.oauthState || state !== req.session.oauthState) return redirectError("State mismatch.");
  if (!req.session.codeVerifier) return redirectError("Missing PKCE code verifier.");

  try {
    const tokenResponse = await exchangeCodeForToken({
      code,
      codeVerifier: req.session.codeVerifier,
    });

    // Clear PKCE values and store the token response for the UI to retrieve.
    req.session.oauthState = null;
    req.session.codeVerifier = null;
    req.session.authResult = tokenResponse;

    req.session.save((saveError) => {
      if (saveError) return redirectError("Could not save session.");
      res.redirect(`${UI_ORIGIN}/callback.html?status=success`);
    });
  } catch (err) {
    redirectError(err.message);
  }
});

// Step 3: Return the token response to the UI.
// The token is kept server-side in the session and served via this endpoint —
// it is never passed through the browser URL or stored client-side.
app.get("/auth/result", (req, res) => {
  if (!req.session.authResult) {
    return res.status(404).json({ error: "No authorization result found in session." });
  }

  res.json(req.session.authResult);
});

app.listen(PORT, () => {
  console.log(`OAuth server listening on http://localhost:${PORT}`);
});
