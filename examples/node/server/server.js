import dotenv from "dotenv";
import express from "express";
import session from "express-session";
import cors from "cors";
import {
  buildAuthorizationUrl,
  exchangeCodeForToken,
  sanitizeTokenResponse,
} from "./oauth.js";

dotenv.config();

const app = express();
const UI_ORIGIN = "http://localhost:3000";
const PORT = 4000;

app.use(
  cors({
    origin: UI_ORIGIN,
    credentials: true,
  }),
);

app.use(
  session({
    secret: "hive-oauth-example-session",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
    },
  }),
);

app.get("/auth/start", (req, res) => {
  const { authorizationUrl, state, codeVerifier } = buildAuthorizationUrl();

  req.session.oauthState = state;
  req.session.codeVerifier = codeVerifier;
  req.session.authResult = null;

  console.log("/auth/start");
  console.log("session id:", req.sessionID);
  console.log("session:", req.session);

  res.redirect(authorizationUrl);
});

app.get("/callback", async (req, res) => {
  const error = req.query.error;
  const errorDescription = req.query.error_description;
  const code = req.query.code;
  const state = req.query.state;

  if (error) {
    const params = new URLSearchParams({
      status: "error",
      message: errorDescription || error,
    });
    return res.redirect(`${UI_ORIGIN}/callback.html?${params.toString()}`);
  }

  if (!code) {
    const params = new URLSearchParams({
      status: "error",
      message: "Missing authorization code.",
    });
    return res.redirect(`${UI_ORIGIN}/callback.html?${params.toString()}`);
  }

  if (!req.session.oauthState || state !== req.session.oauthState) {
    const params = new URLSearchParams({
      status: "error",
      message: "State mismatch.",
    });
    return res.redirect(`${UI_ORIGIN}/callback.html?${params.toString()}`);
  }

  if (!req.session.codeVerifier) {
    const params = new URLSearchParams({
      status: "error",
      message: "Missing PKCE code verifier.",
    });
    return res.redirect(`${UI_ORIGIN}/callback.html?${params.toString()}`);
  }

  try {
    const tokenResponse = await exchangeCodeForToken({
      code,
      codeVerifier: req.session.codeVerifier,
    });

    req.session.oauthState = null;
    req.session.codeVerifier = null;
    req.session.authResult = tokenResponse;

    console.log("/callback");
    console.log("session id:", req.sessionID);
    console.log("authResult being saved:", req.session.authResult);

    req.session.save((saveError) => {
      if (saveError) {
        const params = new URLSearchParams({
          status: "error",
          message: "Could not save session.",
        });
        return res.redirect(`${UI_ORIGIN}/callback.html?${params.toString()}`);
      }

      res.redirect(`${UI_ORIGIN}/callback.html?status=success`);
    });
  } catch (error) {
    const params = new URLSearchParams({
      status: "error",
      message: error.message,
    });
    res.redirect(`${UI_ORIGIN}/callback.html?${params.toString()}`);
  }
});

app.get("/auth/result", (req, res) => {
  console.log("/auth/result");
  console.log("session id:", req.sessionID);
  console.log("session.authResult:", req.session.authResult);

  if (!req.session.authResult) {
    return res.status(404).json({
      error: "No authorization result found in session.",
    });
  }

  res.json(req.session.authResult);
});

app.listen(PORT, () => {
  console.log(`OAuth server listening on http://localhost:${PORT}`);
});
