import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import requests

CLIENT_ID = os.getenv("HIVE_CLIENT_ID")
CLIENT_SECRET = os.getenv("HIVE_CLIENT_SECRET")
AUTHORIZATION_URL = os.getenv("HIVE_AUTHORIZATION_URL")
TOKEN_URL = os.getenv("HIVE_TOKEN_URL")
REDIRECT_URI = os.getenv("HIVE_REDIRECT_URI")
SCOPE = os.getenv("HIVE_SCOPE")


def random_string(byte_length: int) -> str:
    return secrets.token_urlsafe(byte_length)


def create_code_challenge(code_verifier: str) -> str:
    # Derive the code challenge by hashing the verifier with SHA-256.
    # The challenge is sent to Hive upfront; the verifier is sent later during
    # token exchange so Hive can verify they match.
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def build_authorization_url() -> dict:
    # Generate PKCE values and a random state for CSRF protection.
    code_verifier = random_string(64)
    code_challenge = create_code_challenge(code_verifier)
    state = random_string(32)

    query = urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )

    # Return the URL plus the values that must be saved to the session.
    return {
        "authorization_url": f"{AUTHORIZATION_URL}?{query}",
        "state": state,
        "code_verifier": code_verifier,
    }


def exchange_code_for_token(code: str, code_verifier: str) -> dict:
    # Exchange the authorization code for an access token.
    # The client_secret stays here on the server — it is never exposed to the browser.
    if TOKEN_URL is None:
        raise ValueError("TOKEN_URL is not configured")

    response = requests.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": code_verifier,
        },
        timeout=30,
    )

    try:
        data = response.json()
    except ValueError:
        data = {}

    if not response.ok:
        raise Exception(
            data.get("error_description")
            or data.get("error")
            or f"HTTP {response.status_code}"
        )

    return data
