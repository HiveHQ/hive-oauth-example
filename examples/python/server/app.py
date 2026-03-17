from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, session
from flask_cors import CORS
from oauth import (
    build_authorization_url,
    exchange_code_for_token,
)

load_dotenv()

app = Flask(__name__)
app.secret_key = "hive-oauth-example-session"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

UI_ORIGIN = "http://localhost:3000"

CORS(app, supports_credentials=True, origins=[UI_ORIGIN])


@app.get("/auth/start")
def auth_start():
    auth = build_authorization_url()

    session["oauth_state"] = auth["state"]
    session["code_verifier"] = auth["code_verifier"]
    session["auth_result"] = None

    return redirect(auth["authorization_url"])


@app.get("/callback")
def callback():
    error = request.args.get("error")
    error_description = request.args.get("error_description")
    code = request.args.get("code")
    state = request.args.get("state")

    if error:
        params = urlencode({"status": "error", "message": error_description or error})
        return redirect(f"{UI_ORIGIN}/callback.html?{params}")

    if not code:
        params = urlencode(
            {"status": "error", "message": "Missing authorization code."}
        )
        return redirect(f"{UI_ORIGIN}/callback.html?{params}")

    if not session.get("oauth_state") or state != session.get("oauth_state"):
        params = urlencode({"status": "error", "message": "State mismatch."})
        return redirect(f"{UI_ORIGIN}/callback.html?{params}")

    if not session.get("code_verifier"):
        params = urlencode(
            {"status": "error", "message": "Missing PKCE code verifier."}
        )
        return redirect(f"{UI_ORIGIN}/callback.html?{params}")

    try:
        token_response = exchange_code_for_token(code, session["code_verifier"])

        session["oauth_state"] = None
        session["code_verifier"] = None
        session["auth_result"] = token_response

        params = urlencode({"status": "success"})
        return redirect(f"{UI_ORIGIN}/callback.html?{params}")
    except Exception as error:
        params = urlencode({"status": "error", "message": str(error)})
        return redirect(f"{UI_ORIGIN}/callback.html?{params}")


@app.get("/auth/result")
def auth_result():
    auth_result = session.get("auth_result")

    if not auth_result:
        return jsonify({"error": "No authorization result found in session."}), 404

    return jsonify(auth_result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000, debug=True)
