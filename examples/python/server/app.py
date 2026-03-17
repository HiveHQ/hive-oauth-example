from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, session
from flask_cors import CORS
from oauth import build_authorization_url, exchange_code_for_token

load_dotenv()

app = Flask(__name__)
app.secret_key = "hive-oauth-example-session"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

UI_ORIGIN = "http://localhost:3000"

# Allow the UI (served on port 3000) to make credentialed requests to this server.
CORS(app, supports_credentials=True, origins=[UI_ORIGIN])


def redirect_error(message: str):
    params = urlencode({"status": "error", "message": message})
    return redirect(f"{UI_ORIGIN}/callback.html?{params}")


# Step 1: Start the OAuth flow.
# Generates PKCE values and state, saves them to the session, then redirects
# the user to Hive's authorization page.
@app.get("/auth/start")
def auth_start():
    auth = build_authorization_url()

    session["oauth_state"] = auth["state"]
    session["code_verifier"] = auth["code_verifier"]
    session["auth_result"] = None

    return redirect(auth["authorization_url"])


# Step 2: Handle the redirect back from Hive.
# Validates state, exchanges the authorization code for a token, and redirects
# back to the UI with the result status.
@app.get("/callback")
def callback():
    error = request.args.get("error")
    code = request.args.get("code")
    state = request.args.get("state")

    if error:
        return redirect_error(request.args.get("error_description") or error)
    if not code:
        return redirect_error("Missing authorization code.")
    if not session.get("oauth_state") or state != session.get("oauth_state"):
        return redirect_error("State mismatch.")
    if not session.get("code_verifier"):
        return redirect_error("Missing PKCE code verifier.")

    try:
        token_response = exchange_code_for_token(code, session["code_verifier"])

        # Clear PKCE values and store the token response for the UI to retrieve.
        session["oauth_state"] = None
        session["code_verifier"] = None
        session["auth_result"] = token_response

        return redirect(f"{UI_ORIGIN}/callback.html?status=success")
    except Exception as error:
        return redirect_error(str(error))


# Step 3: Return the token response to the UI.
# The token is kept server-side in the session and served via this endpoint —
# it is never passed through the browser URL or stored client-side.
@app.get("/auth/result")
def auth_result():
    auth_result = session.get("auth_result")

    if not auth_result:
        return jsonify({"error": "No authorization result found in session."}), 404

    return jsonify(auth_result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000, debug=True)
