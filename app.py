from flask import Flask, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth
import time
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 

app = Flask(__name__)
app.secret_key = "test_secret_key_123" 
CONF_URL = "https://keytrain.uattdtydomain.gov.hk"
CLIENT_ID = "test.oidc"
CLIENT_SECRET = "gSx9sKPdqDoI6etOFMW6MJHVlV1OFUVF"
# -----------------------

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=CONF_URL,
    client_kwargs={"scope": "openid profile email"},
)


TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OIDC Flask Test</title>
    <style>
        body { font-family: sans-serif; margin: 40px; line-height: 1.6; }
        .token-box { background: #f4f4f4; padding: 10px; border: 1px solid #ddd; word-break: break-all; white-space: pre-wrap; font-family: monospace; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; }
        td, th { padding: 10px; border: 1px solid #ccc; text-align: left; }
        th { background: #eee; width: 200px; }
        .btn { padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Keycloak OIDC 測試專案</h1>
    {% if not user %}
        <p>目前未登入，請使用 Keycloak 驗證。</p>
        <a class="btn" href="{{ url_for('login') }}">登入系統</a>
    {% else %}
        <a class="btn" style="background: #dc3545;" href="{{ url_for('logout') }}">登出</a>
        <br><br>
        <table>
            <tr><th>Email</th><td>{{ user.email }}</td></tr>
            <tr><th>Nombre (Name)</th><td>{{ user.name }}</td></tr>
            <tr><th>Preferred Username</th><td>{{ user.preferred_username }}</td></tr>
            <tr><th>Expires In (Timestamp)</th><td>{{ token.expires_at }}</td></tr>
            <tr><th>Access Token</th><td><div class="token-box">{{ token.access_token }}</div></td></tr>
            <tr><th>Refresh Token</th><td><div class="token-box">{{ token.refresh_token }}</div></td></tr>
        </table>
    {% endif %}
</body>
</html>
"""

@app.route("/")
def index():
    user = session.get("user")
    token = session.get("token")
    return render_template_string(TEMPLATE, user=user, token=token)

@app.route("/login")
def login():
    redirect_uri = url_for("auth", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route("/auth")
def auth():
    token = oauth.keycloak.authorize_access_token()
    user = token.get('userinfo') 
    session["user"] = user
    session["token"] = token
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    
    base_url = url_for("index", _external=True)
    
    logout_url = (
        f"{CONF_URL}/protocol/openid-connect/logout" 
        f"?post_logout_redirect_uri={base_url}"
        f"&client_id={CLIENT_ID}"
    )
    return redirect(logout_url)

if __name__ == "__main__":

    app.run(port=5000, debug=True)


