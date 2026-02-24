from flask import Flask, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth
import os


#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-fallback-key'


CLIENT_ID = "test.oidc"
CLIENT_SECRET = "gSx9sKPdqDoI6etOFMW6MJHVlV1OFUVF"
MY_IP = "testoidc.uattdtydomain.gov.hk"
redirect_uri = f"http://{MY_IP}/auth" 



KEYCLOAK_METADATA = {
    "issuer": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc",
    "authorization_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/auth",
    "token_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/token",
    "userinfo_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/userinfo",
    "end_session_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/logout",
    "jwks_uri": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/certs",
}

oauth = OAuth(app)

oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=None, 
    authorize_url=KEYCLOAK_METADATA["authorization_endpoint"],
    access_token_url=KEYCLOAK_METADATA["token_endpoint"],
    userinfo_endpoint=KEYCLOAK_METADATA["userinfo_endpoint"],
    jwks_uri=KEYCLOAK_METADATA["jwks_uri"],
    client_kwargs={
        "scope": "openid profile email",
        "verify": False  
    },
)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OIDC Flask Test</title>
    <style>
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh;
            background-color: #f0f2f5; 
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 600px;
            width: 90%;
        }
        .token-box { 
            background: #f8f9fa; 
            padding: 15px; 
            border: 1px solid #dee2e6; 
            word-break: break-all; 
            white-space: pre-wrap; 
            font-family: 'Courier New', monospace; 
            font-size: 11px; 
            text-align: left;
            margin-top: 10px;
            max-height: 200px;
            overflow-y: auto;
        }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        td, th { padding: 12px; border: 1px solid #eee; text-align: left; }
        th { background: #f8f9fa; width: 30%; }
        .btn { 
            display: inline-block;
            padding: 12px 30px; 
            background: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 6px; 
            font-weight: bold;
            transition: background 0.3s;
        }
        .btn:hover { background: #0056b3; }
        h1 { color: #333; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Keycloak OIDC 測試專案</h1>
        {% if not user %}
            <p style="color: #666; margin-bottom: 30px;">目前未登入，請點擊下方按鈕進行驗證。</p>
            <a class="btn" href="{{ url_for('login') }}">進入系統登入</a>
        {% else %}
            <div style="text-align: right;">
                <a class="btn" style="background: #dc3545;" href="{{ url_for('logout') }}">登出</a>
            </div>
            <br>
            <table>
                <tr><th>Email</th><td>{{ user.email }}</td></tr>
                <tr><th>Name</th><td>{{ user.name }}</td></tr>
                <tr><th>Username</th><td>{{ user.preferred_username }}</td></tr>
            </table>
            <p style="text-align: left; font-weight: bold; margin-top: 20px;">Access Token:</p>
            <div class="token-box">{{ token.access_token }}</div>
        {% endif %}
    </div>
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
    print("Received callback from Keycloak")
    try:
        token = oauth.keycloak.authorize_access_token()
        user = token.get('userinfo') or oauth.keycloak.parse_id_token(token, nonce=None)
        session["user"] = user
        session["token"] = token
        return redirect(url_for("index"))
    except Exception as e:
        return f"驗證過程中出錯: {str(e)}"

@app.route("/logout")
def logout():
    session.clear()
    post_logout_uri = url_for("index", _external=True)  
    logout_url = (
        f"{KEYCLOAK_METADATA['end_session_endpoint']}"
        f"?post_logout_redirect_uri={post_logout_uri}"
        f"&client_id={CLIENT_ID}"
    )
    return redirect(logout_url)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
















