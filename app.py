from flask import Flask, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth
import os

# 解決 HTTP 傳輸限制與 SSL 憑證問題
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 

app = Flask(__name__)
app.secret_key = "test_secret_key_123" 

# --- 配置資訊 ---
CLIENT_ID = "test.oidc"
CLIENT_SECRET = "gSx9sKPdqDoI6etOFMW6MJHVlV1OFUVF"
# 你的 Ubuntu IP
MY_IP = "192.168.116.25" 

# 直接手動定義 Keycloak 配置，避開網路抓取失敗問題
KEYCLOAK_METADATA = {
    "issuer": "https://keytrain.uattdtydomain.gov.hk",
    "authorization_endpoint": "https://keytrain.uattdtydomain.gov.hk/protocol/openid-connect/auth",
    "token_endpoint": "https://keytrain.uattdtydomain.gov.hk/protocol/openid-connect/token",
    "userinfo_endpoint": "https://keytrain.uattdtydomain.gov.hk/protocol/openid-connect/userinfo",
    "end_session_endpoint": "https://keytrain.uattdtydomain.gov.hk/protocol/openid-connect/logout",
    "jwks_uri": "https://keytrain.uattdtydomain.gov.hk/protocol/openid-connect/certs",
}

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata=KEYCLOAK_METADATA, # 改用手動 Metadata
    client_kwargs={
        "scope": "openid profile email",
        "verify": False  # 解決 SSLError
    },
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
            <tr><th>Name</th><td>{{ user.name }}</td></tr>
            <tr><th>Username</th><td>{{ user.preferred_username }}</td></tr>
            <tr><th>Access Token</th><td><div class="token-box">{{ token.access_token }}</div></td></tr>
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
    # redirect_uri 必須與 Keycloak 後台設定完全一致
    # 建議在 Keycloak 增加 http://192.168.116.25
    redirect_uri = f"http://{MY_IP}:5000/auth"
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route("/auth")
def auth():
    # 這裡會連線到 token_endpoint，若 Ubuntu 無法連網會在此報錯
    token = oauth.keycloak.authorize_access_token()
    user = token.get('userinfo') 
    session["user"] = user
    session["token"] = token
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    # 登出後跳轉回首頁
    post_logout_uri = f"http://{MY_IP}:5000/"
    logout_url = (
        f"{KEYCLOAK_METADATA['end_session_endpoint']}"
        f"?post_logout_redirect_uri={post_logout_uri}"
        f"&client_id={CLIENT_ID}"
    )
    return redirect(logout_url)

if __name__ == "__main__":
    # 監聽 0.0.0.0 允許外部存取
    app.run(host='0.0.0.0', port=5000, debug=True)
