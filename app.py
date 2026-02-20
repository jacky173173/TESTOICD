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
MY_IP = "testoidc.uattdtydomain.gov.hk"
redirect_uri = f"http://{MY_IP}/auth" 


# 使用你剛剛抓到的正確端點
KEYCLOAK_METADATA = {
    "issuer": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc",
    "authorization_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/auth",
    "token_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/token",
    "userinfo_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/userinfo",
    "end_session_endpoint": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/logout",
    "jwks_uri": "https://keytrain.uattdtydomain.gov.hk/realms/test.oidc/protocol/openid-connect/certs",
}

oauth = OAuth(app)
# 註冊時建議直接引用 metadata
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=None, # 我們手動提供 metadata
    authorize_url=KEYCLOAK_METADATA["authorization_endpoint"],
    access_token_url=KEYCLOAK_METADATA["token_endpoint"],
    userinfo_endpoint=KEYCLOAK_METADATA["userinfo_endpoint"],
    jwks_uri=KEYCLOAK_METADATA["jwks_uri"],
    client_kwargs={
        "scope": "openid profile email",
        "verify": False  # 若 Ubuntu 內部連線 SSL 有問題可保持 False
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
    # 確保產生的 URI 是 http://testoidc.uattdtydomain.gov.hk
    redirect_uri = f"http://{MY_IP}:{PORT}/auth"
    return oauth.keycloak.authorize_redirect(redirect_uri)



@app.route("/auth")  # 確保這裡與 Keycloak 後台設定的完全一樣
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
    # 登出後跳轉回首頁
    post_logout_uri = f"http://{MY_IP}/"
    logout_url = (
        f"{KEYCLOAK_METADATA['end_session_endpoint']}"
        f"?post_logout_redirect_uri={post_logout_uri}"
        f"&client_id={CLIENT_ID}"
    )
    return redirect(logout_url)

if __name__ == "__main__":
    # 將 port 從 5000 改為 80
    app.run(host='0.0.0.0', port=80, debug=True)






