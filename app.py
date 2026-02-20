from flask import Flask, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth
import os

# 允許非 HTTPS 傳輸 (本地測試用)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 

app = Flask(__name__)
app.secret_key = "test_secret_key_123" 

# --- 根據你的最新資訊修正 ---
CLIENT_ID = "test.oidc"
CLIENT_SECRET = "gSx9sKPdqDoI6etOFMW6MJHVlV1OFUVF"
MY_IP = "192.168.116.25" 

# 因為 Realm Name 是 test.oidc，網址路徑必須反映這一點
BASE_URL = "http://testoidc.uattdtydomain.gov.hk"

KEYCLOAK_METADATA = {
    "issuer": f"{BASE_URL}",
    "authorization_endpoint": f"{BASE_URL}/protocol/openid-connect/auth",
    "token_endpoint": f"{BASE_URL}/protocol/openid-connect/token",
    "userinfo_endpoint": f"{BASE_URL}/protocol/openid-connect/userinfo",
    "end_session_endpoint": f"{BASE_URL}/protocol/openid-connect/logout",
    "jwks_uri": f"{BASE_URL}/protocol/openid-connect/certs",
}

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata=KEYCLOAK_METADATA,
    client_kwargs={
        "scope": "openid profile email",
        "verify": False  # 忽略 SSL 檢查
    },
)

# ... (中間的 TEMPLATE 與 index 路由保持不變) ...

@app.route("/login")
def login():
    # 確保 redirect_uri 與 Keycloak 後台完全一致
    redirect_uri = f"http://{MY_IP}:5000/auth"
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
    post_logout_uri = f"http://{MY_IP}:5000/"
    logout_url = (
        f"{KEYCLOAK_METADATA['end_session_endpoint']}"
        f"?post_logout_redirect_uri={post_logout_uri}"
        f"&client_id={CLIENT_ID}"
    )
    return redirect(logout_url)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
