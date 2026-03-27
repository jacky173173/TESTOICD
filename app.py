from flask import Flask, redirect, url_for, session, render_template_string, request
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
# 預設一個 key，稍後可以在頁面修改
app.secret_key = "default_temporary_key"

oauth = OAuth(app)

# --- 介面樣式 ---
STYLE = """
<style>
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f0f2f5; display: flex; justify-content: center; padding: 40px; }
    .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); width: 100%; max-width: 500px; }
    h2 { color: #1a73e8; margin-bottom: 20px; text-align: center; }
    .form-group { margin-bottom: 15px; }
    label { display: block; margin-bottom: 5px; font-weight: bold; font-size: 14px; }
    input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
    .btn { display: block; width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; text-align: center; text-decoration: none; }
    .btn:hover { background: #1557b0; }
    .btn-secondary { background: #6c757d; margin-top: 10px; }
    .hint { font-size: 11px; color: #666; margin-top: 4px; }
</style>
"""

# --- 配置頁面模板 ---
SETUP_TEMPLATE = STYLE + """
<div class="card">
    <h2>⚙️ Keycloak 測試配置</h2>
    <form method="POST">
        <div class="form-group">
            <label>Flask Secret Key</label>
            <input name="flask_secret" value="{{ current_secret }}" required>
        </div>
        <hr>
        <div class="form-group">
            <label>Keycloak Issuer URL</label>
            <input name="issuer" placeholder="https://[domain]/realms/[realm]" value="{{ config.issuer }}" required>
            <div class="hint">例如: https://keytrain.uattdtydomain.gov.hk/realms/test.oidc</div>
        </div>
        <div class="form-group">
            <label>Client ID</label>
            <input name="client_id" value="{{ config.client_id }}" required>
        </div>
        <div class="form-group">
            <label>Client Secret</label>
            <input name="client_secret" type="password" value="{{ config.client_secret }}" required>
        </div>
        <div class="form-group">
            <label>Redirect URI (本機回傳路徑)</label>
            <input name="redirect_uri" value="{{ default_redirect_uri }}" required>
        </div>
        <button type="submit" class="btn">儲存並開始測試</button>
    </form>
</div>
"""

# --- 核心邏輯 ---

def get_keycloak_client():
    """從 session 動態讀取並註冊 OAuth Client"""
    cfg = session.get('oidc_config')
    if not cfg:
        return None
    
    # 如果已經註冊過，先移除舊的以確保更新
    if 'keycloak' in oauth._clients:
        del oauth._clients['keycloak']

    return oauth.register(
        name="keycloak",
        client_id=cfg['client_id'],
        client_secret=cfg['client_secret'],
        server_metadata_url=f"{cfg['issuer']}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "verify": False},
    )

@app.route("/")
def index():
    if 'oidc_config' not in session:
        return redirect(url_for('setup'))
    
    user = session.get("user")
    token = session.get("token")
    
    # 使用你原本的 TEMPLATE (簡化版)
    return render_template_string(f"{STYLE} <div class='card'><h2>測試系統</h2>" + 
        ("{% if user %} <p>歡迎, {{user.name}}</p> <a href='/logout' class='btn btn-secondary'>登出</a> {% else %} <a href='/login' class='btn'>前往 Keycloak 登入</a> {% endif %}" 
        " <br><a href='/setup' style='font-size:12px;'>重新修改配置</a> </div>"), user=user)

@app.route("/setup", methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        # 更新 Secret Key
        new_secret = request.form['flask_secret']
        app.secret_key = new_secret
        
        # 儲存 Keycloak 配置
        session['oidc_config'] = {
            'issuer': request.form['issuer'].rstrip('/'),
            'client_id': request.form['client_id'],
            'client_secret': request.form['client_secret'],
            'redirect_uri': request.form['redirect_uri']
        }
        return redirect(url_for('index'))
    
    current_cfg = session.get('oidc_config', {})
    default_uri = url_for('auth', _external=True)
    return render_template_string(SETUP_TEMPLATE, 
                                 config=current_cfg, 
                                 current_secret=app.secret_key,
                                 default_redirect_uri=default_uri)

@app.route("/login")
def login():
    client = get_keycloak_client()
    if not client:
        return redirect(url_for('setup'))
    
    redirect_uri = session['oidc_config']['redirect_uri']
    return client.authorize_redirect(redirect_uri)

@app.route("/auth")
def auth():
    client = get_keycloak_client()
    try:
        token = client.authorize_access_token()
        session["user"] = token.get('userinfo') or client.parse_id_token(token, nonce=None)
        session["token"] = token
        return redirect(url_for('index'))
    except Exception as e:
        return f"驗證失敗: {str(e)} <br> <a href='/setup'>回配置頁面</a>"

@app.route("/logout")
def logout():
    cfg = session.get('oidc_config')
    session.pop('user', None)
    session.pop('token', None)
    
    if cfg:
        # 動態生成登出 URL
        logout_url = (f"{cfg['issuer']}/protocol/openid-connect/logout"
                      f"?post_logout_redirect_uri={url_for('index', _external=True)}"
                      f"&client_id={cfg['client_id']}")
        return redirect(logout_url)
    return redirect(url_for('index'))

if __name__ == "__main__":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0', port=5000, debug=True)
