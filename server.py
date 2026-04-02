from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import yt_dlp
import jwt
import datetime
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)
CORS(app)

# =========================
# ⚙️ CONFIG
# =========================

# Config de email (Gmail)
EMAIL_HOST     = "smtp.gmail.com"
EMAIL_PORT     = 587
SECRET_KEY     = os.getenv("SECRET_KEY")
EMAIL_USER     = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")        # senha de app do Gmail
                                                 # (Conta Google → Segurança → Senhas de app)

# =========================
# 🗄️ BANCO DE DADOS
# =========================
def connect_db():
    return sqlite3.connect("db.sqlite", check_same_thread=False)

def create_tables():
    conn = connect_db()
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT UNIQUE,
            password   TEXT,
            verified   INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS verify_codes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT,
            code       TEXT,
            expires_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS playlists (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name    TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS musics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            playlist_id INTEGER,
            title       TEXT,
            video_id    TEXT
        )
    """)

    conn.commit()
    conn.close()

create_tables()

# =========================
# 🔧 HELPERS
# =========================
def make_token(user_id: int, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email":   email,
        "exp":     datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def auth_required(f):
    """Decorator — rotas protegidas por token."""
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        payload = verify_token(token)
        if not payload:
            return jsonify({"status": "error", "message": "Token inválido ou expirado"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper

def send_email(to: str, subject: str, html: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = EMAIL_USER
    msg["To"]      = to
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as s:
            s.starttls()
            s.login(EMAIL_USER, EMAIL_PASSWORD)
            s.sendmail(EMAIL_USER, to, msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

def gen_code() -> str:
    return str(random.randint(100000, 999999))

# =========================
# 🔐 AUTH — REGISTER
# =========================
@app.route("/register/request", methods=["POST"])
def register_request():
    """
    Recebe email + senha.
    Se o email não existe → gera código e envia pro email.
    Se já existe e verificado → erro.
    """
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"status": "error", "message": "Email e senha obrigatórios"}), 400

    conn = connect_db()
    cur  = conn.cursor()

    # Checa se já existe e verificado
    cur.execute("SELECT id, verified FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if row and row[1] == 1:
        conn.close()
        return jsonify({"status": "error", "message": "Email já cadastrado"}), 409

    # Se não existe, insere como não verificado
    if not row:
        cur.execute("INSERT INTO users (email, password, verified) VALUES (?,?,0)", (email, password))
        conn.commit()
    else:
        # Atualiza senha caso esteja tentando de novo
        cur.execute("UPDATE users SET password=? WHERE email=?", (password, email))
        conn.commit()

    # Gera e salva código (expira em 10 min)
    code    = gen_code()
    expires = (datetime.datetime.utcnow() + datetime.timedelta(minutes=10)).isoformat()
    cur.execute("DELETE FROM verify_codes WHERE email=?", (email,))
    cur.execute("INSERT INTO verify_codes (email, code, expires_at) VALUES (?,?,?)",
                (email, code, expires))
    conn.commit()
    conn.close()

    # Envia email
    html = f"""
    <div style="font-family:sans-serif;background:#0A0A0F;color:#EEF;padding:40px;border-radius:16px;max-width:480px;margin:auto">
        <div style="text-align:center;margin-bottom:24px">
            <div style="width:56px;height:56px;background:linear-gradient(135deg,#6C63FF,#1DB954);
                        border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:26px">🎵</div>
            <h1 style="letter-spacing:6px;font-size:22px;margin:12px 0 4px">SONIQ</h1>
            <p style="color:#7777AA;font-size:13px;margin:0">Verificação de email</p>
        </div>
        <p style="color:#BBBBD0;font-size:14px;line-height:1.6">
            Use o código abaixo para confirmar seu cadastro. Ele expira em <strong>10 minutos</strong>.
        </p>
        <div style="background:#181828;border:1px solid #252538;border-radius:14px;
                    text-align:center;padding:28px;margin:24px 0">
            <span style="font-size:42px;font-weight:900;letter-spacing:14px;color:#6C63FF">{code}</span>
        </div>
        <p style="color:#555566;font-size:12px;text-align:center">
            Se você não solicitou isso, ignore este email.
        </p>
    </div>
    """
    sent = send_email(email, "SONIQ — Código de verificação", html)

    if not sent:
        return jsonify({"status": "error", "message": "Falha ao enviar email"}), 500

    return jsonify({"status": "ok", "message": "Código enviado para o email"})


@app.route("/register/verify", methods=["POST"])
def register_verify():
    """Recebe email + código → verifica e devolve token."""
    data  = request.json or {}
    email = data.get("email", "").strip().lower()
    code  = data.get("code", "").strip()

    conn = connect_db()
    cur  = conn.cursor()

    cur.execute(
        "SELECT code, expires_at FROM verify_codes WHERE email=? ORDER BY id DESC LIMIT 1",
        (email,)
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Código não encontrado"}), 400

    saved_code, expires_at = row
    if datetime.datetime.utcnow() > datetime.datetime.fromisoformat(expires_at):
        conn.close()
        return jsonify({"status": "error", "message": "Código expirado"}), 400

    if code != saved_code:
        conn.close()
        return jsonify({"status": "error", "message": "Código incorreto"}), 400

    # Marca como verificado
    cur.execute("UPDATE users SET verified=1 WHERE email=?", (email,))
    cur.execute("DELETE FROM verify_codes WHERE email=?", (email,))
    conn.commit()

    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()

    token = make_token(user[0], email)
    return jsonify({"status": "ok", "token": token, "user_id": user[0], "email": email})


# =========================
# 🔐 AUTH — LOGIN
# =========================
@app.route("/login", methods=["POST"])
def login():
    """
    Se credenciais batem e usuário está verificado → devolve token JWT.
    Se não verificado → pede verificação.
    """
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = connect_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, verified FROM users WHERE email=? AND password=?", (email, password))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "Email ou senha incorretos"}), 401

    user_id, verified = row

    if not verified:
        return jsonify({"status": "unverified", "message": "Conta não verificada"}), 403

    token = make_token(user_id, email)
    return jsonify({"status": "ok", "token": token, "user_id": user_id, "email": email})


# =========================
# 🔎 BUSCAR MÚSICAS  (protegida)
# =========================
@app.route("/search")
@auth_required
def search():
    query = request.args.get("q", "")

    if not query:
        return jsonify([])

    ydl_opts = {
        "quiet": True,
        "extract_flat": True,
        "extractor_args": {
            "youtube": {
                "player_client": ["web"]
            }
        }
    }

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            result = ydl.extract_info(
                f"ytsearch10:{query}",
                download=False
            )

        songs = []
        for e in result.get("entries", []):
            songs.append({
                "title": e.get("title"),
                "id": e.get("id"),
                "thumbnail": (e.get("thumbnails") or [{}])[0].get("url"),
                "duration": e.get("duration"),
            })

        return jsonify(songs)

    except Exception as e:
        print("ERRO SEARCH:", e)
        return jsonify([])

# =========================
# ▶️ TOCAR MÚSICA  (protegida)
# =========================
@app.route("/play")
@auth_required
def play():
    video_id = request.args.get("id", "")

    ydl_opts = {
        "format": "bestaudio/best",
        "quiet": True,
        "noplaylist": True,
        "cookiefile": "cookies.txt",
        "extractor_args": {
            "youtube": {
                "player_client": ["web"]
            }
        },
        "http_headers": {
            "User-Agent": "Mozilla/5.0"
        }
    }

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(
                f"https://youtube.com/watch?v={video_id}",
                download=False
            )

        return jsonify({
            "url": info.get("url"),
            "title": info.get("title", ""),
            "duration": info.get("duration", 0)
        })

    except Exception as e:
        print("ERRO PLAY:", e)
        return jsonify({"error": "Falha ao carregar áudio"}), 500
# =========================
# 📁 PLAYLISTS  (protegidas)
# =========================
@app.route("/create_playlist", methods=["POST"])
@auth_required
def create_playlist():
    data = request.json or {}
    conn = connect_db(); cur = conn.cursor()
    cur.execute("INSERT INTO playlists (user_id, name) VALUES (?,?)",
                (request.user["user_id"], data.get("name","Sem nome")))
    conn.commit()
    playlist_id = cur.lastrowid
    conn.close()
    return jsonify({"status": "ok", "id": playlist_id})


@app.route("/playlists")
@auth_required
def get_playlists():
    conn = connect_db(); cur = conn.cursor()
    cur.execute("SELECT id, name FROM playlists WHERE user_id=?", (request.user["user_id"],))
    rows = cur.fetchall(); conn.close()
    return jsonify([{"id": r[0], "name": r[1]} for r in rows])


@app.route("/add_music", methods=["POST"])
@auth_required
def add_music():
    data = request.json or {}
    conn = connect_db(); cur = conn.cursor()
    cur.execute("INSERT INTO musics (playlist_id, title, video_id) VALUES (?,?,?)",
                (data["playlist_id"], data["title"], data["video_id"]))
    conn.commit(); conn.close()
    return jsonify({"status": "ok"})


@app.route("/remove_music", methods=["DELETE"])
@auth_required
def remove_music():
    data = request.json or {}
    conn = connect_db(); cur = conn.cursor()
    cur.execute("DELETE FROM musics WHERE id=?", (data.get("music_id"),))
    conn.commit(); conn.close()
    return jsonify({"status": "ok"})


@app.route("/playlist/<int:playlist_id>")
@auth_required
def get_playlist_music(playlist_id):
    conn = connect_db(); cur = conn.cursor()
    cur.execute("SELECT id, title, video_id FROM musics WHERE playlist_id=?", (playlist_id,))
    rows = cur.fetchall(); conn.close()
    return jsonify([{"id": r[0], "title": r[1], "video_id": r[2]} for r in rows])


@app.route("/delete_playlist/<int:playlist_id>", methods=["DELETE"])
@auth_required
def delete_playlist(playlist_id):
    conn = connect_db(); cur = conn.cursor()
    cur.execute("DELETE FROM musics WHERE playlist_id=?", (playlist_id,))
    cur.execute("DELETE FROM playlists WHERE id=?", (playlist_id,))
    conn.commit(); conn.close()
    return jsonify({"status": "ok"})


# =========================
# 🚀 START
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
