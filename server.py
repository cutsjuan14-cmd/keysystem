# -*- coding: utf-8 -*-
"""
Sistema de Keys — Versión Railway + PostgreSQL
"""

import os
import uuid
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, g

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Credenciales admin desde variables de entorno
ADMIN_USERNAME = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "admin123")

# ─────────────────────────────
#  BASE DE DATOS (PostgreSQL)
# ─────────────────────────────

def get_db():
    if "db" not in g:
        DATABASE_URL = os.environ.get("DATABASE_URL")
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL no configurada")
        # Railway usa postgres://, psycopg2 necesita postgresql://
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    """Crea las tablas si no existen."""
    DATABASE_URL = os.environ.get("DATABASE_URL", "")
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id           SERIAL PRIMARY KEY,
            key          TEXT UNIQUE NOT NULL,
            days         INTEGER NOT NULL,
            created_at   TEXT NOT NULL,
            activated_at TEXT,
            expires_at   TEXT,
            hwid         TEXT,
            note         TEXT,
            status       TEXT DEFAULT 'unused'
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id        SERIAL PRIMARY KEY,
            key       TEXT NOT NULL,
            action    TEXT NOT NULL,
            hwid      TEXT,
            ip        TEXT,
            timestamp TEXT NOT NULL
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

# ─────────────────────────────
#  HELPERS
# ─────────────────────────────

def generate_key(prefix="KEY", length=16):
    chars = string.ascii_uppercase + string.digits
    raw = "".join(secrets.choice(chars) for _ in range(length))
    parts = [raw[i:i+4] for i in range(0, 16, 4)]
    return f"{prefix}-{'-'.join(parts)}"

def log_action(key, action, hwid=None):
    ip = request.remote_addr
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO logs (key, action, hwid, ip, timestamp) VALUES (%s, %s, %s, %s, %s)",
        (key, action, hwid, ip, datetime.utcnow().isoformat())
    )
    db.commit()
    cur.close()

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────
#  API DE VALIDACIÓN
# ─────────────────────────────

@app.route("/api/validate", methods=["POST"])
def api_validate():
    data = request.get_json(silent=True) or {}
    key  = data.get("key", "").strip().upper()
    hwid = data.get("hwid", "").strip()

    if not key or not hwid:
        return jsonify({"valid": False, "error": "key y hwid son requeridos"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM keys WHERE key = %s", (key,))
    row = cur.fetchone()
    cur.close()

    if not row:
        log_action(key, "invalid_key", hwid)
        return jsonify({"valid": False, "error": "Key no encontrada"}), 404

    if row["status"] == "banned":
        log_action(key, "banned", hwid)
        return jsonify({"valid": False, "error": "Key baneada"}), 403

    if row["status"] == "unused":
        expires = (datetime.utcnow() + timedelta(days=row["days"])).isoformat()
        cur = db.cursor()
        cur.execute(
            "UPDATE keys SET status='active', activated_at=%s, expires_at=%s, hwid=%s WHERE key=%s",
            (datetime.utcnow().isoformat(), expires, hwid, key)
        )
        db.commit()
        cur.close()
        log_action(key, "activated", hwid)
        return jsonify({"valid": True, "message": "Key activada", "days": row["days"], "expires_at": expires})

    if row["status"] == "active":
        if row["hwid"] != hwid:
            log_action(key, "hwid_mismatch", hwid)
            return jsonify({"valid": False, "error": "HWID no coincide"}), 403

        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.utcnow() > expires:
            cur = db.cursor()
            cur.execute("UPDATE keys SET status='expired' WHERE key=%s", (key,))
            db.commit()
            cur.close()
            log_action(key, "expired", hwid)
            return jsonify({"valid": False, "error": "Key expirada"}), 403

        remaining = (expires - datetime.utcnow()).days
        log_action(key, "checked", hwid)
        return jsonify({"valid": True, "message": "Key válida", "days_remaining": remaining, "expires_at": row["expires_at"]})

    return jsonify({"valid": False, "error": f"Estado: {row['status']}"}), 403


@app.route("/api/reset_hwid", methods=["POST"])
def api_reset_hwid():
    data = request.get_json(silent=True) or {}
    key       = data.get("key", "").strip().upper()
    admin_tok = data.get("admin_token", "")
    expected  = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    if hashlib.sha256(admin_tok.encode()).hexdigest() != expected:
        return jsonify({"success": False, "error": "Token inválido"}), 401
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE keys SET hwid=NULL, status='unused' WHERE key=%s", (key,))
    db.commit()
    cur.close()
    log_action(key, "hwid_reset")
    return jsonify({"success": True})

# ─────────────────────────────
#  PANEL ADMIN
# ─────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USERNAME and request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("dashboard"))
        error = "Credenciales incorrectas"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@admin_required
def dashboard():
    db = get_db()
    cur = db.cursor()
    def count(q): cur.execute(q); return cur.fetchone()[0]
    stats = {
        "total":   count("SELECT COUNT(*) FROM keys"),
        "unused":  count("SELECT COUNT(*) FROM keys WHERE status='unused'"),
        "active":  count("SELECT COUNT(*) FROM keys WHERE status='active'"),
        "expired": count("SELECT COUNT(*) FROM keys WHERE status='expired'"),
        "banned":  count("SELECT COUNT(*) FROM keys WHERE status='banned'"),
    }
    cur.execute("SELECT * FROM keys ORDER BY id DESC LIMIT 50")
    keys = cur.fetchall()
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 30")
    logs = cur.fetchall()
    cur.close()
    return render_template("dashboard.html", stats=stats, keys=keys, logs=logs)

@app.route("/generate", methods=["POST"])
@admin_required
def generate():
    days   = int(request.form.get("days", 30))
    amount = min(int(request.form.get("amount", 1)), 100)
    prefix = request.form.get("prefix", "KEY").upper()[:6]
    note   = request.form.get("note", "")
    db = get_db()
    cur = db.cursor()
    generated = []
    for _ in range(amount):
        k = generate_key(prefix)
        cur.execute(
            "INSERT INTO keys (key, days, created_at, note) VALUES (%s, %s, %s, %s)",
            (k, days, datetime.utcnow().isoformat(), note)
        )
        generated.append(k)
    db.commit()
    cur.close()
    return jsonify({"keys": generated})

@app.route("/ban/<key>", methods=["POST"])
@admin_required
def ban_key(key):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE keys SET status='banned' WHERE key=%s", (key,))
    db.commit()
    cur.close()
    log_action(key, "banned_by_admin")
    return jsonify({"success": True})

@app.route("/delete/<key>", methods=["POST"])
@admin_required
def delete_key(key):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM keys WHERE key=%s", (key,))
    db.commit()
    cur.close()
    return jsonify({"success": True})

@app.route("/reset/<key>", methods=["POST"])
@admin_required
def reset_hwid(key):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE keys SET hwid=NULL, status='unused', activated_at=NULL, expires_at=NULL WHERE key=%s", (key,))
    db.commit()
    cur.close()
    log_action(key, "hwid_reset_admin")
    return jsonify({"success": True})

@app.route("/extend/<key>", methods=["POST"])
@admin_required
def extend_key(key):
    extra_days = int(request.form.get("days", 7))
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM keys WHERE key=%s", (key,))
    row = cur.fetchone()
    if not row:
        cur.close()
        return jsonify({"success": False})
    if row["expires_at"]:
        base = datetime.fromisoformat(row["expires_at"])
        new_exp = (base + timedelta(days=extra_days)).isoformat()
    else:
        new_exp = (datetime.utcnow() + timedelta(days=extra_days)).isoformat()
    cur.execute("UPDATE keys SET expires_at=%s, days=days+%s WHERE key=%s", (new_exp, extra_days, key))
    db.commit()
    cur.close()
    log_action(key, f"extended_{extra_days}d")
    return jsonify({"success": True, "new_expires": new_exp})

@app.route("/search")
@admin_required
def search():
    q = f"%{request.args.get('q', '')}%"
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM keys WHERE key LIKE %s OR note LIKE %s OR hwid LIKE %s", (q, q, q))
    rows = [dict(r) for r in cur.fetchall()]
    cur.close()
    return jsonify(rows)

# ─────────────────────────────
#  INICIO
# ─────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
