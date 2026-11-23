import os
import sys
import re
import sqlite3
import secrets
import uuid
import html
import csv
import io
import shutil
import tempfile
import zipfile
import xml.etree.ElementTree as ET
import bcrypt
import hashlib
import hmac
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, Response, jsonify, request, session, send_file, send_from_directory, url_for
from werkzeug.utils import secure_filename
from crypto_vault import encrypt_file_copy, verify_encrypted_copy

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

PROTECTED_FILE_EXTENSIONS = {
    ".doc", ".docx", ".ppt", ".pptx", ".csv", ".xls", ".xlsx", ".pdf",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff",
}

def is_supported_protected_file(filename):
    return os.path.splitext(filename)[1].lower() in PROTECTED_FILE_EXTENSIONS

def hash_uploaded_file(uploaded):
    digest = hashlib.sha256()
    uploaded.stream.seek(0)
    for chunk in iter(lambda: uploaded.stream.read(1024 * 1024), b""):
        digest.update(chunk)
    uploaded.stream.seek(0)
    return digest.hexdigest()

def load_local_env():
    env_path = os.path.join(PROJECT_DIR, ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                name, value = name.strip(), value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '\"'):
                    value = value[1:-1]
                if name and name not in os.environ:
                    os.environ[name] = value
    except FileNotFoundError:
        pass

load_local_env()

try:
    from module1_dbms import (
        setup_dbms_architecture, get_db_connection, dbms_crash_recovery_demo,
        restore_database_backup, check_database_recovery,
        start_automatic_database_backups, recover_database_if_needed, insert_audit_record,
        execute_2pl_secure_transaction, DATABASE_BACKUP_PATH,
    )
    from module2_os import verify_os_file_permissions, secure_os_read_stream, run_os_concept_demo
    from module3_security import (
        calculate_file_hash,
        authenticate_login, verify_file_access_password, log_audit, release_expired_temporary_locks,
        MAX_FAILED_ATTEMPTS,
        geofence_denies, is_ip_blocked, is_emergency_lockdown_enabled,
        add_ip_block_rule, remove_ip_block_rule, save_emergency_lockdown,
        add_allowed_network, remove_allowed_network, verify_audit_chain,
        record_canary_trip, get_soc_metrics, normalize_ip_address,
        normalize_network_range,
    )
except ImportError as e:
    print(f"[IMPORT ERROR] Module missing: {e}")
    sys.exit(1)


def open_db():
    conn = get_db_connection()
    return conn, conn.cursor()


def auto_discover_and_register_files():
    conn, cur = open_db()
    storage_dirs = [PROJECT_DIR, os.path.join(PROJECT_DIR, "protected_files")]
    target_files = []
    for storage_dir in storage_dirs:
        if os.path.isdir(storage_dir):
            target_files.extend(
                (filename, os.path.join(storage_dir, filename))
                for filename in os.listdir(storage_dir)
                if filename.lower().endswith(".csv")
                and os.path.isfile(os.path.join(storage_dir, filename))
            )
    print(f"\n [DYNAMIC FILE DISCOVERY] Found {len(target_files)} dataset(s) on Storage:")
    for file, filepath in target_files:
        cur.execute("""SELECT filename FROM files
                       WHERE filepath=? AND filename<>? AND is_protected=1 LIMIT 1""",
                    (filepath, file))
        logical_file = cur.fetchone()
        if logical_file:
            print(f"   Skipped duplicate storage name '{file}' (listed as '{logical_file[0]}').")
            continue
        size_kb = os.path.getsize(filepath) / 1024
        cur.execute("""
            INSERT OR IGNORE INTO files (filename, filepath, file_size_kb) 
            VALUES (?, ?, ?)
        """, (file, filepath, round(size_kb, 2)))
        cur.execute("UPDATE files SET filepath=?, file_size_kb=? WHERE filename=?",
                    (filepath, round(size_kb, 2), file))
        cur.execute("SELECT id, is_protected FROM files WHERE filename = ?", (file,))
        file_row = cur.fetchone()
        if not file_row[1]:
            print(f"   Skipped (protection removed by admin): '{file}'")
            continue
        file_id = file_row[0]
        if file_row[1]:
            encrypt_file_copy(file_id, file, filepath, cur)
        can_read_val = 1 if file == "ipl_data.csv" else 0
        cur.execute("SELECT id FROM users WHERE username='chetan_emp'")
        employee = cur.fetchone()
        if employee:
            cur.execute("SELECT id FROM permissions WHERE user_id=? AND file_id=? ORDER BY id LIMIT 1", (employee[0], file_id))
            if not cur.fetchone():
                cur.execute("INSERT INTO permissions (user_id, file_id, can_read) VALUES (?, ?, ?)", (employee[0], file_id, can_read_val))
        f_hash = calculate_file_hash(filepath)
        print(f"   Secured: File = '{file}' | Size = {size_kb:.2f} KB | SHA-256 Hash = {f_hash[:16]}...")
    conn.commit()
    conn.close()
    return [file for file, _filepath in target_files]

def seed_sample_users():
    conn, cur = open_db()
    admin_pass = bcrypt.hashpw("AdminPass123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    emp_pass = bcrypt.hashpw("EmpPass123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (id, username, password_hash, role) VALUES (1, 'admin_user', ?, 'admin')", (admin_pass,))
        cur.execute("INSERT INTO users (id, username, password_hash, role) VALUES (2, 'chetan_emp', ?, 'employee')", (emp_pass,))
    conn.commit()
    conn.close()

def run_project_demo():
    print("==========================================================================")
    print("   FAIL-SAFE ZERO-CRASH ENTERPRISE STORAGE & DYNAMIC SECURITY ENGINE       ")
    print("==========================================================================")
    print("\n--- 1. INITIALIZING DBMS ENGINE ---")
    setup_dbms_architecture()
    seed_sample_users()
    print("  -> Base Engine Ready (Triggers, Views, Foreign Keys, WAL Mode).")
    print("\n--- 2. DYNAMIC UNIVERSAL FILE DISCOVERY ---")
    auto_discover_and_register_files()
    print("\n--- 3. DATABASE RECOVERY & AUDIT ---")
    run_os_concept_demo(os.path.join(PROJECT_DIR, "static", "index.html"))
    dbms_crash_recovery_demo()


app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("AEGIS_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=100 * 1024 * 1024)
PROTECTED_UPLOAD_DIR = os.path.join(PROJECT_DIR, "protected_files")
RESET_CODE_LIFETIME_SECONDS = 600
RESET_CODE_COOLDOWN_SECONDS = 60
RESET_CODE_WINDOW_SECONDS = 900
RESET_CODE_MAX_SENDS_PER_WINDOW = 3
RESET_CODE_MAX_ATTEMPTS = 5
GENERIC_RESET_MESSAGE = "If the username and email match a registered account, a reset code will be sent. The code expires in 10 minutes."

def reset_code_digest(user_id, code):
    pepper = os.environ.get("AEGIS_OTP_PEPPER") or app.secret_key
    return hmac.new(pepper.encode("utf-8"), f"password-reset:{user_id}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()

def send_reset_email(email_address, code):
    sender = os.environ.get("GMAIL_ADDRESS", "").strip()
    app_password = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "")
    if not sender or not app_password:
        return False, "Set GMAIL_ADDRESS and GMAIL_APP_PASSWORD in the server environment."
    email = EmailMessage()
    email["Subject"] = "Aegis password reset code"
    email["From"] = sender
    email["To"] = email_address
    email.set_content(f"Your Aegis password reset code is {code}. It expires in 10 minutes. Do not share this code.")
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(sender, app_password)
            smtp.send_message(email)
        return True, None
    except (smtplib.SMTPException, TimeoutError, OSError):
        app.logger.exception("Gmail SMTP password reset email failed")
        return False, "Gmail SMTP could not send the code. Check the app password and server terminal."

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Please sign in again."}), 401
        conn, cur = open_db()
        cur.execute("SELECT role FROM users WHERE id=?", (session["user_id"],))
        account = cur.fetchone()
        token = session.get("session_token")
        if account and token:
            cur.execute("SELECT 1 FROM active_sessions WHERE user_id=? AND session_token=?", (session["user_id"], token))
            active = cur.fetchone()
        else:
            active = None
        conn.close()
        if not account or account[0] != session.get("role") or not active:
            session.clear()
            return jsonify({"error": "This account is no longer active. Please sign in again."}), 401
        return view(*args, **kwargs)
    return wrapped

def add_password_reset_request(username, requested_at, status, user_id=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO password_reset_request_logs
                       (user_id, username, requested_at, status) VALUES (?, ?, ?, ?)""",
                    (user_id, username[:254] or "(blank)", requested_at, status))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def update_password_reset_request(request_id, status, user_id=None):
    conn = get_db_connection()
    try:
        conn.execute("UPDATE password_reset_request_logs SET status=?, user_id=COALESCE(?, user_id) WHERE id=?",
                     (status, user_id, request_id))
        conn.commit()
    finally:
        conn.close()

def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Administrator access required."}), 403
        return view(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    allowed = {str(value).upper() for value in roles}
    def decorate(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            current_role = session.get("role", "employee").upper()
            if current_role != "ADMIN" and current_role not in allowed:
                return jsonify({"error": "This role cannot access this page."}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorate

def request_data():
    return request.get_json(silent=True) or {}


def insert_audit(cur, username, action, status, filename=""):
    insert_audit_record(cur, username, action, status, filename)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def admin_json_error(exc, message_text):
    app.logger.exception(message_text)
    return jsonify({"error": message_text}), 500


@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify({"error": "File is too large. The upload limit is 100 MB."}), 413

@app.get("/")
@app.get("/index.html")
def index_page():
    return send_from_directory(os.path.join(PROJECT_DIR, "static"), "index.html")

@app.get("/site.css")
def stylesheet():
    return send_from_directory(os.path.join(PROJECT_DIR, "static"), "site.css")

@app.get("/site.js")
def javascript():
    return send_from_directory(os.path.join(PROJECT_DIR, "static"), "site.js")

@app.get("/static/<path:filename>")
def static_assets(filename):
    return send_from_directory(os.path.join(PROJECT_DIR, "static"), filename)

@app.post("/api/login")
def api_login():
    data = request_data()
    username = str(data.get("username", "")).strip()
    password = data.get("password", "")
    if not username or not isinstance(password, str) or not password: return jsonify({"error": "Enter your username and password."}), 400
    conn, cur = open_db()
    cur.execute("SELECT role FROM users WHERE username=?", (username,))
    role_row = cur.fetchone()
    client_address = request.remote_addr or "unknown"
    blocked_address = is_ip_blocked(cur, client_address)
    lockdown = is_emergency_lockdown_enabled(cur)
    cur.execute("SELECT cidr FROM geofence_rules")
    geofence_rules = cur.fetchall()
    conn.close()
    if blocked_address:
        log_audit(username, "LOGIN", "DENIED_FIREWALL", "")
        return jsonify({"error": "This network address is blocked by the administrator."}), 403
    if lockdown and role_row and role_row[0] != "admin":
        log_audit(username, "LOGIN", "DENIED_LOCKDOWN", "")
        return jsonify({"error": "Emergency lockdown is active. Employee sign-in is temporarily disabled."}), 423
    if geofence_rules and role_row and role_row[0] != "admin" and geofence_denies(client_address, geofence_rules):
        log_audit(username, "LOGIN", "DENIED_GEOFENCE", client_address)
        return jsonify({"error": "Sign-in from this network is outside the administrator’s allowed network ranges."}), 403
    try:
        result = authenticate_login(username, password)
    except Exception as exc:
        app.logger.exception("Login processing failed")
        return jsonify({"error": "The security service could not process the login."}), 500
    if not result.get("ok"):
        code = 423 if result.get("locked") or result.get("permanent") else 401
        return jsonify({"error": result["message"], "locked": bool(result.get("locked")),
                        "permanent": bool(result.get("permanent"))}), code
    conn, cur = open_db()
    try:
        token = secrets.token_urlsafe(32)
        cur.execute("INSERT INTO active_sessions(user_id,username,session_token,ip_address,login_time,device_info) VALUES(?,?,?,?,?,?)",
                    (result["id"], username, token, request.remote_addr or "unknown", utc_now(), request.headers.get("User-Agent", "")[:500]))
        insert_audit(cur, username, "LOGIN_SESSION", "SUCCESS")
        conn.commit()
    finally:
        conn.close()
    session.clear()
    session.update(user_id=result["id"], username=result["username"], role=result["role"], session_token=token)
    return jsonify({"ok": True, "username": result["username"], "role": result["role"]})

@app.post("/api/logout")
def api_logout():
    if session.get("session_token"):
        conn, cur = open_db()
        cur.execute("DELETE FROM active_sessions WHERE session_token=?", (session["session_token"],))
        insert_audit(cur, session.get("username", "unknown"), "LOGOUT", "SUCCESS")
        conn.commit()
        conn.close()
    session.clear()
    return jsonify({"ok": True})

@app.post("/api/password-reset/request")
def api_request_password_reset():
    data = request_data()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    request_log_id = add_password_reset_request(username, now_text, "RECEIVED")
    if not username or not email:
        update_password_reset_request(request_log_id, "INVALID_INPUT")
        return jsonify({"error": "Enter your username and registered email address."}), 400
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        update_password_reset_request(request_log_id, "INVALID_EMAIL")
        return jsonify({"error": "Enter a valid email address."}), 400
    if not os.environ.get("GMAIL_ADDRESS", "").strip() or not os.environ.get("GMAIL_APP_PASSWORD", "").strip():
        update_password_reset_request(request_log_id, "GMAIL_NOT_CONFIGURED")
        return jsonify({"error": "Gmail sending is not configured. Set GMAIL_ADDRESS and GMAIL_APP_PASSWORD on the server."}), 503
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("SELECT id, email FROM users WHERE username=?", (username,))
        account = cur.fetchone()
        if not account or not account[1] or str(account[1]).strip().lower() != email:
            cur.execute("UPDATE password_reset_request_logs SET status='ACCOUNT_MISMATCH' WHERE id=?", (request_log_id,))
            conn.commit()
            return jsonify({"ok": True, "message": GENERIC_RESET_MESSAGE})
        user_id, email_address = account
        cur.execute("UPDATE password_reset_request_logs SET user_id=?, status='ACCOUNT_MATCHED' WHERE id=?",
                    (user_id, request_log_id))
        cur.execute("SELECT created_at, window_started_at, request_count FROM password_reset_otps WHERE user_id=?", (user_id,))
        previous = cur.fetchone()
        if previous:
            created_at = datetime.fromisoformat(previous[0])
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if (now - created_at).total_seconds() < RESET_CODE_COOLDOWN_SECONDS:
                cur.execute("UPDATE password_reset_request_logs SET status='RATE_LIMITED_COOLDOWN' WHERE id=?",
                            (request_log_id,))
                conn.commit()
                return jsonify({"ok": True, "message": GENERIC_RESET_MESSAGE})
            window_started = datetime.fromisoformat(previous[1])
            if window_started.tzinfo is None:
                window_started = window_started.replace(tzinfo=timezone.utc)
            if (now - window_started).total_seconds() < RESET_CODE_WINDOW_SECONDS:
                request_count = previous[2] + 1
                if request_count > RESET_CODE_MAX_SENDS_PER_WINDOW:
                    cur.execute("UPDATE password_reset_request_logs SET status='RATE_LIMITED_WINDOW' WHERE id=?",
                                (request_log_id,))
                    conn.commit()
                    return jsonify({"ok": True, "message": GENERIC_RESET_MESSAGE})
            else:
                window_started, request_count = now, 1
        else:
            window_started, request_count = now, 1
        code = f"{secrets.randbelow(1_000_000):06d}"
        cur.execute("""INSERT INTO password_reset_otps
                       (user_id, code_hash, created_at, expires_at, attempts, window_started_at, request_count)
                       VALUES (?, ?, ?, ?, 0, ?, ?)
                       ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,
                       created_at=excluded.created_at, expires_at=excluded.expires_at, attempts=0,
                       window_started_at=excluded.window_started_at, request_count=excluded.request_count""",
                    (user_id, reset_code_digest(user_id, code), now_text,
                     (now + timedelta(seconds=RESET_CODE_LIFETIME_SECONDS)).isoformat(),
                     window_started.isoformat(), request_count))
        cur.execute("UPDATE password_reset_request_logs SET status='CODE_CREATED' WHERE id=?", (request_log_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Could not prepare a password reset code")
        return jsonify({"error": "The password reset request could not be processed."}), 500
    finally:
        conn.close()
    delivered, delivery_error = send_reset_email(email_address, code)
    if not delivered:
        conn = get_db_connection()
        try:
            conn.execute("UPDATE password_reset_otps SET code_hash='', expires_at=? WHERE user_id=?", (now_text, user_id))
            conn.commit()
        finally:
            conn.close()
        update_password_reset_request(request_log_id, "EMAIL_FAILED", user_id)
        if delivery_error:
            app.logger.error("Password reset code was not delivered: %s", delivery_error)
        return jsonify({"error": "The reset code could not be sent. Check the Gmail settings and try again."}), 503
    update_password_reset_request(request_log_id, "EMAIL_SENT", user_id)
    log_audit(username, "PASSWORD_RESET_CODE", "EMAIL_SENT", "")
    return jsonify({"ok": True, "message": GENERIC_RESET_MESSAGE})

@app.post("/api/password-reset/complete")
def api_complete_password_reset():
    data = request_data()
    username = str(data.get("username", "")).strip()
    code = str(data.get("code", "")).strip()
    new_password = data.get("new_password", "")
    if not username or not re.fullmatch(r"\d{6}", code): return jsonify({"error": "Enter your username and the 6-digit code."}), 400
    if not isinstance(new_password, str) or len(new_password) < 8: return jsonify({"error": "The new password must be at least 8 characters."}), 400
    if len(new_password.encode("utf-8")) > 72: return jsonify({"error": "The new password must be no more than 72 UTF-8 bytes."}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("""SELECT u.id, r.code_hash, r.expires_at, r.attempts
                       FROM users u JOIN password_reset_otps r ON r.user_id=u.id WHERE u.username=?""", (username,))
        reset = cur.fetchone()
        if not reset:
            conn.commit()
            return jsonify({"error": "The code is invalid or expired. Request a new code."}), 400
        user_id, stored_hash, expires_at, attempts = reset
        expires = datetime.fromisoformat(expires_at)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if not stored_hash or expires <= now or attempts >= RESET_CODE_MAX_ATTEMPTS:
            conn.commit()
            return jsonify({"error": "The code is invalid or expired. Request a new code."}), 400
        if not hmac.compare_digest(stored_hash, reset_code_digest(user_id, code)):
            cur.execute("UPDATE password_reset_otps SET attempts=attempts+1 WHERE user_id=?", (user_id,))
            insert_audit(cur, username, "PASSWORD_RESET_CODE", "INVALID_CODE")
            conn.commit()
            return jsonify({"error": "The code is invalid or expired. Request a new code."}), 400
        password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cur.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))
        cur.execute("UPDATE password_reset_otps SET code_hash='', expires_at=?, attempts=? WHERE user_id=?",
                    (now.isoformat(), RESET_CODE_MAX_ATTEMPTS, user_id))
        insert_audit(cur, username, "PASSWORD_RESET", "SUCCESS")
        conn.commit()
        return jsonify({"ok": True, "message": "Password updated. You can now sign in with the new password."})
    except Exception:
        conn.rollback()
        app.logger.exception("Could not complete a password reset")
        return jsonify({"error": "The password could not be updated."}), 500
    finally:
        conn.close()

@app.get("/api/me")
@login_required
def api_me():
    return jsonify({"username": session["username"], "role": session["role"]})

@app.get("/api/dashboard")
@login_required
def api_dashboard():
    release_expired_temporary_locks()
    conn, cur = open_db()
    if session["role"] == "admin":
        cur.execute("SELECT filename, filepath, file_size_kb, is_canary FROM files WHERE is_protected=1 ORDER BY filename")
    else:
        cur.execute("""SELECT f.filename, f.filepath, f.file_size_kb, f.is_canary FROM files f
                       WHERE f.is_protected=1 AND (f.is_canary=1 OR EXISTS
                       (SELECT 1 FROM permissions p WHERE p.file_id=f.id AND p.user_id=? AND p.can_read=1))
                       ORDER BY f.filename""", (session["user_id"],))
    files = [{"filename": row[0], "size_kb": row[2], "hash": calculate_file_hash(row[1]) or "Unavailable", "canary": bool(row[3])}
             for row in cur.fetchall()]
    data = {"files": files, "file_count": len(files)}
    if session["role"] == "admin":
        cur.execute("SELECT COUNT(*) FROM users")
        data["user_count"] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM audit_logs")
        data["audit_count"] = cur.fetchone()[0]
        cur.execute("""SELECT username, role, failed_attempts, lockout_count,
                              locked_until, permanently_locked, email FROM users ORDER BY username""")
        data["users"] = [dict(username=r[0], role=r[1], failed_attempts=r[2], lockout_count=r[3],
                               locked_until=r[4], permanently_locked=bool(r[5]), email=r[6] or "")
                        for r in cur.fetchall()]
        cur.execute("""SELECT audit_id, timestamp, username, role_type, action, status,
                              filename, prev_hash, block_hash
                       FROM vw_audit_logs_by_role ORDER BY audit_id DESC LIMIT 100""")
        data["audit"] = [dict(audit_id=r[0], timestamp=r[1], username=r[2], role_type=r[3],
                              action=r[4], status=r[5], filename=r[6], prev_hash=r[7], block_hash=r[8])
                         for r in cur.fetchall()]
        cur.execute("""SELECT u.username, f.filename, p.can_read FROM permissions p
                       JOIN users u ON p.user_id=u.id JOIN files f ON p.file_id=f.id
                       WHERE f.is_protected=1
                       ORDER BY u.username, f.filename""")
        data["permissions"] = [dict(username=r[0], filename=r[1], can_read=bool(r[2])) for r in cur.fetchall()]
    cur.execute("SELECT payload_json FROM nosql_unstructured_logs ORDER BY id DESC LIMIT 1")
    latest = cur.fetchone()
    data["nosql"] = latest[0] if latest else "No security documents recorded."
    conn.close()
    return jsonify(data)

@app.post("/api/users")
@admin_required
def api_create_employee():
    data = request_data()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    role = str(data.get("role", "employee")).strip().lower()
    if role not in {"employee", "hr", "project_manager", "director"}:
        return jsonify({"error": "Choose a valid employee role."}), 400
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", username): return jsonify({"error": "Username must be 3–80 characters using letters, numbers, dots, underscores, or hyphens."}), 400
    if not isinstance(password, str) or len(password) < 8: return jsonify({"error": "Password must be at least 8 characters."}), 400
    if len(password.encode("utf-8")) > 72: return jsonify({"error": "Password must be no more than 72 UTF-8 bytes."}), 400
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): return jsonify({"error": "Enter a valid employee email address."}), 400
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
                    (username, password_hash, role, email))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"error": "That username already exists."}), 409
    finally:
        conn.close()
    log_audit(session["username"], "CREATE_EMPLOYEE", "SUCCESS", f"{username}:{role}")
    return jsonify({"ok": True, "message": f"Employee account '{username}' created with the {role.replace('_', ' ').title()} role."}), 201

@app.post("/api/users/remove")
@admin_required
def api_remove_employee():
    data = request_data()
    username = str(data.get("username", "")).strip()
    if not username: return jsonify({"error": "Select an employee to remove."}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("DELETE FROM users WHERE username=? AND role<>'admin'", (username,))
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Employee account not found."}), 404
        insert_audit(cur, session["username"], "REMOVE_EMPLOYEE", "SUCCESS", username)
        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Could not remove the employee account")
        return jsonify({"error": "The employee account could not be removed."}), 500
    finally:
        conn.close()
    return jsonify({"ok": True, "message": f"Employee account '{username}' was removed."})

@app.post("/api/users/email")
@admin_required
def api_set_user_email():
    data = request_data()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    if not username or len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): return jsonify({"error": "Choose an account and enter a valid email address."}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET email=? WHERE username=?", (email, username))
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Account not found."}), 404
        insert_audit(cur, session["username"], "UPDATE_RECOVERY_EMAIL", "SUCCESS", username)
        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Could not update the account recovery email")
        return jsonify({"error": "The account email could not be saved."}), 500
    finally:
        conn.close()
    return jsonify({"ok": True, "message": f"Recovery email saved for '{username}'."})

@app.post("/api/files")
@admin_required
def api_upload_protected_file():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Choose a file to upload."}), 400
    filename = secure_filename(uploaded.filename)
    if not filename:
        return jsonify({"error": "The file name is not valid."}), 400
    if not is_supported_protected_file(filename):
        return jsonify({"error": "Unsupported file type. Add only Word, PowerPoint, CSV, Excel, PDF, or image files."}), 415
    uploaded_hash = hash_uploaded_file(uploaded)
    conn = None
    saved_path = None
    existing_file_id = None
    existing_managed_path = None
    try:
        conn, cur = open_db()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("SELECT id, is_protected, filepath FROM files WHERE filename=?", (filename,))
        existing_file = cur.fetchone()
        if existing_file and existing_file[1]:
            return jsonify({"error": "A protected file with that name already exists."}), 409
        cur.execute("SELECT filename, filepath FROM files WHERE is_protected=1 ORDER BY filename")
        for protected_name, protected_path in cur.fetchall():
            if os.path.isfile(protected_path) and calculate_file_hash(protected_path) == uploaded_hash:
                return jsonify({"error": f"This file has the same contents as the protected file '{protected_name}'. Upload was cancelled."}), 409
        if existing_file:
            existing_file_id = existing_file[0]
            protected_root = os.path.realpath(PROTECTED_UPLOAD_DIR)
            old_path = os.path.realpath(existing_file[2])
            try:
                if os.path.commonpath((protected_root, old_path)) == protected_root and os.path.isfile(old_path):
                    existing_managed_path = old_path
            except ValueError:
                pass
        os.makedirs(PROTECTED_UPLOAD_DIR, exist_ok=True)
        saved_path = existing_managed_path or os.path.join(PROTECTED_UPLOAD_DIR, f"{uuid.uuid4().hex}_{filename}")
        uploaded.save(saved_path)
        file_size_kb = os.path.getsize(saved_path) / 1024
        if existing_file_id is not None:
            cur.execute("UPDATE files SET filepath=?, file_size_kb=?, is_protected=1 WHERE id=?",
                        (saved_path, round(file_size_kb, 2), existing_file_id))
            file_id = existing_file_id
        else:
            cur.execute("INSERT INTO files (filename, filepath, file_size_kb) VALUES (?, ?, ?)",
                        (filename, saved_path, round(file_size_kb, 2)))
            file_id = cur.lastrowid
        encrypt_file_copy(file_id, filename, saved_path, cur)
        insert_audit(cur, session["username"], "ADD_PROTECTED_FILE", "SUCCESS", filename)
        conn.commit()
    except sqlite3.IntegrityError:
        if conn:
            conn.rollback()
        if saved_path and os.path.exists(saved_path):
            os.remove(saved_path)
        return jsonify({"error": "A protected file with that name already exists."}), 409
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Could not add an uploaded protected file")
        if saved_path and os.path.exists(saved_path):
            os.remove(saved_path)
        return jsonify({"error": "The file could not be added to protected storage."}), 500
    finally:
        if conn:
            conn.close()
    message_text = (f"'{filename}' has been added to protected storage again. Reassign employee permissions under Manage permissions."
                    if existing_file_id is not None else
                    f"'{filename}' is now registered as a protected file. Grant employee access under Manage permissions.")
    return jsonify({"ok": True, "message": message_text}), 201

@app.post("/api/files/replace")
@admin_required
def api_replace_protected_file():
    filename = str(request.form.get("filename", "")).strip()
    uploaded = request.files.get("file")
    uploaded_name = secure_filename(uploaded.filename or "") if uploaded else ""
    if not filename or not uploaded_name:
        return jsonify({"error": "Choose a protected file and its edited version."}), 400
    if not is_supported_protected_file(filename) or not is_supported_protected_file(uploaded_name):
        return jsonify({"error": "Unsupported file type. Replace only Word, PowerPoint, CSV, Excel, PDF, or image files."}), 415
    if os.path.splitext(filename)[1].lower() != os.path.splitext(uploaded_name)[1].lower():
        return jsonify({"error": "The edited version must use the same file type as the protected file."}), 400
    uploaded_hash = hash_uploaded_file(uploaded)

    conn, cur = open_db()
    staged_path = backup_path = original_path = None
    replacement_installed = False
    try:
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("SELECT filepath FROM files WHERE filename=? AND is_protected=1 AND is_canary=0", (filename,))
        file_row = cur.fetchone()
        if not file_row:
            conn.rollback()
            return jsonify({"error": "Protected file not found."}), 404

        stored_path = file_row[0]
        original_path = os.path.realpath(stored_path)
        project_root = os.path.realpath(PROJECT_DIR)
        try:
            inside_project = os.path.commonpath((project_root, original_path)) == project_root
        except ValueError:
            inside_project = False
        if not inside_project or not os.path.isfile(original_path):
            conn.rollback()
            return jsonify({"error": "The protected file is not in the project storage folder."}), 400

        cur.execute("SELECT filename, filepath FROM files WHERE is_protected=1 AND is_canary=0 AND filepath<>? ORDER BY filename",
                    (stored_path,))
        for protected_name, protected_path in cur.fetchall():
            if os.path.isfile(protected_path) and calculate_file_hash(protected_path) == uploaded_hash:
                conn.rollback()
                return jsonify({"error": f"This content already matches the protected file '{protected_name}'. The current file was not changed."}), 409

        folder = os.path.dirname(original_path)
        extension = os.path.splitext(filename)[1].lower()
        staged_fd, staged_path = tempfile.mkstemp(prefix=".aegis-edit-", suffix=".tmp", dir=folder)
        os.close(staged_fd)
        uploaded.save(staged_path)
        backup_fd, backup_path = tempfile.mkstemp(prefix=".aegis-previous-", suffix=".tmp", dir=folder)
        os.close(backup_fd)
        shutil.copy2(original_path, backup_path)
        os.replace(staged_path, original_path)
        staged_path = None
        replacement_installed = True

        size_kb = round(os.path.getsize(original_path) / 1024, 2)
        cur.execute("SELECT id, filename FROM files WHERE filepath=? AND is_protected=1", (stored_path,))
        related_files = cur.fetchall()
        if not related_files:
            raise RuntimeError("No protected file records were found for this stored file.")
        cur.execute("UPDATE files SET file_size_kb=? WHERE filepath=? AND is_protected=1", (size_kb, stored_path))
        for related_id, related_name in related_files:
            encrypt_file_copy(related_id, related_name, original_path, cur)
        insert_audit(cur, session["username"], "EDIT_PROTECTED_FILE", "SUCCESS", filename)
        conn.commit()
        try:
            os.remove(backup_path)
            backup_path = None
        except OSError:
            app.logger.exception("Could not remove the previous-version temporary file")
        return jsonify({"ok": True, "message": f"'{filename}' was updated. Existing read permissions were kept."})
    except Exception:
        conn.rollback()
        if replacement_installed and backup_path and os.path.exists(backup_path):
            os.replace(backup_path, original_path)
            backup_path = None
        app.logger.exception("Could not replace the protected file contents")
        return jsonify({"error": "The edited file could not be saved. The previous version was restored."}), 500
    finally:
        conn.close()
        for temporary_path in (staged_path, backup_path):
            if temporary_path and os.path.exists(temporary_path):
                try:
                    os.remove(temporary_path)
                except OSError:
                    app.logger.exception("Could not remove temporary file: %s", temporary_path)

@app.post("/api/files/unprotect")
@admin_required
def api_unprotect_file():
    data = request_data()
    filename = str(data.get("filename", "")).strip()
    if not filename:
        return jsonify({"error": "Select a protected file to remove."}), 400
    conn = get_db_connection()
    file_path = None
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("SELECT filepath FROM files WHERE filename=? AND is_protected=1", (filename,))
        file_row = cur.fetchone()
        if file_row is None:
            conn.rollback()
            return jsonify({"error": "Protected file not found."}), 404
        file_path = file_row[0]
        cur.execute("UPDATE files SET is_protected=0 WHERE filename=? AND is_protected=1", (filename,))
        cur.execute("DELETE FROM permissions WHERE file_id=(SELECT id FROM files WHERE filename=?)", (filename,))
        cur.execute("DELETE FROM protected_file_blobs WHERE file_id=(SELECT id FROM files WHERE filename=?)", (filename,))
        insert_audit(cur, session["username"], "REMOVE_FILE_PROTECTION", "SUCCESS", filename)
        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Could not remove file protection")
        return jsonify({"error": "The file could not be removed from protected storage."}), 500
    finally:
        conn.close()
    protected_root = os.path.realpath(PROTECTED_UPLOAD_DIR)
    resolved_path = os.path.realpath(file_path) if file_path else ""
    try:
        if (resolved_path and os.path.commonpath((protected_root, resolved_path)) == protected_root
                and os.path.isfile(resolved_path)):
            os.remove(resolved_path)
    except (OSError, ValueError):
        app.logger.exception("Could not delete removed protected file: %s", filename)
        return jsonify({"error": "Protection was removed, but the stored file could not be deleted."}), 500
    return jsonify({"ok": True, "message": f"'{filename}' was removed from protected files and deleted from storage."})

@app.post("/api/unlock")
@admin_required
def api_unlock_employee():
    data = request_data()
    username = str(data.get("username", "")).strip()
    conn, cur = open_db()
    cur.execute("SELECT role FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    if not user or user[0] == "admin":
        conn.close()
        return jsonify({"error": "Employee account not found."}), 404
    cur.execute("""UPDATE users SET failed_attempts=0, lockout_count=0, is_locked=0,
                   locked_until=NULL, permanently_locked=0 WHERE username=?""", (username,))
    insert_audit(cur, session["username"], "UNLOCK_ACCOUNT", "SUCCESS", username)
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Employee account '{username}' has been unlocked. Lockout counters have been reset."})

@app.post("/api/permissions")
@admin_required
def api_set_permission():
    data = request_data()
    username = str(data.get("username", "")).strip()
    filename = str(data.get("filename", "")).strip()
    try:
        can_read = int(data.get("can_read"))
    except (TypeError, ValueError):
        return jsonify({"error": "Choose whether read access is allowed or revoked."}), 400
    if can_read not in (0, 1):
        return jsonify({"error": "Invalid access setting."}), 400
    conn, cur = open_db()
    cur.execute("SELECT id, role FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    cur.execute("SELECT id FROM files WHERE filename=? AND is_protected=1", (filename,))
    file_row = cur.fetchone()
    if not user or user[1] == "admin" or not file_row:
        conn.close()
        return jsonify({"error": "Choose a valid employee and registered file."}), 400
    cur.execute("SELECT id FROM permissions WHERE user_id=? AND file_id=? ORDER BY id LIMIT 1", (user[0], file_row[0]))
    permission = cur.fetchone()
    if permission:
        cur.execute("UPDATE permissions SET can_read=? WHERE id=?", (can_read, permission[0]))
        cur.execute("DELETE FROM permissions WHERE user_id=? AND file_id=? AND id<>?", (user[0], file_row[0], permission[0]))
    else:
        cur.execute("INSERT INTO permissions (user_id, file_id, can_read) VALUES (?, ?, ?)", (user[0], file_row[0], can_read))
    status = "READ_ALLOWED" if can_read else "READ_REVOKED"
    insert_audit(cur, session["username"], "CHANGE_PERMISSION", status, f"{username}:{filename}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Read access {'granted to' if can_read else 'revoked from'} {username} for {filename}."})

@app.post("/api/access")
@login_required
def api_verify_access():
    data = request_data()
    password = data.get("password", "")
    filename = str(data.get("filename", "")).strip()
    if not isinstance(password, str) or not password or not filename:
        return jsonify({"error": "Select a file and enter your password."}), 400
    auth = verify_file_access_password(session["username"], password)
    if not auth.get("ok"):
        log_audit(session["username"], "FILE_PASSWORD_CHECK", "DENIED_INVALID_PASSWORD", filename)
        return jsonify({"error": auth["message"]}), 401
    conn, cur = open_db()
    cur.execute("SELECT id,filepath,is_canary FROM files WHERE filename=? AND is_protected=1", (filename,))
    file_row = cur.fetchone()
    if file_row and file_row[2] and auth["role"] != "admin":
        record_canary_trip(cur, auth["username"], filename, request.remote_addr or "", utc_now())
        conn.commit()
        conn.close()
        return jsonify({"error": "Security decoy accessed. The attempt was recorded and the client address was blocked where safe."}), 403
    if file_row and auth["role"] != "admin" and not file_row[2]:
        cur.execute("SELECT 1 FROM permissions WHERE user_id=? AND file_id=? AND can_read=1", (auth["id"], file_row[0]))
        if not cur.fetchone():
            file_row = None
    conn.close()
    if not file_row:
        log_audit(auth["username"], "UNAUTHORIZED_FILE_ACCESS", "DENIED_NO_PERMISSION_OR_FILE", filename)
        return jsonify({"error": "You do not have read permission for this file."}), 403
    if not is_supported_protected_file(filename):
        log_audit(auth["username"], "FILE_ACCESS_CHECK", "DENIED_UNSUPPORTED_FILE_TYPE", filename)
        return jsonify({"error": "This file type is not supported. Only Word, PowerPoint, CSV, Excel, PDF, and image files can be opened."}), 415
    digest = calculate_file_hash(file_row[1])
    if not digest:
        log_audit(auth["username"], "FILE_VERIFY", "FILE_MISSING", filename)
        return jsonify({"error": "File is missing or could not be verified."}), 404
    log_audit(auth["username"], "FILE_ACCESS_CHECK", "GRANTED_" + auth["role"].upper(), filename)
    return jsonify({"ok": True, "message": "Access verified. Opening the file read-only.",
                    "read_url": url_for("api_read_protected_file", filename=filename)})


def read_preview_bytes(filepath, limit=64 * 1024):
    stream = secure_os_read_stream(filepath)
    preview = bytearray()
    try:
        for chunk in stream:
            preview.extend(chunk[:limit - len(preview)])
            if len(preview) >= limit:
                break
    finally:
        stream.close()
    return bytes(preview)


def preview_table(rows):
    rows = [row[:20] for row in rows[:101]]
    if not rows:
        return "<p>This file has no readable rows.</p>"
    header = "".join(f"<th>{html.escape(str(value)[:500])}</th>" for value in rows[0])
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(value)[:500])}</td>" for value in row) + "</tr>"
        for row in rows[1:]
    )
    return f'<div class="table-wrap"><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>'


def preview_csv_file(filepath):
    text = read_preview_bytes(filepath).decode("utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = []
    try:
        for row in csv.reader(io.StringIO(text), dialect):
            rows.append(row)
            if len(rows) >= 101:
                break
    except csv.Error:
        return "<p>This CSV file could not be displayed as a table.</p>"
    return preview_table(rows)


def excel_column_number(cell_reference):
    number = 0
    for letter in cell_reference:
        if not letter.isalpha():
            break
        number = number * 26 + ord(letter.upper()) - ord("A") + 1
    return number


def preview_xlsx_file(filepath):
    with zipfile.ZipFile(filepath) as workbook:
        shared_strings = []
        if "xl/sharedStrings.xml" in workbook.namelist():
            root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
            shared_strings = [
                "".join(node.text or "" for node in item.iter() if node.tag.endswith("}t"))
                for item in root.iter() if item.tag.endswith("}si")
            ]
        sheet_names = sorted(
            name for name in workbook.namelist()
            if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name)
        )
        if not sheet_names:
            return "<p>No worksheet data was found.</p>"
        rows = []
        with workbook.open(sheet_names[0]) as sheet:
            for _, row_element in ET.iterparse(sheet, events=("end",)):
                if not row_element.tag.endswith("}row"):
                    continue
                cells = {}
                for cell in row_element:
                    if not cell.tag.endswith("}c"):
                        continue
                    column = excel_column_number(cell.attrib.get("r", ""))
                    if not column or column > 20:
                        continue
                    value = next((node.text or "" for node in cell if node.tag.endswith("}v")), "")
                    if cell.attrib.get("t") == "s" and value.isdigit():
                        index = int(value)
                        value = shared_strings[index] if index < len(shared_strings) else ""
                    elif cell.attrib.get("t") == "inlineStr":
                        value = "".join(node.text or "" for node in cell.iter() if node.tag.endswith("}t"))
                    cells[column] = value
                if cells:
                    rows.append([cells.get(column, "") for column in range(1, max(cells) + 1)])
                row_element.clear()
                if len(rows) >= 101:
                    break
        return preview_table(rows)


def preview_openxml_text(filepath, extension):
    with zipfile.ZipFile(filepath) as document:
        if extension == ".docx":
            xml_files = ["word/document.xml"]
        else:
            xml_files = sorted(
                (name for name in document.namelist()
                 if re.fullmatch(r"ppt/slides/slide\d+\.xml", name)),
                key=lambda name: int(re.search(r"slide(\d+)", name).group(1)),
            )
        sections = []
        for number, name in enumerate(xml_files, start=1):
            root = ET.fromstring(document.read(name))
            text = "\n".join(
                "".join(node.text or "" for node in paragraph.iter() if node.tag.endswith("}t"))
                for paragraph in root.iter() if paragraph.tag.endswith("}p")
            )
            if text.strip():
                sections.append(text if extension == ".docx" else f"Slide {number}\n{text}")
        content = "\n\n".join(sections) or "No readable text found."
        return "<pre class=\"document-text\">" + html.escape(content) + "</pre>"


def convert_legacy_powerpoint_to_pdf(filepath):
    import pythoncom
    import win32com.client

    temporary_dir = tempfile.mkdtemp(prefix="aegis_ppt_preview_")
    pdf_path = os.path.join(temporary_dir, "presentation.pdf")
    powerpoint = None
    presentation = None
    pythoncom.CoInitialize()
    try:
        powerpoint = win32com.client.DispatchEx("PowerPoint.Application")
        powerpoint.DisplayAlerts = 0
        presentation = powerpoint.Presentations.Open(
            os.path.abspath(filepath), ReadOnly=True, Untitled=False, WithWindow=False
        )
        presentation.SaveAs(pdf_path, 32)
        presentation.Close()
        presentation = None
        if not os.path.isfile(pdf_path):
            raise OSError("PowerPoint did not create a PDF preview.")
        return temporary_dir, pdf_path
    except Exception:
        shutil.rmtree(temporary_dir, ignore_errors=True)
        raise
    finally:
        if presentation is not None:
            presentation.Close()
        if powerpoint is not None:
            powerpoint.Quit()
        pythoncom.CoUninitialize()


def make_preview_page(filename, preview_kind, preview_markup):
    safe_filename = html.escape(filename)
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{safe_filename} · Read-only</title>
    <style>body{{margin:0;padding:24px;background:#f4f7fb;color:#18243a;font:14px Arial,sans-serif}}main{{max-width:1100px;margin:auto;background:white;padding:22px;border:1px solid #e6ebf2;border-radius:10px}}h1{{font-size:18px;overflow-wrap:anywhere}}p{{color:#68768a;font-size:12px}}.preview{{max-height:75vh;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:#f7f9fc;padding:14px;border:1px solid #e6ebf2;border-radius:8px;font:13px/1.6 Consolas,monospace}}.document-text{{white-space:pre-wrap;overflow-wrap:anywhere;font:15px/1.7 Arial,sans-serif}}.table-wrap{{max-height:75vh;overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid #dce3ed;padding:8px;text-align:left;vertical-align:top;max-width:360px;overflow-wrap:anywhere}}th{{position:sticky;top:0;background:#edf2f9}}tr:nth-child(even){{background:#f8fafc}}</style>
    <main><h1>{safe_filename}</h1><p>{html.escape(preview_kind)} · read-only preview</p>{preview_markup}</main></html>'''


def make_preview_response(filename, preview_kind, preview_markup):
    response = Response(make_preview_page(filename, preview_kind, preview_markup), mimetype="text/html")
    response.headers.update({"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                             "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store",
                             "Content-Disposition": "inline"})
    return response


@app.get("/api/operations")
@admin_required
def api_operations():
    conn, cur = open_db()
    cur.execute("SELECT id,timestamp,sender,message FROM announcements ORDER BY id DESC LIMIT 50")
    announcements = [dict(id=r[0], timestamp=r[1], sender=r[2], message=r[3]) for r in cur.fetchall()]
    cur.execute("SELECT id,username,ip_address,login_time,device_info FROM active_sessions ORDER BY id DESC")
    sessions = [dict(id=r[0], username=r[1], ip=r[2], login_time=r[3], device=r[4]) for r in cur.fetchall()]
    cur.execute("SELECT id,timestamp,username,action,target,status FROM transactions WHERE action='APPLY_FILE_TRANSACTION' ORDER BY id DESC LIMIT 100")
    transactions = [dict(id=r[0], timestamp=r[1], username=r[2], action=r[3], target=r[4], status=r[5]) for r in cur.fetchall()]
    cur.execute("SELECT ip_address,reason,blocked_at,blocked_by FROM firewall_rules ORDER BY blocked_at DESC")
    firewall = [dict(ip=r[0], reason=r[1], blocked_at=r[2], blocked_by=r[3]) for r in cur.fetchall()]
    cur.execute("SELECT cidr,added_at,added_by FROM geofence_rules ORDER BY cidr")
    geofence = [dict(cidr=r[0], added_at=r[1], added_by=r[2]) for r in cur.fetchall()]
    lockdown = is_emergency_lockdown_enabled(cur)
    conn.close()
    return jsonify(announcements=announcements, sessions=sessions, transactions=transactions,
                   firewall=firewall, lockdown=lockdown, geofence=geofence)


@app.get("/api/audit")
@roles_required("HR", "PROJECT_MANAGER", "DIRECTOR")
def api_role_audit():
    role_filter = str(request.args.get("role", "")).strip().lower()
    name_filter = str(request.args.get("name", "")).strip()
    valid_roles = {"admin", "employee", "hr", "project_manager", "director"}
    if role_filter and role_filter not in valid_roles:
        return jsonify({"error": "Choose a valid account role."}), 400
    conn, cur = open_db()
    columns = "audit_id, timestamp, username, role_type, action, status, filename, prev_hash, block_hash"
    if role_filter and name_filter:
        cur.execute(f"SELECT {columns} FROM vw_audit_logs_by_role WHERE role_type=? AND username=? ORDER BY audit_id DESC LIMIT 500",
                    (role_filter, name_filter))
    elif role_filter:
        cur.execute(f"SELECT {columns} FROM vw_audit_logs_by_role WHERE role_type=? ORDER BY audit_id DESC LIMIT 500",
                    (role_filter,))
    elif name_filter:
        cur.execute(f"SELECT {columns.replace('username', 'name')} FROM vw_audit_logs_by_name WHERE name=? ORDER BY audit_id DESC LIMIT 500",
                    (name_filter,))
    else:
        cur.execute(f"SELECT {columns} FROM vw_audit_logs_by_role ORDER BY audit_id DESC LIMIT 100")
    rows = [dict(audit_id=r[0], timestamp=r[1], username=r[2], role_type=r[3], action=r[4],
                 status=r[5], filename=r[6], prev_hash=r[7], block_hash=r[8]) for r in cur.fetchall()]
    conn.close()
    return jsonify(audit=rows)


@app.get("/api/transactions")
@roles_required("HR", "PROJECT_MANAGER", "DIRECTOR")
def api_role_transactions():
    conn, cur = open_db()
    cur.execute("SELECT timestamp,username,action,target,status FROM transactions WHERE action='APPLY_FILE_TRANSACTION' ORDER BY id DESC LIMIT 100")
    rows = [dict(timestamp=r[0], username=r[1], action=r[2], target=r[3], status=r[4]) for r in cur.fetchall()]
    conn.close()
    return jsonify(transactions=rows)


@app.post("/api/transactions/apply")
@admin_required
def api_apply_file_transaction():
    filename = str(request_data().get("filename", "")).strip()
    if not filename:
        return jsonify({"error": "Choose a protected file for the transaction."}), 400
    try:
        result = execute_2pl_secure_transaction(
            session["username"], filename, "APPLY_FILE_TRANSACTION"
        )
    except Exception:
        app.logger.exception("Could not record the protected-file transaction")
        return jsonify({"error": "The file transaction could not be recorded."}), 500
    if not result["ok"]:
        return jsonify({"error": result["message"]}), 404
    return jsonify(result), 201


@app.get("/api/sessions")
@roles_required("HR", "PROJECT_MANAGER", "DIRECTOR")
def api_role_sessions():
    conn, cur = open_db()
    cur.execute("SELECT id,username,ip_address,login_time FROM active_sessions ORDER BY id DESC")
    rows = [dict(id=r[0], username=r[1], ip=r[2], login_time=r[3]) for r in cur.fetchall()]
    conn.close()
    return jsonify(sessions=rows)


@app.post("/api/security/geofence")
@admin_required
def api_add_geofence_range():
    raw_range = str(request_data().get("cidr", "")).strip()
    try:
        cidr = normalize_network_range(raw_range)
    except ValueError:
        return jsonify({"error": "Enter a valid network range, such as 192.168.1.0/24."}), 400
    conn, cur = open_db()
    add_allowed_network(cur, cidr, utc_now(), session["username"])
    if cur.rowcount:
        insert_audit(cur, session["username"], "GEOFENCE_RANGE_ADD", "SUCCESS", cidr)
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Allowed network range saved: {cidr}. When ranges exist, sign-ins outside them are denied."})


@app.delete("/api/security/geofence/<path:cidr>")
@admin_required
def api_remove_geofence_range(cidr):
    try:
        cidr = normalize_network_range(cidr)
    except ValueError:
        return jsonify({"error": "Invalid network range."}), 400
    conn, cur = open_db()
    if remove_allowed_network(cur, cidr):
        insert_audit(cur, session["username"], "GEOFENCE_RANGE_REMOVE", "SUCCESS", cidr)
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Allowed network range removed."})


@app.post("/api/security/canary")
@admin_required
def api_create_canary():
    conn, cur = open_db()
    cur.execute("SELECT filename FROM files WHERE is_protected=1 AND is_canary=1 LIMIT 1")
    existing = cur.fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": True, "message": f"The decoy file is already active: {existing[0]}"})
    filename = f"archive_review_{uuid.uuid4().hex[:8]}.csv"
    os.makedirs(PROTECTED_UPLOAD_DIR, exist_ok=True)
    filepath = os.path.join(PROTECTED_UPLOAD_DIR, f"{uuid.uuid4().hex}_{filename}")
    content = "Record,Information\n1,Decoy security file\n2,No real employee information\n"
    try:
        with open(filepath, "w", encoding="utf-8", newline="") as decoy:
            decoy.write(content)
        size_kb = os.path.getsize(filepath) / 1024
        cur.execute("INSERT INTO files(filename,filepath,file_size_kb,is_protected,is_canary) VALUES(?,?,?,1,1)",
                    (filename, filepath, round(size_kb, 2)))
        encrypt_file_copy(cur.lastrowid, filename, filepath, cur)
        insert_audit(cur, session["username"], "CANARY_CREATED", "ARMED", filename)
        conn.commit()
    except Exception:
        conn.rollback()
        if os.path.exists(filepath):
            os.remove(filepath)
        app.logger.exception("Could not create the security decoy file")
        return jsonify({"error": "The decoy file could not be created."}), 500
    finally:
        conn.close()
    return jsonify({"ok": True, "message": f"Decoy file armed: {filename}. Employee access attempts will be recorded."}), 201


@app.get("/api/announcements")
@login_required
def api_list_announcements():
    conn, cur = open_db()
    cur.execute("SELECT timestamp,sender,message FROM announcements ORDER BY id DESC LIMIT 20")
    items = [dict(timestamp=r[0], sender=r[1], message=r[2]) for r in cur.fetchall()]
    conn.close()
    return jsonify(announcements=items)


@app.post("/api/announcements")
@login_required
def api_add_announcement():
    message_text = str(request_data().get("message", "")).strip()
    if not message_text or len(message_text) > 1000:
        return jsonify({"error": "Enter an announcement up to 1000 characters."}), 400
    conn, cur = open_db()
    cur.execute("INSERT INTO announcements(timestamp,sender,message) VALUES(?,?,?)", (utc_now(), session["username"], message_text))
    insert_audit(cur, session["username"], "ANNOUNCEMENT", "POSTED")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Announcement posted."}), 201


@app.post("/api/sessions/<int:session_id>/terminate")
@admin_required
def api_terminate_session(session_id):
    conn, cur = open_db()
    cur.execute("SELECT username FROM active_sessions WHERE id=?", (session_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Session not found; it may already be signed out."}), 404
    cur.execute("DELETE FROM active_sessions WHERE id=?", (session_id,))
    insert_audit(cur, session["username"], "TERMINATE_SESSION", "SUCCESS", row[0])
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Session for {row[0]} was ended."})


@app.post("/api/firewall")
@admin_required
def api_add_firewall_rule():
    data = request_data()
    try:
        address = normalize_ip_address(data.get("ip", ""))
    except ValueError:
        return jsonify({"error": "Enter a valid IPv4 or IPv6 address."}), 400
    reason = str(data.get("reason", "Blocked by administrator")).strip()[:200]
    conn, cur = open_db()
    add_ip_block_rule(cur, address, reason or "Blocked by administrator", utc_now(), session["username"])
    insert_audit(cur, session["username"], "FIREWALL_BLOCK", "SUCCESS", address)
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"{address} is blocked."})


@app.delete("/api/firewall/<path:address>")
@admin_required
def api_remove_firewall_rule(address):
    try:
        address = normalize_ip_address(address)
    except ValueError:
        return jsonify({"error": "Invalid network address."}), 400
    conn, cur = open_db()
    if remove_ip_block_rule(cur, address):
        insert_audit(cur, session["username"], "FIREWALL_UNBLOCK", "SUCCESS", address)
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Address unblocked."})


@app.post("/api/security/lockdown")
@admin_required
def api_set_lockdown():
    enabled = bool(request_data().get("enabled"))
    conn, cur = open_db()
    save_emergency_lockdown(cur, enabled)
    insert_audit(cur, session["username"], "EMERGENCY_LOCKDOWN", "ENABLED" if enabled else "DISABLED")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Emergency lockdown " + ("enabled." if enabled else "disabled.")})


@app.post("/api/security/fim-simulate")
@admin_required
def api_fim_simulate():
    test_address = "198.51.100.99"
    conn, cur = open_db()
    add_ip_block_rule(cur, test_address, "Simulated file-integrity alert", utc_now(), session["username"])
    insert_audit(cur, session["username"], "FIM_ALERT_SIMULATION", "SIMULATED", test_address)
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Demo alert recorded and reserved test address blocked; no real client address was affected."})


@app.get("/api/security/scan")
@admin_required
def api_security_scan():
    conn, cur = open_db()
    integrity = cur.execute("PRAGMA integrity_check").fetchone()[0]
    chain_ok = verify_audit_chain(cur)
    journal = cur.execute("PRAGMA journal_mode").fetchone()[0]
    protected_files = cur.execute("""SELECT f.filename,f.filepath,b.nonce,b.ciphertext,b.content_hash
                                  FROM files f LEFT JOIN protected_file_blobs b ON b.file_id=f.id
                                  WHERE f.is_protected=1 ORDER BY f.filename""").fetchall()
    locked_accounts = cur.execute("SELECT COUNT(*) FROM users WHERE is_locked=1").fetchone()[0]
    conn.close()
    checks = [
        {"name": "Database consistency", "status": "passed" if integrity == "ok" else "failed", "detail": integrity},
        {"name": "Audit history", "status": "passed" if chain_ok else "failed", "detail": "Hash links are intact." if chain_ok else "A saved audit record does not match its hash."},
        {"name": "Write-ahead logging", "status": "passed" if str(journal).lower() == "wal" else "warning", "detail": f"SQLite journal mode: {journal}."},
        {"name": "Login lockouts", "status": "passed", "detail": f"Three-failure lockout policy is enabled; {locked_accounts} account(s) are currently locked."},
    ]
    file_results = []
    for filename, filepath, nonce, ciphertext, expected_hash in protected_files:
        disk_hash = calculate_file_hash(filepath) if filepath else None
        encrypted_ok = False
        if nonce and ciphertext and expected_hash:
            try:
                encrypted_ok = verify_encrypted_copy(filename, nonce, ciphertext, expected_hash)
            except Exception:
                encrypted_ok = False
        disk_matches = bool(disk_hash and expected_hash and hmac.compare_digest(disk_hash, expected_hash))
        if not filepath or not os.path.isfile(filepath):
            status = "failed"
            detail = "The protected file is missing from disk."
        elif expected_hash and not disk_matches:
            status = "failed"
            detail = "The disk file differs from the saved secure copy."
        elif not expected_hash:
            status = "warning"
            detail = "No encrypted baseline exists yet for comparison."
        elif not encrypted_ok:
            status = "failed"
            detail = "The encrypted database copy did not pass its integrity check."
        else:
            status = "passed"
            detail = "Disk file and encrypted copy match."
        file_results.append({"filename": filename, "status": status, "detail": detail,
                             "encrypted": bool(ciphertext), "disk_matches": disk_matches})
    passed = sum(check["status"] == "passed" for check in checks) + sum(item["status"] == "passed" for item in file_results)
    failed = sum(check["status"] == "failed" for check in checks) + sum(item["status"] == "failed" for item in file_results)
    warnings = sum(check["status"] == "warning" for check in checks) + sum(item["status"] == "warning" for item in file_results)
    return jsonify(ok=failed == 0, summary={"passed": passed,
                   "warnings": warnings, "failed": failed}, checks=checks, files=file_results)


@app.get("/api/soc/metrics")
@admin_required
def api_soc_metrics():
    return jsonify(get_soc_metrics())


@app.get("/api/security/vault")
@roles_required("PROJECT_MANAGER")
def api_vault_status():
    conn, cur = open_db()
    rows = cur.execute("""SELECT f.filename,f.filepath,b.nonce,b.ciphertext,b.content_hash
                          FROM files f LEFT JOIN protected_file_blobs b ON b.file_id=f.id
                          WHERE f.is_protected=1 ORDER BY f.filename""").fetchall()
    conn.close()
    files = []
    for filename, filepath, nonce, ciphertext, expected_hash in rows:
        encrypted_valid = False
        if nonce and ciphertext and expected_hash:
            try:
                encrypted_valid = verify_encrypted_copy(filename, nonce, ciphertext, expected_hash)
            except Exception:
                encrypted_valid = False
        disk_hash = calculate_file_hash(filepath) if filepath else None
        files.append({"filename": filename, "encrypted_copy": bool(ciphertext),
                      "encrypted_valid": encrypted_valid,
                      "disk_matches": bool(disk_hash and expected_hash and hmac.compare_digest(disk_hash, expected_hash))})
    return jsonify(files=files)


@app.post("/api/security/audit/verify")
@admin_required
def api_verify_audit():
    conn, cur = open_db()
    valid = verify_audit_chain(cur)
    insert_audit(cur, session["username"], "AUDIT_CHAIN_CHECK", "VALID" if valid else "INVALID")
    conn.commit()
    conn.close()
    return jsonify(ok=valid, message="Audit chain is valid." if valid else "Audit chain verification failed."), (200 if valid else 409)


@app.post("/api/db/recovery-check")
@admin_required
def api_recovery_check():
    conn = get_db_connection()
    try:
        checkpoint = conn.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()
    backup_exists = os.path.isfile(DATABASE_BACKUP_PATH)
    backup_integrity = None
    if backup_exists:
        backup_conn = sqlite3.connect(DATABASE_BACKUP_PATH)
        try:
            backup_integrity = backup_conn.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            backup_conn.close()
    backup_info = {"exists": backup_exists,
                   "updated": datetime.fromtimestamp(os.path.getmtime(DATABASE_BACKUP_PATH), timezone.utc).isoformat() if backup_exists else None,
                   "size_bytes": os.path.getsize(DATABASE_BACKUP_PATH) if backup_exists else 0,
                   "integrity": backup_integrity}
    log_audit(session["username"], "DATABASE_RECOVERY_CHECK", "OK" if integrity == "ok" else "FAILED")
    return jsonify(ok=integrity == "ok", integrity=integrity, checkpoint=list(checkpoint or ()), backup=backup_info)


@app.get("/api/os/metrics")
@roles_required("PROJECT_MANAGER")
def api_os_metrics():
    try:
        import psutil
        memory = psutil.virtual_memory()
        metrics = {"cpu_percent": psutil.cpu_percent(interval=0.1), "memory_percent": memory.percent,
                   "memory_used_mb": round(memory.used / (1024 * 1024)),
                   "memory_total_mb": round(memory.total / (1024 * 1024)),
                   "disk_percent": psutil.disk_usage(PROJECT_DIR).percent, "process_count": len(psutil.pids())}
    except ImportError:
        metrics = {"message": "Install psutil to display live operating-system metrics."}
    return jsonify(metrics)


@app.post("/api/os/demo/<kind>")
@roles_required("PROJECT_MANAGER")
def api_os_demo(kind):
    data = request_data()
    if kind == "bankers":
        allocation = data.get("allocation", [[0, 1, 0], [2, 0, 0], [3, 0, 2], [2, 1, 1], [0, 0, 2]])
        maximum = data.get("maximum", [[7, 5, 3], [3, 2, 2], [9, 0, 2], [2, 2, 2], [4, 3, 3]])
        available = data.get("available", [3, 3, 2])
        if not isinstance(allocation, list) or not isinstance(maximum, list) or len(allocation) != len(maximum):
            return jsonify({"error": "Provide matching allocation and maximum matrices."}), 400
        work = list(available)
        finished = [False] * len(allocation)
        order = []
        while True:
            found = False
            for i, (allocated, need_max) in enumerate(zip(allocation, maximum)):
                if not finished[i] and all(need_max[j] - allocated[j] <= work[j] for j in range(len(work))):
                    work = [work[j] + allocated[j] for j in range(len(work))]
                    finished[i] = found = True
                    order.append(i)
            if not found:
                break
        result = {"safe": all(finished), "safe_sequence": order}
    elif kind == "page-replacement":
        refs = data.get("references", [7, 0, 1, 2, 0, 3, 0, 4, 2, 3, 0, 3, 2])
        frame_count = max(1, min(10, int(data.get("frames", 3))))
        frames, faults, pointer = [], 0, 0
        for page in refs:
            if page not in frames:
                faults += 1
                if len(frames) < frame_count:
                    frames.append(page)
                else:
                    frames[pointer] = page
                    pointer = (pointer + 1) % frame_count
        result = {"algorithm": "FIFO", "page_faults": faults, "frames": frame_count}
    elif kind == "disk-scheduling":
        requests = data.get("requests", [98, 183, 37, 122, 14, 124, 65, 67])
        head = int(data.get("head", 53))
        sequence = sorted(int(x) for x in requests)
        result = {"algorithm": "SSTF", "service_order": [], "head_movement": 0}
        current = head
        while sequence:
            nxt = min(sequence, key=lambda value: abs(value - current))
            result["service_order"].append(nxt)
            result["head_movement"] += abs(nxt - current)
            current = nxt
            sequence.remove(nxt)
    else:
        return jsonify({"error": "Unknown OS demonstration."}), 404
    conn, cur = open_db()
    insert_audit(cur, session["username"], "OS_DEMO_" + kind.upper(), "COMPLETED")
    conn.commit()
    conn.close()
    return jsonify(result)


@app.get("/api/files/<path:filename>/read")
@login_required
def api_read_protected_file(filename):
    filename = filename.strip()
    if not filename:
        return jsonify({"error": "Choose a protected file."}), 400
    conn, cur = open_db()
    cur.execute("SELECT id, filepath, is_canary FROM files WHERE filename=? AND is_protected=1", (filename,))
    file_row = cur.fetchone()
    if file_row and file_row[2] and session.get("role") != "admin":
        record_canary_trip(cur, session["username"], filename, request.remote_addr or "", utc_now())
        conn.commit()
        conn.close()
        return jsonify({"error": "Security decoy accessed. The attempt was recorded and the client address was blocked where safe."}), 403
    if file_row and session.get("role") != "admin":
        cur.execute("SELECT 1 FROM permissions WHERE user_id=? AND file_id=? AND can_read=1",
                    (session["user_id"], file_row[0]))
        allowed = cur.fetchone() is not None
    else:
        allowed = file_row is not None
    conn.close()
    if not allowed:
        log_audit(session["username"], "READ_FILE", "DENIED_NO_PERMISSION_OR_FILE", filename)
        return jsonify({"error": "You do not have read permission for this file."}), 403
    if not is_supported_protected_file(filename):
        log_audit(session["username"], "READ_FILE", "DENIED_UNSUPPORTED_FILE_TYPE", filename)
        return jsonify({"error": "This file type is not supported. Only Word, PowerPoint, CSV, Excel, PDF, and image files can be opened."}), 415
    filepath = file_row[1]
    os_read_allowed, os_read_message = verify_os_file_permissions(filepath)
    if not os_read_allowed:
        log_audit(session["username"], "READ_FILE", "FILE_MISSING", filename)
        status = 404 if not os.path.exists(filepath) else 403
        return jsonify({"error": os_read_message}), status
    extension = os.path.splitext(filename)[1].lower()
    preview = None
    if extension == ".ppt":
        try:
            temporary_dir, pdf_path = convert_legacy_powerpoint_to_pdf(filepath)
            response = send_file(pdf_path, mimetype="application/pdf", as_attachment=False, conditional=False)
            response.headers["Content-Disposition"] = "inline"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Cache-Control"] = "private, no-store"
            response.call_on_close(lambda: shutil.rmtree(temporary_dir, ignore_errors=True))
            log_audit(session["username"], "READ_FILE", "ALLOWED_" + session["role"].upper(), filename)
            return response
        except ImportError:
            log_audit(session["username"], "READ_FILE", "PPT_PREVIEW_UNAVAILABLE", filename)
            return jsonify({"error": "Opening .ppt files requires Microsoft PowerPoint installed on the server computer."}), 415
        except Exception:
            app.logger.exception("Could not create a read-only PowerPoint preview")
            log_audit(session["username"], "READ_FILE", "PPT_PREVIEW_FAILED", filename)
            return jsonify({"error": "The PowerPoint file could not be converted to a read-only preview."}), 415
    try:
        if extension == ".csv":
            preview = ("CSV table", preview_csv_file(filepath))
        elif extension == ".xlsx":
            preview = ("Excel worksheet", preview_xlsx_file(filepath))
        elif extension in {".docx", ".pptx"}:
            kind = "Word document text" if extension == ".docx" else "PowerPoint slide text"
            preview = (kind, preview_openxml_text(filepath, extension))
        elif extension in {".xls", ".doc"}:
            preview = ("Legacy Office file", "<p>This older Office format cannot be previewed here. Save it as .xlsx, .docx, or .pptx to see a readable preview.</p>")
    except OSError:
        log_audit(session["username"], "READ_FILE", "OS_READ_DENIED", filename)
        return jsonify({"error": "The operating system could not read this file."}), 403
    except (zipfile.BadZipFile, ET.ParseError, KeyError, ValueError):
        log_audit(session["username"], "READ_FILE", "PREVIEW_FAILED", filename)
        return jsonify({"error": "This file could not be parsed for a readable preview."}), 415
    if preview:
        log_audit(session["username"], "READ_FILE", "ALLOWED_" + session["role"].upper(), filename)
        return make_preview_response(filename, *preview)
    content_type = {
        ".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg", ".gif": "image/gif", ".bmp": "image/bmp",
        ".webp": "image/webp", ".tif": "image/tiff", ".tiff": "image/tiff",
    }[extension]
    try:
        file_stream = secure_os_read_stream(filepath)
    except FileNotFoundError:
        log_audit(session["username"], "READ_FILE", "FILE_MISSING", filename)
        return jsonify({"error": "The protected file could not be found."}), 404
    except OSError:
        log_audit(session["username"], "READ_FILE", "OS_READ_DENIED", filename)
        return jsonify({"error": "The operating system could not open this file for reading."}), 403
    log_audit(session["username"], "READ_FILE", "ALLOWED_" + session["role"].upper(), filename)
    response = Response(file_stream, mimetype=content_type, direct_passthrough=True)
    response.headers["Content-Disposition"] = "inline"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response

def initialize_web_app():
    if recover_database_if_needed():
        print("Database restored automatically from the saved backup.")
    setup_dbms_architecture()
    seed_sample_users()
    auto_discover_and_register_files()
    start_automatic_database_backups()

if __name__ == "__main__":
    if "--database-restore" in sys.argv:
        print(f"Database restored from backup: {restore_database_backup()}")
    elif "--database-recovery-check" in sys.argv:
        result = check_database_recovery()
        print(f"Database integrity: {result['integrity']}")
        print(f"Audit records available: {result['audit_logs']}")
    elif "--demo" in sys.argv:
        run_project_demo()
    else:
        initialize_web_app()
        app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
