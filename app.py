import os
import sys
import re
import sqlite3
import secrets
import uuid
import mimetypes
import html
import bcrypt
import hashlib
import hmac
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, Response, jsonify, request, session, send_from_directory, url_for
from werkzeug.utils import secure_filename

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(PROJECT_DIR, "static")
PROTECTED_UPLOAD_DIR = os.path.join(PROJECT_DIR, "protected_files")

if not os.path.exists(PROTECTED_UPLOAD_DIR):
    os.makedirs(PROTECTED_UPLOAD_DIR)

PROTECTED_FILE_EXTENSIONS = {
    ".doc", ".docx", ".ppt", ".pptx", ".csv", ".xls", ".xlsx",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff",
}

def is_supported_protected_file(filename):
    return os.path.splitext(filename)[1].lower() in PROTECTED_FILE_EXTENSIONS

try:
    from module1_dbms import (
        setup_dbms_architecture, get_db_connection, dbms_crash_recovery_demo,
        stored_procedure_grant_permission, run_advanced_sql_analytics, 
        analyze_query_optimization, insert_nosql_document, query_nosql_document
    )
    from module2_os import get_os_process_info, verify_os_file_permissions, secure_os_locked_read, secure_os_read_stream
    from module3_security import (
        authenticate_and_verify, admin_unlock_user, calculate_file_hash,
        authenticate_login, verify_file_access_password, log_audit, release_expired_temporary_locks
    )
except ImportError as e:
    print(f"[IMPORT ERROR] Module missing: {e}")
    sys.exit(1)

def auto_discover_and_register_files():
    conn = get_db_connection()
    cur = conn.cursor()

    storage_dirs = [PROJECT_DIR, PROTECTED_UPLOAD_DIR]
    target_files = []
    for storage_dir in storage_dirs:
        if os.path.isdir(storage_dir):
            target_files.extend(
                (filename, os.path.join(storage_dir, filename))
                for filename in os.listdir(storage_dir)
                if os.path.isfile(os.path.join(storage_dir, filename))
                and is_supported_protected_file(filename)
            )
    print(f"\n[DYNAMIC FILE DISCOVERY] Found {len(target_files)} dataset(s) on Storage:")
    for file, filepath in target_files:
        size_kb = os.path.getsize(filepath) / 1024
        cur.execute("""
            INSERT OR IGNORE INTO files (filename, filepath, file_size_kb) 
            VALUES (?, ?, ?)
        """, (file, filepath, round(size_kb, 2)))
        cur.execute("UPDATE files SET filepath=?, file_size_kb=? WHERE filename=?",
                    (filepath, round(size_kb, 2), file))

        f_hash = calculate_file_hash(filepath) or "N/A"
        print(f"   Secured: File = '{file}' | Size = {size_kb:.2f} KB | SHA-256 Hash = {f_hash[:16]}...")

    conn.commit()
    conn.close()
    return [file for file, _filepath in target_files]

def seed_sample_users():
    conn = get_db_connection()
    cur = conn.cursor()

    admin_pass = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    emp_pass = bcrypt.hashpw("EmpPass123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cur.execute("""
        INSERT INTO users (id, username, password_hash, role, email) 
        VALUES (1, 'Madhvan', ?, 'admin', 'madhvansharma1706@gmail.com')
        ON CONFLICT(id) DO UPDATE SET username='Madhvan', password_hash=?, role='admin', email='madhvansharma1706@gmail.com'
    """, (admin_pass, admin_pass))

    cur.execute("""
        INSERT INTO users (id, username, password_hash, role, email) 
        VALUES (2, 'chetan_emp', ?, 'employee', 'chetan@example.com')
        ON CONFLICT(id) DO UPDATE SET password_hash=?, role='employee', email='chetan@example.com'
    """, (emp_pass, emp_pass))

    conn.commit()
    conn.close()

def run_project_demo():
    print("==========================================================================")
    print("   FAIL-SAFE ZERO-CRASH ENTERPRISE STORAGE & DYNAMIC SECURITY ENGINE       ")
    print("==========================================================================")
    setup_dbms_architecture()
    seed_sample_users()
    auto_discover_and_register_files()
    print("DBMS & Security Engine Initialized.")

app = Flask(__name__, static_folder="static")
app.secret_key = "aegis_static_flask_session_key"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=100 * 1024 * 1024)
RESET_CODE_LIFETIME_SECONDS = 600
RESET_CODE_MAX_ATTEMPTS = 5
GENERIC_RESET_MESSAGE = "If the username and email match a registered account, a reset code will be generated."

def reset_code_digest(user_id, code):
    pepper = "aegis_enterprise_static_pepper_2026"
    return hmac.new(pepper.encode("utf-8"), f"password-reset:{user_id}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()

def send_reset_email(email_address, code):
    mailtrap_user = "c6b996257b9295"
    mailtrap_pass = "a6975fec9ccae8"

    print(f"\n==============================================")
    print(f" [PASSWORD RESET OTP] For Email: {email_address}")
    print(f" OTP CODE: {code}")
    print(f"==============================================\n")

    email = EmailMessage()
    email["Subject"] = "Aegis password reset code"
    email["From"] = "security@aegis-system.local"
    email["To"] = email_address
    email.set_content(f"Your Aegis password reset code is {code}. It expires in 10 minutes. Do not share this code.")
    try:
        with smtplib.SMTP("sandbox.smtp.mailtrap.io", 2525, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(mailtrap_user, mailtrap_pass)
            smtp.send_message(email)
        return True, None
    except Exception as e:
        app.logger.exception("Mailtrap SMTP failed, using console OTP fallback")
        return True, None

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Please sign in again."}), 401
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Administrator access required."}), 403
        return view(*args, **kwargs)
    return wrapped

def request_data():
    return request.get_json(silent=True) or {}

@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify({"error": "File is too large. The upload limit is 100 MB."}), 413

@app.get("/")
def index_page():
    return send_from_directory(STATIC_DIR, "login.html")

@app.get("/dashboard")
@login_required
def dashboard_page():
    return send_from_directory(STATIC_DIR, "dashboard.html")

@app.post("/api/login")
def api_login():
    data = request_data()
    username = str(data.get("username", "")).strip()
    password = data.get("password", "")
    if not username or not isinstance(password, str) or not password:
        return jsonify({"error": "Enter your username and password."}), 400
    try:
        result = authenticate_login(username, password)
    except Exception:
        app.logger.exception("Login processing failed")
        return jsonify({"error": "The security service could not process the login."}), 500
    if not result.get("ok"):
        code = 423 if result.get("locked") or result.get("permanent") else 401
        return jsonify({"error": result["message"], "locked": bool(result.get("locked")),
                        "permanent": bool(result.get("permanent"))}), code
    session.clear()
    session.update(user_id=result["id"], username=result["username"], role=result["role"])
    log_audit(result["username"], "LOGIN", "SUCCESS", "PORTAL")
    return jsonify({"ok": True, "username": result["username"], "role": result["role"]})

@app.post("/api/logout")
def api_logout():
    if session.get("username"):
        log_audit(session["username"], "LOGOUT", "SUCCESS", "PORTAL")
    session.clear()
    return jsonify({"ok": True})

@app.post("/api/password-reset/request")
def api_request_password_reset():
    data = request_data()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    if not username or not email:
        return jsonify({"error": "Enter your username and registered email address."}), 400

    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email FROM users WHERE LOWER(username)=LOWER(?)", (username,))
        account = cur.fetchone()
        if not account or not account[1] or str(account[1]).strip().lower() != email:
            conn.close()
            return jsonify({"error": "Username and registered email do not match."}), 400

        user_id, email_address = account
        code = f"{secrets.randbelow(1_000_000):06d}"

        cur.execute("""INSERT INTO password_reset_otps
                    (user_id, code_hash, created_at, expires_at, attempts, window_started_at, request_count)
                    VALUES (?, ?, ?, ?, 0, ?, 1)
                    ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,
                    created_at=excluded.created_at, expires_at=excluded.expires_at, attempts=0""",
                    (user_id, reset_code_digest(user_id, code), now_text,
                     (now + timedelta(seconds=RESET_CODE_LIFETIME_SECONDS)).isoformat(), now_text))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Reset request failed: {str(e)}"}), 500
    finally:
        conn.close()

    send_reset_email(email_address, code)
    log_audit(username, "PASSWORD_RESET_REQUEST", "SUCCESS", "PORTAL")
    return jsonify({"ok": True, "message": "OTP has been sent to Mailtrap and Terminal Console."})

@app.post("/api/password-reset/verify-otp")
def api_verify_otp():
    data = request_data()
    username = str(data.get("username", "")).strip()
    code = str(data.get("code", "")).strip()
    if not username or not re.fullmatch(r"\d{6}", code):
        return jsonify({"error": "Enter valid username and 6-digit OTP code."}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""SELECT u.id, r.code_hash, r.expires_at, r.attempts
                    FROM users u JOIN password_reset_otps r ON r.user_id=u.id WHERE LOWER(u.username)=LOWER(?)""", (username,))
        reset = cur.fetchone()
        if not reset:
            conn.close()
            return jsonify({"error": "No OTP request found for this user."}), 400

        user_id, stored_hash, expires_at, attempts = reset
        expires = datetime.fromisoformat(expires_at)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        if not stored_hash or expires <= now or attempts >= RESET_CODE_MAX_ATTEMPTS:
            conn.close()
            return jsonify({"error": "OTP code has expired or maximum attempts exceeded."}), 400

        computed_hash = reset_code_digest(user_id, code)
        if not hmac.compare_digest(stored_hash, computed_hash):
            cur.execute("UPDATE password_reset_otps SET attempts=attempts+1 WHERE user_id=?", (user_id,))
            conn.commit()
            conn.close()
            return jsonify({"error": "Invalid OTP code. Please check and try again."}), 400

        conn.close()
        return jsonify({"ok": True, "message": "OTP verified successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.post("/api/password-reset/complete")
def api_complete_password_reset():
    data = request_data()
    username = str(data.get("username", "")).strip()
    code = str(data.get("code", "")).strip()
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not username or not re.fullmatch(r"\d{6}", code):
        return jsonify({"error": "Session error or invalid code format."}), 400
    if not isinstance(new_password, str) or len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters long."}), 400
    if new_password != confirm_password:
        return jsonify({"error": "New Password and Confirm Password do not match."}), 400
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""SELECT u.id, r.code_hash, r.expires_at, r.attempts
                    FROM users u JOIN password_reset_otps r ON r.user_id=u.id WHERE LOWER(u.username)=LOWER(?)""", (username,))
        reset = cur.fetchone()
        if not reset:
            conn.close()
            return jsonify({"error": "Session expired or user not found."}), 400

        user_id, stored_hash, expires_at, attempts = reset
        computed_hash = reset_code_digest(user_id, code)
        if not hmac.compare_digest(stored_hash, computed_hash):
            conn.close()
            return jsonify({"error": "Invalid code session. Please restart reset flow."}), 400

        password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cur.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))
        cur.execute("UPDATE password_reset_otps SET code_hash='', expires_at=?, attempts=? WHERE user_id=?",
                    (datetime.now(timezone.utc).isoformat(), RESET_CODE_MAX_ATTEMPTS, user_id))
        conn.commit()
        conn.close()

        log_audit(username, "PASSWORD_RESET_COMPLETE", "SUCCESS", "PORTAL")
        return jsonify({"ok": True, "message": "Password updated successfully!"})
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Password update failed: {str(e)}"}), 500

@app.get("/api/me")
@login_required
def api_me():
    return jsonify({"username": session["username"], "role": session["role"]})

@app.get("/api/dashboard")
@app.get("/api/data")
@login_required
def api_dashboard():
    release_expired_temporary_locks()
    conn = get_db_connection()
    cur = conn.cursor()
    if session["role"] == "admin":
        cur.execute("SELECT id, filename, filepath, file_size_kb FROM files ORDER BY filename")
    else:
        cur.execute("""SELECT f.id, f.filename, f.filepath, f.file_size_kb FROM files f
                       JOIN permissions p ON p.file_id=f.id
                       WHERE p.user_id=? AND p.can_read=1 ORDER BY f.filename""", (session["user_id"],))
    
    files = []
    for row in cur.fetchall():
        f_hash = calculate_file_hash(row[2]) or "Unavailable"
        files.append({"id": row[0], "filename": row[1], "file_size_kb": row[3], "sha256": f_hash})

    data = {"success": True, "files": files, "file_count": len(files)}
    
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
        cur.execute("SELECT timestamp, username, action, status, filename FROM audit_logs ORDER BY id DESC LIMIT 100")
        data["audit"] = [dict(timestamp=r[0], username=r[1], action=r[2], status=r[3], filename=r[4]) for r in cur.fetchall()]
        
        cur.execute("""
            SELECT u.username, f.filename, COALESCE(p.can_read, 0) 
            FROM users u 
            CROSS JOIN files f 
            LEFT JOIN permissions p ON p.user_id = u.id AND p.file_id = f.id
            WHERE u.role = 'employee'
            ORDER BY u.username, f.filename
        """)
        data["permissions"] = [dict(username=r[0], filename=r[1], can_read=bool(r[2])) for r in cur.fetchall()]
    
    conn.close()
    return jsonify(data)

@app.post("/api/users/add")
@admin_required
def api_add_user():
    data = request_data()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    role = str(data.get("role", "employee")).strip().lower()

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required."}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        pwd_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cur.execute("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
                    (username, pwd_hash, role, email))
        conn.commit()
        conn.close()
        log_audit(session["username"], "ADD_USER", "SUCCESS", username)
        return jsonify({"ok": True, "message": f"User '{username}' added successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.post("/api/users/delete")
@admin_required
def api_delete_user():
    data = request_data()
    username = str(data.get("username", "")).strip()
    if username.lower() == "madhvan":
        return jsonify({"error": "Cannot delete primary administrator 'Madhvan'."}), 403

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        u_row = cur.fetchone()
        if u_row:
            user_id = u_row[0]
            cur.execute("DELETE FROM permissions WHERE user_id=?", (user_id,))
            cur.execute("DELETE FROM password_reset_otps WHERE user_id=?", (user_id,))
            cur.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
        conn.close()
        log_audit(session["username"], "DELETE_USER", "SUCCESS", username)
        return jsonify({"ok": True, "message": f"User '{username}' deleted successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.post("/api/files/upload")
@admin_required
def api_upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    file = request.files["file"]
    filename = secure_filename(file.filename)
    if not is_supported_protected_file(filename):
        return jsonify({"error": "Unsupported file format."}), 400

    filepath = os.path.join(PROTECTED_UPLOAD_DIR, filename)
    file.save(filepath)
    size_kb = os.path.getsize(filepath) / 1024

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO files (filename, filepath, file_size_kb) VALUES (?, ?, ?)",
                    (filename, filepath, round(size_kb, 2)))
        conn.commit()
        conn.close()
        log_audit(session["username"], "UPLOAD_FILE", "SUCCESS", filename)
        return jsonify({"ok": True, "message": f"File '{filename}' uploaded successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.post("/api/files/delete")
@admin_required
def api_delete_file():
    data = request_data()
    filename = str(data.get("filename", "")).strip()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, filepath FROM files WHERE filename=?", (filename,))
        f_row = cur.fetchone()
        if f_row:
            file_id, filepath = f_row
            cur.execute("DELETE FROM permissions WHERE file_id=?", (file_id,))
            cur.execute("DELETE FROM files WHERE id=?", (file_id,))
            conn.commit()
            if os.path.exists(filepath):
                os.remove(filepath)
        conn.close()
        log_audit(session["username"], "DELETE_FILE", "SUCCESS", filename)
        return jsonify({"ok": True, "message": f"File '{filename}' deleted successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.post("/api/permissions/update")
@admin_required
def api_update_permission():
    data = request_data()
    username = str(data.get("username", "")).strip()
    filename = str(data.get("filename", "")).strip()
    can_read = int(data.get("can_read", 0))

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        u_row = cur.fetchone()
        cur.execute("SELECT id FROM files WHERE filename=?", (filename,))
        f_row = cur.fetchone()

        if u_row and f_row:
            cur.execute("""
                INSERT INTO permissions (user_id, file_id, can_read) VALUES (?, ?, ?)
                ON CONFLICT(user_id, file_id) DO UPDATE SET can_read=excluded.can_read
            """, (u_row[0], f_row[0], can_read))
            conn.commit()

        conn.close()
        log_audit(session["username"], "UPDATE_PERMISSION", f"ACCESS_{'GRANTED' if can_read else 'REVOKED'}", f"{username}:{filename}")
        return jsonify({"ok": True, "message": "Permission updated successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.get("/api/files/download/<path:filename>")
@login_required
def api_download_file(filename):
    filename = filename.strip()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, filepath FROM files WHERE filename=?", (filename,))
    file_row = cur.fetchone()
    if file_row and session.get("role") != "admin":
        cur.execute("SELECT 1 FROM permissions WHERE user_id=? AND file_id=? AND can_read=1",
                    (session["user_id"], file_row[0]))
        allowed = cur.fetchone() is not None
    else:
        allowed = file_row is not None
    conn.close()
    if not allowed:
        log_audit(session.get("username", "unknown"), "DOWNLOAD_FILE", "DENIED_NO_PERMISSION", filename)
        return jsonify({"success": False, "message": "You do not have read permission for this file."}), 403
    
    log_audit(session.get("username", "unknown"), "DOWNLOAD_FILE", "SUCCESS", filename)
    return send_from_directory(PROTECTED_UPLOAD_DIR, os.path.basename(file_row[1]), as_attachment=True)

if __name__ == "__main__":
    run_project_demo()
    app.run(debug=True, port=5000)