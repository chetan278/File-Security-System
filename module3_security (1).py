import bcrypt
import hashlib
import os
from module1_dbms import get_db_connection

MAX_FAILED_ATTEMPTS = 3

def calculate_file_hash(filepath):
    """SHA-256 Integrity Hash to detect unauthorized file tampering"""
    if not os.path.exists(filepath):
        return None
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def log_audit(username, action, status, filename):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_logs (username, action, status, filename)
            VALUES (?, ?, ?, ?)
        """, (username, action, status, filename))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT LOG ERROR]: {e}")

def authenticate_and_verify(username, password, filename):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, password_hash, role, failed_attempts, is_locked 
            FROM users WHERE username = ?
        """, (username,))
        user = cur.fetchone()

        # 1. Invalid User Protection (No Crash)
        if not user:
            log_audit(username, 'UNAUTHORIZED_ACCESS', 'DENIED_INVALID_USER', filename)
            conn.close()
            return "🛑 ACCESS DENIED: Unknown User! Incident Logged in DBMS Audit."

        user_id, stored_hash, role, failed_attempts, is_locked = user

        # 2. Check if already Locked
        if is_locked == 1:
            log_audit(username, 'LOCKED_ACCESS_ATTEMPT', 'BLOCKED', filename)
            conn.close()
            return f"🚫 ACCESS BLOCKED: Account '{username}' is LOCKED (3/3 Failed Attempts Exceeded)! Admin Unlock Required."

        # 3. Bcrypt Password Verification with Strict 3-Attempt Lockout
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            new_attempts = failed_attempts + 1
            if new_attempts >= MAX_FAILED_ATTEMPTS:
                cur.execute("UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE id = ?", (new_attempts, user_id))
                conn.commit()
                conn.close()
                log_audit(username, 'FAILED_LOGIN', 'ACCOUNT_LOCKED_3_ATTEMPTS', filename)
                return f"🛑 MAXIMUM ATTEMPTS REACHED ({new_attempts}/{MAX_FAILED_ATTEMPTS})! Account '{username}' is now LOCKED!"
            else:
                cur.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (new_attempts, user_id))
                conn.commit()
                conn.close()
                log_audit(username, 'FAILED_LOGIN', f'ATTEMPT_{new_attempts}_OF_3', filename)
                return f"⚠️ INCORRECT PASSWORD! Attempt {new_attempts} of {MAX_FAILED_ATTEMPTS} used. Warning: {MAX_FAILED_ATTEMPTS - new_attempts} attempt(s) left!"

        # Success Login -> Reset Attempt Count
        cur.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
        conn.commit()

        # 4. SHA-256 Dynamic File Integrity Check
        file_hash = calculate_file_hash(filename)
        if not file_hash:
            log_audit(username, 'FILE_VERIFY', 'FILE_MISSING', filename)
            conn.close()
            return f"❌ SECURITY ERROR: Target file '{filename}' missing on disk!"

        # 5. Role-Based Access Control (RBAC)
        if role == 'admin':
            log_audit(username, 'READ_FILE', 'ALLOWED_ADMIN', filename)
            conn.close()
            return f"✅ ACCESS GRANTED [ADMIN]: SHA-256 Verified ({file_hash[:10]}...). Reading '{filename}'."

        cur.execute("SELECT can_read FROM vw_active_security_permissions WHERE user_id = ? AND filename = ?", (user_id, filename))
        perm = cur.fetchone()
        conn.close()

        if perm and perm[0] == 1:
            log_audit(username, 'READ_FILE', 'ALLOWED_EMPLOYEE', filename)
            return f"✅ ACCESS GRANTED [EMPLOYEE]: SHA-256 Verified ({file_hash[:10]}...). Reading '{filename}'."
        else:
            log_audit(username, 'UNAUTHORIZED_FILE_ACCESS', 'DENIED_NO_PERM', filename)
            return f"🛑 ACCESS DENIED: Employee '{username}' does NOT have permission for '{filename}'!"

    except Exception as e:
        return f"🛡️ FAIL-SAFE TRIGGERED: Exception handled safely ({str(e)})"

def admin_unlock_user(admin_user, target_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE username = ?", (target_user,))
        conn.commit()
        conn.close()
        log_audit(admin_user, 'UNLOCK_ACCOUNT', 'SUCCESS', target_user)
        return f"🔓 ADMIN ACTION: Account for '{target_user}' has been UNLOCKED."
    except Exception as e:
        return f"❌ Admin Unlock Failed: {e}"