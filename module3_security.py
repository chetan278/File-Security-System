import bcrypt
import hashlib
import os
import ipaddress
from datetime import datetime, timedelta, timezone
from math import ceil
from module1_dbms import get_db_connection, insert_audit_record

MAX_FAILED_ATTEMPTS = 3
TEMPORARY_LOCK_SECONDS = 30
PERMANENT_AFTER_LOCKOUTS = 3

def normalize_ip_address(address):
    return str(ipaddress.ip_address(str(address).strip()))

def normalize_network_range(cidr):
    return str(ipaddress.ip_network(str(cidr).strip(), strict=False))

def geofence_denies(address, rules):
    try:
        client = ipaddress.ip_address(address)
        networks = [ipaddress.ip_network(row[0], strict=False) for row in rules]
    except ValueError:
        return True
    return bool(networks) and not any(client.version == network.version and client in network for network in networks)

def is_ip_blocked(cur, address):
    return cur.execute("SELECT 1 FROM firewall_rules WHERE ip_address=?", (address,)).fetchone() is not None

def is_emergency_lockdown_enabled(cur):
    row = cur.execute("SELECT value FROM system_config WHERE key='emergency_lockdown'").fetchone()
    return bool(row and row[0] == "1")

def add_ip_block_rule(cur, address, reason, blocked_at, blocked_by):
    cur.execute("""INSERT INTO firewall_rules(ip_address,reason,blocked_at,blocked_by)
                   VALUES(?,?,?,?) ON CONFLICT(ip_address) DO UPDATE SET reason=excluded.reason,
                   blocked_at=excluded.blocked_at,blocked_by=excluded.blocked_by""",
                (address, reason, blocked_at, blocked_by))

def remove_ip_block_rule(cur, address):
    cur.execute("DELETE FROM firewall_rules WHERE ip_address=?", (address,))
    return cur.rowcount > 0

def save_emergency_lockdown(cur, enabled):
    cur.execute("""INSERT INTO system_config(key,value) VALUES('emergency_lockdown',?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""", ("1" if enabled else "0",))

def add_allowed_network(cur, cidr, added_at, added_by):
    cur.execute("INSERT OR IGNORE INTO geofence_rules(cidr,added_at,added_by) VALUES(?,?,?)",
                (cidr, added_at, added_by))

def remove_allowed_network(cur, cidr):
    cur.execute("DELETE FROM geofence_rules WHERE cidr=?", (cidr,))
    return cur.rowcount > 0

def verify_audit_chain(cur):
    previous = "0" * 64
    for row in cur.execute("SELECT timestamp,username,action,status,filename,block_hash,prev_hash FROM audit_logs ORDER BY id"):
        timestamp, username, action, status, filename, block_hash, prev_hash = row
        payload = f"{previous}|{username}|{action}|{status}|{filename}|{timestamp}"
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if prev_hash != previous or block_hash != expected:
            return False
        previous = block_hash
    return True

def record_canary_trip(cur, username, filename, address, timestamp):
    insert_audit_record(cur, username, "CANARY_ACCESS_ATTEMPT", "TRIPPED", filename)
    try:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_loopback:
            add_ip_block_rule(cur, address, "Security decoy file accessed", timestamp, "canary detector")
            cur.execute("DELETE FROM active_sessions WHERE ip_address=?", (address,))
    except ValueError:
        pass

def get_soc_metrics():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now = datetime.now(timezone.utc)
        day_cutoff = (now - timedelta(days=6)).date().isoformat()
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%LOGIN%' AND (status LIKE '%DENIED%' OR status LIKE '%FAILED%' OR status LIKE '%LOCK%') AND datetime(timestamp)>=datetime('now','-24 hours')")
        failed_logins = cur.fetchone()[0]
        blocked_ips = cur.execute("SELECT COUNT(*) FROM firewall_rules").fetchone()[0]
        active_sessions = cur.execute("SELECT COUNT(*) FROM active_sessions").fetchone()[0]
        locked_accounts = cur.execute("SELECT COUNT(*) FROM users WHERE is_locked=1").fetchone()[0]
        canary_alerts = cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action='CANARY_ACCESS_ATTEMPT' AND timestamp>=?", ((now - timedelta(days=7)).isoformat(),)).fetchone()[0]
        cur.execute("SELECT date(timestamp),COUNT(*) FROM audit_logs WHERE date(timestamp)>=? GROUP BY date(timestamp)", (day_cutoff,))
        event_counts = {row[0]: row[1] for row in cur.fetchall()}
        lockdown = is_emergency_lockdown_enabled(cur)
        recent_events = [{"date": (now.date() - timedelta(days=i)).isoformat(),
                          "count": event_counts.get((now.date() - timedelta(days=i)).isoformat(), 0)}
                         for i in reversed(range(7))]
        threat = "CRITICAL" if canary_alerts else "HIGH" if lockdown else "ELEVATED" if failed_logins or blocked_ips or locked_accounts else "NORMAL"
        return {"threat_level": threat, "failed_logins_24h": failed_logins,
                "blocked_addresses": blocked_ips, "active_sessions": active_sessions,
                "locked_accounts": locked_accounts, "canary_alerts_7d": canary_alerts,
                "events_by_day": recent_events}
    finally:
        conn.close()

def release_expired_temporary_locks():
    """Clear expired temporary locks while retaining repeat-lockout history."""
    now = datetime.now(timezone.utc)
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, username, locked_until FROM users
                       WHERE is_locked=1 AND permanently_locked=0 AND locked_until IS NOT NULL""")
        expired = []
        for user_id, username, locked_until in cur.fetchall():
            try:
                expires_at = datetime.fromisoformat(locked_until)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                expires_at = now
            if expires_at <= now:
                expired.append((user_id, username))
        for user_id, username in expired:
            cur.execute("""UPDATE users SET is_locked=0, failed_attempts=0, locked_until=NULL
                           WHERE id=? AND permanently_locked=0""", (user_id,))
            insert_audit_record(cur, username, "TEMP_LOCK_EXPIRED", "AUTO_UNLOCKED", "")
        conn.commit()
        return len(expired)
    finally:
        conn.close()

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
        cur.execute("BEGIN IMMEDIATE")
        insert_audit_record(cur, username, action, status, filename)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT LOG ERROR]: {e}")

def authenticate_login(username, password):
    """Verify a login and enforce rolling temporary/permanent lockout policy."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("""SELECT id, password_hash, role, failed_attempts, is_locked,
                             lockout_count, locked_until, permanently_locked
                      FROM users WHERE username=?""", (username,))
        user = cur.fetchone()
        if not user:
            conn.commit()
            conn.close()
            log_audit(username, "LOGIN", "DENIED_INVALID_USER", "")
            return {"ok": False, "message": "Invalid username or password."}

        user_id, password_hash, role, failures, locked, lockouts, locked_until, permanent = user
        now = datetime.now(timezone.utc)

        if role == "admin" and (permanent or (locked and not locked_until)):
            cur.execute("""UPDATE users SET failed_attempts=0, lockout_count=0, is_locked=0,
                          locked_until=NULL, permanently_locked=0 WHERE id=?""", (user_id,))
            failures = lockouts = locked = permanent = 0
            locked_until = None

        if permanent:
            conn.commit()
            conn.close()
            log_audit(username, "LOGIN", "DENIED_PERMANENT_LOCK", "")
            return {"ok": False, "permanent": True,
                    "message": "This account is permanently locked. Contact an administrator."}

        if locked and locked_until:
            try:
                expires_at = datetime.fromisoformat(locked_until)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except ValueError:
                expires_at = now
            if expires_at > now:
                seconds = max(1, ceil((expires_at - now).total_seconds()))
                conn.commit()
                conn.close()
                log_audit(username, "LOGIN", "DENIED_TEMPORARY_LOCK", "")
                return {"ok": False, "locked": True,
                        "message": f"Account temporarily locked. Try again in about {seconds} second(s)."}
            cur.execute("UPDATE users SET is_locked=0, failed_attempts=0, locked_until=NULL WHERE id=?", (user_id,))
            failures = 0
        elif locked:
            # Keep legacy locks closed until an admin explicitly resets them.
            cur.execute("UPDATE users SET permanently_locked=1 WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
            log_audit(username, "LOGIN", "DENIED_PERMANENT_LOCK", "")
            return {"ok": False, "permanent": True,
                    "message": "This account is permanently locked. Contact an administrator."}

        try:
            valid_password = bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        except (ValueError, TypeError, AttributeError):
            valid_password = False

        if not valid_password:
            failures += 1
            if failures >= MAX_FAILED_ATTEMPTS:
                if role != "admin":
                    lockouts += 1
                if role != "admin" and lockouts >= PERMANENT_AFTER_LOCKOUTS:
                    cur.execute("""UPDATE users SET failed_attempts=?, lockout_count=?, is_locked=1,
                                   locked_until=NULL, permanently_locked=1 WHERE id=?""",
                                (failures, lockouts, user_id))
                    conn.commit()
                    conn.close()
                    log_audit(username, "LOGIN", "PERMANENTLY_LOCKED", "")
                    return {"ok": False, "permanent": True,
                            "message": "Account permanently locked after three lockouts. Contact an administrator."}
                until = (now + timedelta(seconds=TEMPORARY_LOCK_SECONDS)).isoformat()
                cur.execute("""UPDATE users SET failed_attempts=?, lockout_count=?, is_locked=1,
                               locked_until=?, permanently_locked=0 WHERE id=?""",
                            (failures, lockouts, until, user_id))
                conn.commit()
                conn.close()
                log_audit(username, "LOGIN", "TEMPORARILY_LOCKED", "")
                return {"ok": False, "locked": True,
                        "message": "Three consecutive failed attempts. Login is blocked for 30 seconds."}
            cur.execute("UPDATE users SET failed_attempts=? WHERE id=?", (failures, user_id))
            conn.commit()
            conn.close()
            log_audit(username, "LOGIN", f"FAILED_ATTEMPT_{failures}_OF_3", "")
            return {"ok": False,
                    "message": f"Invalid username or password. {MAX_FAILED_ATTEMPTS - failures} attempt(s) remain before a 30-second lock."}

        cur.execute("""UPDATE users SET failed_attempts=0, lockout_count=0,
                      is_locked=0, locked_until=NULL WHERE id=?""", (user_id,))
        conn.commit()
        conn.close()
        log_audit(username, "LOGIN", "SUCCESS", "")
        return {"ok": True, "id": user_id, "username": username, "role": role}
    except Exception:
        conn.rollback()
        conn.close()
        raise

def verify_file_access_password(username, password):
    """Re-check a signed-in user's password without changing login lockout state."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash, role FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        if not user:
            return {"ok": False, "message": "Invalid username or password."}
        user_id, password_hash, role = user
        try:
            valid = bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            return {"ok": False, "message": "Invalid password. Login attempt counts are unchanged."}
        return {"ok": True, "id": user_id, "username": username, "role": role}
    finally:
        conn.close()

def authenticate_and_verify(username, password, filename):
    login_result = verify_file_access_password(username, password)
    if not login_result.get("ok"):
        log_audit(username, "FILE_PASSWORD_CHECK", "DENIED_INVALID_PASSWORD", filename)
        return login_result["message"]
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""SELECT id, role FROM users WHERE username = ?""", (username,))
        user = cur.fetchone()

        # 1. Invalid User Protection (No Crash)
        if not user:
            log_audit(username, 'UNAUTHORIZED_ACCESS', 'DENIED_INVALID_USER', filename)
            conn.close()
            return "ACCESS DENIED: Unknown User! Incident Logged in DBMS Audit."

        user_id, role = user

        # 4. SHA-256 Dynamic File Integrity Check
        file_hash = calculate_file_hash(filename)
        if not file_hash:
            log_audit(username, 'FILE_VERIFY', 'FILE_MISSING', filename)
            conn.close()
            return f"SECURITY ERROR: Target file '{filename}' missing on disk!"

        # 5. Role-Based Access Control (RBAC)
        if role == 'admin':
            log_audit(username, 'READ_FILE', 'ALLOWED_ADMIN', filename)
            conn.close()
            return f"ACCESS GRANTED [ADMIN]: SHA-256 Verified ({file_hash[:10]}...). Reading '{filename}'."

        cur.execute("SELECT can_read FROM vw_active_security_permissions WHERE user_id = ? AND filename = ?", (user_id, filename))
        perm = cur.fetchone()
        conn.close()

        if perm and perm[0] == 1:
            log_audit(username, 'READ_FILE', 'ALLOWED_EMPLOYEE', filename)
            return f"ACCESS GRANTED [EMPLOYEE]: SHA-256 Verified ({file_hash[:10]}...). Reading '{filename}'."
        else:
            log_audit(username, 'UNAUTHORIZED_FILE_ACCESS', 'DENIED_NO_PERM', filename)
            return f"ACCESS DENIED: Employee '{username}' does NOT have permission for '{filename}'!"

    except Exception as e:
        return f"FAIL-SAFE TRIGGERED: Exception handled safely ({str(e)})"

def admin_unlock_user(admin_user, target_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""UPDATE users SET failed_attempts=0, lockout_count=0, is_locked=0,
                      locked_until=NULL, permanently_locked=0 WHERE username=?""", (target_user,))
        conn.commit()
        conn.close()
        log_audit(admin_user, 'UNLOCK_ACCOUNT', 'SUCCESS', target_user)
        return f"ADMIN ACTION: Account for '{target_user}' has been UNLOCKED."
    except Exception as e:
        return f"Admin Unlock Failed: {e}"
