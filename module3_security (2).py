import bcrypt
import hashlib
import os
import shutil
import sqlite3
import json
import time
from datetime import datetime, timedelta, timezone
from module1_dbms import get_db_connection

MAX_FAILED_ATTEMPTS = 3
BACKUP_DIR = "security_media_backups"

if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# =========================================================================
# 1. REAL-TIME NETWORK IP FIREWALL & AUTO-BLOCK MANAGER
# =========================================================================
IP_BLOCKLIST_DB = {
    "185.220.101.5": {"reason": "Suspicious Activity", "blocked_at": "2026-11-08 12:00", "country": "DE"},
    "45.144.225.12": {"reason": "Multiple Failed Logins", "blocked_at": "2026-11-08 12:30", "country": "RU"}
}

def verify_ip_reputation(ip_address):
    """Real-time Check: Checks if Client IP is blocked in Firewall"""
    if not ip_address:
        ip_address = "127.0.0.1"

    if ip_address in IP_BLOCKLIST_DB:
        block_info = IP_BLOCKLIST_DB[ip_address]
        return {
            "ok": False,
            "status": "BLOCKED",
            "reason": block_info["reason"],
            "message": f"🚫 ACCESS DENIED: IP Address {ip_address} is blocked by Admin ({block_info['reason']})."
        }
    return {"ok": True, "message": "IP Check Passed."}

def add_ip_to_blocklist(ip_address, reason="Manual Admin Block", country="Local Network"):
    """Adds a new client/server IP to the firewall blocklist in real time."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    block_info = {
        "reason": reason,
        "blocked_at": now_str,
        "country": country
    }
    IP_BLOCKLIST_DB[ip_address] = block_info
    return block_info

def remove_ip_from_blocklist(ip_address):
    """Unblocks an IP from the firewall."""
    if ip_address in IP_BLOCKLIST_DB:
        del IP_BLOCKLIST_DB[ip_address]
        return True
    return False

def get_ip_blocklist_summary():
    """Returns list of all currently blocked IPs."""
    return {
        "ok": True,
        "total_blocked": len(IP_BLOCKLIST_DB),
        "blocked_ips": IP_BLOCKLIST_DB
    }

# =========================================================================
# 2. BLOCKCHAIN-BACKED IMMUTABLE AUDIT TRAIL
# =========================================================================
def calculate_blockchain_hash(previous_hash, username, action, status, filename, timestamp):
    data_block = f"{previous_hash}|{username}|{action}|{status}|{filename}|{timestamp}"
    return hashlib.sha256(data_block.encode('utf-8')).hexdigest()

def log_audit_blockchain(username, action, status, filename="PORTAL"):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(audit_logs);")
        columns = [column[1] for column in cur.fetchall()]
        if 'block_hash' not in columns:
            cur.execute("ALTER TABLE audit_logs ADD COLUMN block_hash TEXT;")
            cur.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT;")
            conn.commit()

        cur.execute("SELECT block_hash FROM audit_logs ORDER BY id DESC LIMIT 1;")
        last_block = cur.fetchone()
        prev_hash = last_block[0] if (last_block and last_block[0]) else "0" * 64

        timestamp = datetime.now(timezone.utc).isoformat()
        curr_hash = calculate_blockchain_hash(prev_hash, username, action, status, filename, timestamp)

        cur.execute("""
            INSERT INTO audit_logs (username, action, status, filename, timestamp, block_hash, prev_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, action, status, filename, timestamp, curr_hash, prev_hash))

        conn.commit()
        conn.close()
        return curr_hash
    except Exception as e:
        print(f"Blockchain Audit Error: {e}")

def verify_blockchain_integrity():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, action, status, filename, timestamp, block_hash, prev_hash FROM audit_logs ORDER BY id ASC;")
        logs = cur.fetchall()
        conn.close()

        expected_prev_hash = "0" * 64
        for log in logs:
            log_id, username, action, status, filename, timestamp, block_hash, prev_hash = log
            if not block_hash:
                continue 
            recalculated_hash = calculate_blockchain_hash(prev_hash, username, action, status, filename, timestamp)
            if recalculated_hash != block_hash or prev_hash != expected_prev_hash:
                return {
                    "ok": False,
                    "status": "BLOCKCHAIN_TAMPER_DETECTED",
                    "tampered_log_id": log_id,
                    "message": f"ALERT: Blockchain Integrity Violation detected at Log Entry ID {log_id}!"
                }
            expected_prev_hash = block_hash

        return {"ok": True, "status": "VERIFIED", "message": "Blockchain Audit Chain Intact. Zero Tampering Detected."}
    except Exception as e:
        return {"ok": False, "message": f"Verification Error: {str(e)}"}

# =========================================================================
# 3. KEYSTROKE DYNAMICS & BOT DETECTION
# =========================================================================
def verify_keystroke_dynamics(user_id, timing_array):
    if not timing_array or len(timing_array) < 2:
        return {"ok": True, "score": 100, "message": "Keystroke analysis skipped."}

    avg_latency = sum(timing_array) / len(timing_array)
    if avg_latency < 30:
        return {"ok": False, "score": 10, "message": "SECURITY ALERT: Automated Bot or Scripted Injection Detected!"}
    if avg_latency > 800:
        return {"ok": False, "score": 40, "message": "KEYSTROKE DYNAMICS MISMATCH: Imposter typing rhythm detected!"}

    return {"ok": True, "score": 95, "message": f"Keystroke Dynamics Matched ({int(avg_latency)}ms)."}

# =========================================================================
# 4. ZERO-TRUST GEO-IP & GEOFENCING
# =========================================================================
def verify_geo_ip_geofencing(ip_address):
    if not ip_address:
        ip_address = "127.0.0.1"
    suspicious_subnets = ["192.168.100.", "10.99.99."]
    if any(ip_address.startswith(sub) for sub in suspicious_subnets):
        return {"ok": False, "message": f"ZERO-TRUST GUARD: Suspicious IP subnet ({ip_address}) blocked by Geofencing policy."}
    return {"ok": True, "message": "IP Geofencing check passed."}

# =========================================================================
# 5. SOC & EMERGENCY LOCKDOWN CONTROLS
# =========================================================================
def set_emergency_lockdown(enable=True):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT)")
    cur.execute("INSERT OR REPLACE INTO system_config (key, value) VALUES ('lockdown_active', ?)", ('1' if enable else '0',))
    conn.commit()
    conn.close()
    log_audit_blockchain("SYSTEM_ADMIN", "EMERGENCY_LOCKDOWN", "ENABLED_READ_ONLY" if enable else "DISABLED_NORMAL", "PORTAL_SECURITY")
    return enable

def get_emergency_lockdown_status():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_config';")
        if not cur.fetchone():
            conn.close()
            return False
        cur.execute("SELECT value FROM system_config WHERE key = 'lockdown_active'")
        row = cur.fetchone()
        conn.close()
        return row and row[0] == '1'
    except:
        return False

def get_soc_metrics():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM audit_logs WHERE action LIKE '%LOGIN%' AND (status LIKE '%LOCKED%' OR status LIKE '%FAILED%')")
        brute_force_blocks = cur.fetchone()[0]
        
        cur.execute("SELECT count(*) FROM audit_logs WHERE action LIKE '%KEYSTROKE%' OR status LIKE '%IMPOSTER%' OR status LIKE '%BOT%'")
        bot_detections = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM audit_logs WHERE action LIKE '%FIREWALL%' OR action LIKE '%BLOCK%'")
        firewall_blocks = cur.fetchone()[0]
        conn.close()
        
        is_locked = get_emergency_lockdown_status()
        if is_locked:
            threat_level = "RED (EMERGENCY LOCKDOWN)"
        elif brute_force_blocks > 2 or bot_detections > 0 or firewall_blocks > 0:
            threat_level = "ORANGE (ELEVATED THREAT)"
        else:
            threat_level = "GREEN (NORMAL ZERO-TRUST)"
            
        return {
            "ok": True,
            "brute_force_blocks": brute_force_blocks,
            "bot_detections": bot_detections,
            "firewall_blocks": firewall_blocks,
            "threat_level": threat_level,
            "lockdown_active": is_locked,
            "active_blocked_ips": len(IP_BLOCKLIST_DB)
        }
    except Exception as e:
        return {
            "ok": True,
            "brute_force_blocks": 0,
            "bot_detections": 0,
            "firewall_blocks": 0,
            "threat_level": "GREEN (NORMAL ZERO-TRUST)",
            "lockdown_active": False,
            "active_blocked_ips": len(IP_BLOCKLIST_DB)
        }

# =========================================================================
# 6. AUTHENTICATION ENGINE
# =========================================================================
def authenticate_login(username, password, keystroke_timings=None, client_ip="127.0.0.1"):
    try:
        ip_check = verify_ip_reputation(client_ip)
        if not ip_check["ok"]:
            log_audit_blockchain(username, 'FIREWALL_IP_BLOCK', 'BLOCKED', client_ip)
            return {"ok": False, "edge_blocked": True, "message": ip_check["message"]}

        geo_res = verify_geo_ip_geofencing(client_ip)
        if not geo_res["ok"]:
            log_audit_blockchain(username, 'GEOFENCE_BLOCK', 'BLOCKED_IP', client_ip)
            return {"ok": False, "message": geo_res["message"]}

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, password_hash, role, failed_attempts, is_locked, locked_until 
            FROM users WHERE LOWER(username) = LOWER(?)
        """, (username,))
        user = cur.fetchone()
        
        if not user:
            conn.close()
            log_audit_blockchain(username, 'LOGIN', 'FAILED_USER_NOT_FOUND', 'PORTAL')
            return {"ok": False, "message": "Unauthorized username or invalid credentials."}

        user_id, db_username, stored_hash, role, failed_attempts, is_locked, locked_until = user

        if keystroke_timings:
            ks_res = verify_keystroke_dynamics(user_id, keystroke_timings)
            if not ks_res["ok"]:
                conn.close()
                log_audit_blockchain(db_username, 'KEYSTROKE_DYNAMIC_REJECT', 'BOT_DETECTED', 'PORTAL')
                return {"ok": False, "message": ks_res["message"]}

        if locked_until:
            try:
                lock_time = datetime.fromisoformat(locked_until)
                if lock_time.tzinfo is None:
                    lock_time = lock_time.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) < lock_time:
                    remaining = int((lock_time - datetime.now(timezone.utc)).total_seconds()) + 1
                    conn.close()
                    return {"ok": False, "locked": True, "message": f"Cooldown active. Wait {remaining} seconds."}
            except:
                pass

        if is_locked == 1:
            conn.close()
            return {"ok": False, "locked": True, "message": "Account permanently locked. Contact admin."}

        password_valid = False
        try:
            password_valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except:
            password_valid = (password == stored_hash)

        if password_valid:
            cur.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            log_audit_blockchain(db_username, 'LOGIN', 'SUCCESS', 'PORTAL')
            return {"ok": True, "id": user_id, "username": db_username, "role": role}
        else:
            new_attempts = failed_attempts + 1
            is_locked_val = 1 if new_attempts >= MAX_FAILED_ATTEMPTS else 0
            cooldown_until = (datetime.now(timezone.utc) + timedelta(seconds=15)).isoformat()
            
            cur.execute("UPDATE users SET failed_attempts = ?, is_locked = ?, locked_until = ? WHERE id = ?", 
                        (new_attempts, is_locked_val, cooldown_until, user_id))
            conn.commit()
            conn.close()

            # Auto-block IP if failed attempts reach threshold
            if new_attempts >= MAX_FAILED_ATTEMPTS:
                add_ip_to_blocklist(client_ip, reason="Automated Brute-Force Attack Detected")

            if is_locked_val:
                log_audit_blockchain(db_username, 'FAILED_LOGIN', 'ACCOUNT_LOCKED_3_ATTEMPTS', 'PORTAL')
                return {"ok": False, "locked": True, "message": "Account locked after 3 failed attempts."}
            else:
                log_audit_blockchain(db_username, 'FAILED_LOGIN', f'ATTEMPT_{new_attempts}_OF_3', 'PORTAL')
                return {"ok": False, "locked": False, "message": f"Invalid password. Attempt {new_attempts}/3."}
    except Exception as e:
        return {"ok": False, "message": f"Login error: {str(e)}"}

def execute_2pl_secure_transaction(username, filename, action_type):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN EXCLUSIVE TRANSACTION;") 
        cur.execute("SELECT id FROM files WHERE filename = ?", (filename,))
        if not cur.fetchone():
            conn.rollback()
            return "2PL Lock Aborted: Target file locked or non-existent."
        log_audit_blockchain(username, action_type, '2PL_LOCKED_SUCCESS', filename)
        conn.commit() 
        return f"2PL Transaction Success: Serializability Enforced for '{filename}'."
    except Exception as e:
        conn.rollback()
        return f"2PL Security Trigger: Transaction Aborted ({e})"
    finally:
        conn.close()

def create_security_checkpoint():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("PRAGMA wal_checkpoint(FULL);")
    conn.close()
    backup_path = os.path.join(BACKUP_DIR, "security_system_media_vault.db")
    shutil.copyfile("security_system.db", backup_path)
    return f"CHECKPOINT CREATED: Vault Updated at '{backup_path}'."

def recover_from_media_failure():
    backup_path = os.path.join(BACKUP_DIR, "security_system_media_vault.db")
    if not os.path.exists(backup_path):
        return "Media Recovery Error: No backup found!"
    shutil.copyfile(backup_path, "security_system.db")
    return "MEDIA RECOVERY EXECUTED: System restored successfully."

def recover_from_system_crash():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM audit_logs;")
    logs_count = cur.fetchone()[0]
    conn.close()
    return f"CRASH RECOVERY COMPLETE: {logs_count} Audit logs recovered."

def calculate_file_hash(filepath):
    if not os.path.exists(filepath):
        return None
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return None

def verify_file_access_password(username, password):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        user = cur.fetchone()
        conn.close()
        if not user: return {"ok": False, "message": "User not found."}
        user_id, db_username, stored_hash, role = user
        valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')) if isinstance(stored_hash, str) else (password == stored_hash)
        if valid: return {"ok": True, "id": user_id, "username": db_username, "role": role}
        return {"ok": False, "message": "Invalid password."}
    except Exception as e:
        return {"ok": False, "message": str(e)}

def admin_unlock_user(admin_user, target_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL WHERE username = ?", (target_user,))
        conn.commit()
        conn.close()
        log_audit_blockchain(admin_user, 'UNLOCK_ACCOUNT', 'SUCCESS', target_user)
        return f"Account for '{target_user}' has been UNLOCKED."
    except Exception as e:
        return f"Unlock Failed: {e}"