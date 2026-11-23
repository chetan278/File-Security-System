import sqlite3
import json
import time
import os
import hashlib
import threading
from datetime import datetime, timezone
from transaction import record_transaction

DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_system.db")
DATABASE_BACKUP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database_backups", "security_system_backup.db")
_automatic_backup_started = False
_automatic_backup_lock = threading.Lock()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")  # WAL Mode for Recovery
    return conn


def insert_audit_record(cur, username, action, status, filename="", timestamp=None):
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    previous = cur.execute("SELECT block_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous[0] if previous and previous[0] else "0" * 64
    payload = f"{previous_hash}|{username}|{action}|{status}|{filename}|{timestamp}"
    block_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    cur.execute("""INSERT INTO audit_logs
                   (timestamp, username, action, status, filename, block_hash, prev_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, username, action, status, filename, block_hash, previous_hash))
    return block_hash


def execute_2pl_secure_transaction(username, filename, action_type):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        file_row = cur.execute(
            "SELECT id FROM files WHERE filename=? AND is_protected=1", (filename,)
        ).fetchone()
        if not file_row:
            conn.rollback()
            return {"ok": False, "not_found": True,
                    "message": "The file is not currently protected."}
        timestamp = datetime.now(timezone.utc).isoformat()
        insert_audit_record(cur, username, action_type, "SUCCESS", filename, timestamp)
        record_transaction(cur, timestamp, username, action_type, filename, "SUCCESS")
        conn.commit()
        return {"ok": True, "message": f"Transaction recorded for '{filename}'."}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def create_database_backup():
    os.makedirs(os.path.dirname(DATABASE_BACKUP_PATH), exist_ok=True)
    temporary_path = DATABASE_BACKUP_PATH + ".tmp"
    try:
        source = get_db_connection()
        target = sqlite3.connect(temporary_path)
        try:
            source.backup(target)
            result = target.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise sqlite3.DatabaseError(f"Backup integrity check failed: {result}")
        finally:
            target.close()
            source.close()
        os.replace(temporary_path, DATABASE_BACKUP_PATH)
    except Exception:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise
    return DATABASE_BACKUP_PATH

def start_automatic_database_backups(interval_seconds=300):
    global _automatic_backup_started
    with _automatic_backup_lock:
        if _automatic_backup_started:
            return
        try:
            create_database_backup()
            print(f"Automatic database backup saved: {DATABASE_BACKUP_PATH}")
        except Exception as error:
            print(f"Automatic database backup failed: {error}")
        _automatic_backup_started = True

    def backup_loop():
        while True:
            time.sleep(interval_seconds)
            try:
                if recover_database_if_needed():
                    print("Database damage detected; restored the saved database backup.")
                create_database_backup()
                print(f"Automatic database backup refreshed: {DATABASE_BACKUP_PATH}")
            except Exception as error:
                print(f"Automatic database backup failed: {error}")

    threading.Thread(target=backup_loop, name="database-backup", daemon=True).start()

def restore_database_backup():
    if not os.path.isfile(DATABASE_BACKUP_PATH):
        raise FileNotFoundError("No database backup exists yet. Create one first.")
    source = sqlite3.connect(DATABASE_BACKUP_PATH)
    target = None
    try:
        result = source.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise sqlite3.DatabaseError(f"Backup integrity check failed: {result}")
        backup_tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required_tables = {"users", "files", "permissions", "audit_logs"}
        if not required_tables.issubset(backup_tables):
            raise sqlite3.DatabaseError("The database backup is missing required tables.")
        target = sqlite3.connect(DB_NAME)
        source.backup(target)
    finally:
        if target:
            target.close()
        source.close()
    return DB_NAME

def recover_database_if_needed():
    if not os.path.isfile(DB_NAME) or os.path.getsize(DB_NAME) == 0:
        if os.path.isfile(DATABASE_BACKUP_PATH):
            restore_database_backup()
            return True
        return False

    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError:
        integrity, tables = "failed", set()
    finally:
        if conn:
            conn.close()

    required_tables = {"users", "files", "permissions", "audit_logs"}
    if integrity == "ok" and (not tables or required_tables.issubset(tables)):
        return False
    if not os.path.isfile(DATABASE_BACKUP_PATH):
        raise sqlite3.DatabaseError("The database is damaged and no valid automatic backup is available.")
    restore_database_backup()
    return True

def check_database_recovery():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        integrity = cur.execute("PRAGMA integrity_check").fetchone()[0]
        audit_count = cur.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        return {"integrity": integrity, "audit_logs": audit_count}
    finally:
        conn.close()

def setup_dbms_architecture():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("DROP VIEW IF EXISTS vw_audit_logs_by_role")
    cur.execute("DROP VIEW IF EXISTS vw_audit_logs_by_name")

    # -------------------------------------------------------------
    # 1. CORE SCHEMA & ASSERTIONS / CONSTRAINTS
    # -------------------------------------------------------------
    # Tables with CHECK Constraints (Assertions simulation)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'employee', 'hr', 'project_manager', 'director')),
            failed_attempts INTEGER DEFAULT 0 CHECK(failed_attempts >= 0),
            is_locked INTEGER DEFAULT 0 CHECK(is_locked IN (0, 1)),
            lockout_count INTEGER NOT NULL DEFAULT 0 CHECK(lockout_count >= 0),
            locked_until TEXT,
            permanently_locked INTEGER NOT NULL DEFAULT 0 CHECK(permanently_locked IN (0, 1))
        );
    """)

    # Migrate databases created before timed and permanent account lockouts.
    columns = {row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()}
    for name, declaration in (
        ("lockout_count", "INTEGER NOT NULL DEFAULT 0"),
        ("locked_until", "TEXT"),
        ("permanently_locked", "INTEGER NOT NULL DEFAULT 0"),
        ("email", "TEXT"),
    ):
        if name not in columns:
            cur.execute(f"ALTER TABLE users ADD COLUMN {name} {declaration}")
    if "employee_type" in columns:
        conn.commit()
        cur.execute("DROP VIEW IF EXISTS vw_active_security_permissions")
        cur.execute("PRAGMA foreign_keys=OFF")
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("""CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'employee', 'hr', 'project_manager', 'director')),
                failed_attempts INTEGER DEFAULT 0 CHECK(failed_attempts >= 0),
                is_locked INTEGER DEFAULT 0 CHECK(is_locked IN (0, 1)),
                lockout_count INTEGER NOT NULL DEFAULT 0 CHECK(lockout_count >= 0),
                locked_until TEXT,
                permanently_locked INTEGER NOT NULL DEFAULT 0 CHECK(permanently_locked IN (0, 1)),
                email TEXT
            )""")
            cur.execute("""INSERT INTO users_new
                (id, username, password_hash, role, failed_attempts, is_locked,
                 lockout_count, locked_until, permanently_locked, email)
                SELECT id, username, password_hash,
                       CASE WHEN role='admin' THEN 'admin'
                            WHEN role IN ('hr','project_manager','director') THEN role
                            ELSE LOWER(COALESCE(NULLIF(employee_type,''),'EMPLOYEE')) END,
                       failed_attempts, is_locked, lockout_count, locked_until,
                       permanently_locked, email FROM users""")
            cur.execute("DROP TABLE users")
            cur.execute("ALTER TABLE users_new RENAME TO users")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.execute("PRAGMA foreign_keys=ON")
    # Existing manually locked accounts retain the old admin-unlock requirement.
    cur.execute("UPDATE users SET permanently_locked=1 WHERE is_locked=1 AND locked_until IS NULL AND permanently_locked=0")
    cur.execute("""UPDATE users SET failed_attempts=0, lockout_count=0, is_locked=0,
                   locked_until=NULL, permanently_locked=0
                   WHERE role='admin' AND permanently_locked=1""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT UNIQUE NOT NULL,
            filepath TEXT NOT NULL,
            file_size_kb REAL DEFAULT 0.0 CHECK(file_size_kb >= 0),
            is_protected INTEGER NOT NULL DEFAULT 1 CHECK(is_protected IN (0, 1))
        );
    """)
    file_columns = {row[1] for row in cur.execute("PRAGMA table_info(files)").fetchall()}
    if "is_protected" not in file_columns:
        cur.execute("ALTER TABLE files ADD COLUMN is_protected INTEGER NOT NULL DEFAULT 1 CHECK(is_protected IN (0, 1))")
    if "is_canary" not in file_columns:
        cur.execute("ALTER TABLE files ADD COLUMN is_canary INTEGER NOT NULL DEFAULT 0 CHECK(is_canary IN (0, 1))")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_id INTEGER NOT NULL,
            can_read INTEGER DEFAULT 1 CHECK(can_read IN (0, 1)),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            user_id INTEGER PRIMARY KEY,
            code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            window_started_at TEXT NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Keep a separate history of reset-code requests. The actual OTP is never
    # written here; only the account name, request time, and delivery outcome.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            filename TEXT NOT NULL
        );
    """)
    audit_columns = {row[1] for row in cur.execute("PRAGMA table_info(audit_logs)").fetchall()}
    if "block_hash" not in audit_columns:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN block_hash TEXT")
    if "prev_hash" not in audit_columns:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            ip_address TEXT NOT NULL,
            login_time TEXT NOT NULL,
            device_info TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            ip_address TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            blocked_at TEXT NOT NULL,
            blocked_by TEXT NOT NULL
        )
    """)
    cur.execute("CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    cur.execute("""CREATE TABLE IF NOT EXISTS geofence_rules (
                   cidr TEXT PRIMARY KEY, added_at TEXT NOT NULL, added_by TEXT NOT NULL)""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS protected_file_blobs (
            file_id INTEGER PRIMARY KEY,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            content_hash TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        )
    """)
    cur.execute("DROP INDEX IF EXISTS idx_transactions_time")
    cur.execute("DROP INDEX IF EXISTS idx_sessions_user")

    previous_hash = "0" * 64
    for record in cur.execute("SELECT id, timestamp, username, action, status, filename, block_hash FROM audit_logs ORDER BY id").fetchall():
        log_id, timestamp, username, action, status, filename, block_hash = record
        if block_hash:
            previous_hash = block_hash
            continue
        timestamp = str(timestamp or datetime.now(timezone.utc).isoformat())
        payload = f"{previous_hash}|{username}|{action}|{status}|{filename}|{timestamp}"
        block_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        cur.execute("UPDATE audit_logs SET timestamp=?, block_hash=?, prev_hash=? WHERE id=?",
                    (timestamp, block_hash, previous_hash, log_id))
        previous_hash = block_hash

    # --- NOSQL FEATURE: Document/JSON Table (NoSQL Document Store in SQL) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nosql_unstructured_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id TEXT UNIQUE NOT NULL,
            payload_json TEXT NOT NULL  -- Storing dynamic BSON/JSON document
        );
    """)

    cur.execute("DROP INDEX IF EXISTS idx_users_username")
    cur.execute("DROP INDEX IF EXISTS idx_perm_composite")
    cur.execute("DROP INDEX IF EXISTS idx_audit_user_action")
    cur.execute("DROP INDEX IF EXISTS idx_reset_request_time")

    # -------------------------------------------------------------
    # 3. TRIGGERS (Automated Business Rules & Audit Enforcement)
    # -------------------------------------------------------------
    cur.execute("DROP TRIGGER IF EXISTS trg_audit_file_deletion")

    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_auto_lockout_check
        AFTER UPDATE OF failed_attempts ON users
        FOR EACH ROW
        WHEN NEW.failed_attempts >= 3 AND OLD.is_locked = 0
        BEGIN
            UPDATE users SET is_locked = 1 WHERE id = NEW.id;
        END;
    """)

    # -------------------------------------------------------------
    # 4. SQL VIEWS (Virtual Tables)
    # -------------------------------------------------------------
    cur.execute("DROP VIEW IF EXISTS vw_active_security_permissions")
    cur.execute("""
        CREATE VIEW vw_active_security_permissions AS
        SELECT
            u.id as user_id,
            u.username,
            u.role,
            u.is_locked,
            f.filename,
            p.can_read
        FROM users u
        JOIN permissions p ON u.id = p.user_id
        JOIN files f ON f.id = p.file_id
        WHERE u.is_locked = 0 AND f.is_protected = 1;
    """)

    cur.execute("""
        CREATE VIEW vw_audit_logs_by_role AS
        SELECT a.id AS audit_id, a.timestamp, a.username, u.id AS user_id,
               u.role AS role_type, a.action, a.status, a.filename,
               a.prev_hash, a.block_hash
        FROM audit_logs a
        LEFT JOIN users u ON u.username = a.username;
    """)

    cur.execute("""
        CREATE VIEW vw_audit_logs_by_name AS
        SELECT a.id AS audit_id, a.timestamp, a.username AS name, u.id AS user_id,
               u.role AS role_type, a.action, a.status, a.filename,
               a.prev_hash, a.block_hash
        FROM audit_logs a
        LEFT JOIN users u ON u.username = a.username;
    """)

    conn.commit()
    conn.close()

# -------------------------------------------------------------
# 5. EMBEDDED & DYNAMIC SQL / STORED PROCEDURES (Python Wrapper)
# -------------------------------------------------------------
def execute_dynamic_search_procedure(filter_column, filter_value):
    """
    Demonstrates Dynamic SQL Construction safely with Parameter Binding 
    to prevent SQL Injection.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    # Safe Dynamic Query Generation
    allowed_columns = ['username', 'role', 'status', 'action']
    if filter_column not in allowed_columns:
        conn.close()
        return f"Dynamic SQL Error: Invalid Column '{filter_column}'"

    dynamic_query = f"SELECT * FROM audit_logs WHERE {filter_column} = ? ORDER BY id DESC LIMIT 5;"
    cur.execute(dynamic_query, (filter_value,))
    results = cur.fetchall()
    conn.close()
    return results

def stored_procedure_grant_permission(username, filename, can_read=1):
    """
    Database Stored Procedure (Procedural Logic Execution)
    Calculates user & file IDs inside a single Transaction block.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN TRANSACTION;")
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        u = cur.fetchone()
        cur.execute("SELECT id FROM files WHERE filename = ? AND is_protected=1", (filename,))
        f = cur.fetchone()

        if not u or not f:
            conn.rollback()
            return "Stored Procedure Failed: User or File does not exist!"

        cur.execute("""
            INSERT OR REPLACE INTO permissions (user_id, file_id, can_read)
            VALUES (?, ?, ?)
        """, (u[0], f[0], can_read))

        conn.commit()
        return f"Stored Procedure Executed: Granted permission ({can_read}) to '{username}' for '{filename}'."
    except Exception as e:
        conn.rollback()
        return f"Transaction Aborted: {str(e)}"
    finally:
        conn.close()

# -------------------------------------------------------------
# 6. ADVANCED SQL: CTEs & WINDOW FUNCTIONS
# -------------------------------------------------------------
def run_advanced_sql_analytics():
    """Demonstrates CTEs (Common Table Expressions) and Window Functions (ROW_NUMBER)"""
    conn = get_db_connection()
    cur = conn.cursor()

    query = """
    WITH UserAuditRank AS (
        SELECT
            username,
            action,
            timestamp,
            ROW_NUMBER() OVER(PARTITION BY username ORDER BY timestamp DESC) as rank_no
        FROM audit_logs
    )
    SELECT username, action, timestamp
    FROM UserAuditRank
    WHERE rank_no = 1;
    """
    cur.execute(query)
    recent_activity = cur.fetchall()
    conn.close()
    return recent_activity

# -------------------------------------------------------------
# 8. NOSQL (DOCUMENT STORE IN DBMS)
# -------------------------------------------------------------
def insert_nosql_document(doc_id, json_payload_dict):
    """Insert JSON Document directly into relational storage (NoSQL style)"""
    conn = get_db_connection()
    cur = conn.cursor()
    json_str = json.dumps(json_payload_dict)
    cur.execute("""
        INSERT OR REPLACE INTO nosql_unstructured_logs (doc_id, payload_json)
        VALUES (?, ?)
    """, (doc_id, json_str))
    conn.commit()
    conn.close()
    return f"NoSQL Document '{doc_id}' stored successfully!"

def query_nosql_document(doc_id):
    """Query NoSQL Document using SQL JSON Extraction"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT json_extract(payload_json, '$.system_metadata.ip') as ip_address,
            json_extract(payload_json, '$.threat_level') as threat
        FROM nosql_unstructured_logs
        WHERE doc_id = ?;
    """, (doc_id,))

    data = cur.fetchone()
    conn.close()
    return data

# -------------------------------------------------------------
# 9. CRASH RECOVERY DEMO
# -------------------------------------------------------------
def dbms_crash_recovery_demo():
    print("\n[DBMS MODULE] Simulating System Crash & Transaction Rollback...")
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO files (filename, filepath) VALUES ('crash_test.csv', '/tmp/crash')")
        print("  -> Uncommitted data inserted into WAL buffer...")
        raise SystemExit("  [SIMULATION CRASH] Unexpected Outage!")
    except SystemExit as e:
        print(f"{e}")
        conn.rollback() # ACID Rollback
        print("  [DBMS RECOVERY] Rollback successful via WAL Mode.")
    finally:
        conn.close()
