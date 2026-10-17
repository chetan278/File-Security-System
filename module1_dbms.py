import sqlite3
import json
import time

DB_NAME = "security_system.db"
def get_db_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")  # WAL Mode for Recovery
    return conn

def setup_dbms_architecture():
    conn = get_db_connection()
    cur = conn.cursor()

    # -------------------------------------------------------------
    # 1. CORE SCHEMA & ASSERTIONS / CONSTRAINTS
    # -------------------------------------------------------------
    # Tables with CHECK Constraints (Assertions simulation)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'employee')),
            failed_attempts INTEGER DEFAULT 0 CHECK(failed_attempts >= 0),
            is_locked INTEGER DEFAULT 0 CHECK(is_locked IN (0, 1))
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT UNIQUE NOT NULL,
            filepath TEXT NOT NULL,
            file_size_kb REAL DEFAULT 0.0 CHECK(file_size_kb >= 0)
        );
    """)

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
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            filename TEXT NOT NULL
        );
    """)

    # --- NOSQL FEATURE: Document/JSON Table (NoSQL Document Store in SQL) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nosql_unstructured_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id TEXT UNIQUE NOT NULL,
            payload_json TEXT NOT NULL  -- Storing dynamic BSON/JSON document
        );
    """)

    # -------------------------------------------------------------
    # 2. INDEXING FOR QUERY OPTIMIZATION
    # -------------------------------------------------------------
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_perm_composite ON permissions(user_id, file_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_action ON audit_logs(username, action);")

    # -------------------------------------------------------------
    # 3. TRIGGERS (Automated Business Rules & Audit Enforcement)
    # -------------------------------------------------------------
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_audit_file_deletion
        AFTER DELETE ON files
        FOR EACH ROW
        BEGIN
            INSERT INTO audit_logs (username, action, status, filename)
            VALUES ('DBMS_TRIGGER_ENGINE', 'DELETE_FILE', 'REMOVED_PERMANENTLY', OLD.filename);
        END;
    """)

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
    cur.execute("""
        CREATE VIEW IF NOT EXISTS vw_active_security_permissions AS
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
        WHERE u.is_locked = 0;
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
        return f"❌ Dynamic SQL Error: Invalid Column '{filter_column}'"

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
        cur.execute("SELECT id FROM files WHERE filename = ?", (filename,))
        f = cur.fetchone()

        if not u or not f:
            conn.rollback()
            return "❌ Stored Procedure Failed: User or File does not exist!"

        cur.execute("""
            INSERT OR REPLACE INTO permissions (user_id, file_id, can_read)
            VALUES (?, ?, ?)
        """, (u[0], f[0], can_read))

        conn.commit()
        return f"✅ Stored Procedure Executed: Granted permission ({can_read}) to '{username}' for '{filename}'."
    except Exception as e:
        conn.rollback()
        return f"❌ Transaction Aborted: {str(e)}"
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
# 7. INDEX OPTIMIZATION BENCHMARK (EXPLAIN QUERY PLAN)
# -------------------------------------------------------------
def analyze_query_optimization():
    """Demonstrates Query Execution Plan & B-Tree Index Optimization"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Check Query Plan using B-Tree Index
    cur.execute("EXPLAIN QUERY PLAN SELECT * FROM users WHERE username = 'chetan_emp';")
    plan = cur.fetchall()
    conn.close()
    return plan

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
    return f"📦 NoSQL Document '{doc_id}' stored successfully!"

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
        raise SystemExit("  ⚠️ [SIMULATION CRASH] Unexpected Outage!")
    except SystemExit as e:
        print(f"{e}")
        conn.rollback() # ACID Rollback
        print("  ✅ [DBMS RECOVERY] Rollback successful via WAL Mode.")
    finally:
        conn.close()