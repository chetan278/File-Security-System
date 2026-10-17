import os
import sys
import bcrypt

# Clean up old database file for schema alignment
DB_FILE = "security_system.db"
if os.path.exists(DB_FILE):
    try:
        os.remove(DB_FILE)
    except Exception:
        pass

try:
    from module1_dbms import (
        setup_dbms_architecture, get_db_connection, dbms_crash_recovery_demo,
        stored_procedure_grant_permission, run_advanced_sql_analytics, 
        analyze_query_optimization, insert_nosql_document, query_nosql_document
    )
    from module2_os import get_os_process_info, verify_os_file_permissions, secure_os_locked_read
    from module3_security import authenticate_and_verify, admin_unlock_user, calculate_file_hash
except ImportError as e:
    print(f"[IMPORT ERROR] Module missing: {e}")
    sys.exit(1)

def auto_discover_and_register_files():
    """DYNAMIC SECURITY ENGINE: Automatically finds and secures ALL CSV files in directory"""
    conn = get_db_connection()
    cur = conn.cursor()

    target_files = [f for f in os.listdir('.') if f.endswith('.csv')]
    print(f"\n🔍 [DYNAMIC FILE DISCOVERY] Found {len(target_files)} dataset(s) on Storage:")

    for file in target_files:
        size_kb = os.path.getsize(file) / 1024
        cur.execute("""
            INSERT OR IGNORE INTO files (filename, filepath, file_size_kb) 
            VALUES (?, ?, ?)
        """, (file, file, round(size_kb, 2)))

        cur.execute("SELECT id FROM files WHERE filename = ?", (file,))
        file_id = cur.fetchone()[0]
        # Grant read access only for ipl_data.csv to demonstrate permission blocking on other files
        can_read_val = 1 if "ipl_data.csv" in file else 0
        cur.execute("INSERT OR IGNORE INTO permissions (user_id, file_id, can_read) VALUES (2, ?, ?)", (file_id, can_read_val))

        f_hash = calculate_file_hash(file)
        print(f"   🔒 Secured: File = '{file}' | Size = {size_kb:.2f} KB | SHA-256 Hash = {f_hash[:16]}...")

    conn.commit()
    conn.close()
    return target_files

def seed_sample_users():
    conn = get_db_connection()
    cur = conn.cursor()

    admin_pass = bcrypt.hashpw("AdminPass123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    emp_pass = bcrypt.hashpw("EmpPass123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cur.execute("INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (1, 'admin_user', ?, 'admin')", (admin_pass,))
    cur.execute("INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (2, 'chetan_emp', ?, 'employee')", (emp_pass,))

    conn.commit()
    conn.close()

def run_project_demo():
    print("==========================================================================")
    print("   FAIL-SAFE ZERO-CRASH ENTERPRISE STORAGE & DYNAMIC SECURITY ENGINE       ")
    print("==========================================================================")

    # 1. SETUP DBMS ENGINE
    print("\n--- 1. INITIALIZING DBMS ENGINE ---")
    setup_dbms_architecture()
    seed_sample_users()
    print("  -> Base Engine Ready (Triggers, Views, Indexes, Foreign Keys, WAL Mode).")

    # 2. DYNAMIC FILE DISCOVERY
    print("\n--- 2. DYNAMIC UNIVERSAL FILE DISCOVERY ---")
    discovered_files = auto_discover_and_register_files()

    # 3. ADVANCED SQL & INDEXING
    print("\n--- 3. ADVANCED DBMS OPTIMIZATION & ANALYTICS ---")
    plan = analyze_query_optimization()
    print(f"  -> EXPLAIN QUERY PLAN (Index Optimization): {plan[0][-1]}")

    # 4. UNAUTHORIZED ACCESS & CRASH-PROOF TESTING
    print("\n--- 4. TESTING UNAUTHORIZED ACCESS & FAIL-SAFE PROTECTION ---")
    
    # Test 1: Fake/Hacker User Access (Should block without crash)
    print("\n ⚠️ [TEST 1] Unauthorized Hacker Access Test:")
    print(" ", authenticate_and_verify("hacker_user", "Hack123", "ipl_data.csv"))

    # Test 2: Password Guessing / Lockout Test
    print("\n ⚠️ [TEST 2] Bruteforce Attack Simulation (3-Attempt Lockout):")
    print(" ", authenticate_and_verify("chetan_emp", "WrongPass1", "ipl_data.csv"))
    print(" ", authenticate_and_verify("chetan_emp", "WrongPass2", "ipl_data.csv"))
    print(" ", authenticate_and_verify("chetan_emp", "WrongPass3", "ipl_data.csv"))
    print("  Attempt 4 (Locked Account):", authenticate_and_verify("chetan_emp", "EmpPass123", "ipl_data.csv"))

    # 5. ADMIN UNLOCK & SECURE MULTI-FILE ACCESS
    print("\n--- 5. ADMIN UNLOCK & MULTI-FILE RBAC VERIFICATION ---")
    print(" ", admin_unlock_user("admin_user", "chetan_emp"))
    for file in discovered_files:
        print(f"\n 🛡️ RBAC & Hash Verification for: [{file}]")
        auth_status = authenticate_and_verify("chetan_emp", "EmpPass123", file)
        print("  -> Auth Result:", auth_status)
        if "ACCESS GRANTED" in auth_status:
            print("  -> OS Kernel Read Lock:", secure_os_locked_read(file))

    # 6. DEMO DBMS RECOVERY
    dbms_crash_recovery_demo()

if __name__ == "__main__":
    run_project_demo()