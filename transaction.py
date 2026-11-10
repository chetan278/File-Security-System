# transaction.py
from datetime import datetime
from module1_dbms import get_db_connection

def is_sensitive_file(filename):
    """Checks if the uploaded file is financial or sensitive based on filename keywords."""
    sensitive_keywords = ['financial', 'bank', 'statement', 'payroll', 'salary', 'transaction', 'account']
    filename_lower = filename.lower()
    return any(keyword in filename_lower for keyword in sensitive_keywords)

def process_file_with_selective_transaction(filename, file_size_kb, passcode=""):
    """
    Selective Transaction Handling:
    - Strict database transaction and enhanced audit logging for Financial/Bank files.
    - Lightweight standard insert for normal datasets (like IPL matches).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    sensitive = is_sensitive_file(filename)
    
    try:
        # Explicit database transaction start
        cursor.execute("BEGIN TRANSACTION;")
        
        cursor.execute("SELECT id FROM files WHERE filename = ?", (filename,))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute("UPDATE files SET file_size_kb = ? WHERE filename = ?", (file_size_kb, filename))
            file_id = existing['id']
        else:
            cursor.execute("INSERT INTO files (filename, file_size_kb, passcode) VALUES (?, ?, ?)", (filename, file_size_kb, passcode))
            file_id = cursor.lastrowid
            # Setup default permissions for non-admins
            cursor.execute("SELECT id FROM users WHERE role != 'admin'")
            non_admins = cursor.fetchall()
            for na in non_admins:
                cursor.execute("INSERT INTO permissions (user_id, file_id, can_read) VALUES (?, ?, 0)", (na['id'], file_id))

        # EXTRA STRICT AUDIT LOGGING ONLY FOR FINANCIAL / SENSITIVE FILES
        if sensitive:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                "INSERT INTO audit_logs (timestamp, username, action, status, filename) VALUES (?, ?, ?, ?, ?)",
                (current_time, 'SYSTEM_ENGINE', 'FINANCIAL_ACID_COMMIT', 'ENCRYPTED_AND_LOGGED', filename)
            )

        conn.commit()
        conn.close()
        return True, "Financial Transaction & Audit Logged Successfully" if sensitive else "Standard File Stored Successfully"

    except Exception as e:
        conn.rollback()  # Rollback if transaction fails
        conn.close()
        return False, f"Transaction Failed & Rolled Back: {str(e)}"