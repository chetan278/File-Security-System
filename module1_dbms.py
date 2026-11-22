import sqlite3
import bcrypt

DB_NAME = "security_system.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency and zero-loss crash recovery
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee',
            is_locked INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0
        )
    ''')

    # 2. User Emails Table (Multi-Email Support)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT UNIQUE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # 3. Files Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT UNIQUE NOT NULL,
            file_size_kb INTEGER NOT NULL
        )
    ''')

    # 4. Permissions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_id INTEGER,
            can_read INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
        )
    ''')

    # 5. Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT,
            action TEXT,
            status TEXT,
            filename TEXT
        )
    ''')

    # 6. Password Reset OTPs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            otp TEXT,
            expires_at DATETIME
        )
    ''')

    # Default Admin Creator
    cursor.execute("SELECT * FROM users WHERE username = 'Madhvan'")
    if not cursor.fetchone():
        hashed_pw = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('Madhvan', hashed_pw, 'admin'))
        admin_id = cursor.lastrowid
        cursor.execute("INSERT INTO user_emails (user_id, email) VALUES (?, ?)", (admin_id, 'madhvansharma1706@gmail.com'))

    conn.commit()
    conn.close()
    print("[INFO] Database initialized successfully with WAL Mode & security schemas!")

if __name__ == '__main__':
    init_db()