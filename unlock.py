import sqlite3

conn = sqlite3.connect('security_database.db')
cur = conn.cursor()
cur.execute("UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE username = 'admin_user'")
conn.commit()
conn.close()

print("Admin account successfully unlocked!")