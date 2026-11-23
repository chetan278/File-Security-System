def record_transaction(cursor, timestamp, username, action, target, status):
    cursor.execute(
        "INSERT INTO transactions(timestamp,username,action,target,status) VALUES(?,?,?,?,?)",
        (timestamp, username, action, target or "", status),
    )
