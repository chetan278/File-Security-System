# File Security System

A Python-based file security and database management project designed to help manage users, file records, access permissions, and security auditing.

## Overview

The **File Security System** project aims to provide a structured way to manage file-related security operations. It can be extended with user authentication, role-based access control, file integrity verification, and audit logging.

## Objectives

- Manage user accounts and roles.
- Store file-related metadata in a database.
- Control access to protected operations.
- Support security auditing and activity tracking.
- Help detect unauthorized access or file changes.

## Technologies

- **Python** — application logic and security functions.
- **SQLite** — local relational database for users, file records, and logs.
- **Hashing** — can be used to verify file integrity.
- **Password hashing** — store password hashes instead of plain-text passwords.

## Suggested Features

1. **User Authentication** — verify user credentials before granting access.
2. **Role-Based Access Control** — distinguish administrator and employee permissions.
3. **Failed-Login Protection** — temporarily lock accounts after repeated failed attempts.
4. **File Integrity Checking** — calculate a cryptographic hash (such as SHA-256) and compare it with a trusted stored value.
5. **Audit Logs** — record actions, usernames, timestamps, and success/failure status.
6. **Database Management** — use constraints and transactions to maintain consistent records.
7. **Recovery and Reliability** — use appropriate database settings and error handling to reduce data-loss risks.

## Repository Contents

The repository currently shows a `README.md` file. Add the Python source files, dependency list, and usage instructions as the implementation is added.

A possible structure is:

```text
File-Security-System/
├── README.md
├── main.py
├── module1_dbms.py
├── module2_*.py
├── module3_security.py
├── requirements.txt
└── security_system.db   # generated at runtime; do not commit real user data
```

Adjust the filenames above to match the actual project files.

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/chetan278/File-Security-System.git
cd File-Security-System
```

### 2. Set up Python

Use Python 3.10 or later if compatible with the code.

```bash
python -m venv .venv
```

Activate the environment:

**Windows**
```bash
.venv\Scripts\activate
```

**macOS/Linux**
```bash
source .venv/bin/activate
```

### 3. Install dependencies

If the project includes `requirements.txt`, run:

```bash
pip install -r requirements.txt
```

If no dependency file exists, install only the packages required by the source code. For example, `bcrypt` may be needed if the implementation imports it. Modules such as `sqlite3`, `hashlib`, and `os` are included with Python.

### 4. Run the application

After adding or confirming the entry-point filename, run the corresponding script, for example:

```bash
python main.py
```

Use the actual entry-point name if it differs.

## Security Notes

- Never store passwords in plain text.
- Do not commit real passwords, private keys, sensitive files, or a database containing personal data.
- Restrict administrator-only operations and validate all inputs.
- Use parameterized SQL queries instead of building SQL statements by string concatenation.
- Keep audit logs protected against unauthorized modification.
- A file hash can indicate that a file changed, but integrity verification is meaningful only when the reference hash is stored securely.
- Test account-lockout and recovery behaviour before using the project with important data.

## Current Status

The screenshot of the repository shows an initial commit containing `README.md`. The features and commands above are a project description and setup template; confirm them against the actual source code before treating them as implemented.

## Contributing

1. Create a branch for your change.
2. Make and test the change.
3. Submit a pull request describing what changed.
