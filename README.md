# 🛡️ File Security System — Aegis

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-46E3B7?logo=render&logoColor=white)](https://security-system-xeho.onrender.com)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57?logo=sqlite&logoColor=white)

**Aegis** is a Python/Flask file security platform that combines **DBMS**, **Operating System** and **application-security** concepts. It protects sensitive files with encryption, role-based access control, account lockouts, integrity checking and tamper-evident audit logging, all managed from a single-page web dashboard.

🔗 **Live demo:** https://security-system-xeho.onrender.com

> The demo runs on Render's free hosting. If it has been idle, the first load may take a short while to wake up.

---

## ✨ Features

### Authentication & Access Control
- **bcrypt password hashing** for all user accounts.
- **Role-based access control (RBAC)** with five roles: `admin`, `employee`, `hr`, `project_manager`, `director`.
- **Per-user, per-file read permissions**, managed by admins.
- **Progressive account lockout:** 3 failed logins trigger a 30-second temporary lock; repeated lockouts lead to a permanent lock (admin accounts are exempt from permanent lock). Admins can unlock accounts.
- **Password reset via email OTP** (6-digit code, Gmail SMTP) with expiry, request rate-limiting and a maximum number of attempts.
- **Session tracking** with the ability for admins to terminate active sessions.

### File Protection
- **AES-256-GCM encryption** of protected file copies (`crypto_vault.py`), stored as encrypted blobs in the database.
- **SHA-256 integrity hashing** to detect file modification.
- **Upload, replace and unprotect** protected files from the dashboard (up to 100 MB per request).
- **Supported file types:** Word (`.doc`, `.docx`), PowerPoint (`.ppt`, `.pptx`), Excel/CSV (`.xls`, `.xlsx`, `.csv`), PDF, and images (`.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.webp`, `.tif`, `.tiff`).
- **Read-only secure viewing** of files in the browser (served with no-store cache headers).
- **Canary (decoy) files** that trip an alert and block the offending IP when accessed.

### Security Operations (SOC)
- **Tamper-evident audit log**: SHA-256 hash-chained records with an integrity-chain verification endpoint.
- **IP firewall rules** (block/unblock addresses) and **geofencing** by allowed network ranges.
- **Emergency lockdown** switch.
- **File-integrity-monitoring (FIM) simulation** and a **security scan** endpoint.
- **SOC metrics** (e.g. failed logins in the last 24 hours) and a **vault status** view.
- **Announcements** broadcast to users and **user management** (add/remove accounts) for admins.

### DBMS Concepts (`module1_dbms.py`)
- Normalised SQLite schema with foreign keys, `CHECK` constraints, an account-lockout **trigger** and **views**.
- **WAL mode**, automatic **database backups** (every 5 minutes), restore and recovery integrity checks.
- **2PL-style secure transactions** (`BEGIN IMMEDIATE`) and a transaction log.
- Stored-procedure-style permission granting, **CTE / window-function analytics**, and a NoSQL-style JSON document store.

### OS Concepts (`module2_os.py`)
- Process information and OS file-permission checks (`os.stat`).
- Locked, chunked file reads with limited concurrent readers (mutex/semaphores) and cross-platform file locking (Windows/Linux).
- Dashboard demonstrations of **deadlock-safe locking**, **demand paging (FIFO replacement)**, **round-robin process scheduling**, **SSTF disk scheduling** and the **Banker's algorithm**.
- Live **OS metrics** (CPU/memory via `psutil`).

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite (WAL mode) |
| Security | bcrypt, `cryptography` (AES-GCM), SHA-256, HMAC |
| Frontend | HTML, CSS, JavaScript (single-page dashboard in `static/`) |
| System info | `psutil` (and `pywin32` on Windows for Office file previews) |
| Hosting | Render |

---

## 📁 Project Structure

```text
File-Security-System/
├── app.py                 # Flask app, REST API routes, session/RBAC logic
├── main.py                # Legacy console demo script (use `python app.py --demo` instead)
├── module1_dbms.py        # Schema, trigger, views, backups, 2PL-style transactions, analytics
├── module2_os.py          # OS concepts: locking, concurrency, paging, scheduling
├── module3_security.py    # Authentication, lockout, firewall, geofence, audit chain
├── crypto_vault.py        # AES-256-GCM encryption for protected files
├── transaction.py         # Transaction logging helper
├── unlock.py              # Utility script to unlock the admin account
├── requirements.txt       # Python dependencies
├── static/
│   ├── index.html         # Single-page web interface
│   ├── site.css           # Styles
│   └── site.js            # Frontend logic
└── .gitignore
```

Files created at runtime (not committed): `security_system.db`, `database_backups/`, `protected_files/`, `.aegis_file_key`, `.env`.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or later
- `pip`

### Installation

```bash
git clone https://github.com/chetan278/File-Security-System.git
cd File-Security-System

# Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Run the web app

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser. Set the `PORT` environment variable to use a different port.

### Other commands

```bash
python app.py --demo                       # Run the console demo
python app.py --database-recovery-check    # Check DB integrity and audit-log availability
python app.py --database-restore           # Restore the DB from the latest backup
```

---

## ⚙️ Configuration

Configure through environment variables, or a local `.env` file (loaded automatically and git-ignored):

| Variable | Purpose |
|---|---|
| `AEGIS_SECRET_KEY` | Flask session secret. A random key is generated if unset (sessions reset on restart). |
| `AEGIS_FILE_KEY` | Passphrase used to derive the AES-256 file-encryption key. If unset, a key file `.aegis_file_key` is generated. |
| `AEGIS_OTP_PEPPER` | Extra secret used when hashing password-reset codes (defaults to the secret key). |
| `GMAIL_ADDRESS` | Sender address for password-reset emails. |
| `GMAIL_APP_PASSWORD` | Gmail app password for SMTP. |
| `PORT` | Port the server listens on (default `5000`). |

---

## 🔌 API Overview

| Area | Endpoints |
|---|---|
| Auth | `POST /api/login`, `POST /api/logout`, `GET /api/me`, `POST /api/password-reset/request`, `POST /api/password-reset/complete` |
| Users | `POST /api/users`, `/api/users/remove`, `/api/users/email`, `POST /api/unlock` |
| Files | `POST /api/files`, `/api/files/replace`, `/api/files/unprotect`, `GET /api/files/<name>/read`, `POST /api/access` |
| Permissions | `POST /api/permissions` |
| Monitoring | `GET /api/dashboard`, `/api/audit`, `/api/transactions`, `/api/sessions`, `/api/soc/metrics`, `/api/os/metrics`, `/api/operations` |
| Security | `/api/firewall`, `/api/security/geofence`, `/canary`, `/lockdown`, `/fim-simulate`, `/scan`, `/vault`, `/audit/verify`, `/api/db/recovery-check` |
| OS demos | `POST /api/os/demo/<kind>` |

---

## 👤 Demo Accounts

On a fresh database, two sample accounts are created for local testing:

| Username | Role |
|---|---|
| `admin_user` | admin |
| `chetan_emp` | employee |

The sample passwords are defined in `app.py` (`seed_sample_users`). **Change or remove them before any real deployment.**

---

## 🔒 Security Notes & Limitations

This is an academic/learning project and should be hardened before production use:

- Set `AEGIS_SECRET_KEY`, `AEGIS_FILE_KEY` and `AEGIS_OTP_PEPPER` as environment variables; never commit them.
- Do not commit `secret.key` or any `.db` file; keep them in `.gitignore` (and rotate any secret that was ever committed).
- Change the seeded demo passwords and disable sample accounts on public deployments.
- Serve over HTTPS and enable `SESSION_COOKIE_SECURE` in production.
- Encrypted copies are stored in the database, but the original uploaded files remain in server storage (`protected_files/`) and are what the viewer reads. FIM and firewall features are application-level simulations, and IP blocking can be affected by NAT/proxies.
- On Render's free tier the filesystem is ephemeral, so the SQLite database and uploaded files may reset on redeploy or restart. Use a persistent disk or an external database if data must be kept.

---

## 🎓 Learning Outcomes

- Relational schema design, triggers, views and crash recovery (WAL, backups)
- Transaction control and locking (2PL-style)
- Authentication, RBAC, password hashing and encryption at rest
- Audit trails with hash-chain integrity verification
- File-system access checks, file locking and concurrency control
- Process scheduling, paging, deadlock avoidance and the Banker's algorithm
- Building and deploying a Flask web application

---

## 👥 Team

**Team T026** — Department of Computer Science & Engineering, Graphic Era (Deemed to be University), Dehradun
Madhvan Sharma · Akshat Bansal · Prince Kumar · Chetan Chauhan
Mentor: Dr. Akanksha Gupta

---

## 📌 Links

- **Source code:** https://github.com/chetan278/File-Security-System
- **Live demo:** https://security-system-xeho.onrender.com
