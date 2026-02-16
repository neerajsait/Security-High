markdown

# Security-High: Secure Personal Data Vault (Prototype)

A Flask-based web application focused on experimenting with high-security practices for storing and managing sensitive personal data. Features include user-derived encryption keys (Fernet), OTP-based authentication, session termination links, activity logging with email reports, rate limiting, and IP geolocation — all built as a learning project.

**Important**: This is an **educational prototype** demonstrating security concepts. It is **not production-ready** and should never be used to store real sensitive data. Many features are experimental.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green)](https://flask.palletsprojects.com/)
[![MySQL](https://img.shields.io/badge/MySQL-Database-orange)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/License-MIT-yellowgreen)](LICENSE)
[![Commits](https://img.shields.io/github/commit-activity/m/neerajsait/Security-High)](https://github.com/neerajsait/Security-High/commits/main)

## Why I Built This
I wanted to dive deeper into web application security beyond the basics — things like proper encryption at rest, secure authentication flows, session management, and monitoring suspicious activity. Most tutorials cover one or two concepts, so I decided to combine many of them into one project in my free time.

This is outside my usual full-stack work (Java/Spring Boot/React/MySQL), and it started as an experiment to see how far I could push Flask security features. It's still a prototype with plenty of rough edges, but implementing things like user-derived encryption keys and session termination links taught me a lot about real-world security challenges.

## Key Features (Implemented)
- **OTP Authentication** → Email-based OTP for signup verification and login (no plain password transmission after signup)
- **Data Encryption at Rest** → Sensitive data encrypted using Fernet with a key derived from user-provided details (name + DOB + phone)
- **On-Demand Decryption** → Records stay encrypted; decrypt individually by re-entering the key data
- **Secure Session Management** → Unique session tokens with email-based termination link (log out remotely if suspicious)
- **Activity Logging & Reports** → Tracks actions, sends detailed report with IP/location on logout
- **Rate Limiting** → Prevents brute-force attacks using Flask-Limiter
- **IP Geolocation** → Logs approximate location for login/activity alerts
- **File Support** → Encrypt/store images and videos alongside text data
- **CRUD Operations** → Add, view (encrypted/decrypted), update, delete records

## Screenshots
*(Add these soon — they’ll make the project look much more real! Run locally and capture login, home dashboard, decryption flow, email reports, etc. Upload to a `/screenshots` folder.)*

<!-- Example placeholders — replace with real images -->
<!-- ![Login Page](screenshots/login.png) -->
<!-- ![Home Dashboard](screenshots/home.png) -->
<!-- ![Decryption Flow](screenshots/decrypt.png) -->
<!-- ![Activity Report Email](screenshots/report.png) -->

## Tech Stack
- **Backend** — Python 3.8+ with Flask
- **Database** — MySQL + SQLAlchemy
- **Encryption** — cryptography (Fernet)
- **Email** — Flask-Mail (configured for SMTP, e.g., Gmail)
- **Rate Limiting** — Flask-Limiter
- **Other** — dotenv for env vars, requests for IP lookup

## Installation & Setup
### Prerequisites
- Python 3.8+
- MySQL server running locally or remotely
- Gmail or other SMTP account (recommend App Password if using Gmail)

### Steps
1. Clone the repo
   ```bash
   git clone https://github.com/neerajsait/Security-High.git
   cd Security-High

Create a .env file (copy from .env.example if provided, or create with these vars):

SECRET_KEY=your_strong_secret_key
MYSQL_USER=your_mysql_user
MYSQL_PASSWORD=your_mysql_password
MYSQL_HOST=localhost
MYSQL_DB=your_database_name
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password

(Recommended) Create virtual environmentbash

python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

Install dependenciesbash

pip install flask flask-mail flask-limiter sqlalchemy pymysql python-dotenv cryptography requests

Run the appbash

python app.py

Open in browser
Visit http://127.0.0.1:5000

Note: The app creates tables automatically on first run. Test with a throwaway email.What I Learned & ChallengesDeriving encryption keys from user knowledge (instead of storing them) was interesting but tricky — balancing security vs. usability.
Managing sessions securely with termination links took a lot of debugging (tokens, email links, validation).
SQLAlchemy + encrypted fields added complexity — handling binary data for images/videos was new.
Biggest challenge: keeping everything thread-safe and avoiding decryption errors across sessions.
Learned a ton about rate limiting, IP logging, and why real apps need HTTPS, CSRF tokens, etc.

Future ImprovementsAdd proper CSRF protection
Implement HTTPS in production setup
Better key derivation (consider PBKDF2 or Argon2)
Full audit logging dashboard
Two-factor beyond OTP (e.g., TOTP)
Search/filter records
Dockerize for easier deployment
Unit tests and input sanitization

Critical Ethics & Security NoteFor educational and personal experimentation only.This app handles simulated sensitive data — never store real personal/financial info.
The encryption scheme is experimental and not vetted by security experts.
Running publicly without proper hardening (HTTPS, WAF, etc.) would be dangerous.
Respect privacy laws — only test with your own data and consent.
I am not responsible for any misuse or data loss.

Use responsibly and only locally.LicenseMIT License — see the LICENSE file for details.Built in my free time by @neerajsait as a security learning project. Feedback very welcome!



