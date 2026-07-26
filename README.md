# SentinelWP — WordPress Security Sentinel

Enterprise-grade, non-destructive WordPress security assessment and posture management platform.

SentinelWP is an advanced security auditing and reconnaissance tool designed to evaluate the security posture of WordPress websites and web applications. It provides detailed analysis of attack surfaces, misconfigurations, sensitive information exposure, and HTTP security header compliance without performing destructive actions.

---

## Key Features

- **SSRF Protection & Target Safety**: Integrated SSRF protection mechanism that automatically blocks requests to private IP subnets (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, etc.) and local hostnames.
- **3 Scan Modes**:
  - **Passive** (Default): Zero-impact analysis of the homepage and linked public assets.
  - **Safe-Active**: Non-destructive checks against known WordPress endpoints and public files.
  - **Full**: Includes audit of common default credentials (limited to a maximum of 20 attempts).
- **Multi-Signal WordPress Detection**: Fingerprinting algorithm with aggregate confidence scoring (0.0 to 1.0) based on 8 independent signals (meta generator, asset paths, REST API, cookies, RSS feeds, etc.).
- **REST API & Cookie Audit**:
  - Full route discovery and namespace inspection via /wp-json/ with privacy-first user endpoint auditing (no personal data stored).
  - Security flag analysis for HTTP response cookies (Secure, HttpOnly, SameSite).
- **Passive Plugin & Theme Discovery**: Zero-request extraction of plugins and themes from HTML page source.
- **Exposure & Hardening Checks**: Identification of backup files (wp-config.php.bak), debug logs, directory listing, HTTPS redirection, and visible PHP error messages.
- **Executive Reporting**: Automated report generation in PDF, HTML, Excel, and JSON formats.
- **Role-Based Access Control (RBAC)**: Multi-user management (Admin, Analyst, Viewer) with secure sessions.

---

## Quick Start

### Requirements
- Python 3.10+
- Virtual environment (`venv`)

### Installation & Execution

1. Clone the repository:
   ```bash
   git clone https://github.com/melillopietro/SentinelWP.git
   cd SentinelWP
   ```

2. Activate virtual environment and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Launch the platform:
   ```bash
   python3 app.py
   ```

4. Access the Web Dashboard:
   - URL: http://localhost:8080
   - Default Username: admin
   - Default Password: admin

---

## Architecture & Technology Stack

- **Backend & Web UI**: Python 3, Flask, Jinja2, Vanilla CSS (Dark Theme)
- **Database**: SQLite3 (WAL mode enabled, automatic schema management)
- **Reporting Engine**: ReportLab (PDF generation), OpenPyXL (Excel generation)
- **Security Core**: Requests, Python ipaddress and socket validation modules

---

## Security & Ethical Guidelines

SentinelWP is developed following safe security assessment practices:
- No destructive exploitation techniques or target database modifications.
- Automatic redaction of credentials and secrets detected in exposed configuration files (`content_redacted: True`).
- Alignment with OWASP web application security testing guidelines.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

