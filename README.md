# SentinelWP — WordPress Security Sentinel

Enterprise-grade, non-destructive WordPress security assessment and posture management platform.

SentinelWP is an advanced security auditing and reconnaissance tool designed to evaluate the security posture of WordPress websites and web applications. It provides detailed analysis of attack surfaces, misconfigurations, sensitive information exposure, and HTTP security header compliance without performing destructive actions.

---

## Key Features

- **Initial Setup Wizard**: Zero default credentials. A guided setup wizard (/setup) forces the creation of a custom primary Administrator account on first launch.
- **SSRF Protection & Target Safety**: Integrated SSRF protection mechanism that automatically blocks requests to private IP subnets (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, etc.) and local hostnames.
- **Async Background Scans & Live Progress**: Non-blocking thread-pool scan execution with real-time progress meter (0–100%) and AJAX status polling.
- **3 Scan Modes**:
  - **Passive** (Default): Zero-impact analysis of the homepage and linked public assets.
  - **Safe-Active**: Non-destructive checks against known WordPress endpoints and public files.
  - **Full**: Includes audit of common default credentials (limited to a maximum of 20 attempts).
- **Multi-Signal WordPress Detection**: Fingerprinting algorithm with aggregate confidence scoring (0.0 to 1.0) based on 8 independent signals (meta generator, asset paths, REST API, cookies, RSS feeds, etc.).
- **Live Vulnerability Intelligence**: Automatic matching of detected plugins and themes against official CVE databases via OSV.dev REST API.
- **Scheduled Recurring Audits**: Background scheduler for automated periodic security scans (every 12h, 24h, or 7 days).
- **SMTP Email & Webhook Alerting**: Automated alert dispatching via SMTP email and Webhooks (Slack, Microsoft Teams, or custom endpoints) upon detecting Critical or High severity findings.
- **REST API & Cookie Audit**:
  - Full route discovery and namespace inspection via /wp-json/ with privacy-first user endpoint auditing (no personal data stored).
  - Security flag analysis for HTTP response cookies (Secure, HttpOnly, SameSite).
- **Passive Plugin & Theme Discovery**: Zero-request extraction of plugins and themes from HTML page source.
- **Exposure & Hardening Checks**: Identification of backup files (wp-config.php.bak), debug logs, directory listing, HTTPS redirection, and visible PHP error messages.
- **Executive Reporting & SARIF**: Automated report generation in PDF, HTML, Excel, JSON, and OASIS SARIF v2.1.0 formats for CI/CD integration.
- **Rate Limiting & Anti-DDoS**: In-memory sliding window rate limiter per client IP address (HTTP 429).
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

4. Complete Initial Setup:
   - Access: http://localhost:8080
   - Follow the Initial Setup Wizard (/setup) to create your custom Administrator username and password.

---

## Architecture & Technology Stack

- **Backend & Web UI**: Python 3, Flask, Jinja2, Vanilla CSS (Dark Theme)
- **Database**: SQLite3 (WAL mode enabled, automatic schema management)
- **Async & Scheduling**: ThreadPoolExecutor, background daemon scheduler
- **Reporting Engine**: ReportLab (PDF), OpenPyXL (Excel), SARIF v2.1.0 JSON generator
- **Security Core**: Requests, Python ipaddress/socket validation, in-memory rate limiter

---

## Recent Updates & Changelog (v3.2)

The platform has been enhanced with several powerful, non-destructive auditing capabilities and usability optimizations:

- **Interactive Findings Detail View**: The scan detail page now features an interactive, expandable layout. Clicking any finding row smoothly expands a detailed section showing:
  - Full vulnerability description.
  - Formatted remediation instructions block (e.g., Apache/Nginx configuration snippets).
  - Clickable external reference links (CVEs, OWASP guides).
  - Pre-formatted technical raw JSON metadata for deep inspection.
- **Native WHOIS Integration**:
  - Automatically queries registry servers on port 43 to retrieve Registrar and Expiry Date details for `.com`, `.it`, and `.eu` domains.
  - Features intelligent lookahead parser logic to handle diverse blocks and registry response formats.
  - Displays WHOIS details on the Dashboard, Scan History, and Detail views.
- **Advanced Scanning Capabilities**:
  - **Core WordPress Vulnerability Lookup**: Integrates with OSV.dev to fetch and link active CVE matches for the exposed WordPress Core CMS version.
  - **DNS Security Posture Audit**: Employs public DNS-over-HTTPS (DoH) JSON queries to check for domain SPF (`v=spf1`) and DMARC (`v=DMARC1`) configuration records and policies.
  - **Security Policy File Scanner**: Passively audits target paths (`/security.txt` and `/.well-known/security.txt`) for compliance with RFC 9116.
  - **EOL Software Detection**: Inspects `Server` and `X-Powered-By` response headers to flag End-Of-Life versions of PHP (< 8.2) and Apache (< 2.4).
  - **Enhanced User Enumeration**: Optimizes author discovery by parsing `<dc:creator>` fields within the main RSS `/feed/` to detect username exposure.
- **CSV Data Export**: Added a one-click **Export CSV** feature to the Scan History page that packages all collected metadata (domains, WordPress versions, plugins, and finding counts) into a structured spreadsheet.

---

## Security & Ethical Guidelines

SentinelWP is developed following safe security assessment practices:
- No default credentials; mandatory initial administrator account creation.
- No destructive exploitation techniques or target database modifications.
- Automatic redaction of credentials and secrets detected in exposed configuration files (`content_redacted: True`).
- Alignment with OWASP web application security testing guidelines.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
