# SentinelWP — WordPress Security Sentinel (v3.4.0)

Enterprise-grade, non-destructive WordPress security assessment and posture management platform.

SentinelWP is an advanced security auditing and reconnaissance tool designed to evaluate the security posture of WordPress websites and web applications. It provides detailed analysis of attack surfaces, misconfigurations, sensitive information exposure, and HTTP security header compliance without performing destructive actions.

---

## Key Features

- **Initial Setup Wizard**: Zero default credentials. A guided setup wizard (/setup) forces the creation of a custom primary Administrator account on first launch.
- **WordPress Vulnerability Intelligence Pipeline**: Background ingestion of official Wordfence v3 Threat Intel feeds, CISA KEV (Known Exploited Vulnerabilities) catalog, and WordPress.org plugin popularity data.
- **GUI API Key Management**: Dedicated interface on `/vuln-intel` for Admin users to configure and persist external Wordfence and NVD API keys directly in the database.
- **Enterprise PDF Report Engine**: Zero-overlap layout utilizing ReportLab `Paragraph` flowables inside table cells, dynamic two-pass page footers ("Page X of Y"), Executive Summary cards, and Risk Distribution matrices.
- **Interactive HTML & Multi-Sheet Excel Reports**: Rich responsive HTML reports with live severity tabs and text search, alongside formatted multi-sheet Excel workbooks (`Executive Summary` and `Findings Detail`).
- **SSRF Protection & Target Safety**: Integrated SSRF protection mechanism that automatically blocks requests to private IP subnets (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, etc.) and local hostnames.
- **Async Background Scans & Live Progress**: Non-blocking thread-pool scan execution with real-time progress meter (0–100%) and AJAX status polling.
- **3 Scan Modes**:
  - **Passive** (Default): Zero-impact analysis of the homepage and linked public assets.
  - **Safe-Active**: Non-destructive checks against known WordPress endpoints and public files.
  - **Full**: Includes audit of common default credentials (limited to a maximum of 20 attempts).
- **Multi-Signal WordPress Detection**: Fingerprinting algorithm with aggregate confidence scoring (0.0 to 1.0) based on 8 independent signals (meta generator, asset paths, REST API, cookies, RSS feeds, etc.).
- **Scheduled Recurring Audits**: Background scheduler for automated periodic security scans (every 12h, 24h, or 7 days).
- **SMTP Email & Webhook Alerting**: Automated alert dispatching via SMTP email and Webhooks (Slack, Microsoft Teams, or custom endpoints) upon detecting Critical or High severity findings.
- **REST API & Cookie Audit**:
  - Full route discovery and namespace inspection via /wp-json/ with privacy-first user endpoint auditing (no personal data stored).
  - Security flag analysis for HTTP response cookies (Secure, HttpOnly, SameSite).
- **Passive DNS & WHOIS Audit**: Native domain WHOIS socket parser (expiration and registrar tracking) combined with secure DNS-over-HTTPS (DoH) audits for SPF and DMARC mail protection records.
- **Exposure & Hardening Checks**: Identification of backup files (wp-config.php.bak), debug logs, directory listing, HTTPS redirection, and visible PHP error messages.
- **OASIS SARIF v2.1.0 Support**: Fully compliant SARIF exports for GitHub Actions and GitLab CI/CD pipeline integration.
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
- **Reporting Engine**: ReportLab (PDF), OpenPyXL (Excel), SARIF v2.1.0 JSON generator, CSV exporter
- **Security Core**: Requests, native socket WHOIS client, Google DoH DNS-over-HTTPS client, Python ipaddress validation, in-memory rate limiter

---

- **WordPress Vulnerability Intelligence Pipeline (v3.3)**: Integrated offline local database pipeline driven by Wordfence Intelligence v3, CISA Known Exploited Vulnerabilities (KEV), and WordPress.org Plugin Popularity enrichment. Features deterministic version matching (`1.9` < `1.10`), CISA KEV active exploitation badges, CVSS 3.1 scoring, formula injection-safe export, and a dedicated Threat Intelligence Dashboard.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WORDFENCE_API_KEY` | *(empty)* | Optional API key for Wordfence Intelligence v3 Production Feed |
| `NVD_API_KEY` | *(empty)* | Optional API key for NVD CVE enrichment |
| `VULN_INTEL_ENABLED` | `true` | Enable/disable vulnerability intelligence subsystem |
| `VULN_INTEL_SYNC_HOURS` | `24` | Refresh interval in hours for background feed sync |
| `VULN_INTEL_RETENTION_MONTHS` | `24` | Retain vulnerability records published within N months |
| `VULN_INTEL_STALE_AFTER_HOURS` | `48` | Display stale dataset warning if sync > N hours old |
| `POPULAR_PLUGIN_MIN_ACTIVE_INSTALLS` | `100000` | Minimum active installs threshold for popularity view |

---

## Recent Updates & Changelog (v3.3)

### v3.3.0 — WordPress Vulnerability Intelligence Pipeline
- **Wordfence Intelligence v3 Integration**: Automated background feed ingestion for WordPress Core and plugin vulnerabilities with CVSS 3.1 scoring, CWE classification, and affected version ranges.
- **CISA KEV Correlation**: Automatically flags vulnerabilities actively exploited in the wild with CISA Known Exploited Vulnerabilities badges and metadata.
- **WordPress.org Popularity Enrichment**: Syncs active install counts for plugins to prioritize high-impact vulnerabilities on widely deployed software.
- **Deterministic Version Matcher**: Custom version comparator supporting exact, open/closed intervals, unbounded ranges, and prerelease tags (`1.9` < `1.10`).
- **Threat Intelligence Dashboard & Search**: Dedicated UI dashboard (`/vuln-intel`) with critical vulnerability statistics, stale dataset alerts, manual sync triggers (Admin only), and a paginated, filterable database table (`/vuln-intel/list`).
- **Zero Network Impact During Scans**: All target scans execute version matching purely against the local SQLite database; zero external HTTP requests are performed during scan execution.
- **Enhanced Export Security**: Added formula injection protection (`=`, `+`, `-`, `@`) across CSV and Excel exports, HTML content escaping for external vulnerability descriptions, and SARIF 2.1.0 rule tags.

### v3.2.0 — Interactive Views & WHOIS Integration
- **Interactive Findings Detail View**: Expandable finding rows showing descriptions, remediations, references, and raw JSON metadata.
- **Native WHOIS Integration**: Registry server queries on port 43 for `.com`, `.it`, and `.eu` domains.
- **DNS & EOL Audits**: SPF/DMARC DoH queries, PHP/Apache EOL version detection, and RFC 9116 `/security.txt` checks.

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
