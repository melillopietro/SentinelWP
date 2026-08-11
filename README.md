# SentinelWP — WordPress Security Sentinel (v3.6.0)

Enterprise-grade, non-destructive WordPress security assessment and posture management platform.

SentinelWP is an advanced security auditing and reconnaissance tool designed to evaluate the security posture of WordPress websites and web applications. It provides detailed analysis of attack surfaces, misconfigurations, sensitive information exposure, and HTTP security header compliance without performing destructive actions.

---

## Key Features

- **Initial Setup Wizard**: Zero default credentials. A guided setup wizard (`/setup`) forces the creation of a custom primary Administrator account on first launch.
- **User Panel & Preferences (`/settings`)**: Dedicated user hub for account preferences, password changes, theme toggling, changelog access, and admin user management.
- **Dark & Light Theme Switcher**: Instant switching between Dark Mode (default) and Light Mode (White) with automatic persistence.
- **Streamlined Navigation UI**: Cleaned up navigation bar separating scanning tools from admin controls to streamline workflow.
- **Non-WordPress Target Identification**: Automatically identifies domains without WordPress installed and labels them clearly as `"Not WordPress"` in database records, dashboards, and reports.
- **Automated Threat Intel Auto-Sync**: Automatically syncs Wordfence & CISA KEV feeds on application startup and recurs every 30 minutes in the background.
- **Column-by-Column Table Filters**: Real-time column header search and dropdown filters on dashboard and scan history.
- **Admin Full Database Export**: One-click multi-sheet Excel export (`Scan History` & `All Findings Log`) available to Administrator accounts (`/admin/export-db`).
- **Strategic Executive Summary (CISO / Board Ready)**: Executive risk ratings (*CRITICAL ATTENTION REQUIRED*, *MODERATE RISK*, *STRONG POSTURE*) and a 3-tier prioritized Action Plan with SLA windows (0-48h, 7-14d, Continuous) across PDF, HTML, and Excel reports.
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
  - Full route discovery and namespace inspection via `/wp-json/` with privacy-first user endpoint auditing (no personal data stored).
  - Security flag analysis for HTTP response cookies (`Secure`, `HttpOnly`, `SameSite`).
- **Passive DNS & WHOIS Audit**: Native domain WHOIS socket parser (expiration and registrar tracking) combined with secure DNS-over-HTTPS (DoH) audits for SPF and DMARC mail protection records.
- **OASIS SARIF v2.1.0 Support**: Fully compliant SARIF exports for GitHub Actions and GitLab CI/CD pipeline integration.
- **Role-Based Access Control (RBAC)**: Multi-user management (Admin, Analyst, Viewer) with secure sessions.

---

## Installation Guide (Cross-Platform)

SentinelWP requires **Python 3.10+** and runs seamlessly across **macOS**, **Linux**, and **Windows**.

---

### 1. macOS Installation

#### Prerequisites
- macOS 12+ (Intel or Apple Silicon)
- Homebrew & Python 3.10+

```bash
# Install Python 3 & Git via Homebrew
brew install python3 git

# Clone repository
git clone https://github.com/melillopietro/SentinelWP.git
cd SentinelWP

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Launch SentinelWP
python3 app.py
```

---

### 2. Linux Installation

#### Ubuntu / Debian

```bash
# Update repositories and install prerequisites
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip git build-essential

# Clone repository
git clone https://github.com/melillopietro/SentinelWP.git
cd SentinelWP

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Launch SentinelWP
python3 app.py
```

#### RHEL / Fedora / AlmaLinux / Rocky Linux

```bash
# Install Python 3, Git, and build tools
sudo dnf install -y python3 python3-pip git gcc

# Clone repository
git clone https://github.com/melillopietro/SentinelWP.git
cd SentinelWP

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Launch SentinelWP
python3 app.py
```

---

### 3. Windows Installation

#### Prerequisites
- Windows 10 / 11 / Windows Server 2019+
- [Python 3.10+](https://www.python.org/downloads/) (Make sure to check **"Add python.exe to PATH"** during installation)
- [Git for Windows](https://git-scm.com/download/win)

#### PowerShell / Command Prompt (CMD)

```powershell
# Clone repository
git clone https://github.com/melillopietro/SentinelWP.git
cd SentinelWP

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# PowerShell:
.\.venv\Scripts\Activate.ps1
# OR Command Prompt (CMD):
# .\.venv\Scripts\activate.bat

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Launch SentinelWP
python app.py
```

---

### Accessing the Platform

1. Open your Web Browser and navigate to:
   `http://localhost:8080` (or `http://<SERVER_IP>:8080`)
2. Complete the initial setup wizard (`/setup`) to configure your primary Administrator account.

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
