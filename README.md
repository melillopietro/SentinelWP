# SentinelWP — WordPress Security Sentinel (v4.1.0 Enterprise)

Enterprise-grade, non-destructive WordPress security assessment, posture management, and distributed vulnerability orchestration platform.

SentinelWP is an advanced enterprise security auditing platform designed to evaluate the security posture of WordPress websites and web applications at scale. Powered by a stateless web tier, Celery distributed workers, Redis message broker, and PostgreSQL / SQLite dual-compatibility, SentinelWP provides deep attack surface reconnaissance, configuration audit, and vulnerability intelligence without performing destructive actions.

---

## Key Features

- **Modern Vulnerabilities & DevOps Exposure Auditing**: Active and passive detection for modern cloud/containerized WordPress threats:
  - **Git Repository Exposure**: Checks `/.git/HEAD` and `/.git/config` with commit hash validation to prevent full source code and commit history dumping.
  - **Environment Configuration Leaks**: Audits exposed dotenv files (`/.env`, `/.env.local`, `/.env.production`) across modern Docker, Bedrock, and Roots deployments with automatic secret redaction.
  - **Database Management & Diagnostic Tool Leaks**: Probes for exposed standalone database managers (`adminer.php`) and diagnostic scripts (`phpinfo.php`).
  - **Live Secrets in Sample Files**: Detects if `wp-config-sample.php` was accidentally populated with live production database credentials.
- **Anti-False-Positive Engine (*Soft-404 Payload Inspection*)**: Intelligent payload inspection preventing false positives caused by web servers or custom WordPress themes returning `HTTP 200 OK` on custom 404 error pages.
- **Privilege Escalation & WAF Bypass Detection**:
  - **Open User Registration Audit**: Probes `wp-login.php?action=register` to detect if `users_can_register` is enabled, eliminating the primary attack vector for subscriber-to-admin privilege escalation CVEs.
  - **REST API WAF/Rewrite Bypass**: Tests `/?rest_route=/wp/v2/users` to verify if static path-based WAF or Nginx blocks on `/wp-json/` can be bypassed.
- **Modern Security Isolation Headers**: Audits modern browser isolation controls including `Cross-Origin-Opener-Policy` (COOP), `Cross-Origin-Resource-Policy` (CORP), and `Cross-Origin-Embedder-Policy` (COEP) alongside traditional HSTS and CSP.
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
- **Multi-Tenant Workspaces & Tenant Partitioning**: Complete tenant isolation architecture (`Tenant` domain model). Every scan, finding, scheduled audit, asset, and authorization is strictly scoped to the active workspace. Seamless backward-compatible migration automatically seeds legacy records under a protected default workspace (`default-tenant`).
- **Enterprise Asset Inventory & Asset 360**: Centralized enterprise target management (`/assets`) with automated URL canonicalization (HTTPS scheme normalization, default port removal, path preservation), asset tagging, environment tracking (Production, Staging, Development), and a dedicated Asset 360 profile (`/asset/<id>`) detailing historical scans and active security findings.
- **Scan Authorization Guardrails**: Pre-flight authorization enforcement (`ScanAuthorization` model) ensuring scans against targets in `safe-active` mode are strictly gated by valid, unexpired owner authorization. Attempts to execute safe-active scans without authorization fail closed (HTTP 403) and generate security audit alerts.
- **Centralized Tenant-Aware Object Authorization**: Enforces strict authorization policies across all routes and API endpoints (`core/authorization.py`). Unauthorized cross-tenant resource requests return `HTTP 404 Not Found` rather than `403 Forbidden` to prevent object enumeration and information disclosure (OWASP API1:2023 / BOLA prevention).
- **Immutable Security Audit Logging**: Tamper-evident, append-only security audit trail (`/audit`) capturing security-critical actions (login, asset management, scan authorization grant/revocation, scan execution, role modifications). Automatically redacts passwords, tokens, API keys, and session cookies from metadata before persistence.
- **Role-Based Access Control (RBAC)**: Multi-user management (Admin, Analyst, Viewer) with secure sessions.
- **Stateless Web Cluster Architecture**: The web tier validates, authorizes, creates durable `ScanJob` records, and enqueues tasks to Celery via Redis. Scanners NEVER execute within the HTTP request cycle.
- **PostgreSQL 16+ & Dual SQLite Support**: SQLAlchemy 2.x persistence layer with connection pooling, declarative models, and Alembic migrations. Full dual-compatibility with SQLite WAL mode for development.
- **Distributed Celery Worker Queues**: Segregated task queues (`scan`, `intel`, `maintenance`) for independent horizontal scaling. Threat intelligence synchronization runs isolated from scan workloads.
- **Centralized Celery Beat High-Availability Scheduler**: Atomic schedule claims backed by `ScheduledRun` unique constraints mathematically guarantee **0 duplicate scheduled scans** across distributed deployments.
- **Pre-Flight Worker Authorization Guardrail**: Celery workers re-validate asset scan authorization immediately prior to target analysis, failing closed (HTTP 403 / denied) if permissions expired while queued.
- **Automatic Stale Worker Recovery & Retries**: Active heartbeats flag worker crashes or timeouts, automatically retrying transient errors and recovering hung jobs.
- **Enterprise Observability**: Distributed trace correlation (`X-Request-ID`), Kubernetes liveness/readiness probes (`/health`, `/ready`), and Prometheus telemetry (`/metrics`).

---

## Enterprise Production Deployment (Docker Compose on Ubuntu Server LTS)

For enterprise-grade, high-availability deployments on Ubuntu Server LTS (22.04 / 24.04), SentinelWP provides a fully isolated, production-hardened Docker Compose topology:

- **Isolated Stack**: Nginx Gateway (TLS 1.3 termination, HSTS, rate-limiting), Gunicorn WSGI (`sentinelwp-web`), segregated Celery workers (`worker-scan`, `worker-intel`), autonomous scheduler (`beat`), PostgreSQL 16 (`db`), and Redis 7 (`redis`).
- **Container Hardening**: Python 3.12-slim, unprivileged non-root execution (`appuser` UID 1000), `read_only` filesystems, zero host exposure for PostgreSQL and Redis ports.
- **Automated Migrations**: Ephemeral `migrate` container with PostgreSQL advisory locking (`85504753`).

```bash
# 1. Clone repository
git clone -b feat/sentinelwp-sprint11-enterprise-packaging https://github.com/example/sentinelwp.git
cd sentinelwp

# 2. Configure environment & generate strong secrets
cp .env.production.example .env.production
chmod 600 .env.production
bash scripts/validate_prod_env.sh .env.production

# 3. Provision TLS certificate (or generate staging cert)
bash scripts/generate_self_signed_cert.sh

# 4. Build and start datastores
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d db redis

# 5. Run database migrations and start application stack
docker compose -f docker-compose.prod.yml run --rm migrate
docker compose -f docker-compose.prod.yml up -d

# 6. Verify deployment
bash scripts/verify_deployment.sh --host 127.0.0.1
```

For detailed guides, see:
- [`docs/DEPLOYMENT_UBUNTU.md`](file:///Users/piero/Downloads/SentinelWP/docs/DEPLOYMENT_UBUNTU.md): Complete Ubuntu Server LTS deployment runbook.
- [`docs/PRODUCTION_CONFIGURATION.md`](file:///Users/piero/Downloads/SentinelWP/docs/PRODUCTION_CONFIGURATION.md): Environment variables and security settings.
- [`docs/UPGRADE_ROLLBACK.md`](file:///Users/piero/Downloads/SentinelWP/docs/UPGRADE_ROLLBACK.md): Zero-downtime upgrades and disaster recovery rollback.
- [`docs/BACKUP_RECOVERY.md`](file:///Users/piero/Downloads/SentinelWP/docs/BACKUP_RECOVERY.md): PostgreSQL backup automation and restore drills.
- [`docs/OPERATIONS_RUNBOOK.md`](file:///Users/piero/Downloads/SentinelWP/docs/OPERATIONS_RUNBOOK.md): Day-2 operations, worker scaling, and incident response.
- [`docs/SECURITY_HARDENING.md`](file:///Users/piero/Downloads/SentinelWP/docs/SECURITY_HARDENING.md): Defense-in-depth and vulnerability mitigations.

---

## Local Development & Standalone Installation Guide (Cross-Platform)

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

#### Arch Linux / Manjaro

```bash
# Update repositories and install prerequisites
sudo pacman -Syu
sudo pacman -S --needed git python python-pip base-devel

# Clone repository
git clone https://github.com/melillopietro/SentinelWP.git
cd SentinelWP

# Create virtual environment and install dependencies
python -m venv .venv-sentinelwp
source .venv-sentinelwp/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Launch SentinelWP
python app.py
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

## Recent Updates & Changelog (v4.1.0)

See [CHANGELOG.md](CHANGELOG.md) for the authoritative release notes.

### v4.1.0 — Enterprise Production Release (Sprint 11)
- **Containerized production stack** with Nginx TLS gateway, Gunicorn, Celery workers, Redis, and PostgreSQL 16.
- **Security remediation:** session RBAC, atomic scan job claims, SSRF preflight + worker enforcement, strict DNS in production.
- **Operations:** Alembic migrations through `009_sprint11_schema_parity`, backup/restore scripts, production env validation.
- **Multi-tenant login** with optional organization slug for duplicate usernames.

### v3.7.0 — Enterprise Phase 2: Workspaces, Asset Inventory & Scan Authorization
- **Multi-Tenant Partitioning & Workspace Context**:
  - Introduced `Tenant` domain model and multi-tenant partitioning across all application data.
  - Automatic zero-downtime migration backfills legacy records into `default-tenant`.
  - Global Jinja2 workspace context injection (`current_tenant`, `current_tenant_id`) with header workspace badges.
- **Enterprise Asset Inventory & Asset 360**:
  - Full CRUD inventory management (`/assets`, `/asset/new`, `/asset/<id>`, `/asset/<id>/edit`, `/asset/<id>/delete`).
  - Automated URL canonicalization utility (`core/canonical.py`) guaranteeing consistent scheme, port, and path handling.
  - Dedicated Asset 360 profile view aggregating scan history, active risk statistics, and authorization status.
- **Scan Authorization Guardrails**:
  - Added `ScanAuthorization` domain model for verified site ownership and scanning permissions.
  - Pre-flight authorization validation on active scans (`/scan/new`, `/scan/batch`, `/api/scan`) failing closed (`403 Forbidden`) when targets lack active authorizations.
  - Granular authorization lifecycle management with creation and instant revocation.
- **Centralized Object-Level Authorization (BOLA/IDOR Prevention)**:
  - Centralized policy engine (`core/authorization.py`) enforcing role hierarchy and tenant boundaries.
  - Cross-tenant access attempts return strict `404 Not Found` (rather than 403) to eliminate object enumeration.
- **Immutable Security Audit Logging**:
  - Append-only `audit_events` ledger recording all authentication, authorization, scan, and administrative actions.
  - Automatic pre-persistence sanitization redacting credentials, tokens, cookies, and secret keys.
  - Dedicated Administrator-only Audit Log dashboard (`/audit`).
- **PostgreSQL & Alembic Enterprise Migration Path**:
  - Complete blueprint (`docs/POSTGRESQL_MIGRATION_PLAN.md`) detailing schema migration, PostgreSQL Row-Level Security (RLS) policies, and dual-run cutover procedures.

### v3.6.0 — Modern Vulnerability Engine, User Panel & Enhanced Narrative Reports
- **Modern Vulnerability & DevOps Exposure Engine**:
  - Detection of exposed Git repositories (`/.git/HEAD`) with SHA commit hash verification.
  - Detection of environment configuration files (`/.env`, `/.env.local`, `/.env.production`) across Docker and containerized setups.
  - Detection of standalone database management tools (`adminer.php`) and diagnostic scripts (`phpinfo.php`).
  - Detection of live database credentials accidentally stored in `wp-config-sample.php`.
- **Anti-False-Positive Engine (*Soft-404 Payload Inspection*)**: Multi-layer inspection ensuring that HTTP 200 responses returning custom HTML 404 pages are not falsely reported as sensitive file leaks.
- **Privilege Escalation & Route Bypass Audits**:
  - Open user registration auditing (`users_can_register`) on `wp-login.php?action=register`.
  - WAF/rewrite bypass testing on REST API user enumeration using `/?rest_route=/wp/v2/users`.
- **Modern Security Isolation Headers**: Automated auditing for `Cross-Origin-Opener-Policy` (COOP) and `Cross-Origin-Resource-Policy` (CORP).
- **Python 3.12+ Engine Modernization**: Full deprecation cleanup migrating legacy `datetime.utcnow()` to timezone-aware `datetime.now(timezone.utc)`.
- **Synchronized CVE Pipeline**: Full parity between asynchronous UI scans and synchronous CLI/batch scans with live OSV.dev and local intelligence correlation.
- **User Panel & Preferences (`/settings`)**: Unified settings page for theme selection, password changes, admin user management, and database backup/restore.
- **Narrative Executive Summaries & SLA Action Plans**: Speaking narrative reports in PDF, HTML, and Excel with 3-tier prioritized SLA remediation plans (0-48h, 7-14d, Continuous).
- **GitHub Update Checker**: Automatic update verification comparing local git commit against official GitHub repository releases/commits.
- **Admin Database Backup & Restore**: Full database export and lossless Excel import capability for cross-instance migration.
- **Dark & Light Themes**: Modern Dark/Light theme customizer with instant zero-flash switching.

### v3.5.0 — Non-WP Domain Identification & 30-min Auto-Sync
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
