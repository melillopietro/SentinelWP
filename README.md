# SentinelWP — WordPress Security Sentinel

Enterprise-grade WordPress security auditing tool with a modern dark-theme web UI.

## Features

- **SSRF Protection**: Built-in IP blocklist for private subnets and local hostnames
- **3 Scan Modes**: `passive` (default), `safe-active` (non-destructive), `full` (credential testing)
- **Multi-Signal Detection**: WordPress detection with aggregate confidence scoring (0.0–1.0)
- **REST API Audit**: Full route discovery, namespace inspection, and privacy-first user enumeration
- **Cookie Security**: Secure, HttpOnly, and SameSite flag analysis
- **Passive Plugin Discovery**: Zero-request extraction of plugin slugs from HTML
- **Exposure Analysis**: wp-admin, xmlrpc, debug.log, and wp-config backup checking
- **HTTP Security & Hardening**: HTTPS redirect, PHP error detection, server version disclosure, security headers
- **TLS/SSL Validation**: Certificate expiry and deprecated protocol checks
- **Reporting**: PDF, HTML, Excel, and JSON report generation
- **Role-Based Access Control**: Admin / Analyst / Viewer

## Quick Start

```bash
cd wsa-pro-enterprise
source ../.venv/bin/activate
python3 app.py
```

Open http://localhost:8080

## Default Credentials

- **Username**: `admin`
- **Password**: `admin`

## License

Internal - Würth IT Security
