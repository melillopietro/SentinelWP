# SentinelWP — Sprint 6 Navigation Mapping Matrix
## Consolidation Architecture & Legacy Route Compatibility

**Sprint:** Sprint 6 — Enterprise UI/UX Consolidation  
**Target Branch:** `feat/sentinelwp-sprint6-unified-ui`  
**Base Commit:** `f8b4f99`  

---

### 1. Overview of Navigation Transformation

Prior to Sprint 6, SentinelWP's user experience suffered from navigational fragmentation:
- **14 flat sidebar links** created visual clutter and cognitive overload.
- **5 separate dashboards** (`/`, `/portfolio`, `/data-quality`, `/remediation`, `/sla`) caused overlapping metrics and confusion over where to find actionable data.
- **Scanning features were scattered** across `/`, `/batch-scan`, `/schedules`, and `/scans`.
- **Governance features were split** across `/risk-acceptances`, `/audit`, and `/settings`.

Sprint 6 unified the entire application into **6 cohesive workspaces** with tabbed secondary navigation and modal action workflows, while maintaining 100% backward compatibility via HTTP 302 redirects for legacy URLs.

---

### 2. Comprehensive Navigation Mapping Matrix

| Legacy Sidebar Link / Route | Legacy Endpoint | New Workspace | New Tab / Action Modal | HTTP Status / Handling | Preserved Parameters & Features |
|---|---|---|---|---|---|
| **Dashboard** (`/`) | `dashboard` | **Overview** (`/`) | Tab: `posture` (default) | HTTP 200 OK | Overall security posture, risk score trends, risk distribution, KPI cards. |
| **Portfolio Dashboard** (`/portfolio`) | `portfolio_dashboard` | **Overview** (`/`) | Tab: `portfolio` | HTTP 302 Redirect to `/?tab=portfolio` | Business Unit posture table, unit asset counts, average unit risk scores. |
| **Reports** (fragmented) | N/A | **Overview** (`/`) | Tab: `reports` | In-place tab navigation | Executive summary reports, trend exports, posture snapshots. |
| **Assets** (`/assets`) | `assets` | **Assets** (`/assets`) | Tab: `inventory` (default) | HTTP 200 OK | Filterable asset inventory, search, environment filters, criticality. |
| **Add Asset** (separate page/form) | `add_asset` | **Assets** (`/assets`) | Modal: `#add-asset-modal` | Inline Modal Trigger | Domain URL, environment, criticality, immediate authorization trigger. |
| **Data Quality** (`/data-quality`) | `data_quality_dashboard` | **Assets** (`/assets`) | Tab: `quality` | HTTP 302 Redirect to `/assets?tab=quality` | Data confidence metrics, missing telemetry issues, scan failure logs. |
| **Asset Details** (`/asset/<id>`) | `asset_detail` | **Asset 360** (`/asset/<id>`) | 6 Contextual Tabs | HTTP 200 OK | `overview`, `vulns`, `scans`, `monitoring`, `tech`, `reports`. |
| **Vulnerabilities / Findings** (`/findings`) | `findings_list` | **Vulnerabilities** (`/findings`) | Tab: `all` (default) | HTTP 200 OK | Full vulnerability repository, severity filters, search, status filters. |
| **Critical Findings / KEV** (filtered) | `/findings?severity=critical` | **Vulnerabilities** (`/findings`) | Tab: `critical` | In-place tab navigation | P1 findings, known exploited vulnerabilities (KEV), urgent exposures. |
| **Remediation Dashboard** (`/remediation`) | `remediation_dashboard` | **Vulnerabilities** (`/findings`) | Tab: `remediation` | HTTP 302 Redirect to `/findings?tab=remediation` | Remediation backlog, task status, assignee tracking, SLA timers. |
| **SLA Governance** (`/sla`) | `sla_dashboard` | **Vulnerabilities** (`/findings`) | Tab: `sla` | HTTP 302 Redirect to `/findings?tab=sla` | SLA compliance rates, breached findings, MTTR calculations. |
| **Risk Exceptions** (`/risk-acceptances`) | `risk_acceptance_list` | **Vulnerabilities** (`/findings`) | Tab: `exceptions` | HTTP 302 Redirect to `/findings?tab=exceptions` | Two-person rule risk acceptance records, expiry dates, justification. |
| **Scan History** (`/scans`) | `scan_history` | **Operations** (`/scans`) | Tab: `history` (default) | HTTP 200 OK | Scan execution table, status badges, finding counts, duration. |
| **Scan Schedules** (`/schedules`) | `schedules` | **Operations** (`/scans`) | Tab: `schedules` | HTTP 302 Redirect to `/scans?tab=schedules` | Cron/periodic scan schedules, pause/resume controls, schedule deletion. |
| **Launch Scan / Batch Scan** (`/batch-scan`) | `batch_scan` | **Operations** (`/scans`) | Modal: `#scan-launcher-modal` | Inline Modal Trigger | Single scan, Batch scan (multi-target with SSRF checks), Scheduled scan. |
| **Threat Intelligence** (`/vuln-intel`) | `vuln_intel_dashboard` | **Threat Intel** (`/vuln-intel`) | Tab: `feeds` (default) | HTTP 200 OK | Feed telemetry, sync status, last updated, manual sync trigger. |
| **CVE Database** (embedded) | N/A | **Threat Intel** (`/vuln-intel`) | Tab: `database` | In-place tab navigation | Searchable CVE repository, CVSS scores, affected software versions. |
| **Reassessment Queue / Outbox** | N/A | **Threat Intel** (`/vuln-intel`) | Tab: `outbox` | In-place tab navigation | Celery outbox table, event claim tokens, delivery states, retry counts. |
| **Settings** (`/settings`) | `settings` | **Administration** (`/settings`) | Tab: `general` (default) | HTTP 200 OK | Tenant branding, general settings, profile preferences. |
| **User Management** (admin) | `/users` | **Administration** (`/settings`) | Tab: `users` | In-place tab (Admin only) | User directory, role assignment (`admin`/`analyst`/`viewer`), invites. |
| **API Keys** (`/api-keys`) | `api_keys_view` | **Administration** (`/settings`) | Tab: `api_keys` | In-place tab navigation | Scoped Bearer token generation, expiration, permissions review. |
| **Audit Log** (`/audit`) | `audit_log_view` | **Administration** (`/settings`) | Tab: `audit` (Admin only) | In-place tab (also `/audit` HTTP 200) | Immutable security audit trail, actor username, IP, action parameters. |

---

### 3. API Route Preservation Guarantee

All REST API endpoints (`/api/v1/...`) were intentionally excluded from UI redirection to protect external programmatic callers, CI/CD pipelines, and SDK automations:

- `/api/v1/assets` (GET, POST) — Unchanged
- `/api/v1/assets/<id>` (GET, PUT, DELETE) — Unchanged
- `/api/v1/assets/<id>/differential` (GET) — Unchanged
- `/api/v1/assets/<id>/lifecycle` (GET) — Unchanged
- `/api/v1/findings` (GET) — Unchanged
- `/api/v1/scans` (GET, POST) — Unchanged
- `/api/v1/schedules` (GET, POST) — Unchanged
- `/api/v1/schedules/<id>/pause` (POST) — Unchanged
- `/api/v1/schedules/<id>/resume` (POST) — Unchanged
- `/api/v1/intel/reassess/outbox/recover` (POST) — Unchanged

Zero breaking API changes were introduced.
