# SentinelWP — Sprint 5 UI/UX & Information Architecture Assessment
**Document ID:** SPRINT_5_UI_UX_ASSESSMENT  
**Sprint:** 5 (Production Hardening & UX Assessment)  
**Role:** Enterprise UX & Product Architect  
**Execution Date:** 2026-10-10  
**Scope:** Architectural Audit of 26 HTML Templates and 70+ Routes (Analysis Only — No UI Redesign in Sprint 5)  
**Status:** COMPLETED  

---

## 1. Executive Summary

During Sprint 0 through 4, SentinelWP grew rapidly from a single-target WordPress vulnerability scanner into an enterprise-grade Vulnerability Management & Attack Surface platform. While the underlying backend engine is exceptionally robust, the rapid feature additions resulted in **interface sprawl and cognitive overload**.

Currently, an operator navigating the platform is confronted with:
- **14 top-level sidebar items** spanning the entire viewport height.
- **5 separate, disconnected dashboards** (`Dashboard`, `Portfolio`, `Remediation`, `Data Quality`, and `Threat Intel`).
- **Scanning workflows scattered across 4 distinct pages** (`New Scan`, `Batch Scan`, `Scan History`, `Schedules`).
- **Vulnerability triage scattered across 4 distinct pages** (`Findings`, `Remediation`, `SLA Governance`, `Exceptions`).

This assessment provides a granular, evidence-based critique of all existing views to serve as the functional blueprint for Sprint 6 UI consolidation.

---

## 2. Template & View Inventory

A complete inspection of `/templates` identified 26 active Jinja2 templates:

| Template File | Primary Endpoint | Primary Function | Current Pain Point |
| :--- | :--- | :--- | :--- |
| `base.html` | — | Sidebar layout & CSS theme | 14 menu links; no visual hierarchy or collapsible sections. |
| `login.html` | `/login` | User login & OIDC redirect | Standalone; clean. |
| `setup.html` | `/setup` | First-run onboarding wizard | Functional; one-time use. |
| `dashboard.html` | `/` | Operational vulnerability dashboard | Shows high-level KPIs, but duplicates data from Portfolio & Remediation. |
| `portfolio_dashboard.html` | `/portfolio` | Business-unit & portfolio posture | Redundant KPI cards; isolated from main dashboard. |
| `remediation.html` | `/remediation` | Remediation backlog & assignments | Separate dashboard with its own charts; disconnected from findings table. |
| `sla.html` | `/sla` | SLA compliance & breach metrics | Yet another metric dashboard; should be a filter or tab within Findings. |
| `data_quality_dashboard.html`| `/data-quality` | Asset verification & confidence | Orphaned view; rarely visited by daily security analysts. |
| `vuln_intel_dashboard.html` | `/vuln-intel` | Threat intelligence feed metrics | Disconnected feed telemetry; separate from assets affected. |
| `vuln_intel_list.html` | `/vuln-intel/list` | Feed CVE inventory | Large table; duplicate search paradigms. |
| `assets.html` | `/assets` | Asset inventory list & search | Good list; lacks embedded scan action or direct status filters. |
| `asset_form.html` | `/asset/new`, `/edit` | Asset creation & editing form | Basic form; lacks bulk import UI. |
| `asset_detail.html` | `/asset/<id>` | Comprehensive asset profile | Rich details, but tab navigation is custom and in-page. |
| `new_scan.html` | `/scan/new` | Ad-hoc single asset scan | Isolated form; forces user away from asset list. |
| `batch_scan.html` | `/scan/batch` | Bulk URL scanning form | Duplicate scanning form with slightly different inputs. |
| `scan_history.html` | `/scans` | Historical scan executions | Disconnected from assets; table lacks inline log viewer. |
| `scan_detail.html` | `/scan/<id>` | Scan results, findings, raw logs | Dense layout; hard to distinguish info vs. critical findings. |
| `schedules.html` | `/schedules` | Recurring scan schedule list | Isolated from Asset Management; operator must cross-reference URLs. |
| `findings.html` | `/findings` | Master findings triage table | Powerful filters, but disconnects from SLA and Remediation tabs. |
| `finding_detail.html` | `/finding/<id>` | Finding triage, notes, tickets | Well structured, but action modals feel fragmented. |
| `risk_acceptances.html` | `/risk-acceptances` | Exception & waiver registry | Isolated page; should be an integrated view in Governance. |
| `executive_report.html` | `/reports/executive` | Executive PDF/HTML posture report | Clean executive export; hard to find (hidden in routes). |
| `settings.html` | `/settings` | System & tenant configuration | Buried in bottom footer; mixes user profile and tenant settings. |
| `users.html` | `/users` | User management & RBAC | Functional admin page. |
| `audit.html` | `/audit` | Immutable audit trail | Good compliance log; lacks date-range picker. |
| `changelog.html` | `/changelog` | Release notes & documentation | Static markdown view. |

---

## 3. Core Usability & Architectural Findings

### 3.1 The "Dashboard Fragmentation" Syndrome
Operators currently have to visit 5 separate dashboards to understand platform health:
1. `/` (Dashboard): Shows total findings, severity distribution, recent scans.
2. `/portfolio` (Portfolio): Shows business unit risk scores, asset criticality distribution.
3. `/remediation` (Remediation): Shows open vs. resolved findings, remediation velocity, team ownership.
4. `/sla` (SLA Governance): Shows SLA breaches, warning countdowns, compliance percentages.
5. `/data-quality` (Data Quality): Shows verification rate, confidence bands.

*Impact:* Users spend significant time jumping between tabs to correlate an asset with its SLA status and business unit owner.

### 3.2 The "Disjointed Scanning Workflow"
To launch and monitor scans, the user must navigate:
1. `New Scan` (`/scan/new`) to run an ad-hoc single scan.
2. `Batch Scan` (`/scan/batch`) to paste multiple URLs.
3. `Scan History` (`/scans`) to check if the scan completed.
4. `Schedules` (`/schedules`) to create an automated recurring job.
5. `Asset Inventory` (`/assets`) to view the asset's resulting profile.

*Impact:* Five distinct navigation entries for what is fundamentally a single workflow: **Scanning Operations**.

### 3.3 The "Triage & Remediation Silo"
Managing vulnerabilities is fragmented across:
- `Findings` (`/findings`): Raw finding table.
- `Remediation` (`/remediation`): Assignment tracking.
- `SLA Governance` (`/sla`): Due dates.
- `Exceptions` (`/risk-acceptances`): Approved waivers.

*Impact:* Analysts triaging a finding cannot easily view the asset's SLA policy or check pending risk acceptances without leaving the triage page.

### 3.4 Navigation Hierarchy & Sidebar Clutter
In `templates/base.html` (lines 265–322), all 14 links sit flat in the left sidebar with identical visual weight. There is no conceptual grouping (e.g. "Asset Management", "Vulnerability Operations", "System").

---

## 4. Key Persona Journeys & Friction Points

### Persona A: Security Analyst (Daily Triage)
- **Goal:** Review new findings from overnight scans, prioritize critical WordPress vulnerabilities, and assign tickets.
- **Current Friction:** Must check `/` for new alerts, navigate to `/findings` to filter, click `/finding/<id>` to review, go to `/sla` to check breach status, and go to `/remediation` to track assignee backlog.
- **Desired Experience:** A single unified **Vulnerabilities** workspace with tabs for *Triage*, *Backlog*, *SLA*, and *Exceptions*.

### Persona B: DevSecOps Engineer (Asset Onboarding & Scanning)
- **Goal:** Onboard 50 corporate WordPress sites and configure weekly scans.
- **Current Friction:** Must import assets on `/asset/new`, navigate to `/schedules` to set up cron schedules one by one, and check `/scans` to monitor execution.
- **Desired Experience:** An **Operations / Scans** hub with integrated launch modal, schedule manager, and real-time execution monitor.

### Persona C: CISO / Security Director (Executive Reporting)
- **Goal:** Review overall enterprise posture, SLA compliance rate, and download executive PDF report.
- **Current Friction:** Posture is split between `/portfolio` and `/sla`; the executive report (`/reports/executive`) does not even have a direct link in the sidebar!
- **Desired Experience:** An **Executive Overview** featuring holistic risk score, SLA compliance summary, and a prominent "Export Executive Summary" button.

---

## 5. Architectural Recommendations for Sprint 6

1. **Consolidate Navigation into 6 Core Areas:**
   - **1. Overview:** Unified dashboard combining high-level metrics, portfolio risk, and executive reporting.
   - **2. Assets:** Inventory, business units, asset detail, and data quality.
   - **3. Vulnerabilities:** Triage, remediation backlog, SLA tracking, and risk exceptions.
   - **4. Scans & Operations:** New scan launcher (single & batch), active queue, scan history, and schedules.
   - **5. Threat Intelligence:** CVE lookup, feed sync status, and threat correlation.
   - **6. Administration & Settings:** Users, tenant settings, API keys, and audit log.

2. **Adopt Contextual Modals & Slide-Overs:**
   - Replace standalone pages like `/scan/new` and `/asset/new` with responsive modal dialogues triggered directly from the Assets and Operations tables.

3. **Preserve All Backend Routes & Capabilities:**
   - Retain all existing API endpoints (`/api/v1/...`) and Flask route handlers for backward compatibility; consolidate only the template presentation layer.
