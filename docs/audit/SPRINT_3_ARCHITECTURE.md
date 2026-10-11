# Sprint 3 — Architecture Overview
**Branch:** `feat/sentinelwp-sprint3-continuous-monitoring`  
**Base commit:** `aa38b83`  
**Sprint 3 commit:** `8e2e0a5`  
**Test baseline entering sprint:** 394 passing  
**Test baseline exiting sprint:** 438 passing (+44 new, 0 regressions)

---

## High-Level Architecture

SentinelWP is a Flask 3.0+ / SQLAlchemy 2.x / Celery 5.3+ / Redis / SQLite (dev) + PostgreSQL 16 (prod) / Python 3.12+ platform.

Sprint 3 extends the platform with the following architectural components, all layered on top of the existing Sprint 2 foundation:

```
┌───────────────────────────────────────────────────────────────────────┐
│  HTTP API Layer (app.py / Flask)                                       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Dashboard API endpoint (get_monitoring_dashboard)               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│  Celery Task Layer                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐   │
│  │scan_tasks.py   │  │maintenance_    │  │vuln_intel/service.py   │   │
│  │• scan posture  │  │tasks.py        │  │• sync_all()            │   │
│  │  update on     │  │• pause/resume  │  │• _DistributedSyncLock  │   │
│  │  completion    │  │  schedules     │  │• intel_reassessment    │   │
│  │• failure       │  │• failure       │  │  (Phase 8 hook)        │   │
│  │  tracking      │  │  tracking      │  └────────────────────────┘   │
│  └────────────────┘  └────────────────┘                                │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│  Core Business Logic                                                    │
│  ┌────────────────┐  ┌───────────────┐  ┌──────────────────────────┐  │
│  │core/            │  │core/           │  │core/                     │  │
│  │differential.py  │  │intel_monitor  │  │repository.py             │  │
│  │• ScanDifferent- │  │.py            │  │• _row_to_asset()         │  │
│  │  ial engine     │  │• Intel-driven │  │• get_finding_lifecycle() │  │
│  │• Stable finger- │  │  reassessment │  │• get_monitoring_        │  │
│  │  print-based    │  │• Alert dedup  │  │  dashboard()             │  │
│  │  comparison     │  │  via outbox   │  │• Sprint 3 CRUD           │  │
│  └────────────────┘  └───────────────┘  └──────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│  Scanner Layer                                                          │
│  ┌────────────────┐  ┌───────────────────────────────────────────────┐ │
│  │wp_detector.py  │  │theme_scanner.py                                │ │
│  │• ENABLE_SUBDIR_│  │• _probe_default_themes() now per-theme         │ │
│  │  PROBE gate    │  │• One finding per confirmed theme (DETECT-003)  │ │
│  │• Passive mode  │  │• slug/version/version_confidence in raw_data   │ │
│  │  safety        │  └───────────────────────────────────────────────┘ │
│  └────────────────┘                                                     │
│  orchestrator.py: sets ENABLE_SUBDIR_PROBE=True for safe-active/full   │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│  Data Layer (SQLite / PostgreSQL)                                       │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │Migration 006: Sprint 3 asset monitoring + scheduled scan fields    │ │
│  │assets: wp_install_path, monitoring_enabled, monitoring_paused_at,  │ │
│  │        last_scan_id/at/status, last_successful_scan_at,            │ │
│  │        consecutive_scan_failures, wp_version, detected_themes,     │ │
│  │        detected_plugins, risk_score                                 │ │
│  │scheduled_scans: max_retries, consecutive_failures,                 │ │
│  │                 last_failure_at, last_success_at, paused_until      │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

## Key Architectural Decisions

### 1. Additive Schema Only
All Sprint 3 database changes use `safe_add_column()` (idempotent ALTER TABLE) in `init_db()` plus a formal Alembic migration (`006_sprint3_asset_monitoring.py`). Existing rows gain safe `DEFAULT` values. No columns were dropped or renamed.

### 2. Distributed Lock with Graceful Fallback
The `_DistributedSyncLock` in `service.py` tries Redis first (connection timeout 1s), falling back to the existing `threading.Lock` transparently. This preserves all existing test behaviour while enabling multi-worker safety in production.

### 3. Scan Mode Isolation Preserved
The `ENABLE_SUBDIR_PROBE` flag on `WordPressDetector` follows the same per-instance pattern established by `ENABLE_ACTIVE_PROBE` (DETECT-GAP-003/004). The orchestrator sets it for `safe-active` and `full` modes only — passive scans never issue subdirectory probes.

### 4. Scanner-Observed vs Workflow-Managed State
`FindingObservation` records remain scanner-owned (created by `process_scan_findings`). `FindingHistory` records represent analyst workflow transitions. `get_finding_lifecycle()` returns both collections separately, preventing accidental confusion.

### 5. No External Scan on Intel Update
`check_intel_triggered_reassessment()` uses stored `TechnologyObservation` records from the last scan. It never initiates an external network scan — it stages an outbox event for human/automated review. This respects authorization and rate limits.
