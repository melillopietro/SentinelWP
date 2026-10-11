# Sprint 3 — Asset Management

## Overview

Sprint 3 extends the `Asset` model and repository with all fields required for
continuous security monitoring, security posture tracking, and stable identifiers.

---

## New Asset Fields (Sprint 3)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `wp_install_path` | TEXT | `/` | WordPress install path (e.g. `/blog`, `/wp`) |
| `monitoring_enabled` | BOOL | `False` | Whether the asset is under continuous monitoring |
| `monitoring_paused_at` | TEXT (ISO) | `None` | Non-null = monitoring paused since this timestamp |
| `last_scan_id` | TEXT | `None` | ID of the most recent scan (any status) |
| `last_scan_at` | TEXT (ISO) | `None` | Timestamp of the most recent scan |
| `last_scan_status` | TEXT | `None` | Status of the most recent scan (`completed`, `failed`, `running`) |
| `last_successful_scan_at` | TEXT (ISO) | `None` | Timestamp of the most recent *completed* scan |
| `consecutive_scan_failures` | INT | `0` | Number of consecutive failed scans (reset on success) |
| `wp_version` | TEXT | `None` | Last detected WordPress version |
| `detected_themes` | TEXT | `""` | JSON list of detected theme slugs |
| `detected_plugins` | TEXT | `""` | JSON list of detected plugin slugs |
| `risk_score` | REAL | `None` | Last computed risk score (0–100) |

## Stable Asset Identity

Every asset is identified by a UUID (`id`) generated at creation time.
The `canonical_url` + `tenant_id` combination is unique (enforced via index).
The `ensure_asset_for_target()` function is idempotent — it returns the existing
asset when a URL is already known, preventing duplicate records.

**Acceptance criterion 1** (Managed assets have stable identities) is satisfied
by: UUIDs generated at creation, never regenerated; `canonical_url` deduplicated
per tenant; `_row_to_asset()` helper handles both old and new column sets safely.

## Posture Update Flow

After each successful scan, `scan_tasks.run_scan_task()` calls `update_asset()` with:
- `last_scan_id`, `last_scan_at` = now, `last_scan_status` = `"completed"`
- `last_successful_scan_at` = now
- `consecutive_scan_failures` = 0
- `wp_version` (if WordPress detected)
- `risk_score` (from `completed_scan.score`)
- `tags` (updated with `wordpress`, `wp-{version}`)

After a scan failure:
- `last_scan_id`, `last_scan_at` = now, `last_scan_status` = `"failed"`
- `consecutive_scan_failures` += 1

## Migration

Migration `006_sprint3_asset_monitoring.py` adds all Sprint 3 columns to the
`assets` and `scheduled_scans` tables using `ADD COLUMN IF NOT EXISTS` DDL.
For SQLite (development), `init_db()` uses `safe_add_column()` which is
equivalent and idempotent.

Three indices are added:
- `idx_assets_monitoring` — for tenant-scoped monitoring queries
- `idx_assets_last_scan` — for finding assets needing re-scan
- `idx_scheduled_scans_paused` — for skip-paused filtering in dispatcher

## Authorization Enforcement

Asset-level scan authorization is enforced in `scan_tasks.run_scan_task()` via
`verify_scan_authorization()` before any network activity. This was already in
place from Sprint 2; Sprint 3 does not weaken it.

**Acceptance criterion 7** (Asset-level authorization is enforced) is satisfied
by the unchanged pre-flight guardrail in `run_scan_task()`.
