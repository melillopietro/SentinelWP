"""006_sprint3_asset_monitoring

Sprint 3: Asset Inventory & Continuous Monitoring fields.

Adds Sprint 3 columns to `assets` and `scheduled_scans` tables that
support per-asset monitoring state, security posture summary, and
scheduled scan failure tracking / pause support.

Revision ID: 006_sprint3_asset_monitoring
Revises: 005_phase7_pilot_readiness_indices
Create Date: 2025-07-15 00:00:00.000000
"""
from typing import Sequence, Union
from alembic import op

revision: str = '006_sprint3_asset_monitoring'
down_revision: Union[str, None] = '005_phase7_pilot_readiness_indices'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add Sprint 3 asset monitoring and posture fields.

    All DDL uses ADD COLUMN semantics; columns that may already exist
    on databases initialised from a fresh init_db() are guarded by the
    safe_add_column pattern used in init_db (ALTER TABLE is idempotent here
    because init_db already ran safe_add_column which catches the error).
    For Alembic-managed PostgreSQL databases these are clean additions.
    """
    # --- assets: monitoring state ---
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS wp_install_path TEXT DEFAULT '/'")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS monitoring_enabled INTEGER DEFAULT 0")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS monitoring_paused_at TEXT")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_scan_id TEXT")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_scan_at TEXT")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_scan_status TEXT")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_successful_scan_at TEXT")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS consecutive_scan_failures INTEGER DEFAULT 0")

    # --- assets: security posture summary ---
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS wp_version TEXT")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS detected_themes TEXT DEFAULT ''")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS detected_plugins TEXT DEFAULT ''")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS risk_score REAL")

    # --- scheduled_scans: failure tracking and pause ---
    op.execute("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS max_retries INTEGER DEFAULT 3")
    op.execute("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER DEFAULT 0")
    op.execute("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS last_failure_at TEXT")
    op.execute("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS last_success_at TEXT")
    op.execute("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS paused_until TEXT")

    # Indices for monitoring queries
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_assets_monitoring "
        "ON assets(tenant_id, monitoring_enabled)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_assets_last_scan "
        "ON assets(tenant_id, last_scan_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_scans_paused "
        "ON scheduled_scans(tenant_id, paused_until)"
    )


def downgrade() -> None:
    """Remove Sprint 3 monitoring columns.

    SQLite does not support DROP COLUMN before 3.35 (2021). For SQLite
    databases we accept that downgrade is a no-op (schema columns are
    additive and have safe defaults). PostgreSQL supports DROP COLUMN.
    """
    # PostgreSQL-compatible drops; SQLite will silently skip via IF EXISTS
    for col in [
        "wp_install_path", "monitoring_enabled", "monitoring_paused_at",
        "last_scan_id", "last_scan_at", "last_scan_status", "last_successful_scan_at",
        "consecutive_scan_failures", "wp_version", "detected_themes", "detected_plugins",
        "risk_score",
    ]:
        op.execute(f"ALTER TABLE assets DROP COLUMN IF EXISTS {col}")

    for col in ["max_retries", "consecutive_failures", "last_failure_at", "last_success_at", "paused_until"]:
        op.execute(f"ALTER TABLE scheduled_scans DROP COLUMN IF EXISTS {col}")

    op.execute("DROP INDEX IF EXISTS idx_assets_monitoring")
    op.execute("DROP INDEX IF EXISTS idx_assets_last_scan")
    op.execute("DROP INDEX IF EXISTS idx_scheduled_scans_paused")
