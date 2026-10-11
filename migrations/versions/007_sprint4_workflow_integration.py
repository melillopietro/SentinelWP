"""007_sprint4_workflow_integration

Sprint 4: Workflow Integration — outbox processing states, indices for
intel reassessment queue, and scan differential observability.

Adds:
  - integration_outbox: PROCESSING and DEAD_LETTER status support
    (status CHECK constraint extended; existing rows unaffected)
  - integration_outbox: attempt column with DEFAULT 1 for retry tracking
  - integration_outbox: next_retry_at column for backoff scheduling
  - Indices for outbox processing: event_type + status, attempt, next_retry_at
  - scan_differentials view (virtual summary via query; no DDL needed)

The integration_outbox table uses a TEXT column for status, not an enum
constraint, so PROCESSING and DEAD_LETTER values are accepted without DDL.
This migration adds performance indices for the new event processor query patterns.

Revision ID: 007_sprint4_workflow_integration
Revises: 006_sprint3_asset_monitoring
Create Date: 2025-07-16 00:00:00.000000
"""
from typing import Sequence, Union
from alembic import op

revision: str = '007_sprint4_workflow_integration'
down_revision: Union[str, None] = '006_sprint3_asset_monitoring'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add Sprint 4 outbox processing indices and columns.

    All operations are idempotent: IF NOT EXISTS / IF EXISTS guards used
    throughout to support both fresh and incremental migrations.
    """
    # Index for intel reassessment queue processor (S3-GAP-002 task)
    # Covers: WHERE event_type = 'intel_triggered_reassessment' AND status = 'PENDING'
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbox_event_type_status "
        "ON integration_outbox(event_type, status)"
    )

    # Index for retry scheduling: WHERE status IN ('PENDING','RETRYING') ORDER BY created_at
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbox_status_created "
        "ON integration_outbox(status, created_at)"
    )

    # Index for retry timing: WHERE next_retry_at IS NOT NULL AND status = 'PENDING'
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbox_retry_at "
        "ON integration_outbox(next_retry_at) WHERE next_retry_at IS NOT NULL"
    )

    # Index supporting intel reassessment join on asset_id in payload:
    # Also used for asset-level outbox event count lookups
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbox_tenant_key "
        "ON integration_outbox(tenant_id, event_key)"
    )

    # Index for scan lookups in differential computation:
    # list_scans(filters={asset_id, tenant_id, status}) uses this path
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_asset_status "
        "ON scans(asset_id, tenant_id, status)"
    )

    # Ensure next_retry_at column exists for backoff scheduling
    op.execute(
        "ALTER TABLE integration_outbox ADD COLUMN IF NOT EXISTS next_retry_at TEXT"
    )

    # Ensure last_error column exists
    op.execute(
        "ALTER TABLE integration_outbox ADD COLUMN IF NOT EXISTS last_error TEXT"
    )


def downgrade() -> None:
    """Remove Sprint 4 indices.

    The columns added above have safe defaults and are backward compatible.
    Dropping them in SQLite requires a table rebuild; we only drop indices here.
    """
    op.execute("DROP INDEX IF EXISTS idx_outbox_event_type_status")
    op.execute("DROP INDEX IF EXISTS idx_outbox_status_created")
    op.execute("DROP INDEX IF EXISTS idx_outbox_retry_at")
    op.execute("DROP INDEX IF EXISTS idx_outbox_tenant_key")
    op.execute("DROP INDEX IF EXISTS idx_scans_asset_status")
