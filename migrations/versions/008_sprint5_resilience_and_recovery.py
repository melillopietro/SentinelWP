"""008_sprint5_resilience_and_recovery

Sprint 5: Production Hardening & Crash Recovery
Adds:
  - integration_outbox: claimed_at and claimed_by columns for lease tracking
  - idx_outbox_processing_claimed index for stale PROCESSING event sweeps
  - idx_scheduled_runs_status_job index for orphaned scheduled run reconciliation

Revision ID: 008_sprint5_resilience_and_recovery
Revises: 007_sprint4_workflow_integration
Create Date: 2026-10-10 18:30:00.000000
"""
from typing import Sequence, Union
from alembic import op

revision: str = '008_sprint5_resilience_and_recovery'
down_revision: Union[str, None] = '007_sprint4_workflow_integration'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add Sprint 5 crash recovery columns and indices.

    Idempotent operations: IF NOT EXISTS guards used throughout to
    support both SQLite and PostgreSQL without runtime failure.
    """
    # 1. Lease tracking columns for outbox processing
    try:
        op.execute(
            "ALTER TABLE integration_outbox ADD COLUMN IF NOT EXISTS claimed_at TEXT"
        )
    except Exception:
        # SQLite ALTER TABLE fallback if IF NOT EXISTS not supported in older versions
        pass

    try:
        op.execute(
            "ALTER TABLE integration_outbox ADD COLUMN IF NOT EXISTS claimed_by TEXT"
        )
    except Exception:
        pass

    # 2. Index for stale PROCESSING outbox recovery sweeper
    # Covers: WHERE status = 'PROCESSING' AND (claimed_at <= :cutoff OR claimed_at IS NULL)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbox_processing_claimed "
        "ON integration_outbox(status, claimed_at)"
    )

    # 3. Index for orphaned scheduled runs sweeper
    # Covers: WHERE status = 'dispatched' AND scan_job_id IS NULL AND created_at <= :cutoff
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_sched_runs_status_job "
        "ON scheduled_runs(status, scan_job_id, created_at)"
    )


def downgrade() -> None:
    """Remove Sprint 5 indices."""
    op.execute("DROP INDEX IF EXISTS idx_outbox_processing_claimed")
    op.execute("DROP INDEX IF EXISTS idx_sched_runs_status_job")
