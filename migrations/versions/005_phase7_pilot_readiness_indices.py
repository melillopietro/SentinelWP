"""005_phase7_pilot_readiness_indices

Phase 7 Pilot-Readiness: adds three performance indices to support asset filtering
and scan queue depth metrics introduced in the Sprint 0 remediation.

Revision ID: 005_phase7_pilot_readiness_indices
Revises: 004_product_maturity_easm
Create Date: 2025-07-14 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '005_phase7_pilot_readiness_indices'
down_revision: Union[str, None] = '004_product_maturity_easm'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Creates three indices introduced in Phase 7.

    These indices are created with IF NOT EXISTS semantics via raw DDL so the migration
    is safe to apply against databases that were initialized from a fresh init_db()
    (which already includes the indices) as well as against live upgraded databases.

    Rollback: drop_index() calls in downgrade() remove the indices. Data is unaffected.
    """
    # Index on assets for fast criticality-based filtering (portfolio dashboards, asset lists)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_assets_tenant_crit "
        "ON assets(tenant_id, criticality)"
    )

    # Index on assets for fast internet-exposure filtering (attack surface reports)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_assets_tenant_exposure "
        "ON assets(tenant_id, internet_exposure)"
    )

    # Index on scan_jobs to support queue depth metrics (status + queued_at)
    # queued_at is a NOT NULL column populated at job creation time.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_jobs_queued_time "
        "ON scan_jobs(status, queued_at)"
    )


def downgrade() -> None:
    """Removes the three Phase 7 indices. No data is affected."""
    op.execute("DROP INDEX IF EXISTS idx_assets_tenant_crit")
    op.execute("DROP INDEX IF EXISTS idx_assets_tenant_exposure")
    op.execute("DROP INDEX IF EXISTS idx_scan_jobs_queued_time")
