"""009_sprint11_schema_parity

Sprint 11: Enterprise Packaging & Schema Parity
Adds:
  - scans: wp_version_source and wp_version_confidence backward compatibility columns
    matching ScanModel SQLAlchemy definition.

Revision ID: 009_sprint11_schema_parity
Revises: 008_sprint5_resilience_and_recovery
Create Date: 2026-10-11 13:21:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '009_sprint11_schema_parity'
down_revision: Union[str, None] = '008_sprint5_resilience_and_recovery'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add backward compatibility columns to scans table."""
    op.execute(
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS wp_version_source VARCHAR(64)"
    )
    op.execute(
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS wp_version_confidence VARCHAR(32)"
    )


def downgrade() -> None:
    """Drop backward compatibility columns."""
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS wp_version_confidence")
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS wp_version_source")
