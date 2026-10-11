"""002_add_wordpress_detection_metadata

Revision ID: 002_add_wordpress_detection_metadata
Revises: 002_remediation_sla_integrations
Create Date: 2026-09-29 20:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_add_wordpress_detection_metadata'
down_revision: Union[str, None] = '002_remediation_sla_integrations'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add canonical WordPress detection metadata columns to scans table
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('wordpress_detected', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('wordpress_version', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('wordpress_version_source', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('wordpress_version_confidence', sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('wordpress_version_confidence')
        batch_op.drop_column('wordpress_version_source')
        batch_op.drop_column('wordpress_version')
        batch_op.drop_column('wordpress_detected')
