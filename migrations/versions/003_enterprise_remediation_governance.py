"""003_enterprise_remediation_governance

Revision ID: 003_enterprise_remediation_governance
Revises: 002_add_wordpress_detection_metadata
Create Date: 2026-09-29 21:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003_enterprise_remediation_governance'
down_revision: Union[str, None] = '002_add_wordpress_detection_metadata'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update finding_observations: add asset_id, scanner_id, evidence_reference, unique index
    with op.batch_alter_table('finding_observations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('asset_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('scanner_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('evidence_reference', sa.Text(), nullable=True))
        batch_op.create_index('uq_obs_finding_scan', ['finding_id', 'scan_id'], unique=True)

    # 2. Update api_keys: add key_prefix
    with op.batch_alter_table('api_keys', schema=None) as batch_op:
        batch_op.add_column(sa.Column('key_prefix', sa.String(length=16), nullable=False, server_default=''))

    # 3. Update daily_risk_snapshots: add assets, risk_accepted, avg_risk_score
    with op.batch_alter_table('daily_risk_snapshots', schema=None) as batch_op:
        batch_op.add_column(sa.Column('assets', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('risk_accepted', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('avg_risk_score', sa.Float(), nullable=False, server_default='0.0'))

    # 4. Update sla_policies: add asset_criticality, priority_band
    with op.batch_alter_table('sla_policies', schema=None) as batch_op:
        batch_op.add_column(sa.Column('asset_criticality', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('priority_band', sa.String(length=16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('sla_policies', schema=None) as batch_op:
        batch_op.drop_column('priority_band')
        batch_op.drop_column('asset_criticality')

    with op.batch_alter_table('daily_risk_snapshots', schema=None) as batch_op:
        batch_op.drop_column('avg_risk_score')
        batch_op.drop_column('risk_accepted')
        batch_op.drop_column('assets')

    with op.batch_alter_table('api_keys', schema=None) as batch_op:
        batch_op.drop_column('key_prefix')

    with op.batch_alter_table('finding_observations', schema=None) as batch_op:
        batch_op.drop_index('uq_obs_finding_scan')
        batch_op.drop_column('evidence_reference')
        batch_op.drop_column('scanner_id')
        batch_op.drop_column('asset_id')
