"""004_product_maturity_easm

Revision ID: 004_product_maturity_easm
Revises: 003_enterprise_remediation_governance
Create Date: 2026-09-30 14:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from core.db.base import SafeJSON

# revision identifiers, used by Alembic.
revision: str = '004_product_maturity_easm'
down_revision: Union[str, None] = '003_enterprise_remediation_governance'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update assets: add business_unit_id
    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('business_unit_id', sa.String(length=64), nullable=True))
        batch_op.create_index('idx_assets_bu', ['business_unit_id'], unique=False)

    # 2. Update findings: add finding_confidence, policy_version_id
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('finding_confidence', sa.String(length=32), nullable=False, server_default='HIGH'))
        batch_op.add_column(sa.Column('policy_version_id', sa.String(length=64), nullable=True))
        batch_op.create_index('idx_findings_confidence', ['finding_confidence'], unique=False)
        batch_op.create_index('idx_findings_policy_version', ['policy_version_id'], unique=False)

    # 3. Update scan_jobs: add policy_version_id
    with op.batch_alter_table('scan_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('policy_version_id', sa.String(length=64), nullable=True))

    # 4. Update daily_risk_snapshots: add business_unit_id, verified_asset_count, internet_exposed_count, unassigned_findings, accepted_risk_count
    with op.batch_alter_table('daily_risk_snapshots', schema=None) as batch_op:
        batch_op.add_column(sa.Column('business_unit_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('verified_asset_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('internet_exposed_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('unassigned_findings', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('accepted_risk_count', sa.Integer(), nullable=False, server_default='0'))

    # 5. Create discovery_scopes table
    op.create_table(
        'discovery_scopes',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('root_domain', sa.String(length=255), nullable=False, index=True),
        sa.Column('allowed_suffixes', SafeJSON(), nullable=False),
        sa.Column('excluded_patterns', SafeJSON(), nullable=False),
        sa.Column('max_depth', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_by', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('approved_by', sa.String(length=128), nullable=True),
        sa.Column('valid_from', sa.String(length=64), nullable=False),
        sa.Column('valid_until', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_discovery_scopes_tenant_domain', 'discovery_scopes', ['tenant_id', 'root_domain'])

    # 6. Create discovered_assets table
    op.create_table(
        'discovered_assets',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('discovery_scope_id', sa.String(length=64), sa.ForeignKey('discovery_scopes.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('hostname', sa.String(length=255), nullable=False, index=True),
        sa.Column('canonical_url', sa.String(length=512), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False, server_default='MANUAL_IMPORT'),
        sa.Column('confidence', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('first_seen_at', sa.String(length=64), nullable=False),
        sa.Column('last_seen_at', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='NEW'),
        sa.Column('evidence_id', sa.String(length=64), nullable=True),
        sa.Column('promoted_asset_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
        sa.UniqueConstraint('tenant_id', 'hostname', name='uq_discovered_assets_tenant_host')
    )
    op.create_index('idx_discovered_assets_tenant_status', 'discovered_assets', ['tenant_id', 'status'])

    # 7. Create asset_verifications table
    op.create_table(
        'asset_verifications',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('method', sa.String(length=32), nullable=False, server_default='DNS_TXT'),
        sa.Column('challenge', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('verified_at', sa.String(length=64), nullable=True),
        sa.Column('expires_at', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False)
    )
    op.create_index('idx_asset_verifications_tenant_asset', 'asset_verifications', ['tenant_id', 'asset_id'])

    # 8. Create evidences table
    op.create_table(
        'evidences',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('scan_id', sa.String(length=64), nullable=True, index=True),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('type', sa.String(length=64), nullable=False, server_default='http_response'),
        sa.Column('source', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('content_hash', sa.String(length=64), nullable=False, index=True),
        sa.Column('storage_reference', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('mime_type', sa.String(length=64), nullable=False, server_default='application/json'),
        sa.Column('size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('retention_class', sa.String(length=32), nullable=False, server_default='STANDARD'),
        sa.Column('classification', sa.String(length=32), nullable=False, server_default='internal'),
        sa.Column('sanitized', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('redacted', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('provenance', SafeJSON(), nullable=False),
        sa.Column('quality', sa.String(length=32), nullable=False, server_default='STRONG'),
        sa.Column('payload', sa.Text(), nullable=True)
    )
    op.create_index('idx_evidences_tenant_hash', 'evidences', ['tenant_id', 'content_hash'])
    op.create_index('idx_evidences_tenant_finding', 'evidences', ['tenant_id', 'finding_id'])

    # 9. Create policies table
    op.create_table(
        'policies',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False, server_default='SCAN_PROFILE'),
        sa.Column('active_version_id', sa.String(length=64), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
        sa.UniqueConstraint('tenant_id', 'name', name='uq_policies_tenant_name')
    )

    # 10. Create policy_versions table
    op.create_table(
        'policy_versions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('policy_id', sa.String(length=64), sa.ForeignKey('policies.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='DRAFT'),
        sa.Column('definition_json', SafeJSON(), nullable=False),
        sa.Column('checksum', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('approved_by', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('activated_at', sa.String(length=64), nullable=True),
        sa.UniqueConstraint('policy_id', 'version', name='uq_policy_versions_policy_version')
    )

    # 11. Create business_units table
    op.create_table(
        'business_units',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('code', sa.String(length=64), nullable=False),
        sa.Column('parent_id', sa.String(length=64), nullable=True),
        sa.Column('owner_user_id', sa.String(length=64), nullable=True),
        sa.Column('criticality', sa.String(length=32), nullable=False, server_default='medium'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
        sa.UniqueConstraint('tenant_id', 'code', name='uq_business_units_tenant_code')
    )

    # 12. Create business_services table
    op.create_table(
        'business_services',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('business_unit_id', sa.String(length=64), sa.ForeignKey('business_units.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('criticality', sa.String(length=32), nullable=False, server_default='medium'),
        sa.Column('owner_user_id', sa.String(length=64), nullable=True),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True)
    )

    # 13. Create asset_business_services table
    op.create_table(
        'asset_business_services',
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('service_id', sa.String(length=64), sa.ForeignKey('business_services.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('assigned_at', sa.String(length=64), nullable=False)
    )

    # 14. Create data_quality_issues table
    op.create_table(
        'data_quality_issues',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('entity_type', sa.String(length=64), nullable=False, server_default='asset'),
        sa.Column('entity_id', sa.String(length=64), nullable=False, index=True),
        sa.Column('issue_type', sa.String(length=128), nullable=False, index=True),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='medium'),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('detected_at', sa.String(length=64), nullable=False, index=True),
        sa.Column('resolved_at', sa.String(length=64), nullable=True)
    )
    op.create_index('idx_dq_tenant_type_entity', 'data_quality_issues', ['tenant_id', 'entity_type', 'entity_id'])

    # 15. Create integration_outbox table
    op.create_table(
        'integration_outbox',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('event_type', sa.String(length=128), nullable=False, index=True),
        sa.Column('event_key', sa.String(length=128), unique=True, nullable=False, index=True),
        sa.Column('destination', sa.String(length=64), nullable=False, server_default='siem'),
        sa.Column('payload_hash', sa.String(length=64), nullable=False),
        sa.Column('payload_json', SafeJSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('attempt', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('next_retry_at', sa.String(length=64), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False, index=True)
    )
    op.create_index('idx_outbox_tenant_status', 'integration_outbox', ['tenant_id', 'status'])

    # 16. Create technology_observations table
    op.create_table(
        'technology_observations',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('technology_type', sa.String(length=64), nullable=False, server_default='CMS'),
        sa.Column('name', sa.String(length=255), nullable=False, index=True),
        sa.Column('version', sa.String(length=64), nullable=True),
        sa.Column('source', sa.String(length=128), nullable=False, server_default='meta_generator'),
        sa.Column('confidence', sa.String(length=32), nullable=False, server_default='HIGH'),
        sa.Column('eol_status', sa.String(length=32), nullable=True),
        sa.Column('first_seen', sa.String(length=64), nullable=False),
        sa.Column('last_seen', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True)
    )
    op.create_index('idx_tech_obs_asset_type', 'technology_observations', ['asset_id', 'technology_type'])

    # 17. Create saved_views table
    op.create_table(
        'saved_views',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('user_id', sa.String(length=64), nullable=False, server_default='', index=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=False, server_default='portfolio'),
        sa.Column('filters_json', SafeJSON(), nullable=False),
        sa.Column('is_shared', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.String(length=64), nullable=False)
    )
    op.create_index('idx_saved_views_tenant_user', 'saved_views', ['tenant_id', 'user_id'])


def downgrade() -> None:
    op.drop_table('saved_views')
    op.drop_table('technology_observations')
    op.drop_table('integration_outbox')
    op.drop_table('data_quality_issues')
    op.drop_table('asset_business_services')
    op.drop_table('business_services')
    op.drop_table('business_units')
    op.drop_table('policy_versions')
    op.drop_table('policies')
    op.drop_table('evidences')
    op.drop_table('asset_verifications')
    op.drop_table('discovered_assets')
    op.drop_table('discovery_scopes')

    with op.batch_alter_table('daily_risk_snapshots', schema=None) as batch_op:
        batch_op.drop_column('accepted_risk_count')
        batch_op.drop_column('unassigned_findings')
        batch_op.drop_column('internet_exposed_count')
        batch_op.drop_column('verified_asset_count')
        batch_op.drop_column('business_unit_id')

    with op.batch_alter_table('scan_jobs', schema=None) as batch_op:
        batch_op.drop_column('policy_version_id')

    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index('idx_findings_policy_version')
        batch_op.drop_index('idx_findings_confidence')
        batch_op.drop_column('policy_version_id')
        batch_op.drop_column('finding_confidence')

    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.drop_index('idx_assets_bu')
        batch_op.drop_column('business_unit_id')
