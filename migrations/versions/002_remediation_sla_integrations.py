"""002_remediation_sla_integrations

Revision ID: 002_remediation_sla_integrations
Revises: 001_initial_enterprise_schema
Create Date: 2026-09-29 14:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from core.db.base import SafeJSON

# revision identifiers, used by Alembic.
revision: str = '002_remediation_sla_integrations'
down_revision: Union[str, None] = '001_initial_enterprise_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add Phase 4 columns to findings
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('fingerprint', sa.String(length=64), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'))
        batch_op.add_column(sa.Column('first_seen_at', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('last_seen_at', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('first_scan_id', sa.String(length=64), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('last_scan_id', sa.String(length=64), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('observation_count', sa.Integer(), nullable=False, server_default='1'))
        batch_op.add_column(sa.Column('assigned_to_user_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('assigned_team', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('assigned_at', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('finding_tags', SafeJSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('version', sa.Integer(), nullable=False, server_default='1'))
        batch_op.add_column(sa.Column('priority_score', sa.Float(), nullable=False, server_default='0.0'))
        batch_op.add_column(sa.Column('priority_band', sa.String(length=16), nullable=False, server_default='P3'))
        batch_op.add_column(sa.Column('cvss_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('epss_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('epss_percentile', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('epss_last_updated', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('kev', sa.Boolean(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('kev_date_added', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('kev_due_date', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('known_ransomware_campaign_use', sa.Boolean(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('ransomware_relevance', sa.String(length=32), nullable=False, server_default='NONE'))
        batch_op.add_column(sa.Column('cve_id', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('sla_policy_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('sla_due_at', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('sla_status', sa.String(length=32), nullable=False, server_default='NOT_APPLICABLE'))
        batch_op.add_column(sa.Column('sla_paused_at', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('sla_pause_reason', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('verified_at', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('verified_by_scan_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('false_positive_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('false_positive_by', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('false_positive_at', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('false_positive_valid_until', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('updated_at', sa.String(length=64), nullable=True))
        batch_op.create_index('idx_findings_fingerprint', ['tenant_id', 'fingerprint'])
        batch_op.create_index('idx_findings_status', ['tenant_id', 'status'])
        batch_op.create_index('idx_findings_priority', ['tenant_id', 'priority_score'])
        batch_op.create_index('idx_findings_sla', ['tenant_id', 'sla_status', 'sla_due_at'])

    # 2. finding_observations
    op.create_table(
        'finding_observations',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('scan_id', sa.String(length=64), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('observed_at', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('raw_reference', sa.Text(), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
    )
    op.create_index('idx_observations_finding', 'finding_observations', ['finding_id'])
    op.create_index('idx_observations_scan', 'finding_observations', ['scan_id'])
    op.create_index('idx_observations_time', 'finding_observations', ['observed_at'])

    # 3. finding_history
    op.create_table(
        'finding_history',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('actor_user_id', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('old_status', sa.String(length=32), nullable=True),
        sa.Column('new_status', sa.String(length=32), nullable=True),
        sa.Column('comment', sa.Text(), nullable=False, server_default=''),
        sa.Column('metadata', SafeJSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
    )
    op.create_index('idx_history_finding', 'finding_history', ['finding_id'])

    # 4. finding_comments
    op.create_table(
        'finding_comments',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('author_user_id', sa.String(length=64), nullable=False),
        sa.Column('author_username', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_comments_finding', 'finding_comments', ['finding_id'])

    # 5. remediations
    op.create_table(
        'remediations',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('owner_user_id', sa.String(length=64), nullable=True),
        sa.Column('owner_external', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('priority', sa.String(length=16), nullable=False, server_default='P3'),
        sa.Column('due_date', sa.String(length=64), nullable=True),
        sa.Column('started_at', sa.String(length=64), nullable=True),
        sa.Column('completed_at', sa.String(length=64), nullable=True),
        sa.Column('verification_required', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('verification_status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_remediations_finding', 'remediations', ['finding_id'])
    op.create_index('idx_remediations_status', 'remediations', ['tenant_id', 'status'])

    # 6. remediation_actions
    op.create_table(
        'remediation_actions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('remediation_id', sa.String(length=64), sa.ForeignKey('remediations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action_type', sa.String(length=64), nullable=False, server_default='patch'),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('owner', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('due_date', sa.String(length=64), nullable=True),
        sa.Column('completed_at', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )

    # 7. sla_policies
    op.create_table(
        'sla_policies',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=True),
        sa.Column('criticality', sa.String(length=32), nullable=True),
        sa.Column('kev', sa.Boolean(), nullable=True),
        sa.Column('internet_exposed', sa.Boolean(), nullable=True),
        sa.Column('due_days', sa.Integer(), nullable=False, server_default='7'),
        sa.Column('warning_days', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )

    # 8. risk_acceptances
    op.create_table(
        'risk_acceptances',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('requested_by', sa.String(length=64), nullable=False),
        sa.Column('approved_by', sa.String(length=64), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('business_justification', sa.Text(), nullable=False, server_default=''),
        sa.Column('compensating_controls', sa.Text(), nullable=False, server_default=''),
        sa.Column('valid_from', sa.String(length=64), nullable=False),
        sa.Column('valid_until', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_risk_accept_finding', 'risk_acceptances', ['finding_id'])
    op.create_index('idx_risk_accept_expiry', 'risk_acceptances', ['status', 'valid_until'])

    # 9. integrations
    op.create_table(
        'integrations',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('config_reference', SafeJSON(), nullable=False, server_default='{}'),
        sa.Column('secret_reference', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_integrations_tenant', 'integrations', ['tenant_id', 'type'])

    # 10. ticket_references
    op.create_table(
        'ticket_references',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('integration_id', sa.String(length=64), sa.ForeignKey('integrations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('external_ticket_id', sa.String(length=128), nullable=False),
        sa.Column('external_url', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='open'),
        sa.Column('last_sync_at', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.UniqueConstraint('integration_id', 'external_ticket_id', name='uq_ticket_ref'),
    )
    op.create_index('idx_ticket_refs_finding', 'ticket_references', ['finding_id'])

    # 11. webhook_deliveries
    op.create_table(
        'webhook_deliveries',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('integration_id', sa.String(length=64), sa.ForeignKey('integrations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event', sa.String(length=64), nullable=False),
        sa.Column('payload_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('attempt', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('next_retry_at', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
    )

    # 12. api_keys
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False, unique=True),
        sa.Column('scopes', SafeJSON(), nullable=False, server_default='[]'),
        sa.Column('last_used_at', sa.String(length=64), nullable=True),
        sa.Column('expires_at', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('revoked_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_api_keys_hash', 'api_keys', ['key_hash'])

    # 13. daily_risk_snapshots
    op.create_table(
        'daily_risk_snapshots',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('date', sa.String(length=32), nullable=False),
        sa.Column('open_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('p1_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('p2_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('kev_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sla_breaches', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_score_avg', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('mttr_seconds', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.UniqueConstraint('tenant_id', 'date', name='uq_tenant_date_snapshot'),
    )

    # 14. control_mappings
    op.create_table(
        'control_mappings',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('finding_type', sa.String(length=128), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=64), nullable=False),
        sa.Column('control_title', sa.String(length=255), nullable=False, server_default=''),
        sa.UniqueConstraint('finding_type', 'framework', 'control_id', name='uq_control_mapping'),
    )


def downgrade() -> None:
    op.drop_table('control_mappings')
    op.drop_table('daily_risk_snapshots')
    op.drop_table('api_keys')
    op.drop_table('webhook_deliveries')
    op.drop_table('ticket_references')
    op.drop_table('integrations')
    op.drop_table('risk_acceptances')
    op.drop_table('sla_policies')
    op.drop_table('remediation_actions')
    op.drop_table('remediations')
    op.drop_table('finding_comments')
    op.drop_table('finding_history')
    op.drop_table('finding_observations')
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index('idx_findings_sla')
        batch_op.drop_index('idx_findings_priority')
        batch_op.drop_index('idx_findings_status')
        batch_op.drop_index('idx_findings_fingerprint')
        batch_op.drop_column('updated_at')
        batch_op.drop_column('false_positive_valid_until')
        batch_op.drop_column('false_positive_at')
        batch_op.drop_column('false_positive_by')
        batch_op.drop_column('false_positive_reason')
        batch_op.drop_column('verified_by_scan_id')
        batch_op.drop_column('verified_at')
        batch_op.drop_column('sla_pause_reason')
        batch_op.drop_column('sla_paused_at')
        batch_op.drop_column('sla_status')
        batch_op.drop_column('sla_due_at')
        batch_op.drop_column('sla_policy_id')
        batch_op.drop_column('cve_id')
        batch_op.drop_column('ransomware_relevance')
        batch_op.drop_column('known_ransomware_campaign_use')
        batch_op.drop_column('kev_due_date')
        batch_op.drop_column('kev_date_added')
        batch_op.drop_column('kev')
        batch_op.drop_column('epss_last_updated')
        batch_op.drop_column('epss_percentile')
        batch_op.drop_column('epss_score')
        batch_op.drop_column('cvss_score')
        batch_op.drop_column('priority_band')
        batch_op.drop_column('priority_score')
        batch_op.drop_column('version')
        batch_op.drop_column('finding_tags')
        batch_op.drop_column('assigned_at')
        batch_op.drop_column('assigned_team')
        batch_op.drop_column('assigned_to_user_id')
        batch_op.drop_column('observation_count')
        batch_op.drop_column('last_scan_id')
        batch_op.drop_column('first_scan_id')
        batch_op.drop_column('last_seen_at')
        batch_op.drop_column('first_seen_at')
        batch_op.drop_column('status')
        batch_op.drop_column('fingerprint')
