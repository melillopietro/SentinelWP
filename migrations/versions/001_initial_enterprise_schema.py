"""001_initial_enterprise_schema

Revision ID: 001_initial_enterprise_schema
Revises: 
Create Date: 2026-09-29 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from core.db.base import SafeJSON

# revision identifiers, used by Alembic.
revision: str = '001_initial_enterprise_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Tenants
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=128), nullable=False, unique=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_tenants_slug', 'tenants', ['slug'])

    # 2. Users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('username', sa.String(length=128), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('role', sa.String(length=32), nullable=False, server_default='viewer'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.UniqueConstraint('tenant_id', 'username', name='uq_users_tenant_username'),
    )
    op.create_index('idx_users_tenant', 'users', ['tenant_id'])
    op.create_index('idx_users_username', 'users', ['username'])

    # 3. Assets
    op.create_table(
        'assets',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('canonical_url', sa.String(length=512), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('business_owner', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('technical_owner', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('environment', sa.String(length=64), nullable=False, server_default='production'),
        sa.Column('internet_exposure', sa.String(length=64), nullable=False, server_default='external'),
        sa.Column('criticality', sa.String(length=64), nullable=False, server_default='medium'),
        sa.Column('data_classification', sa.String(length=64), nullable=False, server_default='confidential'),
        sa.Column('authorization_status', sa.String(length=64), nullable=False, server_default='unauthorized'),
        sa.Column('authorization_review_date', sa.String(length=64), nullable=True),
        sa.Column('tags', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
        sa.UniqueConstraint('tenant_id', 'canonical_url', name='uq_assets_tenant_canonical_url'),
    )
    op.create_index('idx_assets_tenant', 'assets', ['tenant_id'])
    op.create_index('idx_assets_canonical', 'assets', ['canonical_url'])
    op.create_index('idx_assets_hostname', 'assets', ['hostname'])
    op.create_index('idx_assets_tenant_status', 'assets', ['tenant_id', 'status'])
    op.create_index('idx_assets_tenant_created', 'assets', ['tenant_id', 'created_at'])

    # 4. Scan Authorizations
    op.create_table(
        'scan_authorizations',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('allowed_profiles', sa.String(length=255), nullable=False, server_default='safe_active,passive'),
        sa.Column('request_budget', sa.Integer(), nullable=False, server_default='1000'),
        sa.Column('valid_from', sa.String(length=64), nullable=False),
        sa.Column('valid_until', sa.String(length=64), nullable=False),
        sa.Column('approved_by', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_scan_auth_tenant', 'scan_authorizations', ['tenant_id'])
    op.create_index('idx_scan_auth_asset', 'scan_authorizations', ['asset_id'])
    op.create_index('idx_scan_auth_asset_status', 'scan_authorizations', ['asset_id', 'status'])

    # 5. Scans
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('target_url', sa.String(length=512), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('scan_mode', sa.String(length=64), nullable=False, server_default='passive'),
        sa.Column('started_at', sa.String(length=64), nullable=False),
        sa.Column('completed_at', sa.String(length=64), nullable=True),
        sa.Column('score', sa.Float(), nullable=True),
        sa.Column('grade', sa.String(length=8), nullable=True),
        sa.Column('notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('tags', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('initiated_by', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('wp_version', sa.String(length=64), nullable=True),
        sa.Column('is_wordpress', sa.Boolean(), nullable=True),
        sa.Column('whois_info', sa.Text(), nullable=True),
    )
    op.create_index('idx_scans_tenant', 'scans', ['tenant_id'])
    op.create_index('idx_scans_asset', 'scans', ['asset_id'])
    op.create_index('idx_scans_status', 'scans', ['status'])
    op.create_index('idx_scans_tenant_status', 'scans', ['tenant_id', 'status'])
    op.create_index('idx_scans_tenant_started', 'scans', ['tenant_id', 'started_at'])
    op.create_index('idx_scans_asset_started', 'scans', ['asset_id', 'started_at'])

    # 6. Findings
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('scan_id', sa.String(length=64), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('category', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('title', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='info'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('remediation', sa.Text(), nullable=False, server_default=''),
        sa.Column('reference', sa.Text(), nullable=False, server_default=''),
        sa.Column('raw_data', SafeJSON, nullable=False),
        sa.Column('created_at', sa.String(length=64), nullable=False),
    )
    op.create_index('idx_findings_tenant', 'findings', ['tenant_id'])
    op.create_index('idx_findings_scan', 'findings', ['scan_id'])
    op.create_index('idx_findings_asset', 'findings', ['asset_id'])
    op.create_index('idx_findings_severity', 'findings', ['severity'])
    op.create_index('idx_findings_scan_severity', 'findings', ['scan_id', 'severity'])
    op.create_index('idx_findings_tenant_severity', 'findings', ['tenant_id', 'severity'])

    # 7. Scheduled Scans
    op.create_table(
        'scheduled_scans',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('target_url', sa.String(length=512), nullable=False),
        sa.Column('scan_mode', sa.String(length=64), nullable=False, server_default='passive'),
        sa.Column('interval_hours', sa.Integer(), nullable=False, server_default='24'),
        sa.Column('last_run_at', sa.String(length=64), nullable=True),
        sa.Column('next_run_at', sa.String(length=64), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_by', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.CheckConstraint('interval_hours > 0', name='chk_scheduled_scan_interval_positive'),
    )
    op.create_index('idx_sched_tenant', 'scheduled_scans', ['tenant_id'])
    op.create_index('idx_sched_enabled_next', 'scheduled_scans', ['enabled', 'next_run_at'])

    # 8. Scheduled Runs (Idempotency / 0 Duplicates)
    op.create_table(
        'scheduled_runs',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('schedule_id', sa.String(length=64), sa.ForeignKey('scheduled_scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('planned_at', sa.String(length=64), nullable=False),
        sa.Column('started_at', sa.String(length=64), nullable=True),
        sa.Column('completed_at', sa.String(length=64), nullable=True),
        sa.Column('scan_job_id', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.UniqueConstraint('schedule_id', 'planned_at', name='uq_scheduled_run_id_planned'),
    )
    op.create_index('idx_sched_runs_schedule', 'scheduled_runs', ['schedule_id'])
    op.create_index('idx_sched_runs_planned', 'scheduled_runs', ['planned_at'])
    op.create_index('idx_sched_runs_tenant_status', 'scheduled_runs', ['tenant_id', 'status'])

    # 9. Scan Jobs (Durable Celery Execution)
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', sa.String(length=64), sa.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('scan_id', sa.String(length=64), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('task_id', sa.String(length=128), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='queued'),
        sa.Column('requested_by', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('profile', sa.String(length=64), nullable=False, server_default='passive'),
        sa.Column('queued_at', sa.String(length=64), nullable=False),
        sa.Column('started_at', sa.String(length=64), nullable=True),
        sa.Column('completed_at', sa.String(length=64), nullable=True),
        sa.Column('failed_at', sa.String(length=64), nullable=True),
        sa.Column('cancelled_at', sa.String(length=64), nullable=True),
        sa.Column('progress_percent', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_step', sa.String(length=255), nullable=False, server_default='Initialized'),
        sa.Column('attempt', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('max_attempts', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('error_code', sa.String(length=64), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('worker_id', sa.String(length=128), nullable=True),
        sa.Column('heartbeat_at', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_scan_jobs_tenant', 'scan_jobs', ['tenant_id'])
    op.create_index('idx_scan_jobs_scan', 'scan_jobs', ['scan_id'])
    op.create_index('idx_scan_jobs_status', 'scan_jobs', ['status'])
    op.create_index('idx_scan_jobs_heartbeat', 'scan_jobs', ['heartbeat_at'])
    op.create_index('idx_scan_jobs_tenant_status', 'scan_jobs', ['tenant_id', 'status'])

    # 10. Audit Events (Append-only)
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('actor_user_id', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('actor_username', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('action', sa.String(length=128), nullable=False),
        sa.Column('resource_type', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('resource_id', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('result', sa.String(length=32), nullable=False, server_default='success'),
        sa.Column('metadata', SafeJSON, nullable=False),
        sa.Column('created_at', sa.String(length=64), nullable=False),
    )
    op.create_index('idx_audit_tenant_created', 'audit_events', ['tenant_id', 'created_at'])
    op.create_index('idx_audit_action', 'audit_events', ['action'])

    # 11. Intelligence Sync Status (SLA tracking)
    op.create_table(
        'intelligence_sync_status',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('source', sa.String(length=64), nullable=False, unique=True),
        sa.Column('last_success', sa.String(length=64), nullable=True),
        sa.Column('last_attempt', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('records_processed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_code', sa.String(length=64), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('freshness_age_seconds', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_intel_sync_source', 'intelligence_sync_status', ['source'])

    # 12. Vulnerability Intelligence Pipeline Tables
    op.create_table(
        'vulnerability_records',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('wordfence_id', sa.String(length=128), unique=True, nullable=True),
        sa.Column('cve', sa.String(length=64), nullable=True),
        sa.Column('title', sa.String(length=512), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=128), nullable=True),
        sa.Column('cvss_rating', sa.String(length=32), nullable=True),
        sa.Column('cwe_id', sa.Integer(), nullable=True),
        sa.Column('cwe_name', sa.String(length=255), nullable=True),
        sa.Column('published', sa.String(length=64), nullable=True),
        sa.Column('updated', sa.String(length=64), nullable=True),
        sa.Column('source', sa.String(length=64), nullable=False, server_default='wordfence'),
        sa.Column('informational', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('references_json', sa.Text(), nullable=False, server_default='[]'),
    )
    op.create_index('idx_vuln_cve', 'vulnerability_records', ['cve'])
    op.create_index('idx_vuln_wfid', 'vulnerability_records', ['wordfence_id'])
    op.create_index('idx_vuln_cvss', 'vulnerability_records', ['cvss_score'])
    op.create_index('idx_vuln_published', 'vulnerability_records', ['published'])

    op.create_table(
        'vulnerability_software',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('vulnerability_id', sa.String(length=64), sa.ForeignKey('vulnerability_records.id', ondelete='CASCADE'), nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False, server_default='plugin'),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('slug', sa.String(length=255), nullable=True),
        sa.Column('patched', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('patched_versions_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('remediation', sa.Text(), nullable=False, server_default=''),
    )
    op.create_index('idx_soft_slug', 'vulnerability_software', ['slug'])
    op.create_index('idx_soft_vuln', 'vulnerability_software', ['vulnerability_id'])

    op.create_table(
        'vulnerability_affected_ranges',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('software_id', sa.String(length=64), sa.ForeignKey('vulnerability_software.id', ondelete='CASCADE'), nullable=False),
        sa.Column('from_version', sa.String(length=64), nullable=True),
        sa.Column('from_inclusive', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('to_version', sa.String(length=64), nullable=True),
        sa.Column('to_inclusive', sa.Integer(), nullable=False, server_default='1'),
    )
    op.create_index('idx_range_software', 'vulnerability_affected_ranges', ['software_id'])

    op.create_table(
        'vulnerability_references',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('vulnerability_id', sa.String(length=64), sa.ForeignKey('vulnerability_records.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url', sa.Text(), nullable=True),
    )
    op.create_index('idx_ref_vuln', 'vulnerability_references', ['vulnerability_id'])

    op.create_table(
        'plugin_metadata',
        sa.Column('slug', sa.String(length=255), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('active_installs', sa.Integer(), nullable=True),
        sa.Column('current_version', sa.String(length=64), nullable=True),
        sa.Column('last_updated', sa.String(length=64), nullable=True),
        sa.Column('tested_wp_version', sa.String(length=64), nullable=True),
        sa.Column('fetched_at', sa.String(length=64), nullable=True),
    )
    op.create_index('idx_plugin_installs', 'plugin_metadata', ['active_installs'])

    op.create_table(
        'cisa_kev_records',
        sa.Column('cve', sa.String(length=64), primary_key=True),
        sa.Column('date_added', sa.String(length=64), nullable=True),
        sa.Column('vendor', sa.String(length=255), nullable=True),
        sa.Column('product', sa.String(length=255), nullable=True),
        sa.Column('vulnerability_name', sa.Text(), nullable=True),
        sa.Column('required_action', sa.Text(), nullable=True),
        sa.Column('due_date', sa.String(length=64), nullable=True),
        sa.Column('ransomware_use', sa.String(length=64), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
    )
    op.create_index('idx_kev_date', 'cisa_kev_records', ['date_added'])

    op.create_table(
        'vulnerability_sync_state',
        sa.Column('source', sa.String(length=64), primary_key=True),
        sa.Column('last_success_at', sa.String(length=64), nullable=True),
        sa.Column('last_attempt_at', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='never'),
        sa.Column('inserted', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('updated', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('unchanged', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('rejected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_summary', sa.Text(), nullable=False, server_default=''),
    )

    op.create_table(
        'vuln_intel_settings',
        sa.Column('key', sa.String(length=128), primary_key=True),
        sa.Column('value', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    # Drop tables in reverse foreign-key order
    op.drop_table('vuln_intel_settings')
    op.drop_table('vulnerability_sync_state')
    op.drop_table('cisa_kev_records')
    op.drop_table('plugin_metadata')
    op.drop_table('vulnerability_references')
    op.drop_table('vulnerability_affected_ranges')
    op.drop_table('vulnerability_software')
    op.drop_table('vulnerability_records')
    op.drop_table('intelligence_sync_status')
    op.drop_table('audit_events')
    op.drop_table('scan_jobs')
    op.drop_table('scheduled_runs')
    op.drop_table('scheduled_scans')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('scan_authorizations')
    op.drop_table('assets')
    op.drop_table('users')
    op.drop_table('tenants')
