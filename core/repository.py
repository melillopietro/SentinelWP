"""
SQLite repository layer - full CRUD for users, scans, findings, tenants, assets, authorizations, audit events
"""
import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, List
from config import DATABASE_PATH, is_postgres_configured

logger = logging.getLogger("sentinelwp.repository")
from core.models import (
    Finding, ScanResult, ScanStatus, Severity,
    User, UserRole, UserStatus, ScheduledScan,
    Tenant, Asset, ScanAuthorization, AuditEvent,
    ScanJob, ScheduledRun, IntelSyncStatus, ScanJobStatus,
    FindingObservation, FindingHistory, FindingComment,
    Remediation, RemediationAction, SLAPolicy, RiskAcceptance,
    Integration, TicketReference, WebhookDelivery, APIKey,
    DailyRiskSnapshot, ControlMapping,
    DiscoveryScope, DiscoveredAsset, AssetVerification, Evidence,
    Policy, PolicyVersion, BusinessUnit, BusinessService, AssetBusinessService,
    DataQualityIssue, IntegrationOutbox, TechnologyObservation, SavedView
)
from core.canonical import canonicalize_url
from core.lifecycle import (
    FindingStatus, RemediationStatus, RiskAcceptanceStatus, SLAStatus,
    validate_transition, can_transition, InvalidStateTransitionError, OptimisticLockError
)
from core.fingerprint import compute_finding_fingerprint
from core.db.adapter import adapter_dispatch

_conn: Optional[sqlite3.Connection] = None
_local = threading.local()
_allow_operational_sqlite_override: bool = False


def reset_conn() -> None:
    """Close and clear the thread-local SQLite operational connection."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        _local.conn = None


def _get_conn() -> sqlite3.Connection:
    """
    Return thread-local SQLite connection for operational data.
    
    OPERATIONAL GUARD: If PostgreSQL is configured as the active operational
    persistence layer, direct access to the operational SQLite database is blocked
    to prevent accidental fallback, unauthorized split-brain writes, or silent data divergence.
    
    Explicitly authorized non-operational stores (such as the vulnerability
    intelligence cache in core.vulnerability_intelligence.repository or isolated
    test-only temporary databases) remain distinct and governed by their own handlers.
    """
    if is_postgres_configured() and not _allow_operational_sqlite_override:
        raise RuntimeError(
            "Operational SQLite access blocked: PostgreSQL is configured as the active persistence layer. "
            "Direct access to operational SQLite (data/wsa.db) is forbidden in PostgreSQL mode to prevent split-brain state."
        )

    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DATABASE_PATH, timeout=60.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=60000")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def _safe_commit(conn: sqlite3.Connection):
    try:
        conn.commit()
    except sqlite3.OperationalError as e:
        if "no transaction is active" not in str(e).lower():
            raise


_db_initialized = False


def init_db(force: bool = False):
    global _db_initialized
    if _db_initialized and not force:
        return
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT DEFAULT '',
            role TEXT DEFAULT 'viewer',
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            tenant_id TEXT DEFAULT 'default-tenant',
            UNIQUE(tenant_id, username)
        );

        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            canonical_url TEXT NOT NULL,
            hostname TEXT NOT NULL,
            display_name TEXT DEFAULT '',
            business_owner TEXT DEFAULT '',
            technical_owner TEXT DEFAULT '',
            environment TEXT DEFAULT 'production',
            internet_exposure TEXT DEFAULT 'external',
            criticality TEXT DEFAULT 'medium',
            data_classification TEXT DEFAULT 'confidential',
            authorization_status TEXT DEFAULT 'unauthorized',
            authorization_review_date TEXT,
            tags TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_authorizations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            allowed_profiles TEXT DEFAULT 'safe_active,passive',
            request_budget INTEGER DEFAULT 1000,
            valid_from TEXT NOT NULL,
            valid_until TEXT NOT NULL,
            approved_by TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            actor_user_id TEXT DEFAULT '',
            actor_username TEXT DEFAULT '',
            action TEXT NOT NULL,
            resource_type TEXT DEFAULT '',
            resource_id TEXT DEFAULT '',
            result TEXT DEFAULT 'success',
            metadata TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            scan_mode TEXT DEFAULT 'passive',
            started_at TEXT NOT NULL,
            completed_at TEXT,
            score REAL,
            grade TEXT,
            notes TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            initiated_by TEXT DEFAULT '',
            wp_version TEXT,
            wp_version_source TEXT,
            wp_version_confidence TEXT,
            is_wordpress INTEGER,
            whois_info TEXT,
            tenant_id TEXT DEFAULT 'default-tenant',
            asset_id TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            category TEXT DEFAULT '',
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity TEXT DEFAULT 'info',
            confidence REAL DEFAULT 1.0,
            remediation TEXT DEFAULT '',
            reference TEXT DEFAULT '',
            raw_data TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            tenant_id TEXT DEFAULT 'default-tenant',
            asset_id TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            scan_mode TEXT DEFAULT 'passive',
            interval_hours INTEGER DEFAULT 24,
            last_run_at TEXT,
            next_run_at TEXT,
            enabled INTEGER DEFAULT 1,
            created_by TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            tenant_id TEXT DEFAULT 'default-tenant',
            asset_id TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_jobs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT,
            scan_id TEXT NOT NULL,
            task_id TEXT,
            status TEXT DEFAULT 'queued',
            requested_by TEXT DEFAULT '',
            profile TEXT DEFAULT 'passive',
            queued_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            failed_at TEXT,
            cancelled_at TEXT,
            progress_percent INTEGER DEFAULT 0,
            current_step TEXT DEFAULT 'Initialized',
            attempt INTEGER DEFAULT 1,
            max_attempts INTEGER DEFAULT 3,
            error_code TEXT,
            error_message TEXT,
            worker_id TEXT,
            heartbeat_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scheduled_runs (
            id TEXT PRIMARY KEY,
            schedule_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            planned_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            scan_job_id TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            FOREIGN KEY (schedule_id) REFERENCES scheduled_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            UNIQUE (schedule_id, planned_at)
        );

        CREATE TABLE IF NOT EXISTS intelligence_sync_status (
            id TEXT PRIMARY KEY,
            source TEXT UNIQUE NOT NULL,
            last_success TEXT,
            last_attempt TEXT,
            status TEXT DEFAULT 'pending',
            records_processed INTEGER DEFAULT 0,
            error_code TEXT,
            error_message TEXT,
            freshness_age_seconds INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS finding_observations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            evidence_id TEXT,
            status TEXT DEFAULT 'OPEN',
            raw_reference TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS finding_history (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            actor_user_id TEXT DEFAULT '',
            action TEXT NOT NULL,
            old_status TEXT,
            new_status TEXT,
            comment TEXT DEFAULT '',
            metadata TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS finding_comments (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            author_user_id TEXT DEFAULT '',
            author_username TEXT DEFAULT '',
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS remediations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            owner_user_id TEXT,
            owner_external TEXT,
            status TEXT DEFAULT 'OPEN',
            priority TEXT DEFAULT 'P3',
            due_date TEXT,
            started_at TEXT,
            completed_at TEXT,
            verification_required INTEGER DEFAULT 1,
            verification_status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS remediation_actions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            remediation_id TEXT NOT NULL,
            action_type TEXT DEFAULT 'patch',
            description TEXT NOT NULL,
            owner TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            due_date TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (remediation_id) REFERENCES remediations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sla_policies (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT,
            criticality TEXT,
            kev INTEGER,
            internet_exposed INTEGER,
            due_days INTEGER DEFAULT 7,
            warning_days INTEGER DEFAULT 5,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS risk_acceptances (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            approved_by TEXT,
            reason TEXT NOT NULL,
            business_justification TEXT DEFAULT '',
            compensating_controls TEXT DEFAULT '',
            valid_from TEXT NOT NULL,
            valid_until TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            config_reference TEXT DEFAULT '{}',
            secret_reference TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ticket_references (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            external_ticket_id TEXT NOT NULL,
            external_url TEXT DEFAULT '',
            status TEXT DEFAULT 'open',
            last_sync_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
            FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE,
            UNIQUE (integration_id, external_ticket_id)
        );

        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            event TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            attempt INTEGER DEFAULT 1,
            last_error TEXT,
            next_retry_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            scopes TEXT DEFAULT '[]',
            last_used_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS daily_risk_snapshots (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            date TEXT NOT NULL,
            open_findings INTEGER DEFAULT 0,
            p1_count INTEGER DEFAULT 0,
            p2_count INTEGER DEFAULT 0,
            kev_count INTEGER DEFAULT 0,
            sla_breaches INTEGER DEFAULT 0,
            risk_score_avg REAL DEFAULT 0.0,
            mttr_seconds REAL DEFAULT 0.0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            UNIQUE (tenant_id, date)
        );

        CREATE TABLE IF NOT EXISTS control_mappings (
            id TEXT PRIMARY KEY,
            finding_type TEXT NOT NULL,
            framework TEXT NOT NULL,
            control_id TEXT NOT NULL,
            control_title TEXT DEFAULT '',
            UNIQUE (finding_type, framework, control_id)
        );

        CREATE TABLE IF NOT EXISTS discovery_scopes (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            root_domain TEXT NOT NULL,
            allowed_suffixes TEXT DEFAULT '[]',
            excluded_patterns TEXT DEFAULT '[]',
            max_depth INTEGER DEFAULT 2,
            enabled INTEGER DEFAULT 1,
            created_by TEXT DEFAULT '',
            approved_by TEXT,
            valid_from TEXT NOT NULL,
            valid_until TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS discovered_assets (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            discovery_scope_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            canonical_url TEXT NOT NULL,
            source TEXT DEFAULT 'MANUAL_IMPORT',
            confidence TEXT DEFAULT 'MEDIUM',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            status TEXT DEFAULT 'NEW',
            evidence_id TEXT,
            promoted_asset_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (discovery_scope_id) REFERENCES discovery_scopes(id) ON DELETE CASCADE,
            UNIQUE (tenant_id, hostname)
        );

        CREATE TABLE IF NOT EXISTS asset_verifications (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            method TEXT DEFAULT 'DNS_TXT',
            challenge TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            verified_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS evidences (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT,
            scan_id TEXT,
            finding_id TEXT,
            type TEXT DEFAULT 'http_response',
            source TEXT DEFAULT '',
            content_hash TEXT NOT NULL,
            storage_reference TEXT DEFAULT '',
            mime_type TEXT DEFAULT 'application/json',
            size_bytes INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            retention_class TEXT DEFAULT 'STANDARD',
            classification TEXT DEFAULT 'internal',
            sanitized INTEGER DEFAULT 1,
            redacted INTEGER DEFAULT 1,
            provenance TEXT DEFAULT '{}',
            quality TEXT DEFAULT 'STRONG',
            payload TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT DEFAULT 'SCAN_PROFILE',
            active_version_id TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            UNIQUE (tenant_id, name)
        );

        CREATE TABLE IF NOT EXISTS policy_versions (
            id TEXT PRIMARY KEY,
            policy_id TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            status TEXT DEFAULT 'DRAFT',
            definition_json TEXT DEFAULT '{}',
            checksum TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            approved_by TEXT,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
            UNIQUE (policy_id, version)
        );

        CREATE TABLE IF NOT EXISTS business_units (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            code TEXT NOT NULL,
            parent_id TEXT,
            owner_user_id TEXT,
            criticality TEXT DEFAULT 'medium',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            UNIQUE (tenant_id, code)
        );

        CREATE TABLE IF NOT EXISTS business_services (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            business_unit_id TEXT,
            criticality TEXT DEFAULT 'medium',
            owner_user_id TEXT,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (business_unit_id) REFERENCES business_units(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS asset_business_services (
            asset_id TEXT NOT NULL,
            service_id TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            PRIMARY KEY (asset_id, service_id),
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            FOREIGN KEY (service_id) REFERENCES business_services(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS data_quality_issues (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            entity_type TEXT DEFAULT 'asset',
            entity_id TEXT NOT NULL,
            issue_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            description TEXT DEFAULT '',
            detected_at TEXT NOT NULL,
            resolved_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS integration_outbox (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_key TEXT UNIQUE NOT NULL,
            destination TEXT DEFAULT 'siem',
            payload_hash TEXT NOT NULL,
            payload_json TEXT DEFAULT '{}',
            status TEXT DEFAULT 'PENDING',
            attempt INTEGER DEFAULT 1,
            next_retry_at TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS technology_observations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            technology_type TEXT DEFAULT 'CMS',
            name TEXT NOT NULL,
            version TEXT,
            source TEXT DEFAULT 'meta_generator',
            confidence TEXT DEFAULT 'HIGH',
            eol_status TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS saved_views (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            user_id TEXT DEFAULT '',
            name TEXT NOT NULL,
            resource_type TEXT DEFAULT 'portfolio',
            filters_json TEXT DEFAULT '{}',
            is_shared INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
    """)
    conn.commit()

    # Backward compatibility migrations for existing databases
    def safe_add_column(table: str, col: str, col_type: str):
        try:
            cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            if col not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
                conn.commit()
        except Exception:
            pass

    safe_add_column("scans", "whois_info", "TEXT")
    safe_add_column("scans", "tenant_id", "TEXT DEFAULT 'default-tenant'")
    safe_add_column("scans", "asset_id", "TEXT")
    safe_add_column("users", "tenant_id", "TEXT DEFAULT 'default-tenant'")

    def _migrate_users_per_tenant_username_unique():
        """Upgrade legacy SQLite users.username UNIQUE to UNIQUE(tenant_id, username)."""
        try:
            indexes = conn.execute("PRAGMA index_list(users)").fetchall()
            composite_ok = False
            global_username_unique = False
            for idx in indexes:
                cols = [r["name"] for r in conn.execute(f"PRAGMA index_info({idx['name']})").fetchall()]
                if idx["unique"] and cols == ["tenant_id", "username"]:
                    composite_ok = True
                if idx["unique"] and cols == ["username"]:
                    global_username_unique = True
            if composite_ok and not global_username_unique:
                return
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users__tenant_username_migration (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT DEFAULT '',
                    role TEXT DEFAULT 'viewer',
                    status TEXT DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    tenant_id TEXT DEFAULT 'default-tenant',
                    UNIQUE(tenant_id, username)
                );
                INSERT OR IGNORE INTO users__tenant_username_migration
                    (id, username, password_hash, email, role, status, created_at, tenant_id)
                SELECT id, username, password_hash, email, role, status, created_at,
                       COALESCE(NULLIF(tenant_id, ''), 'default-tenant')
                FROM users;
                DROP TABLE users;
                ALTER TABLE users__tenant_username_migration RENAME TO users;
                CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
            """)
            conn.commit()
        except Exception as exc:
            logger.warning("SQLite users tenant-scoped username migration skipped or failed: %s", exc)

    _migrate_users_per_tenant_username_unique()
    safe_add_column("findings", "tenant_id", "TEXT DEFAULT 'default-tenant'")
    safe_add_column("findings", "asset_id", "TEXT")
    safe_add_column("findings", "fingerprint", "TEXT DEFAULT ''")
    safe_add_column("findings", "status", "TEXT DEFAULT 'OPEN'")
    safe_add_column("findings", "first_seen_at", "TEXT")
    safe_add_column("findings", "last_seen_at", "TEXT")
    safe_add_column("findings", "first_scan_id", "TEXT DEFAULT ''")
    safe_add_column("findings", "last_scan_id", "TEXT DEFAULT ''")
    safe_add_column("findings", "observation_count", "INTEGER DEFAULT 1")
    safe_add_column("findings", "assigned_to_user_id", "TEXT")
    safe_add_column("findings", "assigned_team", "TEXT")
    safe_add_column("findings", "assigned_at", "TEXT")
    safe_add_column("findings", "finding_tags", "TEXT DEFAULT '[]'")
    safe_add_column("findings", "version", "INTEGER DEFAULT 1")
    safe_add_column("findings", "priority_score", "REAL DEFAULT 0.0")
    safe_add_column("findings", "priority_band", "TEXT DEFAULT 'P3'")
    safe_add_column("findings", "cvss_score", "REAL")
    safe_add_column("findings", "epss_score", "REAL")
    safe_add_column("findings", "epss_percentile", "REAL")
    safe_add_column("findings", "epss_last_updated", "TEXT")
    safe_add_column("findings", "kev", "INTEGER DEFAULT 0")
    safe_add_column("findings", "kev_date_added", "TEXT")
    safe_add_column("findings", "kev_due_date", "TEXT")
    safe_add_column("findings", "known_ransomware_campaign_use", "INTEGER DEFAULT 0")
    safe_add_column("findings", "ransomware_relevance", "TEXT DEFAULT 'NONE'")
    safe_add_column("findings", "cve_id", "TEXT")
    safe_add_column("findings", "sla_policy_id", "TEXT")
    safe_add_column("findings", "sla_due_at", "TEXT")
    safe_add_column("findings", "sla_status", "TEXT DEFAULT 'NOT_APPLICABLE'")
    safe_add_column("findings", "sla_paused_at", "TEXT")
    safe_add_column("findings", "sla_pause_reason", "TEXT")
    safe_add_column("findings", "verified_at", "TEXT")
    safe_add_column("findings", "verified_by_scan_id", "TEXT")
    safe_add_column("findings", "false_positive_reason", "TEXT")
    safe_add_column("findings", "false_positive_by", "TEXT")
    safe_add_column("findings", "false_positive_at", "TEXT")
    safe_add_column("findings", "false_positive_valid_until", "TEXT")
    safe_add_column("findings", "updated_at", "TEXT")
    safe_add_column("scheduled_scans", "tenant_id", "TEXT DEFAULT 'default-tenant'")
    safe_add_column("scheduled_scans", "asset_id", "TEXT")
    safe_add_column("finding_observations", "asset_id", "TEXT")
    safe_add_column("finding_observations", "scanner_id", "TEXT")
    safe_add_column("finding_observations", "evidence_reference", "TEXT")
    safe_add_column("api_keys", "key_prefix", "TEXT DEFAULT ''")
    safe_add_column("daily_risk_snapshots", "assets", "INTEGER DEFAULT 0")
    safe_add_column("daily_risk_snapshots", "risk_accepted", "INTEGER DEFAULT 0")
    safe_add_column("daily_risk_snapshots", "avg_risk_score", "REAL DEFAULT 0.0")
    safe_add_column("sla_policies", "asset_criticality", "TEXT")
    safe_add_column("sla_policies", "priority_band", "TEXT")
    safe_add_column("assets", "business_unit_id", "TEXT")
    # Sprint 3: Asset Inventory & Monitoring fields
    safe_add_column("assets", "wp_install_path", "TEXT DEFAULT '/'")
    safe_add_column("assets", "monitoring_enabled", "INTEGER DEFAULT 0")
    safe_add_column("assets", "monitoring_paused_at", "TEXT")
    safe_add_column("assets", "last_scan_id", "TEXT")
    safe_add_column("assets", "last_scan_at", "TEXT")
    safe_add_column("assets", "last_scan_status", "TEXT")
    safe_add_column("assets", "last_successful_scan_at", "TEXT")
    safe_add_column("assets", "consecutive_scan_failures", "INTEGER DEFAULT 0")
    safe_add_column("assets", "wp_version", "TEXT")
    safe_add_column("assets", "detected_themes", "TEXT DEFAULT ''")
    safe_add_column("assets", "detected_plugins", "TEXT DEFAULT ''")
    safe_add_column("assets", "risk_score", "REAL")
    # Sprint 3: ScheduledScan failure tracking & pause
    safe_add_column("scheduled_scans", "max_retries", "INTEGER DEFAULT 3")
    safe_add_column("scheduled_scans", "consecutive_failures", "INTEGER DEFAULT 0")
    safe_add_column("scheduled_scans", "last_failure_at", "TEXT")
    safe_add_column("scheduled_scans", "last_success_at", "TEXT")
    safe_add_column("scheduled_scans", "paused_until", "TEXT")
    safe_add_column("findings", "finding_confidence", "TEXT DEFAULT 'HIGH'")
    safe_add_column("findings", "policy_version_id", "TEXT")
    safe_add_column("scan_jobs", "policy_version_id", "TEXT")
    safe_add_column("daily_risk_snapshots", "business_unit_id", "TEXT")
    safe_add_column("daily_risk_snapshots", "verified_asset_count", "INTEGER DEFAULT 0")
    safe_add_column("daily_risk_snapshots", "internet_exposed_count", "INTEGER DEFAULT 0")
    safe_add_column("daily_risk_snapshots", "unassigned_findings", "INTEGER DEFAULT 0")
    safe_add_column("daily_risk_snapshots", "accepted_risk_count", "INTEGER DEFAULT 0")
    safe_add_column("integration_outbox", "claimed_at", "TEXT")
    safe_add_column("integration_outbox", "claimed_by", "TEXT")

    # Create indexes after ensuring columns exist
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
        CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(tenant_id, fingerprint);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(tenant_id, priority_score);
        CREATE INDEX IF NOT EXISTS idx_findings_sla ON findings(tenant_id, sla_status, sla_due_at);
        CREATE UNIQUE INDEX IF NOT EXISTS uq_obs_finding_scan ON finding_observations(finding_id, scan_id);
        CREATE INDEX IF NOT EXISTS idx_observations_finding ON finding_observations(finding_id);
        CREATE INDEX IF NOT EXISTS idx_observations_scan ON finding_observations(scan_id);
        CREATE INDEX IF NOT EXISTS idx_observations_time ON finding_observations(observed_at);
        CREATE INDEX IF NOT EXISTS idx_history_finding ON finding_history(finding_id);
        CREATE INDEX IF NOT EXISTS idx_comments_finding ON finding_comments(finding_id);
        CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediations(finding_id);
        CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_risk_accept_finding ON risk_acceptances(finding_id);
        CREATE INDEX IF NOT EXISTS idx_risk_accept_expiry ON risk_acceptances(status, valid_until);
        CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON integrations(tenant_id, type);
        CREATE INDEX IF NOT EXISTS idx_ticket_refs_finding ON ticket_references(finding_id);
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id);
        CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_assets_canonical ON assets(tenant_id, canonical_url);
        CREATE INDEX IF NOT EXISTS idx_authorizations_asset ON scan_authorizations(asset_id);
        CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit_events(tenant_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_scheduled_tenant ON scheduled_scans(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant ON scan_jobs(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_scan ON scan_jobs(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_heartbeat ON scan_jobs(heartbeat_at);
        CREATE INDEX IF NOT EXISTS idx_sched_runs_schedule ON scheduled_runs(schedule_id);
        CREATE INDEX IF NOT EXISTS idx_sched_runs_planned ON scheduled_runs(planned_at);
        CREATE INDEX IF NOT EXISTS idx_assets_bu ON assets(business_unit_id);
        CREATE INDEX IF NOT EXISTS idx_discovery_scopes_domain ON discovery_scopes(tenant_id, root_domain);
        CREATE INDEX IF NOT EXISTS idx_discovered_assets_status ON discovered_assets(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_discovered_assets_host ON discovered_assets(hostname);
        CREATE INDEX IF NOT EXISTS idx_evidences_hash ON evidences(tenant_id, content_hash);
        CREATE INDEX IF NOT EXISTS idx_evidences_finding ON evidences(tenant_id, finding_id);
        CREATE INDEX IF NOT EXISTS idx_evidences_asset ON evidences(tenant_id, asset_id);
        CREATE INDEX IF NOT EXISTS idx_policy_versions_active ON policy_versions(policy_id, status);
        CREATE INDEX IF NOT EXISTS idx_business_units_tenant ON business_units(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_business_services_bu ON business_services(business_unit_id);
        CREATE INDEX IF NOT EXISTS idx_dq_tenant ON data_quality_issues(tenant_id, resolved_at);
        CREATE INDEX IF NOT EXISTS idx_outbox_status ON integration_outbox(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_tech_obs_asset ON technology_observations(asset_id, technology_type);
        CREATE INDEX IF NOT EXISTS idx_saved_views_user ON saved_views(tenant_id, user_id);
        CREATE INDEX IF NOT EXISTS idx_assets_tenant_crit ON assets(tenant_id, criticality);
        CREATE INDEX IF NOT EXISTS idx_assets_tenant_exposure ON assets(tenant_id, internet_exposure);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_queued_time ON scan_jobs(status, queued_at);
        CREATE INDEX IF NOT EXISTS idx_outbox_processing_claimed ON integration_outbox(status, claimed_at);
        CREATE INDEX IF NOT EXISTS idx_sched_runs_status_job ON scheduled_runs(status, scan_job_id, created_at);
    """)
    conn.commit()

    # Seed Default Workspace (Tenant)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, name, slug, status, created_at) VALUES (?, ?, ?, ?, ?)",
        ("default-tenant", "Default Workspace", "default", "active", now_iso)
    )
    conn.commit()

    # Backfill legacy records missing tenant_id
    conn.execute("UPDATE users SET tenant_id = 'default-tenant' WHERE tenant_id IS NULL OR tenant_id = ''")
    conn.execute("UPDATE scans SET tenant_id = 'default-tenant' WHERE tenant_id IS NULL OR tenant_id = ''")
    conn.execute("UPDATE findings SET tenant_id = 'default-tenant' WHERE tenant_id IS NULL OR tenant_id = ''")
    conn.execute("UPDATE scheduled_scans SET tenant_id = 'default-tenant' WHERE tenant_id IS NULL OR tenant_id = ''")
    conn.commit()

    # Backfill new columns for scans if missing
    safe_add_column("scans", "wp_version_source", "TEXT")
    safe_add_column("scans", "wp_version_confidence", "TEXT")
    safe_add_column("scans", "wordpress_detected", "INTEGER")
    safe_add_column("scans", "wordpress_version", "TEXT")
    safe_add_column("scans", "wordpress_version_source", "TEXT")
    safe_add_column("scans", "wordpress_version_confidence", "TEXT")
    conn.commit()

    # Idempotent legacy findings migration
    try:
        legacy_findings = conn.execute("SELECT id, tenant_id, asset_id, scan_id, category, title, description, severity, reference, raw_data, fingerprint, status, created_at FROM findings WHERE fingerprint IS NULL OR fingerprint = ''").fetchall()
        for r in legacy_findings:
            fid = r["id"]
            tid = r["tenant_id"] or "default-tenant"
            aid = r["asset_id"]
            sid = r["scan_id"]
            raw = json.loads(r["raw_data"]) if r["raw_data"] else {}
            scanner_id = raw.get("scanner") or r["category"] or "general"
            finding_type = raw.get("finding_type") or r["category"] or r["title"]
            location = raw.get("location") or raw.get("path") or r["reference"] or ""
            identifier = raw.get("cve_id") or raw.get("vulnerability_id") or r["title"]
            fp = compute_finding_fingerprint(tid, aid, scanner_id, finding_type, location, identifier)

            raw_status = (r["status"] or "OPEN").upper()
            if raw_status == "FIXED":
                status = FindingStatus.VERIFIED.value
            elif raw_status == "FALSE_POSITIVE":
                status = FindingStatus.FALSE_POSITIVE.value
            elif raw_status in FindingStatus.__members__:
                status = FindingStatus[raw_status].value
            else:
                status = FindingStatus.OPEN.value

            conn.execute(
                "UPDATE findings SET fingerprint = ?, status = ?, first_seen_at = coalesce(first_seen_at, ?), last_seen_at = coalesce(last_seen_at, ?), first_scan_id = coalesce(nullif(first_scan_id, ''), ?), last_scan_id = coalesce(nullif(last_scan_id, ''), ?), observation_count = coalesce(observation_count, 1) WHERE id = ?",
                (fp, status, r["created_at"], r["created_at"], sid, sid, fid)
            )
            obs_id = str(uuid.uuid4())
            conn.execute(
                "INSERT OR IGNORE INTO finding_observations (id, tenant_id, finding_id, scan_id, asset_id, scanner_id, observed_at, severity, evidence_id, evidence_reference, status, raw_reference, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (obs_id, tid, fid, sid, aid, scanner_id, r["created_at"], r["severity"] or "info", None, r["reference"], status, r["reference"], r["created_at"])
            )
        conn.commit()
    except Exception:
        pass

    # Initialize vulnerability intelligence tables
    try:
        from core.vulnerability_intelligence.repository import init_vuln_intel_db
        init_vuln_intel_db()
    except Exception:
        pass

    _db_initialized = True


# --- Tenants ---
@adapter_dispatch("save_tenant")
def save_tenant(tenant: Tenant):
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO tenants (id, name, slug, status, created_at, updated_at) VALUES (?,?,?,?,?,?)",
        (tenant.id, tenant.name, tenant.slug, tenant.status, tenant.created_at, tenant.updated_at)
    )
    conn.commit()


@adapter_dispatch("get_tenant_by_id")
def get_tenant_by_id(tenant_id: str) -> Optional[Tenant]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
    if not row:
        return None
    return Tenant(
        id=row["id"], name=row["name"], slug=row["slug"],
        status=row["status"], created_at=row["created_at"],
        updated_at=row["updated_at"]
    )


@adapter_dispatch("get_tenant_by_slug")
def get_tenant_by_slug(slug: str) -> Optional[Tenant]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM tenants WHERE slug = ?", (slug,)).fetchone()
    if not row:
        return None
    return Tenant(
        id=row["id"], name=row["name"], slug=row["slug"],
        status=row["status"], created_at=row["created_at"],
        updated_at=row["updated_at"]
    )


@adapter_dispatch("list_tenants")
def list_tenants() -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM tenants ORDER BY created_at ASC").fetchall()
    return [Tenant(
        id=r["id"], name=r["name"], slug=r["slug"],
        status=r["status"], created_at=r["created_at"],
        updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("update_tenant")
def update_tenant(tenant_id: str, **kwargs):
    conn = _get_conn()
    fields = []
    values = []
    for k, v in kwargs.items():
        if k in ("name", "slug", "status", "updated_at"):
            fields.append(f"{k} = ?")
            values.append(v)
    if not fields:
        return
    if "updated_at" not in kwargs:
        fields.append("updated_at = ?")
        values.append(datetime.now(timezone.utc).isoformat())
    values.append(tenant_id)
    conn.execute(f"UPDATE tenants SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()


@adapter_dispatch("delete_tenant")
def delete_tenant(tenant_id: str, hard: bool = False):
    conn = _get_conn()
    if hard:
        # Enable foreign key cascade or manually clean up if SQLite
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
    else:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE tenants SET status = 'disabled', updated_at = ? WHERE id = ?", (now, tenant_id))
    conn.commit()


get_tenant = get_tenant_by_id
create_tenant = save_tenant


@adapter_dispatch("ensure_default_tenant")
def ensure_default_tenant() -> Tenant:
    t = get_tenant_by_id("default-tenant")
    if not t:
        t = Tenant(
            id="default-tenant",
            name="Default Workspace",
            slug="default",
            status="active"
        )
        save_tenant(t)
    return t



# --- Assets ---
def _row_to_asset(row) -> Asset:
    """Converts a DB row to an Asset, handling Sprint 3 columns safely."""
    keys = row.keys()
    return Asset(
        id=row["id"], tenant_id=row["tenant_id"], canonical_url=row["canonical_url"],
        hostname=row["hostname"],
        wp_install_path=row["wp_install_path"] if "wp_install_path" in keys else "/",
        display_name=row["display_name"],
        business_owner=row["business_owner"], technical_owner=row["technical_owner"],
        environment=row["environment"], internet_exposure=row["internet_exposure"],
        criticality=row["criticality"], data_classification=row["data_classification"],
        authorization_status=row["authorization_status"],
        authorization_review_date=row["authorization_review_date"],
        tags=row["tags"], status=row["status"],
        business_unit_id=row["business_unit_id"] if "business_unit_id" in keys else None,
        monitoring_enabled=bool(row["monitoring_enabled"]) if "monitoring_enabled" in keys else False,
        monitoring_paused_at=row["monitoring_paused_at"] if "monitoring_paused_at" in keys else None,
        last_scan_id=row["last_scan_id"] if "last_scan_id" in keys else None,
        last_scan_at=row["last_scan_at"] if "last_scan_at" in keys else None,
        last_scan_status=row["last_scan_status"] if "last_scan_status" in keys else None,
        last_successful_scan_at=row["last_successful_scan_at"] if "last_successful_scan_at" in keys else None,
        consecutive_scan_failures=int(row["consecutive_scan_failures"]) if "consecutive_scan_failures" in keys and row["consecutive_scan_failures"] is not None else 0,
        wp_version=row["wp_version"] if "wp_version" in keys else None,
        detected_themes=row["detected_themes"] if "detected_themes" in keys else "",
        detected_plugins=row["detected_plugins"] if "detected_plugins" in keys else "",
        risk_score=row["risk_score"] if "risk_score" in keys else None,
        created_at=row["created_at"], updated_at=row["updated_at"]
    )


# --- Assets ---
@adapter_dispatch("save_asset")
def save_asset(asset: Asset):
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO assets (
            id, tenant_id, canonical_url, hostname, wp_install_path, display_name,
            business_owner, technical_owner, environment, internet_exposure,
            criticality, data_classification, authorization_status,
            authorization_review_date, tags, status, business_unit_id,
            monitoring_enabled, monitoring_paused_at,
            last_scan_id, last_scan_at, last_scan_status, last_successful_scan_at,
            consecutive_scan_failures, wp_version, detected_themes, detected_plugins,
            risk_score, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (asset.id, asset.tenant_id, asset.canonical_url, asset.hostname,
         getattr(asset, "wp_install_path", "/"),
         asset.display_name, asset.business_owner, asset.technical_owner,
         asset.environment, asset.internet_exposure, asset.criticality,
         asset.data_classification, asset.authorization_status,
         asset.authorization_review_date, asset.tags, asset.status,
         asset.business_unit_id,
         int(getattr(asset, "monitoring_enabled", False)),
         getattr(asset, "monitoring_paused_at", None),
         getattr(asset, "last_scan_id", None),
         getattr(asset, "last_scan_at", None),
         getattr(asset, "last_scan_status", None),
         getattr(asset, "last_successful_scan_at", None),
         getattr(asset, "consecutive_scan_failures", 0),
         getattr(asset, "wp_version", None),
         getattr(asset, "detected_themes", ""),
         getattr(asset, "detected_plugins", ""),
         getattr(asset, "risk_score", None),
         asset.created_at, asset.updated_at)
    )
    conn.commit()


@adapter_dispatch("get_asset")
def get_asset(asset_id: str, tenant_id: Optional[str] = None) -> Optional[Asset]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM assets WHERE id = ? AND tenant_id = ?", (asset_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if not row:
        return None
    return _row_to_asset(row)


@adapter_dispatch("get_asset_by_url")
def get_asset_by_url(tenant_id: str, canonical_url: str) -> Optional[Asset]:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM assets WHERE tenant_id = ? AND canonical_url = ?",
        (tenant_id, canonical_url)
    ).fetchone()
    if not row:
        return None
    return _row_to_asset(row)


@adapter_dispatch("ensure_asset_for_target")
def ensure_asset_for_target(tenant_id: str, target_url: str, display_name: str = "") -> Asset:
    """Finds existing asset by canonical URL within tenant, or creates and returns a new active Asset."""
    canonical_url, hostname = canonicalize_url(target_url)
    existing = get_asset_by_url(tenant_id, canonical_url)
    if existing:
        return existing

    asset = Asset(
        tenant_id=tenant_id,
        canonical_url=canonical_url,
        hostname=hostname,
        display_name=display_name or hostname,
        status="active"
    )
    save_asset(asset)
    return asset


@adapter_dispatch("ensure_asset")
def ensure_asset(target_url: str, tenant_id: str, display_name: str = "") -> Asset:
    return ensure_asset_for_target(tenant_id, target_url, display_name=display_name)


@adapter_dispatch("list_assets")
def list_assets(
    tenant_id: Optional[str] = None,
    filters: Optional[dict] = None,
    limit: Optional[int] = 500,
    offset: int = 0
) -> list:
    conn = _get_conn()
    query = "SELECT * FROM assets WHERE 1=1"
    params = []

    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)

    if filters:
        if filters.get("query"):
            q = f"%{filters['query']}%"
            query += " AND (canonical_url LIKE ? OR hostname LIKE ? OR display_name LIKE ? OR tags LIKE ?)"
            params.extend([q, q, q, q])
        if filters.get("status"):
            query += " AND status = ?"
            params.append(filters["status"])
        if filters.get("environment"):
            query += " AND environment = ?"
            params.append(filters["environment"])
        if filters.get("criticality"):
            query += " AND criticality = ?"
            params.append(filters["criticality"])
        if filters.get("authorization_status"):
            query += " AND authorization_status = ?"
            params.append(filters["authorization_status"])
        if filters.get("business_unit_id"):
            query += " AND business_unit_id = ?"
            params.append(filters["business_unit_id"])

    query += " ORDER BY created_at DESC"
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [_row_to_asset(r) for r in rows]


@adapter_dispatch("update_asset")
def update_asset(asset_id: str, tenant_id: Optional[str] = None, **kwargs):
    conn = _get_conn()
    allowed = {
        "display_name", "business_owner", "technical_owner", "environment",
        "internet_exposure", "criticality", "data_classification",
        "authorization_status", "authorization_review_date", "tags", "status",
        "canonical_url", "hostname", "business_unit_id",
        # Sprint 3: monitoring & posture fields
        "wp_install_path", "monitoring_enabled", "monitoring_paused_at",
        "last_scan_id", "last_scan_at", "last_scan_status", "last_successful_scan_at",
        "consecutive_scan_failures", "wp_version", "detected_themes", "detected_plugins",
        "risk_score",
    }
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            vals.append(v)
    if sets:
        sets.append("updated_at = ?")
        vals.append(datetime.now(timezone.utc).isoformat())
        vals.append(asset_id)
        where_clause = "WHERE id = ?"
        if tenant_id:
            where_clause += " AND tenant_id = ?"
            vals.append(tenant_id)
        conn.execute(f"UPDATE assets SET {', '.join(sets)} {where_clause}", vals)
        conn.commit()


@adapter_dispatch("delete_asset")
def delete_asset(asset_id: str, tenant_id: Optional[str] = None, hard: bool = False):
    conn = _get_conn()
    if hard:
        if tenant_id:
            conn.execute("DELETE FROM assets WHERE id = ? AND tenant_id = ?", (asset_id, tenant_id))
        else:
            conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    else:
        update_asset(asset_id, tenant_id=tenant_id, status="disabled")
    conn.commit()


# --- Scan Authorizations ---
@adapter_dispatch("save_scan_authorization")
def save_scan_authorization(auth: ScanAuthorization):
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO scan_authorizations (
            id, tenant_id, asset_id, status, allowed_profiles, request_budget,
            valid_from, valid_until, approved_by, notes, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (auth.id, auth.tenant_id, auth.asset_id, auth.status, auth.allowed_profiles,
         auth.request_budget, auth.valid_from, auth.valid_until, auth.approved_by,
         auth.notes, auth.created_at, auth.updated_at)
    )
    conn.commit()


@adapter_dispatch("get_scan_authorization")
def get_scan_authorization(auth_id: str, tenant_id: Optional[str] = None) -> Optional[ScanAuthorization]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM scan_authorizations WHERE id = ? AND tenant_id = ?", (auth_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM scan_authorizations WHERE id = ?", (auth_id,)).fetchone()
    if not row:
        return None
    return ScanAuthorization(
        id=row["id"], tenant_id=row["tenant_id"], asset_id=row["asset_id"],
        status=row["status"], allowed_profiles=row["allowed_profiles"],
        request_budget=row["request_budget"], valid_from=row["valid_from"],
        valid_until=row["valid_until"], approved_by=row["approved_by"],
        notes=row["notes"], created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("get_active_authorization")
def get_active_authorization(asset_id: str, tenant_id: Optional[str] = None) -> Optional[ScanAuthorization]:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    query = """
        SELECT * FROM scan_authorizations
        WHERE asset_id = ? AND status = 'active'
        AND valid_from <= ? AND valid_until >= ?
    """
    params = [asset_id, now_iso, now_iso]
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    query += " ORDER BY valid_until DESC LIMIT 1"
    row = conn.execute(query, params).fetchone()
    if not row:
        return None
    return ScanAuthorization(
        id=row["id"], tenant_id=row["tenant_id"], asset_id=row["asset_id"],
        status=row["status"], allowed_profiles=row["allowed_profiles"],
        request_budget=row["request_budget"], valid_from=row["valid_from"],
        valid_until=row["valid_until"], approved_by=row["approved_by"],
        notes=row["notes"], created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_scan_authorizations")
def list_scan_authorizations(asset_id: Optional[str] = None, tenant_id: Optional[str] = None) -> list:
    conn = _get_conn()
    query = "SELECT * FROM scan_authorizations WHERE 1=1"
    params = []
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    if asset_id:
        query += " AND asset_id = ?"
        params.append(asset_id)
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [ScanAuthorization(
        id=r["id"], tenant_id=r["tenant_id"], asset_id=r["asset_id"],
        status=r["status"], allowed_profiles=r["allowed_profiles"],
        request_budget=r["request_budget"], valid_from=r["valid_from"],
        valid_until=r["valid_until"], approved_by=r["approved_by"],
        notes=r["notes"], created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("revoke_scan_authorization")
def revoke_scan_authorization(auth_id: str, tenant_id: Optional[str] = None):
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if tenant_id:
        conn.execute("UPDATE scan_authorizations SET status = 'revoked', updated_at = ? WHERE id = ? AND tenant_id = ?", (now_iso, auth_id, tenant_id))
    else:
        conn.execute("UPDATE scan_authorizations SET status = 'revoked', updated_at = ? WHERE id = ?", (now_iso, auth_id))
    conn.commit()


# --- Audit Events ---
_SENSITIVE_AUDIT_KEYS = {"password", "secret", "token", "cookie", "session", "key", "api_key", "authorization"}


def _sanitize_metadata(data: Any) -> Any:
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(s in k.lower() for s in _SENSITIVE_AUDIT_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = _sanitize_metadata(v)
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_metadata(item) for item in data]
    return data


@adapter_dispatch("log_audit_event")
def log_audit_event(
    tenant_id: Any,
    actor_user_id: str = "",
    actor_username: str = "",
    action: str = "",
    resource_type: str = "",
    resource_id: str = "",
    result: str = "success",
    metadata: Optional[dict] = None
) -> AuditEvent:
    """Records an immutable audit entry with strictly sanitized metadata."""
    def _clean(val, default=""):
        if val is None or hasattr(val, "_mock_name") or hasattr(val, "_mock_return_value"):
            return default
        return str(val)

    if isinstance(tenant_id, AuditEvent):
        evt = tenant_id
        clean_tenant = _clean(evt.tenant_id, "default-tenant") or "default-tenant"
        clean_user_id = _clean(evt.actor_user_id, "")
        clean_username = _clean(evt.actor_username, "system")
        clean_action = _clean(evt.action, "unknown")
        clean_res_type = _clean(evt.resource_type, "")
        clean_res_id = _clean(evt.resource_id, "")
        clean_result = _clean(evt.result, "success")
        safe_metadata = _sanitize_metadata(evt.metadata or {})
    else:
        clean_tenant = _clean(tenant_id, "default-tenant") or "default-tenant"
        clean_user_id = _clean(actor_user_id, "")
        clean_username = _clean(actor_username, "system")
        clean_action = _clean(action, "unknown")
        clean_res_type = _clean(resource_type, "")
        clean_res_id = _clean(resource_id, "")
        clean_result = _clean(result, "success")
        safe_metadata = _sanitize_metadata(metadata or {})

    conn = _get_conn()
    event = AuditEvent(
        tenant_id=clean_tenant,
        actor_user_id=clean_user_id,
        actor_username=clean_username,
        action=clean_action,
        resource_type=clean_res_type,
        resource_id=clean_res_id,
        result=clean_result,
        metadata=safe_metadata,
        created_at=datetime.now(timezone.utc).isoformat()
    )
    for attempt in range(3):
        try:
            conn.execute(
                """INSERT INTO audit_events (
                    id, tenant_id, actor_user_id, actor_username, action,
                    resource_type, resource_id, result, metadata, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (event.id, event.tenant_id, event.actor_user_id, event.actor_username,
                 event.action, event.resource_type, event.resource_id, event.result,
                 json.dumps(event.metadata), event.created_at)
            )
            conn.commit()
            break
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < 2:
                time.sleep(0.15 * (attempt + 1))
                continue
            logger.warning("Could not persist audit event due to sqlite operational error: %s", e)
            break
    return event


save_audit_event = log_audit_event


@adapter_dispatch("list_audit_events")
def list_audit_events(tenant_id: Optional[str] = None, limit: int = 100, offset: int = 0, filters: Optional[dict] = None) -> list:
    conn = _get_conn()
    query = "SELECT * FROM audit_events WHERE 1=1"
    params = []
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    if filters:
        if filters.get("action"):
            query += " AND action = ?"
            params.append(filters["action"])
        if filters.get("result"):
            query += " AND result = ?"
            params.append(filters["result"])
        if filters.get("resource_type"):
            query += " AND resource_type = ?"
            params.append(filters["resource_type"])
        if filters.get("actor_username"):
            query += " AND actor_username LIKE ?"
            params.append(f"%{filters['actor_username']}%")
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [AuditEvent(
        id=r["id"], tenant_id=r["tenant_id"], actor_user_id=r["actor_user_id"],
        actor_username=r["actor_username"], action=r["action"],
        resource_type=r["resource_type"], resource_id=r["resource_id"],
        result=r["result"],
        metadata=json.loads(r["metadata"]) if r["metadata"] else {},
        created_at=r["created_at"]
    ) for r in rows]


# --- Users ---
@adapter_dispatch("save_user")
def save_user(user: User):
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO users (id, username, password_hash, email, role, status, created_at, tenant_id) VALUES (?,?,?,?,?,?,?,?)",
        (user.id, user.username, user.password_hash, user.email,
         user.role.value if isinstance(user.role, UserRole) else user.role,
         user.status.value if isinstance(user.status, UserStatus) else user.status,
         user.created_at, user.tenant_id)
    )
    conn.commit()


@adapter_dispatch("get_user_by_username")
def get_user_by_username(username: str, tenant_id: Optional[str] = None) -> Optional[User]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM users WHERE username = ? AND tenant_id = ?", (username, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return None
    return User(
        id=row["id"], username=row["username"], password_hash=row["password_hash"],
        email=row["email"], role=UserRole(row["role"]), status=UserStatus(row["status"]),
        created_at=row["created_at"], tenant_id=row["tenant_id"] if "tenant_id" in row.keys() else "default-tenant"
    )


@adapter_dispatch("list_users_by_username")
def list_users_by_username(username: str) -> List[User]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
    return [
        User(
            id=row["id"], username=row["username"], password_hash=row["password_hash"],
            email=row["email"], role=UserRole(row["role"]), status=UserStatus(row["status"]),
            created_at=row["created_at"],
            tenant_id=row["tenant_id"] if "tenant_id" in row.keys() else "default-tenant",
        )
        for row in rows
    ]


@adapter_dispatch("get_user_by_id")
def get_user_by_id(user_id: str, tenant_id: Optional[str] = None) -> Optional[User]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM users WHERE id = ? AND tenant_id = ?", (user_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None
    return User(
        id=row["id"], username=row["username"], password_hash=row["password_hash"],
        email=row["email"], role=UserRole(row["role"]), status=UserStatus(row["status"]),
        created_at=row["created_at"], tenant_id=row["tenant_id"] if "tenant_id" in row.keys() else "default-tenant"
    )


@adapter_dispatch("list_users")
def list_users(tenant_id: Optional[str] = None) -> list:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM users WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [User(
        id=r["id"], username=r["username"], password_hash=r["password_hash"],
        email=r["email"], role=UserRole(r["role"]), status=UserStatus(r["status"]),
        created_at=r["created_at"], tenant_id=r["tenant_id"] if "tenant_id" in r.keys() else "default-tenant"
    ) for r in rows]


@adapter_dispatch("count_users")
def count_users(tenant_id: Optional[str] = None) -> int:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE tenant_id = ?", (tenant_id,)).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()
    return row["cnt"] if row else 0


@adapter_dispatch("update_user")
def update_user(user_id: str, tenant_id: Optional[str] = None, **kwargs):
    conn = _get_conn()
    allowed = {"username", "password_hash", "email", "role", "status", "tenant_id"}
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in allowed:
            if hasattr(v, "value"):
                v = v.value
            sets.append(f"{k} = ?")
            vals.append(v)
    if sets:
        vals.append(user_id)
        where_clause = "WHERE id = ?"
        if tenant_id:
            where_clause += " AND tenant_id = ?"
            vals.append(tenant_id)
        conn.execute(f"UPDATE users SET {', '.join(sets)} {where_clause}", vals)
        conn.commit()


@adapter_dispatch("delete_user")
def delete_user(user_id: str, tenant_id: Optional[str] = None):
    conn = _get_conn()
    if tenant_id:
        conn.execute("DELETE FROM users WHERE id = ? AND tenant_id = ?", (user_id, tenant_id))
    else:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


# --- Scans ---
@adapter_dispatch("save_scan")
def save_scan(scan: ScanResult):
    conn = _get_conn()
    exists = conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan.id,)).fetchone()
    wp_det = scan.wordpress_detected if scan.wordpress_detected is not None else scan.is_wordpress
    wp_v = scan.wordpress_version if scan.wordpress_version is not None else scan.wp_version
    wp_src = scan.wordpress_version_source if scan.wordpress_version_source is not None else scan.wp_version_source
    wp_conf = scan.wordpress_version_confidence if scan.wordpress_version_confidence is not None else scan.wp_version_confidence
    wp_det_int = 1 if wp_det else (0 if wp_det is not None else None)

    cols = [r["name"] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
    has_canonical = "wordpress_version" in cols

    if exists:
        if has_canonical:
            conn.execute(
                """UPDATE scans SET
                    target_url = ?, status = ?, scan_mode = ?, started_at = ?, completed_at = ?,
                    score = ?, grade = ?, notes = ?, tags = ?, initiated_by = ?,
                    wordpress_detected = ?, wordpress_version = ?, wordpress_version_source = ?, wordpress_version_confidence = ?,
                    wp_version = ?, wp_version_source = ?, wp_version_confidence = ?,
                    is_wordpress = ?, whois_info = ?, tenant_id = ?, asset_id = ?
                WHERE id = ?""",
                (scan.target_url, scan.status.value if isinstance(scan.status, ScanStatus) else scan.status,
                 scan.scan_mode, scan.started_at, scan.completed_at, scan.score, scan.grade, scan.notes, scan.tags,
                 scan.initiated_by, wp_det_int, wp_v, wp_src, wp_conf, wp_v, wp_src, wp_conf,
                 wp_det_int, scan.whois_info, scan.tenant_id or "default-tenant", scan.asset_id, scan.id)
            )
        else:
            conn.execute(
                """UPDATE scans SET
                    target_url = ?, status = ?, scan_mode = ?, started_at = ?, completed_at = ?,
                    score = ?, grade = ?, notes = ?, tags = ?, initiated_by = ?, wp_version = ?,
                    wp_version_source = ?, wp_version_confidence = ?,
                    is_wordpress = ?, whois_info = ?, tenant_id = ?, asset_id = ?
                WHERE id = ?""",
                (scan.target_url, scan.status.value if isinstance(scan.status, ScanStatus) else scan.status,
                 scan.scan_mode, scan.started_at, scan.completed_at, scan.score, scan.grade, scan.notes, scan.tags,
                 scan.initiated_by, wp_v, wp_src, wp_conf,
                 wp_det_int, scan.whois_info, scan.tenant_id or "default-tenant", scan.asset_id, scan.id)
            )
    else:
        if has_canonical:
            conn.execute(
                """INSERT INTO scans (
                    id, target_url, status, scan_mode, started_at, completed_at,
                    score, grade, notes, tags, initiated_by,
                    wordpress_detected, wordpress_version, wordpress_version_source, wordpress_version_confidence,
                    wp_version, wp_version_source, wp_version_confidence, is_wordpress,
                    whois_info, tenant_id, asset_id
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan.id, scan.target_url, scan.status.value if isinstance(scan.status, ScanStatus) else scan.status,
                 scan.scan_mode, scan.started_at, scan.completed_at, scan.score, scan.grade, scan.notes, scan.tags,
                 scan.initiated_by, wp_det_int, wp_v, wp_src, wp_conf, wp_v, wp_src, wp_conf,
                 wp_det_int, scan.whois_info, scan.tenant_id or "default-tenant", scan.asset_id)
            )
        else:
            conn.execute(
                """INSERT INTO scans (
                    id, target_url, status, scan_mode, started_at, completed_at,
                    score, grade, notes, tags, initiated_by, wp_version,
                    wp_version_source, wp_version_confidence, is_wordpress,
                    whois_info, tenant_id, asset_id
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan.id, scan.target_url, scan.status.value if isinstance(scan.status, ScanStatus) else scan.status,
                 scan.scan_mode, scan.started_at, scan.completed_at, scan.score, scan.grade, scan.notes, scan.tags,
                 scan.initiated_by, wp_v, wp_src, wp_conf,
                 wp_det_int, scan.whois_info, scan.tenant_id or "default-tenant", scan.asset_id)
            )
    conn.commit()


@adapter_dispatch("get_scan")
def get_scan(scan_id: str, tenant_id: Optional[str] = None) -> Optional[ScanResult]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM scans WHERE id = ? AND tenant_id = ?", (scan_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    keys = row.keys()
    wp_det = bool(row["wordpress_detected"]) if ("wordpress_detected" in keys and row["wordpress_detected"] is not None) else (bool(row["is_wordpress"]) if ("is_wordpress" in keys and row["is_wordpress"] is not None) else None)
    wp_v = row["wordpress_version"] if ("wordpress_version" in keys and row["wordpress_version"] is not None) else (row["wp_version"] if "wp_version" in keys else None)
    wp_src = row["wordpress_version_source"] if ("wordpress_version_source" in keys and row["wordpress_version_source"] is not None) else (row["wp_version_source"] if "wp_version_source" in keys else None)
    wp_conf = row["wordpress_version_confidence"] if ("wordpress_version_confidence" in keys and row["wordpress_version_confidence"] is not None) else (row["wp_version_confidence"] if "wp_version_confidence" in keys else None)

    scan = ScanResult(
        id=row["id"], target_url=row["target_url"], status=ScanStatus(row["status"]),
        scan_mode=row["scan_mode"] if "scan_mode" in keys else "passive",
        started_at=row["started_at"], completed_at=row["completed_at"],
        score=row["score"], grade=row["grade"], notes=row["notes"], tags=row["tags"],
        initiated_by=row["initiated_by"],
        wordpress_detected=wp_det,
        wordpress_version=wp_v,
        wordpress_version_source=wp_src,
        wordpress_version_confidence=wp_conf,
        wp_version=wp_v,
        wp_version_source=wp_src,
        wp_version_confidence=wp_conf,
        is_wordpress=wp_det,
        whois_info=row["whois_info"] if "whois_info" in keys else None,
        tenant_id=row["tenant_id"] if "tenant_id" in keys else "default-tenant",
        asset_id=row["asset_id"] if "asset_id" in keys else None
    )
    scan.findings = get_findings_for_scan(scan_id, tenant_id=tenant_id)
    return scan


@adapter_dispatch("list_scans")
def list_scans(limit: int = 100, offset: int = 0, filters: Optional[dict] = None) -> list:
    conn = _get_conn()
    query = "SELECT * FROM scans WHERE 1=1"
    params = []

    if filters:
        if filters.get("tenant_id"):
            query += " AND tenant_id = ?"
            params.append(filters["tenant_id"])
        if filters.get("asset_id"):
            query += " AND asset_id = ?"
            params.append(filters["asset_id"])
        if filters.get("target_url"):
            query += " AND target_url LIKE ?"
            params.append(f"%{filters['target_url']}%")
        if filters.get("status"):
            query += " AND status = ?"
            params.append(filters["status"])
        if filters.get("scan_mode"):
            query += " AND scan_mode = ?"
            params.append(filters["scan_mode"])
        if filters.get("grade"):
            query += " AND grade = ?"
            params.append(filters["grade"])
        if filters.get("is_wordpress") is not None and str(filters["is_wordpress"]).strip() != "":
            val = str(filters["is_wordpress"]).lower()
            if val in ("1", "true", "yes"):
                query += " AND (is_wordpress = 1 OR wordpress_detected = 1)"
            elif val in ("0", "false", "no"):
                query += " AND ((is_wordpress = 0 OR is_wordpress IS NULL) AND (wordpress_detected = 0 OR wordpress_detected IS NULL))"
        if filters.get("date_from"):
            query += " AND started_at >= ?"
            params.append(filters["date_from"])
        if filters.get("date_to"):
            query += " AND started_at <= ?"
            params.append(filters["date_to"] + "T23:59:59")

    query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    results = []
    for row in rows:
        keys = row.keys()
        wp_det = bool(row["wordpress_detected"]) if ("wordpress_detected" in keys and row["wordpress_detected"] is not None) else (bool(row["is_wordpress"]) if ("is_wordpress" in keys and row["is_wordpress"] is not None) else None)
        wp_v = row["wordpress_version"] if ("wordpress_version" in keys and row["wordpress_version"] is not None) else (row["wp_version"] if "wp_version" in keys else None)
        wp_src = row["wordpress_version_source"] if ("wordpress_version_source" in keys and row["wordpress_version_source"] is not None) else (row["wp_version_source"] if "wp_version_source" in keys else None)
        wp_conf = row["wordpress_version_confidence"] if ("wordpress_version_confidence" in keys and row["wordpress_version_confidence"] is not None) else (row["wp_version_confidence"] if "wp_version_confidence" in keys else None)
        s = ScanResult(
            id=row["id"], target_url=row["target_url"], status=ScanStatus(row["status"]),
            scan_mode=row["scan_mode"] if "scan_mode" in keys else "passive",
            started_at=row["started_at"], completed_at=row["completed_at"],
            score=row["score"], grade=row["grade"], notes=row["notes"], tags=row["tags"],
            initiated_by=row["initiated_by"],
            wordpress_detected=wp_det,
            wordpress_version=wp_v,
            wordpress_version_source=wp_src,
            wordpress_version_confidence=wp_conf,
            wp_version=wp_v,
            wp_version_source=wp_src,
            wp_version_confidence=wp_conf,
            is_wordpress=wp_det,
            whois_info=row["whois_info"] if "whois_info" in keys else None,
            tenant_id=row["tenant_id"] if "tenant_id" in keys else "default-tenant",
            asset_id=row["asset_id"] if "asset_id" in keys else None
        )
        results.append(s)
    return results


@adapter_dispatch("delete_scan")
def delete_scan(scan_id: str, tenant_id: Optional[str] = None):
    conn = _get_conn()
    if tenant_id:
        conn.execute("DELETE FROM scans WHERE id = ? AND tenant_id = ?", (scan_id, tenant_id))
    else:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()


@adapter_dispatch("update_scan")
def update_scan(scan_id: str, tenant_id: Optional[str] = None, **kwargs):
    conn = _get_conn()
    allowed = {
        "target_url", "status", "scan_mode", "completed_at", "score",
        "grade", "notes", "tags",
        "wordpress_detected", "wordpress_version", "wordpress_version_source", "wordpress_version_confidence",
        "wp_version", "wp_version_source", "wp_version_confidence", "is_wordpress",
        "asset_id", "tenant_id"
    }
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in allowed:
            if hasattr(v, "value"):
                v = v.value
            sets.append(f"{k} = ?")
            vals.append(v)
    if sets:
        vals.append(scan_id)
        where_clause = "WHERE id = ?"
        if tenant_id:
            where_clause += " AND tenant_id = ?"
            vals.append(tenant_id)
        conn.execute(f"UPDATE scans SET {', '.join(sets)} {where_clause}", vals)
        conn.commit()


# --- Findings ---
def _row_to_finding(row: sqlite3.Row) -> Finding:
    keys = row.keys()
    raw_data = json.loads(row["raw_data"]) if row["raw_data"] else {}
    tags = json.loads(row["finding_tags"]) if ("finding_tags" in keys and row["finding_tags"]) else []

    p_score = float(row["priority_score"]) if ("priority_score" in keys and row["priority_score"] is not None) else 0.0
    p_band = row["priority_band"] if ("priority_band" in keys and row["priority_band"]) else "P3"

    return Finding(
        id=row["id"],
        tenant_id=row["tenant_id"] if "tenant_id" in keys and row["tenant_id"] else "default-tenant",
        asset_id=row["asset_id"] if "asset_id" in keys else None,
        scan_id=row["scan_id"] if "scan_id" in keys and row["scan_id"] else "",
        category=row["category"] if "category" in keys else "",
        title=row["title"] if "title" in keys else "",
        description=row["description"] if "description" in keys else "",
        severity=Severity(row["severity"]) if "severity" in keys and row["severity"] else Severity.INFO,
        confidence=float(row["confidence"]) if "confidence" in keys and row["confidence"] is not None else 1.0,
        remediation=row["remediation"] if "remediation" in keys and row["remediation"] else "",
        reference=row["reference"] if "reference" in keys and row["reference"] else "",
        raw_data=raw_data,
        fingerprint=row["fingerprint"] if ("fingerprint" in keys and row["fingerprint"]) else "",
        status=row["status"] if ("status" in keys and row["status"]) else "OPEN",
        first_seen_at=row["first_seen_at"] if ("first_seen_at" in keys and row["first_seen_at"]) else (row["created_at"] if "created_at" in keys else datetime.now(timezone.utc).isoformat()),
        last_seen_at=row["last_seen_at"] if ("last_seen_at" in keys and row["last_seen_at"]) else (row["created_at"] if "created_at" in keys else datetime.now(timezone.utc).isoformat()),
        first_scan_id=row["first_scan_id"] if ("first_scan_id" in keys and row["first_scan_id"]) else (row["scan_id"] if "scan_id" in keys else ""),
        last_scan_id=row["last_scan_id"] if ("last_scan_id" in keys and row["last_scan_id"]) else (row["scan_id"] if "scan_id" in keys else ""),
        observation_count=int(row["observation_count"]) if ("observation_count" in keys and row["observation_count"] is not None) else 1,
        assigned_to_user_id=row["assigned_to_user_id"] if "assigned_to_user_id" in keys else None,
        assigned_team=row["assigned_team"] if "assigned_team" in keys else None,
        assigned_at=row["assigned_at"] if "assigned_at" in keys else None,
        finding_tags=tags,
        version=int(row["version"]) if ("version" in keys and row["version"] is not None) else 1,
        priority_score=p_score,
        priority_band=p_band,
        cvss_score=float(row["cvss_score"]) if ("cvss_score" in keys and row["cvss_score"] is not None) else None,
        epss_score=float(row["epss_score"]) if ("epss_score" in keys and row["epss_score"] is not None) else None,
        epss_percentile=float(row["epss_percentile"]) if ("epss_percentile" in keys and row["epss_percentile"] is not None) else None,
        epss_last_updated=row["epss_last_updated"] if "epss_last_updated" in keys else None,
        kev=bool(row["kev"]) if ("kev" in keys and row["kev"] is not None) else False,
        kev_date_added=row["kev_date_added"] if "kev_date_added" in keys else None,
        kev_due_date=row["kev_due_date"] if "kev_due_date" in keys else None,
        known_ransomware_campaign_use=bool(row["known_ransomware_campaign_use"]) if ("known_ransomware_campaign_use" in keys and row["known_ransomware_campaign_use"] is not None) else False,
        ransomware_relevance=row["ransomware_relevance"] if ("ransomware_relevance" in keys and row["ransomware_relevance"]) else "NONE",
        cve_id=row["cve_id"] if "cve_id" in keys else None,
        sla_policy_id=row["sla_policy_id"] if "sla_policy_id" in keys else None,
        sla_due_at=row["sla_due_at"] if "sla_due_at" in keys else None,
        sla_status=row["sla_status"] if ("sla_status" in keys and row["sla_status"]) else "NOT_APPLICABLE",
        sla_paused_at=row["sla_paused_at"] if "sla_paused_at" in keys else None,
        sla_pause_reason=row["sla_pause_reason"] if "sla_pause_reason" in keys else None,
        verified_at=row["verified_at"] if "verified_at" in keys else None,
        verified_by_scan_id=row["verified_by_scan_id"] if "verified_by_scan_id" in keys else None,
        false_positive_reason=row["false_positive_reason"] if "false_positive_reason" in keys else None,
        false_positive_by=row["false_positive_by"] if "false_positive_by" in keys else None,
        false_positive_at=row["false_positive_at"] if "false_positive_at" in keys else None,
        false_positive_valid_until=row["false_positive_valid_until"] if "false_positive_valid_until" in keys else None,
        finding_confidence=row["finding_confidence"] if "finding_confidence" in keys and row["finding_confidence"] else "HIGH",
        policy_version_id=row["policy_version_id"] if "policy_version_id" in keys else None,
        created_at=row["created_at"] if "created_at" in keys else datetime.now(timezone.utc).isoformat(),
        updated_at=row["updated_at"] if "updated_at" in keys else None,
    )


@adapter_dispatch("save_finding")
def save_finding(finding: Finding, expected_version: Optional[int] = None) -> Finding:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if not finding.updated_at:
        finding.updated_at = now_iso
    existing = conn.execute("SELECT version FROM findings WHERE id = ?", (finding.id,)).fetchone()
    if existing:
        current_version = existing["version"] or 1
        target_version = expected_version if expected_version is not None else current_version
        finding.version = current_version + 1
        cursor = conn.execute("""
            UPDATE findings SET
                tenant_id = ?, asset_id = ?, scan_id = ?, category = ?, title = ?,
                description = ?, severity = ?, confidence = ?, remediation = ?, reference = ?,
                raw_data = ?, fingerprint = ?, status = ?, first_seen_at = ?, last_seen_at = ?,
                first_scan_id = ?, last_scan_id = ?, observation_count = ?, assigned_to_user_id = ?,
                assigned_team = ?, assigned_at = ?, finding_tags = ?, version = ?,
                priority_score = ?, priority_band = ?, cvss_score = ?, epss_score = ?,
                epss_percentile = ?, epss_last_updated = ?, kev = ?, kev_date_added = ?,
                kev_due_date = ?, known_ransomware_campaign_use = ?, ransomware_relevance = ?,
                cve_id = ?, sla_policy_id = ?, sla_due_at = ?, sla_status = ?,
                sla_paused_at = ?, sla_pause_reason = ?, verified_at = ?, verified_by_scan_id = ?,
                false_positive_reason = ?, false_positive_by = ?, false_positive_at = ?,
                false_positive_valid_until = ?, finding_confidence = ?, policy_version_id = ?, updated_at = ?
            WHERE id = ? AND version = ?
        """, (
            finding.tenant_id or "default-tenant", finding.asset_id, finding.scan_id, finding.category, finding.title,
            finding.description, finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity),
            finding.confidence, finding.remediation, finding.reference, json.dumps(finding.raw_data),
            finding.fingerprint, finding.status, finding.first_seen_at, finding.last_seen_at,
            finding.first_scan_id, finding.last_scan_id, finding.observation_count, finding.assigned_to_user_id,
            finding.assigned_team, finding.assigned_at, json.dumps(finding.finding_tags), finding.version,
            finding.priority_score, finding.priority_band, finding.cvss_score, finding.epss_score,
            finding.epss_percentile, finding.epss_last_updated, 1 if finding.kev else 0, finding.kev_date_added,
            finding.kev_due_date, 1 if finding.known_ransomware_campaign_use else 0, finding.ransomware_relevance,
            finding.cve_id, finding.sla_policy_id, finding.sla_due_at, finding.sla_status,
            finding.sla_paused_at, finding.sla_pause_reason, finding.verified_at, finding.verified_by_scan_id,
            finding.false_positive_reason, finding.false_positive_by, finding.false_positive_at,
            finding.false_positive_valid_until, getattr(finding, "finding_confidence", "HIGH"),
            getattr(finding, "policy_version_id", None), finding.updated_at, finding.id, target_version
        ))
        if cursor.rowcount == 0:
            raise OptimisticLockError(finding.id, target_version)
    else:
        conn.execute("""
            INSERT INTO findings (
                id, tenant_id, asset_id, scan_id, category, title,
                description, severity, confidence, remediation, reference,
                raw_data, fingerprint, status, first_seen_at, last_seen_at,
                first_scan_id, last_scan_id, observation_count, assigned_to_user_id,
                assigned_team, assigned_at, finding_tags, version,
                priority_score, priority_band, cvss_score, epss_score,
                epss_percentile, epss_last_updated, kev, kev_date_added,
                kev_due_date, known_ransomware_campaign_use, ransomware_relevance,
                cve_id, sla_policy_id, sla_due_at, sla_status,
                sla_paused_at, sla_pause_reason, verified_at, verified_by_scan_id,
                false_positive_reason, false_positive_by, false_positive_at,
                false_positive_valid_until, finding_confidence, policy_version_id, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            finding.id, finding.tenant_id or "default-tenant", finding.asset_id, finding.scan_id, finding.category, finding.title,
            finding.description, finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity),
            finding.confidence, finding.remediation, finding.reference, json.dumps(finding.raw_data),
            finding.fingerprint, finding.status, finding.first_seen_at, finding.last_seen_at,
            finding.first_scan_id, finding.last_scan_id, finding.observation_count, finding.assigned_to_user_id,
            finding.assigned_team, finding.assigned_at, json.dumps(finding.finding_tags), finding.version,
            finding.priority_score, finding.priority_band, finding.cvss_score, finding.epss_score,
            finding.epss_percentile, finding.epss_last_updated, 1 if finding.kev else 0, finding.kev_date_added,
            finding.kev_due_date, 1 if finding.known_ransomware_campaign_use else 0, finding.ransomware_relevance,
            finding.cve_id, finding.sla_policy_id, finding.sla_due_at, finding.sla_status,
            finding.sla_paused_at, finding.sla_pause_reason, finding.verified_at, finding.verified_by_scan_id,
            finding.false_positive_reason, finding.false_positive_by, finding.false_positive_at,
            finding.false_positive_valid_until, getattr(finding, "finding_confidence", "HIGH"),
            getattr(finding, "policy_version_id", None), finding.created_at, finding.updated_at
        ))
    conn.commit()
    return finding


@adapter_dispatch("save_findings_bulk")
def save_findings_bulk(findings: list):
    for f in findings:
        save_finding(f)


save_findings = save_findings_bulk


@adapter_dispatch("get_finding")
def get_finding(finding_id: str, tenant_id: Optional[str] = None) -> Optional[Finding]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM findings WHERE id = ? AND tenant_id = ?", (finding_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        return None
    return _row_to_finding(row)


@adapter_dispatch("get_finding_by_fingerprint")
def get_finding_by_fingerprint(tenant_id: str, fingerprint: str) -> Optional[Finding]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM findings WHERE tenant_id = ? AND fingerprint = ?", (tenant_id, fingerprint)).fetchone()
    if not row:
        return None
    return _row_to_finding(row)


@adapter_dispatch("get_findings_for_scan")
def get_findings_for_scan(scan_id: str, tenant_id: Optional[str] = None) -> list[Finding]:
    conn = _get_conn()
    query = """
        SELECT * FROM findings
        WHERE (scan_id = ? OR id IN (SELECT finding_id FROM finding_observations WHERE scan_id = ?))
    """
    params = [scan_id, scan_id]
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    query += " ORDER BY priority_score DESC, severity, created_at"
    rows = conn.execute(query, params).fetchall()
    return [_row_to_finding(r) for r in rows]


@adapter_dispatch("get_findings_for_asset")
def get_findings_for_asset(asset_id: str, tenant_id: Optional[str] = None) -> list[Finding]:
    conn = _get_conn()
    query = "SELECT * FROM findings WHERE asset_id = ?"
    params = [asset_id]
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    query += " ORDER BY priority_score DESC, severity, created_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [_row_to_finding(r) for r in rows]


@adapter_dispatch("list_findings")
def list_findings(
    tenant_id: str,
    filters: Optional[dict] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[Finding], int]:
    conn = _get_conn()
    filters = filters or {}
    where = ["tenant_id = ?"]
    params = [tenant_id]

    if filters.get("status"):
        where.append("status = ?")
        params.append(filters["status"].upper())
    if filters.get("severity"):
        where.append("severity = ?")
        params.append(filters["severity"].lower())
    if filters.get("priority_band"):
        where.append("priority_band = ?")
        params.append(filters["priority_band"].upper())
    if filters.get("sla_status"):
        where.append("sla_status = ?")
        params.append(filters["sla_status"].upper())
    if filters.get("asset_id"):
        where.append("asset_id = ?")
        params.append(filters["asset_id"])
    if filters.get("kev") is not None:
        where.append("kev = ?")
        params.append(1 if filters["kev"] else 0)
    if filters.get("search"):
        where.append("(title LIKE ? OR cve_id LIKE ? OR description LIKE ?)")
        s = f"%{filters['search']}%"
        params.extend([s, s, s])

    where_sql = " WHERE " + " AND ".join(where)
    count_row = conn.execute(f"SELECT COUNT(*) FROM findings{where_sql}", params).fetchone()
    total_count = count_row[0] if count_row else 0

    offset = max(0, (page - 1) * page_size)
    query_sql = f"SELECT * FROM findings{where_sql} ORDER BY priority_score DESC, created_at DESC LIMIT ? OFFSET ?"
    params.extend([page_size, offset])
    rows = conn.execute(query_sql, params).fetchall()
    return [_row_to_finding(r) for r in rows], total_count


@adapter_dispatch("delete_finding")
def delete_finding(finding_id: str, tenant_id: Optional[str] = None):
    conn = _get_conn()
    if tenant_id:
        conn.execute("DELETE FROM findings WHERE id = ? AND tenant_id = ?", (finding_id, tenant_id))
    else:
        conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
    conn.commit()


@adapter_dispatch("update_finding")
def update_finding(finding_id: str, tenant_id: Optional[str] = None, **kwargs):
    conn = _get_conn()
    allowed = {
        "category", "title", "description", "severity", "confidence", "remediation", "reference",
        "asset_id", "tenant_id", "status", "assigned_to_user_id", "assigned_team", "assigned_at",
        "priority_score", "priority_band", "cvss_score", "epss_score", "epss_percentile",
        "kev", "sla_due_at", "sla_status", "sla_paused_at", "sla_pause_reason", "verified_at",
        "verified_by_scan_id", "false_positive_reason", "false_positive_by", "false_positive_at",
        "false_positive_valid_until", "updated_at"
    }
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in allowed:
            if hasattr(v, "value"):
                v = v.value
            sets.append(f"{k} = ?")
            vals.append(v)
    if sets:
        sets.append("version = version + 1")
        sets.append("updated_at = ?")
        vals.append(datetime.now(timezone.utc).isoformat())
        vals.append(finding_id)
        where_clause = "WHERE id = ?"
        if tenant_id:
            where_clause += " AND tenant_id = ?"
            vals.append(tenant_id)
        conn.execute(f"UPDATE findings SET {', '.join(sets)} {where_clause}", vals)
        conn.commit()


@adapter_dispatch("transition_finding_status")
def transition_finding_status(
    finding_id: str,
    new_status: str,
    actor_user_id: str,
    tenant_id: Optional[str] = None,
    comment: str = "",
    metadata: Optional[dict] = None,
    expected_version: Optional[int] = None,
) -> Finding:
    """
    Validates state machine transition, checks optimistic lock, updates finding,
    and logs immutable history + audit trail.
    Raises InvalidStateTransitionError if transition is illegal.
    Raises OptimisticLockError on version mismatch.
    """
    finding = get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        raise ValueError(f"Finding {finding_id} not found")

    if expected_version is not None and finding.version != expected_version:
        raise OptimisticLockError(finding.id, expected_version)

    old_status = finding.status
    target_status = new_status.upper().strip()

    validate_transition(old_status, target_status)

    now_iso = datetime.now(timezone.utc).isoformat()
    finding.status = target_status
    finding.updated_at = now_iso

    if target_status == FindingStatus.RISK_ACCEPTED.value:
        finding.sla_status = SLAStatus.PAUSED.value
        finding.sla_paused_at = now_iso
        finding.sla_pause_reason = comment or "Risk acceptance approved"
    elif target_status in (FindingStatus.REMEDIATED.value, FindingStatus.VERIFIED.value, FindingStatus.CLOSED.value, FindingStatus.FALSE_POSITIVE.value):
        if finding.sla_status != SLAStatus.BREACHED.value:
            finding.sla_status = SLAStatus.COMPLIED.value
    elif old_status == FindingStatus.RISK_ACCEPTED.value and target_status in (FindingStatus.OPEN.value, FindingStatus.REOPENED.value, FindingStatus.IN_PROGRESS.value):
        finding.sla_paused_at = None
        finding.sla_pause_reason = None
        from core.sla import evaluate_finding_sla_status
        finding.sla_status = evaluate_finding_sla_status(finding)

    save_finding(finding, expected_version=expected_version)

    hist = FindingHistory(
        tenant_id=finding.tenant_id,
        finding_id=finding.id,
        actor_user_id=actor_user_id,
        action="status_transition",
        old_status=old_status,
        new_status=target_status,
        comment=comment,
        metadata=metadata or {},
        created_at=now_iso,
    )
    add_finding_history(hist)

    if comment:
        add_finding_comment(FindingComment(
            tenant_id=finding.tenant_id,
            finding_id=finding.id,
            author_user_id=actor_user_id,
            body=f"Status changed to {target_status}: {comment}",
            created_at=now_iso,
        ))

    log_audit_event(
        tenant_id=finding.tenant_id,
        actor_user_id=actor_user_id,
        action="finding_status_transition",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"old_status": old_status, "new_status": target_status, "comment": comment}
    )

    return finding


@adapter_dispatch("process_scan_findings")
def process_scan_findings(scan_id: str, tenant_id: str, asset_id: Optional[str], raw_findings: list[Finding]) -> list[Finding]:
    """
    Deduplicates findings using compute_finding_fingerprint.
    - If finding exists:
        * records observation in finding_observations
        * updates last_seen_at, last_scan_id, observation_count
        * if status was VERIFIED, CLOSED, or REMEDIATED, reopens: status=REOPENED, adds FindingHistory and audit log
    - If new:
        * assigns fingerprint
        * prioritizes (priority_score, priority_band)
        * assigns SLA due date based on policy / band
        * records observation in finding_observations
        * adds FindingHistory
    Returns list of processed Finding objects.
    """
    from core.prioritization import calculate_priority_score
    from core.sla import calculate_sla_due_date, match_sla_policy

    now_iso = datetime.now(timezone.utc).isoformat()
    processed = []

    policies = list_sla_policies(tenant_id)
    asset = get_asset(asset_id, tenant_id=tenant_id) if asset_id else None
    crit = getattr(asset, "criticality", "medium") if asset else "medium"
    if asset:
        exposure = getattr(asset, "internet_exposure", None)
        if exposure:
            internet_facing = (exposure == "external")
        else:
            internet_facing = bool(getattr(asset, "internet_facing", True))
    else:
        internet_facing = True

    for rf in raw_findings:
        rf.tenant_id = tenant_id
        rf.asset_id = asset_id
        rf.scan_id = scan_id

        scanner_id = rf.raw_data.get("scanner") or rf.category or "general"
        finding_type = rf.raw_data.get("finding_type") or rf.category or rf.title
        location = rf.raw_data.get("location") or rf.raw_data.get("path") or rf.reference or ""
        identifier = rf.cve_id or rf.raw_data.get("cve_id") or rf.raw_data.get("vulnerability_id") or rf.title

        fp = compute_finding_fingerprint(tenant_id, asset_id, scanner_id, finding_type, location, identifier)
        rf.fingerprint = fp

        existing = get_finding_by_fingerprint(tenant_id, fp)
        if existing:
            old_status = existing.status
            should_reopen = old_status in (FindingStatus.VERIFIED.value, FindingStatus.CLOSED.value, FindingStatus.REMEDIATED.value, FindingStatus.VERIFICATION_PENDING.value)

            existing.last_seen_at = now_iso
            existing.last_scan_id = scan_id
            existing.observation_count += 1
            existing.scan_id = scan_id

            if should_reopen:
                existing.status = FindingStatus.REOPENED.value
                existing.verified_at = None
                existing.verified_by_scan_id = None
                hist = FindingHistory(
                    tenant_id=tenant_id,
                    finding_id=existing.id,
                    actor_user_id="system:scanner",
                    action="finding_reopened",
                    old_status=old_status,
                    new_status=FindingStatus.REOPENED.value,
                    comment=f"Vulnerability reappeared in scan {scan_id} after remediation/verification.",
                    created_at=now_iso,
                )
                add_finding_history(hist)
                log_audit_event(
                    tenant_id=tenant_id,
                    actor_user_id="system:scanner",
                    action="finding_reopened",
                    resource_type="finding",
                    resource_id=existing.id,
                    metadata={"scan_id": scan_id, "previous_status": old_status}
                )

            save_finding(existing)

            obs = FindingObservation(
                tenant_id=tenant_id,
                finding_id=existing.id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner_id=scanner_id,
                observed_at=now_iso,
                severity=existing.severity.value if hasattr(existing.severity, "value") else str(existing.severity),
                evidence_reference=rf.reference,
                status=existing.status,
                raw_reference=rf.reference,
            )
            save_finding_observation(obs)
            processed.append(existing)
        else:
            rf.first_seen_at = now_iso
            rf.last_seen_at = now_iso
            rf.first_scan_id = scan_id
            rf.last_scan_id = scan_id
            rf.observation_count = 1
            rf.status = FindingStatus.OPEN.value

            score, band = calculate_priority_score(
                severity=rf.severity,
                cvss_score=rf.cvss_score,
                epss_score=rf.epss_score,
                kev=rf.kev,
                asset_criticality=crit,
                asset_internet_facing=internet_facing,
                ransomware_relevance=rf.ransomware_relevance or rf.known_ransomware_campaign_use,
            )
            rf.priority_score = score
            rf.priority_band = band

            matched_pol = match_sla_policy(rf, policies, asset_criticality=crit, asset_internet_facing=internet_facing)
            due_at, pol_id = calculate_sla_due_date(now_iso, priority_band=band, policy=matched_pol)
            rf.sla_due_at = due_at
            rf.sla_policy_id = pol_id
            rf.sla_status = SLAStatus.ON_TRACK.value

            save_finding(rf)

            obs = FindingObservation(
                tenant_id=tenant_id,
                finding_id=rf.id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner_id=scanner_id,
                observed_at=now_iso,
                severity=rf.severity.value if hasattr(rf.severity, "value") else str(rf.severity),
                evidence_reference=rf.reference,
                status=rf.status,
                raw_reference=rf.reference,
            )
            save_finding_observation(obs)

            # Record immutable evidence in EvidenceStore
            try:
                from core.evidence.store import EvidenceStore
                store = EvidenceStore(tenant_id)
                evidence_payload = json.dumps({
                    "title": rf.title,
                    "category": rf.category,
                    "description": rf.description,
                    "severity": rf.severity.value if hasattr(rf.severity, "value") else str(rf.severity),
                    "reference": rf.reference,
                    "raw_data": rf.raw_data
                }, sort_keys=True)
                store.record_evidence(
                    raw_payload=evidence_payload,
                    source=scanner_id,
                    type_="scanner_observation",
                    finding_id=rf.id,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scanner_id=scanner_id,
                    source_url=location
                )
            except Exception as e:
                logger.warning(f"Could not store evidence for finding {rf.id}: {e}")

            # Stage SIEM outbox event if high priority / KEV
            if rf.priority_band in ("P1", "P2") or rf.kev:
                try:
                    from core.integrations.siem import SIEMExporter
                    exporter = SIEMExporter(tenant_id)
                    exporter.stage_event(
                        event_type="critical_finding" if rf.priority_band == "P1" else "p2_finding",
                        entity_id=rf.id,
                        payload={
                            "finding_id": rf.id,
                            "title": rf.title,
                            "severity": rf.severity.value if hasattr(rf.severity, "value") else str(rf.severity),
                            "priority_band": rf.priority_band,
                            "asset_id": asset_id,
                            "scan_id": scan_id,
                            "kev": rf.kev
                        },
                        destination="siem"
                    )
                except Exception as e:
                    logger.warning(f"Could not stage outbox event for finding {rf.id}: {e}")

            hist = FindingHistory(
                tenant_id=tenant_id,
                finding_id=rf.id,
                actor_user_id="system:scanner",
                action="finding_created",
                old_status=None,
                new_status=FindingStatus.OPEN.value,
                comment=f"Discovered in scan {scan_id}.",
                created_at=now_iso,
            )
            add_finding_history(hist)
            processed.append(rf)

    # Resolve any findings on this asset in VERIFICATION_PENDING that are no longer detected
    if asset_id:
        pending_verification = [f for f in get_findings_for_asset(asset_id, tenant_id=tenant_id) if f.status == FindingStatus.VERIFICATION_PENDING.value]
        processed_fingerprints = {f.fingerprint for f in processed}
        for pv in pending_verification:
            if pv.fingerprint not in processed_fingerprints:
                pv.status = FindingStatus.VERIFIED.value
                pv.verified_at = now_iso
                pv.verified_by_scan_id = scan_id
                save_finding(pv)
                add_finding_history(FindingHistory(
                    tenant_id=tenant_id,
                    finding_id=pv.id,
                    actor_user_id="system:scanner",
                    action="finding_verified",
                    old_status=FindingStatus.VERIFICATION_PENDING.value,
                    new_status=FindingStatus.VERIFIED.value,
                    comment=f"Finding verified remediated; not detected in scan {scan_id}.",
                    created_at=now_iso,
                ))
                log_audit_event(
                    tenant_id=tenant_id,
                    actor_user_id="system:scanner",
                    action="finding_verified",
                    resource_type="finding",
                    resource_id=pv.id,
                    metadata={"scan_id": scan_id}
                )

    return processed


# --- Scheduled Scans ---
def _row_to_scheduled_scan(row) -> ScheduledScan:
    """Converts a DB row to ScheduledScan, handling Sprint 3 columns safely."""
    keys = row.keys()
    return ScheduledScan(
        id=row["id"], target_url=row["target_url"], scan_mode=row["scan_mode"],
        interval_hours=row["interval_hours"], last_run_at=row["last_run_at"],
        next_run_at=row["next_run_at"], enabled=bool(row["enabled"]),
        created_by=row["created_by"], created_at=row["created_at"],
        tenant_id=row["tenant_id"] if "tenant_id" in keys else "default-tenant",
        asset_id=row["asset_id"] if "asset_id" in keys else None,
        max_retries=int(row["max_retries"]) if "max_retries" in keys and row["max_retries"] is not None else 3,
        consecutive_failures=int(row["consecutive_failures"]) if "consecutive_failures" in keys and row["consecutive_failures"] is not None else 0,
        last_failure_at=row["last_failure_at"] if "last_failure_at" in keys else None,
        last_success_at=row["last_success_at"] if "last_success_at" in keys else None,
        paused_until=row["paused_until"] if "paused_until" in keys else None,
    )


@adapter_dispatch("save_scheduled_scan")
def save_scheduled_scan(sched: ScheduledScan):
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO scheduled_scans (
            id, target_url, scan_mode, interval_hours, last_run_at,
            next_run_at, enabled, created_by, created_at, tenant_id, asset_id,
            max_retries, consecutive_failures, last_failure_at, last_success_at, paused_until
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (sched.id, sched.target_url, sched.scan_mode, sched.interval_hours,
         sched.last_run_at, sched.next_run_at, 1 if sched.enabled else 0,
         sched.created_by, sched.created_at, sched.tenant_id or "default-tenant", sched.asset_id,
         getattr(sched, "max_retries", 3),
         getattr(sched, "consecutive_failures", 0),
         getattr(sched, "last_failure_at", None),
         getattr(sched, "last_success_at", None),
         getattr(sched, "paused_until", None))
    )
    _safe_commit(conn)


@adapter_dispatch("update_scheduled_scan")
def update_scheduled_scan(sched: ScheduledScan):
    return save_scheduled_scan(sched)


@adapter_dispatch("get_scheduled_scan")
def get_scheduled_scan(sched_id: str, tenant_id: Optional[str] = None) -> Optional[ScheduledScan]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM scheduled_scans WHERE id = ? AND tenant_id = ?", (sched_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM scheduled_scans WHERE id = ?", (sched_id,)).fetchone()
    if not row:
        return None
    return _row_to_scheduled_scan(row)


@adapter_dispatch("list_scheduled_scans")
def list_scheduled_scans(tenant_id: Optional[str] = None) -> list:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM scheduled_scans WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM scheduled_scans ORDER BY created_at DESC").fetchall()
    return [_row_to_scheduled_scan(r) for r in rows]


@adapter_dispatch("delete_scheduled_scan")
def delete_scheduled_scan(sched_id: str, tenant_id: Optional[str] = None):
    conn = _get_conn()
    if tenant_id:
        conn.execute("DELETE FROM scheduled_scans WHERE id = ? AND tenant_id = ?", (sched_id, tenant_id))
    else:
        conn.execute("DELETE FROM scheduled_scans WHERE id = ?", (sched_id,))
    conn.commit()


@adapter_dispatch("list_due_schedules")
def list_due_schedules(as_of: Optional[str] = None) -> list:
    conn = _get_conn()
    now_iso = as_of or datetime.now(timezone.utc).isoformat()
    rows = conn.execute(
        """SELECT * FROM scheduled_scans 
        WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?
        AND (paused_until IS NULL OR paused_until <= ?)
        ORDER BY next_run_at ASC""",
        (now_iso, now_iso)
    ).fetchall()
    return [_row_to_scheduled_scan(r) for r in rows]


@adapter_dispatch("purge_all_scans_and_findings")
def purge_all_scans_and_findings(tenant_id: Optional[str] = None) -> tuple[int, int]:
    """
    Permanently purges scan records and findings from database (tenant-aware).
    Returns (scans_count, findings_count) deleted.
    """
    conn = _get_conn()
    if tenant_id:
        scans_count = conn.execute("SELECT COUNT(*) FROM scans WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        findings_count = conn.execute("SELECT COUNT(*) FROM findings WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        conn.execute("DELETE FROM findings WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM scans WHERE tenant_id = ?", (tenant_id,))
    else:
        scans_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        findings_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM scans")
    conn.commit()
    return scans_count, findings_count


# =====================================================================
# Phase 3: ScanJob Lifecycle & Persistence
# =====================================================================

@adapter_dispatch("create_scan_job")
def create_scan_job(job: ScanJob) -> ScanJob:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO scan_jobs (
            id, tenant_id, asset_id, scan_id, task_id, status, requested_by, profile,
            queued_at, started_at, completed_at, failed_at, cancelled_at,
            progress_percent, current_step, attempt, max_attempts,
            error_code, error_message, worker_id, heartbeat_at, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        job.id, job.tenant_id, job.asset_id, job.scan_id, job.task_id, job.status,
        job.requested_by, job.profile, job.queued_at, job.started_at, job.completed_at,
        job.failed_at, job.cancelled_at, job.progress_percent, job.current_step,
        job.attempt, job.max_attempts, job.error_code, job.error_message,
        job.worker_id, job.heartbeat_at, job.created_at, job.updated_at
    ))
    conn.commit()
    return job


@adapter_dispatch("update_scan_job")
def update_scan_job(job: ScanJob) -> bool:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    job.updated_at = now_iso
    conn.execute("""
        UPDATE scan_jobs SET
            tenant_id = ?, asset_id = ?, scan_id = ?, task_id = ?, status = ?,
            requested_by = ?, profile = ?, queued_at = ?, started_at = ?, completed_at = ?,
            failed_at = ?, cancelled_at = ?, progress_percent = ?, current_step = ?,
            attempt = ?, max_attempts = ?, error_code = ?, error_message = ?,
            worker_id = ?, heartbeat_at = ?, updated_at = ?
        WHERE id = ?
    """, (
        job.tenant_id, job.asset_id, job.scan_id, job.task_id, job.status,
        job.requested_by, job.profile, job.queued_at, job.started_at, job.completed_at,
        job.failed_at, job.cancelled_at, job.progress_percent, job.current_step,
        job.attempt, job.max_attempts, job.error_code, job.error_message,
        job.worker_id, job.heartbeat_at, job.updated_at, job.id
    ))
    conn.commit()
    return True


@adapter_dispatch("get_scan_job")
def get_scan_job(job_id: str, tenant_id: Optional[str] = None) -> Optional[ScanJob]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM scan_jobs WHERE id = ? AND tenant_id = ?", (job_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return None
    return ScanJob(
        id=row["id"],
        tenant_id=row["tenant_id"],
        asset_id=row["asset_id"],
        scan_id=row["scan_id"],
        task_id=row["task_id"],
        status=row["status"],
        requested_by=row["requested_by"],
        profile=row["profile"],
        queued_at=row["queued_at"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        failed_at=row["failed_at"],
        cancelled_at=row["cancelled_at"],
        progress_percent=row["progress_percent"] or 0,
        current_step=row["current_step"] or "Initialized",
        attempt=row["attempt"] or 1,
        max_attempts=row["max_attempts"] or 3,
        error_code=row["error_code"],
        error_message=row["error_message"],
        worker_id=row["worker_id"],
        heartbeat_at=row["heartbeat_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@adapter_dispatch("get_scan_job_by_scan_id")
def get_scan_job_by_scan_id(scan_id: str, tenant_id: Optional[str] = None) -> Optional[ScanJob]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute(
            "SELECT * FROM scan_jobs WHERE scan_id = ? AND tenant_id = ? ORDER BY created_at DESC LIMIT 1",
            (scan_id, tenant_id)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM scan_jobs WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1",
            (scan_id,)
        ).fetchone()
    if not row:
        return None
    return ScanJob(
        id=row["id"],
        tenant_id=row["tenant_id"],
        asset_id=row["asset_id"],
        scan_id=row["scan_id"],
        task_id=row["task_id"],
        status=row["status"],
        requested_by=row["requested_by"],
        profile=row["profile"],
        queued_at=row["queued_at"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        failed_at=row["failed_at"],
        cancelled_at=row["cancelled_at"],
        progress_percent=row["progress_percent"] or 0,
        current_step=row["current_step"] or "Initialized",
        attempt=row["attempt"] or 1,
        max_attempts=row["max_attempts"] or 3,
        error_code=row["error_code"],
        error_message=row["error_message"],
        worker_id=row["worker_id"],
        heartbeat_at=row["heartbeat_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@adapter_dispatch("update_scan_job_progress")
def update_scan_job_progress(
    job_id: str,
    progress_percent: int,
    current_step: str,
    worker_id: Optional[str] = None
) -> bool:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    pct = max(0, min(100, progress_percent))
    if worker_id:
        conn.execute(
            "UPDATE scan_jobs SET progress_percent = ?, current_step = ?, worker_id = ?, heartbeat_at = ?, updated_at = ? WHERE id = ?",
            (pct, current_step, worker_id, now_iso, now_iso, job_id)
        )
    else:
        conn.execute(
            "UPDATE scan_jobs SET progress_percent = ?, current_step = ?, heartbeat_at = ?, updated_at = ? WHERE id = ?",
            (pct, current_step, now_iso, now_iso, job_id)
        )
    _safe_commit(conn)
    return True


@adapter_dispatch("record_scan_job_heartbeat")
def record_scan_job_heartbeat(job_id: str, worker_id: Optional[str] = None) -> bool:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if worker_id:
        conn.execute(
            "UPDATE scan_jobs SET heartbeat_at = ?, worker_id = ?, updated_at = ? WHERE id = ?",
            (now_iso, worker_id, now_iso, job_id)
        )
    else:
        conn.execute(
            "UPDATE scan_jobs SET heartbeat_at = ?, updated_at = ? WHERE id = ?",
            (now_iso, now_iso, job_id)
        )
    _safe_commit(conn)
    return True


_TERMINAL_SCAN_JOB_STATUSES = frozenset({"completed", "cancelled", "failed", "timed_out"})


@adapter_dispatch("try_claim_scan_job_for_execution")
def try_claim_scan_job_for_execution(job_id: str, worker_id: str) -> Optional[ScanJob]:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """
        UPDATE scan_jobs SET
            status = 'running',
            worker_id = ?,
            heartbeat_at = ?,
            updated_at = ?,
            started_at = CASE WHEN started_at IS NULL OR started_at = '' THEN ? ELSE started_at END
        WHERE id = ? AND status IN ('queued', 'retrying')
        """,
        (worker_id, now_iso, now_iso, now_iso, job_id),
    )
    if cur.rowcount == 0:
        return None
    _safe_commit(conn)
    return get_scan_job(job_id)


@adapter_dispatch("try_reclaim_stale_scan_job_for_retry")
def try_reclaim_stale_scan_job_for_retry(job_id: str, stale_threshold_seconds: int = 600) -> Optional[ScanJob]:
    conn = _get_conn()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_threshold_seconds)).isoformat()
    now_iso = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """
        UPDATE scan_jobs SET
            status = 'retrying',
            attempt = attempt + 1,
            error_code = 'STALE_HEARTBEAT_RETRY',
            error_message = 'Worker heartbeat timed out; job requeued for retry',
            updated_at = ?
        WHERE id = ?
          AND status = 'running'
          AND (
            (heartbeat_at IS NOT NULL AND heartbeat_at < ?)
            OR (heartbeat_at IS NULL AND started_at IS NOT NULL AND started_at < ?)
          )
        """,
        (now_iso, job_id, cutoff, cutoff),
    )
    if cur.rowcount == 0:
        return None
    _safe_commit(conn)
    return get_scan_job(job_id)


@adapter_dispatch("mark_scan_job_status")
def mark_scan_job_status(
    job_id: str,
    status: str,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    worker_id: Optional[str] = None,
) -> bool:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    job = get_scan_job(job_id)
    if not job:
        return False

    if job.status in _TERMINAL_SCAN_JOB_STATUSES:
        return job.status == status
    
    started_at = job.started_at
    completed_at = job.completed_at
    failed_at = job.failed_at
    cancelled_at = job.cancelled_at
    pct = job.progress_percent
    step = job.current_step

    if status == "running" and not started_at:
        started_at = now_iso
    elif status == "completed":
        completed_at = now_iso
        pct = 100
        step = "Completed"
    elif status in ("failed", "timed_out"):
        failed_at = now_iso
    elif status == "cancelled":
        cancelled_at = now_iso

    if worker_id:
        conn.execute("""
            UPDATE scan_jobs SET
                status = ?, started_at = ?, completed_at = ?, failed_at = ?, cancelled_at = ?,
                progress_percent = ?, current_step = ?, error_code = ?, error_message = ?,
                worker_id = ?, updated_at = ?
            WHERE id = ?
        """, (status, started_at, completed_at, failed_at, cancelled_at, pct, step, error_code, error_message, worker_id, now_iso, job_id))
    else:
        conn.execute("""
            UPDATE scan_jobs SET
                status = ?, started_at = ?, completed_at = ?, failed_at = ?, cancelled_at = ?,
                progress_percent = ?, current_step = ?, error_code = ?, error_message = ?,
                updated_at = ?
            WHERE id = ?
        """, (status, started_at, completed_at, failed_at, cancelled_at, pct, step, error_code, error_message, now_iso, job_id))
    _safe_commit(conn)
    return True


@adapter_dispatch("count_active_scan_jobs_for_tenant")
def count_active_scan_jobs_for_tenant(tenant_id: str) -> int:
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) FROM scan_jobs WHERE tenant_id = ? AND status IN ('queued', 'running', 'retrying')",
        (tenant_id,)
    ).fetchone()
    return row[0] if row else 0


@adapter_dispatch("count_active_scan_jobs_global")
def count_active_scan_jobs_global() -> int:
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('queued', 'running', 'retrying')"
    ).fetchone()
    return row[0] if row else 0


@adapter_dispatch("count_active_scan_jobs_for_asset")
def count_active_scan_jobs_for_asset(asset_id: str) -> int:
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) FROM scan_jobs WHERE asset_id = ? AND status IN ('queued', 'running', 'retrying')",
        (asset_id,)
    ).fetchone()
    return row[0] if row else 0


@adapter_dispatch("find_stale_scan_jobs")
def find_stale_scan_jobs(stale_threshold_seconds: int = 600) -> list[ScanJob]:
    from datetime import timedelta
    conn = _get_conn()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_threshold_seconds)).isoformat()
    rows = conn.execute("""
        SELECT * FROM scan_jobs
        WHERE status = 'running'
          AND (
              (heartbeat_at IS NOT NULL AND heartbeat_at < ?)
              OR (heartbeat_at IS NULL AND started_at IS NOT NULL AND started_at < ?)
          )
    """, (cutoff, cutoff)).fetchall()
    return [
        ScanJob(
            id=r["id"], tenant_id=r["tenant_id"], asset_id=r["asset_id"], scan_id=r["scan_id"],
            task_id=r["task_id"], status=r["status"], requested_by=r["requested_by"],
            profile=r["profile"], queued_at=r["queued_at"], started_at=r["started_at"],
            completed_at=r["completed_at"], failed_at=r["failed_at"], cancelled_at=r["cancelled_at"],
            progress_percent=r["progress_percent"] or 0, current_step=r["current_step"] or "Initialized",
            attempt=r["attempt"] or 1, max_attempts=r["max_attempts"] or 3,
            error_code=r["error_code"], error_message=r["error_message"], worker_id=r["worker_id"],
            heartbeat_at=r["heartbeat_at"], created_at=r["created_at"], updated_at=r["updated_at"]
        ) for r in rows
    ]


@adapter_dispatch("list_scan_jobs")
def list_scan_jobs(
    tenant_id: str,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> list[ScanJob]:
    conn = _get_conn()
    if status:
        rows = conn.execute(
            "SELECT * FROM scan_jobs WHERE tenant_id = ? AND status = ? ORDER BY queued_at DESC LIMIT ? OFFSET ?",
            (tenant_id, status, limit, offset)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scan_jobs WHERE tenant_id = ? ORDER BY queued_at DESC LIMIT ? OFFSET ?",
            (tenant_id, limit, offset)
        ).fetchall()
    return [
        ScanJob(
            id=r["id"], tenant_id=r["tenant_id"], asset_id=r["asset_id"], scan_id=r["scan_id"],
            task_id=r["task_id"], status=r["status"], requested_by=r["requested_by"],
            profile=r["profile"], queued_at=r["queued_at"], started_at=r["started_at"],
            completed_at=r["completed_at"], failed_at=r["failed_at"], cancelled_at=r["cancelled_at"],
            progress_percent=r["progress_percent"] or 0, current_step=r["current_step"] or "Initialized",
            attempt=r["attempt"] or 1, max_attempts=r["max_attempts"] or 3,
            error_code=r["error_code"], error_message=r["error_message"], worker_id=r["worker_id"],
            heartbeat_at=r["heartbeat_at"], created_at=r["created_at"], updated_at=r["updated_at"]
        ) for r in rows
    ]


@adapter_dispatch("get_queue_depth_metrics")
def get_queue_depth_metrics() -> dict:
    """
    Returns queue depth and oldest queued job latency for Prometheus metrics.
    All queries are defensive: errors return 0 rather than crashing the /metrics endpoint.
    Note: queued_at is a real column in scan_jobs (NOT NULL, set at job creation).
    """
    conn = _get_conn()
    now = datetime.now(timezone.utc)

    # Scan queue
    try:
        row_scan = conn.execute(
            "SELECT COUNT(*), MIN(queued_at) FROM scan_jobs WHERE status = 'queued'"
        ).fetchone()
    except Exception:
        row_scan = None
    scan_count = row_scan[0] if row_scan else 0
    oldest_scan_queued_at = row_scan[1] if (row_scan and row_scan[1]) else None

    oldest_scan_age_sec = 0
    if oldest_scan_queued_at:
        try:
            dt = datetime.fromisoformat(oldest_scan_queued_at)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            oldest_scan_age_sec = max(0, int((now - dt).total_seconds()))
        except Exception:
            oldest_scan_age_sec = 0

    # Integration Outbox queue
    try:
        row_outbox = conn.execute(
            "SELECT COUNT(*) FROM integration_outbox WHERE status IN ('PENDING', 'RETRYING')"
        ).fetchone()
        outbox_count = row_outbox[0] if row_outbox else 0
    except Exception:
        outbox_count = 0

    # Intel sync tasks: counts active sync rows (may be stale if worker crashed).
    # This is an approximation; label as such in metrics documentation.
    try:
        row_intel = conn.execute(
            "SELECT COUNT(*) FROM intelligence_sync_status WHERE status = 'running'"
        ).fetchone()
        intel_count = row_intel[0] if row_intel else 0
    except Exception:
        intel_count = 0

    return {
        "scan_queue_depth": scan_count,
        "oldest_queued_job_seconds": oldest_scan_age_sec,
        "integration_queue_depth": outbox_count,
        "intel_queue_depth": intel_count
    }


# =====================================================================
# Phase 3: ScheduledRun Execution & Duplicate Dispatch Prevention
# =====================================================================

@adapter_dispatch("claim_scheduled_run")
def claim_scheduled_run(schedule_id: str, tenant_id: str, planned_at: str) -> Optional[ScheduledRun]:
    """
    Attempt to claim execution slot for a scheduled scan.
    Guarantees 0 duplicate scheduled jobs using DB unique constraint.
    """
    import uuid
    conn = _get_conn()
    run_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute("""
            INSERT INTO scheduled_runs (id, schedule_id, tenant_id, planned_at, status, created_at)
            VALUES (?, ?, ?, ?, 'dispatched', ?)
        """, (run_id, schedule_id, tenant_id, planned_at, now_iso))
        conn.commit()
        return ScheduledRun(
            id=run_id,
            schedule_id=schedule_id,
            tenant_id=tenant_id,
            planned_at=planned_at,
            status="dispatched",
            created_at=now_iso,
        )
    except sqlite3.IntegrityError:
        return None


@adapter_dispatch("update_scheduled_run_status")
def update_scheduled_run_status(run_id: str, status: str, scan_job_id: Optional[str] = None) -> bool:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if scan_job_id:
        conn.execute(
            "UPDATE scheduled_runs SET status = ?, scan_job_id = ? WHERE id = ?",
            (status, scan_job_id, run_id)
        )
    else:
        conn.execute(
            "UPDATE scheduled_runs SET status = ? WHERE id = ?",
            (status, run_id)
        )
    if status == "running":
        conn.execute("UPDATE scheduled_runs SET started_at = ? WHERE id = ?", (now_iso, run_id))
    elif status in ("completed", "failed"):
        conn.execute("UPDATE scheduled_runs SET completed_at = ? WHERE id = ?", (now_iso, run_id))
    conn.commit()
    return True


# =====================================================================
# Phase 3: Vulnerability Intelligence Sync Status & Freshness SLA
# =====================================================================

@adapter_dispatch("get_intel_sync_status")
def get_intel_sync_status(source: str) -> Optional[IntelSyncStatus]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM intelligence_sync_status WHERE source = ?", (source,)).fetchone()
    if not row:
        return None
    return IntelSyncStatus(
        id=row["id"],
        source=row["source"],
        last_success=row["last_success"],
        last_attempt=row["last_attempt"],
        status=row["status"],
        records_processed=row["records_processed"] or 0,
        error_code=row["error_code"],
        error_message=row["error_message"],
        freshness_age_seconds=row["freshness_age_seconds"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@adapter_dispatch("list_intel_sync_statuses")
def list_intel_sync_statuses() -> list[IntelSyncStatus]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM intelligence_sync_status ORDER BY source ASC").fetchall()
    return [
        IntelSyncStatus(
            id=r["id"], source=r["source"], last_success=r["last_success"],
            last_attempt=r["last_attempt"], status=r["status"],
            records_processed=r["records_processed"] or 0,
            error_code=r["error_code"], error_message=r["error_message"],
            freshness_age_seconds=r["freshness_age_seconds"],
            created_at=r["created_at"], updated_at=r["updated_at"]
        ) for r in rows
    ]


@adapter_dispatch("update_intel_sync_status")
def update_intel_sync_status(
    source: str,
    status: str,
    records_processed: int = 0,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
) -> IntelSyncStatus:
    import uuid
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    existing = get_intel_sync_status(source)
    
    if not existing:
        new_id = str(uuid.uuid4())
        last_succ = now_iso if status == "success" else None
        conn.execute("""
            INSERT INTO intelligence_sync_status (
                id, source, last_success, last_attempt, status,
                records_processed, error_code, error_message,
                freshness_age_seconds, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (new_id, source, last_succ, now_iso, status, records_processed, error_code, error_message, 0 if last_succ else None, now_iso, now_iso))
        conn.commit()
        return get_intel_sync_status(source)  # type: ignore
    else:
        last_succ = now_iso if status == "success" else existing.last_success
        freshness_age = 0 if status == "success" else existing.freshness_age_seconds
        if last_succ and status != "success":
            try:
                last_dt = datetime.fromisoformat(last_succ)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                freshness_age = int((datetime.now(timezone.utc) - last_dt).total_seconds())
            except Exception:
                pass
        conn.execute("""
            UPDATE intelligence_sync_status SET
                last_success = ?, last_attempt = ?, status = ?,
                records_processed = ?, error_code = ?, error_message = ?,
                freshness_age_seconds = ?, updated_at = ?
            WHERE source = ?
        """, (last_succ, now_iso, status, records_processed, error_code, error_message, freshness_age, now_iso, source))
        conn.commit()
        return get_intel_sync_status(source)  # type: ignore


def evaluate_intel_freshness(source: str) -> dict:
    from config import INTEL_FRESHNESS_SLA_HOURS
    item = get_intel_sync_status(source)
    if not item or not item.last_success:
        return {
            "source": source,
            "status": "Failed" if (item and item.status == "failed") else "Stale",
            "sla_hours": INTEL_FRESHNESS_SLA_HOURS,
            "age_hours": None,
            "label": "No successful sync recorded",
        }
    try:
        last_dt = datetime.fromisoformat(item.last_success)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - last_dt).total_seconds() / 3600.0
    except Exception:
        age_hours = 999.0

    if item.status == "failed":
        sla_state = "Failed"
    elif age_hours <= INTEL_FRESHNESS_SLA_HOURS:
        sla_state = "Fresh"
    elif age_hours <= (INTEL_FRESHNESS_SLA_HOURS * 1.5):
        sla_state = "Warning"
    else:
        sla_state = "Stale"

    return {
        "source": source,
        "status": sla_state,
        "sla_hours": INTEL_FRESHNESS_SLA_HOURS,
        "age_hours": round(age_hours, 2),
        "last_success": item.last_success,
        "records_processed": item.records_processed,
    }


# =====================================================================
# Phase 4: Observations, History, Comments CRUD
# =====================================================================

@adapter_dispatch("save_finding_observation")
def save_finding_observation(obs: FindingObservation) -> FindingObservation:
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO finding_observations (
            id, tenant_id, finding_id, scan_id, asset_id, scanner_id, observed_at, severity, evidence_id, evidence_reference, status, raw_reference, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        obs.id, obs.tenant_id, obs.finding_id, obs.scan_id, obs.asset_id, obs.scanner_id, obs.observed_at,
        obs.severity, obs.evidence_id, obs.evidence_reference or obs.evidence_id, obs.status, obs.raw_reference, obs.created_at
    ))
    conn.commit()
    return obs


@adapter_dispatch("get_observations_for_finding")
def get_observations_for_finding(finding_id: str, tenant_id: Optional[str] = None) -> list[FindingObservation]:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM finding_observations WHERE finding_id = ? AND tenant_id = ? ORDER BY observed_at DESC", (finding_id, tenant_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM finding_observations WHERE finding_id = ? ORDER BY observed_at DESC", (finding_id,)).fetchall()
    return [FindingObservation(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"], scan_id=r["scan_id"],
        asset_id=r["asset_id"] if "asset_id" in r.keys() else None,
        scanner_id=r["scanner_id"] if "scanner_id" in r.keys() else None,
        observed_at=r["observed_at"], severity=r["severity"], evidence_id=r["evidence_id"],
        evidence_reference=r["evidence_reference"] if "evidence_reference" in r.keys() else r["evidence_id"],
        status=r["status"], raw_reference=r["raw_reference"], created_at=r["created_at"]
    ) for r in rows]


@adapter_dispatch("get_observations_for_scan")
def get_observations_for_scan(scan_id: str, tenant_id: Optional[str] = None) -> list[FindingObservation]:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM finding_observations WHERE scan_id = ? AND tenant_id = ? ORDER BY observed_at DESC", (scan_id, tenant_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM finding_observations WHERE scan_id = ? ORDER BY observed_at DESC", (scan_id,)).fetchall()
    return [FindingObservation(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"], scan_id=r["scan_id"],
        asset_id=r["asset_id"] if "asset_id" in r.keys() else None,
        scanner_id=r["scanner_id"] if "scanner_id" in r.keys() else None,
        observed_at=r["observed_at"], severity=r["severity"], evidence_id=r["evidence_id"],
        evidence_reference=r["evidence_reference"] if "evidence_reference" in r.keys() else r["evidence_id"],
        status=r["status"], raw_reference=r["raw_reference"], created_at=r["created_at"]
    ) for r in rows]


@adapter_dispatch("add_finding_history")
def add_finding_history(history: FindingHistory) -> FindingHistory:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO finding_history (
            id, tenant_id, finding_id, actor_user_id, action, old_status, new_status, comment, metadata, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        history.id, history.tenant_id, history.finding_id, history.actor_user_id,
        history.action, history.old_status, history.new_status, history.comment,
        json.dumps(history.metadata), history.created_at
    ))
    conn.commit()
    return history


@adapter_dispatch("get_finding_history")
def get_finding_history(finding_id: str, tenant_id: Optional[str] = None) -> list[FindingHistory]:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM finding_history WHERE finding_id = ? AND tenant_id = ? ORDER BY created_at ASC", (finding_id, tenant_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM finding_history WHERE finding_id = ? ORDER BY created_at ASC", (finding_id,)).fetchall()
    return [FindingHistory(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"],
        actor_user_id=r["actor_user_id"], action=r["action"], old_status=r["old_status"],
        new_status=r["new_status"], comment=r["comment"],
        metadata=json.loads(r["metadata"]) if r["metadata"] else {},
        created_at=r["created_at"]
    ) for r in rows]


@adapter_dispatch("add_finding_comment")
def add_finding_comment(comment: FindingComment) -> FindingComment:
    import html
    sanitized_body = html.escape(comment.body.strip()) if comment.body else ""
    comment.body = sanitized_body
    conn = _get_conn()
    conn.execute("""
        INSERT INTO finding_comments (
            id, tenant_id, finding_id, author_user_id, author_username, body, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        comment.id, comment.tenant_id, comment.finding_id, comment.author_user_id,
        comment.author_username, sanitized_body, comment.created_at, comment.updated_at
    ))
    conn.commit()
    return comment


@adapter_dispatch("get_finding_comments")
def get_finding_comments(finding_id: str, tenant_id: Optional[str] = None) -> list[FindingComment]:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM finding_comments WHERE finding_id = ? AND tenant_id = ? ORDER BY created_at ASC", (finding_id, tenant_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM finding_comments WHERE finding_id = ? ORDER BY created_at ASC", (finding_id,)).fetchall()
    return [FindingComment(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"],
        author_user_id=r["author_user_id"], author_username=r["author_username"] or "",
        body=r["body"], created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


# =====================================================================
# Sprint 3 Phase 4: Finding Lifecycle Query
# =====================================================================

@adapter_dispatch("get_finding_lifecycle")
def get_finding_lifecycle(finding_id: str, tenant_id: Optional[str] = None) -> dict:
    """
    Return a complete lifecycle record for a finding, combining:
      - The finding itself (first_seen, last_seen, status, CVE, confidence)
      - All scanner observations (FindingObservation) — scanner-observed events
      - All workflow history events (FindingHistory) — manual workflow transitions
      - All analyst comments (FindingComment)
      - Remediation record (if any)

    Scanner observations and workflow history are kept separate to preserve
    the distinction between observed evidence and manual workflow state.

    Returns a dict with keys:
      finding, observations, history, comments, remediation
    """
    finding = get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        return {}

    observations = get_observations_for_finding(finding_id, tenant_id=tenant_id)
    history = get_finding_history(finding_id, tenant_id=tenant_id)
    comments = get_finding_comments(finding_id, tenant_id=tenant_id)

    # Remediation (may be absent)
    remediation = None
    try:
        remediation = get_remediation_by_finding(finding_id, tenant_id=tenant_id)
    except Exception:
        pass

    return {
        "finding": finding,
        "observations": observations,   # Scanner-observed events (evidence)
        "history": history,             # Workflow state transitions
        "comments": comments,           # Analyst commentary
        "remediation": remediation,
    }


# =====================================================================
# Phase 4: Remediation Governance CRUD
# =====================================================================

@adapter_dispatch("create_remediation")
def create_remediation(remediation: Remediation) -> Remediation:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO remediations (
            id, tenant_id, finding_id, title, description, owner_user_id, owner_external,
            status, priority, due_date, started_at, completed_at, verification_required,
            verification_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        remediation.id, remediation.tenant_id, remediation.finding_id, remediation.title,
        remediation.description, remediation.owner_user_id, remediation.owner_external,
        remediation.status, remediation.priority, remediation.due_date, remediation.started_at,
        remediation.completed_at, 1 if remediation.verification_required else 0,
        remediation.verification_status, remediation.created_at, remediation.updated_at
    ))
    conn.commit()
    return remediation


@adapter_dispatch("get_remediation")
def get_remediation(remediation_id: str, tenant_id: Optional[str] = None) -> Optional[Remediation]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM remediations WHERE id = ? AND tenant_id = ?", (remediation_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM remediations WHERE id = ?", (remediation_id,)).fetchone()
    if not row:
        return None
    return Remediation(
        id=row["id"], tenant_id=row["tenant_id"], finding_id=row["finding_id"],
        title=row["title"], description=row["description"], owner_user_id=row["owner_user_id"],
        owner_external=row["owner_external"], status=row["status"], priority=row["priority"],
        due_date=row["due_date"], started_at=row["started_at"], completed_at=row["completed_at"],
        verification_required=bool(row["verification_required"]),
        verification_status=row["verification_status"] or "pending",
        created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("get_remediation_by_finding")
def get_remediation_by_finding(finding_id: str, tenant_id: Optional[str] = None) -> Optional[Remediation]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM remediations WHERE finding_id = ? AND tenant_id = ? ORDER BY created_at DESC LIMIT 1", (finding_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM remediations WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1", (finding_id,)).fetchone()
    if not row:
        return None
    return Remediation(
        id=row["id"], tenant_id=row["tenant_id"], finding_id=row["finding_id"],
        title=row["title"], description=row["description"], owner_user_id=row["owner_user_id"],
        owner_external=row["owner_external"], status=row["status"], priority=row["priority"],
        due_date=row["due_date"], started_at=row["started_at"], completed_at=row["completed_at"],
        verification_required=bool(row["verification_required"]),
        verification_status=row["verification_status"] or "pending",
        created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_remediations")
def list_remediations(tenant_id: str, status: Optional[str] = None) -> list[Remediation]:
    conn = _get_conn()
    if status:
        rows = conn.execute("SELECT * FROM remediations WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC", (tenant_id, status.upper())).fetchall()
    else:
        rows = conn.execute("SELECT * FROM remediations WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    return [Remediation(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"],
        title=r["title"], description=r["description"], owner_user_id=r["owner_user_id"],
        owner_external=r["owner_external"], status=r["status"], priority=r["priority"],
        due_date=r["due_date"], started_at=r["started_at"], completed_at=r["completed_at"],
        verification_required=bool(r["verification_required"]),
        verification_status=r["verification_status"] or "pending",
        created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("update_remediation")
def update_remediation(remediation: Remediation) -> Remediation:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    remediation.updated_at = now_iso
    conn.execute("""
        UPDATE remediations SET
            title = ?, description = ?, owner_user_id = ?, owner_external = ?,
            status = ?, priority = ?, due_date = ?, started_at = ?, completed_at = ?,
            verification_required = ?, verification_status = ?, updated_at = ?
        WHERE id = ? AND tenant_id = ?
    """, (
        remediation.title, remediation.description, remediation.owner_user_id,
        remediation.owner_external, remediation.status, remediation.priority,
        remediation.due_date, remediation.started_at, remediation.completed_at,
        1 if remediation.verification_required else 0, remediation.verification_status,
        now_iso, remediation.id, remediation.tenant_id
    ))
    conn.commit()
    return remediation


@adapter_dispatch("add_remediation_action")
def add_remediation_action(action: RemediationAction) -> RemediationAction:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO remediation_actions (
            id, tenant_id, remediation_id, action_type, description, owner, status, due_date, completed_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        action.id, action.tenant_id, action.remediation_id, action.action_type,
        action.description, action.owner, action.status, action.due_date,
        action.completed_at, action.created_at, action.updated_at
    ))
    conn.commit()
    return action


@adapter_dispatch("get_remediation_actions")
def get_remediation_actions(remediation_id: str, tenant_id: Optional[str] = None) -> list[RemediationAction]:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM remediation_actions WHERE remediation_id = ? AND tenant_id = ? ORDER BY created_at ASC", (remediation_id, tenant_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM remediation_actions WHERE remediation_id = ? ORDER BY created_at ASC", (remediation_id,)).fetchall()
    return [RemediationAction(
        id=r["id"], tenant_id=r["tenant_id"], remediation_id=r["remediation_id"],
        action_type=r["action_type"], description=r["description"], owner=r["owner"],
        status=r["status"], due_date=r["due_date"], completed_at=r["completed_at"],
        created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("update_remediation_action")
def update_remediation_action(action: RemediationAction) -> RemediationAction:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    action.updated_at = now_iso
    conn.execute("""
        UPDATE remediation_actions SET
            action_type = ?, description = ?, owner = ?, status = ?, due_date = ?, completed_at = ?, updated_at = ?
        WHERE id = ? AND tenant_id = ?
    """, (action.action_type, action.description, action.owner, action.status, action.due_date, action.completed_at, now_iso, action.id, action.tenant_id))
    conn.commit()
    return action


# =====================================================================
# Phase 4: SLA Policy CRUD
# =====================================================================

@adapter_dispatch("create_sla_policy")
def create_sla_policy(policy: SLAPolicy) -> SLAPolicy:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO sla_policies (
            id, tenant_id, name, severity, criticality, kev, internet_exposed, due_days, warning_days, enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        policy.id, policy.tenant_id, policy.name, policy.severity, policy.criticality,
        1 if policy.kev else (0 if policy.kev is not None else None),
        1 if policy.internet_exposed else (0 if policy.internet_exposed is not None else None),
        policy.due_days, policy.warning_days, 1 if policy.enabled else 0, policy.created_at, policy.updated_at
    ))
    conn.commit()
    return policy


@adapter_dispatch("get_sla_policy")
def get_sla_policy(policy_id: str, tenant_id: Optional[str] = None) -> Optional[SLAPolicy]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM sla_policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM sla_policies WHERE id = ?", (policy_id,)).fetchone()
    if not row:
        return None
    return SLAPolicy(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        severity=row["severity"], criticality=row["criticality"],
        kev=bool(row["kev"]) if row["kev"] is not None else None,
        internet_exposed=bool(row["internet_exposed"]) if row["internet_exposed"] is not None else None,
        due_days=row["due_days"] or 7, warning_days=row["warning_days"] or 5,
        enabled=bool(row["enabled"]), created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_sla_policies")
def list_sla_policies(tenant_id: str) -> list[SLAPolicy]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM sla_policies WHERE tenant_id = ? ORDER BY created_at ASC", (tenant_id,)).fetchall()
    return [SLAPolicy(
        id=r["id"], tenant_id=r["tenant_id"], name=r["name"],
        severity=r["severity"], criticality=r["criticality"],
        kev=bool(r["kev"]) if r["kev"] is not None else None,
        internet_exposed=bool(r["internet_exposed"]) if r["internet_exposed"] is not None else None,
        due_days=r["due_days"] or 7, warning_days=r["warning_days"] or 5,
        enabled=bool(r["enabled"]), created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("update_sla_policy")
def update_sla_policy(policy: SLAPolicy) -> SLAPolicy:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    policy.updated_at = now_iso
    conn.execute("""
        UPDATE sla_policies SET
            name = ?, severity = ?, criticality = ?, kev = ?, internet_exposed = ?,
            due_days = ?, warning_days = ?, enabled = ?, updated_at = ?
        WHERE id = ? AND tenant_id = ?
    """, (
        policy.name, policy.severity, policy.criticality,
        1 if policy.kev else (0 if policy.kev is not None else None),
        1 if policy.internet_exposed else (0 if policy.internet_exposed is not None else None),
        policy.due_days, policy.warning_days, 1 if policy.enabled else 0, now_iso,
        policy.id, policy.tenant_id
    ))
    conn.commit()
    return policy


@adapter_dispatch("delete_sla_policy")
def delete_sla_policy(policy_id: str, tenant_id: str) -> bool:
    conn = _get_conn()
    res = conn.execute("DELETE FROM sla_policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id))
    conn.commit()
    return res.rowcount > 0


# =====================================================================
# Phase 4: Risk Acceptance CRUD
# =====================================================================

@adapter_dispatch("create_risk_acceptance")
def create_risk_acceptance(ra: RiskAcceptance) -> RiskAcceptance:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO risk_acceptances (
            id, tenant_id, finding_id, requested_by, approved_by, reason,
            business_justification, compensating_controls, valid_from, valid_until,
            status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ra.id, ra.tenant_id, ra.finding_id, ra.requested_by, ra.approved_by,
        ra.reason, ra.business_justification, ra.compensating_controls,
        ra.valid_from, ra.valid_until, ra.status, ra.created_at, ra.updated_at
    ))
    conn.commit()
    return ra


@adapter_dispatch("get_risk_acceptance")
def get_risk_acceptance(ra_id: str, tenant_id: Optional[str] = None) -> Optional[RiskAcceptance]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM risk_acceptances WHERE id = ? AND tenant_id = ?", (ra_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM risk_acceptances WHERE id = ?", (ra_id,)).fetchone()
    if not row:
        return None
    return RiskAcceptance(
        id=row["id"], tenant_id=row["tenant_id"], finding_id=row["finding_id"],
        requested_by=row["requested_by"], approved_by=row["approved_by"],
        reason=row["reason"], business_justification=row["business_justification"] or "",
        compensating_controls=row["compensating_controls"] or "",
        valid_from=row["valid_from"], valid_until=row["valid_until"],
        status=row["status"], created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("get_risk_acceptance_by_finding")
def get_risk_acceptance_by_finding(finding_id: str, tenant_id: Optional[str] = None) -> Optional[RiskAcceptance]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM risk_acceptances WHERE finding_id = ? AND tenant_id = ? ORDER BY created_at DESC LIMIT 1", (finding_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM risk_acceptances WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1", (finding_id,)).fetchone()
    if not row:
        return None
    return RiskAcceptance(
        id=row["id"], tenant_id=row["tenant_id"], finding_id=row["finding_id"],
        requested_by=row["requested_by"], approved_by=row["approved_by"],
        reason=row["reason"], business_justification=row["business_justification"] or "",
        compensating_controls=row["compensating_controls"] or "",
        valid_from=row["valid_from"], valid_until=row["valid_until"],
        status=row["status"], created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_risk_acceptances")
def list_risk_acceptances(tenant_id: str, status: Optional[str] = None) -> list[RiskAcceptance]:
    conn = _get_conn()
    if status:
        rows = conn.execute("SELECT * FROM risk_acceptances WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC", (tenant_id, status.upper())).fetchall()
    else:
        rows = conn.execute("SELECT * FROM risk_acceptances WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    return [RiskAcceptance(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"],
        requested_by=r["requested_by"], approved_by=r["approved_by"],
        reason=r["reason"], business_justification=r["business_justification"] or "",
        compensating_controls=r["compensating_controls"] or "",
        valid_from=r["valid_from"], valid_until=r["valid_until"],
        status=r["status"], created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("update_risk_acceptance")
def update_risk_acceptance(ra: RiskAcceptance) -> RiskAcceptance:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    ra.updated_at = now_iso
    conn.execute("""
        UPDATE risk_acceptances SET
            approved_by = ?, reason = ?, business_justification = ?,
            compensating_controls = ?, valid_from = ?, valid_until = ?,
            status = ?, updated_at = ?
        WHERE id = ? AND tenant_id = ?
    """, (
        ra.approved_by, ra.reason, ra.business_justification,
        ra.compensating_controls, ra.valid_from, ra.valid_until,
        ra.status, now_iso, ra.id, ra.tenant_id
    ))
    conn.commit()
    return ra


# =====================================================================
# Phase 4: Integrations, Ticket References, Webhooks CRUD
# =====================================================================

@adapter_dispatch("create_integration")
def create_integration(integration: Integration) -> Integration:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO integrations (
            id, tenant_id, type, name, enabled, config_reference, secret_reference, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        integration.id, integration.tenant_id, integration.type, integration.name,
        1 if integration.enabled else 0, json.dumps(integration.config_reference),
        integration.secret_reference, integration.created_at, integration.updated_at
    ))
    conn.commit()
    return integration


@adapter_dispatch("get_integration")
def get_integration(integration_id: str, tenant_id: Optional[str] = None) -> Optional[Integration]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM integrations WHERE id = ? AND tenant_id = ?", (integration_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM integrations WHERE id = ?", (integration_id,)).fetchone()
    if not row:
        return None
    return Integration(
        id=row["id"], tenant_id=row["tenant_id"], type=row["type"], name=row["name"],
        enabled=bool(row["enabled"]),
        config_reference=json.loads(row["config_reference"]) if row["config_reference"] else {},
        secret_reference=row["secret_reference"] or "",
        created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_integrations")
def list_integrations(tenant_id: str, type: Optional[str] = None) -> list[Integration]:
    conn = _get_conn()
    if type:
        rows = conn.execute("SELECT * FROM integrations WHERE tenant_id = ? AND type = ? ORDER BY created_at ASC", (tenant_id, type.lower())).fetchall()
    else:
        rows = conn.execute("SELECT * FROM integrations WHERE tenant_id = ? ORDER BY created_at ASC", (tenant_id,)).fetchall()
    return [Integration(
        id=r["id"], tenant_id=r["tenant_id"], type=r["type"], name=r["name"],
        enabled=bool(r["enabled"]),
        config_reference=json.loads(r["config_reference"]) if r["config_reference"] else {},
        secret_reference=r["secret_reference"] or "",
        created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("update_integration")
def update_integration(integration: Integration) -> Integration:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    integration.updated_at = now_iso
    conn.execute("""
        UPDATE integrations SET
            name = ?, enabled = ?, config_reference = ?, secret_reference = ?, updated_at = ?
        WHERE id = ? AND tenant_id = ?
    """, (
        integration.name, 1 if integration.enabled else 0,
        json.dumps(integration.config_reference), integration.secret_reference,
        now_iso, integration.id, integration.tenant_id
    ))
    conn.commit()
    return integration


@adapter_dispatch("delete_integration")
def delete_integration(integration_id: str, tenant_id: str) -> bool:
    conn = _get_conn()
    res = conn.execute("DELETE FROM integrations WHERE id = ? AND tenant_id = ?", (integration_id, tenant_id))
    conn.commit()
    return res.rowcount > 0


@adapter_dispatch("create_ticket_reference")
def create_ticket_reference(ref: TicketReference) -> TicketReference:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO ticket_references (
            id, tenant_id, finding_id, integration_id, external_ticket_id, external_url, status, last_sync_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ref.id, ref.tenant_id, ref.finding_id, ref.integration_id,
        ref.external_ticket_id, ref.external_url, ref.status, ref.last_sync_at, ref.created_at
    ))
    conn.commit()
    return ref


@adapter_dispatch("get_ticket_reference")
def get_ticket_reference(ticket_id: str, tenant_id: Optional[str] = None) -> Optional[TicketReference]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM ticket_references WHERE id = ? AND tenant_id = ?", (ticket_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM ticket_references WHERE id = ?", (ticket_id,)).fetchone()
    if not row:
        return None
    return TicketReference(
        id=row["id"], tenant_id=row["tenant_id"], finding_id=row["finding_id"],
        integration_id=row["integration_id"], external_ticket_id=row["external_ticket_id"],
        external_url=row["external_url"] or "", status=row["status"] or "open",
        last_sync_at=row["last_sync_at"], created_at=row["created_at"]
    )


@adapter_dispatch("get_ticket_references_for_finding")
def get_ticket_references_for_finding(finding_id: str, tenant_id: Optional[str] = None) -> list[TicketReference]:
    conn = _get_conn()
    if tenant_id:
        rows = conn.execute("SELECT * FROM ticket_references WHERE finding_id = ? AND tenant_id = ? ORDER BY created_at DESC", (finding_id, tenant_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM ticket_references WHERE finding_id = ? ORDER BY created_at DESC", (finding_id,)).fetchall()
    return [TicketReference(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"],
        integration_id=r["integration_id"], external_ticket_id=r["external_ticket_id"],
        external_url=r["external_url"] or "", status=r["status"] or "open",
        last_sync_at=r["last_sync_at"], created_at=r["created_at"]
    ) for r in rows]


@adapter_dispatch("list_ticket_references")
def list_ticket_references(tenant_id: str) -> list[TicketReference]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM ticket_references WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    return [TicketReference(
        id=r["id"], tenant_id=r["tenant_id"], finding_id=r["finding_id"],
        integration_id=r["integration_id"], external_ticket_id=r["external_ticket_id"],
        external_url=r["external_url"] or "", status=r["status"] or "open",
        last_sync_at=r["last_sync_at"], created_at=r["created_at"]
    ) for r in rows]


@adapter_dispatch("update_ticket_reference")
def update_ticket_reference(ref: TicketReference) -> TicketReference:
    conn = _get_conn()
    conn.execute("""
        UPDATE ticket_references SET
            status = ?, last_sync_at = ?
        WHERE id = ? AND tenant_id = ?
    """, (ref.status, ref.last_sync_at, ref.id, ref.tenant_id))
    conn.commit()
    return ref


@adapter_dispatch("create_webhook_delivery")
def create_webhook_delivery(delivery: WebhookDelivery) -> WebhookDelivery:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO webhook_deliveries (
            id, tenant_id, integration_id, event, payload_hash, status, attempt, last_error, next_retry_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        delivery.id, delivery.tenant_id, delivery.integration_id, delivery.event,
        delivery.payload_hash, delivery.status, delivery.attempt, delivery.last_error,
        delivery.next_retry_at, delivery.created_at
    ))
    conn.commit()
    return delivery


@adapter_dispatch("get_webhook_delivery")
def get_webhook_delivery(delivery_id: str, tenant_id: Optional[str] = None) -> Optional[WebhookDelivery]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM webhook_deliveries WHERE id = ? AND tenant_id = ?", (delivery_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM webhook_deliveries WHERE id = ?", (delivery_id,)).fetchone()
    if not row:
        return None
    return WebhookDelivery(
        id=row["id"], tenant_id=row["tenant_id"], integration_id=row["integration_id"],
        event=row["event"], payload_hash=row["payload_hash"], status=row["status"],
        attempt=row["attempt"] or 1, last_error=row["last_error"],
        next_retry_at=row["next_retry_at"], created_at=row["created_at"]
    )


@adapter_dispatch("list_webhook_deliveries")
def list_webhook_deliveries(tenant_id: str, limit: int = 50) -> list[WebhookDelivery]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM webhook_deliveries WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?", (tenant_id, limit)).fetchall()
    return [WebhookDelivery(
        id=r["id"], tenant_id=r["tenant_id"], integration_id=r["integration_id"],
        event=r["event"], payload_hash=r["payload_hash"], status=r["status"],
        attempt=r["attempt"] or 1, last_error=r["last_error"],
        next_retry_at=r["next_retry_at"], created_at=r["created_at"]
    ) for r in rows]


@adapter_dispatch("update_webhook_delivery")
def update_webhook_delivery(delivery: WebhookDelivery) -> WebhookDelivery:
    conn = _get_conn()
    conn.execute("""
        UPDATE webhook_deliveries SET
            status = ?, attempt = ?, last_error = ?, next_retry_at = ?
        WHERE id = ? AND tenant_id = ?
    """, (delivery.status, delivery.attempt, delivery.last_error, delivery.next_retry_at, delivery.id, delivery.tenant_id))
    conn.commit()
    return delivery


# =====================================================================
# Phase 4: API Keys CRUD
# =====================================================================

@adapter_dispatch("create_api_key")
def create_api_key(api_key: APIKey) -> APIKey:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO api_keys (
            id, tenant_id, name, key_prefix, key_hash, scopes, last_used_at, expires_at, created_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        api_key.id, api_key.tenant_id, api_key.name, api_key.key_prefix or "", api_key.key_hash,
        json.dumps(api_key.scopes), api_key.last_used_at, api_key.expires_at,
        api_key.created_at, api_key.revoked_at
    ))
    conn.commit()
    return api_key


@adapter_dispatch("get_api_key_by_hash")
def get_api_key_by_hash(key_hash: str) -> Optional[APIKey]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
    if not row:
        return None
    keys = row.keys()
    return APIKey(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        key_prefix=row["key_prefix"] if "key_prefix" in keys else "",
        key_hash=row["key_hash"], scopes=json.loads(row["scopes"]) if row["scopes"] else [],
        last_used_at=row["last_used_at"], expires_at=row["expires_at"],
        created_at=row["created_at"], revoked_at=row["revoked_at"]
    )


@adapter_dispatch("get_api_key")
def get_api_key(key_id: str, tenant_id: Optional[str] = None) -> Optional[APIKey]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM api_keys WHERE id = ? AND tenant_id = ?", (key_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
    if not row:
        return None
    keys = row.keys()
    return APIKey(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        key_prefix=row["key_prefix"] if "key_prefix" in keys else "",
        key_hash=row["key_hash"], scopes=json.loads(row["scopes"]) if row["scopes"] else [],
        last_used_at=row["last_used_at"], expires_at=row["expires_at"],
        created_at=row["created_at"], revoked_at=row["revoked_at"]
    )


@adapter_dispatch("list_api_keys")
def list_api_keys(tenant_id: str) -> list[APIKey]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    return [APIKey(
        id=r["id"], tenant_id=r["tenant_id"], name=r["name"],
        key_prefix=r["key_prefix"] if "key_prefix" in r.keys() else "",
        key_hash=r["key_hash"], scopes=json.loads(r["scopes"]) if r["scopes"] else [],
        last_used_at=r["last_used_at"], expires_at=r["expires_at"],
        created_at=r["created_at"], revoked_at=r["revoked_at"]
    ) for r in rows]


@adapter_dispatch("revoke_api_key")
def revoke_api_key(key_id: str, tenant_id: str) -> bool:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    res = conn.execute("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND tenant_id = ?", (now_iso, key_id, tenant_id))
    conn.commit()
    return res.rowcount > 0


@adapter_dispatch("update_api_key")
def update_api_key(api_key: APIKey) -> bool:
    conn = _get_conn()
    conn.execute(
        """UPDATE api_keys SET
            name = ?, scopes = ?, expires_at = ?, revoked_at = ?, last_used_at = ?
        WHERE id = ? AND tenant_id = ?""",
        (api_key.name, json.dumps(api_key.scopes), api_key.expires_at,
         api_key.revoked_at, api_key.last_used_at, api_key.id, api_key.tenant_id)
    )
    conn.commit()
    return True


get_api_key_by_id = get_api_key


# =====================================================================
# Phase 4: Daily Risk Snapshots & Control Mappings CRUD
# =====================================================================

@adapter_dispatch("save_daily_risk_snapshot")
def save_daily_risk_snapshot(snapshot: DailyRiskSnapshot) -> DailyRiskSnapshot:
    conn = _get_conn()
    avg_score = snapshot.avg_risk_score if snapshot.avg_risk_score else snapshot.risk_score_avg
    conn.execute("""
        INSERT OR REPLACE INTO daily_risk_snapshots (
            id, tenant_id, date, assets, open_findings, p1_count, p2_count, kev_count,
            sla_breaches, risk_accepted, risk_score_avg, avg_risk_score, mttr_seconds, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        snapshot.id, snapshot.tenant_id, snapshot.date, getattr(snapshot, "assets", 0),
        snapshot.open_findings, snapshot.p1_count, snapshot.p2_count, snapshot.kev_count,
        snapshot.sla_breaches, getattr(snapshot, "risk_accepted", 0),
        avg_score, avg_score, snapshot.mttr_seconds, snapshot.created_at
    ))
    conn.commit()
    return snapshot


@adapter_dispatch("get_daily_risk_snapshots")
def get_daily_risk_snapshots(tenant_id: str, days: int = 30) -> list[DailyRiskSnapshot]:
    conn = _get_conn()
    rows = conn.execute("""
        SELECT * FROM daily_risk_snapshots
        WHERE tenant_id = ?
        ORDER BY date DESC
        LIMIT ?
    """, (tenant_id, days)).fetchall()
    result = []
    for r in rows:
        keys = r.keys()
        avg_score = r["avg_risk_score"] if "avg_risk_score" in keys and r["avg_risk_score"] is not None else (r["risk_score_avg"] or 0.0)
        result.append(DailyRiskSnapshot(
            id=r["id"], tenant_id=r["tenant_id"], date=r["date"],
            assets=r["assets"] if "assets" in keys and r["assets"] is not None else 0,
            open_findings=r["open_findings"] or 0, p1_count=r["p1_count"] or 0,
            p2_count=r["p2_count"] or 0, kev_count=r["kev_count"] or 0,
            sla_breaches=r["sla_breaches"] or 0,
            risk_accepted=r["risk_accepted"] if "risk_accepted" in keys and r["risk_accepted"] is not None else 0,
            risk_score_avg=avg_score,
            avg_risk_score=avg_score,
            mttr_seconds=r["mttr_seconds"] or 0.0, created_at=r["created_at"]
        ))
    return result


def get_control_mappings(finding_type: Optional[str] = None, framework: Optional[str] = None) -> list[ControlMapping]:
    conn = _get_conn()
    where = []
    params = []
    if finding_type:
        where.append("finding_type = ?")
        params.append(finding_type)
    if framework:
        where.append("framework = ?")
        params.append(framework)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(f"SELECT * FROM control_mappings{where_sql}", params).fetchall()
    return [ControlMapping(
        id=r["id"], finding_type=r["finding_type"], framework=r["framework"],
        control_id=r["control_id"], control_title=r["control_title"] or ""
    ) for r in rows]


def seed_default_control_mappings():
    import uuid
    conn = _get_conn()
    mappings = [
        ("outdated_core", "ISO 27001", "A.12.6.1", "Management of Technical Vulnerabilities"),
        ("outdated_core", "NIST CSF", "ID.RA-1", "Asset vulnerabilities are identified and documented"),
        ("outdated_core", "CIS Controls", "CIS 7", "Continuous Vulnerability Management"),
        ("vulnerable_plugin", "ISO 27001", "A.12.6.1", "Management of Technical Vulnerabilities"),
        ("vulnerable_plugin", "NIST CSF", "DE.CM-8", "Vulnerability scans are performed"),
        ("vulnerable_plugin", "CIS Controls", "CIS 7.4", "Automated Application Patching"),
        ("admin_user_enumeration", "ISO 27001", "A.9.2.1", "User Registration and De-registration"),
        ("admin_user_enumeration", "NIST CSF", "PR.AC-1", "Identities and credentials are managed"),
        ("directory_listing", "ISO 27001", "A.13.1.3", "Segregation in Networks"),
        ("debug_log_exposed", "ISO 27001", "A.12.4.1", "Event Logging"),
        ("missing_security_headers", "ISO 27001", "A.14.1.2", "Securing Application Services"),
        ("xmlrpc_enabled", "CIS Controls", "CIS 4.8", "Uninstall or Disable Unnecessary Services"),
    ]
    for m in mappings:
        mid = str(uuid.uuid4())
        try:
            conn.execute("""
                INSERT OR IGNORE INTO control_mappings (id, finding_type, framework, control_id, control_title)
                VALUES (?, ?, ?, ?, ?)
            """, (mid, m[0], m[1], m[2], m[3]))
        except Exception:
            pass
    conn.commit()


# ==============================================================================
# PHASE 6: EASM, DISCOVERY, EVIDENCE, POLICY, BU, OUTBOX & DATA QUALITY CRUD
# ==============================================================================

# --- Discovery Scopes ---
@adapter_dispatch("save_discovery_scope")
def save_discovery_scope(scope: DiscoveryScope) -> DiscoveryScope:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if not scope.updated_at:
        scope.updated_at = now_iso
    conn.execute("""
        INSERT OR REPLACE INTO discovery_scopes (
            id, tenant_id, name, root_domain, allowed_suffixes, excluded_patterns,
            max_depth, enabled, created_by, approved_by, valid_from, valid_until,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scope.id, scope.tenant_id, scope.name, scope.root_domain,
        json.dumps(scope.allowed_suffixes), json.dumps(scope.excluded_patterns),
        scope.max_depth, 1 if scope.enabled else 0, scope.created_by,
        scope.approved_by, scope.valid_from, scope.valid_until,
        scope.created_at, scope.updated_at
    ))
    conn.commit()
    return scope


@adapter_dispatch("get_discovery_scope")
def get_discovery_scope(scope_id: str, tenant_id: Optional[str] = None) -> Optional[DiscoveryScope]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM discovery_scopes WHERE id = ? AND tenant_id = ?", (scope_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM discovery_scopes WHERE id = ?", (scope_id,)).fetchone()
    if not row:
        return None
    return DiscoveryScope(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        root_domain=row["root_domain"],
        allowed_suffixes=json.loads(row["allowed_suffixes"] or "[]"),
        excluded_patterns=json.loads(row["excluded_patterns"] or "[]"),
        max_depth=row["max_depth"], enabled=bool(row["enabled"]),
        created_by=row["created_by"], approved_by=row["approved_by"],
        valid_from=row["valid_from"], valid_until=row["valid_until"],
        created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_discovery_scopes")
def list_discovery_scopes(tenant_id: str, enabled_only: bool = False) -> list:
    conn = _get_conn()
    query = "SELECT * FROM discovery_scopes WHERE tenant_id = ?"
    params = [tenant_id]
    if enabled_only:
        query += " AND enabled = 1"
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [DiscoveryScope(
        id=r["id"], tenant_id=r["tenant_id"], name=r["name"],
        root_domain=r["root_domain"],
        allowed_suffixes=json.loads(r["allowed_suffixes"] or "[]"),
        excluded_patterns=json.loads(r["excluded_patterns"] or "[]"),
        max_depth=r["max_depth"], enabled=bool(r["enabled"]),
        created_by=r["created_by"], approved_by=r["approved_by"],
        valid_from=r["valid_from"], valid_until=r["valid_until"],
        created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


# --- Discovered Assets (Candidates) ---
def save_discovered_asset(candidate: DiscoveredAsset) -> DiscoveredAsset:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if not candidate.updated_at:
        candidate.updated_at = now_iso
    conn.execute("""
        INSERT OR REPLACE INTO discovered_assets (
            id, tenant_id, discovery_scope_id, hostname, canonical_url, source,
            confidence, first_seen_at, last_seen_at, status, evidence_id,
            promoted_asset_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        candidate.id, candidate.tenant_id, candidate.discovery_scope_id,
        candidate.hostname, candidate.canonical_url, candidate.source,
        candidate.confidence, candidate.first_seen_at, candidate.last_seen_at,
        candidate.status, candidate.evidence_id, candidate.promoted_asset_id,
        candidate.created_at, candidate.updated_at
    ))
    conn.commit()
    return candidate


def get_discovered_asset(candidate_id: str, tenant_id: Optional[str] = None) -> Optional[DiscoveredAsset]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM discovered_assets WHERE id = ? AND tenant_id = ?", (candidate_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM discovered_assets WHERE id = ?", (candidate_id,)).fetchone()
    if not row:
        return None
    return DiscoveredAsset(
        id=row["id"], tenant_id=row["tenant_id"], discovery_scope_id=row["discovery_scope_id"],
        hostname=row["hostname"], canonical_url=row["canonical_url"], source=row["source"],
        confidence=row["confidence"], first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
        status=row["status"], evidence_id=row["evidence_id"], promoted_asset_id=row["promoted_asset_id"],
        created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_discovered_assets")
def list_discovered_assets(tenant_id: str, status: Optional[str] = None, scope_id: Optional[str] = None) -> list:
    conn = _get_conn()
    query = "SELECT * FROM discovered_assets WHERE tenant_id = ?"
    params = [tenant_id]
    if status:
        query += " AND status = ?"
        params.append(status)
    if scope_id:
        query += " AND discovery_scope_id = ?"
        params.append(scope_id)
    query += " ORDER BY first_seen_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [DiscoveredAsset(
        id=r["id"], tenant_id=r["tenant_id"], discovery_scope_id=r["discovery_scope_id"],
        hostname=r["hostname"], canonical_url=r["canonical_url"], source=r["source"],
        confidence=r["confidence"], first_seen_at=r["first_seen_at"], last_seen_at=r["last_seen_at"],
        status=r["status"], evidence_id=r["evidence_id"], promoted_asset_id=r["promoted_asset_id"],
        created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


# --- Domain Ownership Verification ---
def save_asset_verification(verification: AssetVerification) -> AssetVerification:
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO asset_verifications (
            id, tenant_id, asset_id, method, challenge, status, verified_at, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        verification.id, verification.tenant_id, verification.asset_id,
        verification.method, verification.challenge, verification.status,
        verification.verified_at, verification.expires_at, verification.created_at
    ))
    conn.commit()
    return verification


def get_asset_verification(verification_id: str, tenant_id: Optional[str] = None) -> Optional[AssetVerification]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM asset_verifications WHERE id = ? AND tenant_id = ?", (verification_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM asset_verifications WHERE id = ?", (verification_id,)).fetchone()
    if not row:
        return None
    return AssetVerification(
        id=row["id"], tenant_id=row["tenant_id"], asset_id=row["asset_id"],
        method=row["method"], challenge=row["challenge"], status=row["status"],
        verified_at=row["verified_at"], expires_at=row["expires_at"], created_at=row["created_at"]
    )


def get_latest_verification_for_asset(tenant_id: str, asset_id: str) -> Optional[AssetVerification]:
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM asset_verifications
        WHERE tenant_id = ? AND asset_id = ?
        ORDER BY created_at DESC LIMIT 1
    """, (tenant_id, asset_id)).fetchone()
    if not row:
        return None
    return AssetVerification(
        id=row["id"], tenant_id=row["tenant_id"], asset_id=row["asset_id"],
        method=row["method"], challenge=row["challenge"], status=row["status"],
        verified_at=row["verified_at"], expires_at=row["expires_at"], created_at=row["created_at"]
    )


# --- Evidence Store ---
def save_evidence(evidence: Evidence) -> Evidence:
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO evidences (
            id, tenant_id, asset_id, scan_id, finding_id, type, source,
            content_hash, storage_reference, mime_type, size_bytes, created_at,
            retention_class, classification, sanitized, redacted, provenance,
            quality, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        evidence.id, evidence.tenant_id, evidence.asset_id, evidence.scan_id,
        evidence.finding_id, evidence.type, evidence.source, evidence.content_hash,
        evidence.storage_reference, evidence.mime_type, evidence.size_bytes,
        evidence.created_at, evidence.retention_class, evidence.classification,
        1 if evidence.sanitized else 0, 1 if evidence.redacted else 0,
        json.dumps(evidence.provenance), evidence.quality, evidence.payload
    ))
    conn.commit()
    return evidence


def get_evidence(evidence_id: str, tenant_id: Optional[str] = None) -> Optional[Evidence]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM evidences WHERE id = ? AND tenant_id = ?", (evidence_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM evidences WHERE id = ?", (evidence_id,)).fetchone()
    if not row:
        return None
    return Evidence(
        id=row["id"], tenant_id=row["tenant_id"], asset_id=row["asset_id"],
        scan_id=row["scan_id"], finding_id=row["finding_id"], type=row["type"],
        source=row["source"], content_hash=row["content_hash"],
        storage_reference=row["storage_reference"], mime_type=row["mime_type"],
        size_bytes=row["size_bytes"], created_at=row["created_at"],
        retention_class=row["retention_class"], classification=row["classification"],
        sanitized=bool(row["sanitized"]), redacted=bool(row["redacted"]),
        provenance=json.loads(row["provenance"] or "{}"), quality=row["quality"],
        payload=row["payload"]
    )


def list_evidences_for_finding(finding_id: str, tenant_id: str) -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM evidences WHERE finding_id = ? AND tenant_id = ? ORDER BY created_at DESC", (finding_id, tenant_id)).fetchall()
    return [Evidence(
        id=r["id"], tenant_id=r["tenant_id"], asset_id=r["asset_id"],
        scan_id=r["scan_id"], finding_id=r["finding_id"], type=r["type"],
        source=r["source"], content_hash=r["content_hash"],
        storage_reference=r["storage_reference"], mime_type=r["mime_type"],
        size_bytes=r["size_bytes"], created_at=r["created_at"],
        retention_class=r["retention_class"], classification=r["classification"],
        sanitized=bool(r["sanitized"]), redacted=bool(r["redacted"]),
        provenance=json.loads(r["provenance"] or "{}"), quality=r["quality"],
        payload=r["payload"]
    ) for r in rows]


def get_evidence_by_hash(tenant_id: str, content_hash: str) -> Optional[Evidence]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM evidences WHERE tenant_id = ? AND content_hash = ? LIMIT 1", (tenant_id, content_hash)).fetchone()
    if not row:
        return None
    return Evidence(
        id=row["id"], tenant_id=row["tenant_id"], asset_id=row["asset_id"],
        scan_id=row["scan_id"], finding_id=row["finding_id"], type=row["type"],
        source=row["source"], content_hash=row["content_hash"],
        storage_reference=row["storage_reference"], mime_type=row["mime_type"],
        size_bytes=row["size_bytes"], created_at=row["created_at"],
        retention_class=row["retention_class"], classification=row["classification"],
        sanitized=bool(row["sanitized"]), redacted=bool(row["redacted"]),
        provenance=json.loads(row["provenance"] or "{}"), quality=row["quality"],
        payload=row["payload"]
    )


# --- Policy Engine ---
@adapter_dispatch("save_policy")
def save_policy(policy: Policy) -> Policy:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if not policy.updated_at:
        policy.updated_at = now_iso
    existing = conn.execute("SELECT id FROM policies WHERE id = ?", (policy.id,)).fetchone()
    if existing:
        conn.execute("""
            UPDATE policies SET
                tenant_id = ?, name = ?, type = ?, active_version_id = ?, enabled = ?, updated_at = ?
            WHERE id = ?
        """, (
            policy.tenant_id, policy.name, policy.type,
            policy.active_version_id, 1 if policy.enabled else 0,
            policy.updated_at, policy.id
        ))
    else:
        conn.execute("""
            INSERT INTO policies (
                id, tenant_id, name, type, active_version_id, enabled, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            policy.id, policy.tenant_id, policy.name, policy.type,
            policy.active_version_id, 1 if policy.enabled else 0,
            policy.created_at, policy.updated_at
        ))
    conn.commit()
    return policy


@adapter_dispatch("get_policy")
def get_policy(policy_id: str, tenant_id: Optional[str] = None) -> Optional[Policy]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not row:
        return None
    return Policy(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        type=row["type"], active_version_id=row["active_version_id"],
        enabled=bool(row["enabled"]), created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_policies")
def list_policies(tenant_id: str) -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM policies WHERE tenant_id = ? ORDER BY name ASC", (tenant_id,)).fetchall()
    return [Policy(
        id=r["id"], tenant_id=r["tenant_id"], name=r["name"],
        type=r["type"], active_version_id=r["active_version_id"],
        enabled=bool(r["enabled"]), created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


@adapter_dispatch("save_policy_version")
def save_policy_version(version: PolicyVersion) -> PolicyVersion:
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO policy_versions (
            id, policy_id, version, status, definition_json, checksum,
            created_by, approved_by, created_at, activated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        version.id, version.policy_id, version.version, version.status,
        json.dumps(version.definition_json), version.checksum,
        version.created_by, version.approved_by, version.created_at, version.activated_at
    ))
    conn.commit()
    return version


@adapter_dispatch("get_policy_version")
def get_policy_version(version_id: str) -> Optional[PolicyVersion]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM policy_versions WHERE id = ?", (version_id,)).fetchone()
    if not row:
        return None
    return PolicyVersion(
        id=row["id"], policy_id=row["policy_id"], version=row["version"],
        status=row["status"], definition_json=json.loads(row["definition_json"] or "{}"),
        checksum=row["checksum"], created_by=row["created_by"],
        approved_by=row["approved_by"], created_at=row["created_at"], activated_at=row["activated_at"]
    )


@adapter_dispatch("list_policy_versions")
def list_policy_versions(policy_id: str) -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM policy_versions WHERE policy_id = ? ORDER BY version DESC", (policy_id,)).fetchall()
    return [PolicyVersion(
        id=r["id"], policy_id=r["policy_id"], version=r["version"],
        status=r["status"], definition_json=json.loads(r["definition_json"] or "{}"),
        checksum=r["checksum"], created_by=r["created_by"],
        approved_by=r["approved_by"], created_at=r["created_at"], activated_at=r["activated_at"]
    ) for r in rows]


# --- Business Units & Services ---
@adapter_dispatch("save_business_unit")
def save_business_unit(bu: BusinessUnit) -> BusinessUnit:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if not bu.updated_at:
        bu.updated_at = now_iso
    conn.execute("""
        INSERT OR REPLACE INTO business_units (
            id, tenant_id, name, code, parent_id, owner_user_id, criticality, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        bu.id, bu.tenant_id, bu.name, bu.code, bu.parent_id,
        bu.owner_user_id, bu.criticality, bu.created_at, bu.updated_at
    ))
    conn.commit()
    return bu


@adapter_dispatch("get_business_unit")
def get_business_unit(bu_id: str, tenant_id: Optional[str] = None) -> Optional[BusinessUnit]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM business_units WHERE id = ? AND tenant_id = ?", (bu_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM business_units WHERE id = ?", (bu_id,)).fetchone()
    if not row:
        return None
    return BusinessUnit(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        code=row["code"], parent_id=row["parent_id"], owner_user_id=row["owner_user_id"],
        criticality=row["criticality"], created_at=row["created_at"], updated_at=row["updated_at"]
    )


@adapter_dispatch("list_business_units")
def list_business_units(tenant_id: str) -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM business_units WHERE tenant_id = ? ORDER BY name ASC", (tenant_id,)).fetchall()
    return [BusinessUnit(
        id=r["id"], tenant_id=r["tenant_id"], name=r["name"],
        code=r["code"], parent_id=r["parent_id"], owner_user_id=r["owner_user_id"],
        criticality=r["criticality"], created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


def save_business_service(service: BusinessService) -> BusinessService:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if not service.updated_at:
        service.updated_at = now_iso
    conn.execute("""
        INSERT OR REPLACE INTO business_services (
            id, tenant_id, name, business_unit_id, criticality, owner_user_id, description, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        service.id, service.tenant_id, service.name, service.business_unit_id,
        service.criticality, service.owner_user_id, service.description,
        service.created_at, service.updated_at
    ))
    conn.commit()
    return service


def get_business_service(service_id: str, tenant_id: Optional[str] = None) -> Optional[BusinessService]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM business_services WHERE id = ? AND tenant_id = ?", (service_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM business_services WHERE id = ?", (service_id,)).fetchone()
    if not row:
        return None
    return BusinessService(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        business_unit_id=row["business_unit_id"], criticality=row["criticality"],
        owner_user_id=row["owner_user_id"], description=row["description"],
        created_at=row["created_at"], updated_at=row["updated_at"]
    )


def list_business_services(tenant_id: str, bu_id: Optional[str] = None) -> list:
    conn = _get_conn()
    query = "SELECT * FROM business_services WHERE tenant_id = ?"
    params = [tenant_id]
    if bu_id:
        query += " AND business_unit_id = ?"
        params.append(bu_id)
    query += " ORDER BY name ASC"
    rows = conn.execute(query, params).fetchall()
    return [BusinessService(
        id=r["id"], tenant_id=r["tenant_id"], name=r["name"],
        business_unit_id=r["business_unit_id"], criticality=r["criticality"],
        owner_user_id=r["owner_user_id"], description=r["description"],
        created_at=r["created_at"], updated_at=r["updated_at"]
    ) for r in rows]


# --- Data Quality Issues ---
def save_data_quality_issue(issue: DataQualityIssue) -> DataQualityIssue:
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO data_quality_issues (
            id, tenant_id, entity_type, entity_id, issue_type, severity,
            description, detected_at, resolved_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        issue.id, issue.tenant_id, issue.entity_type, issue.entity_id,
        issue.issue_type, issue.severity, issue.description,
        issue.detected_at, issue.resolved_at
    ))
    conn.commit()
    return issue


@adapter_dispatch("list_data_quality_issues")
def list_data_quality_issues(tenant_id: str, unresolved_only: bool = True) -> list:
    conn = _get_conn()
    query = "SELECT * FROM data_quality_issues WHERE tenant_id = ?"
    params = [tenant_id]
    if unresolved_only:
        query += " AND resolved_at IS NULL"
    query += " ORDER BY detected_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [DataQualityIssue(
        id=r["id"], tenant_id=r["tenant_id"], entity_type=r["entity_type"],
        entity_id=r["entity_id"], issue_type=r["issue_type"],
        severity=r["severity"], description=r["description"],
        detected_at=r["detected_at"], resolved_at=r["resolved_at"]
    ) for r in rows]


def resolve_data_quality_issues_for_entity(tenant_id: str, entity_type: str, entity_id: str):
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        UPDATE data_quality_issues SET resolved_at = ?
        WHERE tenant_id = ? AND entity_type = ? AND entity_id = ? AND resolved_at IS NULL
    """, (now_iso, tenant_id, entity_type, entity_id))
    conn.commit()


# --- Integration Outbox ---
@adapter_dispatch("save_outbox_event")
def save_outbox_event(outbox: IntegrationOutbox) -> IntegrationOutbox:
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO integration_outbox (
            id, tenant_id, event_type, event_key, destination, payload_hash,
            payload_json, status, attempt, next_retry_at, last_error, claimed_at, claimed_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        outbox.id, outbox.tenant_id, outbox.event_type, outbox.event_key,
        outbox.destination, outbox.payload_hash, json.dumps(outbox.payload_json),
        outbox.status, outbox.attempt, outbox.next_retry_at, outbox.last_error,
        getattr(outbox, "claimed_at", None), getattr(outbox, "claimed_by", None),
        outbox.created_at
    ))
    conn.commit()
    return outbox


@adapter_dispatch("get_pending_outbox_events")
def get_pending_outbox_events(limit: int = 50) -> list:
    conn = _get_conn()
    rows = conn.execute("""
        SELECT * FROM integration_outbox
        WHERE status IN ('PENDING', 'RETRYING')
        ORDER BY created_at ASC LIMIT ?
    """, (limit,)).fetchall()
    return [IntegrationOutbox(
        id=r["id"], tenant_id=r["tenant_id"], event_type=r["event_type"],
        event_key=r["event_key"], destination=r["destination"], payload_hash=r["payload_hash"],
        payload_json=json.loads(r["payload_json"] or "{}"), status=r["status"],
        attempt=r["attempt"], next_retry_at=r["next_retry_at"], last_error=r["last_error"],
        claimed_at=r["claimed_at"] if "claimed_at" in r.keys() else None,
        claimed_by=r["claimed_by"] if "claimed_by" in r.keys() else None,
        created_at=r["created_at"]
    ) for r in rows]


@adapter_dispatch("update_outbox_status")
def update_outbox_status(event_id: str, status: str, last_error: Optional[str] = None):
    conn = _get_conn()
    conn.execute("UPDATE integration_outbox SET status = ?, last_error = ? WHERE id = ?", (status, last_error, event_id))
    conn.commit()


@adapter_dispatch("claim_outbox_events")
def claim_outbox_events(limit: int = 50, worker_id: Optional[str] = None) -> list:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = conn.execute("""
        SELECT * FROM integration_outbox
        WHERE status IN ('PENDING', 'RETRYING')
        ORDER BY created_at ASC LIMIT ?
    """, (limit,)).fetchall()
    claimed = []
    for r in rows:
        conn.execute("""
            UPDATE integration_outbox
            SET status = 'PROCESSING', claimed_at = ?, claimed_by = ?
            WHERE id = ?
        """, (now_iso, worker_id, r["id"]))
        claimed.append(IntegrationOutbox(
            id=r["id"], tenant_id=r["tenant_id"], event_type=r["event_type"],
            event_key=r["event_key"], destination=r["destination"], payload_hash=r["payload_hash"],
            payload_json=json.loads(r["payload_json"] or "{}"), status="PROCESSING",
            attempt=r["attempt"], next_retry_at=r["next_retry_at"], last_error=r["last_error"],
            claimed_at=now_iso, claimed_by=worker_id, created_at=r["created_at"]
        ))
    conn.commit()
    return claimed


@adapter_dispatch("mark_outbox_event_processed")
def mark_outbox_event_processed(event_id: str, status: str = "PUBLISHED") -> bool:
    conn = _get_conn()
    cur = conn.execute("UPDATE integration_outbox SET status = ? WHERE id = ?", (status, event_id))
    conn.commit()
    return bool(cur.rowcount > 0 if hasattr(cur, "rowcount") else True)


@adapter_dispatch("mark_outbox_event_failed")
def mark_outbox_event_failed(
    event_id: str,
    error: str,
    max_retries: int = 5,
    backoff_base_seconds: int = 30
) -> Optional[IntegrationOutbox]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM integration_outbox WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return None
    attempt = (row["attempt"] or 0) + 1
    now = datetime.now(timezone.utc)
    if attempt >= max_retries:
        new_status = "DEAD_LETTER"
        next_retry = None
    else:
        new_status = "RETRYING"
        delay = backoff_base_seconds * (2 ** (attempt - 1))
        next_retry = (now + timedelta(seconds=delay)).isoformat()
    
    conn.execute("""
        UPDATE integration_outbox
        SET status = ?, attempt = ?, next_retry_at = ?, last_error = ?,
            claimed_at = NULL, claimed_by = NULL
        WHERE id = ?
    """, (new_status, attempt, next_retry, error, event_id))
    conn.commit()
    updated = conn.execute("SELECT * FROM integration_outbox WHERE id = ?", (event_id,)).fetchone()
    if not updated:
        return None
    return IntegrationOutbox(
        id=updated["id"], tenant_id=updated["tenant_id"], event_type=updated["event_type"],
        event_key=updated["event_key"], destination=updated["destination"], payload_hash=updated["payload_hash"],
        payload_json=json.loads(updated["payload_json"] or "{}"), status=updated["status"],
        attempt=updated["attempt"], next_retry_at=updated["next_retry_at"], last_error=updated["last_error"],
        claimed_at=updated["claimed_at"] if "claimed_at" in updated.keys() else None,
        claimed_by=updated["claimed_by"] if "claimed_by" in updated.keys() else None,
        created_at=updated["created_at"]
    )


@adapter_dispatch("recover_stale_outbox_events")
def recover_stale_outbox_events(timeout_seconds: int = 300) -> int:
    conn = _get_conn()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)).isoformat()
    cur = conn.execute("""
        UPDATE integration_outbox
        SET status = 'RETRYING', claimed_at = NULL, claimed_by = NULL
        WHERE status = 'PROCESSING' AND (claimed_at IS NULL OR claimed_at < ?)
    """, (cutoff,))
    conn.commit()
    return cur.rowcount if hasattr(cur, "rowcount") else 0


@adapter_dispatch("get_outbox_event")
def get_outbox_event(event_id: str, tenant_id: Optional[str] = None) -> Optional[IntegrationOutbox]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM integration_outbox WHERE id = ? AND tenant_id = ?", (event_id, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM integration_outbox WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return None
    return IntegrationOutbox(
        id=row["id"], tenant_id=row["tenant_id"], event_type=row["event_type"],
        event_key=row["event_key"], destination=row["destination"], payload_hash=row["payload_hash"],
        payload_json=json.loads(row["payload_json"] or "{}"), status=row["status"],
        attempt=row["attempt"], next_retry_at=row["next_retry_at"], last_error=row["last_error"],
        claimed_at=row["claimed_at"] if "claimed_at" in row.keys() else None,
        claimed_by=row["claimed_by"] if "claimed_by" in row.keys() else None,
        created_at=row["created_at"]
    )


@adapter_dispatch("get_outbox_event_by_key")
def get_outbox_event_by_key(event_key: str, tenant_id: Optional[str] = None) -> Optional[IntegrationOutbox]:
    conn = _get_conn()
    if tenant_id:
        row = conn.execute("SELECT * FROM integration_outbox WHERE event_key = ? AND tenant_id = ?", (event_key, tenant_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM integration_outbox WHERE event_key = ?", (event_key,)).fetchone()
    if not row:
        return None
    return IntegrationOutbox(
        id=row["id"], tenant_id=row["tenant_id"], event_type=row["event_type"],
        event_key=row["event_key"], destination=row["destination"], payload_hash=row["payload_hash"],
        payload_json=json.loads(row["payload_json"] or "{}"), status=row["status"],
        attempt=row["attempt"], next_retry_at=row["next_retry_at"], last_error=row["last_error"],
        claimed_at=row["claimed_at"] if "claimed_at" in row.keys() else None,
        claimed_by=row["claimed_by"] if "claimed_by" in row.keys() else None,
        created_at=row["created_at"]
    )


# --- Technology Inventory ---
@adapter_dispatch("save_technology_observation")
def save_technology_observation(obs: TechnologyObservation) -> TechnologyObservation:
    conn = _get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    if not obs.updated_at:
        obs.updated_at = now_iso
    conn.execute("""
        INSERT OR REPLACE INTO technology_observations (
            id, tenant_id, asset_id, technology_type, name, version,
            source, confidence, eol_status, first_seen, last_seen, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        obs.id, obs.tenant_id, obs.asset_id, obs.technology_type, obs.name,
        obs.version, obs.source, obs.confidence, obs.eol_status,
        obs.first_seen, obs.last_seen, obs.created_at, obs.updated_at
    ))
    conn.commit()
    return obs


@adapter_dispatch("list_technology_observations")
def list_technology_observations(tenant_id: str, asset_id: Optional[str] = None) -> list:
    conn = _get_conn()
    query = "SELECT * FROM technology_observations WHERE tenant_id = ?"
    params = [tenant_id]
    if asset_id:
        query += " AND asset_id = ?"
        params.append(asset_id)
    query += " ORDER BY last_seen DESC"
    rows = conn.execute(query, params).fetchall()
    return [TechnologyObservation(
        id=r["id"], tenant_id=r["tenant_id"], asset_id=r["asset_id"],
        technology_type=r["technology_type"], name=r["name"], version=r["version"],
        source=r["source"], confidence=r["confidence"], eol_status=r["eol_status"],
        first_seen=r["first_seen"], last_seen=r["last_seen"], created_at=r["created_at"],
        updated_at=r["updated_at"]
    ) for r in rows]


# --- Saved Views ---
def save_saved_view(view: SavedView) -> SavedView:
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO saved_views (
            id, tenant_id, user_id, name, resource_type, filters_json, is_shared, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        view.id, view.tenant_id, view.user_id, view.name, view.resource_type,
        json.dumps(view.filters_json), 1 if view.is_shared else 0, view.created_at
    ))
    conn.commit()
    return view


def get_saved_view(view_id: str, tenant_id: str) -> Optional[SavedView]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM saved_views WHERE id = ? AND tenant_id = ?", (view_id, tenant_id)).fetchone()
    if not row:
        return None
    return SavedView(
        id=row["id"], tenant_id=row["tenant_id"], user_id=row["user_id"],
        name=row["name"], resource_type=row["resource_type"],
        filters_json=json.loads(row["filters_json"] or "{}"),
        is_shared=bool(row["is_shared"]), created_at=row["created_at"]
    )


@adapter_dispatch("list_saved_views")
def list_saved_views(tenant_id: str, user_id: Optional[str] = None) -> list:
    conn = _get_conn()
    if user_id:
        rows = conn.execute("""
            SELECT * FROM saved_views
            WHERE tenant_id = ? AND (user_id = ? OR is_shared = 1)
            ORDER BY name ASC
        """, (tenant_id, user_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM saved_views WHERE tenant_id = ? ORDER BY name ASC", (tenant_id,)).fetchall()
    return [SavedView(
        id=r["id"], tenant_id=r["tenant_id"], user_id=r["user_id"],
        name=r["name"], resource_type=r["resource_type"],
        filters_json=json.loads(r["filters_json"] or "{}"),
        is_shared=bool(r["is_shared"]), created_at=r["created_at"]
    ) for r in rows]


# --- Portfolio Governance & Aggregated Metrics ---
@adapter_dispatch("get_portfolio_metrics")
def get_portfolio_metrics(tenant_id: str, bu_id: Optional[str] = None) -> dict:
    conn = _get_conn()
    asset_filter = "WHERE a.tenant_id = ?"
    finding_filter = "WHERE f.tenant_id = ?"
    params = [tenant_id]
    if bu_id:
        asset_filter += " AND a.business_unit_id = ?"
        finding_filter += " AND a.business_unit_id = ?"
        params.append(bu_id)

    # Asset metrics
    asset_row = conn.execute(f"""
        SELECT
            COUNT(a.id) as total_assets,
            SUM(CASE WHEN a.criticality = 'critical' THEN 1 ELSE 0 END) as critical_assets,
            SUM(CASE WHEN a.internet_exposure = 'external' THEN 1 ELSE 0 END) as internet_facing,
            SUM(CASE WHEN a.business_owner != '' AND a.business_owner IS NOT NULL THEN 1 ELSE 0 END) as has_biz_owner,
            SUM(CASE WHEN a.technical_owner != '' AND a.technical_owner IS NOT NULL THEN 1 ELSE 0 END) as has_tech_owner,
            SUM(CASE WHEN a.business_unit_id IS NOT NULL AND a.business_unit_id != '' THEN 1 ELSE 0 END) as assigned_to_bu
        FROM assets a
        {asset_filter}
    """, params).fetchone()

    # Verification count
    ver_params = [tenant_id]
    ver_join = ""
    if bu_id:
        ver_join = "JOIN assets a ON v.asset_id = a.id AND a.business_unit_id = ?"
        ver_params.append(bu_id)
    ver_row = conn.execute(f"""
        SELECT COUNT(DISTINCT v.asset_id) as verified_assets
        FROM asset_verifications v
        {ver_join}
        WHERE v.tenant_id = ? AND v.status = 'VERIFIED'
    """, ver_params).fetchone()

    # Findings metrics
    f_params = [tenant_id]
    if bu_id:
        f_params.append(bu_id)
    finding_row = conn.execute(f"""
        SELECT
            COUNT(f.id) as total_open_findings,
            SUM(CASE WHEN f.priority_band = 'P1' THEN 1 ELSE 0 END) as open_p1,
            SUM(CASE WHEN f.priority_band = 'P2' THEN 1 ELSE 0 END) as open_p2,
            SUM(CASE WHEN f.kev = 1 THEN 1 ELSE 0 END) as open_kev,
            SUM(CASE WHEN f.sla_status = 'BREACHED' THEN 1 ELSE 0 END) as sla_breaches,
            SUM(CASE WHEN f.status = 'ACCEPTED' THEN 1 ELSE 0 END) as risk_accepted,
            SUM(CASE WHEN f.assigned_to_user_id IS NULL OR f.assigned_to_user_id = '' THEN 1 ELSE 0 END) as unassigned_findings,
            SUM(CASE WHEN f.finding_confidence IN ('HIGH', 'CONFIRMED') THEN 1 ELSE 0 END) as high_confidence_findings
        FROM findings f
        JOIN assets a ON f.asset_id = a.id
        {finding_filter} AND f.status NOT IN ('RESOLVED', 'CLOSED', 'FALSE_POSITIVE')
    """, f_params).fetchone()

    # Discovery candidates
    candidate_row = conn.execute(
        "SELECT COUNT(*) as candidates FROM discovered_assets WHERE tenant_id = ? AND status = 'NEW'",
        (tenant_id,)
    ).fetchone()

    total_assets = asset_row["total_assets"] if asset_row else 0
    verified_count = ver_row["verified_assets"] if ver_row else 0

    return {
        "assets": total_assets,
        "verified_assets": verified_count,
        "unverified_assets": max(0, total_assets - verified_count),
        "internet_facing_assets": (asset_row["internet_facing"] or 0) if asset_row else 0,
        "critical_assets": (asset_row["critical_assets"] or 0) if asset_row else 0,
        "open_p1": (finding_row["open_p1"] or 0) if finding_row else 0,
        "open_p2": (finding_row["open_p2"] or 0) if finding_row else 0,
        "open_kev": (finding_row["open_kev"] or 0) if finding_row else 0,
        "sla_breaches": (finding_row["sla_breaches"] or 0) if finding_row else 0,
        "risk_accepted": (finding_row["risk_accepted"] or 0) if finding_row else 0,
        "unassigned_findings": (finding_row["unassigned_findings"] or 0) if finding_row else 0,
        "high_confidence_findings": (finding_row["high_confidence_findings"] or 0) if finding_row else 0,
        "discovery_candidates": candidate_row["candidates"] if candidate_row else 0,
        "business_owner_coverage_pct": round(((asset_row["has_biz_owner"] or 0) / max(1, total_assets)) * 100, 1) if asset_row else 0.0,
        "technical_owner_coverage_pct": round(((asset_row["has_tech_owner"] or 0) / max(1, total_assets)) * 100, 1) if asset_row else 0.0,
        "bu_assignment_coverage_pct": round(((asset_row["assigned_to_bu"] or 0) / max(1, total_assets)) * 100, 1) if asset_row else 0.0,
        "verification_coverage_pct": round((verified_count / max(1, total_assets)) * 100, 1)
    }




# --- Sprint 3 Phase 9: Monitoring Dashboard Data Layer ---
@adapter_dispatch("get_monitoring_dashboard")
def get_monitoring_dashboard(tenant_id: str) -> dict:
    """
    Returns a consolidated monitoring visibility snapshot for a tenant.

    Metrics included:
      - total_assets / monitored_assets / paused_assets
      - assets_needing_attention (last scan failed or not yet scanned)
      - last_scan_status breakdown (completed/failed/running/never)
      - critical_findings / high_findings (open severity counts)
      - newly_discovered_last_24h (findings created in the last 24 hours)
      - resolved_last_24h (findings transitioned to VERIFIED/CLOSED last 24h)
      - scan_failures_last_24h (assets with last_scan_status=failed in last 24h)
      - intel_freshness (seconds since last successful intelligence sync)
      - scheduled_scans_total / scheduled_scans_paused
      - historical_risk_trend (last 7 days from daily_risk_snapshots)

    Alert deduplication is handled in the outbox: see core/intel_monitor.py.
    No secrets are returned in this payload.
    """
    conn = _get_conn()
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    cutoff_24h = (now - timedelta(hours=24)).isoformat()

    # --- Asset monitoring summary ---
    asset_row = conn.execute("""
        SELECT
            COUNT(*) as total_assets,
            SUM(CASE WHEN monitoring_enabled = 1 THEN 1 ELSE 0 END) as monitored_assets,
            SUM(CASE WHEN monitoring_paused_at IS NOT NULL THEN 1 ELSE 0 END) as paused_assets,
            SUM(CASE WHEN last_scan_status = 'failed' OR last_scan_id IS NULL THEN 1 ELSE 0 END) as needs_attention,
            SUM(CASE WHEN last_scan_status = 'completed' THEN 1 ELSE 0 END) as last_completed,
            SUM(CASE WHEN last_scan_status = 'failed' THEN 1 ELSE 0 END) as last_failed,
            SUM(CASE WHEN last_scan_status = 'running' THEN 1 ELSE 0 END) as last_running,
            SUM(CASE WHEN last_scan_id IS NULL THEN 1 ELSE 0 END) as never_scanned
        FROM assets WHERE tenant_id = ? AND status = 'active'
    """, (tenant_id,)).fetchone()

    # --- Finding severity summary (open only) ---
    finding_row = conn.execute("""
        SELECT
            SUM(CASE WHEN severity = 'critical' AND status NOT IN ('VERIFIED','CLOSED','FALSE_POSITIVE','REMEDIATED') THEN 1 ELSE 0 END) as critical_findings,
            SUM(CASE WHEN severity = 'high' AND status NOT IN ('VERIFIED','CLOSED','FALSE_POSITIVE','REMEDIATED') THEN 1 ELSE 0 END) as high_findings
        FROM findings WHERE tenant_id = ?
    """, (tenant_id,)).fetchone()

    # --- New findings in last 24h ---
    new_row = conn.execute(
        "SELECT COUNT(*) as cnt FROM findings WHERE tenant_id = ? AND created_at >= ?",
        (tenant_id, cutoff_24h)
    ).fetchone()

    # --- Resolved findings in last 24h (via finding_history) ---
    resolved_row = conn.execute("""
        SELECT COUNT(*) as cnt FROM finding_history fh
        JOIN findings f ON fh.finding_id = f.id
        WHERE f.tenant_id = ?
          AND fh.new_status IN ('VERIFIED','CLOSED','REMEDIATED')
          AND fh.created_at >= ?
    """, (tenant_id, cutoff_24h)).fetchone()

    # --- Scan failures in last 24h ---
    fail_row = conn.execute(
        "SELECT COUNT(*) as cnt FROM assets WHERE tenant_id = ? AND last_scan_status = 'failed' AND last_scan_at >= ?",
        (tenant_id, cutoff_24h)
    ).fetchone()

    # --- Scheduled scans summary ---
    sched_row = conn.execute("""
        SELECT
            COUNT(*) as total_scheduled,
            SUM(CASE WHEN paused_until IS NOT NULL THEN 1 ELSE 0 END) as paused_scheduled
        FROM scheduled_scans WHERE tenant_id = ?
    """, (tenant_id,)).fetchone()

    # --- Intel freshness (seconds since last successful sync) ---
    intel_freshness_seconds: Optional[int] = None
    try:
        statuses = list_intel_sync_statuses()
        freshest = None
        for s in statuses:
            if s.last_success:
                try:
                    ts = datetime.fromisoformat(s.last_success)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if freshest is None or ts > freshest:
                        freshest = ts
                except Exception:
                    pass
        if freshest:
            intel_freshness_seconds = int((now - freshest).total_seconds())
    except Exception:
        pass

    # --- Historical risk trend (last 7 days) ---
    risk_trend = []
    try:
        snapshots = get_daily_risk_snapshots(tenant_id, days=7)
        risk_trend = [
            {"date": s.date, "risk_score_avg": s.risk_score_avg, "open_findings": s.open_findings}
            for s in snapshots
        ]
    except Exception:
        pass

    return {
        "total_assets": int(asset_row["total_assets"] or 0) if asset_row else 0,
        "monitored_assets": int(asset_row["monitored_assets"] or 0) if asset_row else 0,
        "paused_assets": int(asset_row["paused_assets"] or 0) if asset_row else 0,
        "assets_needing_attention": int(asset_row["needs_attention"] or 0) if asset_row else 0,
        "last_scan_status": {
            "completed": int(asset_row["last_completed"] or 0) if asset_row else 0,
            "failed": int(asset_row["last_failed"] or 0) if asset_row else 0,
            "running": int(asset_row["last_running"] or 0) if asset_row else 0,
            "never_scanned": int(asset_row["never_scanned"] or 0) if asset_row else 0,
        },
        "critical_findings": int(finding_row["critical_findings"] or 0) if finding_row else 0,
        "high_findings": int(finding_row["high_findings"] or 0) if finding_row else 0,
        "newly_discovered_last_24h": int(new_row["cnt"] or 0) if new_row else 0,
        "resolved_last_24h": int(resolved_row["cnt"] or 0) if resolved_row else 0,
        "scan_failures_last_24h": int(fail_row["cnt"] or 0) if fail_row else 0,
        "scheduled_scans_total": int(sched_row["total_scheduled"] or 0) if sched_row else 0,
        "scheduled_scans_paused": int(sched_row["paused_scheduled"] or 0) if sched_row else 0,
        "intel_freshness_seconds": intel_freshness_seconds,
        "historical_risk_trend": risk_trend,
        "generated_at": now.isoformat(),
    }

