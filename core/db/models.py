"""
SQLAlchemy 2.x Declarative ORM Models for SentinelWP Enterprise Architecture.
Defines real Foreign Keys, compound indexes, constraints, and JSON support.
"""
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    Text,
    ForeignKey,
    Index,
    UniqueConstraint,
    CheckConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db.base import Base, SafeJSON, utcnow_str


class TenantModel(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Relationships
    users: Mapped[List["UserModel"]] = relationship("UserModel", back_populates="tenant", cascade="all, delete-orphan")
    assets: Mapped[List["AssetModel"]] = relationship("AssetModel", back_populates="tenant", cascade="all, delete-orphan")
    scans: Mapped[List["ScanModel"]] = relationship("ScanModel", back_populates="tenant", cascade="all, delete-orphan")
    findings: Mapped[List["FindingModel"]] = relationship("FindingModel", back_populates="tenant", cascade="all, delete-orphan")
    scheduled_scans: Mapped[List["ScheduledScanModel"]] = relationship("ScheduledScanModel", back_populates="tenant", cascade="all, delete-orphan")
    audit_events: Mapped[List["AuditEventModel"]] = relationship("AuditEventModel", back_populates="tenant", cascade="all, delete-orphan")
    scan_jobs: Mapped[List["ScanJobModel"]] = relationship("ScanJobModel", back_populates="tenant", cascade="all, delete-orphan")


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="viewer", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)

    tenant: Mapped["TenantModel"] = relationship("TenantModel", back_populates="users")

    __table_args__ = (
        UniqueConstraint("tenant_id", "username", name="uq_users_tenant_username"),
    )


class AssetModel(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    canonical_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    business_owner: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    technical_owner: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="production", nullable=False)
    internet_exposure: Mapped[str] = mapped_column(String(64), default="external", nullable=False)
    criticality: Mapped[str] = mapped_column(String(64), default="medium", nullable=False)
    data_classification: Mapped[str] = mapped_column(String(64), default="confidential", nullable=False)
    authorization_status: Mapped[str] = mapped_column(String(64), default="unauthorized", nullable=False)
    authorization_review_date: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    tags: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)
    business_unit_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    tenant: Mapped["TenantModel"] = relationship("TenantModel", back_populates="assets")
    authorizations: Mapped[List["ScanAuthorizationModel"]] = relationship("ScanAuthorizationModel", back_populates="asset", cascade="all, delete-orphan")
    scans: Mapped[List["ScanModel"]] = relationship("ScanModel", back_populates="asset")
    findings: Mapped[List["FindingModel"]] = relationship("FindingModel", back_populates="asset")

    __table_args__ = (
        UniqueConstraint("tenant_id", "canonical_url", name="uq_assets_tenant_canonical_url"),
        Index("idx_assets_tenant_status", "tenant_id", "status"),
        Index("idx_assets_tenant_created", "tenant_id", "created_at"),
    )


class ScanAuthorizationModel(Base):
    __tablename__ = "scan_authorizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)
    allowed_profiles: Mapped[str] = mapped_column(String(255), default="safe_active,passive", nullable=False)
    request_budget: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    valid_from: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    valid_until: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    asset: Mapped["AssetModel"] = relationship("AssetModel", back_populates="authorizations")

    __table_args__ = (
        Index("idx_scan_auth_asset_status", "asset_id", "status"),
    )


class ScanModel(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    scan_mode: Mapped[str] = mapped_column(String(64), default="passive", nullable=False)
    started_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    grade: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tags: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    initiated_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    # Canonical WordPress detection metadata fields
    wordpress_detected: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    wordpress_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    wordpress_version_source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    wordpress_version_confidence: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    # Backward compatibility aliases
    wp_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    wp_version_source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    wp_version_confidence: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    is_wordpress: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    whois_info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    tenant: Mapped["TenantModel"] = relationship("TenantModel", back_populates="scans")
    asset: Mapped[Optional["AssetModel"]] = relationship("AssetModel", back_populates="scans")
    findings: Mapped[List["FindingModel"]] = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    scan_jobs: Mapped[List["ScanJobModel"]] = relationship("ScanJobModel", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_tenant_status", "tenant_id", "status"),
        Index("idx_scans_tenant_started", "tenant_id", "started_at"),
        Index("idx_scans_asset_started", "asset_id", "started_at"),
    )


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(128), default="", nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="info", nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reference: Mapped[str] = mapped_column(Text, default="", nullable=False)
    raw_data: Mapped[Dict[str, Any]] = mapped_column(SafeJSON, default=dict, nullable=False)

    # Phase 4 Enterprise Lifecycle & Fingerprinting
    fingerprint: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False, index=True)
    first_seen_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    last_seen_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    first_scan_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    last_scan_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    assigned_to_user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    assigned_team: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    assigned_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    finding_tags: Mapped[List[str]] = mapped_column(SafeJSON, default=list, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Vulnerability Prioritization
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    priority_band: Mapped[str] = mapped_column(String(16), default="P3", nullable=False, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_last_updated: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    kev_date_added: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    kev_due_date: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    known_ransomware_campaign_use: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ransomware_relevance: Mapped[str] = mapped_column(String(32), default="NONE", nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # SLA Governance
    sla_policy_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    sla_due_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    sla_status: Mapped[str] = mapped_column(String(32), default="NOT_APPLICABLE", nullable=False, index=True)
    sla_paused_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    sla_pause_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Verification & False Positive
    verified_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    verified_by_scan_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    false_positive_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    false_positive_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    false_positive_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    false_positive_valid_until: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    finding_confidence: Mapped[str] = mapped_column(String(32), default="HIGH", nullable=False, index=True)
    policy_version_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    tenant: Mapped["TenantModel"] = relationship("TenantModel", back_populates="findings")
    asset: Mapped[Optional["AssetModel"]] = relationship("AssetModel", back_populates="findings")
    scan: Mapped["ScanModel"] = relationship("ScanModel", back_populates="findings")

    # Relationships to lifecycle and governance
    observations: Mapped[List["FindingObservationModel"]] = relationship("FindingObservationModel", back_populates="finding", cascade="all, delete-orphan")
    history_entries: Mapped[List["FindingHistoryModel"]] = relationship("FindingHistoryModel", back_populates="finding", cascade="all, delete-orphan")
    comments: Mapped[List["FindingCommentModel"]] = relationship("FindingCommentModel", back_populates="finding", cascade="all, delete-orphan")
    remediations: Mapped[List["RemediationModel"]] = relationship("RemediationModel", back_populates="finding", cascade="all, delete-orphan")
    risk_acceptances: Mapped[List["RiskAcceptanceModel"]] = relationship("RiskAcceptanceModel", back_populates="finding", cascade="all, delete-orphan")
    ticket_references: Mapped[List["TicketReferenceModel"]] = relationship("TicketReferenceModel", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_findings_scan_severity", "scan_id", "severity"),
        Index("idx_findings_tenant_severity", "tenant_id", "severity"),
        Index("idx_findings_tenant_status", "tenant_id", "status"),
        Index("idx_findings_tenant_fingerprint", "tenant_id", "fingerprint"),
        Index("idx_findings_tenant_priority", "tenant_id", "priority_score"),
        Index("idx_findings_asset_created", "asset_id", "created_at"),
    )


class ScheduledScanModel(Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    scan_mode: Mapped[str] = mapped_column(String(64), default="passive", nullable=False)
    interval_hours: Mapped[int] = mapped_column(Integer, default=24, nullable=False)
    last_run_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    next_run_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_failure_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_success_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    paused_until: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    tenant: Mapped["TenantModel"] = relationship("TenantModel", back_populates="scheduled_scans")
    runs: Mapped[List["ScheduledRunModel"]] = relationship("ScheduledRunModel", back_populates="schedule", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("interval_hours > 0", name="chk_scheduled_scan_interval_positive"),
        Index("idx_sched_enabled_next", "enabled", "next_run_at"),
        Index("idx_sched_tenant_enabled", "tenant_id", "enabled"),
    )


class ScheduledRunModel(Base):
    __tablename__ = "scheduled_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schedule_id: Mapped[str] = mapped_column(String(64), ForeignKey("scheduled_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    planned_at: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    started_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scan_job_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)

    schedule: Mapped["ScheduledScanModel"] = relationship("ScheduledScanModel", back_populates="runs")

    __table_args__ = (
        UniqueConstraint("schedule_id", "planned_at", name="uq_scheduled_run_id_planned"),
        Index("idx_sched_run_tenant_status", "tenant_id", "status"),
    )


class ScanJobModel(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    task_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    profile: Mapped[str] = mapped_column(String(64), default="passive", nullable=False)
    queued_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)
    started_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    failed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cancelled_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_step: Mapped[str] = mapped_column(String(255), default="Initialized", nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    worker_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    heartbeat_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    policy_version_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    tenant: Mapped["TenantModel"] = relationship("TenantModel", back_populates="scan_jobs")
    scan: Mapped["ScanModel"] = relationship("ScanModel", back_populates="scan_jobs")

    __table_args__ = (
        Index("idx_scan_jobs_tenant_status", "tenant_id", "status"),
        Index("idx_scan_jobs_status_heartbeat", "status", "heartbeat_at"),
        Index("idx_scan_jobs_asset_status", "asset_id", "status"),
    )


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_user_id: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    actor_username: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(128), default="", nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    result: Mapped[str] = mapped_column(String(32), default="success", nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", SafeJSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)

    tenant: Mapped["TenantModel"] = relationship("TenantModel", back_populates="audit_events")

    __table_args__ = (
        Index("idx_audit_tenant_created", "tenant_id", "created_at"),
    )


class IntelSyncStatusModel(Base):
    __tablename__ = "intelligence_sync_status"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    last_success: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_attempt: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    records_processed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    freshness_age_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


# --- Vulnerability Intelligence Subsystem Tables ---

class VulnerabilityRecordModel(Base):
    __tablename__ = "vulnerability_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    wordfence_id: Mapped[Optional[str]] = mapped_column(String(128), unique=True, nullable=True, index=True)
    cve: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True, index=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cvss_rating: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    cwe_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cwe_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    published: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="wordfence", nullable=False, index=True)
    informational: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    references_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)


class VulnerabilitySoftwareModel(Base):
    __tablename__ = "vulnerability_software"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerability_records.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(64), default="plugin", nullable=False, index=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    slug: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    patched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    patched_versions_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)


class VulnerabilityAffectedRangeModel(Base):
    __tablename__ = "vulnerability_affected_ranges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    software_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerability_software.id", ondelete="CASCADE"), nullable=False, index=True)
    from_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    from_inclusive: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    to_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    to_inclusive: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class VulnerabilityReferenceModel(Base):
    __tablename__ = "vulnerability_references"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerability_records.id", ondelete="CASCADE"), nullable=False, index=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class PluginMetadataModel(Base):
    __tablename__ = "plugin_metadata"

    slug: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    active_installs: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    current_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_updated: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    tested_wp_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fetched_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class CisaKevRecordModel(Base):
    __tablename__ = "cisa_kev_records"

    cve: Mapped[str] = mapped_column(String(64), primary_key=True)
    date_added: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vulnerability_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    required_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    due_date: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ransomware_use: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class VulnerabilitySyncStateModel(Base):
    __tablename__ = "vulnerability_sync_state"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_success_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_attempt_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="never", nullable=False)
    inserted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unchanged: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)


class VulnIntelSettingModel(Base):
    __tablename__ = "vuln_intel_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ==============================================================================
# PHASE 4: REMEDIATION, SLA, GOVERNANCE & INTEGRATIONS MODELS
# ==============================================================================

class FindingObservationModel(Base):
    __tablename__ = "finding_observations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scanner_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="info", nullable=False)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    evidence_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False)
    raw_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)

    finding: Mapped["FindingModel"] = relationship("FindingModel", back_populates="observations")
    scan: Mapped["ScanModel"] = relationship("ScanModel")

    __table_args__ = (
        UniqueConstraint("finding_id", "scan_id", name="uq_obs_finding_scan"),
        Index("idx_observations_finding_time", "finding_id", "observed_at"),
        Index("idx_observations_tenant_time", "tenant_id", "observed_at"),
    )


class FindingHistoryModel(Base):
    __tablename__ = "finding_history"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_user_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    old_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    new_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    comment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", SafeJSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)

    finding: Mapped["FindingModel"] = relationship("FindingModel", back_populates="history_entries")

    __table_args__ = (
        Index("idx_finding_history_finding_created", "finding_id", "created_at"),
        Index("idx_finding_history_tenant_action", "tenant_id", "action"),
    )


class FindingCommentModel(Base):
    __tablename__ = "finding_comments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    author_user_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    author_username: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    finding: Mapped["FindingModel"] = relationship("FindingModel", back_populates="comments")

    __table_args__ = (
        Index("idx_finding_comments_finding_created", "finding_id", "created_at"),
    )


class RemediationModel(Base):
    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    owner_external: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(16), default="P3", nullable=False)
    due_date: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    started_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    verification_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    finding: Mapped["FindingModel"] = relationship("FindingModel", back_populates="remediations")
    actions: Mapped[List["RemediationActionModel"]] = relationship("RemediationActionModel", back_populates="remediation", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_remediations_tenant_status", "tenant_id", "status"),
        Index("idx_remediations_owner", "owner_user_id", "status"),
    )


class RemediationActionModel(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    remediation_id: Mapped[str] = mapped_column(String(64), ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(64), default="patch", nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    due_date: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    remediation: Mapped["RemediationModel"] = relationship("RemediationModel", back_populates="actions")


class SLAPolicyModel(Base):
    __tablename__ = "sla_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    criticality: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    asset_criticality: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    priority_band: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    kev: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    internet_exposed: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    due_days: Mapped[int] = mapped_column(Integer, default=7, nullable=False)
    warning_days: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_sla_policies_tenant_enabled", "tenant_id", "enabled"),
    )


class RiskAcceptanceModel(Base):
    __tablename__ = "risk_acceptances"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    business_justification: Mapped[str] = mapped_column(Text, default="", nullable=False)
    compensating_controls: Mapped[str] = mapped_column(Text, default="", nullable=False)
    valid_from: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    valid_until: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    finding: Mapped["FindingModel"] = relationship("FindingModel", back_populates="risk_acceptances")

    __table_args__ = (
        Index("idx_risk_acceptances_tenant_status", "tenant_id", "status"),
        Index("idx_risk_acceptances_expiry", "status", "valid_until"),
    )


class IntegrationModel(Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # jira, servicenow, webhook
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    config_reference: Mapped[Dict[str, Any]] = mapped_column(SafeJSON, default=dict, nullable=False)
    secret_reference: Mapped[str] = mapped_column(String(255), default="", nullable=False)  # env var name
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    ticket_references: Mapped[List["TicketReferenceModel"]] = relationship("TicketReferenceModel", back_populates="integration", cascade="all, delete-orphan")
    webhook_deliveries: Mapped[List["WebhookDeliveryModel"]] = relationship("WebhookDeliveryModel", back_populates="integration", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_integrations_tenant_type", "tenant_id", "type"),
    )


class TicketReferenceModel(Base):
    __tablename__ = "ticket_references"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    integration_id: Mapped[str] = mapped_column(String(64), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    external_ticket_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    external_url: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    last_sync_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)

    finding: Mapped["FindingModel"] = relationship("FindingModel", back_populates="ticket_references")
    integration: Mapped["IntegrationModel"] = relationship("IntegrationModel", back_populates="ticket_references")

    __table_args__ = (
        UniqueConstraint("integration_id", "external_ticket_id", name="uq_ticket_references_integration_ticket"),
        Index("idx_ticket_references_finding", "finding_id"),
    )


class WebhookDeliveryModel(Base):
    __tablename__ = "webhook_deliveries"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    integration_id: Mapped[str] = mapped_column(String(64), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    next_retry_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)

    integration: Mapped["IntegrationModel"] = relationship("IntegrationModel", back_populates="webhook_deliveries")


class APIKeyModel(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    scopes: Mapped[List[str]] = mapped_column(SafeJSON, default=list, nullable=False)
    last_used_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    revoked_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    __table_args__ = (
        Index("idx_api_keys_tenant_active", "tenant_id", "revoked_at", "expires_at"),
    )


class DailyRiskSnapshotModel(Base):
    __tablename__ = "daily_risk_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    date: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # YYYY-MM-DD
    assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    open_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    p1_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    p2_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    kev_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sla_breaches: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_accepted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score_avg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    mttr_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    business_unit_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    verified_asset_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    internet_exposed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unassigned_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    accepted_risk_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "date", name="uq_daily_risk_snapshots_tenant_date"),
    )


class ControlMappingModel(Base):
    __tablename__ = "control_mappings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    control_title: Mapped[str] = mapped_column(String(255), default="", nullable=False)

    __table_args__ = (
        UniqueConstraint("finding_type", "framework", "control_id", name="uq_control_mappings_type_framework_id"),
    )


# ==============================================================================
# PHASE 6: EASM, DISCOVERY, EVIDENCE, POLICY, BU, OUTBOX & DATA QUALITY ORM
# ==============================================================================

class DiscoveryScopeModel(Base):
    __tablename__ = "discovery_scopes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    root_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    allowed_suffixes: Mapped[List[str]] = mapped_column(SafeJSON, default=list, nullable=False)
    excluded_patterns: Mapped[List[str]] = mapped_column(SafeJSON, default=list, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    valid_from: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    valid_until: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_discovery_scopes_tenant_domain", "tenant_id", "root_domain"),
    )


class DiscoveredAssetModel(Base):
    __tablename__ = "discovered_assets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    discovery_scope_id: Mapped[str] = mapped_column(String(64), ForeignKey("discovery_scopes.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    canonical_url: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="MANUAL_IMPORT", nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False)
    first_seen_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    last_seen_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="NEW", nullable=False, index=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    promoted_asset_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "hostname", name="uq_discovered_assets_tenant_host"),
        Index("idx_discovered_assets_tenant_status", "tenant_id", "status"),
    )


class AssetVerificationModel(Base):
    __tablename__ = "asset_verifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(32), default="DNS_TXT", nullable=False)
    challenge: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False, index=True)
    verified_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)

    __table_args__ = (
        Index("idx_asset_verifications_tenant_asset", "tenant_id", "asset_id"),
    )


class EvidenceModel(Base):
    __tablename__ = "evidences"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(64), default="http_response", nullable=False)
    source: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    storage_reference: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    mime_type: Mapped[str] = mapped_column(String(64), default="application/json", nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    retention_class: Mapped[str] = mapped_column(String(32), default="STANDARD", nullable=False)
    classification: Mapped[str] = mapped_column(String(32), default="internal", nullable=False)
    sanitized: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    redacted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    provenance: Mapped[Dict[str, Any]] = mapped_column(SafeJSON, default=dict, nullable=False)
    quality: Mapped[str] = mapped_column(String(32), default="STRONG", nullable=False)
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_evidences_tenant_hash", "tenant_id", "content_hash"),
        Index("idx_evidences_tenant_finding", "tenant_id", "finding_id"),
    )


class PolicyModel(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(64), default="SCAN_PROFILE", nullable=False, index=True)
    active_version_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_policies_tenant_name"),
    )


class PolicyVersionModel(Base):
    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", nullable=False, index=True)
    definition_json: Mapped[Dict[str, Any]] = mapped_column(SafeJSON, default=dict, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    activated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("policy_id", "version", name="uq_policy_versions_policy_version"),
    )


class BusinessUnitModel(Base):
    __tablename__ = "business_units"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_business_units_tenant_code"),
    )


class BusinessServiceModel(Base):
    __tablename__ = "business_services"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    business_unit_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("business_units.id", ondelete="SET NULL"), nullable=True, index=True)
    criticality: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class AssetBusinessServiceModel(Base):
    __tablename__ = "asset_business_services"

    asset_id: Mapped[str] = mapped_column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True)
    service_id: Mapped[str] = mapped_column(String(64), ForeignKey("business_services.id", ondelete="CASCADE"), primary_key=True)
    assigned_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)


class DataQualityIssueModel(Base):
    __tablename__ = "data_quality_issues"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), default="asset", nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    issue_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    detected_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)
    resolved_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_dq_tenant_type_entity", "tenant_id", "entity_type", "entity_id"),
    )


class IntegrationOutboxModel(Base):
    __tablename__ = "integration_outbox"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    destination: Mapped[str] = mapped_column(String(64), default="siem", nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[Dict[str, Any]] = mapped_column(SafeJSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False, index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    next_retry_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    claimed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    claimed_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False, index=True)

    __table_args__ = (
        Index("idx_outbox_tenant_status", "tenant_id", "status"),
        Index("idx_outbox_processing_claimed", "status", "claimed_at"),
    )


class TechnologyObservationModel(Base):
    __tablename__ = "technology_observations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    technology_type: Mapped[str] = mapped_column(String(64), default="CMS", nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(128), default="meta_generator", nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), default="HIGH", nullable=False)
    eol_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    last_seen: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)
    updated_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_tech_obs_asset_type", "asset_id", "technology_type"),
    )


class SavedViewModel(Base):
    __tablename__ = "saved_views"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), default="portfolio", nullable=False)
    filters_json: Mapped[Dict[str, Any]] = mapped_column(SafeJSON, default=dict, nullable=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), default=utcnow_str, nullable=False)

    __table_args__ = (
        Index("idx_saved_views_tenant_user", "tenant_id", "user_id"),
    )


