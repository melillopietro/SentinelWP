"""
Domain models for SentinelWP
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    PENDING = "pending"


@dataclass
class Tenant:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    slug: str = ""
    status: str = "active"  # active, disabled
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class Asset:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    canonical_url: str = ""
    hostname: str = ""
    wp_install_path: str = "/"  # WordPress install path (e.g. "/blog", "/wp")
    display_name: str = ""
    business_owner: str = ""
    technical_owner: str = ""
    environment: str = "production"  # production, staging, development, internal
    internet_exposure: str = "external"  # external, internal, restricted
    criticality: str = "medium"  # critical, high, medium, low
    data_classification: str = "confidential"  # public, internal, confidential, restricted
    authorization_status: str = "unauthorized"  # authorized, pending, unauthorized, expired
    authorization_review_date: Optional[str] = None
    tags: str = ""
    status: str = "active"  # active, disabled
    business_unit_id: Optional[str] = None
    # Sprint 3: Continuous Monitoring fields
    monitoring_enabled: bool = False
    monitoring_paused_at: Optional[str] = None  # ISO timestamp; non-null = paused
    last_scan_id: Optional[str] = None
    last_scan_at: Optional[str] = None
    last_scan_status: Optional[str] = None  # completed, failed, running
    last_successful_scan_at: Optional[str] = None
    consecutive_scan_failures: int = 0
    # Sprint 3: Security posture summary (populated by scan_tasks after each scan)
    wp_version: Optional[str] = None
    detected_themes: str = ""   # JSON list of theme slugs
    detected_plugins: str = ""  # JSON list of plugin slugs
    risk_score: Optional[float] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class ScanAuthorization:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: str = ""
    status: str = "active"  # active, expired, revoked
    allowed_profiles: str = "safe_active,passive"
    request_budget: int = 1000
    valid_from: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    valid_until: str = ""
    approved_by: str = ""
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class AuditEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    actor_user_id: str = ""
    actor_username: str = ""
    action: str = ""
    resource_type: str = ""
    resource_id: str = ""
    result: str = "success"  # success, failure, denied
    metadata: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: Optional[str] = None
    scan_id: str = ""
    category: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 1.0
    remediation: str = ""
    reference: str = ""
    raw_data: dict = field(default_factory=dict)
    fingerprint: str = ""
    status: str = "OPEN"
    first_seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    first_scan_id: str = ""
    last_scan_id: str = ""
    observation_count: int = 1
    assigned_to_user_id: Optional[str] = None
    assigned_team: Optional[str] = None
    assigned_at: Optional[str] = None
    finding_tags: list = field(default_factory=list)
    version: int = 1
    priority_score: float = 0.0
    priority_band: str = "P3"
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_last_updated: Optional[str] = None
    kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    known_ransomware_campaign_use: bool = False
    ransomware_relevance: str = "NONE"
    cve_id: Optional[str] = None
    sla_policy_id: Optional[str] = None
    sla_due_at: Optional[str] = None
    sla_status: str = "NOT_APPLICABLE"
    sla_paused_at: Optional[str] = None
    sla_pause_reason: Optional[str] = None
    verified_at: Optional[str] = None
    verified_by_scan_id: Optional[str] = None
    false_positive_reason: Optional[str] = None
    false_positive_by: Optional[str] = None
    false_positive_at: Optional[str] = None
    false_positive_valid_until: Optional[str] = None
    finding_confidence: str = "HIGH"  # LOW, MEDIUM, HIGH, CONFIRMED
    policy_version_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class FindingObservation:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    finding_id: str = ""
    scan_id: str = ""
    asset_id: Optional[str] = None
    scanner_id: Optional[str] = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: str = "info"
    evidence_id: Optional[str] = None
    evidence_reference: Optional[str] = None
    status: str = "OPEN"
    raw_reference: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class FindingHistory:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    finding_id: str = ""
    actor_user_id: str = ""
    action: str = ""
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    comment: str = ""
    metadata: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class FindingComment:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    finding_id: str = ""
    author_user_id: str = ""
    author_username: str = ""
    body: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class Remediation:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    finding_id: str = ""
    title: str = ""
    description: str = ""
    owner_user_id: Optional[str] = None
    owner_external: Optional[str] = None
    status: str = "OPEN"
    priority: str = "P3"
    due_date: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    verification_required: bool = True
    verification_status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class RemediationAction:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    remediation_id: str = ""
    action_type: str = "patch"
    description: str = ""
    owner: str = ""
    status: str = "pending"
    due_date: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class SLAPolicy:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    name: str = ""
    severity: Optional[str] = None
    criticality: Optional[str] = None
    asset_criticality: Optional[str] = None
    priority_band: Optional[str] = None
    kev: Optional[bool] = None
    internet_exposed: Optional[bool] = None
    due_days: int = 7
    warning_days: int = 5
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class RiskAcceptance:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    finding_id: str = ""
    requested_by: str = ""
    approved_by: Optional[str] = None
    reason: str = ""
    business_justification: str = ""
    compensating_controls: str = ""
    valid_from: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    valid_until: str = ""
    status: str = "PENDING"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class Integration:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    type: str = "webhook"  # jira, servicenow, webhook
    name: str = ""
    enabled: bool = True
    config_reference: dict = field(default_factory=dict)
    secret_reference: str = ""  # env var name, never plaintext token
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class TicketReference:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    finding_id: str = ""
    integration_id: str = ""
    external_ticket_id: str = ""
    external_url: str = ""
    status: str = "open"
    last_sync_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class WebhookDelivery:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    integration_id: str = ""
    event: str = ""
    payload_hash: str = ""
    status: str = "pending"  # pending, delivered, failed
    attempt: int = 1
    last_error: Optional[str] = None
    next_retry_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class APIKey:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    name: str = ""
    key_prefix: str = ""
    key_hash: str = ""  # SHA-256 of token
    scopes: list = field(default_factory=list)
    last_used_at: Optional[str] = None
    expires_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    revoked_at: Optional[str] = None
    status: str = "active"

    def __post_init__(self):
        if self.revoked_at:
            self.status = "revoked"
        elif self.expires_at and self.expires_at < datetime.now(timezone.utc).isoformat():
            self.status = "expired"


@dataclass
class DailyRiskSnapshot:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    date: str = ""  # YYYY-MM-DD
    assets: int = 0
    open_findings: int = 0
    p1_count: int = 0
    p2_count: int = 0
    kev_count: int = 0
    sla_breaches: int = 0
    risk_accepted: int = 0
    risk_score_avg: float = 0.0
    avg_risk_score: float = 0.0
    mttr_seconds: float = 0.0
    business_unit_id: Optional[str] = None
    verified_asset_count: int = 0
    internet_exposed_count: int = 0
    unassigned_findings: int = 0
    accepted_risk_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ControlMapping:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: str = ""
    framework: str = ""  # ISO 27001, NIST CSF, CIS Controls
    control_id: str = ""
    control_title: str = ""



@dataclass
class ScanResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: Optional[str] = None
    target_url: str = ""
    status: ScanStatus = ScanStatus.PENDING
    scan_mode: str = "passive"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    findings: list = field(default_factory=list)
    score: Optional[float] = None
    grade: Optional[str] = None
    notes: str = ""
    tags: str = ""
    initiated_by: str = ""
    # Canonical WordPress detection metadata fields
    wordpress_detected: Optional[bool] = None
    wordpress_version: Optional[str] = None
    wordpress_version_source: Optional[str] = None
    wordpress_version_confidence: Optional[str] = None
    # Backward compatibility aliases
    is_wordpress: Optional[bool] = None
    wp_version: Optional[str] = None
    wp_version_source: Optional[str] = None
    wp_version_confidence: Optional[str] = None
    whois_info: Optional[str] = None

    def __post_init__(self):
        # Bidirectional synchronization between canonical and legacy fields on init
        if self.wordpress_detected is None and self.is_wordpress is not None:
            self.wordpress_detected = self.is_wordpress
        elif self.wordpress_detected is not None and self.is_wordpress is None:
            self.is_wordpress = self.wordpress_detected

        if self.wordpress_version is None and self.wp_version is not None:
            self.wordpress_version = self.wp_version
        elif self.wordpress_version is not None and self.wp_version is None:
            self.wp_version = self.wordpress_version

        if self.wordpress_version_source is None and self.wp_version_source is not None:
            self.wordpress_version_source = self.wp_version_source
        elif self.wordpress_version_source is not None and self.wp_version_source is None:
            self.wp_version_source = self.wordpress_version_source

        if self.wordpress_version_confidence is None and self.wp_version_confidence is not None:
            self.wordpress_version_confidence = self.wp_version_confidence
        elif self.wordpress_version_confidence is not None and self.wp_version_confidence is None:
            self.wp_version_confidence = self.wordpress_version_confidence
        self._initialized = True

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if not getattr(self, "_initialized", False):
            return
        if name == "is_wordpress" and getattr(self, "wordpress_detected", None) != value:
            super().__setattr__("wordpress_detected", value)
        elif name == "wordpress_detected" and getattr(self, "is_wordpress", None) != value:
            super().__setattr__("is_wordpress", value)
        elif name == "wp_version" and getattr(self, "wordpress_version", None) != value:
            super().__setattr__("wordpress_version", value)
        elif name == "wordpress_version" and getattr(self, "wp_version", None) != value:
            super().__setattr__("wp_version", value)
        elif name == "wp_version_source" and getattr(self, "wordpress_version_source", None) != value:
            super().__setattr__("wordpress_version_source", value)
        elif name == "wordpress_version_source" and getattr(self, "wp_version_source", None) != value:
            super().__setattr__("wp_version_source", value)
        elif name == "wp_version_confidence" and getattr(self, "wordpress_version_confidence", None) != value:
            super().__setattr__("wordpress_version_confidence", value)
        elif name == "wordpress_version_confidence" and getattr(self, "wp_version_confidence", None) != value:
            super().__setattr__("wp_version_confidence", value)


@dataclass
class User:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    username: str = ""
    password_hash: str = ""
    email: str = ""
    role: UserRole = UserRole.VIEWER
    status: UserStatus = UserStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ScheduledScan:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: Optional[str] = None
    target_url: str = ""
    scan_mode: str = "passive"
    interval_hours: int = 24
    last_run_at: Optional[str] = None
    next_run_at: Optional[str] = None
    enabled: bool = True
    created_by: str = ""
    # Sprint 3: failure tracking and pause support
    max_retries: int = 3
    consecutive_failures: int = 0
    last_failure_at: Optional[str] = None
    last_success_at: Optional[str] = None
    paused_until: Optional[str] = None  # non-null = monitoring paused until this ISO timestamp
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScanJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


@dataclass
class ScanJob:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: Optional[str] = None
    scan_id: str = ""
    task_id: Optional[str] = None
    status: str = ScanJobStatus.QUEUED.value
    requested_by: str = ""
    profile: str = "passive"
    queued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    failed_at: Optional[str] = None
    cancelled_at: Optional[str] = None
    progress_percent: int = 0
    current_step: str = "Initialized"
    attempt: int = 1
    max_attempts: int = 3
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    worker_id: Optional[str] = None
    heartbeat_at: Optional[str] = None
    policy_version_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class ScheduledRun:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schedule_id: str = ""
    tenant_id: str = "default-tenant"
    planned_at: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    scan_job_id: Optional[str] = None
    status: str = "pending"  # pending, dispatched, running, completed, failed, duplicate_blocked
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class IntelSyncStatus:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""  # wordfence, cisa_kev, wordpress_org, etc.
    last_success: Optional[str] = None
    last_attempt: Optional[str] = None
    status: str = "pending"  # pending, running, success, failed
    records_processed: int = 0
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    freshness_age_seconds: Optional[int] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


# ==============================================================================
# PHASE 6: EASM, DISCOVERY, EVIDENCE, POLICY, BU, OUTBOX & DATA QUALITY MODELS
# ==============================================================================

class DiscoverySource(str, Enum):
    DNS = "DNS"
    CERTIFICATE_TRANSPARENCY = "CERTIFICATE_TRANSPARENCY"
    MANUAL_IMPORT = "MANUAL_IMPORT"
    EXISTING_SCAN = "EXISTING_SCAN"
    API_IMPORT = "API_IMPORT"
    OTHER = "OTHER"


class DiscoveryConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class DiscoveredAssetStatus(str, Enum):
    NEW = "NEW"
    REVIEW = "REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PROMOTED = "PROMOTED"


@dataclass
class DiscoveryScope:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    name: str = ""
    root_domain: str = ""
    allowed_suffixes: list = field(default_factory=list)
    excluded_patterns: list = field(default_factory=list)
    max_depth: int = 2
    enabled: bool = True
    created_by: str = ""
    approved_by: Optional[str] = None
    valid_from: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    valid_until: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class DiscoveredAsset:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    discovery_scope_id: str = ""
    hostname: str = ""
    canonical_url: str = ""
    source: str = DiscoverySource.MANUAL_IMPORT.value
    confidence: str = DiscoveryConfidence.MEDIUM.value
    first_seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = DiscoveredAssetStatus.NEW.value
    evidence_id: Optional[str] = None
    promoted_asset_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


class VerificationMethod(str, Enum):
    DNS_TXT = "DNS_TXT"
    HTTP_TOKEN = "HTTP_TOKEN"


class VerificationStatus(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


@dataclass
class AssetVerification:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: str = ""
    method: str = VerificationMethod.DNS_TXT.value
    challenge: str = ""
    status: str = VerificationStatus.PENDING.value
    verified_at: Optional[str] = None
    expires_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EvidenceQuality(str, Enum):
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    VERIFIED = "VERIFIED"


class EvidenceRetentionClass(str, Enum):
    SHORT = "SHORT"
    STANDARD = "STANDARD"
    LONG = "LONG"
    AUDIT = "AUDIT"


@dataclass
class Evidence:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: Optional[str] = None
    scan_id: Optional[str] = None
    finding_id: Optional[str] = None
    type: str = "http_response"
    source: str = ""
    content_hash: str = ""
    storage_reference: str = ""
    mime_type: str = "application/json"
    size_bytes: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    retention_class: str = EvidenceRetentionClass.STANDARD.value
    classification: str = "internal"
    sanitized: bool = True
    redacted: bool = True
    provenance: dict = field(default_factory=dict)
    quality: str = EvidenceQuality.STRONG.value
    payload: Optional[str] = None


class PolicyType(str, Enum):
    SCAN_PROFILE = "SCAN_PROFILE"
    SLA = "SLA"
    PRIORITIZATION = "PRIORITIZATION"
    DISCOVERY = "DISCOVERY"
    EVIDENCE_RETENTION = "EVIDENCE_RETENTION"
    NOTIFICATION = "NOTIFICATION"
    RISK_ACCEPTANCE = "RISK_ACCEPTANCE"


class PolicyVersionStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


@dataclass
class Policy:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    name: str = ""
    type: str = PolicyType.SCAN_PROFILE.value
    active_version_id: Optional[str] = None
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class PolicyVersion:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str = ""
    version: int = 1
    status: str = PolicyVersionStatus.DRAFT.value
    definition_json: dict = field(default_factory=dict)
    checksum: str = ""
    created_by: str = ""
    approved_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    activated_at: Optional[str] = None


@dataclass
class BusinessUnit:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    name: str = ""
    code: str = ""
    parent_id: Optional[str] = None
    owner_user_id: Optional[str] = None
    criticality: str = "medium"  # critical, high, medium, low
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class BusinessService:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    name: str = ""
    business_unit_id: Optional[str] = None
    criticality: str = "medium"
    owner_user_id: Optional[str] = None
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class AssetBusinessService:
    asset_id: str = ""
    service_id: str = ""
    assigned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class DataQualityIssue:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    entity_type: str = "asset"  # asset, finding, intel, authorization
    entity_id: str = ""
    issue_type: str = ""
    severity: str = "medium"  # critical, high, medium, low
    description: str = ""
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None


class OutboxStatus(str, Enum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"


@dataclass
class IntegrationOutbox:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    event_type: str = ""
    event_key: str = ""
    destination: str = "siem"  # siem, webhook, soar
    payload_hash: str = ""
    payload_json: dict = field(default_factory=dict)
    status: str = OutboxStatus.PENDING.value
    attempt: int = 1
    next_retry_at: Optional[str] = None
    last_error: Optional[str] = None
    claimed_at: Optional[str] = None
    claimed_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class TechnologyObservation:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    asset_id: str = ""
    technology_type: str = "CMS"  # CMS, WORDPRESS_PLUGIN, WORDPRESS_THEME, SERVER, LANGUAGE
    name: str = ""
    version: Optional[str] = None
    source: str = "meta_generator"
    confidence: str = "HIGH"
    eol_status: Optional[str] = None  # supported, eol, deprecated
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


@dataclass
class SavedView:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    user_id: str = ""
    name: str = ""
    resource_type: str = "portfolio"  # portfolio, assets, findings, discovery
    filters_json: dict = field(default_factory=dict)
    is_shared: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

