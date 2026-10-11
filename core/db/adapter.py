"""
SentinelWP Operational Persistence Adapter Architecture
Provides clean abstraction and transaction governance for PostgreSQL operations
while maintaining full backward compatibility with native SQLite execution.

PostgreSQL adapter implements operational persistence for tenants, users, assets,
scans, scan jobs, findings, remediations, scheduling, outbox, and governance APIs
used in enterprise production mode.
"""
import functools
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple

from config import is_postgres_configured
from core.models import (
    Tenant, User, Asset, ScanAuthorization, ScanResult, ScanJob,
    Finding, FindingObservation, FindingHistory, FindingComment,
    Remediation, RemediationAction, SLAPolicy, AuditEvent,
    ScanStatus, ScheduledScan, ScheduledRun, IntegrationOutbox,
    APIKey, Policy, PolicyVersion, Integration, WebhookDelivery,
    TicketReference, RiskAcceptance, DailyRiskSnapshot,
    DiscoveryScope, BusinessUnit,
    DataQualityIssue, DiscoveredAsset, TechnologyObservation, SavedView,
    IntelSyncStatus
)
from core.lifecycle import FindingStatus, SLAStatus, OptimisticLockError
from core.db.session import session_scope
from core.db.repositories.tenant_repo import TenantRepository
from core.db.repositories.user_repo import UserRepository
from core.db.repositories.asset_repo import AssetRepository
from core.db.repositories.scan_repo import ScanRepository
from core.db.repositories.scan_job_repo import ScanJobRepository
from core.db.repositories.finding_repo import FindingRepository
from core.db.repositories.remediation_repo import RemediationRepository
from core.db.repositories.audit_repo import AuditRepository
from core.db.repositories.scheduler_repo import SchedulerRepository
from core.db.repositories.outbox_repo import OutboxRepository
from core.db.repositories.governance_repo import GovernanceRepository
from core.db.models import (
    FindingModel, ScanModel,
    DataQualityIssueModel, DiscoveredAssetModel, TechnologyObservationModel, SavedViewModel,
    IntelSyncStatusModel
)
from sqlalchemy import delete, text, select

logger = logging.getLogger("sentinelwp.db.adapter")


class OperationalBackendAdapter:
    """Base interface for operational persistence adapters."""
    pass


class PostgresqlOperationalAdapter(OperationalBackendAdapter):
    """
    PostgreSQL Operational Adapter using SQLAlchemy 2.0.
    Executes all persistence operations inside explicit session_scope() transaction boundaries
    with automatic rollback on failure and connection release.
    """

    # =========================================================================
    # Tenant Operations
    # =========================================================================

    def save_tenant(self, tenant: Tenant) -> Tenant:
        with session_scope() as session:
            return TenantRepository(session).save(tenant)

    def get_tenant_by_id(self, tenant_id: str) -> Optional[Tenant]:
        with session_scope() as session:
            return TenantRepository(session).get_by_id(tenant_id)

    def get_tenant_by_slug(self, slug: str) -> Optional[Tenant]:
        with session_scope() as session:
            return TenantRepository(session).get_by_slug(slug)

    def list_tenants(self, limit: int = 100, offset: int = 0) -> List[Tenant]:
        with session_scope() as session:
            return TenantRepository(session).list_tenants(limit=limit, offset=offset)

    def update_tenant(self, tenant_id: str, **kwargs) -> bool:
        with session_scope() as session:
            return TenantRepository(session).update(tenant_id, **kwargs)

    def delete_tenant(self, tenant_id: str) -> bool:
        with session_scope() as session:
            return TenantRepository(session).delete(tenant_id)

    # =========================================================================
    # User Operations
    # =========================================================================

    def create_user(
        self,
        username: str,
        password_hash: str,
        role: str = "viewer",
        email: str = "",
        status: str = "pending",
        tenant_id: str = "default-tenant",
    ) -> User:
        with session_scope() as session:
            return UserRepository(session).create_user(
                username=username,
                password_hash=password_hash,
                role=role,
                email=email,
                status=status,
                tenant_id=tenant_id,
            )

    def save_user(self, user: User) -> User:
        with session_scope() as session:
            return UserRepository(session).save(user)

    def get_user_by_username(self, username: str, tenant_id: Optional[str] = None) -> Optional[User]:
        with session_scope() as session:
            return UserRepository(session).get_by_username(username, tenant_id=tenant_id)

    def list_users_by_username(self, username: str) -> List[User]:
        with session_scope() as session:
            return UserRepository(session).list_by_username(username)

    def get_user_by_id(self, user_id: str, tenant_id: Optional[str] = None) -> Optional[User]:
        with session_scope() as session:
            return UserRepository(session).get_by_id(user_id, tenant_id=tenant_id)

    def list_users(self, tenant_id: Optional[str] = None) -> List[User]:
        with session_scope() as session:
            return UserRepository(session).list_users(tenant_id=tenant_id)

    def count_users(self, tenant_id: Optional[str] = None) -> int:
        with session_scope() as session:
            return UserRepository(session).count_users(tenant_id=tenant_id)

    def update_user(self, user_id: str, **kwargs) -> bool:
        with session_scope() as session:
            return UserRepository(session).update_user(user_id, **kwargs)

    def update_user_status(self, user_id: str, status: str) -> bool:
        with session_scope() as session:
            return UserRepository(session).update_status(user_id, status)

    def update_user_role(self, user_id: str, role: str) -> bool:
        with session_scope() as session:
            return UserRepository(session).update_role(user_id, role)

    def delete_user(self, user_id: str) -> bool:
        with session_scope() as session:
            return UserRepository(session).delete_user(user_id)

    # =========================================================================
    # Asset Operations
    # =========================================================================

    def get_asset(self, asset_id: str, tenant_id: Optional[str] = None) -> Optional[Asset]:
        with session_scope() as session:
            return AssetRepository(session).get_by_id(asset_id, tenant_id=tenant_id)

    def get_asset_by_url(self, tenant_id: str, canonical_url: str) -> Optional[Asset]:
        with session_scope() as session:
            return AssetRepository(session).get_by_canonical_url(canonical_url, tenant_id=tenant_id)

    def ensure_asset_for_target(self, tenant_id: str, target_url: str, display_name: str = "") -> Asset:
        with session_scope() as session:
            return AssetRepository(session).ensure_asset(
                target_url=target_url, tenant_id=tenant_id, display_name=display_name
            )

    def ensure_asset(self, target_url: str, tenant_id: str, display_name: str = "") -> Asset:
        with session_scope() as session:
            return AssetRepository(session).ensure_asset(
                target_url=target_url, tenant_id=tenant_id, display_name=display_name
            )

    def list_assets(
        self,
        tenant_id: Optional[str] = None,
        filters: Optional[dict] = None,
        limit: Optional[int] = 500,
        offset: int = 0
    ) -> List[Asset]:
        with session_scope() as session:
            return AssetRepository(session).list_assets(
                tenant_id=tenant_id, filters=filters, limit=limit, offset=offset
            )

    def save_asset(self, asset: Asset) -> Asset:
        with session_scope() as session:
            return AssetRepository(session).save(asset)

    def update_asset(self, asset_id: str, tenant_id: Optional[str] = None, **kwargs) -> bool:
        with session_scope() as session:
            return AssetRepository(session).update_asset(asset_id, tenant_id=tenant_id, **kwargs)

    def delete_asset(self, asset_id: str, tenant_id: Optional[str] = None, hard: bool = False) -> bool:
        with session_scope() as session:
            return AssetRepository(session).delete_asset(asset_id, tenant_id=tenant_id, hard=hard)

    # =========================================================================
    # Scan Authorization Operations
    # =========================================================================

    def save_scan_authorization(self, auth: ScanAuthorization) -> ScanAuthorization:
        with session_scope() as session:
            return AssetRepository(session).save_authorization(auth)

    def get_scan_authorization(self, auth_id: str, tenant_id: Optional[str] = None) -> Optional[ScanAuthorization]:
        with session_scope() as session:
            return AssetRepository(session).get_authorization(auth_id, tenant_id=tenant_id)

    def get_active_authorization(self, asset_id: str, tenant_id: Optional[str] = None) -> Optional[ScanAuthorization]:
        with session_scope() as session:
            return AssetRepository(session).get_active_authorization(asset_id, tenant_id=tenant_id)

    def list_scan_authorizations(
        self, asset_id: Optional[str] = None, tenant_id: Optional[str] = None
    ) -> List[ScanAuthorization]:
        with session_scope() as session:
            return AssetRepository(session).list_scan_authorizations(asset_id=asset_id, tenant_id=tenant_id)

    def revoke_scan_authorization(self, auth_id: str, tenant_id: Optional[str] = None) -> bool:
        with session_scope() as session:
            return AssetRepository(session).revoke_authorization(auth_id, tenant_id=tenant_id)

    # =========================================================================
    # Scan Operations
    # =========================================================================

    def save_scan(self, scan: ScanResult) -> ScanResult:
        with session_scope() as session:
            return ScanRepository(session).save_scan(scan)

    def get_scan(self, scan_id: str, tenant_id: Optional[str] = None) -> Optional[ScanResult]:
        with session_scope() as session:
            return ScanRepository(session).get_by_id(scan_id, tenant_id=tenant_id)

    def list_scans(
        self, limit: int = 100, offset: int = 0, filters: Optional[dict] = None
    ) -> List[ScanResult]:
        with session_scope() as session:
            return ScanRepository(session).list_scans(limit=limit, offset=offset, filters=filters)

    def count_scans(self, tenant_id: Optional[str] = None) -> int:
        with session_scope() as session:
            return ScanRepository(session).count_scans(tenant_id=tenant_id)

    def update_scan(self, scan_id: str, tenant_id: Optional[str] = None, **kwargs) -> bool:
        with session_scope() as session:
            return ScanRepository(session).update_scan(scan_id, tenant_id=tenant_id, **kwargs)

    def delete_scan(self, scan_id: str, tenant_id: Optional[str] = None) -> bool:
        with session_scope() as session:
            return ScanRepository(session).delete_scan(scan_id, tenant_id=tenant_id)

    # =========================================================================
    # Scan Job Operations
    # =========================================================================

    def create_scan_job(self, job: ScanJob) -> ScanJob:
        with session_scope() as session:
            return ScanJobRepository(session).create_job(job)

    def update_scan_job(self, job: ScanJob) -> bool:
        with session_scope() as session:
            ScanJobRepository(session).update_job(job)
            return True

    def get_scan_job(self, job_id: str, tenant_id: Optional[str] = None) -> Optional[ScanJob]:
        with session_scope() as session:
            return ScanJobRepository(session).get_by_id(job_id, tenant_id=tenant_id)

    def get_scan_job_by_scan_id(self, scan_id: str, tenant_id: Optional[str] = None) -> Optional[ScanJob]:
        with session_scope() as session:
            return ScanJobRepository(session).get_by_scan_id(scan_id, tenant_id=tenant_id)

    def update_scan_job_progress(
        self,
        job_id: str,
        progress_percent: int,
        current_step: str,
        worker_id: Optional[str] = None,
    ) -> bool:
        with session_scope() as session:
            return ScanJobRepository(session).update_progress(
                job_id, progress_percent, current_step, worker_id=worker_id
            )

    def record_scan_job_heartbeat(self, job_id: str, worker_id: Optional[str] = None) -> bool:
        with session_scope() as session:
            return ScanJobRepository(session).record_heartbeat(job_id, worker_id=worker_id)

    def mark_scan_job_status(
        self,
        job_id: str,
        status: str,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> bool:
        with session_scope() as session:
            return ScanJobRepository(session).mark_status(
                job_id,
                status,
                error_code=error_code,
                error_message=error_message,
                worker_id=worker_id,
            )

    def try_claim_scan_job_for_execution(self, job_id: str, worker_id: str) -> Optional[ScanJob]:
        with session_scope() as session:
            return ScanJobRepository(session).try_claim_for_execution(job_id, worker_id)

    def try_reclaim_stale_scan_job_for_retry(
        self,
        job_id: str,
        stale_threshold_seconds: int = 600,
    ) -> Optional[ScanJob]:
        with session_scope() as session:
            return ScanJobRepository(session).try_reclaim_stale_for_retry(
                job_id, stale_threshold_seconds=stale_threshold_seconds
            )

    def count_active_scan_jobs_for_tenant(self, tenant_id: str) -> int:
        with session_scope() as session:
            return ScanJobRepository(session).count_active_jobs_for_tenant(tenant_id)

    def count_active_scan_jobs_global(self) -> int:
        with session_scope() as session:
            return ScanJobRepository(session).count_active_jobs_global()

    def count_active_scan_jobs_for_asset(self, asset_id: str) -> int:
        with session_scope() as session:
            return ScanJobRepository(session).count_active_jobs_for_asset(asset_id)

    def find_stale_scan_jobs(self, stale_threshold_seconds: int = 600) -> List[ScanJob]:
        with session_scope() as session:
            return ScanJobRepository(session).find_stale_jobs(stale_threshold_seconds)

    def list_scan_jobs(
        self,
        tenant_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ScanJob]:
        with session_scope() as session:
            return ScanJobRepository(session).list_jobs(
                tenant_id=tenant_id, status=status, limit=limit, offset=offset
            )

    # =========================================================================
    # Phase 4: Finding Operations
    # =========================================================================

    def save_finding(self, finding: Finding, expected_version: Optional[int] = None) -> Finding:
        with session_scope() as session:
            return FindingRepository(session).save_finding(finding, expected_version=expected_version)

    def save_findings_bulk(self, findings: List[Finding]) -> List[Finding]:
        with session_scope() as session:
            return FindingRepository(session).save_findings_bulk(findings)

    def get_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> Optional[Finding]:
        with session_scope() as session:
            return FindingRepository(session).get_by_id(finding_id, tenant_id=tenant_id)

    def get_finding_by_fingerprint(self, tenant_id: str, fingerprint: str) -> Optional[Finding]:
        with session_scope() as session:
            return FindingRepository(session).get_by_fingerprint(tenant_id, fingerprint)

    def get_findings_for_scan(self, scan_id: str, tenant_id: Optional[str] = None) -> List[Finding]:
        with session_scope() as session:
            return FindingRepository(session).list_by_scan(scan_id, tenant_id=tenant_id)

    def get_findings_for_asset(self, asset_id: str, tenant_id: Optional[str] = None) -> List[Finding]:
        with session_scope() as session:
            return FindingRepository(session).list_by_asset(asset_id, tenant_id=tenant_id)

    def list_findings(
        self,
        tenant_id: str,
        filters: Optional[dict] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[Finding], int]:
        with session_scope() as session:
            return FindingRepository(session).list_findings(
                tenant_id, filters=filters, page=page, page_size=page_size
            )

    def delete_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> bool:
        with session_scope() as session:
            return FindingRepository(session).delete_finding(finding_id, tenant_id=tenant_id)

    def update_finding(self, finding_id: str, tenant_id: Optional[str] = None, **kwargs) -> bool:
        with session_scope() as session:
            return FindingRepository(session).update_finding(finding_id, tenant_id=tenant_id, **kwargs)

    def transition_finding_status(
        self,
        finding_id: str,
        new_status: str,
        actor_user_id: str,
        tenant_id: Optional[str] = None,
        comment: str = "",
        metadata: Optional[dict] = None,
        expected_version: Optional[int] = None,
    ) -> Finding:
        from core.lifecycle import validate_transition
        from core.sla import evaluate_finding_sla_status

        with session_scope() as session:
            finding_repo = FindingRepository(session)
            finding = finding_repo.get_by_id(finding_id, tenant_id=tenant_id)
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
                finding.sla_status = evaluate_finding_sla_status(finding)

            finding_repo.save_finding(finding, expected_version=expected_version)

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
            finding_repo.add_history(hist)

            if comment:
                finding_repo.add_comment(FindingComment(
                    tenant_id=finding.tenant_id,
                    finding_id=finding.id,
                    author_user_id=actor_user_id,
                    body=f"Status changed to {target_status}: {comment}",
                    created_at=now_iso,
                ))

            AuditRepository(session).log_event(AuditEvent(
                tenant_id=finding.tenant_id,
                actor_user_id=actor_user_id,
                action="finding_status_transition",
                resource_type="finding",
                resource_id=finding.id,
                metadata={"old_status": old_status, "new_status": target_status, "comment": comment}
            ))

            return finding

    def process_scan_findings(
        self,
        scan_id: str,
        tenant_id: str,
        asset_id: Optional[str],
        raw_findings: List[Finding]
    ) -> List[Finding]:
        from core.prioritization import calculate_priority_score
        from core.sla import calculate_sla_due_date, match_sla_policy
        from core.fingerprint import compute_finding_fingerprint

        now_iso = datetime.now(timezone.utc).isoformat()
        processed: List[Finding] = []

        with session_scope() as session:
            finding_repo = FindingRepository(session)
            remediation_repo = RemediationRepository(session)
            asset_repo = AssetRepository(session)
            scan_repo = ScanRepository(session)
            audit_repo = AuditRepository(session)

            policies = remediation_repo.list_sla_policies(tenant_id)
            asset = asset_repo.get_by_id(asset_id, tenant_id=tenant_id) if asset_id else None
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

                existing = finding_repo.get_by_fingerprint(tenant_id, fp)
                if existing:
                    old_status = existing.status
                    should_reopen = old_status in (
                        FindingStatus.VERIFIED.value,
                        FindingStatus.CLOSED.value,
                        FindingStatus.REMEDIATED.value,
                        FindingStatus.VERIFICATION_PENDING.value
                    )

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
                        finding_repo.add_history(hist)
                        audit_repo.log_event(AuditEvent(
                            tenant_id=tenant_id,
                            actor_user_id="system:scanner",
                            action="finding_reopened",
                            resource_type="finding",
                            resource_id=existing.id,
                            metadata={"scan_id": scan_id, "previous_status": old_status}
                        ))

                    finding_repo.save_finding(existing)

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
                    finding_repo.save_observation(obs)
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

                    finding_repo.save_finding(rf)

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
                    finding_repo.save_observation(obs)

                    # Defensive record in EvidenceStore if SQLite is active
                    if not is_postgres_configured():
                        try:
                            from core.evidence.store import EvidenceStore
                            import json
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
                    finding_repo.add_history(hist)
                    processed.append(rf)

            # Post-scan differential reconciliation:
            # Mandatory requirement: Never resolve findings based on failed, cancelled or incomplete scans!
            scan = scan_repo.get_by_id(scan_id, tenant_id=tenant_id)
            is_scan_completed = scan is not None and (
                scan.status == ScanStatus.COMPLETED or str(scan.status).lower() == "completed"
            )

            if asset_id and is_scan_completed:
                pending_verification = [
                    f for f in finding_repo.list_by_asset(asset_id, tenant_id=tenant_id)
                    if f.status == FindingStatus.VERIFICATION_PENDING.value
                ]
                processed_fingerprints = {f.fingerprint for f in processed}
                for pv in pending_verification:
                    if pv.fingerprint not in processed_fingerprints:
                        pv.status = FindingStatus.VERIFIED.value
                        pv.verified_at = now_iso
                        pv.verified_by_scan_id = scan_id
                        finding_repo.save_finding(pv)
                        finding_repo.add_history(FindingHistory(
                            tenant_id=tenant_id,
                            finding_id=pv.id,
                            actor_user_id="system:scanner",
                            action="finding_verified",
                            old_status=FindingStatus.VERIFICATION_PENDING.value,
                            new_status=FindingStatus.VERIFIED.value,
                            comment=f"Finding verified remediated; not detected in scan {scan_id}.",
                            created_at=now_iso,
                        ))
                        audit_repo.log_event(AuditEvent(
                            tenant_id=tenant_id,
                            actor_user_id="system:scanner",
                            action="finding_verified",
                            resource_type="finding",
                            resource_id=pv.id,
                            metadata={"scan_id": scan_id}
                        ))

            return processed

    # =========================================================================
    # Phase 4: Observations, History, Comments, Lifecycle
    # =========================================================================

    def save_finding_observation(self, obs: FindingObservation) -> FindingObservation:
        with session_scope() as session:
            return FindingRepository(session).save_observation(obs)

    def get_observations_for_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> List[FindingObservation]:
        with session_scope() as session:
            return FindingRepository(session).get_observations_for_finding(finding_id, tenant_id=tenant_id)

    def get_observations_for_scan(self, scan_id: str, tenant_id: Optional[str] = None) -> List[FindingObservation]:
        with session_scope() as session:
            return FindingRepository(session).get_observations_for_scan(scan_id, tenant_id=tenant_id)

    def add_finding_history(self, history: FindingHistory) -> FindingHistory:
        with session_scope() as session:
            return FindingRepository(session).add_history(history)

    def get_finding_history(self, finding_id: str, tenant_id: Optional[str] = None) -> List[FindingHistory]:
        with session_scope() as session:
            return FindingRepository(session).get_history(finding_id, tenant_id=tenant_id)

    def add_finding_comment(self, comment: FindingComment) -> FindingComment:
        with session_scope() as session:
            return FindingRepository(session).add_comment(comment)

    def get_finding_comments(self, finding_id: str, tenant_id: Optional[str] = None) -> List[FindingComment]:
        with session_scope() as session:
            return FindingRepository(session).get_comments(finding_id, tenant_id=tenant_id)

    def get_finding_lifecycle(self, finding_id: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        with session_scope() as session:
            finding = FindingRepository(session).get_by_id(finding_id, tenant_id=tenant_id)
            if not finding:
                return {}
            obs = FindingRepository(session).get_observations_for_finding(finding_id, tenant_id=tenant_id)
            hist = FindingRepository(session).get_history(finding_id, tenant_id=tenant_id)
            comments = FindingRepository(session).get_comments(finding_id, tenant_id=tenant_id)
            remediation = RemediationRepository(session).get_remediation_by_finding(finding_id, tenant_id=tenant_id)
            return {
                "finding": finding,
                "observations": obs,
                "history": hist,
                "comments": comments,
                "remediation": remediation,
            }

    # =========================================================================
    # Phase 4: Remediation Operations
    # =========================================================================

    def create_remediation(self, remediation: Remediation) -> Remediation:
        with session_scope() as session:
            return RemediationRepository(session).create_remediation(remediation)

    def get_remediation(self, remediation_id: str, tenant_id: Optional[str] = None) -> Optional[Remediation]:
        with session_scope() as session:
            return RemediationRepository(session).get_remediation(remediation_id, tenant_id=tenant_id)

    def get_remediation_by_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> Optional[Remediation]:
        with session_scope() as session:
            return RemediationRepository(session).get_remediation_by_finding(finding_id, tenant_id=tenant_id)

    def list_remediations(self, tenant_id: str, status: Optional[str] = None) -> List[Remediation]:
        with session_scope() as session:
            return RemediationRepository(session).list_remediations(tenant_id, status=status)

    def update_remediation(self, remediation: Remediation) -> Remediation:
        with session_scope() as session:
            return RemediationRepository(session).update_remediation(remediation)

    def add_remediation_action(self, action: RemediationAction) -> RemediationAction:
        with session_scope() as session:
            return RemediationRepository(session).add_remediation_action(action)

    def get_remediation_actions(self, remediation_id: str, tenant_id: Optional[str] = None) -> List[RemediationAction]:
        with session_scope() as session:
            return RemediationRepository(session).get_remediation_actions(remediation_id, tenant_id=tenant_id)

    def update_remediation_action(self, action: RemediationAction) -> RemediationAction:
        with session_scope() as session:
            return RemediationRepository(session).update_remediation_action(action)

    # =========================================================================
    # Phase 4: SLA Policy Operations (Remediation & Differential Tracking)
    # =========================================================================

    def create_sla_policy(self, policy: SLAPolicy) -> SLAPolicy:
        with session_scope() as session:
            return RemediationRepository(session).create_sla_policy(policy)

    def get_sla_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> Optional[SLAPolicy]:
        with session_scope() as session:
            return RemediationRepository(session).get_sla_policy(policy_id, tenant_id=tenant_id)

    def list_sla_policies(self, tenant_id: str) -> List[SLAPolicy]:
        with session_scope() as session:
            return RemediationRepository(session).list_sla_policies(tenant_id)

    def update_sla_policy(self, policy: SLAPolicy) -> SLAPolicy:
        with session_scope() as session:
            return RemediationRepository(session).update_sla_policy(policy)

    def delete_sla_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> bool:
        with session_scope() as session:
            return RemediationRepository(session).delete_sla_policy(policy_id, tenant_id=tenant_id)

    # =========================================================================
    # Audit Logging
    # =========================================================================

    def log_audit_event(
        self,
        tenant_id: Any,
        actor_user_id: str = "",
        actor_username: str = "",
        action: str = "",
        resource_type: str = "",
        resource_id: str = "",
        result: str = "success",
        metadata: Optional[dict] = None,
    ) -> AuditEvent:
        if isinstance(tenant_id, AuditEvent):
            event = tenant_id
        else:
            event = AuditEvent(
                tenant_id=str(tenant_id or "default-tenant"),
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                result=result,
                metadata=metadata or {},
            )
        with session_scope() as session:
            return AuditRepository(session).log_event(event)

    def list_audit_events(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[dict] = None
    ) -> list:
        filters = filters or {}
        with session_scope() as session:
            return AuditRepository(session).list_events(
                tenant_id=tenant_id,
                action=filters.get("action"),
                resource_type=filters.get("resource_type"),
                limit=limit,
                offset=offset,
            )

    def purge_all_scans_and_findings(self, tenant_id: Optional[str] = None) -> Tuple[int, int]:
        with session_scope() as session:
            f_stmt = delete(FindingModel)
            s_stmt = delete(ScanModel)
            if tenant_id:
                f_stmt = f_stmt.where(FindingModel.tenant_id == tenant_id)
                s_stmt = s_stmt.where(ScanModel.tenant_id == tenant_id)
            f_res = session.execute(f_stmt)
            s_res = session.execute(s_stmt)
            session.flush()
            return (s_res.rowcount or 0, f_res.rowcount or 0)

    # =========================================================================
    # Scheduled Scans & Celery Beat Scheduling
    # =========================================================================

    def save_scheduled_scan(self, sched: ScheduledScan) -> ScheduledScan:
        with session_scope() as session:
            return SchedulerRepository(session).save(sched)

    def update_scheduled_scan(self, sched: ScheduledScan) -> ScheduledScan:
        with session_scope() as session:
            return SchedulerRepository(session).update(sched)

    def get_scheduled_scan(self, sched_id: str, tenant_id: Optional[str] = None) -> Optional[ScheduledScan]:
        with session_scope() as session:
            return SchedulerRepository(session).get_by_id(sched_id, tenant_id=tenant_id)

    def list_scheduled_scans(self, tenant_id: Optional[str] = None) -> List[ScheduledScan]:
        with session_scope() as session:
            return SchedulerRepository(session).list_all(tenant_id=tenant_id)

    def delete_scheduled_scan(self, sched_id: str, tenant_id: Optional[str] = None) -> bool:
        with session_scope() as session:
            return SchedulerRepository(session).delete(sched_id, tenant_id=tenant_id)

    def list_due_schedules(self, as_of: Optional[str] = None) -> List[ScheduledScan]:
        with session_scope() as session:
            return SchedulerRepository(session).list_due_schedules(as_of=as_of)

    def claim_scheduled_run(self, schedule_id: str, tenant_id: str, planned_at: str) -> Optional[ScheduledRun]:
        with session_scope() as session:
            return SchedulerRepository(session).claim_scheduled_run(schedule_id, tenant_id, planned_at)

    def update_run_status(self, run_id: str, status: str, scan_job_id: Optional[str] = None) -> bool:
        with session_scope() as session:
            return SchedulerRepository(session).update_run_status(run_id, status, scan_job_id=scan_job_id)

    def update_scheduled_run_status(self, run_id: str, status: str, scan_job_id: Optional[str] = None) -> bool:
        return self.update_run_status(run_id, status, scan_job_id=scan_job_id)

    # =========================================================================
    # Integration Outbox Lifecycle
    # =========================================================================

    def save_outbox_event(self, outbox: IntegrationOutbox) -> IntegrationOutbox:
        with session_scope() as session:
            return OutboxRepository(session).save(outbox)

    def get_pending_outbox_events(self, limit: int = 50) -> List[IntegrationOutbox]:
        with session_scope() as session:
            return OutboxRepository(session).get_pending_events(limit=limit)

    def update_outbox_status(self, event_id: str, status: str, last_error: Optional[str] = None) -> bool:
        with session_scope() as session:
            return OutboxRepository(session).update_status(event_id, status, last_error=last_error)

    def claim_outbox_events(
        self,
        limit: int = 50,
        worker_id: Optional[str] = None,
        batch_size: Optional[int] = None,
        event_type: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> List[IntegrationOutbox]:
        eff_limit = batch_size if batch_size is not None else limit
        eff_worker = worker_id or "worker-default"
        with session_scope() as session:
            return OutboxRepository(session).claim_events(
                worker_id=eff_worker, batch_size=eff_limit, event_type=event_type, tenant_id=tenant_id
            )

    def mark_outbox_event_processed(self, event_id: str, status: str = "PUBLISHED") -> bool:
        with session_scope() as session:
            return OutboxRepository(session).mark_processed(event_id, status=status)

    def mark_outbox_event_failed(
        self, event_id: str, error: str, max_retries: int = 5, backoff_seconds: int = 60
    ) -> bool:
        with session_scope() as session:
            return OutboxRepository(session).mark_failed(
                event_id, error=error, max_retries=max_retries, backoff_seconds=backoff_seconds
            )

    def recover_stale_outbox_events(self, timeout_seconds: int = 300) -> int:
        with session_scope() as session:
            return OutboxRepository(session).recover_stale_events(timeout_seconds=timeout_seconds)

    def purge_published_outbox_events(self, retention_days: int = 7) -> int:
        with session_scope() as session:
            return OutboxRepository(session).purge_published_events(retention_days=retention_days)

    def get_outbox_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[IntegrationOutbox]:
        with session_scope() as session:
            return OutboxRepository(session).get_by_id(event_id, tenant_id=tenant_id)

    def get_outbox_event_by_key(self, event_key: str, tenant_id: Optional[str] = None) -> Optional[IntegrationOutbox]:
        with session_scope() as session:
            return OutboxRepository(session).get_by_key(event_key, tenant_id=tenant_id)

    def count_pending_outbox_events(self, tenant_id: Optional[str] = None) -> int:
        with session_scope() as session:
            return OutboxRepository(session).count_pending(tenant_id=tenant_id)

    # =========================================================================
    # Governance: API Keys, Policies, Webhooks & Integrations
    # =========================================================================

    def create_api_key(self, api_key: APIKey) -> APIKey:
        with session_scope() as session:
            return GovernanceRepository(session).create_api_key(api_key)

    def get_api_key_by_hash(self, key_hash: str) -> Optional[APIKey]:
        with session_scope() as session:
            return GovernanceRepository(session).get_api_key_by_hash(key_hash)

    def get_api_key(self, key_id: str, tenant_id: Optional[str] = None) -> Optional[APIKey]:
        with session_scope() as session:
            return GovernanceRepository(session).get_api_key(key_id, tenant_id=tenant_id)

    def get_api_key_by_id(self, key_id: str, tenant_id: Optional[str] = None) -> Optional[APIKey]:
        return self.get_api_key(key_id, tenant_id=tenant_id)

    def list_api_keys(self, tenant_id: str) -> List[APIKey]:
        with session_scope() as session:
            return GovernanceRepository(session).list_api_keys(tenant_id)

    def revoke_api_key(self, key_id: str, tenant_id: str) -> bool:
        with session_scope() as session:
            return GovernanceRepository(session).revoke_api_key(key_id, tenant_id)

    def update_api_key(self, api_key: APIKey) -> bool:
        with session_scope() as session:
            return GovernanceRepository(session).update_api_key(api_key)

    def save_policy(self, policy: Policy) -> Policy:
        with session_scope() as session:
            return GovernanceRepository(session).save_policy(policy)

    def get_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> Optional[Policy]:
        with session_scope() as session:
            return GovernanceRepository(session).get_policy(policy_id, tenant_id=tenant_id)

    def list_policies(self, tenant_id: str) -> List[Policy]:
        with session_scope() as session:
            return GovernanceRepository(session).list_policies(tenant_id)

    def save_policy_version(self, version: PolicyVersion) -> PolicyVersion:
        with session_scope() as session:
            return GovernanceRepository(session).save_policy_version(version)

    def get_policy_version(self, version_id: str) -> Optional[PolicyVersion]:
        with session_scope() as session:
            return GovernanceRepository(session).get_policy_version(version_id)

    def list_policy_versions(self, policy_id: str) -> List[PolicyVersion]:
        with session_scope() as session:
            return GovernanceRepository(session).list_policy_versions(policy_id)

    def save_integration(self, integration: Integration) -> Integration:
        with session_scope() as session:
            return GovernanceRepository(session).save_integration(integration)

    def get_integration(self, integration_id: str, tenant_id: Optional[str] = None) -> Optional[Integration]:
        with session_scope() as session:
            return GovernanceRepository(session).get_integration(integration_id, tenant_id=tenant_id)

    def list_integrations(self, tenant_id: str, type: Optional[str] = None) -> List[Integration]:
        with session_scope() as session:
            return GovernanceRepository(session).list_integrations(tenant_id, type=type)

    def update_integration(self, integration: Integration) -> Integration:
        with session_scope() as session:
            return GovernanceRepository(session).update_integration(integration)

    def create_integration(self, integration: Integration) -> Integration:
        with session_scope() as session:
            return GovernanceRepository(session).create_integration(integration)

    def delete_integration(self, integration_id: str, tenant_id: str) -> bool:
        with session_scope() as session:
            return GovernanceRepository(session).delete_integration(integration_id, tenant_id)

    def create_webhook_delivery(self, delivery: WebhookDelivery) -> WebhookDelivery:
        with session_scope() as session:
            return GovernanceRepository(session).create_webhook_delivery(delivery)

    def get_webhook_delivery(self, delivery_id: str, tenant_id: Optional[str] = None) -> Optional[WebhookDelivery]:
        with session_scope() as session:
            return GovernanceRepository(session).get_webhook_delivery(delivery_id, tenant_id=tenant_id)

    def list_webhook_deliveries(self, tenant_id: str, limit: int = 50) -> List[WebhookDelivery]:
        with session_scope() as session:
            return GovernanceRepository(session).list_webhook_deliveries(tenant_id, limit=limit)

    def update_webhook_delivery(self, delivery: WebhookDelivery) -> WebhookDelivery:
        with session_scope() as session:
            return GovernanceRepository(session).update_webhook_delivery(delivery)

    def create_ticket_reference(self, ref: TicketReference) -> TicketReference:
        with session_scope() as session:
            return GovernanceRepository(session).create_ticket_reference(ref)

    def get_ticket_reference(self, ticket_id: str, tenant_id: Optional[str] = None) -> Optional[TicketReference]:
        with session_scope() as session:
            return GovernanceRepository(session).get_ticket_reference(ticket_id, tenant_id=tenant_id)

    def get_ticket_references_for_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> List[TicketReference]:
        with session_scope() as session:
            return GovernanceRepository(session).get_ticket_references_for_finding(finding_id, tenant_id=tenant_id)

    def list_ticket_references(self, tenant_id: str) -> List[TicketReference]:
        with session_scope() as session:
            return GovernanceRepository(session).list_ticket_references(tenant_id)

    def update_ticket_reference(self, ref: TicketReference) -> TicketReference:
        with session_scope() as session:
            return GovernanceRepository(session).update_ticket_reference(ref)

    def save_risk_acceptance(self, ra: RiskAcceptance) -> RiskAcceptance:
        with session_scope() as session:
            return GovernanceRepository(session).save_risk_acceptance(ra)

    def create_risk_acceptance(self, ra: RiskAcceptance) -> RiskAcceptance:
        with session_scope() as session:
            return GovernanceRepository(session).create_risk_acceptance(ra)

    def get_risk_acceptance(self, ra_id: str, tenant_id: Optional[str] = None) -> Optional[RiskAcceptance]:
        with session_scope() as session:
            return GovernanceRepository(session).get_risk_acceptance(ra_id, tenant_id=tenant_id)

    def list_risk_acceptances(self, tenant_id: str, status: Optional[str] = None) -> List[RiskAcceptance]:
        with session_scope() as session:
            return GovernanceRepository(session).list_risk_acceptances(tenant_id, status=status)

    def update_risk_acceptance(self, ra: RiskAcceptance) -> RiskAcceptance:
        with session_scope() as session:
            return GovernanceRepository(session).update_risk_acceptance(ra)

    def get_risk_acceptance_by_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> Optional[RiskAcceptance]:
        with session_scope() as session:
            return GovernanceRepository(session).get_risk_acceptance_by_finding(finding_id, tenant_id=tenant_id)

    def list_active_risk_acceptances(self, tenant_id: str) -> List[RiskAcceptance]:
        with session_scope() as session:
            return GovernanceRepository(session).list_active_risk_acceptances(tenant_id)

    def revoke_risk_acceptance(self, ra_id: str, tenant_id: str) -> bool:
        with session_scope() as session:
            return GovernanceRepository(session).revoke_risk_acceptance(ra_id, tenant_id)

    def save_daily_risk_snapshot(self, snapshot: DailyRiskSnapshot) -> DailyRiskSnapshot:
        with session_scope() as session:
            return GovernanceRepository(session).save_daily_risk_snapshot(snapshot)

    def get_daily_risk_snapshots(self, tenant_id: str, days: int = 30) -> List[DailyRiskSnapshot]:
        with session_scope() as session:
            return GovernanceRepository(session).get_daily_risk_snapshots(tenant_id, days=days)

    def save_discovery_scope(self, scope: DiscoveryScope) -> DiscoveryScope:
        with session_scope() as session:
            return GovernanceRepository(session).save_discovery_scope(scope)

    def get_discovery_scope(self, scope_id: str, tenant_id: Optional[str] = None) -> Optional[DiscoveryScope]:
        with session_scope() as session:
            return GovernanceRepository(session).get_discovery_scope(scope_id, tenant_id=tenant_id)

    def list_discovery_scopes(self, tenant_id: str) -> List[DiscoveryScope]:
        with session_scope() as session:
            return GovernanceRepository(session).list_discovery_scopes(tenant_id)

    def save_business_unit(self, bu: BusinessUnit) -> BusinessUnit:
        with session_scope() as session:
            return GovernanceRepository(session).save_business_unit(bu)

    def get_business_unit(self, bu_id: str, tenant_id: Optional[str] = None) -> Optional[BusinessUnit]:
        with session_scope() as session:
            return GovernanceRepository(session).get_business_unit(bu_id, tenant_id=tenant_id)

    def list_business_units(self, tenant_id: str) -> List[BusinessUnit]:
        with session_scope() as session:
            return GovernanceRepository(session).list_business_units(tenant_id)

    # =========================================================================
    # Aggregated Visibility & Dashboard Metrics (PostgreSQL 16)
    # =========================================================================

    def get_queue_depth_metrics(self) -> dict:
        now = datetime.now(timezone.utc)
        with session_scope() as session:
            try:
                row_scan = session.execute(
                    text("SELECT COUNT(*), MIN(queued_at) FROM scan_jobs WHERE status = 'queued'")
                ).fetchone()
                scan_count = row_scan[0] if row_scan else 0
                oldest_scan_queued_at = row_scan[1] if (row_scan and row_scan[1]) else None
            except Exception:
                scan_count, oldest_scan_queued_at = 0, None

            oldest_scan_age_sec = 0
            if oldest_scan_queued_at:
                try:
                    dt = datetime.fromisoformat(str(oldest_scan_queued_at))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    oldest_scan_age_sec = max(0, int((now - dt).total_seconds()))
                except Exception:
                    oldest_scan_age_sec = 0

            try:
                row_outbox = session.execute(
                    text("SELECT COUNT(*) FROM integration_outbox WHERE status IN ('PENDING', 'RETRYING')")
                ).fetchone()
                outbox_count = row_outbox[0] if row_outbox else 0
            except Exception:
                outbox_count = 0

            try:
                row_intel = session.execute(
                    text("SELECT COUNT(*) FROM intelligence_sync_status WHERE status = 'running'")
                ).fetchone()
                intel_count = row_intel[0] if row_intel else 0
            except Exception:
                intel_count = 0

            return {
                "scan_queue_depth": scan_count,
                "oldest_queued_job_seconds": oldest_scan_age_sec,
                "integration_queue_depth": outbox_count,
                "intel_queue_depth": intel_count,
            }

    def get_portfolio_metrics(self, tenant_id: str, bu_id: Optional[str] = None) -> dict:
        with session_scope() as session:
            asset_filter = "WHERE a.tenant_id = :tenant_id"
            finding_filter = "WHERE f.tenant_id = :tenant_id"
            params: Dict[str, Any] = {"tenant_id": tenant_id}
            if bu_id:
                asset_filter += " AND a.business_unit_id = :bu_id"
                finding_filter += " AND a.business_unit_id = :bu_id"
                params["bu_id"] = bu_id

            asset_row = session.execute(text(f"""
                SELECT
                    COUNT(a.id) as total_assets,
                    SUM(CASE WHEN a.criticality = 'critical' THEN 1 ELSE 0 END) as critical_assets,
                    SUM(CASE WHEN a.internet_exposure = 'external' THEN 1 ELSE 0 END) as internet_facing,
                    SUM(CASE WHEN a.business_owner != '' AND a.business_owner IS NOT NULL THEN 1 ELSE 0 END) as has_biz_owner,
                    SUM(CASE WHEN a.technical_owner != '' AND a.technical_owner IS NOT NULL THEN 1 ELSE 0 END) as has_tech_owner,
                    SUM(CASE WHEN a.business_unit_id IS NOT NULL AND a.business_unit_id != '' THEN 1 ELSE 0 END) as assigned_to_bu
                FROM assets a
                {asset_filter}
            """), params).fetchone()

            ver_params: Dict[str, Any] = {"tenant_id": tenant_id}
            ver_join = ""
            if bu_id:
                ver_join = "JOIN assets a ON v.asset_id = a.id AND a.business_unit_id = :bu_id"
                ver_params["bu_id"] = bu_id
            ver_row = session.execute(text(f"""
                SELECT COUNT(DISTINCT v.asset_id) as verified_assets
                FROM asset_verifications v
                {ver_join}
                WHERE v.tenant_id = :tenant_id AND v.status = 'VERIFIED'
            """), ver_params).fetchone()

            f_params: Dict[str, Any] = {"tenant_id": tenant_id}
            if bu_id:
                f_params["bu_id"] = bu_id
            finding_row = session.execute(text(f"""
                SELECT
                    COUNT(f.id) as total_open_findings,
                    SUM(CASE WHEN f.priority_band = 'P1' THEN 1 ELSE 0 END) as open_p1,
                    SUM(CASE WHEN f.priority_band = 'P2' THEN 1 ELSE 0 END) as open_p2,
                    SUM(CASE WHEN f.kev IS TRUE THEN 1 ELSE 0 END) as open_kev,
                    SUM(CASE WHEN f.sla_status = 'BREACHED' THEN 1 ELSE 0 END) as sla_breaches,
                    SUM(CASE WHEN f.status = 'ACCEPTED' THEN 1 ELSE 0 END) as risk_accepted,
                    SUM(CASE WHEN f.assigned_to_user_id IS NULL OR f.assigned_to_user_id = '' THEN 1 ELSE 0 END) as unassigned_findings,
                    SUM(CASE WHEN f.finding_confidence IN ('HIGH', 'CONFIRMED') THEN 1 ELSE 0 END) as high_confidence_findings
                FROM findings f
                JOIN assets a ON f.asset_id = a.id
                {finding_filter} AND f.status NOT IN ('RESOLVED', 'CLOSED', 'FALSE_POSITIVE')
            """), f_params).fetchone()

            candidate_row = session.execute(text(
                "SELECT COUNT(*) as candidates FROM discovered_assets WHERE tenant_id = :tenant_id AND status = 'NEW'"
            ), {"tenant_id": tenant_id}).fetchone()

            total_assets = (asset_row[0] or 0) if asset_row else 0
            verified_count = (ver_row[0] or 0) if ver_row else 0

            return {
                "assets": total_assets,
                "verified_assets": verified_count,
                "unverified_assets": max(0, total_assets - verified_count),
                "internet_facing_assets": (asset_row[2] or 0) if asset_row else 0,
                "critical_assets": (asset_row[1] or 0) if asset_row else 0,
                "open_p1": (finding_row[1] or 0) if finding_row else 0,
                "open_p2": (finding_row[2] or 0) if finding_row else 0,
                "open_kev": (finding_row[3] or 0) if finding_row else 0,
                "sla_breaches": (finding_row[4] or 0) if finding_row else 0,
                "risk_accepted": (finding_row[5] or 0) if finding_row else 0,
                "unassigned_findings": (finding_row[6] or 0) if finding_row else 0,
                "high_confidence_findings": (finding_row[7] or 0) if finding_row else 0,
                "discovery_candidates": (candidate_row[0] or 0) if candidate_row else 0,
                "business_owner_coverage_pct": round(((asset_row[3] or 0) / max(1, total_assets)) * 100, 1) if asset_row else 0.0,
                "technical_owner_coverage_pct": round(((asset_row[4] or 0) / max(1, total_assets)) * 100, 1) if asset_row else 0.0,
                "bu_assignment_coverage_pct": round(((asset_row[5] or 0) / max(1, total_assets)) * 100, 1) if asset_row else 0.0,
                "verification_coverage_pct": round((verified_count / max(1, total_assets)) * 100, 1)
            }

    def get_monitoring_dashboard(self, tenant_id: str) -> dict:
        now = datetime.now(timezone.utc)
        cutoff_24h = (now - timedelta(hours=24)).isoformat()
        with session_scope() as session:
            asset_row = session.execute(text("""
                SELECT
                    COUNT(a.id) as total_assets,
                    SUM(CASE WHEN a.status = 'active' THEN 1 ELSE 0 END) as active_assets
                FROM assets a WHERE a.tenant_id = :tenant_id
            """), {"tenant_id": tenant_id}).fetchone()

            scan_row = session.execute(text("""
                SELECT
                    SUM(CASE WHEN s.status = 'COMPLETED' THEN 1 ELSE 0 END) as completed_scans,
                    SUM(CASE WHEN s.status = 'FAILED' THEN 1 ELSE 0 END) as failed_scans,
                    SUM(CASE WHEN s.status = 'RUNNING' THEN 1 ELSE 0 END) as running_scans
                FROM scans s WHERE s.tenant_id = :tenant_id
            """), {"tenant_id": tenant_id}).fetchone()

            finding_row = session.execute(text("""
                SELECT
                    SUM(CASE WHEN severity = 'critical' AND status NOT IN ('VERIFIED','CLOSED','FALSE_POSITIVE','REMEDIATED') THEN 1 ELSE 0 END) as critical_findings,
                    SUM(CASE WHEN severity = 'high' AND status NOT IN ('VERIFIED','CLOSED','FALSE_POSITIVE','REMEDIATED') THEN 1 ELSE 0 END) as high_findings
                FROM findings WHERE tenant_id = :tenant_id
            """), {"tenant_id": tenant_id}).fetchone()

            new_row = session.execute(text(
                "SELECT COUNT(*) as cnt FROM findings WHERE tenant_id = :tenant_id AND created_at >= :cutoff"
            ), {"tenant_id": tenant_id, "cutoff": cutoff_24h}).fetchone()

            resolved_row = session.execute(text("""
                SELECT COUNT(*) as cnt FROM finding_history fh
                JOIN findings f ON fh.finding_id = f.id
                WHERE f.tenant_id = :tenant_id
                  AND fh.new_status IN ('VERIFIED','CLOSED','REMEDIATED')
                  AND fh.created_at >= :cutoff
            """), {"tenant_id": tenant_id, "cutoff": cutoff_24h}).fetchone()

            fail_row = session.execute(text(
                "SELECT COUNT(*) as cnt FROM scans WHERE tenant_id = :tenant_id AND status = 'FAILED' AND started_at >= :cutoff"
            ), {"tenant_id": tenant_id, "cutoff": cutoff_24h}).fetchone()

            sched_row = session.execute(text("""
                SELECT
                    COUNT(*) as total_scheduled,
                    SUM(CASE WHEN paused_until IS NOT NULL THEN 1 ELSE 0 END) as paused_scheduled
                FROM scheduled_scans WHERE tenant_id = :tenant_id
            """), {"tenant_id": tenant_id}).fetchone()

            hist_rows = session.execute(text("""
                SELECT date, avg_risk_score, open_findings, p1_count, p2_count, sla_breaches
                FROM daily_risk_snapshots
                WHERE tenant_id = :tenant_id
                ORDER BY date DESC LIMIT 7
            """), {"tenant_id": tenant_id}).fetchall()

            trend = [
                {
                    "date": r[0], "risk_score": r[1], "risk_score_avg": r[1], "open_findings": r[2],
                    "critical": r[3], "high": r[4], "sla_breaches": r[5]
                }
                for r in reversed(hist_rows)
            ]

            total_assets = (asset_row[0] or 0) if asset_row else 0
            completed_scans = (scan_row[0] or 0) if scan_row else 0
            failed_scans = (scan_row[1] or 0) if scan_row else 0
            running_scans = (scan_row[2] or 0) if scan_row else 0

            return {
                "tenant_id": tenant_id,
                "total_assets": total_assets,
                "monitored_assets": total_assets,
                "paused_assets": 0,
                "assets_needing_attention": max(0, total_assets - completed_scans),
                "monitoring_coverage_pct": 100.0 if total_assets > 0 else 0.0,
                "last_scan_status": {
                    "completed": completed_scans,
                    "failed": failed_scans,
                    "running": running_scans,
                    "never": max(0, total_assets - completed_scans - failed_scans - running_scans),
                },
                "open_findings": {
                    "critical": (finding_row[0] or 0) if finding_row else 0,
                    "high": (finding_row[1] or 0) if finding_row else 0,
                },
                "newly_discovered_last_24h": (new_row[0] or 0) if new_row else 0,
                "resolved_last_24h": (resolved_row[0] or 0) if resolved_row else 0,
                "scan_failures_last_24h": (fail_row[0] or 0) if fail_row else 0,
                "scheduled_scans": {
                    "total": (sched_row[0] or 0) if sched_row else 0,
                    "paused": (sched_row[1] or 0) if sched_row else 0,
                },
                "intel_freshness_seconds": None,
                "intel_freshness_label": "Unknown",
                "historical_risk_trend": trend,
            }

    def list_data_quality_issues(self, tenant_id: str, unresolved_only: bool = False) -> List[Any]:
        with session_scope() as session:
            stmt = select(DataQualityIssueModel).where(DataQualityIssueModel.tenant_id == tenant_id)
            if unresolved_only:
                stmt = stmt.where(DataQualityIssueModel.resolved_at.is_(None))
            stmt = stmt.order_by(DataQualityIssueModel.detected_at.desc())
            models = session.execute(stmt).scalars().all()
            return [
                DataQualityIssue(
                    id=m.id, tenant_id=m.tenant_id, entity_type=m.entity_type,
                    entity_id=m.entity_id, issue_type=m.issue_type, severity=m.severity,
                    description=m.description, detected_at=m.detected_at, resolved_at=m.resolved_at
                ) for m in models
            ]

    def list_discovered_assets(self, tenant_id: str, status: Optional[str] = None, scope_id: Optional[str] = None) -> List[Any]:
        with session_scope() as session:
            stmt = select(DiscoveredAssetModel).where(DiscoveredAssetModel.tenant_id == tenant_id)
            if status:
                stmt = stmt.where(DiscoveredAssetModel.status == status.upper())
            if scope_id:
                stmt = stmt.where(DiscoveredAssetModel.discovery_scope_id == scope_id)
            stmt = stmt.order_by(DiscoveredAssetModel.created_at.desc())
            models = session.execute(stmt).scalars().all()
            return [
                DiscoveredAsset(
                    id=m.id, tenant_id=m.tenant_id, scope_id=m.discovery_scope_id, source=m.source,
                    host=m.hostname, domain=m.hostname, ip="", port=80, scheme="https",
                    status=m.status, discovered_at=m.created_at, metadata={}
                ) for m in models
            ]

    def save_technology_observation(self, obs: Any) -> Any:
        with session_scope() as session:
            stmt = select(TechnologyObservationModel).where(
                TechnologyObservationModel.tenant_id == obs.tenant_id,
                TechnologyObservationModel.asset_id == obs.asset_id,
                TechnologyObservationModel.name == obs.name
            )
            model = session.execute(stmt).scalar_one_or_none()
            now_iso = datetime.now(timezone.utc).isoformat()
            if model:
                model.version = obs.version
                model.source = obs.source
                model.confidence = obs.confidence
                model.last_seen = obs.last_seen or now_iso
                model.updated_at = now_iso
            else:
                model = TechnologyObservationModel(
                    id=obs.id, tenant_id=obs.tenant_id, asset_id=obs.asset_id,
                    technology_type=obs.technology_type, name=obs.name,
                    version=obs.version, source=obs.source, confidence=obs.confidence,
                    eol_status=obs.eol_status, first_seen=obs.first_seen or now_iso,
                    last_seen=obs.last_seen or now_iso, created_at=obs.created_at or now_iso,
                    updated_at=obs.updated_at or now_iso
                )
                session.add(model)
            session.flush()
            return obs

    def list_technology_observations(self, tenant_id: str, asset_id: Optional[str] = None) -> List[Any]:
        with session_scope() as session:
            stmt = select(TechnologyObservationModel).where(TechnologyObservationModel.tenant_id == tenant_id)
            if asset_id:
                stmt = stmt.where(TechnologyObservationModel.asset_id == asset_id)
            stmt = stmt.order_by(TechnologyObservationModel.last_seen.desc())
            models = session.execute(stmt).scalars().all()
            return [
                TechnologyObservation(
                    id=m.id, tenant_id=m.tenant_id, asset_id=m.asset_id,
                    technology_type=m.technology_type, name=m.name, version=m.version,
                    source=m.source, confidence=m.confidence, eol_status=m.eol_status,
                    first_seen=m.first_seen, last_seen=m.last_seen,
                    created_at=m.created_at, updated_at=m.updated_at
                ) for m in models
            ]

    def list_saved_views(self, tenant_id: str, user_id: Optional[str] = None) -> List[Any]:
        with session_scope() as session:
            stmt = select(SavedViewModel).where(SavedViewModel.tenant_id == tenant_id)
            if user_id:
                stmt = stmt.where((SavedViewModel.user_id == user_id) | (SavedViewModel.is_shared == True))
            stmt = stmt.order_by(SavedViewModel.created_at.desc())
            models = session.execute(stmt).scalars().all()
            return [
                SavedView(
                    id=m.id, tenant_id=m.tenant_id, user_id=m.user_id, name=m.name,
                    resource_type=m.resource_type, filters_json=m.filters_json or {},
                    is_shared=bool(m.is_shared), created_at=m.created_at
                ) for m in models
            ]

    def get_intel_sync_status(self, source: str) -> Optional[Any]:
        with session_scope() as session:
            model = session.execute(
                select(IntelSyncStatusModel).where(IntelSyncStatusModel.source == source)
            ).scalar_one_or_none()
            if not model:
                return None
            return IntelSyncStatus(
                id=model.id,
                source=model.source,
                last_success=model.last_success,
                last_attempt=model.last_attempt,
                status=model.status,
                records_processed=model.records_processed or 0,
                error_code=model.error_code,
                error_message=model.error_message,
                freshness_age_seconds=model.freshness_age_seconds,
                created_at=model.created_at,
                updated_at=model.updated_at,
            )

    def list_intel_sync_statuses(self) -> List[Any]:
        with session_scope() as session:
            models = session.execute(
                select(IntelSyncStatusModel).order_by(IntelSyncStatusModel.source.asc())
            ).scalars().all()
            return [
                IntelSyncStatus(
                    id=m.id,
                    source=m.source,
                    last_success=m.last_success,
                    last_attempt=m.last_attempt,
                    status=m.status,
                    records_processed=m.records_processed or 0,
                    error_code=m.error_code,
                    error_message=m.error_message,
                    freshness_age_seconds=m.freshness_age_seconds,
                    created_at=m.created_at,
                    updated_at=m.updated_at,
                ) for m in models
            ]

    def update_intel_sync_status(
        self,
        source: str,
        status: str,
        records_processed: int = 0,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Any:
        import uuid
        now_iso = datetime.now(timezone.utc).isoformat()
        with session_scope() as session:
            model = session.execute(
                select(IntelSyncStatusModel).where(IntelSyncStatusModel.source == source)
            ).scalar_one_or_none()
            if not model:
                new_id = str(uuid.uuid4())
                last_succ = now_iso if status == "success" else None
                model = IntelSyncStatusModel(
                    id=new_id,
                    source=source,
                    last_success=last_succ,
                    last_attempt=now_iso,
                    status=status,
                    records_processed=records_processed,
                    error_code=error_code,
                    error_message=error_message,
                    freshness_age_seconds=0 if last_succ else None,
                    created_at=now_iso,
                    updated_at=now_iso,
                )
                session.add(model)
            else:
                last_succ = now_iso if status == "success" else model.last_success
                freshness_age = 0 if status == "success" else model.freshness_age_seconds
                if last_succ and status != "success":
                    try:
                        last_dt = datetime.fromisoformat(last_succ)
                        if last_dt.tzinfo is None:
                            last_dt = last_dt.replace(tzinfo=timezone.utc)
                        freshness_age = int((datetime.now(timezone.utc) - last_dt).total_seconds())
                    except Exception:
                        pass
                model.last_success = last_succ
                model.last_attempt = now_iso
                model.status = status
                model.records_processed = records_processed
                model.error_code = error_code
                model.error_message = error_message
                model.freshness_age_seconds = freshness_age
                model.updated_at = now_iso
            session.flush()
            return IntelSyncStatus(
                id=model.id,
                source=model.source,
                last_success=model.last_success,
                last_attempt=model.last_attempt,
                status=model.status,
                records_processed=model.records_processed or 0,
                error_code=model.error_code,
                error_message=model.error_message,
                freshness_age_seconds=model.freshness_age_seconds,
                created_at=model.created_at,
                updated_at=model.updated_at,
            )


_pg_adapter_instance: Optional[PostgresqlOperationalAdapter] = None


def get_operational_adapter() -> Optional[OperationalBackendAdapter]:
    """
    Returns the active operational backend adapter if PostgreSQL is configured,
    or None if SQLite is active.
    """
    global _pg_adapter_instance
    if is_postgres_configured():
        if _pg_adapter_instance is None:
            _pg_adapter_instance = PostgresqlOperationalAdapter()
        return _pg_adapter_instance
    return None


def adapter_dispatch(method_name: str):
    """
    Method decorator for core.repository functions.
    If PostgreSQL is configured:
      - Routes to the active adapter if supported.
      - Explicitly raises NotImplementedError if unsupported (never falls back silently).
    If SQLite is configured:
      - Invokes the original native SQLite function transparently.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            adapter = get_operational_adapter()
            if adapter is not None:
                adapter_method = getattr(adapter, method_name, None)
                if adapter_method is not None:
                    return adapter_method(*args, **kwargs)
                raise NotImplementedError(
                    f"PostgreSQL operational persistence: '{method_name}' is outside Phase 5 scope. "
                    f"Unsupported operation must fail explicitly."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
