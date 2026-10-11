"""
Finding, Observation, and History Repository using SQLAlchemy 2.x
"""
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, timezone
import html
from sqlalchemy import select, and_, or_, delete, func
from sqlalchemy.orm import Session
from core.models import (
    Finding, FindingObservation, FindingHistory, FindingComment,
    Severity
)
from core.lifecycle import FindingStatus, OptimisticLockError
from core.db.models import (
    FindingModel, FindingObservationModel, FindingHistoryModel,
    FindingCommentModel, AuditEventModel
)


class FindingRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(m: FindingModel) -> Finding:
        sev = Severity.INFO
        try:
            sev = Severity(m.severity)
        except Exception:
            pass

        return Finding(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_id=m.asset_id,
            scan_id=m.scan_id,
            category=m.category or "",
            title=m.title or "",
            description=m.description or "",
            severity=sev,
            confidence=float(m.confidence) if m.confidence is not None else 1.0,
            remediation=m.remediation or "",
            reference=m.reference or "",
            raw_data=m.raw_data if isinstance(m.raw_data, dict) else {},
            fingerprint=m.fingerprint or "",
            status=m.status or "OPEN",
            first_seen_at=m.first_seen_at or m.created_at,
            last_seen_at=m.last_seen_at or m.created_at,
            first_scan_id=m.first_scan_id or m.scan_id,
            last_scan_id=m.last_scan_id or m.scan_id,
            observation_count=int(m.observation_count) if m.observation_count is not None else 1,
            assigned_to_user_id=m.assigned_to_user_id,
            assigned_team=m.assigned_team,
            assigned_at=m.assigned_at,
            finding_tags=m.finding_tags if isinstance(m.finding_tags, list) else [],
            version=int(m.version) if m.version is not None else 1,
            priority_score=float(m.priority_score) if m.priority_score is not None else 0.0,
            priority_band=m.priority_band or "P3",
            cvss_score=float(m.cvss_score) if m.cvss_score is not None else None,
            epss_score=float(m.epss_score) if m.epss_score is not None else None,
            epss_percentile=float(m.epss_percentile) if m.epss_percentile is not None else None,
            epss_last_updated=m.epss_last_updated,
            kev=bool(m.kev) if m.kev is not None else False,
            kev_date_added=m.kev_date_added,
            kev_due_date=m.kev_due_date,
            known_ransomware_campaign_use=bool(m.known_ransomware_campaign_use) if m.known_ransomware_campaign_use is not None else False,
            ransomware_relevance=m.ransomware_relevance or "NONE",
            cve_id=m.cve_id,
            sla_policy_id=m.sla_policy_id,
            sla_due_at=m.sla_due_at,
            sla_status=m.sla_status or "NOT_APPLICABLE",
            sla_paused_at=m.sla_paused_at,
            sla_pause_reason=m.sla_pause_reason,
            verified_at=m.verified_at,
            verified_by_scan_id=m.verified_by_scan_id,
            false_positive_reason=m.false_positive_reason,
            false_positive_by=m.false_positive_by,
            false_positive_at=m.false_positive_at,
            false_positive_valid_until=m.false_positive_valid_until,
            finding_confidence=m.finding_confidence or "HIGH",
            policy_version_id=m.policy_version_id,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    @staticmethod
    def _to_observation_domain(m: FindingObservationModel) -> FindingObservation:
        return FindingObservation(
            id=m.id,
            tenant_id=m.tenant_id,
            finding_id=m.finding_id,
            scan_id=m.scan_id,
            asset_id=m.asset_id,
            scanner_id=m.scanner_id,
            observed_at=m.observed_at,
            severity=m.severity,
            evidence_id=m.evidence_id,
            evidence_reference=m.evidence_reference or m.evidence_id,
            status=m.status,
            raw_reference=m.raw_reference,
            created_at=m.created_at,
        )

    @staticmethod
    def _to_history_domain(m: FindingHistoryModel) -> FindingHistory:
        return FindingHistory(
            id=m.id,
            tenant_id=m.tenant_id,
            finding_id=m.finding_id,
            actor_user_id=m.actor_user_id,
            action=m.action,
            old_status=m.old_status,
            new_status=m.new_status,
            comment=m.comment or "",
            metadata=m.metadata_ if isinstance(m.metadata_, dict) else {},
            created_at=m.created_at,
        )

    @staticmethod
    def _to_comment_domain(m: FindingCommentModel) -> FindingComment:
        return FindingComment(
            id=m.id,
            tenant_id=m.tenant_id,
            finding_id=m.finding_id,
            author_user_id=m.author_user_id,
            author_username=m.author_username or "",
            body=m.body,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    # -------------------------------------------------------------------------
    # Finding CRUD & Query Operations
    # -------------------------------------------------------------------------

    def get_by_id(self, finding_id: str, tenant_id: Optional[str] = None) -> Optional[Finding]:
        stmt = select(FindingModel).where(FindingModel.id == finding_id)
        if tenant_id:
            stmt = stmt.where(FindingModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def get_by_fingerprint(self, tenant_id: str, fingerprint: str) -> Optional[Finding]:
        stmt = select(FindingModel).where(
            and_(FindingModel.tenant_id == tenant_id, FindingModel.fingerprint == fingerprint)
        )
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def list_by_scan(self, scan_id: str, tenant_id: Optional[str] = None) -> List[Finding]:
        subq = select(FindingObservationModel.finding_id).where(FindingObservationModel.scan_id == scan_id)
        stmt = select(FindingModel).where(
            or_(FindingModel.scan_id == scan_id, FindingModel.id.in_(subq))
        )
        if tenant_id:
            stmt = stmt.where(FindingModel.tenant_id == tenant_id)
        stmt = stmt.order_by(FindingModel.priority_score.desc(), FindingModel.severity, FindingModel.created_at)
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_by_asset(self, asset_id: str, tenant_id: Optional[str] = None) -> List[Finding]:
        stmt = select(FindingModel).where(FindingModel.asset_id == asset_id)
        if tenant_id:
            stmt = stmt.where(FindingModel.tenant_id == tenant_id)
        stmt = stmt.order_by(FindingModel.priority_score.desc(), FindingModel.severity, FindingModel.created_at.desc())
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_findings(
        self,
        tenant_id: str,
        filters: Optional[dict] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[Finding], int]:
        filters = filters or {}
        conditions = [FindingModel.tenant_id == tenant_id]

        if filters.get("status"):
            conditions.append(FindingModel.status == filters["status"].upper().strip())
        if filters.get("severity"):
            conditions.append(FindingModel.severity == filters["severity"].lower().strip())
        if filters.get("priority_band"):
            conditions.append(FindingModel.priority_band == filters["priority_band"].upper().strip())
        if filters.get("sla_status"):
            conditions.append(FindingModel.sla_status == filters["sla_status"].upper().strip())
        if filters.get("asset_id"):
            conditions.append(FindingModel.asset_id == filters["asset_id"])
        if filters.get("kev") is not None:
            conditions.append(FindingModel.kev == bool(filters["kev"]))
        if filters.get("search"):
            s = f"%{filters['search']}%"
            conditions.append(
                or_(
                    FindingModel.title.ilike(s),
                    FindingModel.cve_id.ilike(s),
                    FindingModel.description.ilike(s)
                )
            )

        # Count total matching
        count_stmt = select(func.count(FindingModel.id)).where(and_(*conditions))
        total_count = self.session.execute(count_stmt).scalar() or 0

        # Query page
        offset = max(0, (page - 1) * page_size)
        query_stmt = (
            select(FindingModel)
            .where(and_(*conditions))
            .order_by(FindingModel.priority_score.desc(), FindingModel.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        models = self.session.execute(query_stmt).scalars().all()
        return [self._to_domain(m) for m in models], total_count

    def save_finding(self, finding: Finding, expected_version: Optional[int] = None) -> Finding:
        now_iso = datetime.now(timezone.utc).isoformat()
        if not finding.updated_at:
            finding.updated_at = now_iso

        sev_str = finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity)

        stmt = select(FindingModel).where(FindingModel.id == finding.id)
        model = self.session.execute(stmt).scalar_one_or_none()

        if model:
            current_version = model.version or 1
            if expected_version is not None and current_version != expected_version:
                raise OptimisticLockError(finding.id, expected_version)

            new_version = current_version + 1
            finding.version = new_version
            finding.updated_at = now_iso

            model.tenant_id = finding.tenant_id or "default-tenant"
            model.asset_id = finding.asset_id
            model.scan_id = finding.scan_id
            model.category = finding.category
            model.title = finding.title
            model.description = finding.description
            model.severity = sev_str
            model.confidence = finding.confidence
            model.remediation = finding.remediation
            model.reference = finding.reference
            model.raw_data = finding.raw_data
            model.fingerprint = finding.fingerprint
            model.status = finding.status
            model.first_seen_at = finding.first_seen_at
            model.last_seen_at = finding.last_seen_at
            model.first_scan_id = finding.first_scan_id
            model.last_scan_id = finding.last_scan_id
            model.observation_count = finding.observation_count
            model.assigned_to_user_id = finding.assigned_to_user_id
            model.assigned_team = finding.assigned_team
            model.assigned_at = finding.assigned_at
            model.finding_tags = finding.finding_tags
            model.version = new_version
            model.priority_score = finding.priority_score
            model.priority_band = finding.priority_band
            model.cvss_score = finding.cvss_score
            model.epss_score = finding.epss_score
            model.epss_percentile = finding.epss_percentile
            model.epss_last_updated = finding.epss_last_updated
            model.kev = bool(finding.kev)
            model.kev_date_added = finding.kev_date_added
            model.kev_due_date = finding.kev_due_date
            model.known_ransomware_campaign_use = bool(finding.known_ransomware_campaign_use)
            model.ransomware_relevance = finding.ransomware_relevance
            model.cve_id = finding.cve_id
            model.sla_policy_id = finding.sla_policy_id
            model.sla_due_at = finding.sla_due_at
            model.sla_status = finding.sla_status
            model.sla_paused_at = finding.sla_paused_at
            model.sla_pause_reason = finding.sla_pause_reason
            model.verified_at = finding.verified_at
            model.verified_by_scan_id = finding.verified_by_scan_id
            model.false_positive_reason = finding.false_positive_reason
            model.false_positive_by = finding.false_positive_by
            model.false_positive_at = finding.false_positive_at
            model.false_positive_valid_until = finding.false_positive_valid_until
            model.finding_confidence = getattr(finding, "finding_confidence", "HIGH")
            model.policy_version_id = getattr(finding, "policy_version_id", None)
            model.updated_at = now_iso
        else:
            model = FindingModel(
                id=finding.id,
                tenant_id=finding.tenant_id or "default-tenant",
                asset_id=finding.asset_id,
                scan_id=finding.scan_id,
                category=finding.category,
                title=finding.title,
                description=finding.description,
                severity=sev_str,
                confidence=finding.confidence,
                remediation=finding.remediation,
                reference=finding.reference,
                raw_data=finding.raw_data,
                fingerprint=finding.fingerprint,
                status=finding.status,
                first_seen_at=finding.first_seen_at,
                last_seen_at=finding.last_seen_at,
                first_scan_id=finding.first_scan_id,
                last_scan_id=finding.last_scan_id,
                observation_count=finding.observation_count,
                assigned_to_user_id=finding.assigned_to_user_id,
                assigned_team=finding.assigned_team,
                assigned_at=finding.assigned_at,
                finding_tags=finding.finding_tags,
                version=finding.version or 1,
                priority_score=finding.priority_score,
                priority_band=finding.priority_band,
                cvss_score=finding.cvss_score,
                epss_score=finding.epss_score,
                epss_percentile=finding.epss_percentile,
                epss_last_updated=finding.epss_last_updated,
                kev=bool(finding.kev),
                kev_date_added=finding.kev_date_added,
                kev_due_date=finding.kev_due_date,
                known_ransomware_campaign_use=bool(finding.known_ransomware_campaign_use),
                ransomware_relevance=finding.ransomware_relevance,
                cve_id=finding.cve_id,
                sla_policy_id=finding.sla_policy_id,
                sla_due_at=finding.sla_due_at,
                sla_status=finding.sla_status,
                sla_paused_at=finding.sla_paused_at,
                sla_pause_reason=finding.sla_pause_reason,
                verified_at=finding.verified_at,
                verified_by_scan_id=finding.verified_by_scan_id,
                false_positive_reason=finding.false_positive_reason,
                false_positive_by=finding.false_positive_by,
                false_positive_at=finding.false_positive_at,
                false_positive_valid_until=finding.false_positive_valid_until,
                finding_confidence=getattr(finding, "finding_confidence", "HIGH"),
                policy_version_id=getattr(finding, "policy_version_id", None),
                created_at=finding.created_at,
                updated_at=finding.updated_at,
            )
            self.session.add(model)

        self.session.flush()
        return finding

    def save_findings_bulk(self, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            self.save_finding(f)
        return findings

    def delete_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> bool:
        stmt = delete(FindingModel).where(FindingModel.id == finding_id)
        if tenant_id:
            stmt = stmt.where(FindingModel.tenant_id == tenant_id)
        res = self.session.execute(stmt)
        self.session.flush()
        return (res.rowcount or 0) > 0

    def delete_by_scan(self, scan_id: str, tenant_id: str) -> int:
        stmt = delete(FindingModel).where(
            and_(FindingModel.scan_id == scan_id, FindingModel.tenant_id == tenant_id)
        )
        res = self.session.execute(stmt)
        self.session.flush()
        return res.rowcount or 0

    def update_finding(self, finding_id: str, tenant_id: Optional[str] = None, **kwargs) -> bool:
        stmt = select(FindingModel).where(FindingModel.id == finding_id)
        if tenant_id:
            stmt = stmt.where(FindingModel.tenant_id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False

        allowed = {
            "category", "title", "description", "severity", "confidence", "remediation", "reference",
            "asset_id", "tenant_id", "status", "assigned_to_user_id", "assigned_team", "assigned_at",
            "priority_score", "priority_band", "cvss_score", "epss_score", "epss_percentile",
            "kev", "sla_due_at", "sla_status", "sla_paused_at", "sla_pause_reason", "verified_at",
            "verified_by_scan_id", "false_positive_reason", "false_positive_by", "false_positive_at",
            "false_positive_valid_until", "updated_at"
        }
        for k, v in kwargs.items():
            if k in allowed:
                if hasattr(v, "value"):
                    v = v.value
                setattr(model, k, v)

        model.version = (model.version or 1) + 1
        model.updated_at = datetime.now(timezone.utc).isoformat()
        self.session.flush()
        return True

    # -------------------------------------------------------------------------
    # Observations
    # -------------------------------------------------------------------------

    def save_observation(self, obs: FindingObservation) -> FindingObservation:
        # Check if observation for (finding_id, scan_id) already exists to handle upsert
        stmt = select(FindingObservationModel).where(
            and_(
                FindingObservationModel.finding_id == obs.finding_id,
                FindingObservationModel.scan_id == obs.scan_id
            )
        )
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.observed_at = obs.observed_at
            model.severity = obs.severity
            model.evidence_id = obs.evidence_id
            model.evidence_reference = obs.evidence_reference or obs.evidence_id
            model.status = obs.status
            model.raw_reference = obs.raw_reference
        else:
            model = FindingObservationModel(
                id=obs.id,
                tenant_id=obs.tenant_id,
                finding_id=obs.finding_id,
                scan_id=obs.scan_id,
                asset_id=obs.asset_id,
                scanner_id=obs.scanner_id,
                observed_at=obs.observed_at,
                severity=obs.severity,
                evidence_id=obs.evidence_id,
                evidence_reference=obs.evidence_reference or obs.evidence_id,
                status=obs.status,
                raw_reference=obs.raw_reference,
                created_at=obs.created_at,
            )
            self.session.add(model)
        self.session.flush()
        return obs

    def get_observations_for_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> List[FindingObservation]:
        stmt = select(FindingObservationModel).where(FindingObservationModel.finding_id == finding_id)
        if tenant_id:
            stmt = stmt.where(FindingObservationModel.tenant_id == tenant_id)
        stmt = stmt.order_by(FindingObservationModel.observed_at.desc())
        return [self._to_observation_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def get_observations_for_scan(self, scan_id: str, tenant_id: Optional[str] = None) -> List[FindingObservation]:
        stmt = select(FindingObservationModel).where(FindingObservationModel.scan_id == scan_id)
        if tenant_id:
            stmt = stmt.where(FindingObservationModel.tenant_id == tenant_id)
        stmt = stmt.order_by(FindingObservationModel.observed_at.desc())
        return [self._to_observation_domain(m) for m in self.session.execute(stmt).scalars().all()]

    # -------------------------------------------------------------------------
    # Finding History
    # -------------------------------------------------------------------------

    def add_history(self, history: FindingHistory) -> FindingHistory:
        model = FindingHistoryModel(
            id=history.id,
            tenant_id=history.tenant_id,
            finding_id=history.finding_id,
            actor_user_id=history.actor_user_id,
            action=history.action,
            old_status=history.old_status,
            new_status=history.new_status,
            comment=history.comment,
            metadata_=history.metadata or {},
            created_at=history.created_at,
        )
        self.session.add(model)
        self.session.flush()
        return history

    def get_history(self, finding_id: str, tenant_id: Optional[str] = None) -> List[FindingHistory]:
        stmt = select(FindingHistoryModel).where(FindingHistoryModel.finding_id == finding_id)
        if tenant_id:
            stmt = stmt.where(FindingHistoryModel.tenant_id == tenant_id)
        stmt = stmt.order_by(FindingHistoryModel.created_at.asc())
        return [self._to_history_domain(m) for m in self.session.execute(stmt).scalars().all()]

    # -------------------------------------------------------------------------
    # Finding Comments
    # -------------------------------------------------------------------------

    def add_comment(self, comment: FindingComment) -> FindingComment:
        sanitized_body = html.escape(comment.body.strip()) if comment.body else ""
        comment.body = sanitized_body
        model = FindingCommentModel(
            id=comment.id,
            tenant_id=comment.tenant_id,
            finding_id=comment.finding_id,
            author_user_id=comment.author_user_id,
            author_username=comment.author_username or "",
            body=sanitized_body,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return comment

    def get_comments(self, finding_id: str, tenant_id: Optional[str] = None) -> List[FindingComment]:
        stmt = select(FindingCommentModel).where(FindingCommentModel.finding_id == finding_id)
        if tenant_id:
            stmt = stmt.where(FindingCommentModel.tenant_id == tenant_id)
        stmt = stmt.order_by(FindingCommentModel.created_at.asc())
        return [self._to_comment_domain(m) for m in self.session.execute(stmt).scalars().all()]
