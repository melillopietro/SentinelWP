"""
Governance, API Keys, Policies, and Integrations Repository using SQLAlchemy 2.x
Handles API Keys, Policies, Policy Versions, Integrations, Webhook Deliveries,
Ticket References, Risk Acceptances, Snapshots, Scopes, and Business Units.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import logging
from sqlalchemy import select, and_, or_, delete, desc
from sqlalchemy.orm import Session

from core.models import (
    APIKey, Policy, PolicyVersion, Integration, WebhookDelivery,
    TicketReference, RiskAcceptance, DailyRiskSnapshot,
    DiscoveryScope, BusinessUnit
)
from core.db.models import (
    APIKeyModel, PolicyModel, PolicyVersionModel, IntegrationModel,
    WebhookDeliveryModel, TicketReferenceModel, RiskAcceptanceModel,
    DailyRiskSnapshotModel, DiscoveryScopeModel, BusinessUnitModel
)

logger = logging.getLogger("sentinelwp.db.governance_repo")


class GovernanceRepository:
    def __init__(self, session: Session):
        self.session = session

    # =========================================================================
    # 1. API Keys
    # =========================================================================

    @staticmethod
    def _api_key_to_domain(m: APIKeyModel) -> APIKey:
        return APIKey(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            key_prefix=m.key_prefix,
            key_hash=m.key_hash,
            scopes=m.scopes or [],
            last_used_at=m.last_used_at,
            expires_at=m.expires_at,
            created_at=m.created_at,
            revoked_at=m.revoked_at,
        )

    def create_api_key(self, api_key: APIKey) -> APIKey:
        model = APIKeyModel(
            id=api_key.id,
            tenant_id=api_key.tenant_id or "default-tenant",
            name=api_key.name,
            key_prefix=api_key.key_prefix or "",
            key_hash=api_key.key_hash,
            scopes=api_key.scopes or [],
            last_used_at=api_key.last_used_at,
            expires_at=api_key.expires_at,
            created_at=api_key.created_at or datetime.now(timezone.utc).isoformat(),
            revoked_at=api_key.revoked_at,
        )
        self.session.add(model)
        self.session.flush()
        return self._api_key_to_domain(model)

    def get_api_key_by_hash(self, key_hash: str) -> Optional[APIKey]:
        stmt = select(APIKeyModel).where(APIKeyModel.key_hash == key_hash)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._api_key_to_domain(res) if res else None

    def get_api_key(self, key_id: str, tenant_id: Optional[str] = None) -> Optional[APIKey]:
        stmt = select(APIKeyModel).where(APIKeyModel.id == key_id)
        if tenant_id:
            stmt = stmt.where(APIKeyModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._api_key_to_domain(res) if res else None

    def list_api_keys(self, tenant_id: str) -> List[APIKey]:
        stmt = select(APIKeyModel).where(APIKeyModel.tenant_id == tenant_id).order_by(desc(APIKeyModel.created_at))
        return [self._api_key_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def revoke_api_key(self, key_id: str, tenant_id: str) -> bool:
        stmt = select(APIKeyModel).where(and_(APIKeyModel.id == key_id, APIKeyModel.tenant_id == tenant_id))
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        model.revoked_at = datetime.now(timezone.utc).isoformat()
        self.session.flush()
        return True

    def update_api_key(self, api_key: APIKey) -> bool:
        stmt = select(APIKeyModel).where(and_(APIKeyModel.id == api_key.id, APIKeyModel.tenant_id == api_key.tenant_id))
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        model.name = api_key.name
        model.scopes = api_key.scopes or []
        model.expires_at = api_key.expires_at
        model.revoked_at = api_key.revoked_at
        model.last_used_at = api_key.last_used_at
        self.session.flush()
        return True

    # =========================================================================
    # 2. Policies & Policy Versions
    # =========================================================================

    @staticmethod
    def _policy_to_domain(m: PolicyModel) -> Policy:
        return Policy(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            type=m.type,
            active_version_id=m.active_version_id,
            enabled=m.enabled,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    @staticmethod
    def _policy_version_to_domain(m: PolicyVersionModel) -> PolicyVersion:
        return PolicyVersion(
            id=m.id,
            policy_id=m.policy_id,
            version=m.version,
            status=m.status,
            definition_json=m.definition_json or {},
            checksum=m.checksum,
            created_by=m.created_by,
            approved_by=m.approved_by,
            created_at=m.created_at,
            activated_at=m.activated_at,
        )

    def save_policy(self, policy: Policy) -> Policy:
        stmt = select(PolicyModel).where(PolicyModel.id == policy.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        now_iso = datetime.now(timezone.utc).isoformat()
        if model:
            model.name = policy.name
            model.type = policy.type
            model.active_version_id = policy.active_version_id
            model.enabled = policy.enabled
            model.updated_at = now_iso
            self.session.flush()
            return self._policy_to_domain(model)

        model = PolicyModel(
            id=policy.id,
            tenant_id=policy.tenant_id or "default-tenant",
            name=policy.name,
            type=policy.type or "SCAN_PROFILE",
            active_version_id=policy.active_version_id,
            enabled=policy.enabled,
            created_at=policy.created_at or now_iso,
            updated_at=policy.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return self._policy_to_domain(model)

    def get_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> Optional[Policy]:
        stmt = select(PolicyModel).where(PolicyModel.id == policy_id)
        if tenant_id:
            stmt = stmt.where(PolicyModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._policy_to_domain(res) if res else None

    def list_policies(self, tenant_id: str) -> List[Policy]:
        stmt = select(PolicyModel).where(PolicyModel.tenant_id == tenant_id).order_by(PolicyModel.name.asc())
        return [self._policy_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def save_policy_version(self, version: PolicyVersion) -> PolicyVersion:
        stmt = select(PolicyVersionModel).where(PolicyVersionModel.id == version.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.status = version.status
            model.definition_json = version.definition_json or {}
            model.checksum = version.checksum
            model.approved_by = version.approved_by
            model.activated_at = version.activated_at
            self.session.flush()
            return self._policy_version_to_domain(model)

        model = PolicyVersionModel(
            id=version.id,
            policy_id=version.policy_id,
            version=version.version,
            status=version.status or "DRAFT",
            definition_json=version.definition_json or {},
            checksum=version.checksum or "",
            created_by=version.created_by or "",
            approved_by=version.approved_by,
            created_at=version.created_at or datetime.now(timezone.utc).isoformat(),
            activated_at=version.activated_at,
        )
        self.session.add(model)
        self.session.flush()
        return self._policy_version_to_domain(model)

    def get_policy_version(self, version_id: str) -> Optional[PolicyVersion]:
        stmt = select(PolicyVersionModel).where(PolicyVersionModel.id == version_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._policy_version_to_domain(res) if res else None

    def list_policy_versions(self, policy_id: str) -> List[PolicyVersion]:
        stmt = select(PolicyVersionModel).where(PolicyVersionModel.policy_id == policy_id).order_by(desc(PolicyVersionModel.version))
        return [self._policy_version_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    # =========================================================================
    # 3. Integrations & Webhooks
    # =========================================================================

    @staticmethod
    def _integration_to_domain(m: IntegrationModel) -> Integration:
        return Integration(
            id=m.id,
            tenant_id=m.tenant_id,
            type=m.type,
            name=m.name,
            enabled=m.enabled,
            config_reference=m.config_reference or {},
            secret_reference=m.secret_reference or "",
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    @staticmethod
    def _webhook_delivery_to_domain(m: WebhookDeliveryModel) -> WebhookDelivery:
        return WebhookDelivery(
            id=m.id,
            tenant_id=m.tenant_id,
            integration_id=m.integration_id,
            event=m.event,
            payload_hash=m.payload_hash,
            status=m.status,
            attempt=m.attempt,
            last_error=m.last_error,
            next_retry_at=m.next_retry_at,
            created_at=m.created_at,
        )

    def save_integration(self, integration: Integration) -> Integration:
        stmt = select(IntegrationModel).where(IntegrationModel.id == integration.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        now_iso = datetime.now(timezone.utc).isoformat()
        if model:
            model.name = integration.name
            model.enabled = integration.enabled
            model.config_reference = integration.config_reference or {}
            model.secret_reference = integration.secret_reference or ""
            model.updated_at = now_iso
            self.session.flush()
            return self._integration_to_domain(model)

        model = IntegrationModel(
            id=integration.id,
            tenant_id=integration.tenant_id or "default-tenant",
            type=integration.type or "webhook",
            name=integration.name,
            enabled=integration.enabled,
            config_reference=integration.config_reference or {},
            secret_reference=integration.secret_reference or "",
            created_at=integration.created_at or now_iso,
            updated_at=integration.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return self._integration_to_domain(model)

    def get_integration(self, integration_id: str, tenant_id: Optional[str] = None) -> Optional[Integration]:
        stmt = select(IntegrationModel).where(IntegrationModel.id == integration_id)
        if tenant_id:
            stmt = stmt.where(IntegrationModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._integration_to_domain(res) if res else None

    def list_integrations(self, tenant_id: str, type: Optional[str] = None) -> List[Integration]:
        stmt = select(IntegrationModel).where(IntegrationModel.tenant_id == tenant_id)
        if type:
            stmt = stmt.where(IntegrationModel.type == type.lower())
        stmt = stmt.order_by(IntegrationModel.created_at.asc())
        return [self._integration_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_integration(self, integration: Integration) -> Integration:
        return self.save_integration(integration)

    def delete_integration(self, integration_id: str, tenant_id: str) -> bool:
        stmt = delete(IntegrationModel).where(and_(IntegrationModel.id == integration_id, IntegrationModel.tenant_id == tenant_id))
        res = self.session.execute(stmt)
        self.session.flush()
        return (res.rowcount or 0) > 0

    def create_webhook_delivery(self, delivery: WebhookDelivery) -> WebhookDelivery:
        model = WebhookDeliveryModel(
            id=delivery.id,
            tenant_id=delivery.tenant_id or "default-tenant",
            integration_id=delivery.integration_id,
            event=delivery.event,
            payload_hash=delivery.payload_hash,
            status=delivery.status or "pending",
            attempt=delivery.attempt or 1,
            last_error=delivery.last_error,
            next_retry_at=delivery.next_retry_at,
            created_at=delivery.created_at or datetime.now(timezone.utc).isoformat(),
        )
        self.session.add(model)
        self.session.flush()
        return self._webhook_delivery_to_domain(model)

    def get_webhook_delivery(self, delivery_id: str, tenant_id: Optional[str] = None) -> Optional[WebhookDelivery]:
        stmt = select(WebhookDeliveryModel).where(WebhookDeliveryModel.id == delivery_id)
        if tenant_id:
            stmt = stmt.where(WebhookDeliveryModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._webhook_delivery_to_domain(res) if res else None

    def list_webhook_deliveries(self, tenant_id: str, limit: int = 50) -> List[WebhookDelivery]:
        stmt = select(WebhookDeliveryModel).where(WebhookDeliveryModel.tenant_id == tenant_id).order_by(desc(WebhookDeliveryModel.created_at)).limit(limit)
        return [self._webhook_delivery_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_webhook_delivery(self, delivery: WebhookDelivery) -> WebhookDelivery:
        stmt = select(WebhookDeliveryModel).where(and_(WebhookDeliveryModel.id == delivery.id, WebhookDeliveryModel.tenant_id == delivery.tenant_id))
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.status = delivery.status
            model.attempt = delivery.attempt
            model.last_error = delivery.last_error
            model.next_retry_at = delivery.next_retry_at
            self.session.flush()
            return self._webhook_delivery_to_domain(model)
        return delivery

    # =========================================================================
    # 4. Ticket References
    # =========================================================================

    @staticmethod
    def _ticket_to_domain(m: TicketReferenceModel) -> TicketReference:
        return TicketReference(
            id=m.id,
            tenant_id=m.tenant_id,
            finding_id=m.finding_id,
            integration_id=m.integration_id,
            external_ticket_id=m.external_ticket_id,
            external_url=m.external_url or "",
            status=m.status or "open",
            last_sync_at=m.last_sync_at,
            created_at=m.created_at,
        )

    def create_ticket_reference(self, ref: TicketReference) -> TicketReference:
        model = TicketReferenceModel(
            id=ref.id,
            tenant_id=ref.tenant_id or "default-tenant",
            finding_id=ref.finding_id,
            integration_id=ref.integration_id,
            external_ticket_id=ref.external_ticket_id,
            external_url=ref.external_url or "",
            status=ref.status or "open",
            last_sync_at=ref.last_sync_at,
            created_at=ref.created_at or datetime.now(timezone.utc).isoformat(),
        )
        self.session.add(model)
        self.session.flush()
        return self._ticket_to_domain(model)

    def get_ticket_reference(self, ticket_id: str, tenant_id: Optional[str] = None) -> Optional[TicketReference]:
        stmt = select(TicketReferenceModel).where(TicketReferenceModel.id == ticket_id)
        if tenant_id:
            stmt = stmt.where(TicketReferenceModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._ticket_to_domain(res) if res else None

    def get_ticket_references_for_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> List[TicketReference]:
        stmt = select(TicketReferenceModel).where(TicketReferenceModel.finding_id == finding_id)
        if tenant_id:
            stmt = stmt.where(TicketReferenceModel.tenant_id == tenant_id)
        stmt = stmt.order_by(desc(TicketReferenceModel.created_at))
        return [self._ticket_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_ticket_references(self, tenant_id: str) -> List[TicketReference]:
        stmt = select(TicketReferenceModel).where(TicketReferenceModel.tenant_id == tenant_id).order_by(desc(TicketReferenceModel.created_at))
        return [self._ticket_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_ticket_reference(self, ref: TicketReference) -> TicketReference:
        stmt = select(TicketReferenceModel).where(and_(TicketReferenceModel.id == ref.id, TicketReferenceModel.tenant_id == ref.tenant_id))
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.status = ref.status
            model.last_sync_at = ref.last_sync_at
            self.session.flush()
            return self._ticket_to_domain(model)
        return ref

    # =========================================================================
    # 5. Risk Acceptances
    # =========================================================================

    @staticmethod
    def _risk_acceptance_to_domain(m: RiskAcceptanceModel) -> RiskAcceptance:
        return RiskAcceptance(
            id=m.id,
            tenant_id=m.tenant_id,
            finding_id=m.finding_id,
            requested_by=m.requested_by,
            approved_by=m.approved_by,
            reason=m.reason,
            business_justification=m.business_justification,
            compensating_controls=m.compensating_controls,
            valid_from=m.valid_from,
            valid_until=m.valid_until,
            status=m.status,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    def save_risk_acceptance(self, ra: RiskAcceptance) -> RiskAcceptance:
        stmt = select(RiskAcceptanceModel).where(RiskAcceptanceModel.id == ra.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        now_iso = datetime.now(timezone.utc).isoformat()
        if model:
            model.status = ra.status
            model.approved_by = ra.approved_by
            model.reason = ra.reason
            model.business_justification = ra.business_justification
            model.compensating_controls = ra.compensating_controls
            model.valid_until = ra.valid_until
            model.updated_at = now_iso
            self.session.flush()
            return self._risk_acceptance_to_domain(model)

        model = RiskAcceptanceModel(
            id=ra.id,
            tenant_id=ra.tenant_id or "default-tenant",
            finding_id=ra.finding_id,
            requested_by=ra.requested_by or "",
            approved_by=ra.approved_by,
            reason=ra.reason or "",
            business_justification=ra.business_justification or "",
            compensating_controls=ra.compensating_controls or "",
            valid_from=ra.valid_from or now_iso,
            valid_until=ra.valid_until or "",
            status=ra.status or "PENDING",
            created_at=ra.created_at or now_iso,
            updated_at=ra.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return self._risk_acceptance_to_domain(model)

    def get_risk_acceptance_by_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> Optional[RiskAcceptance]:
        stmt = select(RiskAcceptanceModel).where(RiskAcceptanceModel.finding_id == finding_id)
        if tenant_id:
            stmt = stmt.where(RiskAcceptanceModel.tenant_id == tenant_id)
        stmt = stmt.order_by(desc(RiskAcceptanceModel.created_at))
        res = self.session.execute(stmt).scalars().first()
        return self._risk_acceptance_to_domain(res) if res else None

    def list_active_risk_acceptances(self, tenant_id: str) -> List[RiskAcceptance]:
        now_iso = datetime.now(timezone.utc).isoformat()
        stmt = select(RiskAcceptanceModel).where(
            and_(
                RiskAcceptanceModel.tenant_id == tenant_id,
                RiskAcceptanceModel.status == "APPROVED",
                RiskAcceptanceModel.valid_until >= now_iso,
            )
        )
        return [self._risk_acceptance_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def create_risk_acceptance(self, ra: RiskAcceptance) -> RiskAcceptance:
        return self.save_risk_acceptance(ra)

    def get_risk_acceptance(self, ra_id: str, tenant_id: Optional[str] = None) -> Optional[RiskAcceptance]:
        stmt = select(RiskAcceptanceModel).where(RiskAcceptanceModel.id == ra_id)
        if tenant_id:
            stmt = stmt.where(RiskAcceptanceModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._risk_acceptance_to_domain(res) if res else None

    def list_risk_acceptances(self, tenant_id: str, status: Optional[str] = None) -> List[RiskAcceptance]:
        stmt = select(RiskAcceptanceModel).where(RiskAcceptanceModel.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(RiskAcceptanceModel.status == status.upper())
        stmt = stmt.order_by(desc(RiskAcceptanceModel.created_at))
        return [self._risk_acceptance_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_risk_acceptance(self, ra: RiskAcceptance) -> RiskAcceptance:
        return self.save_risk_acceptance(ra)

    def create_integration(self, integration: Integration) -> Integration:
        return self.save_integration(integration)

    def revoke_risk_acceptance(self, ra_id: str, tenant_id: str) -> bool:
        stmt = select(RiskAcceptanceModel).where(and_(RiskAcceptanceModel.id == ra_id, RiskAcceptanceModel.tenant_id == tenant_id))
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        model.status = "REVOKED"
        model.updated_at = datetime.now(timezone.utc).isoformat()
        self.session.flush()
        return True

    # =========================================================================
    # 6. Daily Risk Snapshots
    # =========================================================================

    @staticmethod
    def _snapshot_to_domain(m: DailyRiskSnapshotModel) -> DailyRiskSnapshot:
        return DailyRiskSnapshot(
            id=m.id,
            tenant_id=m.tenant_id,
            date=m.date,
            assets=m.assets,
            open_findings=m.open_findings,
            p1_count=m.p1_count,
            p2_count=m.p2_count,
            kev_count=m.kev_count,
            sla_breaches=m.sla_breaches,
            risk_accepted=m.risk_accepted,
            risk_score_avg=m.risk_score_avg,
            avg_risk_score=m.avg_risk_score,
            mttr_seconds=m.mttr_seconds,
            business_unit_id=m.business_unit_id,
            verified_asset_count=m.verified_asset_count,
            internet_exposed_count=m.internet_exposed_count,
            unassigned_findings=m.unassigned_findings,
            accepted_risk_count=m.accepted_risk_count,
            created_at=m.created_at,
        )

    def save_daily_risk_snapshot(self, snapshot: DailyRiskSnapshot) -> DailyRiskSnapshot:
        stmt = select(DailyRiskSnapshotModel).where(DailyRiskSnapshotModel.id == snapshot.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            stmt_date = select(DailyRiskSnapshotModel).where(
                and_(DailyRiskSnapshotModel.tenant_id == snapshot.tenant_id, DailyRiskSnapshotModel.date == snapshot.date)
            )
            model = self.session.execute(stmt_date).scalar_one_or_none()

        avg_score = snapshot.avg_risk_score or snapshot.risk_score_avg or 0.0
        now_iso = datetime.now(timezone.utc).isoformat()

        if model:
            model.assets = snapshot.assets
            model.open_findings = snapshot.open_findings
            model.p1_count = snapshot.p1_count
            model.p2_count = snapshot.p2_count
            model.kev_count = snapshot.kev_count
            model.sla_breaches = snapshot.sla_breaches
            model.risk_accepted = snapshot.risk_accepted
            model.risk_score_avg = avg_score
            model.avg_risk_score = avg_score
            model.mttr_seconds = snapshot.mttr_seconds
            self.session.flush()
            return self._snapshot_to_domain(model)

        model = DailyRiskSnapshotModel(
            id=snapshot.id,
            tenant_id=snapshot.tenant_id or "default-tenant",
            date=snapshot.date,
            assets=snapshot.assets,
            open_findings=snapshot.open_findings,
            p1_count=snapshot.p1_count,
            p2_count=snapshot.p2_count,
            kev_count=snapshot.kev_count,
            sla_breaches=snapshot.sla_breaches,
            risk_accepted=snapshot.risk_accepted,
            risk_score_avg=avg_score,
            avg_risk_score=avg_score,
            mttr_seconds=snapshot.mttr_seconds,
            business_unit_id=snapshot.business_unit_id,
            verified_asset_count=snapshot.verified_asset_count,
            internet_exposed_count=snapshot.internet_exposed_count,
            unassigned_findings=snapshot.unassigned_findings,
            accepted_risk_count=snapshot.accepted_risk_count,
            created_at=snapshot.created_at or now_iso,
        )
        self.session.add(model)
        self.session.flush()
        return self._snapshot_to_domain(model)

    def get_daily_risk_snapshots(self, tenant_id: str, days: int = 30) -> List[DailyRiskSnapshot]:
        stmt = select(DailyRiskSnapshotModel).where(DailyRiskSnapshotModel.tenant_id == tenant_id).order_by(desc(DailyRiskSnapshotModel.date)).limit(days)
        return [self._snapshot_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    # =========================================================================
    # 7. Discovery Scopes
    # =========================================================================

    @staticmethod
    def _scope_to_domain(m: DiscoveryScopeModel) -> DiscoveryScope:
        return DiscoveryScope(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            root_domain=m.root_domain,
            allowed_suffixes=m.allowed_suffixes or [],
            excluded_patterns=m.excluded_patterns or [],
            max_depth=m.max_depth,
            enabled=m.enabled,
            created_by=m.created_by,
            approved_by=m.approved_by,
            valid_from=m.created_at,
            valid_until=None,
            created_at=m.created_at,
        )

    def save_discovery_scope(self, scope: DiscoveryScope) -> DiscoveryScope:
        stmt = select(DiscoveryScopeModel).where(DiscoveryScopeModel.id == scope.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        now_iso = datetime.now(timezone.utc).isoformat()
        if model:
            model.name = scope.name
            model.root_domain = scope.root_domain
            model.allowed_suffixes = scope.allowed_suffixes or []
            model.excluded_patterns = scope.excluded_patterns or []
            model.max_depth = scope.max_depth
            model.enabled = scope.enabled
            model.approved_by = scope.approved_by
            self.session.flush()
            return self._scope_to_domain(model)

        model = DiscoveryScopeModel(
            id=scope.id,
            tenant_id=scope.tenant_id or "default-tenant",
            name=scope.name,
            root_domain=scope.root_domain,
            allowed_suffixes=scope.allowed_suffixes or [],
            excluded_patterns=scope.excluded_patterns or [],
            max_depth=scope.max_depth,
            enabled=scope.enabled,
            created_by=scope.created_by or "",
            approved_by=scope.approved_by,
            created_at=scope.created_at or now_iso,
        )
        self.session.add(model)
        self.session.flush()
        return self._scope_to_domain(model)

    def get_discovery_scope(self, scope_id: str, tenant_id: Optional[str] = None) -> Optional[DiscoveryScope]:
        stmt = select(DiscoveryScopeModel).where(DiscoveryScopeModel.id == scope_id)
        if tenant_id:
            stmt = stmt.where(DiscoveryScopeModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._scope_to_domain(res) if res else None

    def list_discovery_scopes(self, tenant_id: str) -> List[DiscoveryScope]:
        stmt = select(DiscoveryScopeModel).where(DiscoveryScopeModel.tenant_id == tenant_id).order_by(DiscoveryScopeModel.name.asc())
        return [self._scope_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    # =========================================================================
    # 8. Business Units
    # =========================================================================

    @staticmethod
    def _bu_to_domain(m: BusinessUnitModel) -> BusinessUnit:
        return BusinessUnit(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            code=m.code,
            parent_id=m.parent_id,
            owner_user_id=m.owner_user_id,
            criticality=m.criticality,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    def save_business_unit(self, bu: BusinessUnit) -> BusinessUnit:
        stmt = select(BusinessUnitModel).where(BusinessUnitModel.id == bu.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        now_iso = datetime.now(timezone.utc).isoformat()
        if model:
            model.name = bu.name
            model.code = bu.code
            model.parent_id = bu.parent_id
            model.owner_user_id = bu.owner_user_id
            model.criticality = bu.criticality
            model.updated_at = now_iso
            self.session.flush()
            return self._bu_to_domain(model)

        model = BusinessUnitModel(
            id=bu.id,
            tenant_id=bu.tenant_id or "default-tenant",
            name=bu.name,
            code=bu.code,
            parent_id=bu.parent_id,
            owner_user_id=bu.owner_user_id,
            criticality=bu.criticality or "medium",
            created_at=bu.created_at or now_iso,
            updated_at=bu.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return self._bu_to_domain(model)

    def get_business_unit(self, bu_id: str, tenant_id: Optional[str] = None) -> Optional[BusinessUnit]:
        stmt = select(BusinessUnitModel).where(BusinessUnitModel.id == bu_id)
        if tenant_id:
            stmt = stmt.where(BusinessUnitModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._bu_to_domain(res) if res else None

    def list_business_units(self, tenant_id: str) -> List[BusinessUnit]:
        stmt = select(BusinessUnitModel).where(BusinessUnitModel.tenant_id == tenant_id).order_by(BusinessUnitModel.name.asc())
        return [self._bu_to_domain(m) for m in self.session.execute(stmt).scalars().all()]
