"""
Remediation and SLA Repository using SQLAlchemy 2.x
"""
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy import select, and_
from sqlalchemy.orm import Session
from core.models import Remediation, RemediationAction, SLAPolicy
from core.db.models import RemediationModel, RemediationActionModel, SLAPolicyModel


class RemediationRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_remediation_domain(m: RemediationModel) -> Remediation:
        return Remediation(
            id=m.id,
            tenant_id=m.tenant_id,
            finding_id=m.finding_id,
            title=m.title,
            description=m.description,
            owner_user_id=m.owner_user_id,
            owner_external=m.owner_external,
            status=m.status,
            priority=m.priority,
            due_date=m.due_date,
            started_at=m.started_at,
            completed_at=m.completed_at,
            verification_required=bool(m.verification_required),
            verification_status=m.verification_status or "pending",
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    @staticmethod
    def _to_action_domain(m: RemediationActionModel) -> RemediationAction:
        return RemediationAction(
            id=m.id,
            tenant_id=m.tenant_id,
            remediation_id=m.remediation_id,
            action_type=m.action_type,
            description=m.description,
            owner=m.owner,
            status=m.status,
            due_date=m.due_date,
            completed_at=m.completed_at,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    @staticmethod
    def _to_sla_domain(m: SLAPolicyModel) -> SLAPolicy:
        return SLAPolicy(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            severity=m.severity,
            criticality=m.criticality,
            asset_criticality=m.asset_criticality,
            priority_band=m.priority_band,
            kev=bool(m.kev) if m.kev is not None else None,
            internet_exposed=bool(m.internet_exposed) if m.internet_exposed is not None else None,
            due_days=m.due_days or 7,
            warning_days=m.warning_days or 5,
            enabled=bool(m.enabled),
            created_at=m.created_at,
            updated_at=getattr(m, "updated_at", None),
        )

    # -------------------------------------------------------------------------
    # Remediation CRUD
    # -------------------------------------------------------------------------

    def create_remediation(self, remediation: Remediation) -> Remediation:
        stmt = select(RemediationModel).where(RemediationModel.id == remediation.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            return self.update_remediation(remediation)

        model = RemediationModel(
            id=remediation.id,
            tenant_id=remediation.tenant_id,
            finding_id=remediation.finding_id,
            title=remediation.title,
            description=remediation.description,
            owner_user_id=remediation.owner_user_id,
            owner_external=remediation.owner_external,
            status=remediation.status,
            priority=remediation.priority,
            due_date=remediation.due_date,
            started_at=remediation.started_at,
            completed_at=remediation.completed_at,
            verification_required=remediation.verification_required,
            verification_status=remediation.verification_status,
            created_at=remediation.created_at,
            updated_at=remediation.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return remediation

    def get_remediation(self, remediation_id: str, tenant_id: Optional[str] = None) -> Optional[Remediation]:
        stmt = select(RemediationModel).where(RemediationModel.id == remediation_id)
        if tenant_id:
            stmt = stmt.where(RemediationModel.tenant_id == tenant_id)
        m = self.session.execute(stmt).scalar_one_or_none()
        return self._to_remediation_domain(m) if m else None

    def get_remediation_by_finding(self, finding_id: str, tenant_id: Optional[str] = None) -> Optional[Remediation]:
        stmt = select(RemediationModel).where(RemediationModel.finding_id == finding_id)
        if tenant_id:
            stmt = stmt.where(RemediationModel.tenant_id == tenant_id)
        stmt = stmt.order_by(RemediationModel.created_at.desc())
        m = self.session.execute(stmt).scalars().first()
        return self._to_remediation_domain(m) if m else None

    def list_remediations(self, tenant_id: str, status: Optional[str] = None) -> List[Remediation]:
        stmt = select(RemediationModel).where(RemediationModel.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(RemediationModel.status == status.upper())
        stmt = stmt.order_by(RemediationModel.created_at.desc())
        return [self._to_remediation_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_remediation(self, remediation: Remediation) -> Remediation:
        now_iso = datetime.now(timezone.utc).isoformat()
        remediation.updated_at = now_iso
        stmt = select(RemediationModel).where(
            and_(RemediationModel.id == remediation.id, RemediationModel.tenant_id == remediation.tenant_id)
        )
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.title = remediation.title
            model.description = remediation.description
            model.owner_user_id = remediation.owner_user_id
            model.owner_external = remediation.owner_external
            model.status = remediation.status
            model.priority = remediation.priority
            model.due_date = remediation.due_date
            model.started_at = remediation.started_at
            model.completed_at = remediation.completed_at
            model.verification_required = remediation.verification_required
            model.verification_status = remediation.verification_status
            model.updated_at = now_iso
            self.session.flush()
        return remediation

    # -------------------------------------------------------------------------
    # Remediation Actions
    # -------------------------------------------------------------------------

    def add_remediation_action(self, action: RemediationAction) -> RemediationAction:
        stmt = select(RemediationActionModel).where(RemediationActionModel.id == action.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            return self.update_remediation_action(action)

        model = RemediationActionModel(
            id=action.id,
            tenant_id=action.tenant_id,
            remediation_id=action.remediation_id,
            action_type=action.action_type,
            description=action.description,
            owner=action.owner,
            status=action.status,
            due_date=action.due_date,
            completed_at=action.completed_at,
            created_at=action.created_at,
            updated_at=action.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return action

    def get_remediation_actions(self, remediation_id: str, tenant_id: Optional[str] = None) -> List[RemediationAction]:
        stmt = select(RemediationActionModel).where(RemediationActionModel.remediation_id == remediation_id)
        if tenant_id:
            stmt = stmt.where(RemediationActionModel.tenant_id == tenant_id)
        stmt = stmt.order_by(RemediationActionModel.created_at.asc())
        return [self._to_action_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_remediation_action(self, action: RemediationAction) -> RemediationAction:
        now_iso = datetime.now(timezone.utc).isoformat()
        action.updated_at = now_iso
        stmt = select(RemediationActionModel).where(
            and_(RemediationActionModel.id == action.id, RemediationActionModel.tenant_id == action.tenant_id)
        )
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.action_type = action.action_type
            model.description = action.description
            model.owner = action.owner
            model.status = action.status
            model.due_date = action.due_date
            model.completed_at = action.completed_at
            model.updated_at = now_iso
            self.session.flush()
        return action

    # -------------------------------------------------------------------------
    # SLA Policies (Supporting Remediation & Differential Correlation)
    # -------------------------------------------------------------------------

    def create_sla_policy(self, policy: SLAPolicy) -> SLAPolicy:
        stmt = select(SLAPolicyModel).where(SLAPolicyModel.id == policy.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.name = policy.name
            model.severity = policy.severity
            model.criticality = policy.criticality
            model.asset_criticality = policy.asset_criticality
            model.priority_band = policy.priority_band
            model.kev = policy.kev
            model.internet_exposed = policy.internet_exposed
            model.due_days = policy.due_days
            model.warning_days = policy.warning_days
            model.enabled = policy.enabled
        else:
            model = SLAPolicyModel(
                id=policy.id,
                tenant_id=policy.tenant_id,
                name=policy.name,
                severity=policy.severity,
                criticality=policy.criticality,
                asset_criticality=policy.asset_criticality,
                priority_band=policy.priority_band,
                kev=policy.kev,
                internet_exposed=policy.internet_exposed,
                due_days=policy.due_days,
                warning_days=policy.warning_days,
                enabled=policy.enabled,
                created_at=policy.created_at,
            )
            self.session.add(model)
        self.session.flush()
        return policy

    def get_sla_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> Optional[SLAPolicy]:
        stmt = select(SLAPolicyModel).where(SLAPolicyModel.id == policy_id)
        if tenant_id:
            stmt = stmt.where(SLAPolicyModel.tenant_id == tenant_id)
        m = self.session.execute(stmt).scalar_one_or_none()
        return self._to_sla_domain(m) if m else None

    def list_sla_policies(self, tenant_id: str) -> List[SLAPolicy]:
        stmt = select(SLAPolicyModel).where(SLAPolicyModel.tenant_id == tenant_id).order_by(SLAPolicyModel.created_at.asc())
        return [self._to_sla_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_sla_policy(self, policy: SLAPolicy) -> SLAPolicy:
        return self.create_sla_policy(policy)

    def delete_sla_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> bool:
        stmt = delete(SLAPolicyModel).where(SLAPolicyModel.id == policy_id)
        if tenant_id:
            stmt = stmt.where(SLAPolicyModel.tenant_id == tenant_id)
        res = self.session.execute(stmt)
        self.session.flush()
        return (res.rowcount or 0) > 0
