"""
Tenant Repository using SQLAlchemy 2.x
"""
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy import select, func, delete as sql_delete
from sqlalchemy.orm import Session
from core.models import Tenant
from core.db.models import TenantModel


class TenantRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(model: TenantModel) -> Tenant:
        return Tenant(
            id=model.id,
            name=model.name,
            slug=model.slug,
            status=model.status,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    def get_by_id(self, tenant_id: str) -> Optional[Tenant]:
        stmt = select(TenantModel).where(TenantModel.id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def get_by_slug(self, slug: str) -> Optional[Tenant]:
        stmt = select(TenantModel).where(TenantModel.slug == slug)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def list_all(self) -> List[Tenant]:
        stmt = select(TenantModel).order_by(TenantModel.created_at.asc())
        return [self._to_domain(r) for r in self.session.execute(stmt).scalars().all()]

    def list_tenants(self, limit: int = 100, offset: int = 0) -> List[Tenant]:
        stmt = select(TenantModel).order_by(TenantModel.created_at.asc()).limit(limit).offset(offset)
        return [self._to_domain(r) for r in self.session.execute(stmt).scalars().all()]

    def count(self) -> int:
        stmt = select(func.count(TenantModel.id))
        return self.session.execute(stmt).scalar_one() or 0

    def create(self, tenant: Tenant) -> Tenant:
        model = TenantModel(
            id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
            status=tenant.status,
            created_at=tenant.created_at,
            updated_at=tenant.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return tenant

    def save(self, tenant: Tenant) -> Tenant:
        stmt = select(TenantModel).where(TenantModel.id == tenant.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.name = tenant.name
            model.slug = tenant.slug
            model.status = tenant.status
            model.updated_at = tenant.updated_at or datetime.now(timezone.utc).isoformat()
            self.session.flush()
            return self._to_domain(model)
        return self.create(tenant)

    def update(self, tenant_id: str, **kwargs) -> Optional[Tenant]:
        stmt = select(TenantModel).where(TenantModel.id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return None
        for k, v in kwargs.items():
            if k in ("name", "slug", "status", "updated_at"):
                setattr(model, k, v)
        if "updated_at" not in kwargs:
            model.updated_at = datetime.now(timezone.utc).isoformat()
        self.session.flush()
        return self._to_domain(model)

    def delete(self, tenant_id: str, hard: bool = False) -> bool:
        stmt = select(TenantModel).where(TenantModel.id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        if hard:
            self.session.delete(model)
        else:
            model.status = "disabled"
            model.updated_at = datetime.now(timezone.utc).isoformat()
        self.session.flush()
        return True

    def ensure_default_tenant(self) -> Tenant:
        existing = self.get_by_id("default-tenant")
        if not existing:
            default_t = Tenant(
                id="default-tenant",
                name="Default Workspace",
                slug="default",
                status="active",
            )
            return self.create(default_t)
        return existing
