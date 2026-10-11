"""
Asset and ScanAuthorization Repository using SQLAlchemy 2.x
"""
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy import select, and_, delete, func
from sqlalchemy.orm import Session
from core.models import Asset, ScanAuthorization
from core.db.models import AssetModel, ScanAuthorizationModel
from core.canonical import canonicalize_url


class AssetRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _asset_to_domain(m: AssetModel) -> Asset:
        return Asset(
            id=m.id,
            tenant_id=m.tenant_id,
            canonical_url=m.canonical_url,
            hostname=m.hostname,
            display_name=m.display_name,
            business_owner=m.business_owner,
            technical_owner=m.technical_owner,
            environment=m.environment,
            internet_exposure=m.internet_exposure,
            criticality=m.criticality,
            data_classification=m.data_classification,
            authorization_status=m.authorization_status,
            authorization_review_date=m.authorization_review_date,
            tags=m.tags,
            status=m.status,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    @staticmethod
    def _auth_to_domain(m: ScanAuthorizationModel) -> ScanAuthorization:
        return ScanAuthorization(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_id=m.asset_id,
            status=m.status,
            allowed_profiles=m.allowed_profiles,
            request_budget=m.request_budget,
            valid_from=m.valid_from,
            valid_until=m.valid_until,
            approved_by=m.approved_by,
            notes=m.notes,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    def get_by_id(self, asset_id: str, tenant_id: Optional[str] = None) -> Optional[Asset]:
        stmt = select(AssetModel).where(AssetModel.id == asset_id)
        if tenant_id:
            stmt = stmt.where(AssetModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._asset_to_domain(res) if res else None

    def get_by_canonical_url(self, canonical_url: str, tenant_id: str) -> Optional[Asset]:
        stmt = select(AssetModel).where(
            and_(AssetModel.tenant_id == tenant_id, AssetModel.canonical_url == canonical_url)
        )
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._asset_to_domain(res) if res else None

    def count_assets(self, tenant_id: Optional[str] = None) -> int:
        stmt = select(func.count(AssetModel.id))
        if tenant_id:
            stmt = stmt.where(AssetModel.tenant_id == tenant_id)
        return self.session.execute(stmt).scalar_one() or 0

    def list_assets(
        self,
        tenant_id: Optional[str] = None,
        filters: Optional[dict] = None,
        limit: Optional[int] = 500,
        offset: int = 0,
        environment: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Asset]:
        stmt = select(AssetModel)
        if tenant_id:
            stmt = stmt.where(AssetModel.tenant_id == tenant_id)

        # Merge filters dict if provided
        f = filters or {}
        env = environment or f.get("environment")
        stat = status or f.get("status")
        crit = f.get("criticality")
        srch = search or f.get("search")

        if env:
            stmt = stmt.where(AssetModel.environment == env)
        if stat:
            stmt = stmt.where(AssetModel.status == stat)
        if crit:
            stmt = stmt.where(AssetModel.criticality == crit)
        if srch:
            like_term = f"%{srch}%"
            stmt = stmt.where(
                (AssetModel.canonical_url.ilike(like_term)) |
                (AssetModel.hostname.ilike(like_term)) |
                (AssetModel.display_name.ilike(like_term))
            )

        stmt = stmt.order_by(AssetModel.created_at.desc())
        if limit:
            stmt = stmt.limit(limit)
        if offset:
            stmt = stmt.offset(offset)

        return [self._asset_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def create(self, asset: Asset) -> Asset:
        model = AssetModel(
            id=asset.id,
            tenant_id=asset.tenant_id,
            canonical_url=asset.canonical_url,
            hostname=asset.hostname,
            display_name=asset.display_name,
            business_owner=asset.business_owner,
            technical_owner=asset.technical_owner,
            environment=asset.environment,
            internet_exposure=asset.internet_exposure,
            criticality=asset.criticality,
            data_classification=asset.data_classification,
            authorization_status=asset.authorization_status,
            authorization_review_date=asset.authorization_review_date,
            tags=asset.tags,
            status=asset.status,
            business_unit_id=getattr(asset, "business_unit_id", None),
            created_at=asset.created_at,
            updated_at=asset.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return asset

    def save(self, asset: Asset) -> Asset:
        stmt = select(AssetModel).where(AssetModel.id == asset.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.canonical_url = asset.canonical_url
            model.hostname = asset.hostname
            model.display_name = asset.display_name
            model.business_owner = asset.business_owner
            model.technical_owner = asset.technical_owner
            model.environment = asset.environment
            model.internet_exposure = asset.internet_exposure
            model.criticality = asset.criticality
            model.data_classification = asset.data_classification
            model.authorization_status = asset.authorization_status
            model.authorization_review_date = asset.authorization_review_date
            model.tags = asset.tags
            model.status = asset.status
            model.business_unit_id = getattr(asset, "business_unit_id", None)
            model.updated_at = asset.updated_at or datetime.now(timezone.utc).isoformat()
            self.session.flush()
            return self._asset_to_domain(model)
        return self.create(asset)

    def update(self, asset: Asset) -> Asset:
        return self.save(asset)

    def update_fields(self, asset_id: str, tenant_id: Optional[str] = None, **kwargs) -> bool:
        stmt = select(AssetModel).where(AssetModel.id == asset_id)
        if tenant_id:
            stmt = stmt.where(AssetModel.tenant_id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        for k, v in kwargs.items():
            if hasattr(model, k):
                setattr(model, k, v)
        if "updated_at" not in kwargs:
            model.updated_at = datetime.now(timezone.utc).isoformat()
        self.session.flush()
        return True

    update_asset = update_fields

    def delete(self, asset_id: str, tenant_id: str) -> bool:
        return self.delete_asset(asset_id, tenant_id=tenant_id, hard=True)

    def delete_asset(self, asset_id: str, tenant_id: Optional[str] = None, hard: bool = False) -> bool:
        stmt = select(AssetModel).where(AssetModel.id == asset_id)
        if tenant_id:
            stmt = stmt.where(AssetModel.tenant_id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        if hard:
            self.session.delete(model)
        else:
            model.status = "archived"
            model.updated_at = datetime.now(timezone.utc).isoformat()
        self.session.flush()
        return True

    def ensure_asset(
        self,
        target_url: str,
        tenant_id: str,
        display_name: str = "",
        environment: str = "production",
    ) -> Asset:
        c_url, host = canonicalize_url(target_url)
        existing = self.get_by_canonical_url(c_url, tenant_id)
        if existing:
            return existing
        new_asset = Asset(
            tenant_id=tenant_id,
            canonical_url=c_url,
            hostname=host,
            display_name=display_name or host,
            environment=environment,
        )
        return self.create(new_asset)

    # --- Scan Authorization Methods ---

    def create_authorization(self, auth: ScanAuthorization) -> ScanAuthorization:
        model = ScanAuthorizationModel(
            id=auth.id,
            tenant_id=auth.tenant_id,
            asset_id=auth.asset_id,
            status=auth.status,
            allowed_profiles=auth.allowed_profiles,
            request_budget=auth.request_budget,
            valid_from=auth.valid_from,
            valid_until=auth.valid_until,
            approved_by=auth.approved_by,
            notes=auth.notes,
            created_at=auth.created_at,
            updated_at=auth.updated_at,
        )
        self.session.add(model)
        
        # Also update asset status
        asset_stmt = select(AssetModel).where(AssetModel.id == auth.asset_id)
        asset_model = self.session.execute(asset_stmt).scalar_one_or_none()
        if asset_model:
            asset_model.authorization_status = "authorized"
            asset_model.authorization_review_date = auth.valid_until
        self.session.flush()
        return auth

    def save_authorization(self, auth: ScanAuthorization) -> ScanAuthorization:
        stmt = select(ScanAuthorizationModel).where(ScanAuthorizationModel.id == auth.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.tenant_id = auth.tenant_id
            model.asset_id = auth.asset_id
            model.status = auth.status
            model.allowed_profiles = auth.allowed_profiles
            model.request_budget = auth.request_budget
            model.valid_from = auth.valid_from
            model.valid_until = auth.valid_until
            model.approved_by = auth.approved_by
            model.notes = auth.notes
            model.updated_at = auth.updated_at or datetime.now(timezone.utc).isoformat()
            self.session.flush()
            return self._auth_to_domain(model)
        return self.create_authorization(auth)

    def get_authorization(self, auth_id: str, tenant_id: Optional[str] = None) -> Optional[ScanAuthorization]:
        stmt = select(ScanAuthorizationModel).where(ScanAuthorizationModel.id == auth_id)
        if tenant_id:
            stmt = stmt.where(ScanAuthorizationModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._auth_to_domain(res) if res else None

    def get_active_authorization(self, asset_id: str, tenant_id: Optional[str] = None) -> Optional[ScanAuthorization]:
        now_iso = datetime.now(timezone.utc).isoformat()
        stmt = select(ScanAuthorizationModel).where(
            and_(
                ScanAuthorizationModel.asset_id == asset_id,
                ScanAuthorizationModel.status == "active",
                ScanAuthorizationModel.valid_from <= now_iso,
                ScanAuthorizationModel.valid_until >= now_iso,
            )
        )
        if tenant_id:
            stmt = stmt.where(ScanAuthorizationModel.tenant_id == tenant_id)
        stmt = stmt.order_by(ScanAuthorizationModel.valid_until.desc())
        res = self.session.execute(stmt).scalars().first()
        return self._auth_to_domain(res) if res else None

    def get_active_authorizations_for_asset(self, asset_id: str, tenant_id: str) -> List[ScanAuthorization]:
        now_iso = datetime.now(timezone.utc).isoformat()
        stmt = select(ScanAuthorizationModel).where(
            and_(
                ScanAuthorizationModel.asset_id == asset_id,
                ScanAuthorizationModel.tenant_id == tenant_id,
                ScanAuthorizationModel.status == "active",
                ScanAuthorizationModel.valid_until >= now_iso,
            )
        ).order_by(ScanAuthorizationModel.created_at.desc())
        return [self._auth_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_authorizations_for_asset(self, asset_id: str, tenant_id: str) -> List[ScanAuthorization]:
        stmt = select(ScanAuthorizationModel).where(
            and_(
                ScanAuthorizationModel.asset_id == asset_id,
                ScanAuthorizationModel.tenant_id == tenant_id,
            )
        ).order_by(ScanAuthorizationModel.created_at.desc())
        return [self._auth_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_scan_authorizations(
        self, asset_id: Optional[str] = None, tenant_id: Optional[str] = None
    ) -> List[ScanAuthorization]:
        stmt = select(ScanAuthorizationModel)
        if tenant_id:
            stmt = stmt.where(ScanAuthorizationModel.tenant_id == tenant_id)
        if asset_id:
            stmt = stmt.where(ScanAuthorizationModel.asset_id == asset_id)
        stmt = stmt.order_by(ScanAuthorizationModel.created_at.desc())
        return [self._auth_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def revoke_authorization(self, auth_id: str, tenant_id: Optional[str] = None) -> bool:
        stmt = select(ScanAuthorizationModel).where(ScanAuthorizationModel.id == auth_id)
        if tenant_id:
            stmt = stmt.where(ScanAuthorizationModel.tenant_id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.status = "revoked"
            model.updated_at = datetime.now(timezone.utc).isoformat()

            # Check remaining active authorizations
            remaining = self.get_active_authorizations_for_asset(model.asset_id, model.tenant_id)
            if not remaining:
                asset_stmt = select(AssetModel).where(AssetModel.id == model.asset_id)
                asset_model = self.session.execute(asset_stmt).scalar_one_or_none()
                if asset_model:
                    asset_model.authorization_status = "unauthorized"
            self.session.flush()
            return True
        return False
