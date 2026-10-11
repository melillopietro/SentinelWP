"""
Scan Repository using SQLAlchemy 2.x
"""
from typing import Optional, List
from sqlalchemy import select, and_, delete, func
from sqlalchemy.orm import Session
from core.models import ScanResult, ScanStatus
from core.db.models import ScanModel


class ScanRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(m: ScanModel) -> ScanResult:
        status_val = ScanStatus.PENDING
        try:
            status_val = ScanStatus(m.status)
        except Exception:
            pass
        wp_det = m.wordpress_detected if getattr(m, "wordpress_detected", None) is not None else m.is_wordpress
        wp_v = m.wordpress_version if getattr(m, "wordpress_version", None) is not None else m.wp_version
        wp_src = m.wordpress_version_source if getattr(m, "wordpress_version_source", None) is not None else getattr(m, "wp_version_source", None)
        wp_conf = m.wordpress_version_confidence if getattr(m, "wordpress_version_confidence", None) is not None else getattr(m, "wp_version_confidence", None)
        return ScanResult(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_id=m.asset_id,
            target_url=m.target_url,
            status=status_val,
            scan_mode=m.scan_mode,
            started_at=m.started_at,
            completed_at=m.completed_at,
            findings=[],
            score=m.score,
            grade=m.grade,
            notes=m.notes,
            tags=m.tags,
            initiated_by=m.initiated_by,
            wordpress_detected=wp_det,
            wordpress_version=wp_v,
            wordpress_version_source=wp_src,
            wordpress_version_confidence=wp_conf,
            wp_version=wp_v,
            wp_version_source=wp_src,
            wp_version_confidence=wp_conf,
            is_wordpress=wp_det,
            whois_info=m.whois_info,
        )

    def get_by_id(self, scan_id: str, tenant_id: Optional[str] = None) -> Optional[ScanResult]:
        stmt = select(ScanModel).where(ScanModel.id == scan_id)
        if tenant_id:
            stmt = stmt.where(ScanModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def list_scans(
        self,
        tenant_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[dict] = None,
    ) -> List[ScanResult]:
        stmt = select(ScanModel)
        f = filters or {}
        tid = tenant_id or f.get("tenant_id")
        aid = asset_id or f.get("asset_id")

        if tid:
            stmt = stmt.where(ScanModel.tenant_id == tid)
        if aid:
            stmt = stmt.where(ScanModel.asset_id == aid)
        if f.get("target_url"):
            stmt = stmt.where(ScanModel.target_url.ilike(f"%{f['target_url']}%"))
        if f.get("status"):
            stat_val = f["status"].value if hasattr(f["status"], "value") else str(f["status"])
            stmt = stmt.where(ScanModel.status == stat_val)
        if f.get("scan_mode"):
            stmt = stmt.where(ScanModel.scan_mode == f["scan_mode"])
        if f.get("grade"):
            stmt = stmt.where(ScanModel.grade == f["grade"])
        if f.get("date_from"):
            stmt = stmt.where(ScanModel.started_at >= f["date_from"])
        if f.get("date_to"):
            stmt = stmt.where(ScanModel.started_at <= f["date_to"] + "T23:59:59")

        stmt = stmt.order_by(ScanModel.started_at.desc()).limit(limit).offset(offset)
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def count_scans(self, tenant_id: Optional[str] = None) -> int:
        stmt = select(func.count(ScanModel.id))
        if tenant_id:
            stmt = stmt.where(ScanModel.tenant_id == tenant_id)
        return self.session.execute(stmt).scalar_one() or 0

    def save_scan(self, scan: ScanResult) -> ScanResult:
        status_str = scan.status.value if isinstance(scan.status, ScanStatus) else str(scan.status)
        wp_det = scan.wordpress_detected if scan.wordpress_detected is not None else scan.is_wordpress
        wp_v = scan.wordpress_version if scan.wordpress_version is not None else scan.wp_version
        wp_src = scan.wordpress_version_source if scan.wordpress_version_source is not None else scan.wp_version_source
        wp_conf = scan.wordpress_version_confidence if scan.wordpress_version_confidence is not None else scan.wp_version_confidence

        stmt = select(ScanModel).where(ScanModel.id == scan.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.tenant_id = scan.tenant_id or "default-tenant"
            model.asset_id = scan.asset_id
            model.target_url = scan.target_url
            model.status = status_str
            model.scan_mode = scan.scan_mode
            model.started_at = scan.started_at
            model.completed_at = scan.completed_at
            model.score = scan.score
            model.grade = scan.grade
            model.notes = scan.notes
            model.tags = scan.tags
            model.initiated_by = scan.initiated_by
            model.wordpress_detected = wp_det
            model.wordpress_version = wp_v
            model.wordpress_version_source = wp_src
            model.wordpress_version_confidence = wp_conf
            model.wp_version = wp_v
            model.wp_version_source = wp_src
            model.wp_version_confidence = wp_conf
            model.is_wordpress = wp_det
            model.whois_info = scan.whois_info
        else:
            model = ScanModel(
                id=scan.id,
                tenant_id=scan.tenant_id or "default-tenant",
                asset_id=scan.asset_id,
                target_url=scan.target_url,
                status=status_str,
                scan_mode=scan.scan_mode,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                score=scan.score,
                grade=scan.grade,
                notes=scan.notes,
                tags=scan.tags,
                initiated_by=scan.initiated_by,
                wordpress_detected=wp_det,
                wordpress_version=wp_v,
                wordpress_version_source=wp_src,
                wordpress_version_confidence=wp_conf,
                wp_version=wp_v,
                wp_version_source=wp_src,
                wp_version_confidence=wp_conf,
                is_wordpress=wp_det,
                whois_info=scan.whois_info,
            )
            self.session.add(model)
        self.session.flush()
        return scan

    def update_scan(self, scan_id: str, tenant_id: Optional[str] = None, **kwargs) -> bool:
        stmt = select(ScanModel).where(ScanModel.id == scan_id)
        if tenant_id:
            stmt = stmt.where(ScanModel.tenant_id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        for k, v in kwargs.items():
            if hasattr(model, k):
                val = v.value if hasattr(v, "value") else v
                setattr(model, k, val)
        self.session.flush()
        return True

    def delete_scan(self, scan_id: str, tenant_id: Optional[str] = None) -> bool:
        stmt = delete(ScanModel).where(ScanModel.id == scan_id)
        if tenant_id:
            stmt = stmt.where(ScanModel.tenant_id == tenant_id)
        res = self.session.execute(stmt)
        self.session.flush()
        return (res.rowcount or 0) > 0
