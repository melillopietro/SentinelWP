"""
Vulnerability Intelligence Sync Status and Freshness Repository using SQLAlchemy 2.x
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from config import INTEL_FRESHNESS_SLA_HOURS
from core.models import IntelSyncStatus
from core.db.models import IntelSyncStatusModel


class IntelRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(m: IntelSyncStatusModel) -> IntelSyncStatus:
        return IntelSyncStatus(
            id=m.id,
            source=m.source,
            last_success=m.last_success,
            last_attempt=m.last_attempt,
            status=m.status,
            records_processed=m.records_processed,
            error_code=m.error_code,
            error_message=m.error_message,
            freshness_age_seconds=m.freshness_age_seconds,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    def get_sync_status(self, source: str) -> Optional[IntelSyncStatus]:
        stmt = select(IntelSyncStatusModel).where(IntelSyncStatusModel.source == source)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def list_sync_statuses(self) -> List[IntelSyncStatus]:
        stmt = select(IntelSyncStatusModel).order_by(IntelSyncStatusModel.source.asc())
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def update_sync_status(
        self,
        source: str,
        status: str,
        records_processed: int = 0,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> IntelSyncStatus:
        now_iso = datetime.now(timezone.utc).isoformat()
        stmt = select(IntelSyncStatusModel).where(IntelSyncStatusModel.source == source)
        model = self.session.execute(stmt).scalar_one_or_none()
        
        if not model:
            import uuid
            model = IntelSyncStatusModel(
                id=str(uuid.uuid4()),
                source=source,
                last_attempt=now_iso,
                status=status,
                records_processed=records_processed,
                error_code=error_code,
                error_message=error_message,
                created_at=now_iso,
            )
            if status == "success":
                model.last_success = now_iso
                model.freshness_age_seconds = 0
            self.session.add(model)
        else:
            model.last_attempt = now_iso
            model.status = status
            model.records_processed = records_processed
            model.error_code = error_code
            model.error_message = error_message
            model.updated_at = now_iso
            if status == "success":
                model.last_success = now_iso
                model.freshness_age_seconds = 0
            elif model.last_success:
                try:
                    last_dt = datetime.fromisoformat(model.last_success)
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    age = int((datetime.now(timezone.utc) - last_dt).total_seconds())
                    model.freshness_age_seconds = age
                except Exception:
                    pass

        self.session.flush()
        return self._to_domain(model)

    def evaluate_freshness(self, source: str) -> Dict[str, Any]:
        """
        Evaluate freshness against INTEL_FRESHNESS_SLA_HOURS.
        Returns dict with status: 'Fresh', 'Warning', 'Stale', or 'Failed'.
        """
        item = self.get_sync_status(source)
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
