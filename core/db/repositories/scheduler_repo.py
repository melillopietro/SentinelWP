"""
Scheduler Repository using SQLAlchemy 2.x
Manages ScheduledScan definitions and ScheduledRun executions with duplicate dispatch prevention.
"""
from typing import Optional, List
from datetime import datetime, timezone
import uuid
import logging
from sqlalchemy import select, and_, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from core.models import ScheduledScan, ScheduledRun
from core.db.models import ScheduledScanModel, ScheduledRunModel

logger = logging.getLogger("sentinelwp.db.scheduler_repo")


class SchedulerRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _scan_to_domain(m: ScheduledScanModel) -> ScheduledScan:
        return ScheduledScan(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_id=m.asset_id,
            target_url=m.target_url,
            scan_mode=m.scan_mode,
            interval_hours=m.interval_hours,
            last_run_at=m.last_run_at,
            next_run_at=m.next_run_at,
            enabled=m.enabled,
            created_by=m.created_by,
            max_retries=m.max_retries,
            consecutive_failures=m.consecutive_failures,
            last_failure_at=m.last_failure_at,
            last_success_at=m.last_success_at,
            paused_until=m.paused_until,
            created_at=m.created_at,
        )

    @staticmethod
    def _run_to_domain(m: ScheduledRunModel) -> ScheduledRun:
        return ScheduledRun(
            id=m.id,
            schedule_id=m.schedule_id,
            tenant_id=m.tenant_id,
            planned_at=m.planned_at,
            started_at=m.started_at,
            completed_at=m.completed_at,
            scan_job_id=m.scan_job_id,
            status=m.status,
            created_at=m.created_at,
        )

    def get_by_id(self, schedule_id: str, tenant_id: Optional[str] = None) -> Optional[ScheduledScan]:
        stmt = select(ScheduledScanModel).where(ScheduledScanModel.id == schedule_id)
        if tenant_id:
            stmt = stmt.where(ScheduledScanModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._scan_to_domain(res) if res else None

    def list_all(self, tenant_id: Optional[str] = None) -> List[ScheduledScan]:
        stmt = select(ScheduledScanModel)
        if tenant_id:
            stmt = stmt.where(ScheduledScanModel.tenant_id == tenant_id)
        stmt = stmt.order_by(ScheduledScanModel.created_at.desc())
        return [self._scan_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_due_schedules(self, as_of: Optional[str] = None) -> List[ScheduledScan]:
        now_iso = as_of or datetime.now(timezone.utc).isoformat()
        stmt = select(ScheduledScanModel).where(
            and_(
                ScheduledScanModel.enabled == True,  # noqa: E712
                (ScheduledScanModel.next_run_at != None),  # noqa: E711
                ScheduledScanModel.next_run_at <= now_iso,
            )
        )
        return [self._scan_to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def create(self, sched: ScheduledScan) -> ScheduledScan:
        model = ScheduledScanModel(
            id=sched.id,
            tenant_id=sched.tenant_id or "default-tenant",
            asset_id=sched.asset_id,
            target_url=sched.target_url,
            scan_mode=sched.scan_mode,
            interval_hours=sched.interval_hours,
            last_run_at=sched.last_run_at,
            next_run_at=sched.next_run_at,
            enabled=sched.enabled,
            created_by=sched.created_by,
            max_retries=getattr(sched, "max_retries", 3),
            consecutive_failures=getattr(sched, "consecutive_failures", 0),
            last_failure_at=getattr(sched, "last_failure_at", None),
            last_success_at=getattr(sched, "last_success_at", None),
            paused_until=getattr(sched, "paused_until", None),
            created_at=sched.created_at,
        )
        self.session.add(model)
        self.session.flush()
        return sched

    def save(self, sched: ScheduledScan) -> ScheduledScan:
        stmt = select(ScheduledScanModel).where(ScheduledScanModel.id == sched.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.asset_id = sched.asset_id
            model.target_url = sched.target_url
            model.scan_mode = sched.scan_mode
            model.interval_hours = sched.interval_hours
            model.last_run_at = sched.last_run_at
            model.next_run_at = sched.next_run_at
            model.enabled = sched.enabled
            model.created_by = sched.created_by
            if sched.tenant_id:
                model.tenant_id = sched.tenant_id
            model.max_retries = getattr(sched, "max_retries", 3)
            model.consecutive_failures = getattr(sched, "consecutive_failures", 0)
            model.last_failure_at = getattr(sched, "last_failure_at", None)
            model.last_success_at = getattr(sched, "last_success_at", None)
            model.paused_until = getattr(sched, "paused_until", None)
            self.session.flush()
            return self._scan_to_domain(model)
        return self.create(sched)

    def update(self, sched: ScheduledScan) -> ScheduledScan:
        return self.save(sched)

    def delete(self, schedule_id: str, tenant_id: Optional[str] = None) -> bool:
        stmt = delete(ScheduledScanModel).where(ScheduledScanModel.id == schedule_id)
        if tenant_id:
            stmt = stmt.where(ScheduledScanModel.tenant_id == tenant_id)
        res = self.session.execute(stmt)
        self.session.flush()
        return (res.rowcount or 0) > 0

    # --- ScheduledRun Idempotent Dispatch Protection ---

    def claim_scheduled_run(
        self,
        schedule_id: str,
        tenant_id: str,
        planned_at: str,
    ) -> Optional[ScheduledRun]:
        """
        Attempts to claim execution for a specific planned schedule time slot.
        Enforces 0 duplicates via DB unique constraint on (schedule_id, planned_at).
        Returns the claimed ScheduledRun, or None if already claimed by another worker/beat instance.
        """
        # Savepoint to safely catch unique violation without breaking outer session
        nested = self.session.begin_nested()
        try:
            run_id = str(uuid.uuid4())
            model = ScheduledRunModel(
                id=run_id,
                schedule_id=schedule_id,
                tenant_id=tenant_id,
                planned_at=planned_at,
                status="dispatched",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self.session.add(model)
            nested.commit()
            self.session.flush()
            return self._run_to_domain(model)
        except IntegrityError:
            nested.rollback()
            logger.info(
                f"Duplicate schedule run prevented for schedule {schedule_id} at {planned_at}."
            )
            return None

    def update_run_status(
        self,
        run_id: str,
        status: str,
        scan_job_id: Optional[str] = None,
    ) -> bool:
        stmt = select(ScheduledRunModel).where(ScheduledRunModel.id == run_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            now_iso = datetime.now(timezone.utc).isoformat()
            model.status = status
            if scan_job_id:
                model.scan_job_id = scan_job_id
            if status == "running" and not model.started_at:
                model.started_at = now_iso
            elif status in ("completed", "failed"):
                model.completed_at = now_iso
            self.session.flush()
            return True
        return False
