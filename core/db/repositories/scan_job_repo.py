"""
ScanJob Repository using SQLAlchemy 2.x
Handles persistent scan job lifecycle, progress, worker heartbeats, and stale job queries.
"""
from typing import Optional, List
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, and_, func, update, case
from sqlalchemy.orm import Session
from core.models import ScanJob, ScanJobStatus
from core.db.models import ScanJobModel


class ScanJobRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(m: ScanJobModel) -> ScanJob:
        return ScanJob(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_id=m.asset_id,
            scan_id=m.scan_id,
            task_id=m.task_id,
            status=m.status,
            requested_by=m.requested_by,
            profile=m.profile,
            queued_at=m.queued_at,
            started_at=m.started_at,
            completed_at=m.completed_at,
            failed_at=m.failed_at,
            cancelled_at=m.cancelled_at,
            progress_percent=m.progress_percent,
            current_step=m.current_step,
            attempt=m.attempt,
            max_attempts=m.max_attempts,
            error_code=m.error_code,
            error_message=m.error_message,
            worker_id=m.worker_id,
            heartbeat_at=m.heartbeat_at,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    TERMINAL_STATUSES = {"completed", "cancelled", "failed", "timed_out"}
    CLAIMABLE_STATUSES = {
        ScanJobStatus.QUEUED.value,
        ScanJobStatus.RETRYING.value,
    }

    def create_job(self, job: ScanJob) -> ScanJob:
        stmt = select(ScanJobModel).where(ScanJobModel.id == job.id)
        existing = self.session.execute(stmt).scalar_one_or_none()
        if existing:
            # Audit protection: duplicate job delivery must never overwrite or regress terminal states
            if existing.status in self.TERMINAL_STATUSES:
                return self._to_domain(existing)
            return self.update_job(job)

        model = ScanJobModel(
            id=job.id,
            tenant_id=job.tenant_id,
            asset_id=job.asset_id,
            scan_id=job.scan_id,
            task_id=job.task_id,
            status=job.status,
            requested_by=job.requested_by,
            profile=job.profile,
            queued_at=job.queued_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            failed_at=job.failed_at,
            cancelled_at=job.cancelled_at,
            progress_percent=job.progress_percent,
            current_step=job.current_step,
            attempt=job.attempt,
            max_attempts=job.max_attempts,
            error_code=job.error_code,
            error_message=job.error_message,
            worker_id=job.worker_id,
            heartbeat_at=job.heartbeat_at,
            created_at=job.created_at,
            updated_at=job.updated_at,
        )
        self.session.add(model)
        self.session.flush()
        return job

    def get_by_id(self, job_id: str, tenant_id: Optional[str] = None) -> Optional[ScanJob]:
        stmt = select(ScanJobModel).where(ScanJobModel.id == job_id)
        if tenant_id:
            stmt = stmt.where(ScanJobModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def get_by_scan_id(self, scan_id: str, tenant_id: Optional[str] = None) -> Optional[ScanJob]:
        stmt = select(ScanJobModel).where(ScanJobModel.scan_id == scan_id)
        if tenant_id:
            stmt = stmt.where(ScanJobModel.tenant_id == tenant_id)
        stmt = stmt.order_by(ScanJobModel.created_at.desc())
        res = self.session.execute(stmt).scalars().first()
        return self._to_domain(res) if res else None

    def update_job(self, job: ScanJob) -> ScanJob:
        stmt = select(ScanJobModel).where(ScanJobModel.id == job.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            # Audit protection: do not regress terminal status if incoming update is non-terminal
            if model.status in self.TERMINAL_STATUSES and job.status not in self.TERMINAL_STATUSES:
                return self._to_domain(model)

            model.status = job.status
            model.task_id = job.task_id
            model.requested_by = job.requested_by
            model.profile = job.profile
            model.started_at = job.started_at
            model.completed_at = job.completed_at
            model.failed_at = job.failed_at
            model.cancelled_at = job.cancelled_at
            model.progress_percent = job.progress_percent
            model.current_step = job.current_step
            model.attempt = job.attempt
            model.max_attempts = job.max_attempts
            model.error_code = job.error_code
            model.error_message = job.error_message
            model.worker_id = job.worker_id
            model.heartbeat_at = job.heartbeat_at
            model.updated_at = datetime.now(timezone.utc).isoformat()
            self.session.flush()
        return job

    def update_progress(
        self,
        job_id: str,
        progress_percent: int,
        current_step: str,
        worker_id: Optional[str] = None,
    ) -> bool:
        stmt = select(ScanJobModel).where(ScanJobModel.id == job_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            model.progress_percent = max(0, min(100, progress_percent))
            model.current_step = current_step
            now_iso = datetime.now(timezone.utc).isoformat()
            model.heartbeat_at = now_iso
            model.updated_at = now_iso
            if worker_id:
                model.worker_id = worker_id
            self.session.flush()
            return True
        return False

    def record_heartbeat(self, job_id: str, worker_id: Optional[str] = None) -> bool:
        stmt = select(ScanJobModel).where(ScanJobModel.id == job_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if model:
            now_iso = datetime.now(timezone.utc).isoformat()
            model.heartbeat_at = now_iso
            model.updated_at = now_iso
            if worker_id:
                model.worker_id = worker_id
            self.session.flush()
            return True
        return False

    def mark_status(
        self,
        job_id: str,
        status: str,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> bool:
        stmt = select(ScanJobModel).where(ScanJobModel.id == job_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False

        if model.status in self.TERMINAL_STATUSES:
            return model.status == status

        now_iso = datetime.now(timezone.utc).isoformat()
        model.status = status
        model.updated_at = now_iso
        if status == ScanJobStatus.RUNNING.value and not model.started_at:
            model.started_at = now_iso
            model.heartbeat_at = now_iso
        elif status == ScanJobStatus.COMPLETED.value:
            model.completed_at = now_iso
            model.progress_percent = 100
            model.current_step = "Completed"
        elif status in (ScanJobStatus.FAILED.value, ScanJobStatus.TIMED_OUT.value):
            model.failed_at = now_iso
            model.error_code = error_code
            model.error_message = error_message
        elif status == ScanJobStatus.CANCELLED.value:
            model.cancelled_at = now_iso
        if worker_id:
            model.worker_id = worker_id
        self.session.flush()
        return True

    def try_claim_for_execution(self, job_id: str, worker_id: str) -> Optional[ScanJob]:
        """
        Atomically transition queued/retrying -> running for exactly one worker.
        Returns the claimed job domain model, or None if another worker owns or terminal state.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        stmt = (
            update(ScanJobModel)
            .where(
                ScanJobModel.id == job_id,
                ScanJobModel.status.in_(list(self.CLAIMABLE_STATUSES)),
            )
            .values(
                status=ScanJobStatus.RUNNING.value,
                worker_id=worker_id,
                started_at=case(
                    (ScanJobModel.started_at.is_(None), now_iso),
                    (ScanJobModel.started_at == "", now_iso),
                    else_=ScanJobModel.started_at,
                ),
                heartbeat_at=now_iso,
                updated_at=now_iso,
            )
            .returning(ScanJobModel)
        )
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def try_reclaim_stale_for_retry(
        self,
        job_id: str,
        stale_threshold_seconds: int,
    ) -> Optional[ScanJob]:
        """
        Atomically move a stale running job to retrying and bump attempt.
        Only succeeds if heartbeat/start time proves the worker is stale.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_threshold_seconds)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()
        stmt = (
            update(ScanJobModel)
            .where(
                ScanJobModel.id == job_id,
                ScanJobModel.status == ScanJobStatus.RUNNING.value,
                (
                    (ScanJobModel.heartbeat_at.isnot(None) & (ScanJobModel.heartbeat_at < cutoff))
                    | (
                        ScanJobModel.heartbeat_at.is_(None)
                        & ScanJobModel.started_at.isnot(None)
                        & (ScanJobModel.started_at < cutoff)
                    )
                ),
            )
            .values(
                status=ScanJobStatus.RETRYING.value,
                attempt=ScanJobModel.attempt + 1,
                error_code="STALE_HEARTBEAT_RETRY",
                error_message="Worker heartbeat timed out; job requeued for retry",
                updated_at=now_iso,
            )
            .returning(ScanJobModel)
        )
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def count_active_jobs_for_tenant(self, tenant_id: str) -> int:
        active_statuses = [ScanJobStatus.QUEUED.value, ScanJobStatus.RUNNING.value, ScanJobStatus.RETRYING.value]
        stmt = select(func.count(ScanJobModel.id)).where(
            and_(
                ScanJobModel.tenant_id == tenant_id,
                ScanJobModel.status.in_(active_statuses)
            )
        )
        return self.session.execute(stmt).scalar_one() or 0

    def count_active_jobs_global(self) -> int:
        active_statuses = [ScanJobStatus.QUEUED.value, ScanJobStatus.RUNNING.value, ScanJobStatus.RETRYING.value]
        stmt = select(func.count(ScanJobModel.id)).where(ScanJobModel.status.in_(active_statuses))
        return self.session.execute(stmt).scalar_one() or 0

    def count_active_jobs_for_asset(self, asset_id: str) -> int:
        active_statuses = [ScanJobStatus.QUEUED.value, ScanJobStatus.RUNNING.value, ScanJobStatus.RETRYING.value]
        stmt = select(func.count(ScanJobModel.id)).where(
            and_(
                ScanJobModel.asset_id == asset_id,
                ScanJobModel.status.in_(active_statuses)
            )
        )
        return self.session.execute(stmt).scalar_one() or 0

    def find_stale_jobs(self, stale_threshold_seconds: int = 600) -> List[ScanJob]:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_threshold_seconds)).isoformat()
        stmt = select(ScanJobModel).where(
            and_(
                ScanJobModel.status == ScanJobStatus.RUNNING.value,
                (
                    (ScanJobModel.heartbeat_at != None) & (ScanJobModel.heartbeat_at < cutoff)  # noqa: E711
                ) | (
                    (ScanJobModel.heartbeat_at == None) & (ScanJobModel.started_at != None) & (ScanJobModel.started_at < cutoff)  # noqa: E711
                )
            )
        )
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_jobs(
        self,
        tenant_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ScanJob]:
        stmt = select(ScanJobModel)
        if tenant_id:
            stmt = stmt.where(ScanJobModel.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(ScanJobModel.status == status)
        stmt = stmt.order_by(ScanJobModel.queued_at.desc()).limit(limit).offset(offset)
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]
