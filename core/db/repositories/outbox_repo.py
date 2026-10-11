"""
Outbox Repository using SQLAlchemy 2.x
Handles reliable transactional outbox event creation, concurrent row-level locking
claiming with SELECT FOR UPDATE SKIP LOCKED on PostgreSQL, status transitions,
retry backoff, dead-letter routing, and stale event crash recovery.
"""
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import logging
from sqlalchemy import select, and_, or_, delete, func, text
from sqlalchemy.orm import Session

from core.models import IntegrationOutbox, OutboxStatus
from core.db.models import IntegrationOutboxModel

logger = logging.getLogger("sentinelwp.db.outbox_repo")


class OutboxRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(m: IntegrationOutboxModel) -> IntegrationOutbox:
        return IntegrationOutbox(
            id=m.id,
            tenant_id=m.tenant_id,
            event_type=m.event_type,
            event_key=m.event_key,
            destination=m.destination,
            payload_hash=m.payload_hash,
            payload_json=m.payload_json or {},
            status=m.status,
            attempt=m.attempt,
            next_retry_at=m.next_retry_at,
            last_error=m.last_error,
            claimed_at=m.claimed_at,
            claimed_by=m.claimed_by,
            created_at=m.created_at,
        )

    def save(self, outbox: IntegrationOutbox) -> IntegrationOutbox:
        """Create or update an outbox event."""
        stmt = select(IntegrationOutboxModel).where(IntegrationOutboxModel.id == outbox.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model and outbox.event_key:
            stmt_key = select(IntegrationOutboxModel).where(
                and_(
                    IntegrationOutboxModel.tenant_id == outbox.tenant_id,
                    IntegrationOutboxModel.event_key == outbox.event_key
                )
            )
            model = self.session.execute(stmt_key).scalar_one_or_none()

        if model:
            model.status = outbox.status
            model.attempt = outbox.attempt
            model.next_retry_at = outbox.next_retry_at
            model.last_error = outbox.last_error
            model.claimed_at = getattr(outbox, "claimed_at", None)
            model.claimed_by = getattr(outbox, "claimed_by", None)
            model.payload_json = outbox.payload_json or {}
            model.payload_hash = outbox.payload_hash
            self.session.flush()
            return self._to_domain(model)

        model = IntegrationOutboxModel(
            id=outbox.id,
            tenant_id=outbox.tenant_id or "default-tenant",
            event_type=outbox.event_type,
            event_key=outbox.event_key,
            destination=outbox.destination or "siem",
            payload_hash=outbox.payload_hash,
            payload_json=outbox.payload_json or {},
            status=outbox.status or OutboxStatus.PENDING.value,
            attempt=outbox.attempt or 1,
            next_retry_at=outbox.next_retry_at,
            last_error=outbox.last_error,
            claimed_at=getattr(outbox, "claimed_at", None),
            claimed_by=getattr(outbox, "claimed_by", None),
            created_at=outbox.created_at or datetime.now(timezone.utc).isoformat(),
        )
        self.session.add(model)
        self.session.flush()
        return self._to_domain(model)

    def get_by_id(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[IntegrationOutbox]:
        stmt = select(IntegrationOutboxModel).where(IntegrationOutboxModel.id == event_id)
        if tenant_id:
            stmt = stmt.where(IntegrationOutboxModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def get_by_key(self, event_key: str, tenant_id: Optional[str] = None) -> Optional[IntegrationOutbox]:
        stmt = select(IntegrationOutboxModel).where(IntegrationOutboxModel.event_key == event_key)
        if tenant_id:
            stmt = stmt.where(IntegrationOutboxModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def get_pending_events(self, limit: int = 50, tenant_id: Optional[str] = None) -> List[IntegrationOutbox]:
        now_iso = datetime.now(timezone.utc).isoformat()
        stmt = select(IntegrationOutboxModel).where(
            or_(
                IntegrationOutboxModel.status == "PENDING",
                and_(
                    IntegrationOutboxModel.status == "RETRYING",
                    or_(
                        IntegrationOutboxModel.next_retry_at == None,  # noqa: E711
                        IntegrationOutboxModel.next_retry_at <= now_iso
                    )
                )
            )
        )
        if tenant_id:
            stmt = stmt.where(IntegrationOutboxModel.tenant_id == tenant_id)
        stmt = stmt.order_by(IntegrationOutboxModel.created_at.asc()).limit(limit)
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def claim_events(
        self,
        worker_id: str,
        batch_size: int = 20,
        event_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[IntegrationOutbox]:
        """
        Concurrently claims pending/retrying events.
        On PostgreSQL, uses SELECT FOR UPDATE SKIP LOCKED to prevent duplicate
        claims and contention between concurrent Celery/Beat workers.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        stmt = select(IntegrationOutboxModel).where(
            or_(
                IntegrationOutboxModel.status == "PENDING",
                and_(
                    IntegrationOutboxModel.status == "RETRYING",
                    or_(
                        IntegrationOutboxModel.next_retry_at == None,  # noqa: E711
                        IntegrationOutboxModel.next_retry_at <= now_iso
                    )
                )
            )
        )
        if event_type:
            stmt = stmt.where(IntegrationOutboxModel.event_type == event_type)
        if tenant_id:
            stmt = stmt.where(IntegrationOutboxModel.tenant_id == tenant_id)

        stmt = stmt.order_by(IntegrationOutboxModel.created_at.asc()).limit(batch_size)

        bind = self.session.get_bind()
        if bind and bind.dialect.name == "postgresql":
            # PostgreSQL row-level locking with SKIP LOCKED for concurrent multi-worker safety
            stmt = stmt.with_for_update(skip_locked=True)

        claimed_models = self.session.execute(stmt).scalars().all()
        result: List[IntegrationOutbox] = []
        for model in claimed_models:
            model.status = "PROCESSING"
            model.claimed_at = now_iso
            model.claimed_by = worker_id
            result.append(self._to_domain(model))

        self.session.flush()
        return result

    def update_status(self, event_id: str, status: str, last_error: Optional[str] = None) -> bool:
        stmt = select(IntegrationOutboxModel).where(IntegrationOutboxModel.id == event_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        model.status = status
        if last_error is not None:
            model.last_error = last_error
        if status in ("PUBLISHED", "DEAD_LETTER", "SUCCESS"):
            model.claimed_at = None
            model.claimed_by = None
        self.session.flush()
        return True

    def mark_processed(self, event_id: str, status: str = "PUBLISHED") -> bool:
        return self.update_status(event_id, status)

    def mark_failed(
        self,
        event_id: str,
        error: str,
        max_retries: int = 5,
        backoff_seconds: int = 60,
    ) -> bool:
        """
        Record failure with exponential backoff.
        Routes to DEAD_LETTER if maximum attempts reached.
        """
        stmt = select(IntegrationOutboxModel).where(IntegrationOutboxModel.id == event_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False

        model.attempt += 1
        model.last_error = error
        model.claimed_at = None
        model.claimed_by = None

        if model.attempt >= max_retries:
            model.status = "DEAD_LETTER"
            model.next_retry_at = None
            logger.warning(
                f"Outbox event {event_id} exceeded max retries ({max_retries}). Routed to DEAD_LETTER."
            )
        else:
            model.status = "RETRYING"
            # Exponential backoff based on attempt
            delay = backoff_seconds * (2 ** (model.attempt - 1))
            next_retry = datetime.now(timezone.utc) + timedelta(seconds=delay)
            model.next_retry_at = next_retry.isoformat()

        self.session.flush()
        return True

    def recover_stale_events(self, timeout_seconds: int = 300) -> int:
        """
        Recover events stranded in PROCESSING state due to worker crashes or timeouts.
        Resets their status to RETRYING so they can be picked up by surviving workers.
        """
        threshold = (datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)).isoformat()
        stmt = select(IntegrationOutboxModel).where(
            and_(
                IntegrationOutboxModel.status == "PROCESSING",
                or_(
                    IntegrationOutboxModel.claimed_at == None,  # noqa: E711
                    IntegrationOutboxModel.claimed_at <= threshold
                )
            )
        )
        stale_models = self.session.execute(stmt).scalars().all()
        recovered_count = 0
        for model in stale_models:
            logger.warning(
                f"Recovering stale outbox event {model.id} claimed by {model.claimed_by} at {model.claimed_at}"
            )
            model.status = "RETRYING"
            model.claimed_at = None
            model.claimed_by = None
            model.attempt += 1
            model.last_error = "Recovered from stale PROCESSING state (worker crash / timeout)"
            recovered_count += 1

        self.session.flush()
        return recovered_count

    def purge_published_events(self, retention_days: int = 7) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        stmt = delete(IntegrationOutboxModel).where(
            and_(
                IntegrationOutboxModel.status.in_(["PUBLISHED", "SUCCESS"]),
                IntegrationOutboxModel.created_at <= cutoff
            )
        )
        res = self.session.execute(stmt)
        self.session.flush()
        return res.rowcount or 0

    def count_pending(self, tenant_id: Optional[str] = None) -> int:
        stmt = select(func.count(IntegrationOutboxModel.id)).where(
            IntegrationOutboxModel.status.in_(["PENDING", "RETRYING"])
        )
        if tenant_id:
            stmt = stmt.where(IntegrationOutboxModel.tenant_id == tenant_id)
        return self.session.execute(stmt).scalar_one() or 0
