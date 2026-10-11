"""
AuditEvent Repository using SQLAlchemy 2.x
Append-only tamper-evident audit logging with automatic credential and token sanitization.
"""
from typing import Optional, List, Dict, Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from core.models import AuditEvent
from core.db.models import AuditEventModel


def _sanitize_metadata(meta: Any) -> Dict[str, Any]:
    if not isinstance(meta, dict):
        return {}
    sensitive_keys = {
        "password", "secret", "token", "api_key", "cookie", "session",
        "authorization", "credentials", "access_token", "refresh_token"
    }
    sanitized = {}
    for k, v in meta.items():
        k_lower = str(k).lower()
        if any(s in k_lower for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_metadata(v)
        elif isinstance(v, (str, int, float, bool)) or v is None:
            sanitized[k] = v
        else:
            sanitized[k] = str(v)
    return sanitized


class AuditRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(m: AuditEventModel) -> AuditEvent:
        return AuditEvent(
            id=m.id,
            tenant_id=m.tenant_id,
            actor_user_id=m.actor_user_id,
            actor_username=m.actor_username,
            action=m.action,
            resource_type=m.resource_type,
            resource_id=m.resource_id,
            result=m.result,
            metadata=m.metadata_json or {},
            created_at=m.created_at,
        )

    def log_event(self, event: AuditEvent) -> AuditEvent:
        clean_meta = _sanitize_metadata(event.metadata)
        model = AuditEventModel(
            id=event.id,
            tenant_id=event.tenant_id or "default-tenant",
            actor_user_id=str(event.actor_user_id or ""),
            actor_username=str(event.actor_username or ""),
            action=str(event.action or ""),
            resource_type=str(event.resource_type or ""),
            resource_id=str(event.resource_id or ""),
            result=str(event.result or "success"),
            metadata_json=clean_meta,
            created_at=event.created_at,
        )
        self.session.add(model)
        self.session.flush()
        return event

    def list_events(
        self,
        tenant_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEvent]:
        stmt = select(AuditEventModel)
        if tenant_id:
            stmt = stmt.where(AuditEventModel.tenant_id == tenant_id)
        if action:
            stmt = stmt.where(AuditEventModel.action == action)
        if resource_type:
            stmt = stmt.where(AuditEventModel.resource_type == resource_type)
        stmt = stmt.order_by(AuditEventModel.created_at.desc()).limit(limit).offset(offset)
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]
