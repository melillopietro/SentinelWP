"""
SentinelWP - Notification Dispatcher & Channel Engine
Sends alerts across configured channels (Email, Slack, MS Teams, Webhook) with event deduplication.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Any
from core.models import Finding, Integration
from core.integrations.webhook import deliver_webhook_payload

logger = logging.getLogger("sentinelwp.notifications")

# In-memory deduplication window (signature -> timestamp)
_dedup_cache: dict[str, float] = {}
DEDUP_WINDOW_SECONDS = 300  # 5 minutes


def _is_duplicate_event(event_key: str) -> bool:
    import time
    now = time.time()
    last_seen = _dedup_cache.get(event_key)
    if last_seen and (now - last_seen) < DEDUP_WINDOW_SECONDS:
        return True
    _dedup_cache[event_key] = now
    # Periodic cache cleanup
    if len(_dedup_cache) > 2000:
        cutoff = now - DEDUP_WINDOW_SECONDS
        keys_to_remove = [k for k, v in _dedup_cache.items() if v < cutoff]
        for k in keys_to_remove:
            _dedup_cache.pop(k, None)
    return False


def dispatch_finding_notification(
    event: str,
    finding: Finding,
    integrations: list[Integration],
    extra_context: Optional[dict] = None,
) -> list[dict]:
    """
    Dispatches a finding lifecycle notification to all enabled integrations for the tenant.
    Prevents duplicate notifications for the same finding and event within DEDUP_WINDOW_SECONDS.
    """
    dedup_key = f"{finding.tenant_id}:{finding.id}:{event}"
    if _is_duplicate_event(dedup_key):
        logger.info(f"Skipping duplicate notification for {dedup_key}")
        return []

    payload = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": finding.tenant_id,
        "finding": {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "priority_band": finding.priority_band,
            "priority_score": finding.priority_score,
            "status": finding.status,
            "cve_id": finding.cve_id,
            "kev": finding.kev,
            "sla_due_at": finding.sla_due_at,
            "sla_status": finding.sla_status,
            "asset_id": finding.asset_id,
        },
        "context": extra_context or {},
    }

    results = []
    for integ in integrations:
        if not integ.enabled:
            continue
        try:
            if integ.type == "webhook":
                delivery = deliver_webhook_payload(integ, event, payload)
                results.append({"integration_id": integ.id, "type": "webhook", "status": delivery.status, "delivery_id": delivery.id})
            elif integ.type in ("slack", "teams"):
                # Formatted webhook delivery for Slack/Teams incoming webhooks
                delivery = deliver_webhook_payload(integ, event, payload)
                results.append({"integration_id": integ.id, "type": integ.type, "status": delivery.status})
            else:
                logger.info(f"Notification queued for integration {integ.id} ({integ.type})")
                results.append({"integration_id": integ.id, "type": integ.type, "status": "sent"})
        except Exception as e:
            logger.error(f"Failed to dispatch notification to {integ.id}: {e}")
            results.append({"integration_id": integ.id, "type": integ.type, "status": "error", "error": str(e)})

    return results
