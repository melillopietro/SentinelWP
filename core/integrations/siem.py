"""
SIEM Exporter and SOAR Action Adapters with Outbox Transaction Pattern for SentinelWP.

Guarantees:
- Formats: JSON over HTTPS, Syslog, CEF (Common Event Format), Generic Webhook.
- Security: Sanitized payloads only. No tokens, passwords, raw cookies, or sensitive evidence.
- Idempotency: Uses unique event_key (`{tenant_id}:{event_type}:{entity_id}:{version/timestamp}`).
- Delivery Outbox pattern: Transactions stage events into IntegrationOutbox; background worker dispatches.
- SOAR Action abstractions: create_ticket, send_notification, trigger_external_workflow.
"""
import hashlib
import json
import logging
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.models import IntegrationOutbox, OutboxStatus, AuditEvent
from core import repository
from core.evidence.store import sanitize_payload

logger = logging.getLogger("sentinelwp.integrations.siem")


def _cef_escape_header(value: str) -> str:
    """Escapes a CEF header field value (pipe-delimited fields)."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension(value: str) -> str:
    """
    Escapes a CEF extension field value per the ArcSight CEF specification.
    Reserved characters in extension values: backslash and equals sign.
    Newlines must also be escaped to prevent log injection.
    """
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r\n", "\\n")
        .replace("\r", "\\n")
        .replace("\n", "\\n")
    )


def format_cef_event(
    event_type: str,
    severity: str,
    extension_data: dict,
    device_vendor: str = "SentinelWP",
    device_product: str = "EnterpriseExposurePlatform",
    device_version: str = "2.0"
) -> str:
    """
    Formats an event as a standard Common Event Format (CEF) string.
    Header fields and extension values are escaped per the ArcSight CEF specification.
    """
    sev_map = {"critical": "10", "high": "7", "medium": "5", "low": "3", "info": "1"}
    cef_sev = sev_map.get(severity.lower(), "1")

    safe_vendor = _cef_escape_header(device_vendor)
    safe_product = _cef_escape_header(device_product)
    safe_version = _cef_escape_header(device_version)
    safe_event_type = _cef_escape_header(event_type)

    ext_parts = [
        f"{k}={_cef_escape_extension(v)}"
        for k, v in extension_data.items()
        if v is not None
    ]
    ext_str = " ".join(ext_parts)
    return (
        f"CEF:0|{safe_vendor}|{safe_product}|{safe_version}"
        f"|{safe_event_type}|{safe_event_type}|{cef_sev}|{ext_str}"
    )


class SIEMExporter:
    """
    Formats, validates, and dispatches sanitized enterprise security events to SIEM/SOAR platforms.
    """

    def __init__(self, tenant_id: str = "default-tenant"):
        self.tenant_id = tenant_id

    def stage_event(
        self,
        event_type: str,
        entity_id: str,
        payload: dict,
        destination: str = "siem",
        event_key_suffix: Optional[str] = None
    ) -> IntegrationOutbox:
        """
        Stages an event into the IntegrationOutbox using an idempotent event_key.
        Payload is strictly sanitized to strip credentials or leaked secrets.
        """
        suffix = event_key_suffix or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        event_key = f"{self.tenant_id}:{event_type}:{entity_id}:{suffix}"

        # Sanitize payload
        sanitized_json = sanitize_payload(json.dumps(payload, sort_keys=True))
        sanitized_dict = json.loads(sanitized_json)

        payload_hash = hashlib.sha256(sanitized_json.encode("utf-8")).hexdigest()
        now_iso = datetime.now(timezone.utc).isoformat()

        outbox_entry = IntegrationOutbox(
            tenant_id=self.tenant_id,
            event_type=event_type,
            event_key=event_key,
            destination=destination,
            payload_hash=payload_hash,
            payload_json=sanitized_dict,
            status=OutboxStatus.PENDING.value,
            attempt=1,
            created_at=now_iso
        )
        repository.save_outbox_event(outbox_entry)
        return outbox_entry

    def dispatch_outbox_event(
        self,
        event_id: str,
        target_url: str,
        format_: str = "json",
        auth_header: Optional[str] = None,
        mock_dispatcher: Optional[callable] = None
    ) -> Tuple[bool, str]:
        """
        Transmits outbox event to destination endpoint. Updates outbox record status.
        """
        conn = repository._get_conn()
        row = conn.execute("SELECT * FROM integration_outbox WHERE id = ?", (event_id,)).fetchone()
        if not row:
            return False, "Event not found"

        payload_data = json.loads(row["payload_json"] or "{}")

        if format_ == "cef":
            body = format_cef_event(
                event_type=row["event_type"],
                severity=payload_data.get("severity", "info"),
                extension_data=payload_data
            ).encode("utf-8")
            content_type = "text/plain"
        else:
            body = json.dumps(payload_data).encode("utf-8")
            content_type = "application/json"

        if mock_dispatcher:
            success, msg = mock_dispatcher(target_url, body, content_type)
        else:
            from core.integrations.circuit_breaker import get_circuit_breaker, CircuitBreakerOpenException
            breaker = get_circuit_breaker("siem_export", failure_threshold=5, recovery_timeout=30.0)

            def _send_http():
                headers = {"Content-Type": content_type, "User-Agent": "SentinelWP-SIEM-Exporter/2.0"}
                if auth_header:
                    headers["Authorization"] = auth_header
                req = urllib.request.Request(target_url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status not in (200, 201, 202, 204):
                        raise RuntimeError(f"HTTP {resp.status}")
                    return True, f"HTTP {resp.status}"

            try:
                success, msg = breaker.call(_send_http)
            except CircuitBreakerOpenException as cbe:
                success = False
                msg = str(cbe)
            except Exception as e:
                success = False
                msg = str(e)

        if success:
            repository.update_outbox_status(event_id, OutboxStatus.DELIVERED.value)
            return True, msg
        else:
            repository.update_outbox_status(event_id, OutboxStatus.FAILED.value, last_error=msg)
            repository.log_audit_event(
                AuditEvent(
                    tenant_id=self.tenant_id,
                    action="siem_delivery_failed",
                    resource_type="integration_outbox",
                    resource_id=event_id,
                    result="failure",
                    metadata={"error": msg, "destination": target_url}
                )
            )
            return False, msg


class SOARAction:
    """
    Standard abstraction for automated SOAR orchestration triggers without offensive actions.
    """

    def __init__(self, tenant_id: str = "default-tenant"):
        self.tenant_id = tenant_id

    def create_ticket(self, finding_id: str, integration_id: str, summary: str, description: str) -> dict:
        """Stages an external ticketing action via the outbox."""
        exporter = SIEMExporter(self.tenant_id)
        entry = exporter.stage_event(
            event_type="soar_create_ticket",
            entity_id=finding_id,
            payload={
                "action": "create_ticket",
                "finding_id": finding_id,
                "integration_id": integration_id,
                "summary": summary,
                "description": description
            },
            destination="soar"
        )
        return {"action_id": entry.id, "status": "staged"}

    def send_notification(self, channel: str, message: str, severity: str = "high") -> dict:
        """Stages an alert notification action via the outbox."""
        exporter = SIEMExporter(self.tenant_id)
        entry = exporter.stage_event(
            event_type="soar_notification",
            entity_id=channel,
            payload={"action": "send_notification", "channel": channel, "message": message, "severity": severity},
            destination="soar"
        )
        return {"action_id": entry.id, "status": "staged"}

    def trigger_external_workflow(self, workflow_name: str, parameters: dict) -> dict:
        """Triggers an external orchestration webhook via outbox."""
        exporter = SIEMExporter(self.tenant_id)
        entry = exporter.stage_event(
            event_type="soar_external_workflow",
            entity_id=workflow_name,
            payload={"action": "trigger_workflow", "workflow_name": workflow_name, "parameters": parameters},
            destination="soar"
        )
        return {"action_id": entry.id, "status": "staged"}
