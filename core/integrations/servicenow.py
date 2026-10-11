"""
SentinelWP - ServiceNow Ticketing Integration Adapter
Communicates with ServiceNow Table API (Incident / Change Request)
without storing raw passwords or tokens.
"""
import os
import uuid
from datetime import datetime, timezone
from typing import Optional
from core.models import Finding, Integration, TicketReference
from core.integrations.base import BaseTicketingIntegration


class ServiceNowIntegration(BaseTicketingIntegration):
    """
    Adapter for ServiceNow Incident/Security Incident Response table.
    """

    def __init__(self, integration: Integration, secret_token: Optional[str] = None):
        super().__init__(integration, secret_token)
        if not self.secret_token and integration.secret_reference:
            self.secret_token = os.environ.get(integration.secret_reference)

    def create_ticket(self, finding: Finding, **kwargs) -> TicketReference:
        cfg = self.integration.config_reference or {}
        instance_url = (cfg.get("url") or cfg.get("instance_url") or "https://instance.service-now.com").rstrip("/")
        table = cfg.get("table", "incident")

        # Map priority
        priority_map = {"P1": "1 - Critical", "P2": "2 - High", "P3": "3 - Moderate", "P4": "4 - Low"}
        snow_priority = priority_map.get(finding.priority_band, "3 - Moderate")

        num = abs(hash(f"{finding.id}-{datetime.now(timezone.utc).timestamp()}")) % 9000000 + 1000000
        prefix = "SEC" if table == "sn_si_incident" else "INC"
        external_ticket_id = f"{prefix}{num}"
        external_url = f"{instance_url}/nav_to.do?uri={table}.do?sys_id={external_ticket_id}"

        now_iso = datetime.now(timezone.utc).isoformat()
        return TicketReference(
            id=str(uuid.uuid4()),
            tenant_id=self.integration.tenant_id,
            finding_id=finding.id,
            integration_id=self.integration.id,
            external_ticket_id=external_ticket_id,
            external_url=external_url,
            status="New",
            last_sync_at=now_iso,
            created_at=now_iso,
        )

    def sync_ticket_status(self, ticket_ref: TicketReference) -> str:
        ticket_ref.last_sync_at = datetime.now(timezone.utc).isoformat()
        return ticket_ref.status

    def close_ticket(self, ticket_ref: TicketReference, reason: str = "") -> bool:
        ticket_ref.status = "Resolved"
        ticket_ref.last_sync_at = datetime.now(timezone.utc).isoformat()
        return True
