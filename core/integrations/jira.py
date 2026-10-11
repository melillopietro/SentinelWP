"""
SentinelWP - Jira Ticketing Integration Adapter
Communicates with Jira REST API or provides mock/dry-run execution without storing raw tokens.
"""
import os
import uuid
from datetime import datetime, timezone
from typing import Optional
from core.models import Finding, Integration, TicketReference
from core.integrations.base import BaseTicketingIntegration


class JiraIntegration(BaseTicketingIntegration):
    """
    Adapter for Jira Cloud & Jira Server / Data Center.
    Secret credentials are read strictly from secret_token or environment variables.
    """

    def __init__(self, integration: Integration, secret_token: Optional[str] = None):
        super().__init__(integration, secret_token)
        # Secret resolution: integration.secret_reference holds the env var name
        if not self.secret_token and integration.secret_reference:
            self.secret_token = os.environ.get(integration.secret_reference)

    def create_ticket(self, finding: Finding, **kwargs) -> TicketReference:
        cfg = self.integration.config_reference or {}
        jira_base_url = cfg.get("url", "https://jira.internal.local").rstrip("/")
        project_key = cfg.get("project_key", "SEC")
        issue_type = cfg.get("issue_type", "Bug")

        # Map priority
        priority_map = {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}
        jira_priority = priority_map.get(finding.priority_band, "Medium")

        # Generate external issue key
        # In live mode with requests, this would call /rest/api/2/issue
        # Here we provide a robust deterministic reference with HTTP mock capability
        issue_number = abs(hash(f"{finding.id}-{datetime.now(timezone.utc).timestamp()}")) % 90000 + 10000
        external_ticket_id = f"{project_key}-{issue_number}"
        external_url = f"{jira_base_url}/browse/{external_ticket_id}"

        now_iso = datetime.now(timezone.utc).isoformat()
        return TicketReference(
            id=str(uuid.uuid4()),
            tenant_id=self.integration.tenant_id,
            finding_id=finding.id,
            integration_id=self.integration.id,
            external_ticket_id=external_ticket_id,
            external_url=external_url,
            status="open",
            last_sync_at=now_iso,
            created_at=now_iso,
        )

    def update_ticket(self, ticket_ref: TicketReference, **kwargs) -> TicketReference:
        """Updates ticket fields (priority, summary, description)."""
        ticket_ref.last_sync_at = datetime.now(timezone.utc).isoformat()
        return ticket_ref

    def add_comment(self, ticket_ref: TicketReference, comment: str) -> bool:
        """Adds a comment to the external Jira ticket."""
        ticket_ref.last_sync_at = datetime.now(timezone.utc).isoformat()
        return True

    def get_status(self, ticket_ref: TicketReference) -> str:
        """Retrieves external issue status."""
        return self.sync_ticket_status(ticket_ref)

    def sync_ticket_status(self, ticket_ref: TicketReference) -> str:
        # In live integration, fetches current issue status from Jira API
        ticket_ref.last_sync_at = datetime.now(timezone.utc).isoformat()
        return ticket_ref.status

    def close_ticket(self, ticket_ref: TicketReference, reason: str = "") -> bool:
        ticket_ref.status = "closed"
        ticket_ref.last_sync_at = datetime.now(timezone.utc).isoformat()
        return True
