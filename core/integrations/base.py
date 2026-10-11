"""
SentinelWP - Base Integration Interface
Defines common contract for ticketing and alert integrations.
"""
from abc import ABC, abstractmethod
from typing import Optional, Any
from core.models import Finding, Integration, TicketReference


class BaseTicketingIntegration(ABC):
    """Abstract base class for ticketing integrations (Jira, ServiceNow, GitHub, etc.)."""

    def __init__(self, integration: Integration, secret_token: Optional[str] = None):
        self.integration = integration
        self.secret_token = secret_token

    @abstractmethod
    def create_ticket(self, finding: Finding, **kwargs) -> TicketReference:
        """Creates an external ticket for the given finding."""
        pass

    @abstractmethod
    def sync_ticket_status(self, ticket_ref: TicketReference) -> str:
        """Polls or synchronizes the external ticket status and returns normalized status."""
        pass

    @abstractmethod
    def close_ticket(self, ticket_ref: TicketReference, reason: str = "") -> bool:
        """Closes the external ticket upon finding resolution/verification."""
        pass
