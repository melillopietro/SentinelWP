"""
SentinelWP - ServiceNow Ticketing Integration Adapter
Re-exports ServiceNowIntegration from core.integrations.servicenow.
"""
from core.integrations.servicenow import ServiceNowIntegration

__all__ = ["ServiceNowIntegration"]
