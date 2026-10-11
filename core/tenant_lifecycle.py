"""
Tenant Lifecycle Management: Soft-delete, Hard-delete, offboarding, and data wiping.
Ensures GDPR/SOC2 compliance, resource cleanup, and complete audit trail.
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from core import repository
from core.models import AuditEvent

logger = logging.getLogger("sentinelwp.tenant_lifecycle")


def soft_delete_tenant(tenant_id: str, actor_id: str = "system", reason: str = "") -> Dict[str, Any]:
    """
    Soft-deletes/suspends a tenant.
    - Marks tenant status as 'disabled'
    - Revokes all API keys for tenant
    - Disables scheduled scans
    - Creates an AuditEvent
    """
    tenant = repository.get_tenant_by_id(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant '{tenant_id}' not found.")

    if tenant_id == "default-tenant":
        raise ValueError("Cannot offboard default-tenant.")

    # 1. Update tenant status to disabled
    repository.update_tenant(tenant_id, status="disabled")

    # 2. Revoke all active API keys
    api_keys = repository.list_api_keys(tenant_id)
    revoked_keys = 0
    for key in api_keys:
        if key.status == "active":
            repository.revoke_api_key(key.id, tenant_id)
            revoked_keys += 1

    # 3. Disable scheduled scans
    scheduled = repository.list_scheduled_scans(tenant_id)
    disabled_schedules = 0
    for s in scheduled:
        if getattr(s, "enabled", True):
            s.enabled = False
            repository.save_scheduled_scan(s)
            disabled_schedules += 1

    # 4. Record audit event
    audit = AuditEvent(
        tenant_id=tenant_id,
        actor_user_id=actor_id,
        action="tenant_offboarded",
        resource_type="tenant",
        resource_id=tenant_id,
        metadata={
            "operation": "soft_delete",
            "reason": reason,
            "revoked_api_keys": revoked_keys,
            "disabled_schedules": disabled_schedules,
        }
    )
    repository.save_audit_event(audit)

    logger.info(
        f"Tenant {tenant_id} offboarded (soft-delete) by {actor_id}: {revoked_keys} keys revoked, {disabled_schedules} schedules disabled"
    )

    return {
        "tenant_id": tenant_id,
        "status": "disabled",
        "revoked_api_keys": revoked_keys,
        "disabled_schedules": disabled_schedules,
        "audit_event_id": audit.id,
    }


def hard_delete_tenant(tenant_id: str, actor_id: str = "system", confirmation: str = "") -> Dict[str, Any]:
    """
    Permanently wipes a tenant and all associated data.
    Requires explicit confirmation matching tenant_id.
    Cascades through scans, findings, assets, auths, schedules, jobs, etc.
    """
    if confirmation != tenant_id:
        raise ValueError(f"Confirmation '{confirmation}' does not match tenant ID '{tenant_id}'.")

    if tenant_id == "default-tenant":
        raise ValueError("Cannot delete default-tenant.")

    tenant = repository.get_tenant_by_id(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant '{tenant_id}' not found.")

    # Record system-wide audit event before destruction
    audit = AuditEvent(
        tenant_id="default-tenant",
        actor_user_id=actor_id,
        action="tenant_hard_deleted",
        resource_type="tenant",
        resource_id=tenant_id,
        metadata={
            "operation": "hard_delete",
            "tenant_name": tenant.name,
            "tenant_slug": tenant.slug,
        }
    )
    repository.save_audit_event(audit)

    # Clean up scans and findings
    deleted_scans, deleted_findings = repository.purge_all_scans_and_findings(tenant_id=tenant_id)

    # Perform hard delete on tenant record (cascade removes assets, authorizations, etc.)
    repository.delete_tenant(tenant_id, hard=True)

    logger.warning(
        f"Tenant {tenant_id} permanently wiped by {actor_id}: {deleted_scans} scans, {deleted_findings} findings deleted."
    )

    return {
        "tenant_id": tenant_id,
        "status": "deleted",
        "purged_scans": deleted_scans,
        "purged_findings": deleted_findings,
        "audit_event_id": audit.id,
    }
