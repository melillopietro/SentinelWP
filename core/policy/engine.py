"""
Enterprise Versioned Policy Engine for SentinelWP.

Guarantees:
- Immutable ACTIVE policy versions: Modifications require creating a new PolicyVersion draft.
- Cryptographic SHA-256 checksum over canonical JSON definition.
- Policy diff engine computing added, modified, and removed attributes across versions.
- Two-person approval gating support (POLICY_APPROVAL_REQUIRED).
- Policy types: SCAN_PROFILE, SLA, PRIORITIZATION, DISCOVERY, EVIDENCE_RETENTION, NOTIFICATION, RISK_ACCEPTANCE.
- Full traceability linking ScanJob, Finding, and SLA evaluations to policy_version_id.
"""
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.models import Policy, PolicyVersion, PolicyType, PolicyVersionStatus, AuditEvent
from core import repository

logger = logging.getLogger("sentinelwp.policy")

POLICY_APPROVAL_REQUIRED = os.getenv("POLICY_APPROVAL_REQUIRED", "false").lower() in ("true", "1", "yes")


def compute_policy_checksum(definition_dict: dict) -> str:
    """Computes deterministic SHA-256 checksum over sorted canonical JSON policy definition."""
    canonical_json = json.dumps(definition_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class PolicyEngine:
    """
    Manages immutable versioned enterprise governance policies.
    """

    def __init__(self, tenant_id: str = "default-tenant"):
        self.tenant_id = tenant_id

    def create_policy(
        self,
        name: str,
        type_: PolicyType = PolicyType.SCAN_PROFILE,
        initial_definition: Optional[dict] = None,
        created_by: str = "admin"
    ) -> Tuple[Policy, PolicyVersion]:
        """Creates a new policy with version 1 DRAFT."""
        now_iso = datetime.now(timezone.utc).isoformat()
        definition = initial_definition or {}
        checksum = compute_policy_checksum(definition)

        policy = Policy(
            tenant_id=self.tenant_id,
            name=name,
            type=type_.value if hasattr(type_, "value") else str(type_),
            enabled=True,
            created_at=now_iso
        )
        repository.save_policy(policy)

        version = PolicyVersion(
            policy_id=policy.id,
            version=1,
            status=PolicyVersionStatus.DRAFT.value,
            definition_json=definition,
            checksum=checksum,
            created_by=created_by,
            created_at=now_iso
        )
        repository.save_policy_version(version)

        repository.log_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                actor_user_id=created_by,
                action="policy_created",
                resource_type="policy",
                resource_id=policy.id,
                result="success",
                metadata={"name": name, "version": 1, "checksum": checksum}
            )
        )
        return policy, version

    def create_new_version(
        self,
        policy_id: str,
        definition_json: dict,
        created_by: str = "admin"
    ) -> PolicyVersion:
        """
        Creates a new draft version for an existing policy.
        Enforces immutability: existing ACTIVE versions are never overwritten.
        """
        policy = repository.get_policy(policy_id, self.tenant_id)
        if not policy:
            raise ValueError(f"Policy {policy_id} not found in tenant {self.tenant_id}")

        existing_versions = repository.list_policy_versions(policy_id)
        max_ver = max([v.version for v in existing_versions], default=0)
        next_ver = max_ver + 1

        checksum = compute_policy_checksum(definition_json)
        now_iso = datetime.now(timezone.utc).isoformat()

        version = PolicyVersion(
            policy_id=policy.id,
            version=next_ver,
            status=PolicyVersionStatus.DRAFT.value,
            definition_json=definition_json,
            checksum=checksum,
            created_by=created_by,
            created_at=now_iso
        )
        repository.save_policy_version(version)
        return version

    def activate_version(
        self,
        version_id: str,
        approved_by: Optional[str] = None,
        actor_user_id: str = "admin"
    ) -> PolicyVersion:
        """
        Activates a draft policy version.
        Retires previous active version and updates policy.active_version_id.
        Enforces two-person approval if configured.
        """
        version = repository.get_policy_version(version_id)
        if not version:
            raise ValueError(f"PolicyVersion {version_id} not found")

        policy = repository.get_policy(version.policy_id, self.tenant_id)
        if not policy:
            raise ValueError(f"Parent Policy not found for version {version_id}")

        if POLICY_APPROVAL_REQUIRED:
            if not approved_by or approved_by == version.created_by:
                raise PermissionError("Policy activation requires two-person approval by an independent reviewer")

        now_iso = datetime.now(timezone.utc).isoformat()

        # Retire previously active version
        if policy.active_version_id:
            old_ver = repository.get_policy_version(policy.active_version_id)
            if old_ver:
                old_ver.status = PolicyVersionStatus.RETIRED.value
                repository.save_policy_version(old_ver)

        # Activate target version
        version.status = PolicyVersionStatus.ACTIVE.value
        version.approved_by = approved_by or actor_user_id
        version.activated_at = now_iso
        repository.save_policy_version(version)

        # Update policy pointer
        policy.active_version_id = version.id
        policy.updated_at = now_iso
        repository.save_policy(policy)

        repository.log_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                actor_user_id=actor_user_id,
                action="policy_version_activated",
                resource_type="policy_version",
                resource_id=version.id,
                result="success",
                metadata={
                    "policy_id": policy.id,
                    "version": version.version,
                    "checksum": version.checksum,
                    "approved_by": version.approved_by
                }
            )
        )
        return version

    def diff_versions(self, version_id_a: str, version_id_b: str) -> dict:
        """
        Computes structured field-by-field diff between two policy versions.
        Returns: {added: {...}, removed: {...}, modified: {field: {old: ..., new: ...}}}
        """
        va = repository.get_policy_version(version_id_a)
        vb = repository.get_policy_version(version_id_b)
        if not va or not vb:
            raise ValueError("One or both policy versions not found")

        da = va.definition_json or {}
        db = vb.definition_json or {}

        added = {k: db[k] for k in db if k not in da}
        removed = {k: da[k] for k in da if k not in db}
        modified = {}

        for k in da:
            if k in db and da[k] != db[k]:
                modified[k] = {"old": da[k], "new": db[k]}

        return {
            "version_a": va.version,
            "version_b": vb.version,
            "checksum_a": va.checksum,
            "checksum_b": vb.checksum,
            "added": added,
            "removed": removed,
            "modified": modified
        }
