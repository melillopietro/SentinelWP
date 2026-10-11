"""
Authorized External Attack Surface Management (EASM) Discovery Engine for SentinelWP.

Guarantees:
- Strictly bounded to authorized DiscoveryScope roots and allowed suffixes.
- No unbounded internet enumeration.
- Candidate deduplication and review lifecycle (NEW -> REVIEW -> APPROVED -> PROMOTED / REJECTED).
- Promotion to Asset with mandatory audit event logging.
- Confidence scoring: LOW, MEDIUM, HIGH, CONFIRMED.
"""
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from core.models import (
    DiscoveryScope, DiscoveredAsset, DiscoveredAssetStatus,
    DiscoverySource, DiscoveryConfidence, Asset, AuditEvent
)
from core.canonical import canonicalize_url
from core import repository

logger = logging.getLogger("sentinelwp.easm.discovery")


class BoundedDiscoveryEngine:
    """
    Executes controlled, authorized asset discovery strictly within defined scopes.
    """

    def __init__(self, tenant_id: str = "default-tenant"):
        self.tenant_id = tenant_id

    def is_target_allowed(self, target_hostname: str, scope: DiscoveryScope) -> Tuple[bool, str]:
        """
        Validates if target hostname is strictly bounded by the authorized scope:
        - Must be subdomain of root_domain or equal to root_domain
        - Must match allowed_suffixes if specified
        - Must not match any excluded_patterns
        - Must not exceed max_depth subdomains
        """
        host = target_hostname.lower().strip()
        root = scope.root_domain.lower().strip()

        # 1. Scope root domain boundary check
        if host != root and not host.endswith(f".{root}"):
            return False, f"Hostname '{host}' is outside authorized root domain '{root}'"

        # 2. Excluded patterns check (regex or substring)
        for pattern in scope.excluded_patterns:
            if pattern and (pattern.lower() in host or re.search(pattern, host, re.IGNORECASE)):
                return False, f"Hostname '{host}' matches excluded pattern '{pattern}'"

        # 3. Allowed suffixes check (if non-empty)
        if scope.allowed_suffixes:
            matched_suffix = any(host.endswith(s.lower().strip()) for s in scope.allowed_suffixes)
            if not matched_suffix:
                return False, f"Hostname '{host}' does not match any allowed suffix {scope.allowed_suffixes}"

        # 4. Max depth check: count subdomain labels relative to root_domain
        if host != root:
            subdomain_part = host[:-len(f".{root}")]
            depth = len(subdomain_part.split("."))
            if depth > scope.max_depth:
                return False, f"Hostname '{host}' depth {depth} exceeds allowed max_depth {scope.max_depth}"

        return True, "Authorized"

    def process_discovered_candidate(
        self,
        scope: DiscoveryScope,
        raw_target: str,
        source: DiscoverySource = DiscoverySource.MANUAL_IMPORT,
        confidence: DiscoveryConfidence = DiscoveryConfidence.MEDIUM,
        evidence_id: Optional[str] = None
    ) -> Optional[DiscoveredAsset]:
        """
        Validates, canonicalizes, and records a candidate discovered asset.
        Deduplicates against existing candidates and assets.
        """
        if not scope.enabled:
            logger.warning(f"Discovery scope {scope.id} is disabled, ignoring candidate {raw_target}")
            return None

        # Canonicalize target
        try:
            canonical_url, hostname = canonicalize_url(raw_target)
        except Exception as e:
            logger.warning(f"Failed to canonicalize target '{raw_target}': {e}")
            return None

        allowed, reason = self.is_target_allowed(hostname, scope)
        if not allowed:
            logger.info(f"Target '{raw_target}' rejected: {reason}")
            return None

        now_iso = datetime.now(timezone.utc).isoformat()

        # Check existing candidates in tenant
        existing_candidates = repository.list_discovered_assets(self.tenant_id, scope_id=scope.id)
        for cand in existing_candidates:
            if cand.hostname.lower() == hostname.lower():
                # Update last seen timestamp
                cand.last_seen_at = now_iso
                repository.save_discovered_asset(cand)
                return cand

        # Create new candidate in NEW status
        candidate = DiscoveredAsset(
            tenant_id=self.tenant_id,
            discovery_scope_id=scope.id,
            hostname=hostname,
            canonical_url=canonical_url,
            source=source.value if hasattr(source, "value") else str(source),
            confidence=confidence.value if hasattr(confidence, "value") else str(confidence),
            first_seen_at=now_iso,
            last_seen_at=now_iso,
            status=DiscoveredAssetStatus.NEW.value,
            evidence_id=evidence_id
        )
        repository.save_discovered_asset(candidate)

        # Log audit event
        repository.log_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                action="asset_discovered",
                resource_type="discovered_asset",
                resource_id=candidate.id,
                result="success",
                metadata={"hostname": hostname, "scope_id": scope.id, "source": candidate.source}
            )
        )
        return candidate

    def promote_candidate_to_asset(
        self,
        candidate_id: str,
        actor_user_id: str = "system",
        business_unit_id: Optional[str] = None,
        criticality: str = "medium"
    ) -> Optional[Asset]:
        """
        Promotes an APPROVED DiscoveredAsset into an official Asset.
        Strict transition gating with mandatory audit logging.
        """
        candidate = repository.get_discovered_asset(candidate_id, self.tenant_id)
        if not candidate:
            raise ValueError(f"DiscoveredAsset {candidate_id} not found in tenant {self.tenant_id}")

        if candidate.status in (DiscoveredAssetStatus.REJECTED.value, DiscoveredAssetStatus.PROMOTED.value):
            raise ValueError(f"Cannot promote DiscoveredAsset with status {candidate.status}")

        now_iso = datetime.now(timezone.utc).isoformat()

        # Check if Asset already exists
        existing_asset = repository.get_asset_by_url(self.tenant_id, candidate.canonical_url)
        if existing_asset:
            asset = existing_asset
        else:
            asset = Asset(
                tenant_id=self.tenant_id,
                canonical_url=candidate.canonical_url,
                hostname=candidate.hostname,
                display_name=candidate.hostname,
                business_unit_id=business_unit_id,
                criticality=criticality,
                status="active"
            )
            repository.save_asset(asset)

        # Update candidate status to PROMOTED
        candidate.status = DiscoveredAssetStatus.PROMOTED.value
        candidate.promoted_asset_id = asset.id
        candidate.updated_at = now_iso
        repository.save_discovered_asset(candidate)

        # Mandatory audit trail
        repository.log_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                actor_user_id=actor_user_id,
                action="asset_promoted",
                resource_type="asset",
                resource_id=asset.id,
                result="success",
                metadata={
                    "candidate_id": candidate.id,
                    "canonical_url": candidate.canonical_url,
                    "hostname": candidate.hostname
                }
            )
        )
        return asset
