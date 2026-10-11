"""
Domain Ownership Verification Engine for SentinelWP EASM.

Methods:
- DNS_TXT: Checks for _sentinelwp-verification.<hostname> TXT challenge token.
- HTTP_TOKEN: Checks for /.well-known/sentinelwp-verification.txt challenge token.

Lifecycle:
- PENDING -> VERIFIED / FAILED / EXPIRED
- Integrates with ScanAuthorization to enforce REQUIRE_VERIFIED_OWNERSHIP_FOR_ACTIVE_SCANS.
"""
import hashlib
import logging
import os
import secrets
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from core.models import AssetVerification, VerificationMethod, VerificationStatus, AuditEvent
from core import repository

logger = logging.getLogger("sentinelwp.easm.verification")

# Production policy configuration
REQUIRE_VERIFIED_OWNERSHIP_FOR_ACTIVE_SCANS = os.getenv(
    "REQUIRE_VERIFIED_OWNERSHIP_FOR_ACTIVE_SCANS",
    "true" if os.getenv("ENVIRONMENT") in ("production", "prod") else "false"
).lower() in ("true", "1", "yes")


def generate_verification_challenge(tenant_id: str, asset_id: str) -> str:
    """Generates a cryptographically strong, non-guessable ownership verification token."""
    raw_token = f"sentinelwp-verify-{tenant_id[:8]}-{secrets.token_urlsafe(24)}"
    return raw_token


def initiate_domain_verification(
    tenant_id: str,
    asset_id: str,
    method: VerificationMethod = VerificationMethod.DNS_TXT,
    ttl_days: int = 30
) -> AssetVerification:
    """Creates a new domain verification record with challenge token."""
    asset = repository.get_asset(asset_id, tenant_id)
    if not asset:
        raise ValueError(f"Asset {asset_id} not found in tenant {tenant_id}")

    challenge = generate_verification_challenge(tenant_id, asset_id)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(days=ttl_days)).isoformat()

    verification = AssetVerification(
        tenant_id=tenant_id,
        asset_id=asset_id,
        method=method.value if hasattr(method, "value") else str(method),
        challenge=challenge,
        status=VerificationStatus.PENDING.value,
        expires_at=expires_at,
        created_at=now.isoformat()
    )
    repository.save_asset_verification(verification)

    repository.log_audit_event(
        AuditEvent(
            tenant_id=tenant_id,
            action="asset_verification_started",
            resource_type="asset_verification",
            resource_id=verification.id,
            result="success",
            metadata={"asset_id": asset_id, "method": verification.method}
        )
    )
    return verification


def verify_asset_ownership(
    verification_id: str,
    tenant_id: str,
    dns_resolver_mock: Optional[callable] = None,
    http_fetcher_mock: Optional[callable] = None
) -> Tuple[bool, str]:
    """
    Executes real or mocked verification for a pending verification challenge.
    Updates verification status to VERIFIED or FAILED with audit event.
    """
    ver = repository.get_asset_verification(verification_id, tenant_id)
    if not ver:
        return False, f"Verification {verification_id} not found"

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    if ver.expires_at and ver.expires_at < now_iso:
        ver.status = VerificationStatus.EXPIRED.value
        repository.save_asset_verification(ver)
        return False, "Verification challenge has expired"

    asset = repository.get_asset(ver.asset_id, tenant_id)
    if not asset:
        return False, "Associated asset not found"

    verified = False
    details = ""

    if ver.method == VerificationMethod.DNS_TXT.value:
        # Check TXT record on _sentinelwp-verification.<hostname>
        record_name = f"_sentinelwp-verification.{asset.hostname}"
        if dns_resolver_mock:
            txt_records = dns_resolver_mock(record_name)
        else:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(record_name, "TXT", lifetime=5)
                txt_records = [b"".join(r.strings).decode("utf-8") for r in answers]
            except Exception as e:
                txt_records = []
                details = f"DNS query failed: {e}"

        if ver.challenge in txt_records:
            verified = True
            details = f"TXT record matching challenge verified on {record_name}"
        else:
            details = details or f"Challenge token not found in TXT records for {record_name}"

    elif ver.method == VerificationMethod.HTTP_TOKEN.value:
        # Check /.well-known/sentinelwp-verification.txt
        well_known_url = f"{asset.canonical_url.rstrip('/')}/.well-known/sentinelwp-verification.txt"
        if http_fetcher_mock:
            status_code, body = http_fetcher_mock(well_known_url)
        else:
            try:
                req = urllib.request.Request(well_known_url, headers={"User-Agent": "SentinelWP-Verifier/1.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status_code = resp.status
                    body = resp.read().decode("utf-8", errors="replace")
            except Exception as e:
                status_code = 500
                body = ""
                details = f"HTTP check failed: {e}"

        if status_code == 200 and ver.challenge in body:
            verified = True
            details = f"Well-known token verified at {well_known_url}"
        else:
            details = details or f"Challenge token not found at {well_known_url} (HTTP {status_code})"

    # Update verification status
    if verified:
        ver.status = VerificationStatus.VERIFIED.value
        ver.verified_at = now_iso
        repository.save_asset_verification(ver)
        repository.log_audit_event(
            AuditEvent(
                tenant_id=tenant_id,
                action="asset_verified",
                resource_type="asset_verification",
                resource_id=ver.id,
                result="success",
                metadata={"asset_id": ver.asset_id, "method": ver.method, "details": details}
            )
        )
        return True, details
    else:
        ver.status = VerificationStatus.FAILED.value
        repository.save_asset_verification(ver)
        repository.log_audit_event(
            AuditEvent(
                tenant_id=tenant_id,
                action="asset_verification_failed",
                resource_type="asset_verification",
                resource_id=ver.id,
                result="failure",
                metadata={"asset_id": ver.asset_id, "method": ver.method, "details": details}
            )
        )
        return False, details


def is_asset_verified(tenant_id: str, asset_id: str) -> bool:
    """Returns True if the asset currently holds a valid, unexpired VERIFIED status."""
    latest = repository.get_latest_verification_for_asset(tenant_id, asset_id)
    if not latest or latest.status != VerificationStatus.VERIFIED.value:
        return False
    if latest.expires_at and latest.expires_at < datetime.now(timezone.utc).isoformat():
        return False
    return True
