"""
EASM module public interface for SentinelWP.
"""
from core.easm.discovery import BoundedDiscoveryEngine
from core.easm.verification import (
    initiate_domain_verification,
    verify_asset_ownership,
    is_asset_verified,
    REQUIRE_VERIFIED_OWNERSHIP_FOR_ACTIVE_SCANS
)

__all__ = [
    "BoundedDiscoveryEngine",
    "initiate_domain_verification",
    "verify_asset_ownership",
    "is_asset_verified",
    "REQUIRE_VERIFIED_OWNERSHIP_FOR_ACTIVE_SCANS",
]
