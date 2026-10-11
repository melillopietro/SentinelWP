"""
Deterministic Finding Fingerprinting Module for SentinelWP.
Ensures stable, non-volatile correlation of findings across recurring scans.
"""
import hashlib
import re
from typing import Optional
from urllib.parse import urlparse


def normalize_location(location: str) -> str:
    """
    Normalizes URLs, paths, or file locations to prevent false differentiation.
    Strips protocol, domain, query parameters, fragments, and standardizes slashes.
    """
    if not location:
        return ""
    loc = location.strip()
    if loc.startswith("http://") or loc.startswith("https://"):
        parsed = urlparse(loc)
        loc = parsed.path or "/"
    elif "?" in loc or "#" in loc:
        loc = loc.split("?")[0].split("#")[0]

    # Normalize Windows and Unix paths
    clean = loc.replace("\\", "/").strip().lower()
    clean = re.sub(r"/+", "/", clean)
    if not clean.startswith("/"):
        clean = "/" + clean
    clean = clean.rstrip("/")
    return clean or "/"


def normalize_identifier(identifier: str) -> str:
    """Normalizes CVE, CWE, plugin slug, or rule identifier."""
    if not identifier:
        return ""
    return identifier.strip().upper()


def normalize_component(component: str) -> str:
    """Normalizes plugin slug, theme slug, core component, or header."""
    if not component:
        return ""
    return component.strip().lower()


def compute_finding_fingerprint(
    tenant_id: str,
    asset_id: Optional[str],
    scanner_id: str,
    finding_type: str,
    location: str,
    identifier: str = "",
    component: str = "",
) -> str:
    """
    Calculates a stable, deterministic SHA-256 fingerprint for a logical security issue.

    Attributes included:
    - tenant_id (workspace boundary)
    - asset_id (target boundary)
    - scanner_id (detection module)
    - finding_type (category or vulnerability type)
    - normalized_component (optional plugin/theme/core component)
    - normalized_location (static resource or endpoint)
    - normalized_identifier (CVE, CWE, or canonical title key)

    Explicitly excluded to maintain stability across runs:
    - scan_id
    - timestamp / first_seen / last_seen
    - volatile evidence / dynamic response headers / random nonces
    """
    norm_loc = normalize_location(location)
    norm_id = normalize_identifier(identifier)
    norm_comp = normalize_component(component)
    clean_tenant = str(tenant_id or "default-tenant").strip()
    clean_asset = str(asset_id or "global-asset").strip()
    clean_scanner = str(scanner_id or "general").strip().lower()
    clean_type = str(finding_type or "unknown").strip().lower()

    if norm_comp:
        raw_payload = f"{clean_tenant}|{clean_asset}|{clean_scanner}|{clean_type}|{norm_comp}|{norm_loc}|{norm_id}"
    else:
        raw_payload = f"{clean_tenant}|{clean_asset}|{clean_scanner}|{clean_type}|{norm_loc}|{norm_id}"
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
