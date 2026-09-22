"""
WordPress core version parsing and comparison helpers.
"""
from __future__ import annotations

import re
from typing import List, Optional, Sequence

from core.vulnerability_intelligence.version_matcher import compare_versions, parse_version

# Latest security/maintenance release per major.minor branch (SentinelWP curated).
# Updated for WordPress 7.1.2 (2026-09-22).
WORDPRESS_LATEST_BY_BRANCH: dict[str, str] = {
    "7.1": "7.1.2",
    "7.0": "7.0.4",
    "6.9": "6.9.7",
    "6.8": "6.8.8",
    "6.7": "6.7.7",
    "6.6": "6.6.7",
    "6.5": "6.5.10",
    "6.4": "6.4.10",
    "6.3": "6.3.10",
    "6.2": "6.2.11",
    "6.1": "6.1.12",
    "6.0": "6.0.14",
}

_NON_VERSION_LABELS = frozenset(
    {"unknown", "not wordpress", "not detected", "n/a", ""}
)


def normalize_wp_version_label(version: Optional[str]) -> Optional[str]:
    if not version:
        return None
    cleaned = version.strip()
    if cleaned.lower() in _NON_VERSION_LABELS:
        return None
    if not re.match(r"^\d+\.\d+(\.\d+)?", cleaned):
        return None
    return cleaned


def version_tuple(version: str) -> Optional[tuple]:
    return parse_version(normalize_wp_version_label(version) or "")


def compare_wp_versions(a: str, b: str) -> Optional[int]:
    """Return -1/0/1 if both parse; None if either is invalid."""
    ta = version_tuple(a)
    tb = version_tuple(b)
    if ta is None or tb is None:
        return None
    return compare_versions(ta, tb)


def is_version_less_than(detected: str, fixed_in: str) -> bool:
    cmp = compare_wp_versions(detected, fixed_in)
    return cmp is not None and cmp < 0


def branch_key(version: str) -> Optional[str]:
    norm = normalize_wp_version_label(version)
    if not norm:
        return None
    parts = norm.split(".")
    if len(parts) < 2:
        return None
    return f"{parts[0]}.{parts[1]}"


def recommended_security_release(version: str) -> Optional[str]:
    key = branch_key(version)
    if not key:
        return None
    return WORDPRESS_LATEST_BY_BRANCH.get(key)


def extract_wordpress_version(findings: Sequence) -> Optional[str]:
    """
    Prefer version from WordPress detector findings, not plugin/theme assets.
    """
    for f in findings:
        raw = getattr(f, "raw_data", None) or {}
        if raw.get("is_wordpress") and raw.get("version"):
            return normalize_wp_version_label(str(raw.get("version")))
    for f in findings:
        raw = getattr(f, "raw_data", None) or {}
        if raw.get("version_source"):
            return normalize_wp_version_label(str(raw.get("version")))
        title = getattr(f, "title", "") or ""
        if title.startswith("WordPress Version Exposed:"):
            return normalize_wp_version_label(str(raw.get("version")))
    return None


def collect_detected_plugins(findings: Sequence) -> List[dict]:
    plugins: List[dict] = []
    seen = set()
    for f in findings:
        if getattr(f, "category", "") != "plugins":
            continue
        raw = getattr(f, "raw_data", None) or {}
        slug = raw.get("slug") or raw.get("plugin")
        version = raw.get("version")
        if not slug:
            continue
        key = (slug, version)
        if key in seen:
            continue
        seen.add(key)
        plugins.append({"slug": slug, "version": version})
    return plugins
