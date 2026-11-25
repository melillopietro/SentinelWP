"""
Canonical technology inventory sync from scan findings.

One observation per (tenant, asset, component name); each successful scan
refreshes version metadata so rescanning does not leave stale duplicate rows.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from core.models import TechnologyObservation
from core.wordpress_version import collect_detected_plugins

logger = logging.getLogger(__name__)

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


def _norm_confidence(raw: Optional[str]) -> str:
    if not raw:
        return "MEDIUM"
    return str(raw).strip().upper() or "MEDIUM"


def collect_detected_themes(findings: Sequence) -> List[dict]:
    """Merge theme detections per slug, preferring higher version confidence."""
    merged: Dict[str, dict] = {}
    for f in findings:
        if getattr(f, "category", "") == "plugins":
            continue
        raw = getattr(f, "raw_data", None) or {}
        theme = raw.get("theme")
        if not theme and raw.get("type") == "theme":
            theme = raw.get("slug") or raw.get("name")
        if not theme:
            title = getattr(f, "title", "") or ""
            m = re.match(r"^(?:Theme Identified|Default Theme Present):\s*([a-zA-Z0-9_-]+)", title)
            if m:
                theme = m.group(1)
        if not theme:
            continue

        version = raw.get("version")
        conf = str(raw.get("version_confidence") or "low").lower()
        source = raw.get("source") or raw.get("method") or raw.get("detection_method") or "passive"
        rank = _CONFIDENCE_RANK.get(conf, 1)

        prev = merged.get(theme)
        if not prev:
            merged[theme] = {
                "slug": theme,
                "version": version,
                "version_confidence": conf,
                "source": source,
                "_rank": rank,
            }
            continue

        prev_rank = prev.get("_rank", 0)
        if rank > prev_rank or (rank == prev_rank and version and not prev.get("version")):
            merged[theme] = {
                "slug": theme,
                "version": version or prev.get("version"),
                "version_confidence": conf,
                "source": source,
                "_rank": rank,
            }
        elif version and not prev.get("version"):
            prev["version"] = version
            prev["version_confidence"] = conf

    out: List[dict] = []
    for item in merged.values():
        item.pop("_rank", None)
        out.append(item)
    return out


def _upsert_observation(
    *,
    tenant_id: str,
    asset_id: str,
    technology_type: str,
    name: str,
    version: Optional[str],
    source: str,
    confidence: str,
    now_iso: str,
) -> None:
    from core.repository import save_technology_observation

    save_technology_observation(
        TechnologyObservation(
            tenant_id=tenant_id,
            asset_id=asset_id,
            technology_type=technology_type,
            name=name,
            version=version,
            source=source,
            confidence=_norm_confidence(confidence),
            first_seen=now_iso,
            last_seen=now_iso,
            created_at=now_iso,
            updated_at=now_iso,
        )
    )


def sync_asset_technology_inventory(
    tenant_id: str,
    asset_id: str,
    findings: Sequence,
    *,
    is_wordpress: bool = False,
    wp_version: Optional[str] = None,
    wp_version_source: Optional[str] = None,
    wp_version_confidence: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Persist canonical per-asset technology rows from the latest scan findings.
    Returns summary counts for logging/metrics.
    """
    from core.repository import update_asset

    now_iso = datetime.now(timezone.utc).isoformat()
    saved = 0

    if is_wordpress:
        core_ver = wp_version
        if core_ver in ("Unknown", "Not WordPress", None, ""):
            core_ver = None
        _upsert_observation(
            tenant_id=tenant_id,
            asset_id=asset_id,
            technology_type="CMS",
            name="WordPress",
            version=core_ver,
            source=wp_version_source or "scan",
            confidence=wp_version_confidence or "MEDIUM",
            now_iso=now_iso,
        )
        saved += 1

    plugin_slugs: List[str] = []
    for plugin in collect_detected_plugins(findings):
        slug = plugin.get("slug")
        if not slug:
            continue
        plugin_slugs.append(slug)
        _upsert_observation(
            tenant_id=tenant_id,
            asset_id=asset_id,
            technology_type="WORDPRESS_PLUGIN",
            name=slug,
            version=plugin.get("version"),
            source="plugin_scanner",
            confidence=plugin.get("version_confidence") or "low",
            now_iso=now_iso,
        )
        saved += 1

    theme_slugs: List[str] = []
    for theme in collect_detected_themes(findings):
        slug = theme.get("slug")
        if not slug:
            continue
        theme_slugs.append(slug)
        _upsert_observation(
            tenant_id=tenant_id,
            asset_id=asset_id,
            technology_type="WORDPRESS_THEME",
            name=slug,
            version=theme.get("version"),
            source=theme.get("source") or "theme_scanner",
            confidence=theme.get("version_confidence") or "low",
            now_iso=now_iso,
        )
        saved += 1

    posture: Dict[str, Any] = {}
    if is_wordpress and wp_version and wp_version not in ("Unknown", "Not WordPress"):
        posture["wp_version"] = wp_version
    if plugin_slugs:
        posture["detected_plugins"] = json.dumps(sorted(set(plugin_slugs)))
    if theme_slugs:
        posture["detected_themes"] = json.dumps(sorted(set(theme_slugs)))

    if posture:
        try:
            update_asset(asset_id, tenant_id=tenant_id, **posture)
        except Exception as exc:
            logger.debug("Asset technology posture update skipped: %s", exc)

    return {
        "observations_written": saved,
        "plugins": len(set(plugin_slugs)),
        "themes": len(set(theme_slugs)),
    }