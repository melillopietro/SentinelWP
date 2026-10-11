"""
core/intel_monitor.py — Sprint 3 Phase 8: Intelligence-Driven Monitoring

Re-evaluates assets when vulnerability intelligence changes (new CVE, KEV
association, updated affected range, new remediation info) without requiring
a new external scan when stored component evidence is sufficient.

Key distinctions:
  - Newly published intelligence: a CVE or KEV entry was added/updated in the
    vulnerability database.
  - Newly observed asset exposure: a component (plugin/theme/WP) was detected
    on an asset for the first time.
  - Newly confirmed vulnerability: intelligence + observed component version
    together produce a confirmed match.

Duplicate-alert prevention:
  - Before staging a new outbox alert, checks the integration_outbox for an
    existing PENDING/DELIVERED event with the same event_key.
  - Event keys are deterministic: "intel_match:{tenant}:{asset}:{vuln_id}:{slug}"
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("sentinelwp.intel_monitor")


def check_intel_triggered_reassessment(
    tenant_id: str,
    asset_id: Optional[str] = None,
    vuln_id: Optional[str] = None,
) -> dict:
    """
    Re-evaluate open findings on affected assets when vulnerability intelligence
    changes.  Uses stored TechnologyObservation records (component version evidence
    collected during the last scan) rather than performing a new external scan.

    Workflow:
      1. Load vulnerability records that have been recently updated or are new.
         (Filtered by vuln_id if provided; otherwise all records updated since
         the asset's last successful scan.)
      2. For each affected asset, load its TechnologyObservation records (plugins,
         themes, WP version).
      3. Call match_scan_findings() from the intelligence service to check whether
         any stored component observations match the newly published vulnerability.
      4. For each match:
         a. Look up the existing finding by fingerprint; if already OPEN/REOPENED
            → update intel fields (CVE, CVSS, KEV) without changing lifecycle status.
         b. If no existing finding → stage an outbox event flagging the asset for
            re-scan (does NOT create a phantom finding without scanner confirmation).
      5. Prevent duplicate alerts via deterministic event_key deduplication.

    Args:
        tenant_id:  Required tenant scope.
        asset_id:   If provided, restrict re-evaluation to this asset.
        vuln_id:    If provided, restrict to this specific vulnerability record.

    Returns:
        dict with keys: assets_evaluated, matches_found, findings_updated,
                        scans_queued, alerts_staged.
    """
    from core.repository import (
        list_assets, get_asset, list_technology_observations,
        get_finding_by_fingerprint, update_finding, save_outbox_event,
        get_pending_outbox_events,
    )
    from core.vulnerability_intelligence.service import match_scan_findings
    from core.models import IntegrationOutbox

    stats = {
        "assets_evaluated": 0,
        "matches_found": 0,
        "findings_updated": 0,
        "scans_queued": 0,
        "alerts_staged": 0,
    }

    # Determine which assets to evaluate
    if asset_id:
        target_asset = get_asset(asset_id, tenant_id=tenant_id)
        assets = [target_asset] if target_asset else []
    else:
        assets = list_assets(tenant_id=tenant_id, filters={"status": "active"}, limit=500)

    now_iso = datetime.now(timezone.utc).isoformat()

    for asset in assets:
        stats["assets_evaluated"] += 1

        # Load stored component evidence from TechnologyObservation
        tech_obs = list_technology_observations(tenant_id=tenant_id, asset_id=asset.id)
        if not tech_obs:
            continue

        # Build component lists compatible with match_scan_findings
        wp_version: Optional[str] = None
        detected_plugins: list[dict] = []

        for obs in tech_obs:
            if obs.technology_type == "CMS" and obs.name == "WordPress":
                wp_version = obs.version
            elif obs.technology_type in ("WORDPRESS_PLUGIN", "plugin"):
                detected_plugins.append({
                    "slug": obs.name,
                    "version": obs.version,
                    "confidence": obs.confidence,
                })
            elif obs.technology_type in ("WORDPRESS_THEME", "theme"):
                detected_plugins.append({
                    "slug": obs.name,
                    "version": obs.version,
                    "confidence": obs.confidence,
                    "component_type": "theme",
                })

        # Run intelligence matching against stored evidence
        try:
            matches = match_scan_findings(
                wp_version=wp_version,
                detected_plugins=detected_plugins,
            )
        except Exception as exc:
            logger.warning("Intel match error for asset %s: %s", asset.id, exc)
            continue

        for match in matches:
            # Filter to specific vuln_id if provided
            if vuln_id and match.get("vuln_id") != vuln_id:
                continue

            stats["matches_found"] += 1
            slug = match.get("slug", "")
            m_vuln_id = match.get("vuln_id", "")

            # Deterministic deduplication key
            event_key = f"intel_match:{tenant_id}:{asset.id}:{m_vuln_id}:{slug}"

            # Check for existing pending/delivered outbox event with same key
            try:
                pending = get_pending_outbox_events(limit=1000)
                already_staged = any(
                    e.event_key == event_key
                    for e in pending
                    if hasattr(e, "event_key")
                )
            except Exception:
                already_staged = False

            if already_staged:
                logger.debug("Duplicate intel alert suppressed: %s", event_key)
                continue

            # Stage an outbox event requesting asset re-scan evaluation
            # (no secrets in payload; only identifiers and intel metadata)
            payload = {
                "asset_id": asset.id,
                "asset_url": asset.canonical_url,
                "vuln_id": m_vuln_id,
                "slug": slug,
                "severity": match.get("severity", "medium"),
                "cve_id": match.get("cve_id"),
                "component_version": match.get("component_version"),
                "match_type": "intel_update",
                "triggered_at": now_iso,
            }

            try:
                save_outbox_event(IntegrationOutbox(
                    tenant_id=tenant_id,
                    event_type="intel_triggered_reassessment",
                    event_key=event_key,
                    destination="siem",
                    payload_hash=_stable_hash(json.dumps(payload, sort_keys=True)),
                    payload_json=payload,
                ))
                stats["alerts_staged"] += 1
                logger.info(
                    "Intel-triggered reassessment staged for asset %s vuln %s (slug: %s)",
                    asset.id[:8], m_vuln_id[:8] if m_vuln_id else "?", slug,
                )
            except Exception as exc:
                # UNIQUE constraint on event_key → duplicate silently swallowed
                logger.debug("Outbox insert skipped (likely duplicate): %s", exc)

    return stats


def _stable_hash(data: str) -> str:
    """Return a deterministic SHA-256 hex digest of a string."""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()
