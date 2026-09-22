"""
Shared scan post-processing: CVE enrichment, local intel matching, metadata extraction.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from config import OSV_LIVE_ENRICHMENT_ENABLED
from core.models import Finding, ScanResult, ScanStatus, Severity
from core.risk_engine import compute_risk_score
from core.wordpress_version import (
    collect_detected_plugins,
    extract_wordpress_version,
    is_version_less_than,
    recommended_security_release,
)

logger = logging.getLogger(__name__)


def _severity_from_cvss(cvss: float, match_status: str) -> Severity:
    if match_status == "version_unknown":
        return Severity.MEDIUM
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def apply_vulnerability_intelligence(all_findings: List[Finding], scan_id: str, wp_version: Optional[str]) -> List[Finding]:
    if OSV_LIVE_ENRICHMENT_ENABLED:
        try:
            from scanners.vuln_intel import enrich_findings_with_cves
            all_findings = enrich_findings_with_cves(all_findings)
        except Exception as exc:
            logger.debug("OSV enrichment skipped: %s", exc)

    existing_cves = set()
    for f in all_findings:
        raw = f.raw_data or {}
        if raw.get("cve"):
            existing_cves.add(raw["cve"])
        for m in raw.get("cve_matches") or []:
            cve_id = m.get("cve_id")
            if cve_id:
                existing_cves.add(cve_id)

    detected_plugins = collect_detected_plugins(all_findings)

    try:
        from core.vulnerability_intelligence.service import match_scan_findings

        vuln_matches = match_scan_findings(wp_version, detected_plugins)
        for vm in vuln_matches:
            cve = vm.get("cve")
            if cve and cve in existing_cves:
                continue

            cvss = float(vm.get("cvss_score") or 0)
            match_status = vm.get("match_status", "affected")
            sev = _severity_from_cvss(cvss, match_status)

            slug = vm.get("plugin_slug") or vm.get("slug") or "unknown"
            if vm.get("software_type") == "core":
                slug = "wordpress"

            if match_status == "version_unknown":
                title = f"Potential Exposure: {cve or 'Unknown CVE'} — {slug}"
                desc = (
                    f"Potential exposure — version not detected. {cve or ''} affects {slug} "
                    f"({vm.get('affected_range', 'unknown range')})."
                )
            else:
                title = f"Vulnerability: {cve or 'Unknown CVE'} — {slug} {vm.get('detected_version', '')}"
                desc = (
                    f"{cve or ''} affects {slug} version {vm.get('detected_version', 'unknown')} "
                    f"(range: {vm.get('affected_range', 'N/A')}). "
                    f"Patched in: {vm.get('patched_version', 'N/A')}."
                )

            if vm.get("kev_listed"):
                title += " [Listed in CISA KEV]"

            refs = vm.get("references") or []
            reference = refs[0] if isinstance(refs, list) and refs else ""

            all_findings.append(
                Finding(
                    scan_id=scan_id,
                    category="vulnerability_intelligence",
                    title=title,
                    description=desc,
                    severity=sev,
                    confidence=0.95 if match_status == "affected" else 0.6,
                    remediation=f"Update to patched version: {vm.get('patched_version', 'N/A')}.",
                    reference=reference,
                    raw_data=vm,
                )
            )
    except Exception as exc:
        logger.warning("Local vulnerability intelligence matching failed: %s", exc)

    return all_findings


def add_core_maintenance_findings(all_findings: List[Finding], scan_id: str, wp_version: Optional[str]) -> List[Finding]:
    if not wp_version:
        return all_findings
    latest = recommended_security_release(wp_version)
    if not latest or not is_version_less_than(wp_version, latest):
        return all_findings

    all_findings.append(
        Finding(
            scan_id=scan_id,
            category="configuration",
            title=f"WordPress Core Update Available ({wp_version} → {latest})",
            description=(
                f"Detected WordPress {wp_version}. The latest security release for this branch is {latest}. "
                "Apply updates promptly, especially after critical core advisories."
            ),
            severity=Severity.MEDIUM,
            confidence=0.9,
            remediation=f"Upgrade WordPress to {latest} or newer on this branch.",
            reference="https://wordpress.org/news/category/releases/",
            raw_data={"detected_version": wp_version, "recommended_version": latest},
        )
    )
    return all_findings


def extract_scan_metadata(all_findings: List[Finding]) -> Tuple[bool, Optional[str], Optional[str]]:
    wp_findings = [f for f in all_findings if (f.raw_data or {}).get("is_wordpress")]
    is_wp = len(wp_findings) > 0
    wp_version = extract_wordpress_version(all_findings) if is_wp else None
    if is_wp and not wp_version:
        wp_version = "Unknown"
    elif not is_wp:
        wp_version = "Not WordPress"

    whois_info = None
    for f in all_findings:
        info = (f.raw_data or {}).get("whois_info")
        if info:
            whois_info = info
            break

    return is_wp, wp_version, whois_info


def finalize_scan_findings(all_findings: List[Finding], scan: ScanResult) -> List[Finding]:
    is_wp, wp_version, whois_info = extract_scan_metadata(all_findings)
    scan.is_wordpress = is_wp
    scan.wp_version = wp_version if wp_version else None
    scan.whois_info = whois_info

    wp_for_intel = wp_version if is_wp and wp_version not in ("Unknown", "Not WordPress") else None
    all_findings = apply_vulnerability_intelligence(all_findings, scan.id, wp_for_intel)
    all_findings = add_core_maintenance_findings(all_findings, scan.id, wp_for_intel)
    return all_findings


def finalize_and_score_scan(all_findings: List[Finding], scan: ScanResult) -> List[Finding]:
    """Single entry point: metadata, intel enrichment, risk score (sync + async)."""
    all_findings = finalize_scan_findings(all_findings, scan)
    score, grade = compute_risk_score(all_findings)
    scan.score = score
    scan.grade = grade
    scan.findings = all_findings
    return all_findings


def mark_scan_completed(scan: ScanResult) -> None:
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc).isoformat()
