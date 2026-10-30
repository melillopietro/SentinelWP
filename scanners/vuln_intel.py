"""
Live Vulnerability Intelligence Integration (OSV.dev & CIRCL CVE APIs).
Enriches findings for detected plugins/themes/core with real CVE IDs and CVSS scores.
"""
import requests
from typing import List, Dict, Any, Optional
from core.models import Finding, Severity

# OSV.dev REST API endpoint (free, no API key required)
OSV_API_URL = "https://api.osv.dev/v1/query"


def lookup_osv_vulnerabilities(package_name: str, version: str, ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
    """
    Query OSV.dev for known vulnerabilities for a given package/version.
    Returns list of dicts with cve_id, summary, details, severity.
    """
    if not package_name or not version:
        return []

    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": "WordPress"
        }
    }
    
    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=5)
        if resp.status_code != 200:
            return []
        
        data = resp.json()
        vulns = data.get("vulns", [])
        results = []

        for v in vulns[:5]:  # Limit to top 5
            aliases = v.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id", "UNKNOWN-VULN"))
            summary = v.get("summary", v.get("details", "Known vulnerability detected"))[:250]
            
            results.append({
                "cve_id": cve_id,
                "summary": summary,
                "details": v.get("details", "")[:500],
                "osv_id": v.get("id"),
                "references": [ref.get("url") for ref in v.get("references", []) if ref.get("url")][:3],
            })
        return results
    except Exception:
        return []


def _cvss_to_severity(cvss_score: Optional[float]) -> Optional[Severity]:
    """
    Map a CVSS base score to a Severity enum value using the standard CVSS v3 scale.
    Returns None if the score is missing or not a usable float.

    INTEL-GAP-004: replaces the unconditional Severity.HIGH assignment in
    enrich_findings_with_cves() with a score-based mapping.

    CVSS v3 bands:
      9.0–10.0 → CRITICAL
      7.0–8.9  → HIGH
      4.0–6.9  → MEDIUM
      0.1–3.9  → LOW
      0.0      → INFO
    """
    if cvss_score is None:
        return None
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def enrich_findings_with_cves(findings: List[Finding]) -> List[Finding]:
    """
    Enrich a list of findings with real CVE data from OSV.dev.

    Enterprise policy: gated by OSV_LIVE_ENRICHMENT_ENABLED (default false).
    Local Wordfence/CISA matching remains authoritative via scan_pipeline.
    Uncorroborated OSV hits are advisory-only (confidence capped at 0.75).

    INTEL-GAP-004: severity is derived from CVSS when present; otherwise preserved.
    """
    try:
        from config import OSV_LIVE_ENRICHMENT_ENABLED
        if not OSV_LIVE_ENRICHMENT_ENABLED:
            return findings
    except Exception:
        return findings

    for f in findings:
        is_core = "WordPress CMS Detected" in f.title or "WordPress Version Exposed" in f.title
        if f.category in ("plugins", "information_disclosure") or is_core:
            slug = f.raw_data.get("slug") or f.raw_data.get("plugin") or f.raw_data.get("theme")
            version = f.raw_data.get("version")

            if is_core and not slug and version:
                slug = "wordpress"

            if slug and version:
                cves = lookup_osv_vulnerabilities(slug, version)
                if cves:
                    cve_ids = [c["cve_id"] for c in cves]
                    local_corroborated = False
                    try:
                        from core.vulnerability_intelligence import repository as vuln_repo

                        sw_type = "core" if slug == "wordpress" else "plugin"
                        local_rows = vuln_repo.get_vulnerabilities_for_slug(slug, sw_type)
                        local_cves = {r.get("cve") for r in local_rows if r.get("cve")}
                        local_corroborated = bool(local_cves.intersection(cve_ids))
                    except Exception:
                        local_corroborated = False

                    f.title += f" [CVE: {', '.join(cve_ids[:2])}]"
                    f.description += (
                        f" Live OSV feed match: {len(cves)} record(s) ({', '.join(cve_ids[:3])})."
                    )
                    if not local_corroborated:
                        f.description += (
                            " Not corroborated by the local Wordfence/CISA corpus — treat as advisory "
                            "until validated against your pinned intelligence sync."
                        )
                        f.confidence = min(float(getattr(f, "confidence", 0.7) or 0.7), 0.75)
                    # INTEL-GAP-004: derive severity from CVSS score; never unconditionally HIGH
                    best_cvss = None
                    for cve_entry in cves:
                        cvss = cve_entry.get("cvss_score")
                        if cvss is not None:
                            try:
                                best_cvss = max(best_cvss or 0.0, float(cvss))
                            except (TypeError, ValueError):
                                pass
                    derived_severity = _cvss_to_severity(best_cvss)
                    if derived_severity is not None:
                        # Only update severity if CVSS data is present and trustworthy
                        f.severity = derived_severity
                    # If no CVSS data in OSV records, preserve existing finding severity
                    f.raw_data["cve_matches"] = cves
                    f.raw_data["osv_cvss_score"] = best_cvss
                    f.reference = cves[0]["references"][0] if cves[0].get("references") else f.reference

    return findings
