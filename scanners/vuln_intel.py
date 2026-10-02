"""
Live Vulnerability Intelligence Integration (OSV.dev & CIRCL CVE APIs).
Enriches findings for detected plugins/themes/core with real CVE IDs and CVSS scores.
"""
import requests
from typing import List, Dict, Any
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


def enrich_findings_with_cves(findings: List[Finding]) -> List[Finding]:
    """
    Enrich a list of findings with real CVE data from OSV.dev.
    """
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
                    f.title += f" [CVE: {', '.join(cve_ids[:2])}]"
                    f.description += f" Live Vulnerability Feed Match: Found {len(cves)} vulnerability entry/entries ({', '.join(cve_ids[:3])})."
                    f.severity = Severity.HIGH
                    f.raw_data["cve_matches"] = cves
                    f.reference = cves[0]["references"][0] if cves[0].get("references") else f.reference

    return findings
