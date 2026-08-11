"""
Scan orchestrator - coordinates all scanners, computes risk, persists results.
Supports three scan modes: passive, safe-active, full.
"""
from datetime import datetime
from typing import Optional
from core.models import ScanResult, ScanStatus
from core import repository
from core.risk_engine import compute_risk_score
from scanners.base import BaseScanner
from scanners.wp_detector import WordPressDetector
from scanners.enumeration_scanner import EnumerationScanner
from scanners.exposure_scanner import ExposureScanner
from scanners.headers_scanner import HeadersScanner
from scanners.tls_scanner import TLSScanner
from scanners.plugin_scanner import PluginScanner
from scanners.theme_scanner import ThemeScanner
from scanners.waf_scanner import WAFScanner
from scanners.robots_scanner import RobotsScanner
from scanners.db_export_scanner import DBExportScanner
from scanners.xmlrpc_scanner import XMLRPCScanner
from scanners.bruteforce_scanner import BruteForceScanner
from scanners.rest_api_scanner import RESTAPIScanner
from scanners.cookie_scanner import CookieSecurityScanner
from scanners.whois_scanner import WhoisScanner
from scanners.security_txt_scanner import SecurityTxtScanner
from scanners.dns_scanner import DNSScanner




# ---------------------------------------------------------------------------
# Scan Profiles — maps mode name to the scanners that should run
# ---------------------------------------------------------------------------
SCAN_PROFILES = {
    "passive": [
        WordPressDetector,
        HeadersScanner,
        TLSScanner,
        ThemeScanner,
        WAFScanner,
        CookieSecurityScanner,
        WhoisScanner,
        SecurityTxtScanner,
        DNSScanner,
    ],
    "safe-active": [
        WordPressDetector,
        EnumerationScanner,
        ExposureScanner,
        HeadersScanner,
        TLSScanner,
        PluginScanner,
        ThemeScanner,
        WAFScanner,
        RobotsScanner,
        DBExportScanner,
        XMLRPCScanner,
        RESTAPIScanner,
        CookieSecurityScanner,
        WhoisScanner,
        SecurityTxtScanner,
        DNSScanner,
    ],
    "full": [
        WordPressDetector,
        EnumerationScanner,
        ExposureScanner,
        HeadersScanner,
        TLSScanner,
        PluginScanner,
        ThemeScanner,
        WAFScanner,
        RobotsScanner,
        DBExportScanner,
        XMLRPCScanner,
        RESTAPIScanner,
        CookieSecurityScanner,
        BruteForceScanner,
        WhoisScanner,
        SecurityTxtScanner,
        DNSScanner,
    ],
}

# Legacy compatibility alias
ALL_SCANNERS = SCAN_PROFILES["full"]

VALID_MODES = tuple(SCAN_PROFILES.keys())


def run_scan(
    target_url: str,
    initiated_by: str = "",
    scan_mode: str = "passive",
    scanner_classes: Optional[list] = None,
    persist: bool = True,
) -> ScanResult:
    """
    Execute a scan against target_url using the selected scan mode.
    Returns ScanResult with all findings, score, and grade.

    scan_mode: 'passive' | 'safe-active' | 'full' (default: 'passive')
    """
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    # Validate target (SSRF protection)
    is_valid, error_msg = BaseScanner.validate_target(target_url)
    if not is_valid:
        raise ValueError(f"Target blocked: {error_msg}")

    if scan_mode not in VALID_MODES:
        scan_mode = "passive"

    scan = ScanResult(
        target_url=target_url,
        status=ScanStatus.RUNNING,
        scan_mode=scan_mode,
        initiated_by=initiated_by,
    )

    if persist:
        repository.save_scan(scan)

    scanners_to_run = scanner_classes or SCAN_PROFILES.get(scan_mode, SCAN_PROFILES["passive"])
    all_findings = []

    for scanner_cls in scanners_to_run:
        try:
            scanner = scanner_cls(target_url)
            findings = scanner.scan()
            for f in findings:
                f.scan_id = scan.id
            all_findings.extend(findings)
        except Exception as e:
            # Log but don't fail the entire scan
            from core.models import Finding, Severity
            err_finding = Finding(
                scan_id=scan.id,
                category="error",
                title=f"Scanner Error: {scanner_cls.__name__}",
                description=str(e)[:500],
                severity=Severity.INFO,
                confidence=0.5,
            )
            all_findings.append(err_finding)

    # Determine WP status from findings
    wp_findings = [f for f in all_findings if f.raw_data.get("is_wordpress")]
    scan.is_wordpress = len(wp_findings) > 0
    if scan.is_wordpress:
        wp_ver_findings = [f for f in all_findings if f.raw_data.get("version")]
        if wp_ver_findings:
            scan.wp_version = wp_ver_findings[0].raw_data["version"]
        elif not scan.wp_version:
            scan.wp_version = "Unknown"
    else:
        scan.wp_version = "Not WordPress"

    whois_findings = [f for f in all_findings if f.raw_data.get("whois_info")]
    if whois_findings:
        scan.whois_info = whois_findings[0].raw_data["whois_info"]

    # Match findings against local vulnerability intelligence database
    try:
        from core.vulnerability_intelligence.service import match_scan_findings
        from core.models import Finding, Severity
        
        # Collect detected plugins from findings
        detected_plugins = []
        for f in all_findings:
            slug = f.raw_data.get("slug") or f.raw_data.get("plugin")
            version = f.raw_data.get("version")
            if slug and f.category in ("plugins",):
                detected_plugins.append({"slug": slug, "version": version})
        
        # Get existing CVEs to avoid duplicates
        existing_cves = set()
        for f in all_findings:
            if f.raw_data.get("cve_matches"):
                for m in f.raw_data["cve_matches"]:
                    if m.get("cve_id"):
                        existing_cves.add(m["cve_id"])
        
        vuln_matches = match_scan_findings(scan.wp_version, detected_plugins)
        for vm in vuln_matches:
            if vm.get("cve") and vm["cve"] in existing_cves:
                continue  # Skip duplicate CVE
            
            severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}
            cvss = vm.get("cvss_score", 0) or 0
            if cvss >= 9.0:
                sev = Severity.CRITICAL
            elif cvss >= 7.0:
                sev = Severity.HIGH
            elif cvss >= 4.0:
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW
            
            match_status = vm.get("match_status", "affected")
            if match_status == "version_unknown":
                title = f"Potential Exposure: {vm.get('cve', 'Unknown CVE')} — {vm.get('plugin_slug', 'unknown')}"
                desc = f"Potential exposure — version not detected. {vm.get('cve', '')} affects {vm.get('plugin_slug', 'unknown')} ({vm.get('affected_range', 'unknown range')})."
                sev = Severity.MEDIUM
            else:
                title = f"Vulnerability: {vm.get('cve', 'Unknown CVE')} — {vm.get('plugin_slug', 'unknown')} {vm.get('detected_version', '')}"
                desc = f"{vm.get('cve', '')} affects {vm.get('plugin_slug', 'unknown')} version {vm.get('detected_version', 'unknown')} (range: {vm.get('affected_range', 'N/A')}). Patched in: {vm.get('patched_version', 'N/A')}."
            
            kev_label = "Listed in CISA KEV" if vm.get("kev_listed") else ""
            if kev_label:
                title += f" [{kev_label}]"
            
            remediation = f"Update to patched version: {vm.get('patched_version', 'N/A')}."
            refs = vm.get("references", [])
            reference = refs[0] if refs else ""
            
            intel_finding = Finding(
                scan_id=scan.id,
                category="vulnerability_intelligence",
                title=title,
                description=desc,
                severity=sev,
                confidence=0.95 if match_status == "affected" else 0.6,
                remediation=remediation,
                reference=reference,
                raw_data=vm,
            )
            all_findings.append(intel_finding)
    except Exception:
        pass

    # Compute risk score
    score, grade = compute_risk_score(all_findings)
    scan.score = score
    scan.grade = grade
    scan.findings = all_findings
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.utcnow().isoformat()

    if persist:
        repository.save_scan(scan)
        repository.save_findings_bulk(all_findings)

    return scan
