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
    wp_ver_findings = [f for f in all_findings if f.raw_data.get("version")]
    if wp_ver_findings:
        scan.wp_version = wp_ver_findings[0].raw_data["version"]

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
