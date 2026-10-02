"""
Scan orchestrator - coordinates all scanners, computes risk, persists results.
Supports three scan modes: passive, safe-active, full.
"""
from typing import Optional

from core import repository
from core.models import Finding, ScanResult, ScanStatus, Severity
from core.scan_pipeline import finalize_and_score_scan, mark_scan_completed
from scanners.base import BaseScanner
from scanners.bruteforce_scanner import BruteForceScanner
from scanners.cookie_scanner import CookieSecurityScanner
from scanners.core_security_scanner import CoreSecurityScanner
from scanners.db_export_scanner import DBExportScanner
from scanners.dns_scanner import DNSScanner
from scanners.enumeration_scanner import EnumerationScanner
from scanners.exposure_scanner import ExposureScanner
from scanners.headers_scanner import HeadersScanner
from scanners.plugin_scanner import PluginScanner
from scanners.rest_api_scanner import RESTAPIScanner
from scanners.robots_scanner import RobotsScanner
from scanners.security_txt_scanner import SecurityTxtScanner
from scanners.theme_scanner import ThemeScanner
from scanners.tls_scanner import TLSScanner
from scanners.waf_scanner import WAFScanner
from scanners.whois_scanner import WhoisScanner
from scanners.wp_detector import WordPressDetector
from scanners.xmlrpc_scanner import XMLRPCScanner

SCAN_PROFILES = {
    "passive": [
        WordPressDetector,
        CoreSecurityScanner,
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
        CoreSecurityScanner,
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
        CoreSecurityScanner,
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
    """
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

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
            err_finding = Finding(
                scan_id=scan.id,
                category="error",
                title=f"Scanner Error: {scanner_cls.__name__}",
                description=str(e)[:500],
                severity=Severity.INFO,
                confidence=0.5,
            )
            all_findings.append(err_finding)

    all_findings = finalize_and_score_scan(all_findings, scan)
    mark_scan_completed(scan)

    if persist:
        repository.save_scan(scan)
        repository.save_findings_bulk(all_findings)

    return scan
