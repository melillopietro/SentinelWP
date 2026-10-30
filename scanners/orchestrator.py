"""
Scan orchestrator - coordinates all scanners, computes risk, persists results.
Supports three scan modes: passive, safe-active, full.
"""
from datetime import datetime, timezone
from typing import Optional
from core.models import ScanResult, ScanStatus
from core import repository
from core.risk_engine import compute_risk_score
from scanners.base import BaseScanner
from scanners.wp_detector import WordPressDetector
from scanners.core_security_scanner import CoreSecurityScanner
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
from scanners.php_artifact_scanner import PhpArtifactScanner




# ---------------------------------------------------------------------------
# Scan Profiles — maps mode name to the scanners that should run
# ---------------------------------------------------------------------------
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
        PhpArtifactScanner,
    ],
    # 'full' profile is maintained for backward compatibility as an extended safe profile;
    # BruteForceScanner has been removed to enforce Enterprise Credential Safety.
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
        WhoisScanner,
        SecurityTxtScanner,
        DNSScanner,
        PhpArtifactScanner,
    ],
}

# Legacy compatibility alias
ALL_SCANNERS = SCAN_PROFILES["full"]

VALID_MODES = tuple(SCAN_PROFILES.keys())


class ScanOrchestrator:
    """Class wrapper around run_scan for Celery task workers."""
    def __init__(
        self,
        target_url: str,
        scan_mode: str = "passive",
        tenant_id: str = "default-tenant",
        asset_id: Optional[str] = None,
    ):
        self.target_url = target_url
        self.scan_mode = scan_mode
        self.tenant_id = tenant_id
        self.asset_id = asset_id

    def run(self) -> ScanResult:
        return run_scan(
            self.target_url,
            scan_mode=self.scan_mode,
            tenant_id=self.tenant_id,
            asset_id=self.asset_id,
            persist=False,
        )


import logging as _logging
_orch_logger = _logging.getLogger("sentinelwp.orchestrator")


def run_scan(
    target_url: str,
    initiated_by: str = "",
    scan_mode: str = "passive",
    scanner_classes: Optional[list] = None,
    persist: bool = True,
    tenant_id: str = "default-tenant",
    asset_id: Optional[str] = None,
) -> ScanResult:
    """
    Execute a scan against target_url using the selected scan mode.
    Returns ScanResult with all findings, score, and grade.

    scan_mode: 'passive' | 'safe-active' | 'full' (default: 'passive')

    NOTE (FUNC-001): 'full' is an alias for 'safe-active'. Destructive probing
    (brute-force) is permanently excluded from all automated profiles.
    """
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    # FUNC-001: Warn callers that 'full' is treated identically to 'safe-active'.
    if scan_mode == "full":
        _orch_logger.warning(
            "Scan mode 'full' is deprecated and treated as 'safe-active'. "
            "BruteForceScanner is excluded from all automated profiles. "
            "No additional probing beyond safe-active will be performed."
        )

    # Validate target (SSRF protection)
    is_valid, error_msg = BaseScanner.validate_target(target_url)
    if not is_valid:
        raise ValueError(f"Target blocked: {error_msg}")

    if scan_mode not in VALID_MODES:
        scan_mode = "passive"

    # Link to asset if not explicitly passed
    if not asset_id and persist:
        try:
            asset = repository.ensure_asset_for_target(tenant_id, target_url)
            asset_id = asset.id
        except Exception:
            asset_id = None

    scan = ScanResult(
        target_url=target_url,
        status=ScanStatus.RUNNING,
        scan_mode=scan_mode,
        initiated_by=initiated_by,
        tenant_id=tenant_id or "default-tenant",
        asset_id=asset_id,
    )

    if persist:
        repository.save_scan(scan)

    scanners_to_run = scanner_classes or SCAN_PROFILES.get(scan_mode, SCAN_PROFILES["passive"])
    all_findings = []

    for scanner_cls in scanners_to_run:
        try:
            scanner = scanner_cls(target_url)
            # DETECT-GAP-003 / DETECT-GAP-004: enable active probing only for
            # safe-active and full modes, not for passive scans.
            if scan_mode in ("safe-active", "full") and hasattr(scanner, "ENABLE_ACTIVE_PROBE"):
                scanner.ENABLE_ACTIVE_PROBE = True
            # Sprint 3 PHASE 7: enable subdirectory probing only for safe-active+.
            # Passive scans must not issue extra probes beyond the root GET.
            if scan_mode in ("safe-active", "full") and hasattr(scanner, "ENABLE_SUBDIR_PROBE"):
                scanner.ENABLE_SUBDIR_PROBE = True
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

    # Determine WP status and core version exclusively from WordPressDetector finding
    wp_detector_findings = [
        f for f in all_findings
        if f.title == "WordPress CMS Detected" or (f.raw_data.get("is_wordpress") is True and f.raw_data.get("wp_confidence") is not None)
    ]
    if wp_detector_findings:
        wp_f = wp_detector_findings[0]
        scan.wordpress_detected = True
        scan.is_wordpress = True
        ver_val = wp_f.raw_data.get("version")
        if ver_val and str(ver_val).strip() and str(ver_val).strip().lower() not in ("none", "null", "unknown"):
            v_str = str(ver_val).strip()
            v_src = wp_f.raw_data.get("version_source")
            v_conf = wp_f.raw_data.get("version_confidence")
            scan.wordpress_version = v_str
            scan.wordpress_version_source = v_src
            scan.wordpress_version_confidence = v_conf
            scan.wp_version = v_str
            scan.wp_version_source = v_src
            scan.wp_version_confidence = v_conf
        else:
            scan.wordpress_version = "Unknown"
            scan.wordpress_version_source = None
            scan.wordpress_version_confidence = None
            scan.wp_version = "Unknown"
            scan.wp_version_source = None
            scan.wp_version_confidence = None
    else:
        # Check if any finding explicitly identified WordPress
        any_wp = [f for f in all_findings if f.raw_data.get("is_wordpress") is True]
        if any_wp:
            scan.wordpress_detected = True
            scan.is_wordpress = True
            scan.wordpress_version = "Unknown"
            scan.wordpress_version_source = None
            scan.wordpress_version_confidence = None
            scan.wp_version = "Unknown"
            scan.wp_version_source = None
            scan.wp_version_confidence = None
        else:
            scan.wordpress_detected = False
            scan.is_wordpress = False
            scan.wordpress_version = "Not WordPress"
            scan.wordpress_version_source = None
            scan.wordpress_version_confidence = None
            scan.wp_version = "Not WordPress"
            scan.wp_version_source = None
            scan.wp_version_confidence = None

    whois_findings = [f for f in all_findings if f.raw_data.get("whois_info")]
    if whois_findings:
        scan.whois_info = whois_findings[0].raw_data["whois_info"]

    from core.scan_pipeline import finalize_scan_findings

    all_findings = finalize_scan_findings(all_findings, scan)
    score, grade = compute_risk_score(all_findings)
    scan.score = score
    scan.grade = grade
    scan.findings = all_findings
    for f in scan.findings:
        f.tenant_id = scan.tenant_id
        f.asset_id = scan.asset_id

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc).isoformat()

    if persist:
        repository.save_scan(scan)
        repository.save_findings_bulk(all_findings)

    return scan
