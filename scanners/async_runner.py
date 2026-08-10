"""
Async Scan Runner with ThreadPoolExecutor and Live Progress tracking.
"""
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Any, Optional
from core.models import ScanResult, ScanStatus
from core import repository
from core.risk_engine import compute_risk_score
from scanners.base import BaseScanner
from scanners.orchestrator import SCAN_PROFILES

# Thread pool for asynchronous background scans (max 5 concurrent scans)
_executor = ThreadPoolExecutor(max_workers=5)

# In-memory progress tracking: scan_id -> dict(progress, current_step, total_steps, status)
_scan_progress: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def get_scan_progress(scan_id: str) -> Dict[str, Any]:
    """Retrieve current progress state for a scan."""
    with _lock:
        if scan_id in _scan_progress:
            return dict(_scan_progress[scan_id])
    
    # Fallback to DB check
    scan = repository.get_scan(scan_id)
    if scan:
        status_val = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        is_done = status_val in ("completed", "failed")
        return {
            "scan_id": scan_id,
            "status": status_val,
            "progress": 100 if is_done else 0,
            "current_step": "Complete" if is_done else "Pending",
            "total_steps": 1,
            "current_step_num": 1 if is_done else 0,
        }
    return {"scan_id": scan_id, "status": "unknown", "progress": 0, "current_step": "Not found"}


def _update_progress(scan_id: str, current_step: str, step_num: int, total_steps: int, status: str = "running"):
    """Update progress tracking dictionary."""
    progress_pct = int((step_num / max(1, total_steps)) * 100)
    with _lock:
        _scan_progress[scan_id] = {
            "scan_id": scan_id,
            "status": status,
            "progress": min(100, progress_pct),
            "current_step": current_step,
            "step_num": step_num,
            "total_steps": total_steps,
        }


def _execute_async_scan(scan_id: str, target_url: str, initiated_by: str, scan_mode: str):
    """Background task function executed by ThreadPoolExecutor."""
    scanners = SCAN_PROFILES.get(scan_mode, SCAN_PROFILES["passive"])
    total_steps = len(scanners)
    all_findings = []

    _update_progress(scan_id, "Initializing scan", 0, total_steps, status="running")

    for idx, scanner_cls in enumerate(scanners, 1):
        step_name = scanner_cls.__name__
        _update_progress(scan_id, f"Running {step_name}", idx, total_steps, status="running")
        try:
            scanner = scanner_cls(target_url)
            findings = scanner.scan()
            for f in findings:
                f.scan_id = scan_id
            all_findings.extend(findings)
        except Exception as e:
            from core.models import Finding, Severity
            err_finding = Finding(
                scan_id=scan_id,
                category="error",
                title=f"Scanner Error: {step_name}",
                description=str(e)[:500],
                severity=Severity.INFO,
                confidence=0.5,
            )
            all_findings.append(err_finding)

    # Enrich findings with Live Vulnerability Intelligence if available
    try:
        from scanners.vuln_intel import enrich_findings_with_cves
        all_findings = enrich_findings_with_cves(all_findings)
    except Exception:
        pass

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
        
        # Determine WP version
        wp_ver_f = [f for f in all_findings if f.raw_data.get("version")]
        wp_ver = wp_ver_f[0].raw_data["version"] if wp_ver_f else None
        
        vuln_matches = match_scan_findings(wp_ver, detected_plugins)
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
                scan_id=scan_id,
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


    # Complete scan
    score, grade = compute_risk_score(all_findings)
    wp_findings = [f for f in all_findings if f.raw_data.get("is_wordpress")]
    is_wp = len(wp_findings) > 0
    wp_ver_findings = [f for f in all_findings if f.raw_data.get("version")]
    wp_ver = wp_ver_findings[0].raw_data["version"] if wp_ver_findings else None
    whois_findings = [f for f in all_findings if f.raw_data.get("whois_info")]
    whois_info = whois_findings[0].raw_data["whois_info"] if whois_findings else None

    # Load scan record and update
    scan = repository.get_scan(scan_id)
    if scan:
        scan.status = ScanStatus.COMPLETED
        scan.score = score
        scan.grade = grade
        scan.is_wordpress = is_wp
        scan.wp_version = wp_ver
        scan.whois_info = whois_info
        scan.completed_at = datetime.utcnow().isoformat()
        scan.findings = all_findings
        repository.save_scan(scan)
        repository.save_findings_bulk(all_findings)

        # Trigger Notifications (Email / Webhook)
        try:
            from core.notifications import dispatch_scan_notifications
            dispatch_scan_notifications(scan)
        except Exception:
            pass

    _update_progress(scan_id, "Completed", total_steps, total_steps, status="completed")


def start_async_scan(target_url: str, initiated_by: str = "", scan_mode: str = "passive") -> ScanResult:
    """
    Create a new scan record in DB and queue it for async background execution.
    Returns ScanResult immediately (in PENDING/RUNNING state).
    """
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    is_valid, error_msg = BaseScanner.validate_target(target_url)
    if not is_valid:
        raise ValueError(f"Target blocked: {error_msg}")

    if scan_mode not in SCAN_PROFILES:
        scan_mode = "passive"

    scan = ScanResult(
        target_url=target_url,
        status=ScanStatus.RUNNING,
        scan_mode=scan_mode,
        initiated_by=initiated_by,
    )
    repository.save_scan(scan)

    # Initialize progress state
    _update_progress(scan.id, "Queued", 0, len(SCAN_PROFILES[scan_mode]), status="running")

    # Dispatch to background thread pool
    _executor.submit(_execute_async_scan, scan.id, target_url, initiated_by, scan_mode)

    return scan
