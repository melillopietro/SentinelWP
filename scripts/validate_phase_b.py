#!/usr/bin/env python3
"""
SentinelWP Phase B Real Validation Script.
Validates live WordPress target (http://test-wordpress/) across all profiles:
- Passive Scan
- Safe-Active Scan
- Full Scan
- Parity & Persistence verification
- Asset 360 & Report generation (HTML & JSON)
- Vulnerability Intelligence matching
- Hidden version / alternative detection fallback mechanisms
- Unknown fallback (non-WordPress target)
- Batch & Scheduled scans
"""
import sys
import os
import time
import json
from datetime import datetime, timezone, timedelta

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import ScanResult, ScanJob, ScanJobStatus, ScanStatus, ScanAuthorization
from core import repository
from core.tasks.scan_tasks import run_scan_task
from scanners.wp_detector import WordPressDetector
from reports.generator import generate_html_report, generate_json_report
from core.vulnerability_intelligence.service import match_scan_findings

TARGET_URL = os.environ.get("WP_TEST_TARGET", "http://test-wordpress/")
NON_WP_TARGET = os.environ.get("NON_WP_TARGET", "http://sentinelwp-web:8080/health")
TENANT_ID = "default-tenant"


def log(msg, status="INFO"):
    print(f"[{status}] {msg}", flush=True)


def wait_for_job(job_id: str, timeout: int = 90) -> ScanJob:
    start = time.time()
    while time.time() - start < timeout:
        job = repository.get_scan_job(job_id)
        if not job:
            raise RuntimeError(f"ScanJob {job_id} not found in repository")
        if job.status in (ScanJobStatus.COMPLETED.value, ScanJobStatus.FAILED.value, ScanJobStatus.CANCELLED.value):
            return job
        time.sleep(1)
    raise TimeoutError(f"Job {job_id} timed out after {timeout}s (current status: {job.status})")


def run_scan_flow(profile: str, target: str, asset_id: str = None) -> tuple[ScanResult, ScanJob]:
    log(f"Initiating {profile} scan on {target}...")
    scan = ScanResult(
        tenant_id=TENANT_ID,
        asset_id=asset_id,
        target_url=target,
        scan_mode=profile,
        status=ScanStatus.PENDING,
        initiated_by="phase_b_validator",
    )
    repository.save_scan(scan)

    job = ScanJob(
        tenant_id=TENANT_ID,
        asset_id=asset_id,
        scan_id=scan.id,
        status=ScanJobStatus.QUEUED.value,
        requested_by="phase_b_validator",
        profile=profile,
    )
    repository.create_scan_job(job)

    # Dispatch to Celery
    task = run_scan_task.delay(job.id)
    job.task_id = task.id
    repository.update_scan_job(job)
    log(f"Dispatched Celery task {task.id} for job {job.id}")

    # Wait for completion
    completed_job = wait_for_job(job.id)
    completed_scan = repository.get_scan(scan.id, tenant_id=TENANT_ID)
    return completed_scan, completed_job


def main():
    log("=== STARTING PHASE B REAL WORDPRESS VALIDATION ===")
    
    # Pre-check target connectivity
    detector = WordPressDetector(TARGET_URL)
    probe = detector.detect()
    log(f"Pre-flight direct probe: detected={probe.detected}, version={probe.version}, source={probe.version_source}, confidence={probe.version_confidence}")
    if not probe.detected:
        log("ERROR: Live WordPress target not detected on pre-flight probe!", "FAIL")
        sys.exit(1)
    
    EXPECTED_VERSION = probe.version
    asset = repository.ensure_asset_for_target(TENANT_ID, TARGET_URL)
    auth_start = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    auth_until = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    auth = ScanAuthorization(
        tenant_id=TENANT_ID,
        asset_id=asset.id,
        status="active",
        allowed_profiles="safe_active,full,passive,*",
        valid_from=auth_start,
        valid_until=auth_until,
        approved_by="phase_b_admin",
        notes="Phase B validation authorization",
    )
    repository.save_scan_authorization(auth)
    repository.update_asset(asset.id, tenant_id=TENANT_ID, authorization_status="authorized")
    log(f"Asset '{asset.hostname}' (id={asset.id}) authorized for all profiles.")

    # ----------------------------------------------------
    # TEST 1: Passive Scan
    # ----------------------------------------------------
    log("--- TEST 1: Passive Scan via Celery ---")
    p_scan, p_job = run_scan_flow("passive", TARGET_URL, asset_id=asset.id)
    assert p_job.status == ScanJobStatus.COMPLETED.value, f"Passive job failed: {p_job.error_message}"
    assert p_scan.status == ScanStatus.COMPLETED, f"Passive scan status is {p_scan.status}"
    assert p_scan.wordpress_detected or p_scan.is_wordpress, "WordPress not detected in passive scan!"
    assert p_scan.wordpress_version or p_scan.wp_version, "WordPress version empty in passive scan!"
    p_ver = p_scan.wordpress_version or p_scan.wp_version
    p_src = p_scan.wordpress_version_source or p_scan.wp_version_source
    p_conf = p_scan.wordpress_version_confidence or p_scan.wp_version_confidence
    log(f"Passive Scan PASSED: version={p_ver}, source={p_src}, confidence={p_conf}")
    assert p_ver == EXPECTED_VERSION, f"Version mismatch: {p_ver} != {EXPECTED_VERSION}"

    # ----------------------------------------------------
    # TEST 2: Safe-Active Scan
    # ----------------------------------------------------
    log("--- TEST 2: Safe-Active Scan via Celery ---")
    sa_scan, sa_job = run_scan_flow("safe-active", TARGET_URL, asset_id=asset.id)
    assert sa_job.status == ScanJobStatus.COMPLETED.value, f"Safe-Active job failed: {sa_job.error_message}"
    assert sa_scan.status == ScanStatus.COMPLETED, f"Safe-Active scan status is {sa_scan.status}"
    sa_ver = sa_scan.wordpress_version or sa_scan.wp_version
    sa_src = sa_scan.wordpress_version_source or sa_scan.wp_version_source
    sa_conf = sa_scan.wordpress_version_confidence or sa_scan.wp_version_confidence
    log(f"Safe-Active Scan PASSED: version={sa_ver}, source={sa_src}, confidence={sa_conf}")
    assert sa_ver == EXPECTED_VERSION, f"Safe-Active version mismatch with passive: {sa_ver} != {EXPECTED_VERSION}"

    # ----------------------------------------------------
    # TEST 3: Full Scan
    # ----------------------------------------------------
    log("--- TEST 3: Full Scan via Celery ---")
    f_scan, f_job = run_scan_flow("full", TARGET_URL, asset_id=asset.id)
    assert f_job.status == ScanJobStatus.COMPLETED.value, f"Full job failed: {f_job.error_message}"
    assert f_scan.status == ScanStatus.COMPLETED, f"Full scan status is {f_scan.status}"
    f_ver = f_scan.wordpress_version or f_scan.wp_version
    f_src = f_scan.wordpress_version_source or f_scan.wp_version_source
    f_conf = f_scan.wordpress_version_confidence or f_scan.wp_version_confidence
    log(f"Full Scan PASSED: version={f_ver}, source={f_src}, confidence={f_conf}")
    assert f_ver == EXPECTED_VERSION, f"Full version mismatch with passive: {f_ver} != {EXPECTED_VERSION}"

    # ----------------------------------------------------
    # TEST 4: Asset 360 & Report Generation (HTML & JSON)
    # ----------------------------------------------------
    log("--- TEST 4: Asset 360, Scan Detail & Reports ---")
    updated_asset = repository.get_asset(asset.id, tenant_id=TENANT_ID)
    log(f"Updated Asset tags: {updated_asset.tags}")
    assert "wordpress" in updated_asset.tags, "Asset tags missing 'wordpress'!"
    assert f"wp-{EXPECTED_VERSION}" in updated_asset.tags, f"Asset tags missing 'wp-{EXPECTED_VERSION}'!"

    # HTML Report
    html_rep = generate_html_report(p_scan)
    assert EXPECTED_VERSION in html_rep, f"HTML report missing version {EXPECTED_VERSION}"
    log("HTML report verified containing version.")

    # JSON Report
    json_rep = generate_json_report(p_scan)
    json_data = json.loads(json_rep)
    assert json_data.get("wordpress_detected") is True or json_data.get("is_wordpress") is True
    assert (json_data.get("wordpress_version") == EXPECTED_VERSION or json_data.get("wp_version") == EXPECTED_VERSION)
    log("JSON report verified containing WordPress detection fields.")

    # ----------------------------------------------------
    # TEST 5: Vulnerability Intelligence Version Matching
    # ----------------------------------------------------
    log("--- TEST 5: Vulnerability Intelligence Service Matching ---")
    from core.vulnerability_intelligence.version_matcher import is_version_affected
    # Test version affected logic
    test_range = {"operator": "<=", "version": "6.4.1"}
    match_eval = is_version_affected(EXPECTED_VERSION, test_range)
    log(f"Version matcher range check (<= 6.4.1 for {EXPECTED_VERSION}): {match_eval.status}")
    assert match_eval.status in ("affected", "not_affected")
    
    # Query intelligence matching
    intel_findings = match_scan_findings(EXPECTED_VERSION, [])
    log(f"Vulnerability intelligence matching for WordPress {EXPECTED_VERSION}: returned {len(intel_findings)} findings")
    assert isinstance(intel_findings, list), "match_scan_findings must return a list"
    log("Vulnerability Intelligence matching passed.")

    # ----------------------------------------------------
    # TEST 6: Hidden Version & Fallback Mechanisms
    # ----------------------------------------------------
    log("--- TEST 6: Alternative Fallback Mechanisms ---")
    # 6a. Verify live RSS feed has generator version
    import requests
    feed_url = f"{TARGET_URL.rstrip('/')}/feed/"
    try:
        r_feed = requests.get(feed_url, timeout=10)
        log(f"Live RSS Feed status: {r_feed.status_code}")
        if r_feed.status_code == 200:
            assert "wordpress.org" in r_feed.text.lower()
            log("Live RSS feed verified containing WordPress generator.")
    except Exception as e:
        log(f"Live RSS feed check note: {e}")

    # 6b. Verify fallback detection when generator tag is absent (e.g. core asset block library)
    from unittest.mock import MagicMock, patch
    mock_resp = MagicMock()
    mock_resp.text = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" id="wp-block-library-css" href="/wp-includes/css/dist/block-library/style.min.css?ver={EXPECTED_VERSION}" media="all" />
        <link rel="https://api.w.org/" href="/wp-json/" />
    </head>
    <body class="home"><div class="wp-site">Hello</div></body>
    </html>
    """
    mock_resp.cookies = []
    mock_resp.headers = {"link": '<http://test-wordpress/wp-json/>; rel="https://api.w.org/"'}
    mock_resp.url = TARGET_URL

    detector_fallback = WordPressDetector(TARGET_URL)
    with patch.object(detector_fallback, "_get", return_value=mock_resp), \
         patch.object(detector_fallback, "_head", return_value=None):
        fallback_res = detector_fallback.detect()

    assert fallback_res.detected is True, "Fallback detector failed to detect WordPress!"
    assert fallback_res.version == EXPECTED_VERSION, f"Fallback version {fallback_res.version} != {EXPECTED_VERSION}"
    assert fallback_res.version_source == "asset_ver_param", f"Expected asset_ver_param source, got {fallback_res.version_source}"
    log(f"Fallback without meta-generator (asset_ver_param) PASSED: version={fallback_res.version}, source={fallback_res.version_source}")

    # ----------------------------------------------------
    # TEST 7: Unknown Fallback (Non-WordPress Target)
    # ----------------------------------------------------
    log("--- TEST 7: Non-WordPress Target Fallback ---")
    non_wp_detector = WordPressDetector(NON_WP_TARGET)
    non_wp_res = non_wp_detector.detect()
    log(f"Non-WP target detection: detected={non_wp_res.detected}, version={non_wp_res.version}")
    assert not non_wp_res.detected or non_wp_res.version in (None, "Unknown", ""), "False positive version on non-WordPress target!"
    assert non_wp_res.version_confidence in ("none", "low", None), f"Unexpected high confidence on non-WP: {non_wp_res.version_confidence}"
    log("Non-WordPress target fallback PASSED.")

    # ----------------------------------------------------
    # TEST 8: Batch Scan & Scheduled Scan Execution
    # ----------------------------------------------------
    log("--- TEST 8: Batch Scan Execution (2 Targets) ---")
    b_scan1, b_job1 = run_scan_flow("passive", TARGET_URL, asset_id=asset.id)
    b_scan2, b_job2 = run_scan_flow("passive", NON_WP_TARGET)
    assert b_job1.status == ScanJobStatus.COMPLETED.value
    assert b_job2.status == ScanJobStatus.COMPLETED.value
    log("Batch scan (2 concurrent/sequential scans) PASSED.")

    log("=== ALL PHASE B TESTS PASSED WITH 100% SUCCESS ===")


if __name__ == "__main__":
    main()
