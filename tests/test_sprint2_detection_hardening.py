"""
Sprint 2 — Detection Hardening Regression Tests
================================================
Covers:
  DETECT-GAP-003  ThemeScanner passive-mode gate (ENABLE_ACTIVE_PROBE)
  DETECT-GAP-003  Orchestrator sets ENABLE_ACTIVE_PROBE for safe-active / full modes
  SCAN-GAP-001    PluginScanner soft-404 suppression
  DETECT-GAP-001  WordPressDetector subdirectory fallback
  INTEL-GAP-003   Concurrent sync_all / individual sync functions return 'skipped'
  INTEL-GAP-004   CVSS-based severity normalisation (_cvss_to_severity)
  INTEL-GAP-001   _enrich_with_nvd_inner runs inside sync_all and is failure-isolated
  SCAN-GAP-004    _check_protocols uses ssl.TLSVersion, not deprecated PROTOCOL_* constants
  EVI-GAP-002     ThemeScanner adds version_confidence to raw_data
"""
import ssl
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest
import requests

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_response(status_code=200, text="", headers=None, content_type="text/html"):
    """Build a minimal requests.Response-like mock."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"Content-Type": content_type}
    if headers:
        resp.headers.update(headers)
    return resp


# ===========================================================================
# DETECT-GAP-003 — ThemeScanner: passive mode does NOT call _head()
# ===========================================================================

class TestThemeScannerPassiveGate:
    """
    ThemeScanner.ENABLE_ACTIVE_PROBE defaults to False.
    _probe_default_themes() must NOT be called in passive mode.
    """

    def test_passive_mode_no_active_probe_called(self):
        """In passive mode (ENABLE_ACTIVE_PROBE=False) _probe_default_themes is skipped."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        assert scanner.ENABLE_ACTIVE_PROBE is False

        with patch.object(scanner, "_get", return_value=_make_response(200, "")), \
             patch.object(scanner, "_head") as mock_head, \
             patch.object(scanner, "_probe_default_themes") as mock_probe:
            scanner.scan()
            mock_probe.assert_not_called()

    def test_passive_mode_head_not_called_for_default_themes(self):
        """No _head() requests should be made for default theme paths in passive mode."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        assert scanner.ENABLE_ACTIVE_PROBE is False

        with patch.object(scanner, "_get", return_value=_make_response(200, "")), \
             patch.object(scanner, "_head") as mock_head:
            scanner.scan()
            # The only _head calls that could happen are from _probe_default_themes
            mock_head.assert_not_called()

    def test_active_mode_probes_default_themes(self):
        """When ENABLE_ACTIVE_PROBE=True, _probe_default_themes() IS called."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True

        with patch.object(scanner, "_get", return_value=_make_response(200, "")), \
             patch.object(scanner, "_probe_default_themes") as mock_probe:
            scanner.scan()
            mock_probe.assert_called_once()

    def test_active_mode_head_called_for_each_default_theme(self):
        """HEAD requests are made for every default theme when active probing is on."""
        from scanners.theme_scanner import ThemeScanner, DEFAULT_THEMES

        scanner = ThemeScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True

        head_404 = _make_response(404)
        with patch.object(scanner, "_get", return_value=_make_response(200, "")), \
             patch.object(scanner, "_head", return_value=head_404) as mock_head:
            scanner.scan()
            # One HEAD per default theme
            assert mock_head.call_count == len(DEFAULT_THEMES)

    def test_active_probe_finding_emitted_when_theme_exists(self):
        """A finding is emitted when a default theme returns HTTP 200 in active mode.

        Sprint 3 DETECT-OPEN-003: one finding per confirmed theme, not aggregated.
        """
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True

        def _head_side_effect(url):
            if "twentytwentyfour" in url:
                return _make_response(200)
            return _make_response(404)

        with patch.object(scanner, "_get", return_value=_make_response(200, "")), \
             patch.object(scanner, "_head", side_effect=_head_side_effect):
            findings = scanner.scan()

        # Sprint 3: per-theme finding title is "Default Theme Present: <slug>"
        default_theme_findings = [
            f for f in findings if "Default Theme Present" in f.title
        ]
        assert len(default_theme_findings) == 1
        assert default_theme_findings[0].raw_data["slug"] == "twentytwentyfour"


# ===========================================================================
# DETECT-GAP-003 — Orchestrator sets ENABLE_ACTIVE_PROBE per scanner instance
# ===========================================================================

class TestOrchestratorActiveProbeGate:
    """
    run_scan() must set scanner.ENABLE_ACTIVE_PROBE = True for safe-active and full
    modes, and must NOT set it for passive mode.
    """

    def _run_scan_and_collect_scanner_instances(self, scan_mode):
        """Run scan with all HTTP mocked; return list of scanner instances created."""
        from scanners.orchestrator import run_scan, SCAN_PROFILES
        from scanners.theme_scanner import ThemeScanner
        from scanners.plugin_scanner import PluginScanner

        instances_seen = []

        original_init = ThemeScanner.__init__

        def _capture_theme(self_inner, *args, **kwargs):
            original_init(self_inner, *args, **kwargs)
            instances_seen.append(self_inner)

        # We only need to inspect ThemeScanner (has ENABLE_ACTIVE_PROBE)
        with patch.object(ThemeScanner, "__init__", _capture_theme), \
             patch("scanners.base.BaseScanner._get", return_value=_make_response(200, "")), \
             patch("scanners.base.BaseScanner._head", return_value=_make_response(404)), \
             patch("scanners.orchestrator.repository"), \
             patch("scanners.base.BaseScanner.validate_target", return_value=(True, "")):
            try:
                run_scan("https://example.com", scan_mode=scan_mode, persist=False)
            except Exception:
                pass  # Scan errors are irrelevant; we inspect scanner state

        return instances_seen

    def test_passive_mode_does_not_enable_active_probe(self):
        """passive mode: ThemeScanner.ENABLE_ACTIVE_PROBE remains False."""
        from scanners.orchestrator import run_scan, SCAN_PROFILES
        from scanners.theme_scanner import ThemeScanner

        captured = []

        original_scan = ThemeScanner.scan

        def _spy_scan(self_inner):
            captured.append(self_inner.ENABLE_ACTIVE_PROBE)
            # Mock the underlying HTTP calls
            with patch.object(self_inner, "_get", return_value=_make_response(200, "")):
                return original_scan(self_inner)

        with patch.object(ThemeScanner, "scan", _spy_scan), \
             patch("scanners.base.BaseScanner.validate_target", return_value=(True, "")), \
             patch("scanners.orchestrator.repository"), \
             patch("scanners.base.BaseScanner._get", return_value=_make_response(200, "")), \
             patch("scanners.base.BaseScanner._head", return_value=_make_response(404)):
            run_scan("https://example.com", scan_mode="passive", persist=False)

        assert captured, "ThemeScanner.scan() was never called"
        assert captured[0] is False, "ENABLE_ACTIVE_PROBE must remain False in passive mode"

    def test_safe_active_mode_enables_active_probe(self):
        """safe-active mode: ThemeScanner.ENABLE_ACTIVE_PROBE is set to True."""
        from scanners.orchestrator import run_scan
        from scanners.theme_scanner import ThemeScanner

        captured = []

        original_scan = ThemeScanner.scan

        def _spy_scan(self_inner):
            captured.append(self_inner.ENABLE_ACTIVE_PROBE)
            with patch.object(self_inner, "_get", return_value=_make_response(200, "")), \
                 patch.object(self_inner, "_head", return_value=_make_response(404)):
                return original_scan(self_inner)

        with patch.object(ThemeScanner, "scan", _spy_scan), \
             patch("scanners.base.BaseScanner.validate_target", return_value=(True, "")), \
             patch("scanners.orchestrator.repository"), \
             patch("scanners.base.BaseScanner._get", return_value=_make_response(200, "")), \
             patch("scanners.base.BaseScanner._head", return_value=_make_response(404)):
            run_scan("https://example.com", scan_mode="safe-active", persist=False)

        assert captured, "ThemeScanner.scan() was never called"
        assert captured[0] is True, "ENABLE_ACTIVE_PROBE must be True in safe-active mode"


# ===========================================================================
# SCAN-GAP-001 — PluginScanner soft-404 suppression
# ===========================================================================

class TestPluginScannerSoft404:
    """
    _active_enumerate() must call is_soft_404() on first HTTP-200 hit and
    suppress all subsequent 200 responses when the site is a soft-404 host.
    HTTP 403 bypasses the soft-404 check and is always accepted.
    """

    def _make_scanner(self):
        from scanners.plugin_scanner import PluginScanner
        scanner = PluginScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True
        return scanner

    def test_soft404_site_suppresses_200_responses(self):
        """When is_soft_404 returns True, 200 responses are discarded."""
        scanner = self._make_scanner()

        with patch.object(scanner, "_head", return_value=_make_response(200)), \
             patch.object(scanner, "is_soft_404", return_value=True) as mock_s404, \
             patch.object(scanner, "_get_plugin_version_from_readme", return_value=None):
            scanner._active_enumerate()

        # is_soft_404 should have been called exactly once (first hit, then cached)
        mock_s404.assert_called_once()
        # No findings should have been emitted
        plugin_findings = [f for f in scanner.findings if "Plugin Detected" in f.title]
        assert len(plugin_findings) == 0

    def test_genuine_content_200_accepted(self):
        """When is_soft_404 returns False, HTTP 200 is accepted as a real finding."""
        scanner = self._make_scanner()

        # Only return 200 for a specific known plugin, 404 for everything else
        target_plugin = "akismet"
        url_200 = f"https://example.com/wp-content/plugins/{target_plugin}/"

        def _head_side(url):
            return _make_response(200) if url == url_200 else _make_response(404)

        with patch.object(scanner, "_head", side_effect=_head_side), \
             patch.object(scanner, "is_soft_404", return_value=False), \
             patch.object(scanner, "_get_plugin_version_from_readme", return_value=None):
            scanner._active_enumerate()

        plugin_findings = [f for f in scanner.findings if f.title == f"Plugin Detected: {target_plugin}"]
        assert len(plugin_findings) == 1

    def test_http_403_bypasses_soft404_check(self):
        """HTTP 403 is accepted without calling is_soft_404."""
        scanner = self._make_scanner()

        target_plugin = "wordfence"
        url_403 = f"https://example.com/wp-content/plugins/{target_plugin}/"

        def _head_side(url):
            return _make_response(403) if url == url_403 else _make_response(404)

        with patch.object(scanner, "_head", side_effect=_head_side), \
             patch.object(scanner, "is_soft_404") as mock_s404, \
             patch.object(scanner, "_get_plugin_version_from_readme", return_value=None):
            scanner._active_enumerate()

        mock_s404.assert_not_called()
        plugin_findings = [f for f in scanner.findings if f.title == f"Plugin Detected: {target_plugin}"]
        assert len(plugin_findings) == 1

    def test_is_soft404_called_only_once(self):
        """is_soft_404 is called once per _active_enumerate() invocation, not per URL."""
        scanner = self._make_scanner()

        with patch.object(scanner, "_head", return_value=_make_response(200)), \
             patch.object(scanner, "is_soft_404", return_value=False) as mock_s404, \
             patch.object(scanner, "_get_plugin_version_from_readme", return_value=None):
            scanner._active_enumerate()

        assert mock_s404.call_count == 1


# ===========================================================================
# SCAN-GAP-001 — BaseScanner.is_soft_404 behaviour
# ===========================================================================

class TestIsSoft404:
    """Unit tests for BaseScanner.is_soft_404()."""

    def _make_scanner(self):
        from scanners.base import BaseScanner
        # Concrete stub
        class _ConcreteScanner(BaseScanner):
            def scan(self):
                return []
        return _ConcreteScanner("https://example.com")

    def test_returns_false_when_probe_returns_nonhtml(self):
        """Non-HTML content-type → real content, not a soft-404."""
        scanner = self._make_scanner()
        css_resp = _make_response(200, "body { color: red; }", content_type="text/css")
        with patch.object(scanner, "_get", return_value=css_resp):
            assert scanner.is_soft_404("https://example.com/wp-content/themes/x/style.css") is False

    def test_returns_false_when_sentinel_returns_real_404(self):
        """Sentinel returns 404 → site does NOT use soft-404 → return False."""
        scanner = self._make_scanner()

        probe_resp = _make_response(200, "<html>Plugin page here</html>")
        sentinel_resp = _make_response(404, "")

        def _get_side(url):
            if "sentinelwp-does-not-exist" in url:
                return sentinel_resp
            return probe_resp

        with patch.object(scanner, "_get", side_effect=_get_side):
            result = scanner.is_soft_404("https://example.com/wp-content/plugins/real-plugin/")
        assert result is False

    def test_returns_true_when_bodies_are_identical(self):
        """Same body length as sentinel → soft-404."""
        scanner = self._make_scanner()
        body = "<html>" + ("x" * 500) + "</html>"
        same_resp = _make_response(200, body)

        with patch.object(scanner, "_get", return_value=same_resp):
            result = scanner.is_soft_404("https://example.com/wp-content/plugins/nonexistent/")
        assert result is True

    def test_returns_false_when_probe_returns_non_200(self):
        """Non-200 probe status → is_soft_404 returns False (already handled upstream)."""
        scanner = self._make_scanner()
        with patch.object(scanner, "_get", return_value=_make_response(404)):
            assert scanner.is_soft_404("https://example.com/wp-content/plugins/x/") is False


# ===========================================================================
# DETECT-GAP-001 — WordPressDetector subdirectory fallback
# ===========================================================================

class TestWordPressDetectorSubdirectory:
    """
    If root probe returns confidence < 0.15, detect() tries subdirectory candidates.
    """

    def _make_detector(self, url="https://example.com"):
        from scanners.wp_detector import WordPressDetector
        return WordPressDetector(url)

    def test_subdir_detection_used_when_root_misses(self):
        """Root returns no WP signals; /blog subdir returns wp-login signal.

        Sprint 3 PHASE 7: ENABLE_SUBDIR_PROBE must be True for subdir probing to occur
        (gated to safe-active+ by the orchestrator; set manually in test for safe-active).
        """
        from scanners.wp_detector import WordPressDetector

        detector = self._make_detector()
        # Sprint 3: subdir probing is gated; set flag as orchestrator would for safe-active
        detector.ENABLE_SUBDIR_PROBE = True

        root_result = {
            "confidence": 0.0,
            "evidence": [],
            "version": {"value": None, "source": None, "confidence": None},
            "base_url": "https://example.com",
        }
        blog_result = {
            "confidence": 0.6,
            "evidence": ["wp-login.php found"],
            "version": {"value": "6.4.2", "source": "meta generator", "confidence": "high"},
            "base_url": "https://example.com/blog",
        }

        call_count = {"n": 0}

        def _multi_signal(override_url=None):
            call_count["n"] += 1
            if override_url and "/blog" in override_url:
                return blog_result
            return root_result

        with patch.object(detector, "_detect_multi_signal", side_effect=_multi_signal):
            result = detector.detect()

        assert result.detected is True
        assert result.version == "6.4.2"
        assert result.confidence_score >= 0.15
        assert any("Detected in subdirectory" in e for e in result.evidence)

    def test_root_detection_wins_if_confident_enough(self):
        """Root confidence ≥ 0.15 → subdirectory probe is never attempted."""
        detector = self._make_detector()

        root_result = {
            "confidence": 0.5,
            "evidence": ["meta generator"],
            "version": {"value": "6.3", "source": "meta", "confidence": "high"},
            "base_url": "https://example.com",
        }

        with patch.object(detector, "_detect_multi_signal", return_value=root_result) as mock_ms:
            result = detector.detect()

        # Only called once (for the root)
        assert mock_ms.call_count == 1
        assert result.detected is True

    def test_no_detection_if_all_subdirs_miss(self):
        """All probes return confidence < 0.15 → not detected."""
        detector = self._make_detector()

        miss_result = {
            "confidence": 0.0,
            "evidence": [],
            "version": {"value": None, "source": None, "confidence": None},
            "base_url": "https://example.com",
        }

        with patch.object(detector, "_detect_multi_signal", return_value=miss_result):
            result = detector.detect()

        assert result.detected is False
        assert result.confidence_score < 0.15


# ===========================================================================
# INTEL-GAP-003 — Concurrent sync_all / per-function skipped returns
# ===========================================================================

class TestVulnIntelConcurrencyGate:
    """
    A second concurrent call to sync_all (or individual sync functions) while
    one is already running must return {'status': 'skipped'}.
    """

    @pytest.fixture(autouse=True)
    def reset_lock(self):
        from core.vulnerability_intelligence import service
        r = service._get_redis_client()
        if r is not None:
            try:
                r.delete(service._REDIS_LOCK_NAME)
            except Exception:
                pass
        if service._sync_lock.locked():
            try:
                service._sync_lock.release()
            except RuntimeError:
                pass
        yield
        if r is not None:
            try:
                r.delete(service._REDIS_LOCK_NAME)
            except Exception:
                pass
        if service._sync_lock.locked():
            try:
                service._sync_lock.release()
            except RuntimeError:
                pass

    def test_sync_all_skipped_when_lock_held(self):
        from core.vulnerability_intelligence import service

        mock_lock = MagicMock()
        mock_lock.acquire.return_value = False
        mock_lock.locked.return_value = True

        with patch.object(service, '_sync_lock', mock_lock), \
             patch.object(service, 'VULN_INTEL_ENABLED', True):
            result = service.sync_all()

        assert result['status'] == 'skipped'
        assert result['reason'] == 'Sync in progress'

    def test_sync_wordfence_skipped_when_lock_held(self):
        from core.vulnerability_intelligence import service

        mock_lock = MagicMock()
        mock_lock.acquire.return_value = False
        mock_lock.locked.return_value = True

        with patch.object(service, '_sync_lock', mock_lock):
            result = service.sync_wordfence()

        assert result['status'] == 'skipped'

    def test_sync_kev_skipped_when_lock_held(self):
        from core.vulnerability_intelligence import service

        mock_lock = MagicMock()
        mock_lock.acquire.return_value = False
        mock_lock.locked.return_value = True

        with patch.object(service, '_sync_lock', mock_lock):
            result = service.sync_kev()

        assert result['status'] == 'skipped'

    def test_sync_plugin_metadata_skipped_when_lock_held(self):
        from core.vulnerability_intelligence import service

        mock_lock = MagicMock()
        mock_lock.acquire.return_value = False
        mock_lock.locked.return_value = True

        with patch.object(service, '_sync_lock', mock_lock):
            result = service.sync_plugin_metadata(['test-plugin'])

        assert result['status'] == 'skipped'

    def test_concurrent_sync_all_second_call_skips(self):
        """Simulate genuine thread race: first call holds lock, second returns skipped."""
        from core.vulnerability_intelligence import service

        results = {}
        barrier = threading.Barrier(2)

        def _first_call():
            # Manually acquire the lock to simulate in-progress sync
            acquired = service._sync_lock.acquire(blocking=False)
            barrier.wait()   # Signal second thread to proceed
            time.sleep(0.05)
            if acquired:
                service._sync_lock.release()

        def _second_call():
            barrier.wait()   # Wait until lock is held
            with patch.object(service, 'VULN_INTEL_ENABLED', True):
                results['second'] = service.sync_all()

        t1 = threading.Thread(target=_first_call)
        t2 = threading.Thread(target=_second_call)
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert results['second']['status'] == 'skipped'
        assert results['second']['reason'] == 'Sync in progress'


# ===========================================================================
# INTEL-GAP-004 — CVSS-based severity normalisation
# ===========================================================================

class TestCvssSeverityNormalisation:
    """_cvss_to_severity must map CVSS scores to the correct Severity enum values."""

    def test_none_cvss_returns_none(self):
        from scanners.vuln_intel import _cvss_to_severity
        assert _cvss_to_severity(None) is None

    def test_critical_score(self):
        from scanners.vuln_intel import _cvss_to_severity
        from core.models import Severity
        assert _cvss_to_severity(9.8) == Severity.CRITICAL

    def test_high_score(self):
        from scanners.vuln_intel import _cvss_to_severity
        from core.models import Severity
        assert _cvss_to_severity(7.5) == Severity.HIGH
        assert _cvss_to_severity(8.9) == Severity.HIGH

    def test_medium_score(self):
        from scanners.vuln_intel import _cvss_to_severity
        from core.models import Severity
        assert _cvss_to_severity(4.0) == Severity.MEDIUM
        assert _cvss_to_severity(6.9) == Severity.MEDIUM

    def test_low_score(self):
        from scanners.vuln_intel import _cvss_to_severity
        from core.models import Severity
        assert _cvss_to_severity(3.9) == Severity.LOW
        assert _cvss_to_severity(0.1) == Severity.LOW

    def test_zero_score_is_info(self):
        from scanners.vuln_intel import _cvss_to_severity
        from core.models import Severity
        assert _cvss_to_severity(0.0) == Severity.INFO

    def test_string_cvss_score_parsed(self):
        """String-typed CVSS score (e.g. from JSON) must be coerced to float."""
        from scanners.vuln_intel import _cvss_to_severity
        from core.models import Severity
        assert _cvss_to_severity("4.0") == Severity.MEDIUM

    def test_invalid_cvss_returns_none(self):
        from scanners.vuln_intel import _cvss_to_severity
        assert _cvss_to_severity("not-a-number") is None

    def test_enrich_no_cvss_preserves_existing_severity(self):
        """If OSV returns no CVSS score, existing finding severity is preserved."""
        from scanners.vuln_intel import enrich_findings_with_cves
        from core.models import Finding, Severity

        f = Finding(
            scan_id="s1",
            category="plugins",
            title="Plugin Identified: contact-form-7",
            description="Plugin detected",
            severity=Severity.MEDIUM,
            confidence=0.9,
            raw_data={"slug": "contact-form-7", "version": "5.7.5"},
        )

        # OSV returns a vuln but no cvss_score field
        mock_cves = [{"cve_id": "CVE-2023-9999", "summary": "XSS", "details": "", "references": []}]
        with patch("scanners.vuln_intel.lookup_osv_vulnerabilities", return_value=mock_cves):
            result = enrich_findings_with_cves([f])

        # Severity must be preserved (not escalated to HIGH or CRITICAL)
        assert result[0].severity == Severity.MEDIUM

    def test_enrich_cvss_4_maps_to_medium(self):
        """CVSS 4.0 → MEDIUM, not HIGH."""
        from scanners.vuln_intel import enrich_findings_with_cves
        from core.models import Finding, Severity

        f = Finding(
            scan_id="s1",
            category="plugins",
            title="Plugin Identified: contact-form-7",
            description="Plugin detected",
            severity=Severity.INFO,
            confidence=0.9,
            raw_data={"slug": "contact-form-7", "version": "5.7.5"},
        )

        mock_cves = [{"cve_id": "CVE-2023-9999", "summary": "XSS", "cvss_score": 4.0,
                      "details": "", "references": []}]
        with patch("scanners.vuln_intel.lookup_osv_vulnerabilities", return_value=mock_cves):
            result = enrich_findings_with_cves([f])

        assert result[0].severity == Severity.MEDIUM

    def test_enrich_cvss_9_8_maps_to_critical(self):
        """CVSS 9.8 → CRITICAL."""
        from scanners.vuln_intel import enrich_findings_with_cves
        from core.models import Finding, Severity

        f = Finding(
            scan_id="s1",
            category="plugins",
            title="Plugin Identified: wordfence",
            description="Plugin detected",
            severity=Severity.INFO,
            confidence=0.9,
            raw_data={"slug": "wordfence", "version": "7.10.0"},
        )

        mock_cves = [{"cve_id": "CVE-2024-0001", "summary": "RCE", "cvss_score": 9.8,
                      "details": "", "references": []}]
        with patch("scanners.vuln_intel.lookup_osv_vulnerabilities", return_value=mock_cves):
            result = enrich_findings_with_cves([f])

        assert result[0].severity == Severity.CRITICAL


# ===========================================================================
# INTEL-GAP-001 — _enrich_with_nvd_inner wiring and isolation
# ===========================================================================

class TestNvdEnrichmentInner:
    """
    sync_all() must call _enrich_with_nvd_inner(); NVD failures must not
    affect the overall sync_all() return value or other sync results.
    """

    @pytest.fixture(autouse=True)
    def reset_lock(self):
        from core.vulnerability_intelligence import service
        r = service._get_redis_client()
        if r is not None:
            try:
                r.delete(service._REDIS_LOCK_NAME)
            except Exception:
                pass
        if service._sync_lock.locked():
            try:
                service._sync_lock.release()
            except RuntimeError:
                pass
        yield
        if r is not None:
            try:
                r.delete(service._REDIS_LOCK_NAME)
            except Exception:
                pass
        if service._sync_lock.locked():
            try:
                service._sync_lock.release()
            except RuntimeError:
                pass

    def test_sync_all_calls_enrich_nvd_inner(self):
        """_enrich_with_nvd_inner is called as part of sync_all()."""
        from core.vulnerability_intelligence import service

        with patch.object(service, '_sync_wordfence_inner', return_value={'status': 'ok'}), \
             patch.object(service, '_sync_kev_inner', return_value={'status': 'ok'}), \
             patch.object(service, '_sync_plugin_metadata_inner', return_value={'status': 'ok'}), \
             patch.object(service, '_enrich_with_nvd_inner', return_value={'status': 'ok', 'enriched': 3}) as mock_nvd, \
             patch.object(service, 'VULN_INTEL_ENABLED', True), \
             patch('core.vulnerability_intelligence.service.vuln_repo') as mock_repo:
            mock_repo._get_vuln_conn().cursor().fetchall.return_value = []
            result = service.sync_all()

        mock_nvd.assert_called_once()
        assert 'nvd_enrichment' in result

    def test_nvd_failure_does_not_break_sync_all(self):
        """If _enrich_with_nvd_inner raises an exception, sync_all still returns full results."""
        from core.vulnerability_intelligence import service

        with patch.object(service, '_sync_wordfence_inner', return_value={'status': 'ok'}), \
             patch.object(service, '_sync_kev_inner', return_value={'status': 'ok'}), \
             patch.object(service, '_sync_plugin_metadata_inner', return_value={'status': 'ok'}), \
             patch.object(service, '_enrich_with_nvd_inner', side_effect=RuntimeError("NVD timeout")), \
             patch.object(service, 'VULN_INTEL_ENABLED', True), \
             patch('core.vulnerability_intelligence.service.vuln_repo') as mock_repo:
            mock_repo._get_vuln_conn().cursor().fetchall.return_value = []
            # sync_all should not raise
            try:
                result = service.sync_all()
            except RuntimeError:
                pytest.fail("sync_all() must not propagate NVD enrichment errors")

    def test_enrich_with_nvd_inner_available(self):
        """_enrich_with_nvd_inner must be importable and callable from service."""
        from core.vulnerability_intelligence import service
        assert callable(getattr(service, '_enrich_with_nvd_inner', None)), \
            "_enrich_with_nvd_inner must be defined in service.py"


# ===========================================================================
# SCAN-GAP-004 — TLSScanner uses ssl.TLSVersion, not deprecated PROTOCOL_*
# ===========================================================================

class TestTLSScannerModernAPI:
    """
    _check_protocols() must use ssl.TLSVersion enum constraints (minimum_version /
    maximum_version) instead of deprecated ssl.PROTOCOL_TLSv1 / PROTOCOL_TLSv1_1
    constants when those enum values are available.
    """

    def test_check_protocols_does_not_use_deprecated_protocol_constants(self):
        """Verify _check_protocols never calls ssl.SSLContext with legacy PROTOCOL_TLS{v1,v1_1}."""
        from scanners.tls_scanner import TLSScanner
        import socket

        scanner = TLSScanner("https://example.com")

        ssl_context_calls = []
        original_ssl_context = ssl.SSLContext

        def _spy_ssl_context(proto):
            ssl_context_calls.append(proto)
            raise ssl.SSLError("blocked in test")

        # Socket should not connect; raise immediately
        with patch("ssl.SSLContext", side_effect=_spy_ssl_context), \
             patch("socket.create_connection", side_effect=socket.error("blocked")):
            try:
                scanner._check_protocols("example.com", 443)
            except Exception:
                pass

        # The deprecated legacy constants (if they still exist) should NOT appear in calls
        deprecated_protos = set()
        for attr in ("PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"):
            v = getattr(ssl, attr, None)
            if v is not None:
                deprecated_protos.add(v)

        used_deprecated = deprecated_protos & set(ssl_context_calls)
        assert not used_deprecated, (
            f"_check_protocols() must not use deprecated ssl.PROTOCOL_* constants. "
            f"Found: {used_deprecated}"
        )

    def test_tls_version_enum_used_when_available(self):
        """If ssl.TLSVersion.TLSv1 is available, the modern path (minimum_version) is taken."""
        from scanners.tls_scanner import TLSScanner
        import socket

        if not hasattr(ssl.TLSVersion, "TLSv1"):
            pytest.skip("ssl.TLSVersion.TLSv1 not available on this Python build")

        scanner = TLSScanner("https://example.com")

        ctx_instances = []

        class _MockCtx:
            def __init__(self, proto):
                ctx_instances.append(self)
                self.check_hostname = True
                self.verify_mode = None
                self.minimum_version = None
                self.maximum_version = None

            def wrap_socket(self, *a, **kw):
                raise ssl.SSLError("handshake fail")

        with patch("ssl.SSLContext", side_effect=_MockCtx), \
             patch("socket.create_connection", side_effect=socket.error("blocked")):
            try:
                scanner._check_protocols("example.com", 443)
            except Exception:
                pass

        # At least one context should have had minimum_version / maximum_version set
        # (rather than being created with the deprecated protocol directly)
        assert any(
            ctx.minimum_version is not None or ctx.maximum_version is not None
            for ctx in ctx_instances
        ), "Expected ssl.TLSVersion min/max constraints but found none"


# ===========================================================================
# EVI-GAP-002 — ThemeScanner version_confidence in raw_data
# ===========================================================================

class TestThemeScannerVersionConfidence:
    """
    Theme findings emitted by ThemeScanner must include a version_confidence
    field in raw_data (EVI-GAP-002).
    """

    def test_theme_with_version_has_high_confidence(self):
        """Detected theme with a version → version_confidence == 'high'."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        html = '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">'

        with patch.object(scanner, "_get", return_value=_make_response(200, html)), \
             patch.object(scanner, "_get_theme_version", return_value="1.0"):
            scanner._detect_active_theme()

        theme_findings = [f for f in scanner.findings if "Theme Identified" in f.title]
        assert len(theme_findings) == 1
        assert theme_findings[0].raw_data.get("version_confidence") == "high"

    def test_theme_without_version_has_none_confidence(self):
        """Detected theme without version → version_confidence == 'none'."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        html = '<link href="/wp-content/themes/astra/style.css">'

        with patch.object(scanner, "_get", return_value=_make_response(200, html)), \
             patch.object(scanner, "_get_theme_version", return_value=""):
            scanner._detect_active_theme()

        theme_findings = [f for f in scanner.findings if "Theme Identified" in f.title]
        assert len(theme_findings) == 1
        assert theme_findings[0].raw_data.get("version_confidence") == "none"

    def test_theme_raw_data_has_method_passive(self):
        """Passive theme findings must record method='passive' in raw_data."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        html = '<link href="/wp-content/themes/storefront/style.css">'

        with patch.object(scanner, "_get", return_value=_make_response(200, html)), \
             patch.object(scanner, "_get_theme_version", return_value="4.2"):
            scanner._detect_active_theme()

        finding = next((f for f in scanner.findings if "Theme Identified" in f.title), None)
        assert finding is not None
        assert finding.raw_data.get("method") == "passive"
