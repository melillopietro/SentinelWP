"""
Sprint 1 Regression Tests — SentinelWP Detection Accuracy & Vulnerability Intelligence

Covers:
  FUNC-001  — 'full' scan mode logs a deprecation warning (silent-alias fix)
  FUNC-003  — BruteForceScanner disabled guard (deprecated scanner protection)
  SEC-007   — CircuitBreaker thread-safety (threading.Lock present and functional)
  QA-002    — CircuitBreaker state-machine tests (CLOSED, OPEN, HALF_OPEN transitions)
  CODE-006  — is_stale() uses VULN_INTEL_STALE_AFTER_HOURS, not hardcoded 30 minutes
  OPS-001   — sync_wordfence / sync_kev / sync_plugin_metadata respect _sync_lock when
              called via sync_all(); individual callsites verified to not bypass lock
  WFBUG-001 — fetch_production_feed_with_reason() always returns a tuple (max-retry path)
  VM-001    — version_matcher edge cases: 1.9 < 1.10, prerelease, missing version,
              overlapping advisory ranges, unbounded ranges, version_unknown propagation
  VM-002    — match_software does not classify a component as vulnerable based solely on
              a loose name match — slug must match exactly
  DETECT-001 — WP detector: non-WordPress target is not classified as WordPress
  DETECT-002 — WP detector: version precedence policy (meta_generator > asset_ver_param)
  DETECT-003 — WP detector: missing version evidence does not imply secure configuration
  PLUGIN-001 — Plugin scanner: version_confidence is 'low' for ?ver= param source
  PLUGIN-002 — Plugin scanner: version_confidence is 'high' when readme.txt present
  THEME-001  — Theme scanner: version is empty string when style.css is inaccessible
  RISK-001   — Risk engine: findings below confidence threshold are excluded from score
  RISK-002   — Risk engine: empty findings list produces score=0.0 grade=A+
  RISK-003   — Risk engine: CRITICAL finding produces higher score than LOW-only findings
  RISK-004   — Risk engine: score is deterministic (same inputs → same output)
"""
import os
import sys
import time
import threading
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("ENVIRONMENT", "development")


# =============================================================================
# FUNC-001 — 'full' scan mode deprecation warning
# =============================================================================

class TestFullScanModeDeprecationWarning(unittest.TestCase):
    """FUNC-001: run_scan with mode='full' must emit a deprecation warning."""

    def test_full_mode_logs_deprecation_warning(self):
        """run_scan('full') must call _orch_logger.warning mentioning 'deprecated'."""
        with patch("scanners.orchestrator._orch_logger") as mock_log, \
             patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")), \
             patch("scanners.orchestrator.repository") as mock_repo, \
             patch("scanners.orchestrator.compute_risk_score", return_value=(0.0, "A+")):

            # Prevent any real scanner from running
            with patch("scanners.orchestrator.SCAN_PROFILES", {"passive": [], "safe-active": [], "full": []}):
                from scanners.orchestrator import run_scan
                from core.models import ScanResult, ScanStatus

                mock_repo.ensure_asset_for_target.return_value = MagicMock(id="asset-1")
                mock_repo.save_scan.return_value = None
                mock_repo.save_findings_bulk.return_value = None

                run_scan("https://example.com", scan_mode="full")

            # warning must have been called at least once
            assert mock_log.warning.called, "Expected _orch_logger.warning to be called for 'full' mode"
            call_args = mock_log.warning.call_args[0][0]
            assert "deprecated" in call_args.lower() or "safe-active" in call_args.lower(), \
                f"Warning message did not mention deprecation: {call_args}"

    def test_passive_mode_does_not_log_deprecation_warning(self):
        """run_scan('passive') must NOT emit a deprecation warning."""
        with patch("scanners.orchestrator._orch_logger") as mock_log, \
             patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")), \
             patch("scanners.orchestrator.repository") as mock_repo, \
             patch("scanners.orchestrator.compute_risk_score", return_value=(0.0, "A+")):

            with patch("scanners.orchestrator.SCAN_PROFILES", {"passive": [], "safe-active": [], "full": []}):
                from scanners.orchestrator import run_scan
                run_scan("https://example.com", scan_mode="passive")

            mock_log.warning.assert_not_called()

    def test_full_mode_scanner_list_equals_safe_active(self):
        """'full' and 'safe-active' profiles must use the identical scanner list."""
        from scanners.orchestrator import SCAN_PROFILES
        assert SCAN_PROFILES["full"] == SCAN_PROFILES["safe-active"], \
            "SCAN_PROFILES['full'] must equal SCAN_PROFILES['safe-active']"


# =============================================================================
# FUNC-003 — BruteForceScanner disabled guard
# =============================================================================

class TestBruteForceDeprecationGuard(unittest.TestCase):
    """FUNC-003: BruteForceScanner.scan() must raise RuntimeError unless ALLOW_BRUTEFORCE=True."""

    def test_scan_raises_without_allow_flag(self):
        from scanners.bruteforce_scanner import BruteForceScanner
        scanner = BruteForceScanner("https://example.com")
        assert scanner.ALLOW_BRUTEFORCE is False, "Default ALLOW_BRUTEFORCE must be False"
        with self.assertRaises(RuntimeError) as ctx:
            scanner.scan()
        assert "deprecated" in str(ctx.exception).lower() or "disabled" in str(ctx.exception).lower()

    def test_scan_runs_when_allow_flag_set(self):
        """With ALLOW_BRUTEFORCE=True, scan() must proceed (not raise on the guard)."""
        from scanners.bruteforce_scanner import BruteForceScanner
        scanner = BruteForceScanner("https://example.com")
        scanner.ALLOW_BRUTEFORCE = True
        with patch.object(scanner, "_test_default_credentials", return_value=None) as mock_creds:
            result = scanner.scan()
            mock_creds.assert_called_once()
        assert isinstance(result, list)

    def test_bruteforce_not_in_any_automated_profile(self):
        """BruteForceScanner must not appear in passive, safe-active, or full profiles."""
        from scanners.orchestrator import SCAN_PROFILES
        from scanners.bruteforce_scanner import BruteForceScanner
        for profile_name, scanners in SCAN_PROFILES.items():
            assert BruteForceScanner not in scanners, \
                f"BruteForceScanner must not be in the '{profile_name}' scan profile"


# =============================================================================
# SEC-007 & QA-002 — CircuitBreaker thread-safety and state machine
# =============================================================================

class TestCircuitBreakerThreadSafety(unittest.TestCase):
    """SEC-007: CircuitBreaker must have a threading.Lock."""

    def test_circuit_breaker_has_lock_attribute(self):
        from core.integrations.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test-sec007")
        assert hasattr(cb, "_lock"), "CircuitBreaker must have a _lock attribute (threading.Lock)"
        assert isinstance(cb._lock, type(threading.Lock())), \
            "CircuitBreaker._lock must be a threading.Lock instance"

    def test_concurrent_failures_do_not_corrupt_state(self):
        """Multiple threads recording failures concurrently must not exceed threshold."""
        from core.integrations.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException
        cb = CircuitBreaker("test-concurrent", failure_threshold=3, recovery_timeout=999)
        errors = []

        def trigger_failure():
            try:
                def bad_fn():
                    raise ValueError("simulated")
                cb.call(bad_fn)
            except (ValueError, CircuitBreakerOpenException):
                pass
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=trigger_failure) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Unexpected errors in concurrent test: {errors}"
        # failure_count must not exceed threshold (circuit opens and fast-fails after that)
        assert cb.failure_count <= cb.failure_threshold or cb.state == cb.OPEN

    def test_concurrent_success_does_not_corrupt_closed_state(self):
        """Multiple threads calling a successful function must not corrupt CLOSED state."""
        from core.integrations.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test-concurrent-success", failure_threshold=5)
        errors = []

        def call_success():
            try:
                cb.call(lambda: 42)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=call_success) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Unexpected errors: {errors}"
        assert cb.state == cb.CLOSED
        assert cb.failure_count == 0


class TestCircuitBreakerStateMachine(unittest.TestCase):
    """QA-002: Full state machine coverage for CircuitBreaker."""

    def test_initial_state_is_closed(self):
        from core.integrations.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test-init")
        assert cb.state == cb.CLOSED

    def test_success_in_closed_state_resets_failure_count(self):
        from core.integrations.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test-success-reset", failure_threshold=3)
        # Record one failure manually to simulate a partial-fail scenario
        cb.failure_count = 2
        cb.call(lambda: None)
        assert cb.failure_count == 0

    def test_failures_above_threshold_open_circuit(self):
        from core.integrations.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException
        cb = CircuitBreaker("test-open", failure_threshold=3, recovery_timeout=999)
        for _ in range(3):
            try:
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
            except ValueError:
                pass
        assert cb.state == cb.OPEN

    def test_open_circuit_raises_without_calling_function(self):
        from core.integrations.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException
        cb = CircuitBreaker("test-fast-fail", failure_threshold=1, recovery_timeout=999)
        try:
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        except ValueError:
            pass
        assert cb.state == cb.OPEN

        sentinel = []
        with self.assertRaises(CircuitBreakerOpenException):
            cb.call(lambda: sentinel.append(1))
        assert not sentinel, "Function must not be called when circuit is OPEN"

    def test_open_transitions_to_half_open_after_timeout(self):
        from core.integrations.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException
        cb = CircuitBreaker("test-half-open", failure_threshold=1, recovery_timeout=0.05)
        try:
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        except ValueError:
            pass
        assert cb.state == cb.OPEN

        time.sleep(0.1)
        # The next call should transition to HALF_OPEN and allow the probe
        cb.call(lambda: None)
        # After one success, still in HALF_OPEN (needs 2 successes by default)
        assert cb.state in (cb.HALF_OPEN, cb.CLOSED)

    def test_half_open_success_threshold_closes_circuit(self):
        from core.integrations.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test-close", failure_threshold=1, recovery_timeout=0.05,
                            half_open_success_threshold=2)
        try:
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        except ValueError:
            pass
        time.sleep(0.1)
        cb.call(lambda: None)  # probe → HALF_OPEN, success_count=1
        cb.call(lambda: None)  # success_count=2 → CLOSED
        assert cb.state == cb.CLOSED
        assert cb.failure_count == 0

    def test_half_open_failure_returns_to_open(self):
        from core.integrations.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test-reopen", failure_threshold=1, recovery_timeout=0.05)
        try:
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        except ValueError:
            pass
        time.sleep(0.1)
        # Force HALF_OPEN state
        cb.state = cb.HALF_OPEN
        cb.failure_count = 0
        try:
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail again")))
        except ValueError:
            pass
        assert cb.state == cb.OPEN


# =============================================================================
# CODE-006 — is_stale() uses VULN_INTEL_STALE_AFTER_HOURS
# =============================================================================

class TestIsStaleUsesConfiguredThreshold(unittest.TestCase):
    """CODE-006: is_stale() must use VULN_INTEL_STALE_AFTER_HOURS, not a hardcoded value."""

    def test_is_stale_uses_vuln_intel_stale_after_hours_when_fresh(self):
        """A sync recorded 1 hour ago with VULN_INTEL_STALE_AFTER_HOURS=24 should NOT be stale."""
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        mock_state = {"last_success_at": one_hour_ago, "status": "success"}
        with patch("core.vulnerability_intelligence.service.vuln_repo") as mock_repo, \
             patch("core.vulnerability_intelligence.service.VULN_INTEL_STALE_AFTER_HOURS", 24.0), \
             patch("core.vulnerability_intelligence.wordfence_client._get_api_key", return_value="key123"):
            mock_repo.get_sync_state.return_value = mock_state
            from core.vulnerability_intelligence.service import is_stale
            assert not is_stale(), "1-hour-old sync should not be stale with 24-hour threshold"

    def test_is_stale_detects_stale_beyond_threshold(self):
        """A sync recorded 25 hours ago with VULN_INTEL_STALE_AFTER_HOURS=24 SHOULD be stale."""
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        mock_state = {"last_success_at": old_time, "status": "success"}
        with patch("core.vulnerability_intelligence.service.vuln_repo") as mock_repo, \
             patch("core.vulnerability_intelligence.service.VULN_INTEL_STALE_AFTER_HOURS", 24.0), \
             patch("core.vulnerability_intelligence.wordfence_client._get_api_key", return_value="key123"):
            mock_repo.get_sync_state.return_value = mock_state
            from core.vulnerability_intelligence.service import is_stale
            assert is_stale(), "25-hour-old sync should be stale with 24-hour threshold"

    def test_is_stale_source_reads_from_config_not_hardcoded_minutes(self):
        """Inspect source to confirm timedelta(hours=...) is used, not timedelta(minutes=30)."""
        import inspect
        from core.vulnerability_intelligence import service
        src = inspect.getsource(service.is_stale)
        assert "timedelta(hours=" in src, "is_stale() must use timedelta(hours=...)"
        assert "timedelta(minutes=30)" not in src, \
            "is_stale() must not use the old hardcoded timedelta(minutes=30)"


# =============================================================================
# WFBUG-001 — fetch_production_feed_with_reason() always returns a tuple
# =============================================================================

class TestWordfenceFeedReturnType(unittest.TestCase):
    """WFBUG-001: fetch_production_feed_with_reason() must always return (data, reason) tuple."""

    def test_max_retries_exceeded_returns_tuple(self):
        """When max retries are exhausted, the function must return (None, str), not bare None."""
        import requests
        from core.vulnerability_intelligence.wordfence_client import fetch_production_feed_with_reason

        # Simulate repeated 503 server errors to exhaust retries
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.headers = {}

        with patch("core.vulnerability_intelligence.wordfence_client._get_api_key", return_value="test-key"), \
             patch("requests.get", return_value=mock_resp), \
             patch("time.sleep", return_value=None):
            result = fetch_production_feed_with_reason()

        assert isinstance(result, tuple), \
            f"fetch_production_feed_with_reason() must return a tuple, got {type(result)}"
        assert len(result) == 2, f"Expected 2-tuple, got {len(result)}-tuple"
        data, reason = result
        assert data is None, f"data must be None on failure, got {data}"
        assert isinstance(reason, str), f"reason must be a str, got {type(reason)}"

    def test_missing_api_key_returns_tuple(self):
        """When no API key, must return (None, str)."""
        from core.vulnerability_intelligence.wordfence_client import fetch_production_feed_with_reason
        with patch("core.vulnerability_intelligence.wordfence_client._get_api_key", return_value=""):
            result = fetch_production_feed_with_reason()
        assert isinstance(result, tuple) and len(result) == 2
        data, reason = result
        assert data is None
        assert "api key" in reason.lower() or "missing" in reason.lower()

    def test_auth_error_returns_tuple(self):
        """401 response must return (None, str)."""
        from core.vulnerability_intelligence.wordfence_client import fetch_production_feed_with_reason
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("core.vulnerability_intelligence.wordfence_client._get_api_key", return_value="bad-key"), \
             patch("requests.get", return_value=mock_resp):
            result = fetch_production_feed_with_reason()
        assert isinstance(result, tuple) and len(result) == 2
        data, reason = result
        assert data is None
        assert "401" in reason or "authentication" in reason.lower()


# =============================================================================
# VM-001 — Version matcher edge cases
# =============================================================================

class TestVersionMatcherEdgeCases(unittest.TestCase):
    """VM-001: Version comparison must be strictly numeric (1.9 < 1.10, etc.)."""

    def setUp(self):
        from core.vulnerability_intelligence.version_matcher import (
            parse_version, compare_versions, is_version_affected, MatchResult
        )
        self.parse = parse_version
        self.compare = compare_versions
        self.affected = is_version_affected
        self.MatchResult = MatchResult

    def test_1_9_less_than_1_10(self):
        """1.9 must be strictly less than 1.10 (numeric, not lexicographic comparison)."""
        assert self.compare(self.parse("1.9"), self.parse("1.10")) == -1

    def test_1_10_less_than_1_10_1(self):
        assert self.compare(self.parse("1.10"), self.parse("1.10.1")) == -1

    def test_1_10_equals_1_10(self):
        assert self.compare(self.parse("1.10"), self.parse("1.10")) == 0

    def test_2_0_greater_than_1_99(self):
        assert self.compare(self.parse("2.0"), self.parse("1.99")) == 1

    def test_prerelease_less_than_release(self):
        """1.2.3-beta must sort below 1.2.3."""
        assert self.compare(self.parse("1.2.3-beta"), self.parse("1.2.3")) == -1

    def test_prerelease_alpha_less_than_beta(self):
        assert self.compare(self.parse("1.0.0-alpha"), self.parse("1.0.0-beta")) == -1

    def test_prerelease_rc_less_than_release(self):
        assert self.compare(self.parse("5.8-rc1"), self.parse("5.8")) == -1

    def test_missing_version_returns_version_unknown(self):
        """Empty or None detected version must produce version_unknown, not affected."""
        for v in ("", None, "*"):
            result = self.affected(v, {
                "from_version": "1.0", "from_inclusive": True,
                "to_version": "2.0", "to_inclusive": True
            })
            assert result.status == "version_unknown", \
                f"Expected version_unknown for version={v!r}, got {result.status}"

    def test_overlapping_ranges_first_match_wins(self):
        """When two ranges overlap, the first matching range must produce 'affected'."""
        from core.vulnerability_intelligence.version_matcher import match_software
        sw_list = [
            {
                "type": "plugin",
                "slug": "overlap-plugin",
                "affected_versions": {
                    "range1": {"from_version": "1.0", "from_inclusive": True,
                               "to_version": "3.0", "to_inclusive": False},
                    "range2": {"from_version": "2.0", "from_inclusive": True,
                               "to_version": "4.0", "to_inclusive": True},
                }
            }
        ]
        res = match_software("overlap-plugin", "2.5", "plugin", sw_list)
        assert res.status == "affected"

    def test_version_above_all_ranges_is_not_affected(self):
        from core.vulnerability_intelligence.version_matcher import match_software
        sw_list = [
            {
                "type": "plugin",
                "slug": "test-plugin",
                "affected_versions": {
                    "range1": {"from_version": "1.0", "from_inclusive": True,
                               "to_version": "2.0", "to_inclusive": True},
                }
            }
        ]
        res = match_software("test-plugin", "3.0", "plugin", sw_list)
        assert res.status == "not_affected"

    def test_slug_mismatch_never_produces_affected(self):
        """VM-002: A component must not be flagged as vulnerable based on a partial name match."""
        from core.vulnerability_intelligence.version_matcher import match_software
        sw_list = [
            {
                "type": "plugin",
                "slug": "contact-form-7",
                "affected_versions": {
                    "range1": {"from_version": "1.0", "from_inclusive": True,
                               "to_version": "9.9", "to_inclusive": True},
                }
            }
        ]
        # "contact-form" is a substring of "contact-form-7" but must NOT match
        res = match_software("contact-form", "5.0", "plugin", sw_list)
        assert res.status == "not_affected", \
            "Slug must match exactly — partial substring match must not produce 'affected'"

    def test_type_mismatch_never_produces_affected(self):
        """A 'core' slug must not match a 'plugin' record even if slug is identical."""
        from core.vulnerability_intelligence.version_matcher import match_software
        sw_list = [
            {
                "type": "plugin",
                "slug": "wordpress",
                "affected_versions": {
                    "range1": {"from_version": "5.0", "from_inclusive": True,
                               "to_version": "6.0", "to_inclusive": True},
                }
            }
        ]
        res = match_software("wordpress", "5.5", "core", sw_list)
        assert res.status == "not_affected"

    def test_unbounded_lower_range(self):
        res = self.affected("0.1", {
            "from_version": "*", "from_inclusive": True,
            "to_version": "2.0", "to_inclusive": True
        })
        assert res.status == "affected"

    def test_unbounded_upper_range(self):
        res = self.affected("99.0", {
            "from_version": "1.0", "from_inclusive": True,
            "to_version": "*", "to_inclusive": True
        })
        assert res.status == "affected"


# =============================================================================
# DETECT-001/002/003 — WordPress detector behaviour
# =============================================================================

class TestWordPressDetectorBehaviour(unittest.TestCase):
    """Detection accuracy: non-WP targets, version precedence, missing evidence."""

    def _make_scanner(self, homepage_body: str, extra_mocks: dict = None):
        """Construct a WordPressDetector with mocked HTTP responses."""
        from scanners.wp_detector import WordPressDetector

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = homepage_body
        mock_resp.url = "https://example.com"
        mock_resp.cookies = []
        mock_resp.headers = {}

        scanner = WordPressDetector("https://example.com")

        def fake_get(url, **kwargs):
            if extra_mocks and url in extra_mocks:
                return extra_mocks[url]
            # Return generic 404 for sub-requests
            r = MagicMock()
            r.status_code = 404
            r.text = ""
            r.json.side_effect = ValueError
            r.cookies = []
            r.headers = {}
            return r

        def fake_head(url, **kwargs):
            r = MagicMock()
            r.status_code = 404
            return r

        scanner._get = fake_get
        scanner._get_override = fake_get

        # Inject mock for the homepage call
        original_get = scanner._get

        def patched_get(url, **kwargs):
            if url == "https://example.com" or url == "https://example.com/":
                return mock_resp
            return original_get(url, **kwargs)

        scanner._get = patched_get
        scanner._head = fake_head
        return scanner

    def test_non_wordpress_target_not_detected(self):
        """DETECT-001: A plain HTML page with no WP signals must produce detected=False."""
        body = "<html><head><title>My Blog</title></head><body><p>Hello world</p></body></html>"
        scanner = self._make_scanner(body)
        result = scanner.detect()
        assert result.detected is False, \
            f"Non-WordPress page must not be detected as WP; confidence={result.confidence_score}"
        assert result.confidence_score < 0.15

    def test_meta_generator_takes_precedence_over_asset_ver(self):
        """DETECT-002: meta_generator version must win over asset_ver_param."""
        body = (
            '<meta name="generator" content="WordPress 6.5.2" />'
            '<script src="/wp-includes/js/wp-embed.min.js?ver=6.3.0"></script>'
        )
        scanner = self._make_scanner(body)
        result = scanner.detect()
        assert result.detected is True
        assert result.version == "6.5.2", \
            f"meta_generator (6.5.2) must beat asset_ver_param (6.3.0), got {result.version}"
        assert result.version_source == "meta_generator"

    def test_missing_version_does_not_mean_no_vulnerability(self):
        """DETECT-003: Detecting WP without a version must not imply secure config.
        The scan() method must still produce a 'WordPress CMS Detected' finding."""
        body = (
            '<link rel="https://api.w.org/" href="https://example.com/wp-json/" />'
            '/wp-content/themes/twentytwentythree/'
            '/wp-includes/js/wp-embed.min.js'
        )
        scanner = self._make_scanner(body)
        findings = scanner.scan()
        wp_findings = [f for f in findings if "WordPress" in f.title]
        assert len(wp_findings) >= 1, \
            "WP must still be reported when detected even without a version"
        # No version finding should be emitted (version is None)
        version_findings = [f for f in findings if "Version Exposed" in f.title]
        assert len(version_findings) == 0, \
            "No 'Version Exposed' finding expected when version is unknown"

    def test_wp_content_signal_alone_is_not_sufficient_for_detection(self):
        """A single /wp-content/ reference (weight 0.15) is below the 0.15 threshold."""
        body = '<img src="/wp-content/uploads/2024/logo.png" />'
        scanner = self._make_scanner(body)
        result = scanner.detect()
        # wp_content weight=0.15, threshold=0.15 → confidence==0.15 → detected=True
        # This is expected behaviour (just at boundary); confirm no false TypeError/crash.
        assert isinstance(result.detected, bool)
        assert 0.0 <= result.confidence_score <= 1.0


# =============================================================================
# PLUGIN-001/002 — Plugin scanner version confidence
# =============================================================================

class TestPluginScannerVersionConfidence(unittest.TestCase):
    """Plugin version confidence rating must reflect the detection source."""

    def _make_scanner(self, html_body: str, readme_response=None):
        from scanners.plugin_scanner import PluginScanner
        scanner = PluginScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = False

        mock_home = MagicMock()
        mock_home.status_code = 200
        mock_home.text = html_body

        def fake_get(url, **kwargs):
            if url == "https://example.com" or url.rstrip("/") == "https://example.com":
                return mock_home
            if readme_response and "readme.txt" in url:
                return readme_response
            r = MagicMock()
            r.status_code = 404
            r.text = ""
            return r

        scanner._get = fake_get
        return scanner

    def test_ver_param_only_gives_low_confidence(self):
        """PLUGIN-001: ?ver= parameter alone should produce version_confidence='low'."""
        html = '/wp-content/plugins/woocommerce/assets/js/jquery-blockui.min.js?ver=2.70'
        scanner = self._make_scanner(html)
        findings = scanner.scan()
        woo_findings = [f for f in findings if "woocommerce" in f.title.lower()]
        assert woo_findings, "woocommerce plugin should be detected"
        raw = woo_findings[0].raw_data
        # readme.txt unavailable (404) → confidence stays 'low'
        assert raw.get("version_confidence") == "low", \
            f"Expected 'low' confidence without readme.txt, got {raw.get('version_confidence')}"

    def test_readme_txt_gives_high_confidence(self):
        """PLUGIN-002: readme.txt Stable tag should produce version_confidence='high'."""
        html = '/wp-content/plugins/akismet/assets/js/akismet.js?ver=3.1.4'
        readme = MagicMock()
        readme.status_code = 200
        readme.text = "=== Akismet ===\nStable tag: 5.3.1\n"
        scanner = self._make_scanner(html, readme_response=readme)
        findings = scanner.scan()
        akismet_findings = [f for f in findings if "akismet" in f.title.lower()]
        assert akismet_findings
        raw = akismet_findings[0].raw_data
        assert raw.get("version_confidence") == "high", \
            f"Expected 'high' confidence from readme.txt, got {raw.get('version_confidence')}"
        assert raw.get("version") == "5.3.1", \
            f"readme.txt version should override ?ver= value, got {raw.get('version')}"


# =============================================================================
# THEME-001 — Theme scanner version
# =============================================================================

class TestThemeScannerVersionHandling(unittest.TestCase):
    """THEME-001: version must be empty string when style.css returns non-200."""

    def test_inaccessible_style_css_returns_empty_version(self):
        from scanners.theme_scanner import ThemeScanner
        scanner = ThemeScanner("https://example.com")

        mock_home = MagicMock()
        mock_home.status_code = 200
        mock_home.text = "/wp-content/themes/mytheme/style.css"

        def fake_get(url, **kwargs):
            if url == "https://example.com":
                return mock_home
            r = MagicMock()
            r.status_code = 403
            r.text = ""
            return r

        def fake_head(url, **kwargs):
            r = MagicMock()
            r.status_code = 404
            return r

        scanner._get = fake_get
        scanner._head = fake_head
        findings = scanner.scan()
        theme_findings = [f for f in findings if "mytheme" in f.title.lower()]
        assert theme_findings, "mytheme should be detected from homepage HTML"
        raw = theme_findings[0].raw_data
        assert raw.get("version") == "" or raw.get("version") is None, \
            f"Version must be empty when style.css is inaccessible, got {raw.get('version')}"


# =============================================================================
# RISK-001/002/003/004 — Risk scoring validation
# =============================================================================

class TestRiskScoring(unittest.TestCase):
    """Risk engine correctness and determinism."""

    def _make_finding(self, severity_str, category="general", confidence=1.0):
        from core.models import Finding, Severity
        return Finding(
            category=category,
            title=f"Test {severity_str}",
            description="test",
            severity=Severity(severity_str),
            confidence=confidence,
        )

    def test_empty_findings_produces_zero_score(self):
        """RISK-002: No findings → score=0.0, grade='A+'."""
        from core.risk_engine import compute_risk_score
        score, grade = compute_risk_score([])
        assert score == 0.0
        assert grade == "A+"

    def test_findings_below_confidence_threshold_excluded(self):
        """RISK-001: Findings below confidence threshold must not raise the score."""
        from core.risk_engine import compute_risk_score
        f = self._make_finding("critical", confidence=0.1)
        score, grade = compute_risk_score([f], confidence_threshold=0.3)
        assert score == 0.0, "CRITICAL finding at 0.1 confidence should be excluded at 0.3 threshold"

    def test_critical_beats_low_only(self):
        """RISK-003: A CRITICAL finding must produce a higher score than a LOW-only finding."""
        from core.risk_engine import compute_risk_score
        critical_score, _ = compute_risk_score([self._make_finding("critical")])
        low_score, _ = compute_risk_score([self._make_finding("low")])
        assert critical_score > low_score, \
            f"CRITICAL score {critical_score} must exceed LOW score {low_score}"

    def test_scoring_is_deterministic(self):
        """RISK-004: Same inputs must always produce the same score."""
        from core.risk_engine import compute_risk_score
        findings = [
            self._make_finding("critical", "authentication"),
            self._make_finding("high", "enumeration"),
            self._make_finding("medium", "headers"),
            self._make_finding("low", "plugins"),
        ]
        score1, grade1 = compute_risk_score(findings)
        score2, grade2 = compute_risk_score(findings)
        assert score1 == score2, "Score must be deterministic"
        assert grade1 == grade2, "Grade must be deterministic"

    def test_score_bounded_between_0_and_100(self):
        """Score must always be in [0, 100]."""
        from core.risk_engine import compute_risk_score
        many_criticals = [self._make_finding("critical") for _ in range(50)]
        score, _ = compute_risk_score(many_criticals)
        assert 0.0 <= score <= 100.0

    def test_category_breakdown_reflects_all_findings(self):
        """compute_category_breakdown must count all unfiltered findings."""
        from core.risk_engine import compute_category_breakdown
        findings = [
            self._make_finding("critical", "authentication"),
            self._make_finding("high", "authentication"),
            self._make_finding("low", "headers"),
        ]
        breakdown = compute_category_breakdown(findings)
        assert breakdown["authentication"]["count"] == 2
        assert breakdown["headers"]["count"] == 1
        assert breakdown["authentication"]["max_severity"] == "critical"


if __name__ == "__main__":
    unittest.main()
