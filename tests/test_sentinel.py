"""
Automated Test Suite for SentinelWP v2.1 Enterprise.
Run with: python3 -m unittest discover -s tests -p "test_*.py"
"""
import unittest
import json
from unittest.mock import MagicMock, patch
from scanners.base import BaseScanner
from scanners.wp_detector import WordPressDetector
from core.risk_engine import compute_risk_score
from core.models import Finding, Severity, ScanResult
from core.rate_limiter import RateLimiter
from reports.generator import generate_sarif_report, generate_html_report, generate_json_report


class TestBaseScannerSSRF(unittest.TestCase):
    def test_ssrf_protection_valid_targets(self):
        valid, msg = BaseScanner.validate_target("https://wordpress.org")
        self.assertTrue(valid)
        self.assertEqual(msg, "")

    def test_ssrf_protection_blocked_targets(self):
        # Localhost
        valid, msg = BaseScanner.validate_target("http://localhost")
        self.assertFalse(valid)
        self.assertIn("blocked", msg)

        # Private IPv4
        valid, msg = BaseScanner.validate_target("http://192.168.1.1")
        self.assertFalse(valid)

        # Private IPv6 / loopback
        valid, msg = BaseScanner.validate_target("http://[::1]")
        self.assertFalse(valid)


class TestRateLimiter(unittest.TestCase):
    def test_rate_limiter_allows_under_limit(self):
        limiter = RateLimiter()
        allowed, retry_after = limiter.is_allowed("test_ip", max_requests=3, window_seconds=60)
        self.assertTrue(allowed)
        self.assertEqual(retry_after, 0)

    def test_rate_limiter_blocks_over_limit(self):
        limiter = RateLimiter()
        key = "test_ip_block"
        for _ in range(3):
            limiter.is_allowed(key, max_requests=3, window_seconds=60)
        
        # 4th request should be blocked
        allowed, retry_after = limiter.is_allowed(key, max_requests=3, window_seconds=60)
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)


class TestRiskEngine(unittest.TestCase):
    def test_compute_risk_score_clean(self):
        score, grade = compute_risk_score([])
        self.assertEqual(score, 0.0)
        self.assertEqual(grade, "A+")

    def test_compute_risk_score_with_findings(self):
        findings = [
            Finding(category="exposure", title="Critical Exposure", severity=Severity.CRITICAL, confidence=0.95),
            Finding(category="authentication", title="Default Creds", severity=Severity.HIGH, confidence=0.9),
        ]
        score, grade = compute_risk_score(findings)
        self.assertGreater(score, 0.0)
        self.assertIn(grade[0], ["A", "B", "C", "D", "E", "F"])


class TestSARIFGenerator(unittest.TestCase):
    def test_generate_sarif_report_format(self):
        scan = ScanResult(
            target_url="https://example.com",
            score=45.0,
            grade="B",
            findings=[
                Finding(category="headers", title="Missing CSP", severity=Severity.MEDIUM, confidence=0.9, remediation="Add CSP header")
            ]
        )
        sarif_str = generate_sarif_report(scan)
        sarif_json = json.loads(sarif_str)

        self.assertEqual(sarif_json["version"], "2.1.0")
        self.assertEqual(sarif_json["runs"][0]["tool"]["driver"]["name"], "SentinelWP")
        self.assertEqual(len(sarif_json["runs"][0]["results"]), 1)
        self.assertEqual(sarif_json["runs"][0]["results"][0]["level"], "warning")


class TestBatchRunner(unittest.TestCase):
    def test_batch_runner_scan_mode(self):
        from scanners.batch_runner import BatchJob, run_batch
        job = BatchJob(targets=["https://example.com"], scan_mode="safe-active")
        self.assertEqual(job.scan_mode, "safe-active")


class TestSetupWizard(unittest.TestCase):
    def test_setup_wizard_flow(self):
        from core import repository
        from core.models import UserRole
        
        # Test count_users
        cnt = repository.count_users()
        self.assertIsInstance(cnt, int)


if __name__ == "__main__":
    unittest.main()
