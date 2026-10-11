import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock
from app import app
from core.models import Finding, Severity, ScanResult
from core.risk_engine import compute_risk_score
from reports.generator import _build_executive_summary_details
from scanners.base import BaseScanner, is_safe_target_url
from scanners.orchestrator import SCAN_PROFILES
from scanners.bruteforce_scanner import BruteForceScanner
from scanners.enumeration_scanner import EnumerationScanner
from config import get_validated_secret_key


class TestP0CSRFProtection(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = True
        self.client = app.test_client()

    def _login(self, client, role="analyst"):
        with client.session_transaction() as sess:
            sess["user_id"] = "test-user"
            sess["username"] = "analyst1"
            sess["role"] = role
            sess["_csrf_token"] = "valid-csrf-token-12345"

    def test_post_without_csrf_token_returns_400(self):
        self._login(self.client)
        resp = self.client.post("/schedule/create", data={"targets": "https://example.com"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"CSRF token missing", resp.data)

    def test_post_with_invalid_csrf_token_returns_400(self):
        self._login(self.client)
        resp = self.client.post("/schedule/create", data={
            "targets": "https://example.com",
            "csrf_token": "wrong-token-abc",
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"CSRF token invalid", resp.data)

    def test_post_with_valid_csrf_token_succeeds(self):
        self._login(self.client)
        resp = self.client.post("/schedule/create", data={
            "targets": "https://example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
            "csrf_token": "valid-csrf-token-12345",
        })
        # Should succeed and redirect to schedules
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/schedules", resp.headers["Location"])

    def test_post_with_valid_header_csrf_token_succeeds(self):
        self._login(self.client)
        resp = self.client.post(
            "/schedule/create",
            data={"targets": "https://example.org", "scan_mode": "safe-active", "interval_hours": "24"},
            headers={"X-CSRFToken": "valid-csrf-token-12345"}
        )
        self.assertEqual(resp.status_code, 302)


class TestP0SecretAndSessionHardening(unittest.TestCase):
    @patch.dict(os.environ, {"ENVIRONMENT": "production", "WSA_SECRET_KEY": ""})
    def test_production_rejects_missing_secret_key(self):
        with self.assertRaises(ValueError) as ctx:
            get_validated_secret_key()
        self.assertIn("Production mode requires a secure WSA_SECRET_KEY", str(ctx.exception))

    @patch.dict(os.environ, {"ENVIRONMENT": "production", "WSA_SECRET_KEY": "CHANGE-ME-IN-PRODUCTION-USE-RANDOM-32-BYTES"})
    def test_production_rejects_default_insecure_secret_key(self):
        with self.assertRaises(ValueError) as ctx:
            get_validated_secret_key()
        self.assertIn("Default or weak secrets are strictly rejected", str(ctx.exception))

    @patch.dict(os.environ, {"ENVIRONMENT": "production", "WSA_SECRET_KEY": "short-key"})
    def test_production_rejects_short_secret_key(self):
        with self.assertRaises(ValueError) as ctx:
            get_validated_secret_key()
        self.assertIn("at least 32 characters", str(ctx.exception))

    @patch.dict(os.environ, {"ENVIRONMENT": "development", "WSA_SECRET_KEY": ""})
    def test_development_allows_permissive_key(self):
        key = get_validated_secret_key()
        self.assertTrue(len(key) > 0)

    def test_session_cookie_flags_configured(self):
        self.assertTrue(app.config.get("SESSION_COOKIE_HTTPONLY"))
        self.assertIn(app.config.get("SESSION_COOKIE_SAMESITE"), ("Lax", "Strict", "None"))

    def test_session_regeneration_on_login(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        client = app.test_client()

        # Seed pre-login session state (simulating session fixation attempt)
        with client.session_transaction() as sess:
            sess["attacker_planted_key"] = "compromised_session_data"

        with patch("app.authenticate_login_user") as mock_auth:
            user_mock = MagicMock()
            user_mock.id = "user-123"
            user_mock.username = "legit_user"
            user_mock.role = "analyst"
            user_mock.status = "active"
            user_mock.tenant_id = "default-tenant"
            mock_auth.return_value = user_mock

            resp = client.post("/login", data={"username": "legit_user", "password": "Password123!"})
            self.assertEqual(resp.status_code, 302)

            with client.session_transaction() as sess:
                # Prior pre-login session data must be wiped clean
                self.assertNotIn("attacker_planted_key", sess)
                self.assertEqual(sess["user_id"], "user-123")
                self.assertIn("_csrf_token", sess)


class DummyScanner(BaseScanner):
    def scan(self) -> list:
        return []


class TestP0SSRFAndNetworkSafety(unittest.TestCase):
    def test_ip_literals_blocked(self):
        blocked_targets = [
            "http://127.0.0.1",
            "http://127.0.0.2:8080",
            "http://10.0.0.5",
            "http://172.16.1.1",
            "http://192.168.1.100",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]",
            "http://[fc00::1]",
            "http://[fe80::1]",
            "http://[::ffff:127.0.0.1]",
            "http://0.0.0.0",
        ]
        for url in blocked_targets:
            safe, msg = is_safe_target_url(url, resolve_dns=False)
            self.assertFalse(safe, f"Expected {url} to be blocked by SSRF check, but passed.")

    def test_internal_hostnames_blocked(self):
        blocked_hosts = [
            "http://localhost",
            "http://localhost.localdomain",
            "http://corp.local",
            "http://intranet.internal",
            "http://metadata.google.internal",
            "http://instance-data",
        ]
        for url in blocked_hosts:
            safe, msg = is_safe_target_url(url, resolve_dns=False)
            self.assertFalse(safe, f"Expected hostname {url} to be blocked.")

    @patch("scanners.base.requests.Session.get")
    def test_redirect_to_loopback_blocked(self, mock_get):
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.is_redirect = True
        resp1.headers = {"Location": "http://127.0.0.1:8080/admin"}
        mock_get.return_value = resp1

        scanner = DummyScanner("https://example.org")
        res = scanner._get("https://example.org/test")
        self.assertIsNone(res, "Redirect to 127.0.0.1 was not blocked!")

    @patch("scanners.base.requests.Session.get")
    def test_redirect_to_cloud_metadata_blocked(self, mock_get):
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.is_redirect = True
        resp1.headers = {"Location": "http://169.254.169.254/latest/meta-data"}
        mock_get.return_value = resp1

        scanner = DummyScanner("https://example.org")
        res = scanner._get("https://example.org/test")
        self.assertIsNone(res, "Redirect to cloud metadata 169.254.169.254 was not blocked!")

    @patch("scanners.base.requests.Session.get")
    def test_redirect_to_internal_local_hostname_blocked(self, mock_get):
        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.is_redirect = True
        resp1.headers = {"Location": "http://internal-database.local/dump"}
        mock_get.return_value = resp1

        scanner = DummyScanner("https://example.org")
        res = scanner._get("https://example.org/test")
        self.assertIsNone(res, "Redirect to .local internal hostname was not blocked!")

    @patch("scanners.base.requests.Session.get")
    def test_redirect_to_ipv6_loopback_blocked(self, mock_get):
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.is_redirect = True
        resp1.headers = {"Location": "http://[::1]:8080/secrets"}
        mock_get.return_value = resp1

        scanner = DummyScanner("https://example.org")
        res = scanner._get("https://example.org/test")
        self.assertIsNone(res, "Redirect to IPv6 loopback was not blocked!")


class TestP0CredentialAndPIISafety(unittest.TestCase):
    def test_bruteforce_scanner_excluded_from_full_profile(self):
        full_scanners = SCAN_PROFILES["full"]
        self.assertNotIn(
            BruteForceScanner,
            full_scanners,
            "BruteForceScanner must NOT be part of standard 'full' scan profile!"
        )

    @patch("scanners.base.requests.Session.get")
    @patch("scanners.base.requests.Session.post")
    def test_bruteforce_zero_password_persistence(self, mock_post, mock_get):
        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.is_redirect = False
        mock_get.return_value = get_resp

        post_resp = MagicMock()
        post_resp.status_code = 302
        post_resp.is_redirect = False
        post_resp.headers = {"Location": "https://example.org/wp-admin/"}
        mock_post.return_value = post_resp

        scanner = BruteForceScanner("https://example.org")
        scanner.ALLOW_BRUTEFORCE = True  # Explicit opt-in required since FUNC-003 guard
        findings = scanner.scan()

        self.assertTrue(len(findings) > 0)
        finding = findings[0]

        # Zero plaintext password policy
        raw_str = str(finding.raw_data)
        desc_str = finding.description
        self.assertNotIn("admin:admin", desc_str)
        self.assertNotIn("password", raw_str)
        self.assertNotIn("123456", raw_str)

        self.assertTrue(finding.raw_data.get("credential_control_failed"))
        self.assertIn("account_identifier_hashes", finding.raw_data)
        self.assertGreater(finding.raw_data.get("attempt_count", 0), 0)

    @patch("scanners.base.requests.Session.get")
    def test_enumeration_scanner_pii_minimization(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.is_redirect = False
        mock_resp.json.return_value = [
            {"slug": "johndoe_confidential_login", "name": "John Doe"},
            {"slug": "ceo_admin_account", "name": "Jane Smith"},
        ]
        mock_get.return_value = mock_resp

        scanner = EnumerationScanner("https://example.org")
        scanner._check_rest_api_users()

        self.assertEqual(len(scanner.findings), 1)
        f = scanner.findings[0]

        # Usernames must not be stored in cleartext in description or raw_data
        self.assertNotIn("johndoe_confidential_login", f.description)
        self.assertNotIn("ceo_admin_account", f.description)
        self.assertNotIn("johndoe_confidential_login", str(f.raw_data))

        self.assertEqual(f.raw_data.get("user_count"), 2)
        self.assertTrue(f.raw_data.get("exposure_detected"))
        self.assertTrue(len(f.raw_data.get("pseudonymized_user_hashes", [])) == 2)


class TestP0RiskEngineAndReportMonotonicity(unittest.TestCase):
    def test_risk_score_monotonicity(self):
        # 0 findings = 0.0 risk score (A+)
        score0, grade0 = compute_risk_score([])
        self.assertEqual(score0, 0.0)
        self.assertEqual(grade0, "A+")

        # Adding a low finding increases risk
        f_low = Finding(category="general", title="Low", severity=Severity.LOW, confidence=1.0)
        score_low, _ = compute_risk_score([f_low])
        self.assertGreater(score_low, score0)

        # Adding a high finding increases risk further
        f_high = Finding(category="general", title="High", severity=Severity.HIGH, confidence=1.0)
        score_high, _ = compute_risk_score([f_low, f_high])
        self.assertGreater(score_high, score_low)

        # Adding critical finding increases risk further
        f_crit = Finding(category="general", title="Crit", severity=Severity.CRITICAL, confidence=1.0)
        score_crit, _ = compute_risk_score([f_low, f_high, f_crit])
        self.assertGreater(score_crit, score_high)
        self.assertLessEqual(score_crit, 100.0)

    def test_executive_summary_report_narrative_not_inverted(self):
        # Case 1: Low risk score (10/100, Grade A+) with no critical/high findings
        scan_low = MagicMock()
        scan_low.score = 10.0
        scan_low.grade = "A+"
        scan_low.target_url = "https://clean-site.example.org"
        scan_low.findings = []
        counts_low = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        info_low = _build_executive_summary_details(scan_low, counts_low)
        self.assertEqual(info_low["title"], "STRONG SECURITY POSTURE")

        # Case 2: High risk score (90/100, Grade F) with critical findings
        scan_high = MagicMock()
        scan_high.score = 90.0
        scan_high.grade = "F"
        scan_high.target_url = "https://compromised.example.org"
        scan_high.findings = [MagicMock()]
        counts_high = {"critical": 2, "high": 3, "medium": 1, "low": 0, "info": 0}

        info_high = _build_executive_summary_details(scan_high, counts_high)
        self.assertEqual(info_high["title"], "CRITICAL EXECUTIVE ATTENTION REQUIRED")


class TestP0ObjectLevelAuthorization(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def _login(self, client, role="viewer"):
        with client.session_transaction() as sess:
            sess["user_id"] = "viewer-user"
            sess["username"] = "viewer1"
            sess["role"] = role

    def test_viewer_blocked_from_deleting_scan(self):
        self._login(self.client, role="viewer")
        resp = self.client.post("/scan/scan-123/delete")
        self.assertEqual(resp.status_code, 403)

    def test_viewer_blocked_from_creating_schedule(self):
        self._login(self.client, role="viewer")
        resp = self.client.post("/schedule/create", data={"targets": "https://example.org"})
        self.assertEqual(resp.status_code, 403)

    def test_viewer_blocked_from_editing_finding(self):
        self._login(self.client, role="viewer")
        resp = self.client.post("/finding/finding-123/edit", data={"title": "tampered"})
        self.assertEqual(resp.status_code, 403)

    def test_viewer_blocked_from_deleting_finding(self):
        self._login(self.client, role="viewer")
        resp = self.client.post("/finding/finding-123/delete")
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
