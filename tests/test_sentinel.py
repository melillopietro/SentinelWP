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


class TestWhoisScanner(unittest.TestCase):
    @patch("scanners.whois_scanner.query_whois_raw")
    def test_whois_scanner_parses_info(self, mock_query):
        mock_query.return_value = "Registrar: NameCheap, Inc.\nRegistry Expiry Date: 2029-01-01T00:00:00Z"
        from scanners.whois_scanner import WhoisScanner
        scanner = WhoisScanner("https://example.com")
        findings = scanner.scan()
        self.assertGreater(len(findings), 0)
        finding = findings[0]
        self.assertEqual(finding.raw_data["registrar"], "NameCheap, Inc.")
        self.assertEqual(finding.raw_data["expiry_date"], "2029-01-01")
        self.assertEqual(finding.raw_data["whois_info"], "NameCheap, Inc. (Expires: 2029-01-01)")

    @patch("scanners.whois_scanner.query_whois_raw")
    def test_whois_scanner_parses_block_format(self, mock_query):
        mock_query.return_value = "Registrar:\n\tName: Aruba S.p.A.\n\tWebsite: http://www.aruba.it"
        from scanners.whois_scanner import WhoisScanner
        scanner = WhoisScanner("https://example.eu")
        findings = scanner.scan()
        self.assertGreater(len(findings), 0)
        finding = findings[0]
        self.assertEqual(finding.raw_data["registrar"], "Aruba S.p.A.")


class TestCSVExport(unittest.TestCase):
    def test_csv_export_endpoint(self):
        from app import app
        from core import repository
        
        with patch.object(repository, "list_scans") as mock_list, \
             patch.object(repository, "get_findings_for_scan") as mock_findings:
             
            from core.models import ScanResult, ScanStatus
            mock_list.return_value = [
                ScanResult(id="123", target_url="https://example.com", status=ScanStatus.COMPLETED, whois_info="NameCheap, Inc. (Expires: 2029-01-01)")
            ]
            mock_findings.return_value = []
            
            app.config["TESTING"] = True
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["user_id"] = "test-user-id"
                    sess["username"] = "test-user"
                    sess["role"] = "admin"
                
                resp = client.get("/scans/export/csv")
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.mimetype, "text/csv")
                csv_data = resp.data.decode("utf-8")
                self.assertIn("Scan ID,Target URL,WHOIS Info", csv_data)
                self.assertIn("https://example.com", csv_data)


class TestSecurityTxtScanner(unittest.TestCase):
    @patch("scanners.base.requests.Session.get")
    def test_security_txt_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Contact: mailto:security@example.com"
        mock_get.return_value = mock_resp
        
        from scanners.security_txt_scanner import SecurityTxtScanner
        scanner = SecurityTxtScanner("https://example.com")
        findings = scanner.scan()
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].title, "Security Policy File (security.txt) Found")

    @patch("scanners.base.requests.Session.get")
    def test_security_txt_missing(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp
        
        from scanners.security_txt_scanner import SecurityTxtScanner
        scanner = SecurityTxtScanner("https://example.com")
        findings = scanner.scan()
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].title, "Missing Security Policy File (security.txt)")


class TestDNSScanner(unittest.TestCase):
    @patch("scanners.base.requests.Session.get")
    def test_dns_scanner_checks_spf_and_dmarc(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Answer": [
                {"type": 16, "data": '"v=spf1 include:_spf.example.com ~all"'},
                {"type": 16, "data": '"v=DMARC1; p=reject; pct=100"'}
            ]
        }
        mock_get.return_value = mock_resp
        
        from scanners.dns_scanner import DNSScanner
        scanner = DNSScanner("https://example.com")
        findings = scanner.scan()
        self.assertGreater(len(findings), 0)
        titles = [f.title for f in findings]
        self.assertTrue(any("SPF" in t for t in titles))
        self.assertTrue(any("DMARC" in t for t in titles))


class TestEOLHeaders(unittest.TestCase):
    @patch("scanners.base.requests.Session.get")
    def test_eol_php_detection(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "X-Powered-By": "PHP/7.4.30",
            "Server": "Apache/2.2.22"
        }
        mock_resp.text = ""
        mock_get.return_value = mock_resp
        
        from scanners.headers_scanner import HeadersScanner
        scanner = HeadersScanner("https://example.com")
        findings = scanner.scan()
        titles = [f.title for f in findings]
        self.assertTrue(any("EOL PHP Version Detected" in t for t in titles))
        self.assertTrue(any("EOL Apache Version Detected" in t for t in titles))


class TestChangelogRoute(unittest.TestCase):
    def test_changelog_route_authenticated(self):
        from app import app
        app.config["TESTING"] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = "test-user-id"
                sess["username"] = "test-user"
                sess["role"] = "admin"
            resp = client.get("/changelog")
            self.assertEqual(resp.status_code, 200)
class TestUpdateChecker(unittest.TestCase):
    @patch("core.update_checker.requests.get")
    @patch("core.update_checker.get_local_commit_hash", return_value="b812559")
    def test_check_for_updates_latest(self, mock_hash, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "sha": "b812559abcdef",
            "commit": {"message": "Test commit", "committer": {"date": "2026-08-11T12:00:00Z"}}
        }
        mock_get.return_value = mock_resp
        
        from core.update_checker import check_for_updates
        res = check_for_updates(force=True)
        self.assertTrue(res["is_latest"])
        self.assertEqual(res["local_commit"], "b812559")
        self.assertEqual(res["remote_commit"], "b812559")

    @patch("core.update_checker.requests.get")
    @patch("core.update_checker.get_local_commit_hash", return_value="a1b2c3d")
    def test_check_for_updates_available(self, mock_hash, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "sha": "b812559abcdef",
            "commit": {"message": "New commit", "committer": {"date": "2026-08-11T12:00:00Z"}}
        }
        mock_get.return_value = mock_resp
        
        from core.update_checker import check_for_updates
        res = check_for_updates(force=True)
        self.assertFalse(res["is_latest"])
        self.assertEqual(res["remote_commit"], "b812559")


class TestPurgeDatabase(unittest.TestCase):
    @patch("core.repository.purge_all_scans_and_findings", return_value=(5, 12))
    def test_purge_db_route_authenticated_admin(self, mock_purge):
        from app import app
        app.config["TESTING"] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = "admin-id"
                sess["username"] = "admin"
                sess["role"] = "admin"
            resp = client.post("/admin/purge-db", data={"confirm_purge": "PURGE"})
            self.assertEqual(resp.status_code, 302)
            mock_purge.assert_called_once()

    def test_purge_db_route_cancelled_without_confirmation(self):
        from app import app
        app.config["TESTING"] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = "admin-id"
                sess["username"] = "admin"
                sess["role"] = "admin"
            resp = client.post("/admin/purge-db", data={"confirm_purge": "NO"})
            self.assertEqual(resp.status_code, 302)


if __name__ == "__main__":
    unittest.main()
