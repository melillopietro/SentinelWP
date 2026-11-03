"""
Post-remediation assertions for the 11 accuracy / false-positive vectors,
user enumeration usernames, scan API v1, and finding-title catalog.
"""
import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from core import repository
from core.models import (
    Asset,
    Finding,
    ScanAuthorization,
    ScanResult,
    ScanStatus,
    Severity,
    Tenant,
    User,
    UserRole,
    UserStatus,
)
from core.scan_pipeline import apply_vulnerability_intelligence
from scanners.cookie_scanner import CookieSecurityScanner
from scanners.db_export_scanner import DBExportScanner
from scanners.enumeration_scanner import EnumerationScanner
from scanners.exposure_scanner import ExposureScanner
from scanners.headers_scanner import HeadersScanner
from scanners.plugin_scanner import PluginScanner
from scanners.theme_scanner import ThemeScanner, DEFAULT_THEMES
from scanners.waf_scanner import WAFScanner
from scanners.wp_detector import WordPressDetector


def _resp(status=200, text="", headers=None, content=None, url=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = content if content is not None else text.encode("utf-8")
    r.headers = headers or {"content-type": "text/html"}
    r.cookies = []
    r.url = url or "https://example.com/"
    r.history = []
    r.json = MagicMock(side_effect=lambda: json.loads(text) if text.strip().startswith(("[", "{")) else (_ for _ in ()).throw(ValueError()))
    return r


class TestFPRemediationVectors(unittest.TestCase):
    def test_v1_wp_detector_rejects_prose_wp_content(self):
        html = "<html><body>We migrated our blog from /wp-content/ to Hugo.</body></html>"
        det = WordPressDetector("https://example.com")
        with patch.object(det, "_get", return_value=_resp(200, html)):
            result = det.detect()
        self.assertFalse(result.detected)

    def test_v1_wp_detector_accepts_attribute_wp_content_with_second_signal(self):
        html = (
            '<html><head><link rel="https://api.w.org/" href="https://example.com/wp-json/"/></head>'
            '<body><img src="/wp-content/uploads/x.png"/></body></html>'
        )
        det = WordPressDetector("https://example.com")
        with patch.object(det, "_get", return_value=_resp(200, html, headers={"link": ""})):
            result = det.detect()
        # wp_content 0.15 + rest_api_link 0.15 = 0.30 >= 0.25 OR 2 signals
        self.assertTrue(result.detected)

    def test_v2_plugin_global_403_does_not_flood(self):
        scanner = PluginScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True

        def head(url):
            if "/wp-content/plugins/" in url:
                return _resp(403, headers={"content-type": "text/html"})
            return _resp(404)

        with patch.object(scanner, "_head", side_effect=head), \
             patch.object(scanner, "_get_plugin_version_from_readme", return_value=None):
            scanner._active_enumerate()
        plugin_findings = [f for f in scanner.findings if f.title.startswith("Plugin Detected:")]
        self.assertEqual(len(plugin_findings), 0)

    def test_v3_theme_catchall_200_without_theme_name_skipped(self):
        scanner = ThemeScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True
        with patch.object(scanner, "_get", return_value=_resp(200, "/* generic css */ body{color:red}")):
            scanner._probe_default_themes()
        self.assertEqual(len([f for f in scanner.findings if "Default Theme" in f.title]), 0)

    def test_v3_theme_real_style_css_accepted(self):
        scanner = ThemeScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True
        css = "Theme Name: Twenty Twenty-Four\nVersion: 1.2\n"
        with patch.object(scanner, "_get", return_value=_resp(200, css, headers={"content-type": "text/css"})):
            scanner._probe_default_themes()
        self.assertEqual(len([f for f in scanner.findings if "Default Theme" in f.title]), len(DEFAULT_THEMES))

    def test_v4_install_php_prose_not_critical(self):
        scanner = ExposureScanner("https://example.com")
        html = "<html><body>Learn how to install and setup our software product.</body></html>"
        with patch.object(scanner, "_get", return_value=_resp(200, html)):
            scanner._check_install_php()
        titles = [f.title for f in scanner.findings]
        self.assertNotIn("WordPress Installation Page Exposed", titles)

    def test_v4_install_php_real_setup_detected(self):
        scanner = ExposureScanner("https://example.com")
        html = '<html><body><form id="setup"><input name="weblog_title"/></form></body></html>'
        with patch.object(scanner, "_get", return_value=_resp(200, html)):
            scanner._check_install_php()
        self.assertTrue(any(f.title == "WordPress Installation Page Exposed" for f in scanner.findings))

    def test_v5_enumeration_css_author_bio_not_username(self):
        scanner = EnumerationScanner("https://example.com")

        def get(url, **kwargs):
            if "author=" in url:
                return _resp(200, '<div class="post author-bio">About the writer</div>')
            if url.endswith("/feed/"):
                return _resp(404)
            return _resp(404)

        with patch.object(scanner, "_get", side_effect=get):
            scanner._check_author_archives()
        self.assertEqual(len(scanner.findings), 0)

    def test_v5_enumeration_shows_usernames(self):
        scanner = EnumerationScanner("https://example.com")
        users_json = json.dumps([
            {"id": 1, "slug": "alice", "name": "Alice"},
            {"id": 2, "slug": "bob", "name": "Bob"},
        ])

        def get(url, **kwargs):
            if "/wp-json/wp/v2/users" in url and "rest_route" not in url:
                r = _resp(200, users_json, headers={"content-type": "application/json"})
                r.json = MagicMock(return_value=json.loads(users_json))
                return r
            return _resp(404)

        with patch.object(scanner, "_get", side_effect=get):
            scanner._check_rest_api_users()
        self.assertEqual(len(scanner.findings), 1)
        f = scanner.findings[0]
        self.assertIn("alice", f.description)
        self.assertIn("bob", f.description)
        self.assertEqual(f.raw_data.get("usernames"), ["alice", "bob"])

    def test_v7_db_export_requires_magic_bytes(self):
        scanner = DBExportScanner("https://example.com")

        def head(url):
            return _resp(200, headers={"content-type": "application/octet-stream", "content-length": "5000"})

        def get(url, **kwargs):
            return _resp(200, content=b"\x00\x01\x02not-a-backup", headers={"content-type": "application/octet-stream"})

        with patch.object(scanner, "_head", side_effect=head), \
             patch.object(scanner, "_get", side_effect=get):
            scanner._check_db_exports()
        self.assertEqual(len(scanner.findings), 0)

    def test_v7_db_export_sql_dump_detected(self):
        scanner = DBExportScanner("https://example.com")
        sample = b"-- MySQL dump 10.13\nCREATE TABLE wp_users (\n"

        def head(url):
            if url.endswith("dump.sql"):
                return _resp(200, headers={"content-type": "application/sql", "content-length": "9999"})
            return _resp(404)

        def get(url, **kwargs):
            if url.endswith("dump.sql"):
                return _resp(200, content=sample, headers={"content-type": "application/sql"})
            return _resp(404)

        with patch.object(scanner, "_head", side_effect=head), \
             patch.object(scanner, "_get", side_effect=get):
            scanner._check_db_exports()
        self.assertTrue(any("Database Backup Exposed" in f.title for f in scanner.findings))

    def test_v8_waf_no_contradiction(self):
        scanner = WAFScanner("https://example.com")

        def get(url, **kwargs):
            if "<script>" in url:
                return _resp(403)
            return _resp(200, "<html></html>", headers={"server": "nginx"})

        with patch.object(scanner, "_get", side_effect=get):
            scanner._detect_waf()
        titles = [f.title for f in scanner.findings]
        self.assertIn("WAF Actively Blocking Malicious Requests", titles)
        self.assertNotIn("No WAF Detected", titles)

    def test_v9_headers_php_prose_not_flagged(self):
        scanner = HeadersScanner("https://example.com")
        html = "<html><body>Notice: our store is closed today for inventory.</body></html>"
        with patch.object(scanner, "_get", return_value=_resp(200, html, headers={
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
        })):
            scanner.scan()
        self.assertFalse(any("PHP Error" in f.title for f in scanner.findings))
        self.assertFalse(any("X-XSS-Protection" in f.title for f in scanner.findings))

    def test_v10_cookie_httponly_session_vs_functional(self):
        scanner = CookieSecurityScanner("https://example.com")
        # Force unique cookies via patched extract
        fake = {
            "wordpress_logged_in_abc": {
                "name": "wordpress_logged_in_abc", "secure": True, "httponly": False,
                "samesite": True, "samesite_value": "Lax",
            },
            "cookie_notice_accepted": {
                "name": "cookie_notice_accepted", "secure": True, "httponly": False,
                "samesite": True, "samesite_value": "Lax",
            },
        }
        with patch.object(scanner, "_get", return_value=_resp(200)), \
             patch.object(scanner, "_extract_cookies", return_value=list(fake.values())):
            # Re-run logic by calling scan but inject unique via wrapping
            findings_before = len(scanner.findings)
            # Manually exercise the same grouping by calling scan with patched unique path
            # Easiest: patch scan internals after extract
            resp = _resp(200)
            with patch.object(scanner, "_extract_cookies", return_value=list(fake.values())):
                # Call the middle of scan by setting up like scan()
                scanner.findings = []
                unique = fake
                missing_httponly = [c for c in unique.values() if not c["httponly"]]
                self.assertEqual(len(missing_httponly), 2)
        # Direct scan with cookies on response jar is hard; assert helper classification via titles by running partial
        scanner2 = CookieSecurityScanner("https://example.com")
        jar_cookie_session = MagicMock()
        jar_cookie_session.name = "wordpress_logged_in_x"
        jar_cookie_session.value = "1"
        jar_cookie_session.has_nonstandard_attr = lambda a: a.lower() == "secure"
        jar_cookie_func = MagicMock()
        jar_cookie_func.name = "cookie_notice_accepted"
        jar_cookie_func.value = "1"
        jar_cookie_func.has_nonstandard_attr = lambda a: a.lower() == "secure"

        resp = _resp(200)
        resp.cookies = [jar_cookie_session, jar_cookie_func]
        # _extract_cookies uses requests cookie attrs — patch extract to return our fake list
        with patch.object(scanner2, "_get", return_value=resp), \
             patch.object(scanner2, "_extract_cookies", return_value=[
                 {"name": "wordpress_logged_in_x", "domain": "example.com", "path": "/",
                  "secure": True, "httponly": False, "samesite": True, "samesite_value": "Lax"},
                 {"name": "cookie_notice_accepted", "domain": "example.com", "path": "/",
                  "secure": True, "httponly": False, "samesite": True, "samesite_value": "Lax"},
             ]):
            scanner2.scan()
        titles = [f.title for f in scanner2.findings]
        self.assertIn("Session Cookies Missing HttpOnly Flag", titles)
        self.assertIn("Non-Session Cookies Missing HttpOnly Flag", titles)
        self.assertNotIn("Cookies Missing HttpOnly Flag", titles)

    def test_v11_version_unknown_consolidated(self):
        findings = [
            Finding(
                scan_id="s1",
                category="plugins",
                title="Plugin Detected: woocommerce",
                description="x",
                severity=Severity.INFO,
                confidence=0.9,
                raw_data={"slug": "woocommerce", "version": None, "type": "plugin"},
            )
        ]
        fake_matches = [
            {
                "cve": f"CVE-2018-{i:04d}",
                "match_status": "version_unknown",
                "plugin_slug": "woocommerce",
                "cvss_score": 9.8,
                "kev_listed": False,
            }
            for i in range(40)
        ]
        with patch("core.vulnerability_intelligence.service.match_scan_findings", return_value=fake_matches):
            out = apply_vulnerability_intelligence(findings, "s1", None)
        intel = [f for f in out if f.category == "vulnerability_intelligence"]
        self.assertEqual(len(intel), 1)
        self.assertIn("Component Version Unverified", intel[0].title)
        self.assertEqual(intel[0].severity, Severity.LOW)
        self.assertLessEqual(intel[0].confidence, 0.5)


class TestScanAPIv1AndCatalog(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        repository.init_db(force=True)
        self.tenant_id = "default-tenant"
        repository.save_tenant(Tenant(id=self.tenant_id, name="Default", slug="default"))
        self.admin = User(
            id="api-admin-1",
            tenant_id=self.tenant_id,
            username="api_admin",
            password_hash="x",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        repository.save_user(self.admin)

    def _login(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin.id
            sess["username"] = self.admin.username
            sess["role"] = "admin"
            sess["tenant_id"] = self.tenant_id

    def test_finding_titles_endpoint(self):
        self._login()
        resp = self.client.get("/api/v1/finding-titles")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data.get("count", 0), 20)
        self.assertTrue(any("Author Archive" in (t.get("title_template") or "") for t in data["titles"]))

    def test_create_and_get_scan_api(self):
        self._login()
        with patch("app.start_async_scan") as mock_start, \
             patch("app.SCAN_EXECUTION_BACKEND", "thread"):
            mock_start.return_value = None
            resp = self.client.post(
                "/api/v1/scans",
                json={"target_url": "https://scan-api.example.com", "scan_mode": "passive"},
            )
        self.assertIn(resp.status_code, (202, 200))
        body = resp.get_json()
        self.assertIn("scan_id", body)
        scan_id = body["scan_id"]

        # Seed a completed scan with enumeration finding including usernames
        scan = repository.get_scan(scan_id, tenant_id=self.tenant_id)
        scan.status = ScanStatus.COMPLETED
        scan.score = 10
        scan.grade = "A"
        repository.save_scan(scan)
        f = Finding(
            scan_id=scan_id,
            tenant_id=self.tenant_id,
            asset_id=scan.asset_id,
            category="enumeration",
            title="REST API User Enumeration",
            description="Detected 2 public user account(s): alice, bob.",
            severity=Severity.HIGH,
            confidence=0.95,
            raw_data={"usernames": ["alice", "bob"], "user_count": 2},
        )
        repository.save_finding(f)

        resp = self.client.get(f"/api/v1/scans/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["scan_id"], scan_id)
        self.assertGreaterEqual(data["findings_count"], 1)
        enum = next(x for x in data["findings"] if "User Enumeration" in x["title"])
        self.assertEqual(enum["usernames"], ["alice", "bob"])

    def test_catalog_file_exists(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "vulnerability_finding_titles.json")
        self.assertTrue(os.path.isfile(path))
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertGreaterEqual(data["count"], 20)


if __name__ == "__main__":
    unittest.main()
