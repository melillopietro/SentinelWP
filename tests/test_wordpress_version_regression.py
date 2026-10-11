"""
Automated Regression and Validation Test Suite for WordPress Version Fingerprinting.

Verifies:
1. WordPressDetector multi-signal detection and core version fingerprinting:
   - Meta generator in various attribute orders (standard, reversed, prerelease RC1)
   - Meta generator without version (detects WP, sets version to Unknown)
   - Core assets in /wp-includes/ (block-library, wp-embed, emoji) without meta generator
   - Immunity against jQuery (3.7.1) or theme (1.0) version pollution
   - RSS feed generator tag (/feed/)
   - Documentation file (/readme.html)
   - REST API discovery (/wp-json/)
   - Non-WordPress target (clean negative detection)
2. Scan Profiles Parity:
   - PASSIVE, SAFE-ACTIVE, and FULL profiles all run WordPressDetector and detect WP version
3. Orchestrator & Async Runner integrity:
   - Theme and Plugin scanner findings never overwrite or steal core WP version
4. Persistence and Data Flow:
   - SQLite and SQLAlchemy database roundtrips for is_wordpress, wp_version, source, confidence
   - Celery worker (run_scan_task) execution and Asset 360 metadata enrichment
5. Vulnerability Intelligence & UI/Report generation:
   - Core CVE matching receiving clean version
   - HTML, JSON, Excel, and PDF reports correctly displaying status
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import json
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from scanners.wp_detector import WordPressDetector
from scanners.orchestrator import run_scan, ScanOrchestrator, SCAN_PROFILES
from scanners.async_runner import start_async_scan, _execute_async_scan
from core.models import (
    ScanResult, ScanStatus, Finding, Severity, Asset,
    ScanJob, ScanJobStatus, ScheduledScan, User, UserRole, UserStatus
)
from core import repository
from core.db.session import get_session_factory
from core.db.repositories.scan_repo import ScanRepository
from reports.generator import (
    generate_html_report,
    generate_json_report,
    generate_excel_report,
    generate_pdf_report,
)


class TestWordPressDetectorDirect(unittest.TestCase):
    """Direct unit tests for WordPressDetector multi-signal and version extraction."""

    def setUp(self):
        self.dns_patcher = patch("scanners.base.is_safe_target_url", return_value=(True, ""))
        self.dns_patcher.start()

    def tearDown(self):
        self.dns_patcher.stop()

    def test_meta_generator_standard(self):
        """Standard meta generator: <meta name="generator" content="WordPress 6.7.2">"""
        detector = WordPressDetector("https://wp.example.com")
        mock_resp = MagicMock()
        mock_resp.text = '<html><head><meta name="generator" content="WordPress 6.7.2" /></head><body></body></html>'
        mock_resp.cookies = []
        mock_resp.headers = {}
        mock_resp.url = "https://wp.example.com/"

        with patch.object(detector, "_get", return_value=mock_resp), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        self.assertTrue(len(findings) >= 2)
        cms_finding = next(f for f in findings if f.title == "WordPress CMS Detected")
        self.assertTrue(cms_finding.raw_data["is_wordpress"])
        self.assertEqual(cms_finding.raw_data["version"], "6.7.2")
        self.assertEqual(cms_finding.raw_data["version_source"], "meta_generator")
        self.assertEqual(cms_finding.raw_data["version_confidence"], "high")

        ver_finding = next(f for f in findings if "WordPress Version Exposed" in f.title)
        self.assertEqual(ver_finding.raw_data["version"], "6.7.2")

    def test_meta_generator_reversed_attributes_and_prerelease(self):
        """Reversed attributes order and prerelease version: <meta content="WordPress 6.8.2-RC1" name="generator">"""
        detector = WordPressDetector("https://wp.example.com")
        mock_resp = MagicMock()
        mock_resp.text = '<html><head><meta content="WordPress 6.8.2-RC1" name="generator"></head><body></body></html>'
        mock_resp.cookies = []
        mock_resp.headers = {}
        mock_resp.url = "https://wp.example.com"

        with patch.object(detector, "_get", return_value=mock_resp), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        cms_finding = next(f for f in findings if f.title == "WordPress CMS Detected")
        self.assertTrue(cms_finding.raw_data["is_wordpress"])
        self.assertEqual(cms_finding.raw_data["version"], "6.8.2-RC1")
        self.assertEqual(cms_finding.raw_data["version_source"], "meta_generator")

    def test_meta_generator_without_version(self):
        """Meta generator without explicit version: <meta name="generator" content="WordPress">"""
        detector = WordPressDetector("https://wp.example.com")
        mock_resp = MagicMock()
        mock_resp.text = '<html><head><meta name="generator" content="WordPress"></head><body><div class="test"></div></body></html>'
        mock_resp.cookies = []
        mock_resp.headers = {}
        mock_resp.url = "https://wp.example.com"

        with patch.object(detector, "_get", return_value=mock_resp), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        cms_finding = next(f for f in findings if f.title == "WordPress CMS Detected")
        self.assertTrue(cms_finding.raw_data["is_wordpress"])
        # Should be None on detector finding; orchestrator will normalize to 'Unknown'
        self.assertIsNone(cms_finding.raw_data["version"])
        self.assertFalse(any("WordPress Version Exposed" in f.title for f in findings))

    def test_core_asset_block_library_without_generator(self):
        """Modern WordPress: meta generator hidden, version fingerprinted via block-library CSS in /wp-includes/."""
        detector = WordPressDetector("https://wp.example.com")
        mock_resp = MagicMock()
        mock_resp.text = """
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="https://wp.example.com/wp-content/themes/custom/style.css?ver=1.0.0" />
            <link rel="stylesheet" id="wp-block-library-css" href="https://wp.example.com/wp-includes/css/dist/block-library/style.min.css?ver=6.8.2" media="all" />
            <script src="https://wp.example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
        </head>
        <body class="home">
            <img src="/wp-content/uploads/2026/01/logo.png" />
        </body>
        </html>
        """
        mock_resp.cookies = []
        mock_resp.headers = {}
        mock_resp.url = "https://wp.example.com"

        with patch.object(detector, "_get", return_value=mock_resp), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        cms_finding = next(f for f in findings if f.title == "WordPress CMS Detected")
        self.assertTrue(cms_finding.raw_data["is_wordpress"])
        # Crucial test: must detect 6.8.2, NOT jQuery 3.7.1 or theme 1.0.0!
        self.assertEqual(cms_finding.raw_data["version"], "6.8.2")
        self.assertEqual(cms_finding.raw_data["version_source"], "asset_ver_param")

    def test_core_asset_emoji_and_embed(self):
        """Core version detection via wp-embed and wp-emoji-release in /wp-includes/."""
        detector = WordPressDetector("https://wp.example.com")
        mock_resp = MagicMock()
        mock_resp.text = """
        <html>
        <head>
            <link rel="https://api.w.org/" href="https://wp.example.com/wp-json/" />
            <script>
            window._wpemojiSettings = {"concatemoji":"https:\\/\\/wp.example.com\\/wp-includes\\/js\\/wp-emoji-release.min.js?ver=6.7.1"};
            </script>
        </head>
        <body>
            <script src="/wp-includes/js/wp-embed.min.js?ver=6.7.1"></script>
        </body>
        </html>
        """
        mock_resp.cookies = []
        mock_resp.headers = {}
        mock_resp.url = "https://wp.example.com"

        with patch.object(detector, "_get", return_value=mock_resp), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        cms_finding = next(f for f in findings if f.title == "WordPress CMS Detected")
        self.assertTrue(cms_finding.raw_data["is_wordpress"])
        self.assertEqual(cms_finding.raw_data["version"], "6.7.1")

    def test_rss_feed_fallback(self):
        """Core version detected via /feed/ generator tag."""
        detector = WordPressDetector("https://wp.example.com")

        home_resp = MagicMock()
        home_resp.text = '<html><head><link rel="alternate" type="application/rss+xml" href="https://wp.example.com/feed/" /></head><body><div class="content">/wp-content/</div></body></html>'
        home_resp.cookies = []
        home_resp.headers = {}
        home_resp.url = "https://wp.example.com"

        feed_resp = MagicMock()
        feed_resp.status_code = 200
        feed_resp.text = """<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>Test WP Blog</title>
                <generator>https://wordpress.org/?v=6.8.0</generator>
            </channel>
        </rss>
        """

        def mock_get(url, **kwargs):
            if "feed" in url:
                return feed_resp
            return home_resp

        with patch.object(detector, "_get", side_effect=mock_get), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        cms_finding = next(f for f in findings if f.title == "WordPress CMS Detected")
        self.assertTrue(cms_finding.raw_data["is_wordpress"])
        self.assertEqual(cms_finding.raw_data["version"], "6.8.0")
        self.assertEqual(cms_finding.raw_data["version_source"], "rss_feed")

    def test_readme_html_fallback(self):
        """Core version detected via /readme.html."""
        detector = WordPressDetector("https://wp.example.com")

        home_resp = MagicMock()
        home_resp.text = '<html><body>/wp-content/uploads/</body></html>'
        home_resp.cookies = []
        home_resp.headers = {}
        home_resp.url = "https://wp.example.com"

        readme_resp = MagicMock()
        readme_resp.status_code = 200
        readme_resp.text = """
        <!DOCTYPE html>
        <html>
        <head><title>WordPress &rsaquo; Readme</title></head>
        <body>
        <h1 id="logo">WordPress</h1>
        <br /> Version 6.6.1
        </body>
        </html>
        """

        def mock_get(url, **kwargs):
            if "readme.html" in url:
                return readme_resp
            return home_resp

        with patch.object(detector, "_get", side_effect=mock_get), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        cms_finding = next(f for f in findings if f.title == "WordPress CMS Detected")
        self.assertTrue(cms_finding.raw_data["is_wordpress"])
        self.assertEqual(cms_finding.raw_data["version"], "6.6.1")
        self.assertEqual(cms_finding.raw_data["version_source"], "readme_html")

    def test_non_wordpress_target(self):
        """Clean static HTML or non-WordPress target."""
        detector = WordPressDetector("https://static.example.com")
        mock_resp = MagicMock()
        mock_resp.text = "<html><head><title>Static Site</title></head><body><h1>Welcome to My Hugo Site</h1></body></html>"
        mock_resp.cookies = []
        mock_resp.headers = {}
        mock_resp.url = "https://static.example.com"

        with patch.object(detector, "_get", return_value=mock_resp), \
             patch.object(detector, "_head", return_value=None):
            findings = detector.scan()

        self.assertEqual(len(findings), 0)

    def test_precedence_policy_hierarchy(self):
        """
        Documented precedence policy: meta_generator > rss_feed > asset_ver_param > readme_html > rest_api.
        When multiple candidate versions are detected from distinct sources, the highest precedence wins.
        """
        detector = WordPressDetector("https://wp.example.com")
        mock_home = MagicMock()
        mock_home.url = "https://wp.example.com/"
        mock_home.cookies = []
        mock_home.headers = {}
        # Page contains: meta generator (6.8.2) AND block library (6.8.0) AND feed link
        mock_home.text = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.8.2" />
            <link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.8.0" />
            <link rel="alternate" type="application/rss+xml" href="https://wp.example.com/feed/" />
        </head>
        <body></body>
        </html>
        """
        feed_resp = MagicMock()
        feed_resp.status_code = 200
        feed_resp.text = '<rss><channel><generator>https://wordpress.org/?v=6.8.1</generator></channel></rss>'

        readme_resp = MagicMock()
        readme_resp.status_code = 200
        readme_resp.text = '<h1>WordPress</h1><br /> Version 6.7.9'

        def mock_get(url, **kwargs):
            if "feed" in url:
                return feed_resp
            elif "readme.html" in url:
                return readme_resp
            return mock_home

        with patch.object(detector, "_get", side_effect=mock_get), \
             patch.object(detector, "_head", return_value=None):
            result = detector.detect()

        self.assertTrue(result.detected)
        # Meta generator (6.8.2) has highest precedence
        self.assertEqual(result.version, "6.8.2")
        self.assertEqual(result.version_source, "meta_generator")

        # Now remove meta generator: feed (6.8.1) vs asset_ver (6.8.0) vs readme (6.7.9) -> feed wins
        mock_home.text = """
        <html>
        <head>
            <link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.8.0" />
            <link rel="alternate" type="application/rss+xml" href="https://wp.example.com/feed/" />
        </head>
        <body></body>
        </html>
        """
        with patch.object(detector, "_get", side_effect=mock_get), \
             patch.object(detector, "_head", return_value=None):
            result_no_meta = detector.detect()

        self.assertTrue(result_no_meta.detected)
        self.assertEqual(result_no_meta.version, "6.8.1")
        self.assertEqual(result_no_meta.version_source, "rss_feed")

    def test_redirect_followed_updates_base_url(self):
        """When initial URL redirects (e.g. 301 http -> https), base_url must update."""
        detector = WordPressDetector("http://wp.example.com")
        mock_resp = MagicMock()
        mock_resp.text = '<html><head><meta name="generator" content="WordPress 6.8.2" /></head><body></body></html>'
        mock_resp.cookies = []
        mock_resp.headers = {}
        mock_resp.url = "https://wp.example.com/blog/"

        with patch.object(detector, "_get", return_value=mock_resp), \
             patch.object(detector, "_head", return_value=None):
            result = detector.detect()

        self.assertTrue(result.detected)
        self.assertEqual(result.version, "6.8.2")
        self.assertEqual(result.base_url, "https://wp.example.com/blog")


class TestOrchestratorAndProfilesParity(unittest.TestCase):
    """Verifies that orchestrator handles WordPress version correctly across all 3 scan profiles."""

    def setUp(self):
        self.dns_patcher = patch("scanners.base.is_safe_target_url", return_value=(True, ""))
        self.dns_patcher.start()

    def tearDown(self):
        self.dns_patcher.stop()

    def test_all_three_profiles_contain_wp_detector_as_first_scanner(self):
        """Verify SCAN_PROFILES for passive, safe-active, and full all have WordPressDetector."""
        for profile in ("passive", "safe-active", "full"):
            scanners = SCAN_PROFILES[profile]
            self.assertIn(WordPressDetector, scanners, f"{profile} must contain WordPressDetector")
            self.assertEqual(scanners[0], WordPressDetector, f"WordPressDetector must be first scanner in {profile}")

    def test_orchestrator_protection_against_theme_and_plugin_version_stealing(self):
        """
        Verify orchestrator does NOT steal theme version or plugin version when WP version is Unknown.
        """
        # Construct findings as if WordPress was detected without version, but theme and plugin were found
        wp_finding = Finding(
            title="WordPress CMS Detected",
            category="information_disclosure",
            severity=Severity.INFO,
            raw_data={
                "is_wordpress": True,
                "wp_confidence": 0.35,
                "evidence": ["HTML references /wp-content/"],
                "version": None,
                "version_source": None,
                "version_confidence": None,
            }
        )
        theme_finding = Finding(
            title="Theme Identified: twentytwentyfour",
            category="information_disclosure",
            severity=Severity.INFO,
            raw_data={"theme": "twentytwentyfour", "version": "1.1", "method": "passive"}
        )
        plugin_finding = Finding(
            title="Plugin Detected: akismet",
            category="plugins",
            severity=Severity.INFO,
            raw_data={"plugin": "akismet", "version": "5.3"}
        )

        mock_scanner = MagicMock()
        mock_scanner.return_value.scan.return_value = [wp_finding, theme_finding, plugin_finding]

        with patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")):
            scan = run_scan(
                "https://wp.example.com",
                scan_mode="passive",
                scanner_classes=[mock_scanner],
                persist=False,
            )

        self.assertTrue(scan.is_wordpress)
        # MUST remain 'Unknown' and not get hijacked by theme '1.1' or plugin '5.3'!
        self.assertEqual(scan.wp_version, "Unknown")
        self.assertIsNone(scan.wp_version_source)

    def test_orchestrator_propagates_detected_core_version_and_source(self):
        """Verify orchestrator properly sets scan.wp_version, wp_version_source, and wp_version_confidence."""
        wp_finding = Finding(
            title="WordPress CMS Detected",
            category="information_disclosure",
            severity=Severity.INFO,
            raw_data={
                "is_wordpress": True,
                "wp_confidence": 0.85,
                "version": "6.8.2",
                "version_source": "asset_ver_param",
                "version_confidence": "high",
            }
        )
        wp_exp_finding = Finding(
            title="WordPress Version Exposed: 6.8.2",
            category="information_disclosure",
            severity=Severity.MEDIUM,
            raw_data={"is_wordpress": True, "version": "6.8.2", "source": "asset_ver_param"}
        )

        mock_scanner = MagicMock()
        mock_scanner.return_value.scan.return_value = [wp_finding, wp_exp_finding]

        with patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")):
            scan = run_scan(
                "https://wp.example.com",
                scan_mode="safe-active",
                scanner_classes=[mock_scanner],
                persist=False,
            )

        self.assertTrue(scan.is_wordpress)
        self.assertEqual(scan.wp_version, "6.8.2")
        self.assertEqual(scan.wp_version_source, "asset_ver_param")
        self.assertEqual(scan.wp_version_confidence, "high")

    def test_orchestrator_non_wordpress_sets_not_wordpress(self):
        """Verify orchestrator sets scan.is_wordpress=False and scan.wp_version='Not WordPress'."""
        info_finding = Finding(
            title="TLS Security Verified",
            category="tls",
            severity=Severity.INFO,
            raw_data={"tls_version": "TLSv1.3"}
        )
        mock_scanner = MagicMock()
        mock_scanner.return_value.scan.return_value = [info_finding]

        with patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")):
            scan = run_scan(
                "https://static.example.com",
                scan_mode="passive",
                scanner_classes=[mock_scanner],
                persist=False,
            )

        self.assertFalse(scan.is_wordpress)
        self.assertEqual(scan.wp_version, "Not WordPress")

    def test_three_profiles_end_to_end_detection_parity(self):
        """Verify that passive, safe-active, and full profiles all detect WordPress 6.8.2."""
        wp_finding = Finding(
            title="WordPress CMS Detected",
            category="information_disclosure",
            severity=Severity.INFO,
            raw_data={
                "is_wordpress": True,
                "wp_confidence": 0.95,
                "version": "6.8.2",
                "version_source": "meta_generator",
                "version_confidence": "high",
            }
        )
        for profile in ("passive", "safe-active", "full"):
            with patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")):
                orchestrator = ScanOrchestrator(
                    target_url="https://wp.example.com",
                    scan_mode=profile
                )
                with patch.object(WordPressDetector, "scan", return_value=[wp_finding]), \
                     patch("scanners.vuln_intel.enrich_findings_with_cves", side_effect=lambda x: x):
                    completed = orchestrator.run()

                self.assertTrue(completed.wordpress_detected)
                self.assertTrue(completed.is_wordpress)
                self.assertEqual(completed.wordpress_version, "6.8.2")
                self.assertEqual(completed.wp_version, "6.8.2")
                self.assertEqual(completed.wordpress_version_source, "meta_generator")
                self.assertEqual(completed.wordpress_version_confidence, "high")


class TestPersistenceAndDatabase(unittest.TestCase):
    """Verify SQLite and SQLAlchemy models and repositories persist and restore WP detection fields."""

    def test_sqlite_repository_save_and_get_scan(self):
        """Verify repository.save_scan and repository.get_scan roundtrip in SQLite."""
        repository.init_db()
        test_scan = ScanResult(
            target_url="https://wp.persist.example.com",
            scan_mode="safe-active",
            status=ScanStatus.COMPLETED,
            is_wordpress=True,
            wp_version="6.8.2",
            wp_version_source="asset_ver_param",
            wp_version_confidence="high",
            tenant_id="default-tenant",
        )
        repository.save_scan(test_scan)

        loaded = repository.get_scan(test_scan.id, tenant_id="default-tenant")
        self.assertIsNotNone(loaded)
        self.assertTrue(loaded.is_wordpress)
        self.assertEqual(loaded.wp_version, "6.8.2")
        self.assertEqual(loaded.wp_version_source, "asset_ver_param")
        self.assertEqual(loaded.wp_version_confidence, "high")

    def test_sqlalchemy_scan_repository_save_and_get(self):
        """Verify SQLAlchemy ScanRepository save and retrieval roundtrip."""
        factory = get_session_factory()
        with factory() as session:
            repo = ScanRepository(session)
            test_scan = ScanResult(
                target_url="https://wp.sa.example.com",
                scan_mode="full",
                status=ScanStatus.COMPLETED,
                is_wordpress=True,
                wp_version="6.7.1",
                wp_version_source="meta_generator",
                wp_version_confidence="high",
                tenant_id="default-tenant",
            )
            repo.save_scan(test_scan)
            session.commit()

            loaded = repo.get_by_id(test_scan.id, tenant_id="default-tenant")
            self.assertIsNotNone(loaded)
            self.assertTrue(loaded.is_wordpress)
            self.assertTrue(loaded.wordpress_detected)
            self.assertEqual(loaded.wp_version, "6.7.1")
            self.assertEqual(loaded.wordpress_version, "6.7.1")
            self.assertEqual(loaded.wp_version_source, "meta_generator")
            self.assertEqual(loaded.wordpress_version_source, "meta_generator")
            self.assertEqual(loaded.wp_version_confidence, "high")
            self.assertEqual(loaded.wordpress_version_confidence, "high")

    def test_sqlite_update_scan_does_not_wipe_wordpress_version(self):
        """Verify update_scan updating status/score preserves detected WordPress version."""
        repository.init_db()
        test_scan = ScanResult(
            target_url="https://wp.update.example.com",
            scan_mode="passive",
            status=ScanStatus.RUNNING,
            is_wordpress=True,
            wordpress_detected=True,
            wp_version="6.8.2",
            wordpress_version="6.8.2",
            wp_version_source="asset_ver_param",
            wordpress_version_source="asset_ver_param",
            tenant_id="default-tenant",
        )
        repository.save_scan(test_scan)

        # Update status and score only (as orchestrator or celery worker does during progress)
        repository.update_scan(
            test_scan.id,
            tenant_id="default-tenant",
            status=ScanStatus.COMPLETED,
            score=15.0,
            grade="A",
        )

        loaded = repository.get_scan(test_scan.id, tenant_id="default-tenant")
        self.assertIsNotNone(loaded)
        self.assertTrue(loaded.wordpress_detected)
        self.assertTrue(loaded.is_wordpress)
        self.assertEqual(loaded.wordpress_version, "6.8.2")
        self.assertEqual(loaded.wp_version, "6.8.2")
        self.assertEqual(loaded.wordpress_version_source, "asset_ver_param")

    def test_save_findings_bulk_preserves_scan_metadata(self):
        """Verify saving findings for a scan does not modify or wipe scan WordPress detection."""
        repository.init_db()
        test_scan = ScanResult(
            target_url="https://wp.findings.example.com",
            scan_mode="safe-active",
            status=ScanStatus.COMPLETED,
            is_wordpress=True,
            wordpress_detected=True,
            wp_version="6.8.2",
            wordpress_version="6.8.2",
            tenant_id="default-tenant",
        )
        repository.save_scan(test_scan)

        test_finding = Finding(
            scan_id=test_scan.id,
            category="information_disclosure",
            title="WordPress Version Exposed: 6.8.2",
            severity=Severity.MEDIUM,
            tenant_id="default-tenant",
        )
        repository.save_findings_bulk([test_finding])

        loaded = repository.get_scan(test_scan.id, tenant_id="default-tenant")
        self.assertIsNotNone(loaded)
        self.assertTrue(loaded.wordpress_detected)
        self.assertEqual(loaded.wordpress_version, "6.8.2")
        self.assertEqual(len(loaded.findings), 1)
        self.assertEqual(loaded.findings[0].title, "WordPress Version Exposed: 6.8.2")


class TestReportsAndUIFormatting(unittest.TestCase):
    """Verify HTML, JSON, Excel, and PDF reports render clean WordPress metadata."""

    def setUp(self):
        self.scan_detected = ScanResult(
            target_url="https://wp.example.com",
            scan_mode="safe-active",
            status=ScanStatus.COMPLETED,
            score=25.0,
            grade="B",
            is_wordpress=True,
            wp_version="6.8.2",
            wp_version_source="asset_ver_param",
            wp_version_confidence="high",
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

        self.scan_unknown = ScanResult(
            target_url="https://wp.unknown.example.com",
            scan_mode="passive",
            status=ScanStatus.COMPLETED,
            score=10.0,
            grade="A",
            is_wordpress=True,
            wp_version="Unknown",
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

        self.scan_not_wp = ScanResult(
            target_url="https://static.example.com",
            scan_mode="passive",
            status=ScanStatus.COMPLETED,
            score=0.0,
            grade="A+",
            is_wordpress=False,
            wp_version="Not WordPress",
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

    def test_html_report_formatting(self):
        html_detected = generate_html_report(self.scan_detected)
        self.assertIn("6.8.2", html_detected)

        html_not_wp = generate_html_report(self.scan_not_wp)
        self.assertIn("Not WordPress", html_not_wp)

    def test_json_report_formatting(self):
        json_str = generate_json_report(self.scan_detected)
        data = json.loads(json_str)
        self.assertTrue(data["is_wordpress"])
        self.assertEqual(data["wp_version"], "6.8.2")
        self.assertEqual(data["wp_version_source"], "asset_ver_param")

        json_str_not = generate_json_report(self.scan_not_wp)
        data_not = json.loads(json_str_not)
        self.assertFalse(data_not["is_wordpress"])
        self.assertEqual(data_not["wp_version"], "Not WordPress")

    def test_excel_report_formatting(self):
        excel_bytes = generate_excel_report(self.scan_detected)
        self.assertTrue(len(excel_bytes) > 100)

    def test_pdf_report_formatting(self):
        pdf_bytes = generate_pdf_report(self.scan_detected)
        self.assertTrue(len(pdf_bytes) > 100)


class TestVulnerabilityIntelligenceIntegration(unittest.TestCase):
    """Verify that Vulnerability Intelligence service handles clean core version."""

    def test_match_scan_findings_ignores_not_wordpress(self):
        from core.vulnerability_intelligence.service import match_scan_findings
        # Should not query core vulns or fail if target is not WordPress
        matches = match_scan_findings("Not WordPress", [])
        self.assertEqual(len(matches), 0)

    def test_match_scan_findings_with_valid_core_version(self):
        from core.vulnerability_intelligence.service import match_scan_findings
        # With valid version 6.0 and empty plugin list, should execute without exception
        matches = match_scan_findings("6.0", [])
        self.assertIsInstance(matches, list)


class TestCeleryWorkerAndAsset360(unittest.TestCase):
    """Verify Celery scan worker execution and Asset 360 CMS metadata derivation."""

    def setUp(self):
        repository.init_db()
        from app import app as flask_app
        flask_app.config["TESTING"] = True
        flask_app.config["WTF_CSRF_ENABLED"] = False
        # Fresh CI runners have no users; before_request redirects to /setup (302).
        if repository.count_users() == 0:
            repository.save_user(
                User(
                    id="test-analyst",
                    tenant_id="default-tenant",
                    username="wp_regression_analyst",
                    password_hash="pbkdf2:test",
                    role="analyst",
                    status="active",
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            )

    def test_celery_worker_persists_wordpress_metadata_and_updates_asset_tags(self):
        """Worker executing run_scan_task persists wordpress_version='6.8.2' and enriches Asset tags."""
        from core.tasks.scan_tasks import run_scan_task
        
        asset = Asset(
            tenant_id="default-tenant",
            canonical_url="https://wp.celery.example.com",
            hostname="wp.celery.example.com",
            tags="production",
            status="active"
        )
        repository.save_asset(asset)

        scan = ScanResult(
            tenant_id="default-tenant",
            asset_id=asset.id,
            target_url="https://wp.celery.example.com",
            scan_mode="passive",
            status=ScanStatus.PENDING,
        )
        repository.save_scan(scan)

        job = ScanJob(
            tenant_id="default-tenant",
            asset_id=asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.QUEUED.value,
            profile="passive",
        )
        repository.create_scan_job(job)

        mock_completed = ScanResult(
            id=scan.id,
            tenant_id="default-tenant",
            asset_id=asset.id,
            target_url="https://wp.celery.example.com",
            status=ScanStatus.COMPLETED,
            score=20.0,
            grade="B",
            wordpress_detected=True,
            wordpress_version="6.8.2",
            wordpress_version_source="asset_ver_param",
            wordpress_version_confidence="high",
        )

        with patch("core.tasks.scan_tasks.ScanOrchestrator") as mock_orch_cls, \
             patch("core.tasks.scan_tasks.process_scan_findings", return_value=[]), \
             patch("core.tasks.scan_tasks.verify_scan_authorization", return_value=(True, "", None)), \
             patch("core.tasks.scan_tasks.count_active_scan_jobs_global", return_value=0):
            mock_orch_inst = mock_orch_cls.return_value
            mock_orch_inst.run.return_value = mock_completed

            # Run worker task synchronously
            success = run_scan_task.run(job.id)

        self.assertTrue(success)
        loaded_scan = repository.get_scan(scan.id, tenant_id="default-tenant")
        self.assertIsNotNone(loaded_scan)
        self.assertTrue(loaded_scan.wordpress_detected)
        self.assertTrue(loaded_scan.is_wordpress)
        self.assertEqual(loaded_scan.wordpress_version, "6.8.2")
        self.assertEqual(loaded_scan.wp_version, "6.8.2")
        self.assertEqual(loaded_scan.wordpress_version_source, "asset_ver_param")

        loaded_asset = repository.get_asset(asset.id, tenant_id="default-tenant")
        self.assertIsNotNone(loaded_asset)
        self.assertIn("wordpress", loaded_asset.tags)
        self.assertIn("wp-6.8.2", loaded_asset.tags)

    def test_asset_detail_derives_cms_from_latest_completed_scan(self):
        """Asset 360 view renders CMS Platform and version from the latest completed scan."""
        import app as flask_app_module
        
        asset = Asset(
            tenant_id="default-tenant",
            canonical_url="https://wp.360.example.com",
            hostname="wp.360.example.com",
            display_name="WP 360 Asset",
            status="active"
        )
        repository.save_asset(asset)

        scan = ScanResult(
            tenant_id="default-tenant",
            asset_id=asset.id,
            target_url="https://wp.360.example.com",
            scan_mode="passive",
            status=ScanStatus.COMPLETED,
            wordpress_detected=True,
            wordpress_version="6.8.2",
            wordpress_version_source="meta_generator",
            wordpress_version_confidence="high",
        )
        repository.save_scan(scan)

        app = flask_app_module.app
        app.config["TESTING"] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = "test-analyst"
                sess["username"] = "analyst"
                sess["role"] = "analyst"
                sess["tenant_id"] = "default-tenant"

            resp = client.get(f"/asset/{asset.id}")
            self.assertEqual(resp.status_code, 200)
            body = resp.get_data(as_text=True)
            self.assertIn("WordPress", body)
            self.assertIn("v6.8.2", body)


class TestBatchAndScheduledScans(unittest.TestCase):
    """Verify batch scans and scheduled scan triggers retain WordPress version metadata."""

    def setUp(self):
        repository.init_db()

    def test_scheduled_and_batch_scans_preserve_detection_fields(self):
        """Verify scheduled scan creation and linked scan result preserve detection metadata."""
        sched = ScheduledScan(
            target_url="https://wp.batch.example.com",
            scan_mode="passive",
            interval_hours=24,
            tenant_id="default-tenant",
        )
        repository.save_scheduled_scan(sched)

        loaded_sched = repository.get_scheduled_scan(sched.id, tenant_id="default-tenant")
        self.assertIsNotNone(loaded_sched)
        self.assertEqual(loaded_sched.target_url, "https://wp.batch.example.com")

        # Emulate a run triggered for this schedule
        scan = ScanResult(
            tenant_id="default-tenant",
            target_url=sched.target_url,
            scan_mode=sched.scan_mode,
            status=ScanStatus.COMPLETED,
            wordpress_detected=True,
            wordpress_version="6.8.2",
            wordpress_version_source="asset_ver_param",
            wordpress_version_confidence="high",
        )
        repository.save_scan(scan)

        loaded_scan = repository.get_scan(scan.id, tenant_id="default-tenant")
        self.assertTrue(loaded_scan.wordpress_detected)
        self.assertEqual(loaded_scan.wordpress_version, "6.8.2")
        self.assertEqual(loaded_scan.wp_version, "6.8.2")


if __name__ == "__main__":
    unittest.main()
