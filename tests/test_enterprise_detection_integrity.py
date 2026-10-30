"""Enterprise detection integrity: FP controls, intel honesty, PHP artifact scanner."""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Severity
from scanners.php_artifact_signatures import analyze_php_artifact
from scanners.php_artifact_scanner import PhpArtifactScanner, default_probe_paths
from scanners.soft404 import response_is_soft_404
from scanners.orchestrator import SCAN_PROFILES


class TestPhpArtifactSignatures(unittest.TestCase):
    def test_legitimate_plugin_header_not_flagged(self):
        body = "<?php\n/**\n * Plugin Name: Example\n */\nfunction foo() { return 1; }\n"
        a = analyze_php_artifact("/wp-content/plugins/example/example.php", body)
        self.assertEqual(a.verdict, "none")

    def test_known_shell_with_obfuscation_flagged(self):
        body = "<?php eval(base64_decode($_POST['x'])); shell_exec($_GET['c']); ?>"
        a = analyze_php_artifact("/wp-content/uploads/shell.php", body)
        self.assertIn(a.verdict, ("indicator", "likely_artifact"))
        self.assertTrue(a.verification_required)
        self.assertGreaterEqual(a.confidence, 0.78)

    def test_html_soft_page_not_flagged(self):
        body = "<!doctype html><html><title>404</title><body>not found</body></html>"
        a = analyze_php_artifact("/shell.php", body)
        self.assertEqual(a.verdict, "none")

    def test_filename_alone_without_php_not_flagged(self):
        a = analyze_php_artifact("/shell.php", "Not Found")
        self.assertEqual(a.verdict, "none")

    def test_branded_shell_ui_flagged(self):
        body = "<?php /* FilesMan WSO 2 */ eval(base64_decode($_POST['a'])); ?>"
        a = analyze_php_artifact("/wso.php", body)
        self.assertIn(a.verdict, ("indicator", "likely_artifact"))
        self.assertIn("known_shell_branding", a.signature_hits)


class TestSoft404Shared(unittest.TestCase):
    def test_themed_404_detected(self):
        resp = MagicMock()
        resp.headers = {"content-type": "text/html"}
        resp.text = "<html><title>Page Not Found</title><body>oops</body></html>"
        self.assertTrue(response_is_soft_404(resp))

    def test_real_php_not_soft404(self):
        resp = MagicMock()
        resp.headers = {"content-type": "text/html"}
        resp.text = "<?php echo 'ok'; ?>"
        self.assertFalse(response_is_soft_404(resp))


class TestPhpArtifactScannerIntegration(unittest.TestCase):
    def test_scanner_in_safe_active_and_full_only(self):
        self.assertIn(PhpArtifactScanner, SCAN_PROFILES["safe-active"])
        self.assertIn(PhpArtifactScanner, SCAN_PROFILES["full"])
        self.assertNotIn(PhpArtifactScanner, SCAN_PROFILES["passive"])

    def test_probe_budget_bounded(self):
        paths = default_probe_paths()
        self.assertLessEqual(len(paths), 24)
        self.assertIn("/shell.php", paths)

    def test_scanner_skips_when_soft404_site(self):
        scanner = PhpArtifactScanner("https://example.com")
        with patch.object(scanner, "is_soft_404", return_value=True):
            with patch.object(scanner, "_get") as mock_get:
                findings = scanner.scan()
        mock_get.assert_not_called()
        self.assertEqual(findings, [])

    def test_scanner_emits_finding_for_webshell_response(self):
        scanner = PhpArtifactScanner("https://example.com")
        malicious = "<?php eval(base64_decode('Z')); passthru($_GET['c']); ?>"
        mock_resp = MagicMock(status_code=200, text=malicious, headers={"Content-Type": "text/html"})

        with patch.object(scanner, "is_soft_404", return_value=False):
            with patch.object(scanner, "_get", return_value=mock_resp):
                with patch("scanners.php_artifact_scanner.response_is_soft_404", return_value=False):
                    findings = scanner.scan()

        compromise = [f for f in findings if f.category == "compromise_indicator"]
        self.assertGreaterEqual(len(compromise), 1)
        self.assertTrue(compromise[0].raw_data.get("verification_required"))
        self.assertTrue(compromise[0].raw_data.get("content_redacted"))
        self.assertIn(compromise[0].severity, (Severity.HIGH, Severity.CRITICAL))
        self.assertIn("not a confirmed compromise", compromise[0].description.lower())
        self.assertFalse(compromise[0].title.lower().startswith("confirmed"))


class TestOsvLocalCorroboration(unittest.TestCase):
    def test_osv_disabled_by_default_skips_network(self):
        from core.models import Finding
        from scanners.vuln_intel import enrich_findings_with_cves

        finding = Finding(
            category="plugins",
            title="Plugin Detected: demo",
            description="test",
            severity=Severity.MEDIUM,
            confidence=0.9,
            raw_data={"slug": "demo-plugin", "version": "1.0.0"},
        )
        with patch("scanners.vuln_intel.lookup_osv_vulnerabilities") as mock_osv:
            with patch("config.OSV_LIVE_ENRICHMENT_ENABLED", False):
                out = enrich_findings_with_cves([finding])[0]
        mock_osv.assert_not_called()
        self.assertEqual(out.confidence, 0.9)

    def test_osv_without_local_corpus_lowers_confidence(self):
        from core.models import Finding
        from scanners.vuln_intel import enrich_findings_with_cves

        finding = Finding(
            category="plugins",
            title="Plugin Detected: demo",
            description="test",
            severity=Severity.MEDIUM,
            confidence=0.9,
            raw_data={"slug": "demo-plugin", "version": "1.0.0"},
        )
        fake_cves = [{"cve_id": "CVE-2099-0001", "summary": "x", "references": []}]

        with patch("scanners.vuln_intel.lookup_osv_vulnerabilities", return_value=fake_cves):
            with patch(
                "core.vulnerability_intelligence.repository.get_vulnerabilities_for_slug",
                return_value=[],
            ):
                with patch("config.OSV_LIVE_ENRICHMENT_ENABLED", True):
                    out = enrich_findings_with_cves([finding])[0]

        self.assertIn("Not corroborated", out.description)
        self.assertLessEqual(out.confidence, 0.75)


class TestScanPipelineAuthoritative(unittest.TestCase):
    def test_version_unknown_is_potential_exposure_not_vulnerability(self):
        from core.models import Finding
        from core.scan_pipeline import apply_vulnerability_intelligence

        plugin_finding = Finding(
            category="plugins",
            title="Plugin Detected: demo",
            description="x",
            severity=Severity.INFO,
            confidence=0.85,
            raw_data={"slug": "vulnerable-plugin", "version": None},
        )
        fake_match = {
            "cve": "CVE-2024-99999",
            "cvss_score": 9.8,
            "plugin_slug": "vulnerable-plugin",
            "slug": "vulnerable-plugin",
            "software_type": "plugin",
            "match_status": "version_unknown",
            "affected_range": "<1.0",
            "detected_version": None,
            "patched_version": "1.0",
            "references": [],
            "kev_listed": False,
        }
        with patch(
            "core.vulnerability_intelligence.service.match_scan_findings",
            return_value=[fake_match],
        ):
            out = apply_vulnerability_intelligence([plugin_finding], "scan-1", None)

        intel = [f for f in out if f.category == "vulnerability_intelligence"]
        self.assertEqual(len(intel), 1)
        self.assertTrue(intel[0].title.startswith("Potential Exposure:"))
        self.assertEqual(intel[0].confidence, 0.6)
        self.assertEqual(intel[0].severity, Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
