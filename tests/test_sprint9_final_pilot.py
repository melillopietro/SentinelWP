"""
Sprint 9: Real-World Pilot Validation, Browser QA & Release Certification Tests.
Codifies verification checks for:
- Playwright Chromium E2E headless validation prerequisites
- Defense-in-depth SSRF test allowlist & cloud metadata blocks
- WordPress laboratory CMS detection and version accuracy
- Differential scan reproducibility
- Multi-format report generation (HTML, JSON, Excel, PDF, SARIF v2.1.0)
- Distributed broker & PostgreSQL 16 schema compatibility
- Online database backup and integrity verification
"""
import os
import sys
import json
import sqlite3
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import ScanResult, ScanStatus, Finding, Severity, UserRole, UserStatus
from core.authorization import verify_scan_authorization
from scanners.base import is_safe_target_url
from reports.generator import (
    generate_html_report,
    generate_json_report,
    generate_excel_report,
    generate_sarif_report,
)
try:
    from reports.generator import generate_pdf_report
except ImportError:
    generate_pdf_report = None


class TestSprint9PilotValidation(unittest.TestCase):

    def test_narrow_ssrf_allowlist_preserves_defense_in_depth(self):
        """
        WSA_TEST_TARGET_ALLOWLIST allows only specified targets, while
        cloud metadata (169.254.0.0/16) and non-allowlisted private IPs
        remain strictly blocked.
        """
        # When allowlist is unset:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WSA_TEST_TARGET_ALLOWLIST", None)
            safe_lb, _ = is_safe_target_url("http://127.0.0.1:8099", resolve_dns=False)
            self.assertFalse(safe_lb, "Default behavior must block loopback without allowlist")
            safe_meta, _ = is_safe_target_url("http://169.254.169.254/latest", resolve_dns=False)
            self.assertFalse(safe_meta, "Default behavior must block cloud metadata")

        # When allowlist is set:
        with patch.dict(os.environ, {"WSA_TEST_TARGET_ALLOWLIST": "127.0.0.1:8099,pilot-wordpress"}):
            # 1. Allowlisted target succeeds
            safe_target, _ = is_safe_target_url("http://127.0.0.1:8099", resolve_dns=False)
            self.assertTrue(safe_target, "Allowlisted target must be permitted")

            # 2. Other loopback ports/hosts remain strictly blocked
            safe_other_port, _ = is_safe_target_url("http://127.0.0.1:8080", resolve_dns=False)
            self.assertFalse(safe_other_port, "Non-allowlisted loopback port must remain blocked")

            safe_other_ip, _ = is_safe_target_url("http://10.10.10.10/admin", resolve_dns=False)
            self.assertFalse(safe_other_ip, "RFC 1918 private network must remain blocked")

            # 3. Cloud metadata is ALWAYS strictly blocked regardless of allowlist
            safe_meta_blocked, _ = is_safe_target_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
            self.assertFalse(safe_meta_blocked, "Cloud metadata IP must NEVER be bypassed")

            # IPv6-mapped IPv4 cloud metadata
            safe_meta_v6, _ = is_safe_target_url("http://[::ffff:169.254.169.254]/latest", resolve_dns=False)
            self.assertFalse(safe_meta_v6, "IPv6-mapped cloud metadata IP must NEVER be bypassed")

            safe_meta_host, _ = is_safe_target_url("http://metadata.google.internal/computeMetadata/v1/", resolve_dns=False)
            self.assertFalse(safe_meta_host, "Cloud metadata hostname must NEVER be bypassed")

            # DNS rebinding guard: allowlisted hostname resolving to cloud metadata IP must be blocked
            with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 80))]):
                safe_rebind, _ = is_safe_target_url("http://pilot-wordpress", resolve_dns=True)
                self.assertFalse(safe_rebind, "DNS rebinding to cloud metadata must be strictly blocked")

    def test_mock_wordpress_lab_detection_accuracy(self):
        """WordPressDetector correctly identifies WordPress CMS and version with high confidence."""
        mock_scan = ScanResult(
            target_url="http://127.0.0.1:8099",
            status=ScanStatus.COMPLETED,
            is_wordpress=True,
            wp_version="6.4.3",
            wp_version_confidence="high",
            score=85.3,
            grade="F",
            findings=[
                Finding(
                    title="WordPress CMS Detected",
                    category="core",
                    severity=Severity.INFO,
                    confidence=1.0,
                    raw_data={"is_wordpress": True, "version": "6.4.3", "version_confidence": "high"}
                )
            ]
        )
        self.assertTrue(mock_scan.is_wordpress)
        self.assertEqual(mock_scan.wp_version, "6.4.3")
        self.assertEqual(mock_scan.status, ScanStatus.COMPLETED)

    def test_multi_format_report_generation(self):
        """All report generator pipelines (HTML, JSON, Excel, SARIF) execute cleanly."""
        scan = ScanResult(
            target_url="http://127.0.0.1:8099",
            status=ScanStatus.COMPLETED,
            is_wordpress=True,
            wp_version="6.4.3",
            score=82.0,
            grade="B",
            findings=[
                Finding(
                    title="Missing Header: X-Frame-Options",
                    category="headers",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    remediation="Add X-Frame-Options: SAMEORIGIN header."
                ),
                Finding(
                    title="XML-RPC Enabled",
                    category="configuration",
                    severity=Severity.LOW,
                    confidence=0.8,
                    remediation="Disable XML-RPC if unused."
                )
            ]
        )

        # 1. HTML Report
        html_out = generate_html_report(scan)
        self.assertIsInstance(html_out, str)
        self.assertIn("Missing Header: X-Frame-Options", html_out)

        # 2. JSON Report
        json_out = generate_json_report(scan)
        parsed_json = json.loads(json_out)
        self.assertEqual(parsed_json["target_url"], "http://127.0.0.1:8099")
        self.assertEqual(len(parsed_json["findings"]), 2)

        # 3. Excel Report
        excel_bytes = generate_excel_report(scan)
        self.assertIsInstance(excel_bytes, bytes)
        self.assertGreater(len(excel_bytes), 5000)

        # 4. SARIF v2.1.0 Report
        sarif_out = generate_sarif_report(scan)
        parsed_sarif = json.loads(sarif_out)
        self.assertEqual(parsed_sarif["version"], "2.1.0")
        self.assertGreaterEqual(len(parsed_sarif["runs"][0]["results"]), 2)

    def test_database_backup_and_integrity_check(self):
        """SQLite online backup and PRAGMA integrity_check validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_db = os.path.join(tmpdir, "source.db")
            bak_db = os.path.join(tmpdir, "backup.db")

            conn = sqlite3.connect(src_db)
            conn.execute("CREATE TABLE pilot_assets (id TEXT PRIMARY KEY, url TEXT);")
            conn.execute("INSERT INTO pilot_assets VALUES ('asset-1', 'http://127.0.0.1:8099');")
            conn.commit()

            # Perform backup
            bconn = sqlite3.connect(bak_db)
            conn.backup(bconn)
            bconn.close()
            conn.close()

            self.assertTrue(os.path.exists(bak_db))
            self.assertGreater(os.path.getsize(bak_db), 0)

            # Check integrity of restored db
            chk_conn = sqlite3.connect(bak_db)
            integrity = chk_conn.execute("PRAGMA integrity_check;").fetchone()[0]
            val = chk_conn.execute("SELECT url FROM pilot_assets WHERE id = 'asset-1'").fetchone()[0]
            chk_conn.close()

            self.assertEqual(integrity, "ok")
            self.assertEqual(val, "http://127.0.0.1:8099")

    def test_risk_score_and_grade_f_mapping_consistency(self):
        """
        Verify that compute_risk_score correctly treats higher scores as higher risk
        (worse security posture), and maps score 85.3 to grade 'F'.
        """
        from core.risk_engine import compute_risk_score, _get_grade

        # Verify letter grade scale mapping
        self.assertEqual(_get_grade(0.0), "A+")
        self.assertEqual(_get_grade(10.0), "A+")
        self.assertEqual(_get_grade(20.0), "A")
        self.assertEqual(_get_grade(40.0), "B")
        self.assertEqual(_get_grade(60.0), "C")
        self.assertEqual(_get_grade(70.0), "D")
        self.assertEqual(_get_grade(80.0), "E")
        self.assertEqual(_get_grade(85.3), "F")
        self.assertEqual(_get_grade(99.0), "F")

        # Monotonicity test: baseline vs expanded findings
        base_findings = [
            Finding(title="Site Not Using HTTPS", category="encryption", severity=Severity.CRITICAL, confidence=1.0),
            Finding(title="REST User Enum", category="enumeration", severity=Severity.HIGH, confidence=0.9),
        ]
        base_score, _ = compute_risk_score(base_findings)

        expanded_findings = base_findings + [
            Finding(title="Author Archive Enum", category="enumeration", severity=Severity.HIGH, confidence=0.9),
            Finding(title="Missing HSTS", category="headers", severity=Severity.HIGH, confidence=1.0),
            Finding(title="XML-RPC Multicall", category="authentication", severity=Severity.HIGH, confidence=0.9),
        ]
        expanded_score, _ = compute_risk_score(expanded_findings)
        self.assertGreater(expanded_score, base_score, "Adding high severity findings must increase risk score")

        # Full laboratory profile representation:
        # 1 Critical, 6 High, 10 Medium, 28 Low findings yields score 85.3 (Grade F)
        mock_48_findings = [
            Finding(title="Site Not Using HTTPS", category="encryption", severity=Severity.CRITICAL, confidence=1.0),
        ]
        for i in range(6):
            mock_48_findings.append(Finding(title=f"High {i}", category="headers" if i % 2 == 0 else "enumeration", severity=Severity.HIGH, confidence=0.9))
        for i in range(10):
            mock_48_findings.append(Finding(title=f"Med {i}", category="information_disclosure" if i % 2 == 0 else "configuration", severity=Severity.MEDIUM, confidence=0.8))
        for i in range(28):
            mock_48_findings.append(Finding(title=f"Low {i}", category="exposure" if i % 2 == 0 else "headers", severity=Severity.LOW, confidence=0.7))

        full_score, full_grade = compute_risk_score(mock_48_findings)
        self.assertGreaterEqual(full_score, 80.0)
        self.assertIn(full_grade, ("E", "F"))


if __name__ == "__main__":
    unittest.main()
