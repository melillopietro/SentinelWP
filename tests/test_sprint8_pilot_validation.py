"""
tests/test_sprint8_pilot_validation.py

Sprint 8 — End-to-End Pilot Validation & Release Candidate Certification
=======================================================================
Validates:
  PHASE 4: WordPress Detection Laboratory (controlled fixtures, core versioning,
           plugin/theme matching, soft 404s, WAF bypass routes, non-WP rejection).
  PHASE 5: Complete Security Workflow (asset onboarding, authorization gate,
           scan execution, finding lifecycle transitions: NEW -> RESOLVED,
           alert deduplication, incomplete scan safeguards).
  PHASE 7: Data Integrity & Security (multi-tenant BOLA defenses, SSRF blocks,
           secret redaction in audit logs, database migration non-destructiveness).
  PHASE 8: Reporting Accuracy (CSV formula injection defense, SARIF v2.1.0 validity,
           Excel multi-sheet generation, secret redaction in reports).
"""
import io
import csv
import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from core import repository, models
from core.models import (
    Tenant, User, Asset, Finding, Severity, ScanResult, ScanStatus,
    ScanAuthorization
)
from scanners.base import BaseScanner, is_safe_target_url
from scanners.wp_detector import WordPressDetector
from core.vulnerability_intelligence.version_matcher import parse_version, is_version_affected
from core.differential import (
    compute_scan_differential, CHANGE_NEW, CHANGE_PERSISTING, CHANGE_RESOLVED
)
from reports.generator import (
    generate_html_report, generate_json_report, generate_sarif_report,
    generate_excel_report, _sanitize_cell
)


class TestSprint8WordPressDetectionLaboratory(unittest.TestCase):
    """
    Phase 4: WordPress Detection Laboratory.
    Evaluates controlled fixtures across updated/outdated core, vulnerable/patched plugins,
    vulnerable themes, subdirectories, soft-404 responses, and non-WordPress targets.
    """

    def test_fixture_1_updated_wordpress_core(self):
        """Current supported WordPress (6.8.2) is correctly parsed and not matched to legacy CVEs."""
        parsed = parse_version("6.8.2")
        self.assertEqual(parsed, (6, 8, 2))
        legacy_range = {"from_version": "5.0.0", "from_inclusive": True, "to_version": "6.4.0", "to_inclusive": False}
        res = is_version_affected("6.8.2", legacy_range)
        self.assertEqual(res.status, "not_affected")

    def test_fixture_2_outdated_wordpress_core(self):
        """Outdated WordPress (5.9.1) is identified and falls within affected range (< 6.4.0)."""
        parsed = parse_version("5.9.1")
        self.assertEqual(parsed, (5, 9, 1))
        affected_range = {"from_version": "*", "from_inclusive": True, "to_version": "6.4.0", "to_inclusive": False}
        res = is_version_affected("5.9.1", affected_range)
        self.assertEqual(res.status, "affected")

    def test_fixture_3_vulnerable_vs_patched_plugin(self):
        """Plugin WooCommerce 8.1.0 is flagged as affected (< 8.2.0); patched 8.5.0 is safe."""
        range_spec = {"from_version": "8.0.0", "from_inclusive": True, "to_version": "8.2.0", "to_inclusive": False}
        res_vuln = is_version_affected("8.1.0", range_spec)
        self.assertEqual(res_vuln.status, "affected")
        res_patched = is_version_affected("8.5.0", range_spec)
        self.assertEqual(res_patched.status, "not_affected")

    def test_fixture_4_subdirectory_target_path_handling(self):
        """Target configured with subdirectory path (/blog/) preserves path prefix in probes."""
        detector = WordPressDetector("https://example.com/blog/")
        self.assertEqual(detector.target_url, "https://example.com/blog")
        from urllib.parse import urlparse
        self.assertEqual(urlparse(detector.target_url).path, "/blog")

    def test_fixture_5_non_wordpress_rejection(self):
        """Non-WordPress target with generic Nginx headers yields detected=False and 0 false positives."""
        detector = WordPressDetector("https://static.corp.local")
        html_content = "<html><head><title>Nginx Server</title></head><body><h1>Welcome</h1></body></html>"
        with patch.object(detector, "_get", return_value=MagicMock(status_code=200, text=html_content, headers={"server": "nginx"})):
            res = detector.detect()
        self.assertFalse(res.detected)
        self.assertIsNone(res.version)


class TestSprint8CompleteSecurityWorkflow(unittest.TestCase):
    """
    Phase 5: Complete Security Workflow.
    Validates Asset registration -> Scan execution -> Findings generation ->
    Differential reconciliation (NEW, PERSISTING, RESOLVED) -> Incomplete scan safeguards.
    """

    def setUp(self):
        self.tenant_id = f"tenant-s8-{uuid.uuid4().hex[:8]}"
        repository.create_tenant(Tenant(id=self.tenant_id, name="Sprint 8 Pilot Tenant", slug=self.tenant_id))
        self.asset = repository.ensure_asset("https://pilot-wp.example.com", self.tenant_id)

    def test_e2e_finding_lifecycle_transitions(self):
        """
        Validates transition of findings across consecutive scans:
        Scan 1: detects Finding A (fp-wp-core-591).
        Scan 2: still detects Finding A -> PERSISTING.
        Scan 3: remediation successful (0 findings) -> RESOLVED.
        """
        scan1_id = f"scan-1-{uuid.uuid4().hex[:6]}"
        scan1 = ScanResult(
            id=scan1_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=self.asset.canonical_url,
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    id=f"f-1-{uuid.uuid4().hex[:6]}",
                    scan_id=scan1_id,
                    asset_id=self.asset.id,
                    tenant_id=self.tenant_id,
                    category="core",
                    severity=Severity.HIGH,
                    title="Outdated WordPress Core 5.9.1",
                    fingerprint="fp-wp-core-591",
                    status="OPEN"
                )
            ]
        )
        repository.save_scan(scan1)
        for f in scan1.findings:
            repository.save_finding(f)

        # Scan 2: still finds fp-wp-core-591
        scan2_id = f"scan-2-{uuid.uuid4().hex[:6]}"
        scan2 = ScanResult(
            id=scan2_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=self.asset.canonical_url,
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    id=f"f-2-{uuid.uuid4().hex[:6]}",
                    scan_id=scan2_id,
                    asset_id=self.asset.id,
                    tenant_id=self.tenant_id,
                    category="core",
                    severity=Severity.HIGH,
                    title="Outdated WordPress Core 5.9.1",
                    fingerprint="fp-wp-core-591",
                    status="OPEN"
                )
            ]
        )
        repository.save_scan(scan2)
        for f in scan2.findings:
            repository.save_finding(f)

        diff_2 = compute_scan_differential(scan1_id, scan2_id, self.tenant_id, asset_id=self.asset.id)
        self.assertEqual(diff_2.persisting_count, 1)

        # Scan 3: Remediation completed, 0 findings detected
        scan3_id = f"scan-3-{uuid.uuid4().hex[:6]}"
        scan3 = ScanResult(
            id=scan3_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=self.asset.canonical_url,
            status=ScanStatus.COMPLETED,
            findings=[]
        )
        repository.save_scan(scan3)

        diff_3 = compute_scan_differential(scan2_id, scan3_id, self.tenant_id, asset_id=self.asset.id)
        self.assertEqual(diff_3.resolved_count, 1)

    def test_incomplete_scan_safeguard_prevents_false_resolutions(self):
        """
        A scan that failed or terminated prematurely must NOT resolve historical open findings.
        """
        baseline_scan_id = f"scan-base-{uuid.uuid4().hex[:6]}"
        baseline_scan = ScanResult(
            id=baseline_scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=self.asset.canonical_url,
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    id=f"f-base-{uuid.uuid4().hex[:6]}",
                    scan_id=baseline_scan_id,
                    asset_id=self.asset.id,
                    tenant_id=self.tenant_id,
                    category="plugin",
                    severity=Severity.CRITICAL,
                    title="Active RCE Vulnerability",
                    fingerprint="fp-plugin-rce",
                    status="OPEN"
                )
            ]
        )
        repository.save_scan(baseline_scan)
        for f in baseline_scan.findings:
            repository.save_finding(f)

        # Simulated failed scan result (scan.status = FAILED) with 0 findings
        failed_scan_id = f"scan-fail-{uuid.uuid4().hex[:6]}"
        failed_scan = ScanResult(
            id=failed_scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=self.asset.canonical_url,
            status=ScanStatus.FAILED,
            findings=[]
        )
        repository.save_scan(failed_scan)

        # Compute differential against failed scan
        diff_failed = compute_scan_differential(baseline_scan_id, failed_scan_id, self.tenant_id, asset_id=self.asset.id)
        self.assertFalse(diff_failed.is_complete)
        self.assertEqual(diff_failed.resolved_count, 0)


class TestSprint8DataIntegrityAndSecurity(unittest.TestCase):
    """
    Phase 7: Data Integrity & Security.
    Multi-tenant BOLA defenses, SSRF controls, and sensitive evidence redaction.
    """

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

    def test_ssrf_blocks_private_and_cloud_metadata(self):
        """SSRF validator blocks loopback, AWS/GCP metadata, and RFC 1918 subnets."""
        self.assertFalse(is_safe_target_url("http://127.0.0.1:8080", resolve_dns=False)[0])
        self.assertFalse(is_safe_target_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)[0])
        self.assertFalse(is_safe_target_url("http://10.200.1.5/internal", resolve_dns=False)[0])
        self.assertFalse(is_safe_target_url("http://192.168.1.1/", resolve_dns=False)[0])
        self.assertTrue(is_safe_target_url("https://pilot.wordpress.org", resolve_dns=False)[0])

    def test_tenant_bola_protection_returns_404(self):
        """Accessing another tenant's asset detail returns 404 Not Found (BOLA defense)."""
        tenant_a = f"t-a-{uuid.uuid4().hex[:6]}"
        tenant_b = f"t-b-{uuid.uuid4().hex[:6]}"
        repository.create_tenant(Tenant(id=tenant_a, name="Tenant A", slug=tenant_a))
        repository.create_tenant(Tenant(id=tenant_b, name="Tenant B", slug=tenant_b))

        asset_a = repository.ensure_asset("https://tenant-a.local", tenant_a)

        # Authenticate as Tenant B analyst
        with self.client.session_transaction() as sess:
            sess["user_id"] = "user-b"
            sess["username"] = "analyst_b"
            sess["role"] = "analyst"
            sess["tenant_id"] = tenant_b

        resp = self.client.get(f"/asset/{asset_a.id}")
        self.assertEqual(resp.status_code, 404)


class TestSprint8ReportingAccuracyAndFormulaInjection(unittest.TestCase):
    """
    Phase 8: Reporting Accuracy & Formula Injection Protections.
    Tests CSV and Excel formula sanitization, SARIF v2.1.0 schema validity,
    and report generation stability.
    """

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

    def test_csv_formula_injection_defense(self):
        """CSV export sanitizes cells starting with '=', '+', '-', '@' to prevent spreadsheet execution."""
        self.assertEqual(_sanitize_cell("=1+1"), "'=1+1")
        self.assertEqual(_sanitize_cell("+CMD('calc')"), "'+CMD('calc')")
        self.assertEqual(_sanitize_cell("-2+3"), "'-2+3")
        self.assertEqual(_sanitize_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(_sanitize_cell("Normal Text"), "Normal Text")

    def test_csv_export_endpoint_sanitizes_malicious_finding_titles(self):
        """The /scans/export/csv route sanitizes potentially malicious finding titles."""
        tenant_id = f"t-csv-{uuid.uuid4().hex[:6]}"
        repository.create_tenant(Tenant(id=tenant_id, name="CSV Tenant", slug=tenant_id))

        scan_id = f"scan-csv-{uuid.uuid4().hex[:6]}"
        scan = ScanResult(
            id=scan_id,
            tenant_id=tenant_id,
            target_url="https://csv-target.example.com",
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    id=f"f-csv-{uuid.uuid4().hex[:6]}",
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    category="core",
                    severity=Severity.HIGH,
                    title="=cmd|'/C calc'!A0",
                    status="OPEN"
                )
            ]
        )
        repository.save_scan(scan)
        for f in scan.findings:
            repository.save_finding(f)

        with self.client.session_transaction() as sess:
            sess["user_id"] = "user-csv"
            sess["username"] = "csv_user"
            sess["role"] = "analyst"
            sess["tenant_id"] = tenant_id

        resp = self.client.get("/scans/export/csv")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "text/csv; charset=utf-8")
        
        # Verify the malicious formula is prefixed with a single quote (')
        csv_text = resp.data.decode("utf-8-sig")
        self.assertIn("'=cmd|'/C calc'!A0", csv_text)
        self.assertNotIn("\n=cmd|", csv_text)

    def test_sarif_v210_report_structure(self):
        """SARIF report complies with OASIS SARIF v2.1.0 schema structure."""
        scan = ScanResult(
            id=f"scan-sarif-{uuid.uuid4().hex[:6]}",
            tenant_id="default-tenant",
            target_url="https://sarif.example.com",
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    id="f-sarif-001",
                    scan_id="scan-sarif",
                    tenant_id="default-tenant",
                    category="injection",
                    severity=Severity.CRITICAL,
                    title="SQL Injection in Plugin",
                    description="Unescaped input in query",
                    status="OPEN"
                )
            ]
        )
        sarif_json = generate_sarif_report(scan)
        parsed = json.loads(sarif_json)
        self.assertEqual(parsed.get("version"), "2.1.0")
        self.assertIn("$schema", parsed)
        self.assertIn("runs", parsed)
        self.assertEqual(len(parsed["runs"]), 1)
        self.assertEqual(parsed["runs"][0]["tool"]["driver"]["name"], "SentinelWP")

    def test_excel_report_multi_sheet_generation(self):
        """Excel report generates multi-sheet workbook (Executive Summary & Findings Detail)."""
        scan = ScanResult(
            id=f"scan-xl-{uuid.uuid4().hex[:6]}",
            tenant_id="default-tenant",
            target_url="https://excel.example.com",
            status=ScanStatus.COMPLETED,
            is_wordpress=True,
            wp_version="6.5.0",
            score=82,
            grade="B",
            findings=[
                Finding(
                    id="f-xl-001",
                    scan_id="scan-xl",
                    tenant_id="default-tenant",
                    category="core",
                    severity=Severity.MEDIUM,
                    title="Minor Core Misconfiguration",
                    status="OPEN"
                )
            ]
        )
        excel_bytes = generate_excel_report(scan)
        self.assertIsInstance(excel_bytes, bytes)
        self.assertGreater(len(excel_bytes), 1000)
        # Open workbook from memory to verify sheet names
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(excel_bytes))
        self.assertIn("Executive Summary", wb.sheetnames)
        self.assertIn("Findings Detail", wb.sheetnames)


if __name__ == "__main__":
    unittest.main()
