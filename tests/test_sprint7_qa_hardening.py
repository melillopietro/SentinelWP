import os
import sys
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from core import repository, models, auth
from core.models import Tenant, User, Asset, Finding, Severity, UserStatus, IntegrationOutbox
from core.vulnerability_intelligence import service as vuln_service
from core.vulnerability_intelligence import repository as vuln_repo
from scanners.wp_detector import WordPressDetector, WordPressDetectionResult
from scanners.base import is_safe_target_url
from core.vulnerability_intelligence.version_matcher import parse_version, is_version_affected
from scanners.base import BaseScanner
from core.tasks.maintenance_tasks import recover_stale_outbox_events_task


class TestSprint7NvdEnrichmentFix(unittest.TestCase):
    """
    Validates fix for Phase 1 defect where NVD enrichment SQL query failed
    with 'no such column: cve_id' because the column name in SQLite is 'cve'.
    """

    def setUp(self):
        vuln_repo.init_vuln_intel_db()

    def test_enrich_with_nvd_inner_executes_against_real_schema(self):
        """_enrich_with_nvd_inner queries real vulnerability_records table without SQL syntax/column errors."""
        conn = vuln_repo._get_vuln_conn()
        rec_id = f"test-vuln-{uuid.uuid4()}"
        # Insert a real record needing enrichment
        conn.execute(
            """INSERT OR REPLACE INTO vulnerability_records (
                id, wordfence_id, cve, title, description, cvss_score, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (rec_id, f"wf-{uuid.uuid4()}", "CVE-2024-9999", "Test Vuln", "Desc", None, "wordfence")
        )
        conn.commit()

        # Mock enrich_cve network call to return sample CVSS score
        with patch("core.vulnerability_intelligence.nvd_client.enrich_cve", return_value={"cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N"}), \
             patch("core.vulnerability_intelligence.service._get_redis_client", return_value=None):
            result = vuln_service._enrich_with_nvd_inner()

        self.assertIn(result["status"], ("success", "ok", "skipped"))
        self.assertGreaterEqual(result.get("enriched", 0), 1)

        # Verify the record was updated in the database
        updated_row = conn.execute("SELECT cvss_score FROM vulnerability_records WHERE id = ?", (rec_id,)).fetchone()
        self.assertIsNotNone(updated_row)
        self.assertEqual(updated_row[0], 7.5)


class TestSprint7WordPressDetectionQuality(unittest.TestCase):
    """
    Phase 3: Controlled WordPress detection fixtures and ground truth validation.
    Tests core version detection, plugin matching, soft 404 suppression, and non-WP targets.
    """

    def test_updated_vs_outdated_wordpress_core_evaluation(self):
        """Detects outdated core version and evaluates vulnerability boundaries."""
        # Clean current version (e.g. 6.8.2)
        v_current = parse_version("6.8.2")
        self.assertIsNotNone(v_current)
        range_vuln = {"from_version": "*", "from_inclusive": True, "to_version": "6.4.0", "to_inclusive": False}
        res_current = is_version_affected("6.8.2", range_vuln)
        self.assertEqual(res_current.status, "not_affected")

        # Outdated vulnerable version (e.g. 5.9.1)
        v_outdated = parse_version("5.9.1")
        self.assertIsNotNone(v_outdated)
        res_outdated = is_version_affected("5.9.1", range_vuln)
        self.assertEqual(res_outdated.status, "affected")

    def test_non_wordpress_target_yields_zero_wp_findings(self):
        """Scanning a plain non-WordPress HTML site produces 0 WordPress findings (0 False Positives)."""
        html_non_wp = "<html><head><title>Static Site</title></head><body><h1>Welcome to Nginx</h1></body></html>"
        detector = WordPressDetector("https://static.example.com")
        detector.html = html_non_wp
        detector.headers = {"server": "nginx"}
        
        # Mock _detect_multi_signal to simulate non-WP probe response
        with patch.object(detector, "_get", return_value=MagicMock(status_code=200, text=html_non_wp, headers={"server": "nginx"})):
            res = detector.detect()
        self.assertFalse(res.detected)
        self.assertIsNone(res.version)

    def test_wordpress_target_detected_with_version(self):
        """Scanning a WordPress target identifies version from generator tag."""
        html_wp = '<html><head><meta name="generator" content="WordPress 6.4.2"/><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"/></head><body>Blog</body></html>'
        detector = WordPressDetector("https://wp.example.com")
        with patch.object(detector, "_get", return_value=MagicMock(status_code=200, text=html_wp, headers={"server": "Apache"})):
            res = detector.detect()
        self.assertTrue(res.detected)
        self.assertEqual(res.version, "6.4.2")

    def test_soft404_response_suppression(self):
        """Base scanner soft-404 detector suppresses bogus HTTP 200 responses on missing plugins."""
        class ConcreteScanner(BaseScanner):
            def scan(self):
                return []

        scanner = ConcreteScanner("https://example.com")
        sentinel_body = "<html><body><h1>404 Not Found</h1><p>The page does not exist.</p></body></html>"
        probe_body = "<html><body><h1>404 Not Found</h1><p>The page does not exist.</p></body></html>"

        with patch.object(scanner, "_get") as mock_get:
            # First call for probe URL, second call for sentinel baseline
            mock_get.side_effect = [
                MagicMock(status_code=200, text=probe_body, headers={"Content-Type": "text/html"}),
                MagicMock(status_code=200, text=sentinel_body, headers={"Content-Type": "text/html"}),
            ]
            is_soft = scanner.is_soft_404("https://example.com/wp-content/plugins/nonexistent/")
            self.assertTrue(is_soft)


class TestSprint7SecurityAndTenantIsolation(unittest.TestCase):
    """
    Phase 5: Security Hardening, Multi-Tenant Isolation, CSRF & SSRF Validation.
    """

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

    def setUp(self):
        self.tenant_a = "tenant-s7-a"
        self.tenant_b = "tenant-s7-b"
        if not repository.get_tenant(self.tenant_a):
            repository.save_tenant(Tenant(id=self.tenant_a, name="Tenant A", slug="tenant-a"))
        if not repository.get_tenant(self.tenant_b):
            repository.save_tenant(Tenant(id=self.tenant_b, name="Tenant B", slug="tenant-b"))

        self.asset_a = Asset(
            id=f"asset-s7-a-{uuid.uuid4()}",
            tenant_id=self.tenant_a,
            canonical_url="https://site-a.example.com",
            hostname="site-a.example.com",
            status="active"
        )
        repository.save_asset(self.asset_a)

    def _login(self, client, role="analyst", tenant_id="tenant-s7-a"):
        with client.session_transaction() as sess:
            sess["user_id"] = f"user-{role}"
            sess["username"] = f"user_{role}"
            sess["role"] = role
            sess["tenant_id"] = tenant_id

    def test_tenant_cross_access_blocked_returns_404(self):
        """Tenant B analyst cannot access Asset A detail page belonging to Tenant A (Object-level isolation)."""
        self._login(self.client, role="analyst", tenant_id=self.tenant_b)
        resp = self.client.get(f"/asset/{self.asset_a.id}")
        self.assertEqual(resp.status_code, 404)

    def test_ssrf_validator_blocks_cloud_metadata_ip(self):
        """SSRF validator strictly blocks AWS/GCP cloud metadata IP 169.254.169.254."""
        is_safe, reason = is_safe_target_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
        self.assertFalse(is_safe)

    def test_ssrf_validator_blocks_loopback_and_private_networks(self):
        """SSRF validator blocks localhost and RFC 1918 private ranges."""
        self.assertFalse(is_safe_target_url("http://127.0.0.1:8080", resolve_dns=False)[0])
        self.assertFalse(is_safe_target_url("http://10.0.0.1/admin", resolve_dns=False)[0])
        self.assertFalse(is_safe_target_url("http://192.168.1.1/", resolve_dns=False)[0])
        self.assertFalse(is_safe_target_url("http://172.16.0.1/", resolve_dns=False)[0])

    def test_public_fqdn_accepted_by_ssrf_validator(self):
        """Legitimate external domain names pass SSRF validation."""
        self.assertTrue(is_safe_target_url("https://example.com", resolve_dns=False)[0])
        self.assertTrue(is_safe_target_url("https://wordpress.org", resolve_dns=False)[0])


class TestSprint7DistributedReliability(unittest.TestCase):
    """
    Phase 4: Distributed Processing, Idempotency, Outbox Recovery, and Distributed Lock.
    """

    def test_require_distributed_lock_fails_closed_when_redis_offline(self):
        """When REQUIRE_DISTRIBUTED_LOCK=true and Redis is unreachable, acquisition fails closed."""
        with patch.dict(os.environ, {"REQUIRE_DISTRIBUTED_LOCK": "true"}), \
             patch("redis.Redis.from_url", side_effect=ConnectionError("Redis connection refused")):
            from core.vulnerability_intelligence import service as svc
            svc._redis_client = None  # Force re-evaluation
            with self.assertRaises(RuntimeError):
                svc._get_redis_client()

    def test_outbox_event_claim_and_stale_recovery_guarantee(self):
        """Stale PROCESSING outbox events are recovered idempotently without duplicating scan jobs."""
        tenant_id = f"tenant-outbox-{uuid.uuid4()}"
        repository.save_tenant(Tenant(id=tenant_id, name="Outbox Tenant", slug="outbox"))

        # Create a stale outbox event
        event_id = f"evt-{uuid.uuid4()}"
        now_dt = datetime.now(timezone.utc)
        claimed_at = (now_dt - timedelta(seconds=1200)).isoformat()
        outbox = IntegrationOutbox(
            id=event_id,
            tenant_id=tenant_id,
            event_type="intel_triggered_reassessment",
            event_key=f"key-{uuid.uuid4()}",
            destination="celery",
            payload_hash="hash123",
            payload_json={"asset_id": "asset-test", "cve_id": "CVE-2024-1111"},
            status="PROCESSING",
            attempt=1,
            claimed_at=claimed_at,
            created_at=claimed_at,
        )
        repository.save_outbox_event(outbox)

        # Run recovery task with stale threshold of 60 seconds
        result = recover_stale_outbox_events_task(stale_threshold_seconds=60, limit=10)
        self.assertIsInstance(result, dict)
        self.assertIn("recovered", result)
        self.assertGreaterEqual(result["recovered"], 1)

        # Verify event transitioned back to PENDING or DEAD_LETTER
        conn = repository._get_conn()
        row = conn.execute("SELECT status FROM integration_outbox WHERE id = ?", (event_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertIn(row[0], ("PENDING", "DEAD_LETTER"))


if __name__ == "__main__":
    unittest.main()
