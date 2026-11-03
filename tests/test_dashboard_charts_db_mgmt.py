"""Smoke tests for dashboard chart context, logo markers, and DB maintenance routes."""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from core import repository
from core.models import (
    Asset,
    Finding,
    ScanResult,
    ScanStatus,
    Severity,
    Tenant,
    User,
    UserRole,
    UserStatus,
)


class TestDashboardChartsLogoDbMgmt(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        repository.init_db(force=True)
        self.tenant_id = "default-tenant"
        repository.save_tenant(Tenant(id=self.tenant_id, name="Default", slug="default"))
        self.admin = User(
            id="db-admin-1",
            tenant_id=self.tenant_id,
            username="db_admin",
            password_hash="x",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        repository.save_user(self.admin)
        asset = Asset(
            tenant_id=self.tenant_id,
            canonical_url="https://charts.example.com",
            hostname="charts.example.com",
            display_name="Charts Site",
            risk_score=72.0,
            status="active",
        )
        repository.save_asset(asset)
        scan = ScanResult(
            tenant_id=self.tenant_id,
            asset_id=asset.id,
            target_url=asset.canonical_url,
            status=ScanStatus.COMPLETED,
            score=72.0,
            grade="D",
        )
        repository.save_scan(scan)
        repository.save_finding(
            Finding(
                scan_id=scan.id,
                tenant_id=self.tenant_id,
                asset_id=asset.id,
                category="headers",
                title="Missing Security Header: CSP",
                description="test",
                severity=Severity.HIGH,
                confidence=0.9,
                status="OPEN",
            )
        )

    def _login(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin.id
            sess["username"] = self.admin.username
            sess["role"] = "admin"
            sess["tenant_id"] = self.tenant_id

    def test_dashboard_contains_chart_canvases_and_chartjs(self):
        self._login()
        resp = self.client.get("/?tab=posture")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"severityDonutChart", resp.data)
        self.assertIn(b"topSitesBarChart", resp.data)
        self.assertIn(b"topCategoriesChart", resp.data)
        self.assertIn(b"chart.js@4.4.1", resp.data)

    def test_logo_shield_in_base_and_login(self):
        self._login()
        dash = self.client.get("/")
        self.assertIn(b"SentinelWP Enterprise Logo", dash.data)
        self.assertIn(b"M20 3L6 8.5V18.2", dash.data)
        # logout to hit login page branding via GET /login if available
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"M20 3L6 8.5V18.2", resp.data)

    def test_settings_database_tab_renders(self):
        self._login()
        resp = self.client.get("/settings?tab=database")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Database Snapshot", resp.data)
        self.assertIn(b"RESET-CONFIRM", resp.data)
        self.assertIn(b"Export Database", resp.data)

    def test_database_reset_requires_phrase(self):
        self._login()
        resp = self.client.post(
            "/admin/database/reset",
            data={"confirmation": "WRONG"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Reset aborted", resp.data)
        # scan still present
        scans = repository.list_scans(limit=10, filters={"tenant_id": self.tenant_id})
        self.assertGreaterEqual(len(scans), 1)

    def test_database_export_sqlite_header(self):
        self._login()
        resp = self.client.get("/admin/database/export")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data.startswith(b"SQLite format 3\x00"))

    def test_purge_older_than_and_reset(self):
        self._login()
        old = ScanResult(
            tenant_id=self.tenant_id,
            target_url="https://old.example.com",
            status=ScanStatus.COMPLETED,
            started_at=(datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
            score=10,
        )
        repository.save_scan(old)
        n_scans, n_findings = repository.purge_scans_older_than(90, tenant_id=self.tenant_id)
        self.assertGreaterEqual(n_scans, 1)

        resp = self.client.post(
            "/admin/database/reset",
            data={"confirmation": "RESET-CONFIRM"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Operational data wiped", resp.data)
        # admin user still exists
        self.assertIsNotNone(repository.get_user_by_id(self.admin.id, tenant_id=self.tenant_id))


if __name__ == "__main__":
    unittest.main()
