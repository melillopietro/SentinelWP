import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from datetime import datetime, timezone

from app import app
from core import repository
from core.models import Tenant, User, Asset, ScanResult, ScanStatus, Finding, Severity


class TestSprint6UnifiedWorkspaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

    def setUp(self):
        self.tenant_id = "test-tenant-sprint6"

        # Ensure tenant exists
        if not repository.get_tenant(self.tenant_id):
            repository.save_tenant(Tenant(id=self.tenant_id, name="Sprint 6 Test Corp", slug="sprint6"))

        # Create test users with distinct roles
        self.admin = repository.get_user_by_username("sprint6_admin", tenant_id=self.tenant_id)
        if not self.admin:
            self.admin = repository.save_user(
                User(
                    id="user-s6-admin",
                    tenant_id=self.tenant_id,
                    username="sprint6_admin",
                    password_hash="pbkdf2:sha256:fakehash",
                    role="admin",
                    email="admin@test.local",
                    created_at=datetime.now(timezone.utc).isoformat()
                )
            )

        self.analyst = repository.get_user_by_username("sprint6_analyst", tenant_id=self.tenant_id)
        if not self.analyst:
            self.analyst = repository.save_user(
                User(
                    id="user-s6-analyst",
                    tenant_id=self.tenant_id,
                    username="sprint6_analyst",
                    password_hash="pbkdf2:sha256:fakehash",
                    role="analyst",
                    email="analyst@test.local",
                    created_at=datetime.now(timezone.utc).isoformat()
                )
            )

        self.viewer = repository.get_user_by_username("sprint6_viewer", tenant_id=self.tenant_id)
        if not self.viewer:
            self.viewer = repository.save_user(
                User(
                    id="user-s6-viewer",
                    tenant_id=self.tenant_id,
                    username="sprint6_viewer",
                    password_hash="pbkdf2:sha256:fakehash",
                    role="viewer",
                    email="viewer@test.local",
                    created_at=datetime.now(timezone.utc).isoformat()
                )
            )

        # Create test asset
        self.asset = repository.get_asset_by_url(self.tenant_id, "https://s6-test.example.com")
        if not self.asset:
            self.asset = repository.save_asset(
                Asset(
                    id="asset-s6-001",
                    tenant_id=self.tenant_id,
                    canonical_url="https://s6-test.example.com",
                    hostname="s6-test.example.com",
                    display_name="Sprint 6 Test Asset",
                    environment="production",
                    criticality="high",
                    created_at=datetime.now(timezone.utc).isoformat(),
                    updated_at=datetime.now(timezone.utc).isoformat(),
                )
            )

    def _login(self, client, role="analyst"):
        user_id = f"user-s6-{role}"
        username = f"sprint6_{role}"
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = username
            sess["role"] = role
            sess["tenant_id"] = self.tenant_id

    # --- 1. Six Primary Workspaces HTTP 200 Entry Point Tests ---

    def test_workspace1_overview_entry_point(self):
        """Workspace 1: Overview renders with HTTP 200 and posture header."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Operations Overview", resp.data)
        self.assertIn(b"Posture Overview", resp.data)
        self.assertIn(b"Business Units &amp; Governance", resp.data)
        self.assertIn(b"Executive Summary", resp.data)

    def test_workspace2_assets_entry_point(self):
        """Workspace 2: Assets renders with HTTP 200 and sub-tabs."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/assets")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Asset Inventory &amp; Attack Surface", resp.data)
        self.assertIn(b"All Assets", resp.data)
        self.assertIn(b"Business Units", resp.data)
        self.assertIn(b"Data Quality &amp; Confidence", resp.data)
        self.assertIn(b"add-asset-modal", resp.data)

    def test_workspace3_vulnerabilities_entry_point(self):
        """Workspace 3: Vulnerabilities renders with HTTP 200 and unified tabs."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/findings")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Vulnerabilities &amp; Exposure Governance", resp.data)
        self.assertIn(b"All Findings", resp.data)
        self.assertIn(b"Critical &amp; High", resp.data)
        self.assertIn(b"Remediation Backlog", resp.data)
        self.assertIn(b"SLA Governance", resp.data)
        self.assertIn(b"Risk Exceptions", resp.data)

    def test_workspace4_operations_entry_point(self):
        """Workspace 4: Operations renders with HTTP 200 and unified scan launcher."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/scans")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Operations &amp; Scans", resp.data)
        self.assertIn(b"Scan History &amp; Queue", resp.data)
        self.assertIn(b"Recurring Schedules", resp.data)
        self.assertIn(b"scan-launcher-modal", resp.data)

    def test_workspace5_threat_intel_entry_point(self):
        """Workspace 5: Threat Intel renders with HTTP 200 and telemetry tabs."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/vuln-intel")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Threat Intelligence &amp; Advisories", resp.data)
        self.assertIn(b"Feed Telemetry &amp; Health", resp.data)
        self.assertIn(b"CVE Advisory Database", resp.data)
        self.assertIn(b"Reassessment Queue", resp.data)

    def test_workspace6_administration_entry_point(self):
        """Workspace 6: Administration renders with HTTP 200."""
        self._login(self.client, role="admin")
        resp = self.client.get("/settings")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Platform Governance &amp; Administration", resp.data)
        self.assertIn(b"General &amp; Profile", resp.data)
        self.assertIn(b"User Management", resp.data)
        self.assertIn(b"API Keys &amp; Integrations", resp.data)
        self.assertIn(b"Security Audit Trail", resp.data)

    # --- 2. Legacy Route Compatibility & Graceful Redirects ---

    def test_legacy_portfolio_route_redirects_to_overview(self):
        """Legacy /portfolio redirects to /?tab=portfolio."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/portfolio", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("tab=portfolio", resp.headers["Location"])

    def test_legacy_data_quality_route_redirects_to_assets(self):
        """Legacy /data-quality redirects to /assets?tab=quality."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/data-quality", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("tab=quality", resp.headers["Location"])

    def test_legacy_remediation_route_redirects_to_vulnerabilities(self):
        """Legacy /remediation redirects to /findings?tab=remediation."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/remediation", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("tab=remediation", resp.headers["Location"])

    def test_legacy_sla_route_redirects_to_vulnerabilities(self):
        """Legacy /sla redirects to /findings?tab=sla."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/sla", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("tab=sla", resp.headers["Location"])

    def test_legacy_risk_acceptances_route_redirects_to_vulnerabilities(self):
        """Legacy /risk-acceptances redirects to /findings?tab=exceptions."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/risk-acceptances", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("tab=exceptions", resp.headers["Location"])

    def test_legacy_schedules_route_redirects_to_operations(self):
        """Legacy /schedules redirects to /scans?tab=schedules."""
        self._login(self.client, role="analyst")
        resp = self.client.get("/schedules", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("tab=schedules", resp.headers["Location"])

    # --- 3. Sidebar Navigation Structure ---

    def test_sidebar_contains_exactly_six_workspaces(self):
        """Sidebar contains links for all 6 unified workspaces and no legacy scattered links."""
        self._login(self.client, role="admin")
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

        # The 6 primary workspace labels must be present
        self.assertIn(b"Overview", resp.data)
        self.assertIn(b"Assets", resp.data)
        self.assertIn(b"Vulnerabilities", resp.data)
        self.assertIn(b"Operations", resp.data)
        self.assertIn(b"Threat Intel", resp.data)
        self.assertIn(b"Administration", resp.data)

        # Ensure flat fragmented navigation entries are NOT in the sidebar nav
        # E.g. "Batch Scan", "SLA Governance" as standalone sidebar nav links
        self.assertNotIn(b">Batch Scan<", resp.data)
        self.assertNotIn(b">SLA Governance<", resp.data)

    # --- 4. Asset 360 Contextual Navigation ---

    def test_asset_detail_renders_six_contextual_tabs(self):
        """Asset detail page provides 6 contextual sub-tabs."""
        self._login(self.client, role="analyst")
        resp = self.client.get(f"/asset/{self.asset.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Overview", resp.data)
        self.assertIn(b"Vulnerabilities", resp.data)
        self.assertIn(b"Scan History", resp.data)
        self.assertIn(b"Continuous Monitoring", resp.data)
        self.assertIn(b"Technology Inventory", resp.data)
        self.assertIn(b"Reports &amp; Diff", resp.data)

    # --- 5. RBAC & Privileged Workspace Protections ---

    def test_viewer_role_cannot_view_admin_tabs_or_user_management(self):
        """Viewer role accessing /settings does not see user management tab."""
        self._login(self.client, role="viewer")
        resp = self.client.get("/settings")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b"User Management (Admin Console)", resp.data)
        self.assertNotIn(b"Security Audit Trail", resp.data)

    def test_viewer_blocked_from_audit_route(self):
        """Direct access to /audit by viewer returns 403."""
        self._login(self.client, role="viewer")
        resp = self.client.get("/audit")
        self.assertEqual(resp.status_code, 403)

    def test_admin_has_full_access_to_audit_route(self):
        """Admin can access /audit directly with 200 OK."""
        self._login(self.client, role="admin")
        resp = self.client.get("/audit")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Audit Log", resp.data)


if __name__ == "__main__":
    unittest.main()
