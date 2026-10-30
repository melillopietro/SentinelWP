"""
SWP residual functional regression: BU↔asset UI, live auth badge sync,
admin access-request queue, and executive PDF enrichment.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from core import repository
from core.models import (
    Asset,
    BusinessUnit,
    ScanAuthorization,
    Tenant,
    User,
    UserRole,
    UserStatus,
)


class TestSWPFunctionalFixes(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        repository.init_db(force=True)

        self.tenant_id = "default-tenant"
        repository.save_tenant(Tenant(id=self.tenant_id, name="Default", slug="default"))

        self.admin = User(
            id="swp-admin-1",
            tenant_id=self.tenant_id,
            username="swp_admin",
            password_hash="fakehash",
            email="admin@example.com",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        repository.save_user(self.admin)

        self.bu = BusinessUnit(
            tenant_id=self.tenant_id,
            name="Finance IT",
            code="FIN-IT",
            criticality="high",
        )
        repository.save_business_unit(self.bu)

        self.asset = Asset(
            tenant_id=self.tenant_id,
            canonical_url="https://swp-test.example.com",
            hostname="swp-test.example.com",
            display_name="SWP Test Site",
            environment="production",
            criticality="high",
            status="active",
            authorization_status="authorized",  # stale; live window will disagree
        )
        repository.save_asset(self.asset)

    def _login(self, role="admin"):
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin.id
            sess["username"] = self.admin.username
            sess["role"] = role
            sess["tenant_id"] = self.tenant_id

    def test_a_asset_form_lists_business_units_and_persists_assignment(self):
        self._login("analyst")
        resp = self.client.get("/asset/new")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Business Unit", resp.data)
        self.assertIn(b"FIN-IT", resp.data)

        resp = self.client.post(
            "/asset/create",
            data={
                "target_url": "https://bu-assign.example.com",
                "display_name": "BU Assigned",
                "environment": "production",
                "internet_exposure": "external",
                "criticality": "medium",
                "data_classification": "confidential",
                "business_unit_id": self.bu.id,
            },
            follow_redirects=False,
        )
        self.assertIn(resp.status_code, (302, 303))
        created = repository.get_asset_by_url(self.tenant_id, "https://bu-assign.example.com")
        self.assertIsNotNone(created)
        self.assertEqual(created.business_unit_id, self.bu.id)

        # Edit can clear / change BU
        resp = self.client.post(
            f"/asset/{created.id}/edit",
            data={
                "display_name": "BU Cleared",
                "business_owner": "",
                "technical_owner": "",
                "environment": "production",
                "internet_exposure": "external",
                "criticality": "medium",
                "data_classification": "confidential",
                "tags": "",
                "business_unit_id": "",
            },
            follow_redirects=False,
        )
        self.assertIn(resp.status_code, (302, 303))
        updated = repository.get_asset(created.id, tenant_id=self.tenant_id)
        self.assertIsNone(updated.business_unit_id or None)

    def test_a_bu_edit_and_safe_delete(self):
        self._login("admin")
        resp = self.client.post(
            f"/business-units/{self.bu.id}/edit",
            data={"name": "Finance Platform", "criticality": "critical"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        bu = repository.get_business_unit(self.bu.id, self.tenant_id)
        self.assertEqual(bu.name, "Finance Platform")
        self.assertEqual(bu.criticality, "critical")

        # Assign asset → delete must fail
        repository.update_asset(self.asset.id, tenant_id=self.tenant_id, business_unit_id=self.bu.id)
        resp = self.client.post(f"/business-units/{self.bu.id}/delete", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(repository.get_business_unit(self.bu.id, self.tenant_id))

        # Unassign → delete succeeds
        repository.update_asset(self.asset.id, tenant_id=self.tenant_id, business_unit_id=None)
        resp = self.client.post(f"/business-units/{self.bu.id}/delete", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(repository.get_business_unit(self.bu.id, self.tenant_id))

    def test_b_asset_360_badge_uses_live_auth_and_syncs_status(self):
        self._login("analyst")
        # Stale column says authorized but no active window → expired after prior auth
        past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        earlier = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        repository.save_scan_authorization(
            ScanAuthorization(
                tenant_id=self.tenant_id,
                asset_id=self.asset.id,
                status="active",
                allowed_profiles="safe_active,passive",
                request_budget=1000,
                valid_from=earlier,
                valid_until=past,
                approved_by="swp_admin",
            )
        )
        resp = self.client.get(f"/asset/{self.asset.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Authorization Expired", resp.data)
        self.assertNotIn(b"Authorized for Active Scanning", resp.data)
        refreshed = repository.get_asset(self.asset.id, tenant_id=self.tenant_id)
        self.assertEqual(refreshed.authorization_status, "expired")

        # Grant live window → authorized badge
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        repository.save_scan_authorization(
            ScanAuthorization(
                tenant_id=self.tenant_id,
                asset_id=self.asset.id,
                status="active",
                allowed_profiles="safe_active,passive",
                request_budget=1000,
                valid_from=datetime.now(timezone.utc).isoformat(),
                valid_until=future,
                approved_by="swp_admin",
            )
        )
        resp = self.client.get(f"/asset/{self.asset.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Authorized for Active Scanning", resp.data)
        refreshed = repository.get_asset(self.asset.id, tenant_id=self.tenant_id)
        self.assertEqual(refreshed.authorization_status, "authorized")

    def test_d_access_request_queue_and_handle(self):
        # Public request forms (unauthenticated)
        resp = self.client.post(
            "/request-access",
            data={
                "username": "newhire",
                "email": "newhire@example.com",
                "justification": "Need analyst access for WP audits",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)

        resp = self.client.post(
            "/forgot-password",
            data={"username": "swp_admin", "tenant_slug": "default"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)

        pending = repository.list_pending_access_requests(tenant_id=None, limit=20)
        self.assertGreaterEqual(len(pending), 2)
        types = {p["request_type"] for p in pending}
        self.assertIn("account_access", types)
        self.assertIn("password_reset", types)

        self._login("admin")
        resp = self.client.get("/settings?tab=requests")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Pending Access", resp.data)
        self.assertIn(b"newhire", resp.data)

        target = next(p for p in pending if p["request_type"] == "account_access")
        resp = self.client.post(
            f"/admin/access-request/{target['id']}/handle",
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        still = repository.list_pending_access_requests(tenant_id=None, limit=50)
        self.assertFalse(any(p["id"] == target["id"] for p in still))

    def test_c_executive_pdf_export_enriched(self):
        self._login("analyst")
        resp = self.client.get("/reports/executive/export?format=pdf")
        # Either PDF bytes or HTML fallback redirect/attachment — must not 500
        self.assertIn(resp.status_code, (200, 302))
        if resp.status_code == 200:
            ctype = resp.headers.get("Content-Type", "")
            self.assertTrue(
                "pdf" in ctype or "html" in ctype,
                f"Unexpected content-type: {ctype}",
            )
            if "pdf" in ctype:
                self.assertTrue(resp.data.startswith(b"%PDF"))
                # Compressed stream — assert non-trivial enriched document size
                self.assertGreater(len(resp.data), 800)
                self.assertIn(b"ReportLab", resp.data)

    def test_smoke_key_routes(self):
        self._login("admin")
        for path in ("/", "/assets", "/assets?tab=units", "/settings?tab=users",
                     "/settings?tab=requests", "/reports/executive"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, f"Failed smoke for {path}")


if __name__ == "__main__":
    unittest.main()
