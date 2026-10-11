"""
Phase 2 Enterprise Tests: Tenant Isolation, Asset Inventory, Scan Authorization, and Audit Logging.
Validates multi-tenant boundaries (IDOR prevention returning HTTP 404),
Safe Active guardrails (fail-closed 403 on missing/expired authorization),
asset canonicalization, RBAC rules, and sanitized immutable audit logs.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from datetime import datetime, timedelta, timezone
from app import app
from core import repository
from core.models import (
    Tenant, Asset, ScanAuthorization, AuditEvent,
    ScanResult, Finding, ScheduledScan, User, UserRole, UserStatus, ScanStatus, Severity
)
from core.canonical import canonicalize_url
from core.authorization import verify_scan_authorization


class TestPhase2TenantAssetAuthorization(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        repository.init_db(force=True)

        # Create two distinct tenants
        self.tenant_a = Tenant(id="tenant-alpha", name="Alpha Corp", slug="alpha")
        self.tenant_b = Tenant(id="tenant-beta", name="Beta Corp", slug="beta")
        repository.save_tenant(self.tenant_a)
        repository.save_tenant(self.tenant_b)

        # Create assets for both tenants
        self.asset_a = Asset(
            id="asset-alpha-1",
            tenant_id="tenant-alpha",
            canonical_url="https://alpha.example.com",
            hostname="alpha.example.com",
            display_name="Alpha Main Site",
            environment="production",
            criticality="high",
            status="active"
        )
        self.asset_b = Asset(
            id="asset-beta-1",
            tenant_id="tenant-beta",
            canonical_url="https://beta.example.com",
            hostname="beta.example.com",
            display_name="Beta Main Site",
            environment="production",
            criticality="critical",
            status="active"
        )
        repository.save_asset(self.asset_a)
        repository.save_asset(self.asset_b)

        # Create scans for both tenants
        self.scan_a = ScanResult(
            id="scan-alpha-1",
            tenant_id="tenant-alpha",
            asset_id=self.asset_a.id,
            target_url="https://alpha.example.com",
            status=ScanStatus.COMPLETED,
            score=85.0,
            grade="B"
        )
        self.scan_b = ScanResult(
            id="scan-beta-1",
            tenant_id="tenant-beta",
            asset_id=self.asset_b.id,
            target_url="https://beta.example.com",
            status=ScanStatus.COMPLETED,
            score=60.0,
            grade="D"
        )
        repository.save_scan(self.scan_a)
        repository.save_scan(self.scan_b)

        # Create findings for both tenants
        self.finding_a = Finding(
            id="finding-alpha-1",
            scan_id=self.scan_a.id,
            tenant_id="tenant-alpha",
            asset_id=self.asset_a.id,
            category="headers",
            title="Missing HSTS Header in Alpha",
            severity=Severity.LOW
        )
        self.finding_b = Finding(
            id="finding-beta-1",
            scan_id=self.scan_b.id,
            tenant_id="tenant-beta",
            asset_id=self.asset_b.id,
            category="vulnerability",
            title="Critical SQL Injection in Beta",
            severity=Severity.CRITICAL
        )
        repository.save_finding(self.finding_a)
        repository.save_finding(self.finding_b)

        # Create schedules for both tenants
        self.sched_a = ScheduledScan(
            id="sched-alpha-1",
            tenant_id="tenant-alpha",
            asset_id=self.asset_a.id,
            target_url="https://alpha.example.com",
            scan_mode="passive"
        )
        self.sched_b = ScheduledScan(
            id="sched-beta-1",
            tenant_id="tenant-beta",
            asset_id=self.asset_b.id,
            target_url="https://beta.example.com",
            scan_mode="passive"
        )
        repository.save_scheduled_scan(self.sched_a)
        repository.save_scheduled_scan(self.sched_b)

        # Create users for both tenants
        self.user_a_admin = User(
            id="user-a-admin",
            tenant_id="tenant-alpha",
            username="alpha_admin",
            password_hash="fakehash",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE
        )
        self.user_b_admin = User(
            id="user-b-admin",
            tenant_id="tenant-beta",
            username="beta_admin",
            password_hash="fakehash",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE
        )
        repository.save_user(self.user_a_admin)
        repository.save_user(self.user_b_admin)

    def _login(self, client, role="analyst", tenant_id="tenant-alpha", user_id="user-a-1", username="alpha_user"):
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = username
            sess["role"] = role
            sess["tenant_id"] = tenant_id

    # --- 1. Tenant Isolation & IDOR Prevention Tests ---

    def test_tenant_scan_detail_cross_tenant_returns_404(self):
        """Cross-tenant scan view attempt MUST return 404 (prevent resource disclosure)."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        # Try to view Tenant B's scan
        resp = self.client.get(f"/scan/{self.scan_b.id}")
        self.assertEqual(resp.status_code, 404)

        # View own scan returns 200
        resp_own = self.client.get(f"/scan/{self.scan_a.id}")
        self.assertEqual(resp_own.status_code, 200)

    def test_tenant_scan_delete_cross_tenant_returns_404(self):
        """Cross-tenant scan delete attempt MUST return 404."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp = self.client.post(f"/scan/{self.scan_b.id}/delete")
        self.assertEqual(resp.status_code, 404)
        # Verify scan B was not deleted
        self.assertIsNotNone(repository.get_scan(self.scan_b.id, tenant_id="tenant-beta"))

    def test_tenant_asset_detail_cross_tenant_returns_404(self):
        """Cross-tenant asset view attempt MUST return 404."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp = self.client.get(f"/asset/{self.asset_b.id}")
        self.assertEqual(resp.status_code, 404)

        resp_own = self.client.get(f"/asset/{self.asset_a.id}")
        self.assertEqual(resp_own.status_code, 200)

    def test_tenant_asset_edit_cross_tenant_returns_404(self):
        """Cross-tenant asset edit attempt MUST return 404."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp = self.client.post(f"/asset/{self.asset_b.id}/edit", data={"display_name": "Hacked Asset"})
        self.assertEqual(resp.status_code, 404)
        asset_b_fresh = repository.get_asset(self.asset_b.id, tenant_id="tenant-beta")
        self.assertEqual(asset_b_fresh.display_name, "Beta Main Site")

    def test_tenant_asset_delete_cross_tenant_returns_404(self):
        """Cross-tenant asset delete attempt MUST return 404."""
        self._login(self.client, role="admin", tenant_id="tenant-alpha")
        resp = self.client.post(f"/asset/{self.asset_b.id}/delete")
        self.assertEqual(resp.status_code, 404)
        asset_b_fresh = repository.get_asset(self.asset_b.id, tenant_id="tenant-beta")
        self.assertEqual(asset_b_fresh.status, "active")

    def test_tenant_finding_edit_and_delete_cross_tenant_returns_404(self):
        """Cross-tenant finding mutation MUST return 404."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp_edit = self.client.post(f"/finding/{self.finding_b.id}/edit", data={"title": "Tampered"})
        self.assertEqual(resp_edit.status_code, 404)

        resp_del = self.client.post(f"/finding/{self.finding_b.id}/delete")
        self.assertEqual(resp_del.status_code, 404)
        self.assertIsNotNone(repository.get_finding(self.finding_b.id, tenant_id="tenant-beta"))

    def test_tenant_schedule_delete_cross_tenant_returns_404(self):
        """Cross-tenant schedule delete attempt MUST return 404."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp = self.client.post(f"/schedule/{self.sched_b.id}/delete")
        self.assertEqual(resp.status_code, 404)
        self.assertIsNotNone(repository.get_scheduled_scan(self.sched_b.id, tenant_id="tenant-beta"))

    def test_tenant_report_cross_tenant_returns_404(self):
        """Cross-tenant report download attempt MUST return 404."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        for fmt in ("html", "json", "sarif", "excel", "pdf"):
            resp = self.client.get(f"/scan/{self.scan_b.id}/report/{fmt}")
            self.assertEqual(resp.status_code, 404, f"Format {fmt} should return 404 for cross-tenant request")

    def test_tenant_user_management_cross_tenant_returns_404(self):
        """Admin of Tenant A cannot delete user belonging to Tenant B."""
        self._login(self.client, role="admin", tenant_id="tenant-alpha", user_id="user-a-admin")
        resp = self.client.post(f"/user/{self.user_b_admin.id}/delete")
        self.assertEqual(resp.status_code, 404)
        self.assertIsNotNone(repository.get_user_by_id(self.user_b_admin.id, tenant_id="tenant-beta"))

    def test_tenant_scans_and_assets_listing_isolated(self):
        """Listings of scans and assets must only return records belonging to the caller's tenant."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp_scans = self.client.get("/scans")
        self.assertEqual(resp_scans.status_code, 200)
        self.assertIn(b"alpha.example.com", resp_scans.data)
        self.assertNotIn(b"beta.example.com", resp_scans.data)

        resp_assets = self.client.get("/assets")
        self.assertEqual(resp_assets.status_code, 200)
        self.assertIn(b"Alpha Main Site", resp_assets.data)
        self.assertNotIn(b"Beta Main Site", resp_assets.data)

    # --- 2. Scan Authorization Guardrail Tests ---

    def test_safe_active_scan_blocked_without_authorization(self):
        """Safe Active scan must fail closed (403) if no active authorization exists."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        # Attempt safe-active scan on unauthorized asset
        resp = self.client.post("/scan/new", data={
            "target_url": "https://alpha.example.com",
            "scan_mode": "safe-active"
        })
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"Safe Active scan blocked", resp.data)

        # Audit log must record denied event
        audit_events = repository.list_audit_events(tenant_id="tenant-alpha", filters={"action": "scan_denied"})
        self.assertTrue(len(audit_events) >= 1)
        self.assertEqual(audit_events[0].result, "denied")

    def test_passive_scan_allowed_without_active_authorization(self):
        """Passive scan is allowed without explicit active authorization window."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp = self.client.post("/scan/new", data={
            "target_url": "https://alpha.example.com",
            "scan_mode": "passive"
        })
        # Should be queued and redirect to scan detail
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/scan/", resp.headers["Location"])

    def test_safe_active_scan_allowed_with_valid_authorization(self):
        """Safe Active scan succeeds when asset has an active unexpired authorization."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        future_iso = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        auth = ScanAuthorization(
            tenant_id="tenant-alpha",
            asset_id=self.asset_a.id,
            status="active",
            allowed_profiles="safe_active,passive",
            valid_from=datetime.now(timezone.utc).isoformat(),
            valid_until=future_iso,
            approved_by="alpha_admin"
        )
        repository.save_scan_authorization(auth)

        resp = self.client.post("/scan/new", data={
            "target_url": "https://alpha.example.com",
            "scan_mode": "safe-active"
        })
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/scan/", resp.headers["Location"])

    def test_safe_active_scan_blocked_when_authorization_expired(self):
        """Safe Active scan fails closed when authorization valid_until is in the past."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        past_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        auth = ScanAuthorization(
            tenant_id="tenant-alpha",
            asset_id=self.asset_a.id,
            status="active",
            valid_from=(datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
            valid_until=past_iso,
            approved_by="alpha_admin"
        )
        repository.save_scan_authorization(auth)

        resp = self.client.post("/scan/new", data={
            "target_url": "https://alpha.example.com",
            "scan_mode": "safe-active"
        })
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"Safe Active scan blocked", resp.data)

    def test_safe_active_scan_blocked_when_authorization_revoked(self):
        """Safe Active scan fails closed when authorization status is 'revoked'."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        future_iso = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        auth = ScanAuthorization(
            tenant_id="tenant-alpha",
            asset_id=self.asset_a.id,
            status="revoked",
            valid_from=datetime.now(timezone.utc).isoformat(),
            valid_until=future_iso,
            approved_by="alpha_admin"
        )
        repository.save_scan_authorization(auth)

        is_auth, reason, _ = verify_scan_authorization("tenant-alpha", self.asset_a.canonical_url, "safe-active")
        self.assertFalse(is_auth)
        self.assertIn("blocked", reason.lower())

    # --- 3. Asset Canonicalization Tests ---

    def test_url_canonicalization_rules(self):
        """Tests standard normalization rules for target URLs."""
        # Lowercase hostname and strip standard ports
        canon, host = canonicalize_url("HTTP://EXAMPLE.COM:80/blog/")
        self.assertEqual(canon, "http://example.com/blog")
        self.assertEqual(host, "example.com")

        canon2, host2 = canonicalize_url("https://Example.org:443/")
        self.assertEqual(canon2, "https://example.org")
        self.assertEqual(host2, "example.org")

        # Keep custom ports
        canon3, host3 = canonicalize_url("https://wp.internal.org:8443/wp/")
        self.assertEqual(canon3, "https://wp.internal.org:8443/wp")
        self.assertEqual(host3, "wp.internal.org")

        # Strip query parameters and fragments
        canon4, _ = canonicalize_url("https://example.com/subsite?query=1#section")
        self.assertEqual(canon4, "https://example.com/subsite")

        # Missing scheme defaults to https
        canon5, host5 = canonicalize_url("wordpress.company.com/portal")
        self.assertEqual(canon5, "https://wordpress.company.com/portal")
        self.assertEqual(host5, "wordpress.company.com")

    # --- 4. Immutable Audit Logging & Sanitization Tests ---

    def test_audit_logging_sanitizes_credentials_and_secrets(self):
        """Verify audit log redacts passwords, tokens, API keys, and session cookies."""
        metadata = {
            "target_url": "https://example.com",
            "password": "SuperSecretPassword123!",
            "api_key": "wf-api-key-9999",
            "auth_token": "bearer-token-xyz",
            "cookie": "session=abcdef",
            "normal_field": "public_data"
        }
        event = repository.log_audit_event(
            tenant_id="tenant-alpha",
            actor_user_id="user-1",
            actor_username="admin_user",
            action="test_sanitization",
            metadata=metadata
        )
        self.assertEqual(event.metadata["password"], "[REDACTED]")
        self.assertEqual(event.metadata["api_key"], "[REDACTED]")
        self.assertEqual(event.metadata["auth_token"], "[REDACTED]")
        self.assertEqual(event.metadata["cookie"], "[REDACTED]")
        self.assertEqual(event.metadata["normal_field"], "public_data")

    def test_audit_log_access_restricted_to_admin(self):
        """Audit log endpoint (/audit) must be restricted to Admin role; Viewer and Analyst receive 403."""
        # Viewer access
        self._login(self.client, role="viewer", tenant_id="tenant-alpha")
        resp_v = self.client.get("/audit")
        self.assertEqual(resp_v.status_code, 403)

        # Analyst access
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp_a = self.client.get("/audit")
        self.assertEqual(resp_a.status_code, 403)

        # Admin access
        self._login(self.client, role="admin", tenant_id="tenant-alpha")
        resp_admin = self.client.get("/audit")
        self.assertEqual(resp_admin.status_code, 200)
        self.assertIn(b"Security Audit Log", resp_admin.data)

    # --- 5. RBAC Permissions Matrix Tests ---

    def test_viewer_blocked_from_asset_mutations(self):
        """Viewer role is strictly read-only and blocked from creating or editing assets."""
        self._login(self.client, role="viewer", tenant_id="tenant-alpha")

        resp_create = self.client.post("/asset/create", data={"target_url": "https://new.example.com"})
        self.assertEqual(resp_create.status_code, 403)

        resp_edit = self.client.post(f"/asset/{self.asset_a.id}/edit", data={"display_name": "Viewer Edit"})
        self.assertEqual(resp_edit.status_code, 403)

        resp_delete = self.client.post(f"/asset/{self.asset_a.id}/delete")
        self.assertEqual(resp_delete.status_code, 403)

    def test_analyst_cannot_delete_asset(self):
        """Analyst can edit asset metadata but cannot decommission/delete assets (Admin only)."""
        self._login(self.client, role="analyst", tenant_id="tenant-alpha")
        resp_delete = self.client.post(f"/asset/{self.asset_a.id}/delete")
        self.assertEqual(resp_delete.status_code, 403)


if __name__ == "__main__":
    unittest.main()
