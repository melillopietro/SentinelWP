"""
Sprint 11 — Independent Cursor audit remediation regression tests.
Covers SWP-AUTH-001, SWP-DIST-001, SWP-AUTH-002, and SSRF strict-DNS hardening.
"""
import os
import sys
import threading
import uuid
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from core.auth import authenticate_login_user, get_session_role
from core.auth.passwords import hash_password, create_user
from core.models import UserRole, UserStatus, ScanJob, ScanJobStatus, Tenant, ScanResult, ScanStatus
from core import repository
from scanners.base import is_safe_target_url

LIVE_POSTGRES_URL = os.getenv(
    "SENTINELWP_TEST_POSTGRES_URL",
    "postgresql://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s10",
)


def _postgres_available() -> bool:
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(LIVE_POSTGRES_URL, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


class TestSessionRoleCanonical(unittest.TestCase):
    def test_get_session_role_prefers_role_over_legacy_user_role(self):
        with app.test_request_context():
            from flask import session
            session["role"] = "admin"
            session["user_role"] = "viewer"
            self.assertEqual(get_session_role(), "admin")


class TestApiSessionAuthorizationMatrix(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _session_login(self, role: str, tenant_id: str = "default-tenant"):
        with self.client.session_transaction() as sess:
            sess["user_id"] = f"user-{role}"
            sess["username"] = f"{role}_user"
            sess["role"] = role
            sess["tenant_id"] = tenant_id

    @patch("core.api_auth.verify_api_key")
    def test_admin_session_allowed_admin_scope_route(self, mock_verify):
        mock_verify.return_value = None
        self._session_login("admin")
        resp = self.client.get("/api/v1/portfolio")
        self.assertEqual(resp.status_code, 200)

    @patch("core.api_auth.verify_api_key")
    def test_viewer_session_forbidden_on_write_scope(self, mock_verify):
        mock_verify.return_value = None
        self._session_login("viewer")
        resp = self.client.post(
            "/api/v1/findings/fake-id/status",
            json={"status": "IN_PROGRESS"},
        )
        self.assertEqual(resp.status_code, 403)

    @patch("core.api_auth.verify_api_key")
    def test_analyst_session_allowed_findings_write(self, mock_verify):
        mock_verify.return_value = None
        self._session_login("analyst")
        with patch("app.repository.get_finding", return_value=None):
            resp = self.client.post(
                "/api/v1/findings/fake-id/status",
                json={"status": "IN_PROGRESS"},
            )
        self.assertIn(resp.status_code, (404, 400, 409))

    @patch("core.api_auth.verify_api_key")
    def test_missing_session_unauthorized(self, mock_verify):
        mock_verify.return_value = None
        resp = self.client.get("/api/v1/findings")
        self.assertEqual(resp.status_code, 401)

    @patch("core.api_auth.verify_api_key")
    def test_api_key_scopes_enforced_independently(self, mock_verify):
        from core.models import APIKey
        key = APIKey(
            id="k1",
            tenant_id="tenant-a",
            name="read",
            key_prefix="swp_live_ab",
            key_hash="abc",
            scopes=["findings:read"],
        )
        mock_verify.return_value = key
        resp = self.client.get(
            "/api/v1/findings",
            headers={"Authorization": "Bearer swp_live_testtoken"},
        )
        self.assertEqual(resp.status_code, 200)

    @patch("core.api_auth.verify_api_key")
    def test_api_key_missing_scope_forbidden(self, mock_verify):
        from core.models import APIKey
        key = APIKey(
            id="k2",
            tenant_id="tenant-a",
            name="read",
            key_prefix="swp_live_ab",
            key_hash="abc",
            scopes=["findings:read"],
        )
        mock_verify.return_value = key
        resp = self.client.post(
            "/api/v1/findings/fake-id/status",
            json={"status": "IN_PROGRESS"},
            headers={"Authorization": "Bearer swp_live_testtoken"},
        )
        self.assertEqual(resp.status_code, 403)

    @patch("core.api_auth.verify_api_key")
    def test_cross_tenant_session_does_not_switch_api_tenant(self, mock_verify):
        mock_verify.return_value = None
        self._session_login("admin", tenant_id="tenant-a")
        with patch("app.repository.list_findings", return_value=([], 0)) as mock_list:
            self.client.get("/api/v1/findings")
            mock_list.assert_called_once()
            called_tenant = mock_list.call_args[0][0] if mock_list.call_args[0] else mock_list.call_args.kwargs.get("tenant_id")
            self.assertEqual(called_tenant, "tenant-a")


class TestMultiTenantLoginResolution(unittest.TestCase):
    def setUp(self):
        os.environ.pop("DATABASE_URL", None)
        repository.reset_conn()
        repository._allow_operational_sqlite_override = True
        repository.init_db()
        self.prefix = uuid.uuid4().hex[:8]
        self.slug_a = f"org-a-{self.prefix}"
        self.slug_b = f"org-b-{self.prefix}"
        self.username = f"dupuser_{self.prefix}"
        self.password = "UniquePilotPassword!99"
        repository.save_tenant(Tenant(id=f"t-a-{self.prefix}", name="A", slug=self.slug_a, status="active"))
        repository.save_tenant(Tenant(id=f"t-b-{self.prefix}", name="B", slug=self.slug_b, status="active"))
        for tid, pwd in (
            (f"t-a-{self.prefix}", self.password),
            (f"t-b-{self.prefix}", self.password),
        ):
            u = create_user(
                username=self.username,
                password=pwd,
                role=UserRole.ANALYST,
                status=UserStatus.ACTIVE,
            )
            u.tenant_id = tid
            repository.save_user(u)

    def test_tenant_slug_disambiguates_duplicate_username(self):
        user = authenticate_login_user(self.username, self.password, tenant_slug=self.slug_a)
        self.assertIsNotNone(user)
        self.assertEqual(user.tenant_id, f"t-a-{self.prefix}")

    def test_ambiguous_duplicate_username_without_slug_rejected(self):
        user = authenticate_login_user(self.username, self.password, tenant_slug=None)
        self.assertIsNone(user)

    def test_wrong_password_same_generic_failure(self):
        user = authenticate_login_user(self.username, "wrong-password", tenant_slug=self.slug_a)
        self.assertIsNone(user)


class TestScanJobAtomicClaimSqlite(unittest.TestCase):
    def setUp(self):
        os.environ.pop("DATABASE_URL", None)
        repository.reset_conn()
        repository._allow_operational_sqlite_override = True
        repository.init_db()
        self.job_id = f"job_{uuid.uuid4().hex[:10]}"
        self.scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        now = "2026-01-01T00:00:00+00:00"
        scan = ScanResult(
            id=self.scan_id,
            tenant_id="default-tenant",
            target_url="https://example.com",
            scan_mode="passive",
            status=ScanStatus.PENDING,
        )
        repository.save_scan(scan)
        job = ScanJob(
            id=self.job_id,
            tenant_id="default-tenant",
            scan_id=self.scan_id,
            status=ScanJobStatus.QUEUED.value,
            queued_at=now,
            created_at=now,
            updated_at=now,
        )
        repository.create_scan_job(job)

    def test_exactly_one_worker_claims_job(self):
        results = []

        def claim(worker):
            results.append(
                repository.try_claim_scan_job_for_execution(self.job_id, worker)
            )

        t1 = threading.Thread(target=claim, args=("worker-a",))
        t2 = threading.Thread(target=claim, args=("worker-b",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        claimed = [r for r in results if r is not None]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0].status, ScanJobStatus.RUNNING.value)

    def test_terminal_status_immutable(self):
        repository.mark_scan_job_status(self.job_id, ScanJobStatus.COMPLETED.value)
        ok = repository.mark_scan_job_status(self.job_id, ScanJobStatus.RUNNING.value)
        self.assertFalse(ok)
        job = repository.get_scan_job(self.job_id)
        self.assertEqual(job.status, ScanJobStatus.COMPLETED.value)
        self.assertNotEqual(job.status, ScanJobStatus.RUNNING.value)


@unittest.skipUnless(_postgres_available(), "Live PostgreSQL not available for concurrency claim test")
class TestScanJobAtomicClaimPostgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core.db.session import get_engine, init_db_schema, reset_engine
        cls.engine = get_engine(LIVE_POSTGRES_URL)

    def setUp(self):
        from core.db.session import reset_engine
        self._orig = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = LIVE_POSTGRES_URL
        reset_engine()
        repository.reset_conn()
        repository._allow_operational_sqlite_override = False

        prefix = uuid.uuid4().hex[:8]
        self.tenant_id = f"claim_t_{prefix}"
        repository.save_tenant(
            Tenant(id=self.tenant_id, name="Claim Test", slug=f"claim-{prefix}", status="active")
        )
        self.job_id = f"pgjob_{prefix}"
        now = "2026-01-01T00:00:00+00:00"
        scan_id = f"scan_{prefix}"
        repository.save_scan(
            ScanResult(
                id=scan_id,
                tenant_id=self.tenant_id,
                target_url="https://example.com",
                scan_mode="passive",
                status=ScanStatus.PENDING,
            )
        )
        repository.create_scan_job(
            ScanJob(
                id=self.job_id,
                tenant_id=self.tenant_id,
                scan_id=scan_id,
                status=ScanJobStatus.QUEUED.value,
                queued_at=now,
                created_at=now,
                updated_at=now,
            )
        )

    def tearDown(self):
        from core.db.session import reset_engine
        if self._orig is not None:
            os.environ["DATABASE_URL"] = self._orig
        else:
            os.environ.pop("DATABASE_URL", None)
        reset_engine()
        repository.reset_conn()

    def test_postgres_concurrent_claim_single_winner(self):
        results = []

        def claim(worker):
            results.append(
                repository.try_claim_scan_job_for_execution(self.job_id, worker)
            )

        threads = [threading.Thread(target=claim, args=(f"w-{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        winners = [r for r in results if r is not None]
        self.assertEqual(len(winners), 1)


class TestStrictDnsProduction(unittest.TestCase):
    @patch.dict(os.environ, {"ENVIRONMENT": "production", "WSA_STRICT_DNS": "true"}, clear=False)
    def test_unresolved_hostname_blocked_in_production_strict_mode(self):
        with patch("socket.getaddrinfo", side_effect=OSError("nodename nor servname provided")):
            safe, reason = is_safe_target_url("https://definitely-not-a-real-host.invalid", resolve_dns=True)
        self.assertFalse(safe)
        self.assertTrue("DNS" in reason or "resolution" in reason.lower())


if __name__ == "__main__":
    unittest.main()
