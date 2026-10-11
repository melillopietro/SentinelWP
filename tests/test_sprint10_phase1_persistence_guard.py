"""
Sprint 10 - Phase 1: Fail-Closed Persistence Guard and Configuration Tests

Tests deterministic PostgreSQL configuration detection, URL credential sanitization,
startup connectivity guards for Flask and Celery, and the fail-closed protection
against accidental operational SQLite fallback.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import is_postgres_configured, sanitize_db_url
from core.db.session import verify_operational_persistence_guard, reset_engine
from core import repository
from core.vulnerability_intelligence import repository as vuln_repo
from tests.postgres_integration import get_sprint10_postgres_url


UNREACHABLE_POSTGRES_URL = "postgresql://s10_user:super_secret_leak_pwd@127.0.0.1:54399/sentinelwp_s10"


class TestSprint10PersistenceGuard(unittest.TestCase):
    def tearDown(self):
        reset_engine()
        repository.reset_conn()
        repository._allow_operational_sqlite_override = False

    # 1. Deterministic Backend Selection
    def test_is_postgres_configured_detection(self):
        self.assertFalse(is_postgres_configured("sqlite:///data/wsa.db"))
        self.assertFalse(is_postgres_configured("sqlite:///:memory:"))
        self.assertFalse(is_postgres_configured(""))
        self.assertFalse(is_postgres_configured(None))

        self.assertTrue(is_postgres_configured("postgresql://user:pass@host:5432/db"))
        self.assertTrue(is_postgres_configured("postgres://user:pass@host:5432/db"))
        self.assertTrue(is_postgres_configured("postgresql+psycopg://user:pass@host:5432/db"))
        self.assertTrue(is_postgres_configured("POSTGRESQL://user:pass@host:5432/db"))

    # 2. Credential Sanitization
    def test_sanitize_db_url_redacts_passwords(self):
        raw_url = "postgresql://app_user:s3cr3t_p@ssw0rd!@10.0.0.5:5432/sentinelwp"
        sanitized = sanitize_db_url(raw_url)
        self.assertNotIn("s3cr3t_p@ssw0rd!", sanitized)
        self.assertIn("app_user:***@", sanitized)
        self.assertIn("10.0.0.5:5432/sentinelwp", sanitized)

    def test_sanitize_db_url_leaves_safe_urls_intact(self):
        sqlite_url = "sqlite:///Users/piero/Downloads/SentinelWP/data/wsa.db"
        self.assertEqual(sanitize_db_url(sqlite_url), sqlite_url)

        no_pass_url = "postgresql://localhost:5432/sentinelwp"
        self.assertEqual(sanitize_db_url(no_pass_url), no_pass_url)

    # 3. Startup Connectivity Guard (SQLite mode)
    def test_startup_guard_succeeds_in_sqlite_mode(self):
        result = verify_operational_persistence_guard(db_url="sqlite:///data/wsa.db")
        self.assertTrue(result)

    # 4. Startup Connectivity Guard with Live PostgreSQL
    def test_startup_guard_succeeds_with_live_postgres(self):
        result = verify_operational_persistence_guard(db_url=get_sprint10_postgres_url(), timeout_seconds=3.0)
        self.assertTrue(result)

    # 5. Startup Connectivity Guard Fails Fast on Unreachable PostgreSQL (Zero Credential Leakage)
    def test_startup_guard_fails_closed_and_redacts_credentials(self):
        with self.assertRaises(RuntimeError) as ctx:
            verify_operational_persistence_guard(db_url=UNREACHABLE_POSTGRES_URL, timeout_seconds=1.0)
        
        err_msg = str(ctx.exception)
        self.assertIn("PostgreSQL startup persistence guard failed", err_msg)
        self.assertIn("127.0.0.1:54399", err_msg)
        self.assertNotIn("super_secret_leak_pwd", err_msg, "CRITICAL: Password must never be exposed in diagnostic errors!")
        self.assertIn("***@", err_msg)

    # 6. Guard Against Accidental Operational SQLite Fallback
    def test_operational_sqlite_blocked_when_postgres_configured(self):
        # Verify that in normal SQLite mode, repository._get_conn() works
        with patch("core.repository.is_postgres_configured", return_value=False):
            repository.reset_conn()
            conn = repository._get_conn()
            self.assertIsNotNone(conn)
            self.assertEqual(type(conn).__name__, "Connection")

        # When PostgreSQL is configured, calling repository._get_conn() MUST fail-closed
        with patch("core.repository.is_postgres_configured", return_value=True):
            repository.reset_conn()
            with self.assertRaises(RuntimeError) as ctx:
                repository._get_conn()
            self.assertIn("Operational SQLite access blocked", str(ctx.exception))
            self.assertIn("split-brain", str(ctx.exception))

    # 7. Distinct Intelligence Store Remains Accessible
    def test_distinct_vulnerability_intelligence_store_operates_independently(self):
        # Vulnerability intelligence store connects via its own authorized connection handler
        vuln_conn = vuln_repo._get_vuln_conn()
        self.assertIsNotNone(vuln_conn)
        row = vuln_conn.execute("SELECT 1 AS ok").fetchone()
        self.assertEqual(row["ok"], 1)

    # 8. Flask Readiness Endpoint Reflects Persistence Backend
    def test_flask_readiness_endpoint_in_postgres_mode(self):
        from app import app
        app.config["TESTING"] = True
        client = app.test_client()

        # Test live PostgreSQL readiness
        with patch("app.is_postgres_configured", return_value=True):
            with patch.dict(os.environ, {"DATABASE_URL": get_sprint10_postgres_url()}):
                resp = client.get("/ready")
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertEqual(data["checks"].get("database"), "connected")
                self.assertEqual(data["checks"].get("storage_backend"), "postgresql")

        # Test unreachable PostgreSQL readiness
        with patch("app.is_postgres_configured", return_value=True):
            with patch.dict(os.environ, {"DATABASE_URL": UNREACHABLE_POSTGRES_URL}):
                resp = client.get("/ready")
                self.assertEqual(resp.status_code, 503)
                data = resp.get_json()
                self.assertIn("error", data["checks"].get("database", ""))
                # Ensure no credential leakage in ready check payload
                self.assertNotIn("super_secret_leak_pwd", str(data))

    # 9. Celery Signals Fail-Closed Guard
    def test_celery_signals_trigger_guard(self):
        from core.tasks.celery_app import on_worker_init, on_beat_init

        # Live PostgreSQL: worker and beat signals succeed
        with patch("core.tasks.celery_app.is_postgres_configured", return_value=True):
            with patch.dict(os.environ, {"DATABASE_URL": get_sprint10_postgres_url()}):
                on_worker_init()
                on_beat_init()

        # Unreachable PostgreSQL: worker and beat signals fail closed
        with patch("core.tasks.celery_app.is_postgres_configured", return_value=True):
            with patch.dict(os.environ, {"DATABASE_URL": UNREACHABLE_POSTGRES_URL}):
                with self.assertRaises(RuntimeError) as ctx_worker:
                    on_worker_init()
                self.assertNotIn("super_secret_leak_pwd", str(ctx_worker.exception))

                with self.assertRaises(RuntimeError) as ctx_beat:
                    on_beat_init()
                self.assertNotIn("super_secret_leak_pwd", str(ctx_beat.exception))


if __name__ == "__main__":
    unittest.main()
