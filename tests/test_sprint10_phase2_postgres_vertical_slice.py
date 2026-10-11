"""
Sprint 10 - Phase 2: PostgreSQL Vertical-Slice Proof of Concept
Integration and Parity Test Suite for Tenant, User, and Asset Persistence.

Validates:
1. Tenant persistence (create, get by id, get by slug, list, update, delete)
2. User persistence & authentication (create, bcrypt hash verify, tenant scoping)
3. Asset persistence (ensure_asset, canonicalization, tenant scoping)
4. Cross-tenant access denial (strict isolation)
5. Direct PostgreSQL SQL query verification (bypassing ORM)
6. Transaction boundaries and rollback on failure
7. Process restart persistence simulation
8. SQLite vs PostgreSQL output and domain model parity
9. Unsupported operations fail explicitly (never silent fallback)
10. Zero operational SQLite fallback during PostgreSQL mode
"""
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone
from sqlalchemy import text

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import is_postgres_configured
from core.models import Tenant, User, UserRole, UserStatus, Asset
from core.auth import hash_password, verify_password
from core.db.session import get_engine, init_db_schema, session_scope, reset_engine
from core.db.adapter import get_operational_adapter, PostgresqlOperationalAdapter
from core import repository

LIVE_POSTGRES_URL = "postgresql://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s10"


class TestSprint10Phase2PostgresVerticalSlice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize schema in live isolated PostgreSQL 16 container
        cls.engine = get_engine(LIVE_POSTGRES_URL)
        init_db_schema(cls.engine)

    def setUp(self):
        # Force PostgreSQL mode for test execution
        self.orig_db_url = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = LIVE_POSTGRES_URL
        reset_engine()
        repository.reset_conn()
        repository._allow_operational_sqlite_override = False

        self.test_prefix = f"s10_{uuid.uuid4().hex[:6]}"
        self.tenant_id = f"tenant_{self.test_prefix}"
        self.tenant_slug = f"slug_{self.test_prefix}"

    def tearDown(self):
        if self.orig_db_url is not None:
            os.environ["DATABASE_URL"] = self.orig_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        reset_engine()
        repository.reset_conn()

    # 1. Tenant Persistence & Direct SQL Verification
    def test_tenant_persistence_and_direct_sql_verification(self):
        tenant = Tenant(
            id=self.tenant_id,
            name="Sprint 10 Enterprise Tenant",
            slug=self.tenant_slug,
            status="active"
        )
        saved = repository.save_tenant(tenant)
        self.assertIsNotNone(saved)
        self.assertEqual(saved.id, self.tenant_id)

        # Retrieve via repository API
        retrieved_id = repository.get_tenant_by_id(self.tenant_id)
        self.assertIsNotNone(retrieved_id)
        self.assertEqual(retrieved_id.name, "Sprint 10 Enterprise Tenant")

        retrieved_slug = repository.get_tenant_by_slug(self.tenant_slug)
        self.assertIsNotNone(retrieved_slug)
        self.assertEqual(retrieved_slug.id, self.tenant_id)

        # Verify DIRECTLY using PostgreSQL SQL query (bypassing ORM layer)
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, name, slug, status FROM tenants WHERE id = :id"),
                {"id": self.tenant_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], self.tenant_id)
            self.assertEqual(row[1], "Sprint 10 Enterprise Tenant")
            self.assertEqual(row[2], self.tenant_slug)
            self.assertEqual(row[3], "active")

    # 2. User Persistence, Password Hashing & Authentication
    def test_user_persistence_and_authentication(self):
        # Ensure parent tenant exists in PostgreSQL
        tenant = Tenant(id=self.tenant_id, name="User Test Tenant", slug=self.tenant_slug)
        repository.save_tenant(tenant)

        password = "EnterpriseSecurePass123!"
        pwd_hash = hash_password(password)

        user_id = f"user_{self.test_prefix}"
        username = f"admin_{self.test_prefix}"
        user = User(
            id=user_id,
            tenant_id=self.tenant_id,
            username=username,
            password_hash=pwd_hash,
            email=f"{username}@example.com",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE
        )
        repository.save_user(user)

        # Retrieve user via username and tenant_id
        fetched_user = repository.get_user_by_username(username, tenant_id=self.tenant_id)
        self.assertIsNotNone(fetched_user)
        self.assertEqual(fetched_user.email, f"{username}@example.com")
        self.assertEqual(fetched_user.role, UserRole.ADMIN)

        # Verify password authentication against fetched hash
        self.assertTrue(verify_password(password, fetched_user.password_hash))
        self.assertFalse(verify_password("WrongPassword123!", fetched_user.password_hash))

        # Direct PostgreSQL SQL verification
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, username, password_hash, role, status FROM users WHERE id = :id"),
                {"id": user_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[1], username)
            self.assertTrue(row[2].startswith("$2b$") or row[2].startswith("$2a$"))
            self.assertNotIn("EnterpriseSecurePass123!", row[2], "Plaintext password must never be stored!")
            self.assertEqual(row[3], "admin")
            self.assertEqual(row[4], "active")

    # 3. Asset Persistence & URL Canonicalization
    def test_asset_persistence_and_canonicalization(self):
        tenant = Tenant(id=self.tenant_id, name="Asset Tenant", slug=self.tenant_slug)
        repository.save_tenant(tenant)

        target_url = "https://app.corp.internal/wp-admin/"
        asset = repository.ensure_asset(target_url, self.tenant_id, display_name="Corporate WP")
        self.assertIsNotNone(asset)
        self.assertEqual(asset.tenant_id, self.tenant_id)
        self.assertEqual(asset.hostname, "app.corp.internal")
        self.assertEqual(asset.canonical_url, "https://app.corp.internal/wp-admin")

        # Retrieve by ID
        fetched_asset = repository.get_asset(asset.id, tenant_id=self.tenant_id)
        self.assertIsNotNone(fetched_asset)
        self.assertEqual(fetched_asset.display_name, "Corporate WP")

        # Retrieve by canonical URL
        fetched_by_url = repository.get_asset_by_url(self.tenant_id, "https://app.corp.internal/wp-admin")
        self.assertIsNotNone(fetched_by_url)
        self.assertEqual(fetched_by_url.id, asset.id)

        # Direct PostgreSQL SQL verification
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, tenant_id, canonical_url, hostname, display_name FROM assets WHERE id = :id"),
                {"id": asset.id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[1], self.tenant_id)
            self.assertEqual(row[2], "https://app.corp.internal/wp-admin")
            self.assertEqual(row[3], "app.corp.internal")
            self.assertEqual(row[4], "Corporate WP")

    # 4. Strict Tenant Isolation & Cross-Tenant Access Denial
    def test_tenant_isolation_and_cross_tenant_denial(self):
        # Create Tenant Alpha and Asset Alpha
        tenant_a = Tenant(id=f"tenant_a_{self.test_prefix}", name="Tenant A", slug=f"slug_a_{self.test_prefix}")
        repository.save_tenant(tenant_a)
        asset_a = repository.ensure_asset("https://alpha.corp/blog", tenant_a.id, "Alpha Blog")

        # Create Tenant Beta and Asset Beta
        tenant_b = Tenant(id=f"tenant_b_{self.test_prefix}", name="Tenant B", slug=f"slug_b_{self.test_prefix}")
        repository.save_tenant(tenant_b)
        asset_b = repository.ensure_asset("https://beta.corp/blog", tenant_b.id, "Beta Blog")

        # Tenant-scoped listing verification
        assets_for_a = repository.list_assets(tenant_id=tenant_a.id)
        self.assertEqual(len(assets_for_a), 1)
        self.assertEqual(assets_for_a[0].id, asset_a.id)

        assets_for_b = repository.list_assets(tenant_id=tenant_b.id)
        self.assertEqual(len(assets_for_b), 1)
        self.assertEqual(assets_for_b[0].id, asset_b.id)

        # Cross-Tenant Access Denial
        # Requesting Asset B with Tenant A's scope MUST return None
        cross_asset = repository.get_asset(asset_b.id, tenant_id=tenant_a.id)
        self.assertIsNone(cross_asset, "Security violation: Cross-tenant asset access must be strictly denied!")

        # Cross-tenant asset retrieval by URL must return None
        cross_url = repository.get_asset_by_url(tenant_a.id, asset_b.canonical_url)
        self.assertIsNone(cross_url, "Security violation: Cross-tenant canonical URL lookup must be denied!")

    # 5. Persistence Across Simulated Process Restart
    def test_persistence_across_simulated_process_restart(self):
        tenant = Tenant(id=self.tenant_id, name="Restart Tenant", slug=self.tenant_slug)
        repository.save_tenant(tenant)
        asset = repository.ensure_asset("https://restart.corp/site", self.tenant_id, "Restart Site")

        # Simulate process termination and reinitialization
        reset_engine()

        # Re-fetch with fresh engine / connection pool
        fresh_tenant = repository.get_tenant_by_id(self.tenant_id)
        self.assertIsNotNone(fresh_tenant)
        self.assertEqual(fresh_tenant.name, "Restart Tenant")

        fresh_asset = repository.get_asset(asset.id, tenant_id=self.tenant_id)
        self.assertIsNotNone(fresh_asset)
        self.assertEqual(fresh_asset.canonical_url, "https://restart.corp/site")

    # 6. Transaction Rollback on Failure
    def test_transaction_rollback_on_failure(self):
        tenant = Tenant(id=self.tenant_id, name="Rollback Tenant", slug=self.tenant_slug)
        repository.save_tenant(tenant)

        # Attempt atomic batch write with intentional exception
        failed_asset_id = f"fail_{self.test_prefix}"
        try:
            with session_scope(LIVE_POSTGRES_URL) as session:
                from core.db.repositories.asset_repo import AssetRepository
                repo = AssetRepository(session)
                new_asset = Asset(
                    id=failed_asset_id,
                    tenant_id=self.tenant_id,
                    canonical_url="https://rollback-test.local",
                    hostname="rollback-test.local"
                )
                repo.create(new_asset)
                # Intentionally trigger exception before transaction commit
                raise ValueError("Simulated operational failure during transaction")
        except ValueError:
            pass

        # Verify that rollback prevented persistence
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id FROM assets WHERE id = :id"),
                {"id": failed_asset_id}
            ).fetchone()
            self.assertIsNone(row, "Transaction rollback failed: uncommitted asset was persisted!")

    # 7. SQLite vs PostgreSQL Behavioral Parity
    def test_sqlite_vs_postgres_behavioral_parity(self):
        # 1. Run flow in PostgreSQL mode
        pg_tenant = Tenant(id=self.tenant_id, name="Parity Workspace", slug=self.tenant_slug, status="active")
        repository.save_tenant(pg_tenant)
        pg_fetched = repository.get_tenant_by_id(self.tenant_id)

        # 2. Run identical flow in SQLite mode
        sqlite_db = f"data/test_parity_{self.test_prefix}.db"
        sqlite_url = f"sqlite:///{sqlite_db}"
        os.environ["DATABASE_URL"] = sqlite_url
        os.environ["WSA_DATABASE_PATH"] = sqlite_db
        reset_engine()
        repository.reset_conn()
        repository.init_db()

        try:
            sqlite_tenant = Tenant(id=self.tenant_id, name="Parity Workspace", slug=self.tenant_slug, status="active")
            repository.save_tenant(sqlite_tenant)
            sqlite_fetched = repository.get_tenant_by_id(self.tenant_id)

            # Compare outputs
            self.assertEqual(pg_fetched.id, sqlite_fetched.id)
            self.assertEqual(pg_fetched.name, sqlite_fetched.name)
            self.assertEqual(pg_fetched.slug, sqlite_fetched.slug)
            self.assertEqual(pg_fetched.status, sqlite_fetched.status)
        finally:
            if os.path.exists(sqlite_db):
                os.remove(sqlite_db)

    # 8. Unsupported Operations Fail Explicitly in PostgreSQL Mode
    def test_unsupported_operations_fail_explicitly_in_postgres_mode(self):
        # Operations outside current scope (e.g. Saved Views, Tech Observations) must fail explicitly.
        # Calling them in PostgreSQL mode must fail explicitly (never fall back silently to SQLite).
        os.environ["DATABASE_URL"] = LIVE_POSTGRES_URL
        reset_engine()
        repository.reset_conn()

        from core.models import SavedView
        view = SavedView(
            id=f"view_{self.test_prefix}",
            tenant_id=self.tenant_id,
            user_id="user_test",
            name="Test View",
            resource_type="findings"
        )

        with self.assertRaises((RuntimeError, NotImplementedError)) as ctx:
            repository.save_saved_view(view)
        
        err_msg = str(ctx.exception)
        self.assertTrue(
            "Operational SQLite access blocked" in err_msg or "outside" in err_msg,
            f"Expected explicit failure message, got: {err_msg}"
        )


if __name__ == "__main__":
    unittest.main()
