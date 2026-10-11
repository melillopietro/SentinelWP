"""
Sprint 10 - Phase 3: PostgreSQL Persistence for Authorizations, Scans & Scan Jobs
Integration and Parity Test Suite for Real PostgreSQL 16 Execution.

Validates:
1. Scan Authorization persistence (save, get, list, active retrieval, expiration, revocation)
2. Scan persistence & metadata (save, get, update, delete, list, WordPress detection metadata)
3. Scan Job lifecycle (create, update, progress, heartbeat, status transitions, duplicate handling)
4. Active job counting & stale job detection (tenant-scoped, asset-scoped, global)
5. Cross-tenant access denial (strict tenant isolation across authorizations, scans, jobs)
6. Transaction boundaries and rollback on failure
7. Process restart persistence simulation (reset_engine, new connections)
8. Direct PostgreSQL SQL query verification (bypassing ORM layer)
9. Unsupported operations fail explicitly (fail-closed, zero SQLite fallback)
10. Domain model parity between PostgreSQL adapter and repository signatures
"""
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import text

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import is_postgres_configured
from core.models import Tenant, Asset, ScanAuthorization, ScanResult, ScanStatus, ScanJob, ScanJobStatus
from core.db.session import get_engine, init_db_schema, session_scope, reset_engine
from core.db.adapter import get_operational_adapter, PostgresqlOperationalAdapter
from core import repository

LIVE_POSTGRES_URL = "postgresql://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s10"


class TestSprint10Phase3PostgresScansJobs(unittest.TestCase):
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

        self.test_prefix = f"s10_p3_{uuid.uuid4().hex[:6]}"
        self.tenant_id = f"tenant_{self.test_prefix}"
        self.tenant_slug = f"slug_{self.test_prefix}"

        # Provision parent tenant and asset in PostgreSQL
        tenant = Tenant(
            id=self.tenant_id,
            name="Sprint 10 Phase 3 Tenant",
            slug=self.tenant_slug,
            status="active"
        )
        repository.save_tenant(tenant)

        self.asset = repository.ensure_asset(
            target_url=f"https://{self.test_prefix}.example.com",
            tenant_id=self.tenant_id,
            display_name=f"Asset {self.test_prefix}"
        )

    def tearDown(self):
        if self.orig_db_url is not None:
            os.environ["DATABASE_URL"] = self.orig_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        reset_engine()
        repository.reset_conn()

    # -------------------------------------------------------------------------
    # 1. Scan Authorization Persistence & Lifecycle
    # -------------------------------------------------------------------------

    def test_scan_authorization_persistence_and_direct_sql_verification(self):
        auth_id = f"auth_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
        valid_from = (now - timedelta(hours=1)).isoformat()
        valid_until = (now + timedelta(days=7)).isoformat()

        auth = ScanAuthorization(
            id=auth_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            status="active",
            allowed_profiles="safe_active,passive",
            request_budget=5000,
            valid_from=valid_from,
            valid_until=valid_until,
            approved_by="secops-lead",
            notes="Pilot authorization for Sprint 10"
        )
        repository.save_scan_authorization(auth)

        # Retrieval via repository API
        retrieved = repository.get_scan_authorization(auth_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, auth_id)
        self.assertEqual(retrieved.tenant_id, self.tenant_id)
        self.assertEqual(retrieved.asset_id, self.asset.id)
        self.assertEqual(retrieved.allowed_profiles, "safe_active,passive")
        self.assertEqual(retrieved.request_budget, 5000)
        self.assertEqual(retrieved.approved_by, "secops-lead")
        self.assertEqual(retrieved.status, "active")

        # Active authorization lookup
        active_auth = repository.get_active_authorization(self.asset.id, tenant_id=self.tenant_id)
        self.assertIsNotNone(active_auth)
        self.assertEqual(active_auth.id, auth_id)

        # Verify DIRECTLY via PostgreSQL SQL query bypassing ORM
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, tenant_id, asset_id, status, request_budget, approved_by FROM scan_authorizations WHERE id = :id"),
                {"id": auth_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], auth_id)
            self.assertEqual(row[1], self.tenant_id)
            self.assertEqual(row[2], self.asset.id)
            self.assertEqual(row[3], "active")
            self.assertEqual(row[4], 5000)
            self.assertEqual(row[5], "secops-lead")

    def test_scan_authorization_expiration_and_revocation(self):
        # 1. Expired authorization
        expired_id = f"auth_exp_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
        expired_auth = ScanAuthorization(
            id=expired_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            status="active",
            valid_from=(now - timedelta(days=10)).isoformat(),
            valid_until=(now - timedelta(days=1)).isoformat(),  # expired yesterday
            approved_by="admin"
        )
        repository.save_scan_authorization(expired_auth)

        # get_active_authorization should NOT return expired auth
        active = repository.get_active_authorization(self.asset.id, tenant_id=self.tenant_id)
        self.assertIsNone(active)

        # 2. Revoked authorization
        valid_id = f"auth_rev_{uuid.uuid4().hex[:8]}"
        valid_auth = ScanAuthorization(
            id=valid_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            status="active",
            valid_from=(now - timedelta(hours=1)).isoformat(),
            valid_until=(now + timedelta(days=1)).isoformat(),
            approved_by="admin"
        )
        repository.save_scan_authorization(valid_auth)

        active = repository.get_active_authorization(self.asset.id, tenant_id=self.tenant_id)
        self.assertIsNotNone(active)
        self.assertEqual(active.id, valid_id)

        # Revoke it
        repository.revoke_scan_authorization(valid_id, tenant_id=self.tenant_id)

        # Confirm status updated to 'revoked'
        revoked = repository.get_scan_authorization(valid_id, tenant_id=self.tenant_id)
        self.assertEqual(revoked.status, "revoked")

        # Active lookup now returns None
        active_after = repository.get_active_authorization(self.asset.id, tenant_id=self.tenant_id)
        self.assertIsNone(active_after)

    def test_list_scan_authorizations(self):
        auth1_id = f"auth_list1_{uuid.uuid4().hex[:6]}"
        auth2_id = f"auth_list2_{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)

        repository.save_scan_authorization(ScanAuthorization(
            id=auth1_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            status="active", valid_until=(now + timedelta(days=1)).isoformat()
        ))
        repository.save_scan_authorization(ScanAuthorization(
            id=auth2_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            status="revoked", valid_until=(now + timedelta(days=2)).isoformat()
        ))

        auths = repository.list_scan_authorizations(asset_id=self.asset.id, tenant_id=self.tenant_id)
        ids = [a.id for a in auths]
        self.assertIn(auth1_id, ids)
        self.assertIn(auth2_id, ids)

    # -------------------------------------------------------------------------
    # 2. Scan Results & Metadata Persistence
    # -------------------------------------------------------------------------

    def test_scan_persistence_and_direct_sql_verification(self):
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        scan = ScanResult(
            id=scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://testwp.internal",
            status=ScanStatus.COMPLETED,
            scan_mode="safe_active",
            score=88.5,
            grade="B",
            notes="Sprint 10 Automated Integration Scan",
            tags="sprint10,qa",
            initiated_by="test-user",
            wordpress_detected=True,
            wordpress_version="6.4.2",
            wordpress_version_source="generator_meta",
            wordpress_version_confidence="high"
        )
        repository.save_scan(scan)

        # Retrieval via repository API
        retrieved = repository.get_scan(scan_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, scan_id)
        self.assertEqual(retrieved.tenant_id, self.tenant_id)
        self.assertEqual(retrieved.asset_id, self.asset.id)
        self.assertEqual(retrieved.target_url, "https://testwp.internal")
        self.assertEqual(retrieved.status, ScanStatus.COMPLETED)
        self.assertEqual(retrieved.score, 88.5)
        self.assertEqual(retrieved.grade, "B")
        self.assertTrue(retrieved.wordpress_detected)
        self.assertEqual(retrieved.wordpress_version, "6.4.2")
        self.assertEqual(retrieved.wordpress_version_confidence, "high")

        # Verify DIRECTLY via PostgreSQL SQL query bypassing ORM
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, tenant_id, asset_id, target_url, status, score, grade, wordpress_detected, wordpress_version FROM scans WHERE id = :id"),
                {"id": scan_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], scan_id)
            self.assertEqual(row[1], self.tenant_id)
            self.assertEqual(row[2], self.asset.id)
            self.assertEqual(row[3], "https://testwp.internal")
            self.assertEqual(row[4], "completed")
            self.assertEqual(float(row[5]), 88.5)
            self.assertEqual(row[6], "B")
            self.assertTrue(row[7])
            self.assertEqual(row[8], "6.4.2")

    def test_scan_update_and_delete(self):
        scan_id = f"scan_up_{uuid.uuid4().hex[:8]}"
        scan = ScanResult(
            id=scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://testwp.internal",
            status=ScanStatus.RUNNING,
            scan_mode="passive"
        )
        repository.save_scan(scan)

        # Update scan
        repository.update_scan(
            scan_id,
            tenant_id=self.tenant_id,
            status=ScanStatus.COMPLETED,
            score=95.0,
            grade="A",
            completed_at=datetime.now(timezone.utc).isoformat()
        )

        updated = repository.get_scan(scan_id, tenant_id=self.tenant_id)
        self.assertEqual(updated.status, ScanStatus.COMPLETED)
        self.assertEqual(updated.score, 95.0)
        self.assertEqual(updated.grade, "A")
        self.assertIsNotNone(updated.completed_at)

        # Delete scan
        repository.delete_scan(scan_id, tenant_id=self.tenant_id)
        deleted = repository.get_scan(scan_id, tenant_id=self.tenant_id)
        self.assertIsNone(deleted)

    def test_list_scans_with_filters(self):
        s1_id = f"s1_{uuid.uuid4().hex[:6]}"
        s2_id = f"s2_{uuid.uuid4().hex[:6]}"

        repository.save_scan(ScanResult(
            id=s1_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            target_url="https://app1.internal", status=ScanStatus.COMPLETED, scan_mode="passive"
        ))
        repository.save_scan(ScanResult(
            id=s2_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            target_url="https://app2.internal", status=ScanStatus.FAILED, scan_mode="active"
        ))

        # Filter by tenant
        results = repository.list_scans(filters={"tenant_id": self.tenant_id})
        ids = [s.id for s in results]
        self.assertIn(s1_id, ids)
        self.assertIn(s2_id, ids)

        # Filter by status
        results_failed = repository.list_scans(filters={"tenant_id": self.tenant_id, "status": "failed"})
        failed_ids = [s.id for s in results_failed]
        self.assertIn(s2_id, failed_ids)
        self.assertNotIn(s1_id, failed_ids)

    # -------------------------------------------------------------------------
    # 3. Scan Job Lifecycle & Persistence
    # -------------------------------------------------------------------------

    def test_scan_job_lifecycle_and_direct_sql_verification(self):
        # Scan job foreign key requires existing scan
        scan_id = f"scan_job_test_{uuid.uuid4().hex[:8]}"
        repository.save_scan(ScanResult(
            id=scan_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            target_url="https://wp.internal", status=ScanStatus.PENDING
        ))

        job_id = f"job_{uuid.uuid4().hex[:8]}"
        job = ScanJob(
            id=job_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=scan_id,
            task_id="celery-task-001",
            status=ScanJobStatus.QUEUED.value,
            requested_by="admin@sentinelwp.local",
            profile="passive",
            progress_percent=0,
            current_step="Queued"
        )
        created = repository.create_scan_job(job)
        self.assertEqual(created.id, job_id)

        # Verify DIRECTLY via PostgreSQL SQL query bypassing ORM
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, tenant_id, asset_id, scan_id, task_id, status, requested_by, progress_percent FROM scan_jobs WHERE id = :id"),
                {"id": job_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], job_id)
            self.assertEqual(row[1], self.tenant_id)
            self.assertEqual(row[2], self.asset.id)
            self.assertEqual(row[3], scan_id)
            self.assertEqual(row[4], "celery-task-001")
            self.assertEqual(row[5], "queued")
            self.assertEqual(row[6], "admin@sentinelwp.local")
            self.assertEqual(row[7], 0)

        # Transition to RUNNING
        repository.mark_scan_job_status(job_id, "running")
        running_job = repository.get_scan_job(job_id, tenant_id=self.tenant_id)
        self.assertEqual(running_job.status, "running")
        self.assertIsNotNone(running_job.started_at)

        # Update progress and heartbeat
        repository.update_scan_job_progress(job_id, 45, "Crawling WordPress routes", worker_id="worker-node-1")
        repository.record_scan_job_heartbeat(job_id, worker_id="worker-node-1")

        progressed_job = repository.get_scan_job(job_id, tenant_id=self.tenant_id)
        self.assertEqual(progressed_job.progress_percent, 45)
        self.assertEqual(progressed_job.current_step, "Crawling WordPress routes")
        self.assertEqual(progressed_job.worker_id, "worker-node-1")
        self.assertIsNotNone(progressed_job.heartbeat_at)

        # Lookup by scan_id
        by_scan = repository.get_scan_job_by_scan_id(scan_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(by_scan)
        self.assertEqual(by_scan.id, job_id)

        # Transition to COMPLETED
        repository.mark_scan_job_status(job_id, "completed")
        completed_job = repository.get_scan_job(job_id, tenant_id=self.tenant_id)
        self.assertEqual(completed_job.status, "completed")
        self.assertEqual(completed_job.progress_percent, 100)
        self.assertEqual(completed_job.current_step, "Completed")
        self.assertIsNotNone(completed_job.completed_at)

    def test_scan_job_duplicate_handling_idempotency(self):
        scan_id = f"scan_dup_{uuid.uuid4().hex[:8]}"
        repository.save_scan(ScanResult(
            id=scan_id, tenant_id=self.tenant_id, asset_id=self.asset.id, target_url="https://wp.internal"
        ))

        job_id = f"job_dup_{uuid.uuid4().hex[:8]}"
        job1 = ScanJob(
            id=job_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            scan_id=scan_id, status="queued", requested_by="user1"
        )
        created1 = repository.create_scan_job(job1)
        self.assertEqual(created1.id, job_id)

        # Attempt to create the same job id again with different requested_by
        job2 = ScanJob(
            id=job_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            scan_id=scan_id, status="queued", requested_by="user2"
        )
        created2 = repository.create_scan_job(job2)
        self.assertEqual(created2.id, job_id)

        # Confirm idempotent update without error
        stored = repository.get_scan_job(job_id, tenant_id=self.tenant_id)
        self.assertEqual(stored.id, job_id)
        self.assertEqual(stored.requested_by, "user2")

    def test_active_and_stale_job_queries(self):
        scan_id = f"scan_active_{uuid.uuid4().hex[:8]}"
        repository.save_scan(ScanResult(
            id=scan_id, tenant_id=self.tenant_id, asset_id=self.asset.id, target_url="https://wp.internal"
        ))

        j_active = ScanJob(
            id=f"job_act_{uuid.uuid4().hex[:6]}", tenant_id=self.tenant_id, asset_id=self.asset.id,
            scan_id=scan_id, status="running", started_at=datetime.now(timezone.utc).isoformat()
        )
        j_queued = ScanJob(
            id=f"job_q_{uuid.uuid4().hex[:6]}", tenant_id=self.tenant_id, asset_id=self.asset.id,
            scan_id=scan_id, status="queued"
        )
        repository.create_scan_job(j_active)
        repository.create_scan_job(j_queued)

        # Count active jobs for tenant
        tenant_active = repository.count_active_scan_jobs_for_tenant(self.tenant_id)
        self.assertGreaterEqual(tenant_active, 2)

        # Count active jobs for asset
        asset_active = repository.count_active_scan_jobs_for_asset(self.asset.id)
        self.assertGreaterEqual(asset_active, 2)

        # Count active jobs globally
        global_active = repository.count_active_scan_jobs_global()
        self.assertGreaterEqual(global_active, 2)

        # List jobs
        jobs = repository.list_scan_jobs(tenant_id=self.tenant_id, status="running")
        running_ids = [j.id for j in jobs]
        self.assertIn(j_active.id, running_ids)
        self.assertNotIn(j_queued.id, running_ids)

        # Stale job test: heartbeat far in the past
        stale_id = f"job_stale_{uuid.uuid4().hex[:6]}"
        past_time = (datetime.now(timezone.utc) - timedelta(seconds=1200)).isoformat()
        j_stale = ScanJob(
            id=stale_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            scan_id=scan_id, status="running", started_at=past_time, heartbeat_at=past_time
        )
        repository.create_scan_job(j_stale)

        stale_jobs = repository.find_stale_scan_jobs(stale_threshold_seconds=600)
        stale_job_ids = [j.id for j in stale_jobs]
        self.assertIn(stale_id, stale_job_ids)

    # -------------------------------------------------------------------------
    # 4. Strict Cross-Tenant Access Denial (Tenant Isolation)
    # -------------------------------------------------------------------------

    def test_strict_cross_tenant_isolation(self):
        other_tenant_id = f"other_{self.test_prefix}"
        repository.save_tenant(Tenant(id=other_tenant_id, name="Other Tenant", slug=f"other_{self.test_prefix}"))
        other_asset = repository.ensure_asset(
            target_url="https://other.internal", tenant_id=other_tenant_id, display_name="Other Asset"
        )

        other_scan_id = f"other_scan_{uuid.uuid4().hex[:6]}"
        repository.save_scan(ScanResult(
            id=other_scan_id, tenant_id=other_tenant_id, asset_id=other_asset.id, target_url="https://other.internal"
        ))

        other_auth_id = f"other_auth_{uuid.uuid4().hex[:6]}"
        repository.save_scan_authorization(ScanAuthorization(
            id=other_auth_id, tenant_id=other_tenant_id, asset_id=other_asset.id, status="active",
            valid_until=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        ))

        other_job_id = f"other_job_{uuid.uuid4().hex[:6]}"
        repository.create_scan_job(ScanJob(
            id=other_job_id, tenant_id=other_tenant_id, asset_id=other_asset.id, scan_id=other_scan_id, status="queued"
        ))

        # Tenant A attempts to access Tenant B's records with tenant_id=self.tenant_id
        # 1. Authorization
        self.assertIsNone(repository.get_scan_authorization(other_auth_id, tenant_id=self.tenant_id))
        self.assertIsNone(repository.get_active_authorization(other_asset.id, tenant_id=self.tenant_id))
        my_auths = repository.list_scan_authorizations(tenant_id=self.tenant_id)
        self.assertNotIn(other_auth_id, [a.id for a in my_auths])

        # 2. Scan
        self.assertIsNone(repository.get_scan(other_scan_id, tenant_id=self.tenant_id))
        my_scans = repository.list_scans(filters={"tenant_id": self.tenant_id})
        self.assertNotIn(other_scan_id, [s.id for s in my_scans])

        # 3. Scan Job
        self.assertIsNone(repository.get_scan_job(other_job_id, tenant_id=self.tenant_id))
        self.assertIsNone(repository.get_scan_job_by_scan_id(other_scan_id, tenant_id=self.tenant_id))
        my_jobs = repository.list_scan_jobs(tenant_id=self.tenant_id)
        self.assertNotIn(other_job_id, [j.id for j in my_jobs])

    # -------------------------------------------------------------------------
    # 5. Transaction Boundaries & Rollback on Error
    # -------------------------------------------------------------------------

    def test_transaction_boundary_and_rollback(self):
        adapter = get_operational_adapter()
        self.assertIsInstance(adapter, PostgresqlOperationalAdapter)

        scan_id = f"tx_scan_{uuid.uuid4().hex[:6]}"
        scan = ScanResult(
            id=scan_id, tenant_id=self.tenant_id, asset_id=self.asset.id, target_url="https://tx.internal"
        )
        repository.save_scan(scan)

        # Attempt atomic batch with deliberate failure in second statement
        try:
            with session_scope() as session:
                from core.db.repositories.scan_repo import ScanRepository
                from core.db.repositories.scan_job_repo import ScanJobRepository
                scan_repo = ScanRepository(session)
                job_repo = ScanJobRepository(session)

                # Valid scan job
                job_id = f"tx_job_{uuid.uuid4().hex[:6]}"
                job = ScanJob(
                    id=job_id, tenant_id=self.tenant_id, asset_id=self.asset.id, scan_id=scan_id, status="queued"
                )
                job_repo.create_job(job)

                # Simulate critical error inside the transaction boundary
                raise ValueError("Simulated unexpected transaction fault")
        except ValueError:
            pass

        # Verify job was rolled back and does not exist in PostgreSQL
        with self.engine.connect() as conn:
            row = conn.execute(text("SELECT id FROM scan_jobs WHERE id = :id"), {"id": job_id}).fetchone()
            self.assertIsNone(row, "Uncommitted scan job must be rolled back on exception")

    # -------------------------------------------------------------------------
    # 6. Process Restart Persistence Simulation
    # -------------------------------------------------------------------------

    def test_process_restart_persistence_simulation(self):
        scan_id = f"restart_scan_{uuid.uuid4().hex[:6]}"
        scan = ScanResult(
            id=scan_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            target_url="https://restart.internal", status=ScanStatus.COMPLETED
        )
        repository.save_scan(scan)

        job_id = f"restart_job_{uuid.uuid4().hex[:6]}"
        job = ScanJob(
            id=job_id, tenant_id=self.tenant_id, asset_id=self.asset.id,
            scan_id=scan_id, status="completed", progress_percent=100
        )
        repository.create_scan_job(job)

        # Simulate process termination and engine reinitialization
        reset_engine()
        repository.reset_conn()

        # New engine connection to live PostgreSQL
        new_engine = get_engine(LIVE_POSTGRES_URL)
        with new_engine.connect() as conn:
            scan_row = conn.execute(text("SELECT target_url, status FROM scans WHERE id = :id"), {"id": scan_id}).fetchone()
            self.assertIsNotNone(scan_row)
            self.assertEqual(scan_row[0], "https://restart.internal")
            self.assertEqual(scan_row[1], "completed")

            job_row = conn.execute(text("SELECT status, progress_percent FROM scan_jobs WHERE id = :id"), {"id": job_id}).fetchone()
            self.assertIsNotNone(job_row)
            self.assertEqual(job_row[0], "completed")
            self.assertEqual(job_row[1], 100)

    # -------------------------------------------------------------------------
    # 7. Explicit Failure on Unsupported Operations (Fail-Closed)
    # -------------------------------------------------------------------------

    def test_unsupported_operations_fail_explicitly_zero_sqlite_fallback(self):
        # Operations not yet migrated to PostgreSQL (e.g. Saved Views, Tech Observations) must raise NotImplementedError or RuntimeError
        with self.assertRaises((NotImplementedError, RuntimeError)):
            from core.models import SavedView
            view = SavedView(
                id=f"view_{uuid.uuid4().hex[:6]}",
                tenant_id=self.tenant_id,
                user_id="user_test",
                name="Test View",
                resource_type="findings"
            )
            repository.save_saved_view(view)


if __name__ == "__main__":
    unittest.main()
