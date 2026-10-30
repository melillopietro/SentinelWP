"""
Phase 3 Enterprise Test Suite:
SQLAlchemy 2.x, PostgreSQL/SQLite Compatibility, Alembic, Celery Tasks,
HA Scheduler (0 Duplicate Runs), ScanJob Lifecycle, Timeout, Cancellation,
Stale Recovery, Worker Guardrails, Health/Readiness, and Metrics.
"""
import unittest
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["ENVIRONMENT"] = "development"
os.environ["WSA_SECRET_KEY"] = "super-secret-key-for-phase3-testing-32chars"
os.environ["SCAN_EXECUTION_BACKEND"] = "local"

from app import app
from core import repository
from core.version import __version__
from core.models import (
    Tenant, Asset, ScanAuthorization, ScanResult, ScanStatus,
    ScanJob, ScanJobStatus, ScheduledScan, ScheduledRun, AuditEvent,
    Finding, Severity
)
from core.db.session import init_db_schema, get_engine
from core.tasks.scan_tasks import run_scan_task
from core.tasks.maintenance_tasks import dispatch_scheduled_scans_task, recover_stale_jobs_task
from core.tasks.intel_tasks import sync_vulnerability_intelligence_task
from scripts.migrate_sqlite_to_postgres import run_migration


class TestPhase3PostgresCeleryHA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository.init_db()

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

        self.tenant_id = f"tenant-{uuid.uuid4().hex[:8]}"
        self.tenant = Tenant(
            id=self.tenant_id,
            name="Phase 3 Workspace",
            slug=f"p3-{uuid.uuid4().hex[:6]}",
            status="active"
        )
        repository.create_tenant(self.tenant)

        self.asset = repository.ensure_asset("https://example.com", self.tenant_id)

    def _login(self, role="admin"):
        with self.client.session_transaction() as sess:
            sess["user_id"] = f"user-{role}"
            sess["username"] = f"{role}_user"
            sess["role"] = role
            sess["tenant_id"] = self.tenant_id

    # 1. Health & Readiness Endpoints
    def test_health_endpoint(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["app"], "SentinelWP")
        self.assertEqual(data["version"], __version__)

    def test_ready_endpoint(self):
        resp = self.client.get("/ready")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("checks", data)
        self.assertEqual(data["checks"].get("database"), "connected")

    def test_metrics_endpoint(self):
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("sentinel_scan_jobs_queued", body)
        self.assertIn("sentinel_scan_jobs_running", body)
        self.assertIn("sentinel_scan_jobs_failed_total", body)
        self.assertIn("sentinel_intel_freshness_seconds", body)

    # 2. ScanJob Lifecycle & Worker Execution
    @patch("core.tasks.scan_tasks.count_active_scan_jobs_global", return_value=0)
    @patch("core.tasks.scan_tasks.ScanOrchestrator")
    def test_scan_task_successful_execution(self, mock_orchestrator_cls, _mock_global):
        mock_orch = MagicMock()
        mock_result = ScanResult(
            tenant_id=self.tenant_id,
            target_url="https://example.com",
            scan_mode="passive",
            findings=[
                Finding(
                    tenant_id=self.tenant_id,
                    scan_id="temp",
                    title="Mock Finding",
                    severity=Severity.HIGH,
                )
            ],
            score=85.0,
            grade="B"
        )
        mock_orch.run.return_value = mock_result
        mock_orchestrator_cls.return_value = mock_orch

        # Create scan and job
        scan = ScanResult(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://example.com",
            scan_mode="passive",
            status=ScanStatus.PENDING,
        )
        repository.save_scan(scan)

        job = ScanJob(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.QUEUED.value,
            profile="passive",
        )
        repository.create_scan_job(job)

        # Run worker task
        res = run_scan_task(job.id)

        self.assertTrue(res)

        # Verify DB persistence
        fresh_job = repository.get_scan_job(job.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_job.status, ScanJobStatus.COMPLETED.value)
        self.assertEqual(fresh_job.progress_percent, 100)

        fresh_scan = repository.get_scan(scan.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(fresh_scan.grade, "B")

    # 3. Pre-flight Guardrail: Worker Re-validates Authorization
    def test_worker_fails_closed_when_safe_active_authorization_expired(self):
        scan = ScanResult(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://example.com",
            scan_mode="safe-active",
            status=ScanStatus.PENDING,
        )
        repository.save_scan(scan)

        # Expired authorization (yesterday)
        past_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        auth = ScanAuthorization(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            status="active",
            valid_from=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
            valid_until=past_iso,
        )
        repository.save_scan_authorization(auth)

        job = ScanJob(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.QUEUED.value,
            profile="safe-active",
        )
        repository.create_scan_job(job)

        res = run_scan_task(job.id)

        self.assertFalse(res)

        fresh_job = repository.get_scan_job(job.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_job.status, ScanJobStatus.FAILED.value)
        self.assertEqual(fresh_job.error_code, "AUTHORIZATION_EXPIRED")

        fresh_scan = repository.get_scan(scan.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_scan.status, ScanStatus.FAILED)

    # 4. Web Status API reads from persistent ScanJob
    def test_api_scan_status_reads_persistent_progress(self):
        self._login("analyst")

        scan = ScanResult(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://example.com",
            status=ScanStatus.RUNNING,
        )
        repository.save_scan(scan)

        job = ScanJob(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.RUNNING.value,
            progress_percent=65,
            current_step="TLS Security Audit",
            attempt=1,
        )
        repository.create_scan_job(job)

        resp = self.client.get(f"/api/scan/{scan.id}/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["scan_id"], scan.id)
        self.assertEqual(data["job_id"], job.id)
        self.assertEqual(data["status"], "running")
        self.assertEqual(data["progress"], 65)
        self.assertEqual(data["current_step"], "TLS Security Audit")

    # 5. Cancellation Endpoint
    def test_cancel_scan_job(self):
        self._login("analyst")

        scan = ScanResult(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://example.com",
            status=ScanStatus.RUNNING,
        )
        repository.save_scan(scan)

        job = ScanJob(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.RUNNING.value,
            task_id="celery-task-12345",
        )
        repository.create_scan_job(job)

        resp = self.client.post(f"/scan-job/{job.id}/cancel", headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertIn(resp.status_code, (200, 302))

        fresh_job = repository.get_scan_job(job.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_job.status, ScanJobStatus.CANCELLED.value)

        fresh_scan = repository.get_scan(scan.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_scan.status, ScanStatus.FAILED)
        self.assertIn("cancelled", fresh_scan.notes.lower())

    # 6. Retry Endpoint
    def test_retry_scan_job(self):
        self._login("analyst")

        scan = ScanResult(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://example.com",
            status=ScanStatus.FAILED,
        )
        repository.save_scan(scan)

        job = ScanJob(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.FAILED.value,
            attempt=1,
            error_code="TIMEOUT",
        )
        repository.create_scan_job(job)

        resp = self.client.post(f"/scan-job/{job.id}/retry")
        self.assertEqual(resp.status_code, 302)

        fresh_job = repository.get_scan_job(job.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_job.attempt, 2)
        self.assertEqual(fresh_job.status, ScanJobStatus.QUEUED.value)
        self.assertIsNone(fresh_job.error_code)

    # 7. HA Scheduler: Duplicate Dispatch Prevention (0 Duplicates)
    def test_ha_scheduler_duplicate_prevention(self):
        schedule_id = f"sched-{uuid.uuid4().hex[:8]}"
        planned_time = "2026-09-29T12:00:00+00:00"

        schedule = ScheduledScan(
            id=schedule_id,
            tenant_id=self.tenant_id,
            target_url="https://example.com",
            interval_hours=24,
        )
        repository.save_scheduled_scan(schedule)

        # Worker 1 claims
        run1 = repository.claim_scheduled_run(schedule_id, self.tenant_id, planned_time)
        self.assertIsNotNone(run1)
        self.assertEqual(run1.schedule_id, schedule_id)
        self.assertEqual(run1.status, "dispatched")

        # Worker 2 simultaneously attempts to claim the EXACT same schedule and slot
        run2 = repository.claim_scheduled_run(schedule_id, self.tenant_id, planned_time)
        self.assertIsNone(run2, "Worker 2 must be blocked to guarantee 0 duplicate scheduled runs!")

    # 8. Stale Job Recovery
    def test_stale_job_recovery(self):
        conn = repository._get_conn()
        conn.execute("UPDATE scan_jobs SET status = 'completed' WHERE status = 'running'")
        conn.commit()

        scan = ScanResult(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url="https://example.com",
            status=ScanStatus.RUNNING,
        )
        repository.save_scan(scan)

        # Heartbeat 15 minutes ago
        past_heartbeat = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        job = ScanJob(
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.RUNNING.value,
            attempt=1,
            max_attempts=3,
            heartbeat_at=past_heartbeat,
        )
        repository.create_scan_job(job)

        with patch("core.tasks.scan_tasks.run_scan_task.delay") as mock_delay:
            res = recover_stale_jobs_task(stale_threshold_seconds=300)
            self.assertEqual(res["recovered"], 1)

        fresh_job = repository.get_scan_job(job.id, tenant_id=self.tenant_id)
        self.assertEqual(fresh_job.status, ScanJobStatus.RETRYING.value)
        self.assertEqual(fresh_job.attempt, 2)

    # 9. Vulnerability Intelligence Source Isolation
    @patch("core.tasks.intel_tasks.sync_wordfence")
    @patch("core.tasks.intel_tasks.sync_kev")
    def test_intel_sync_wordfence_failure_does_not_block_kev(self, mock_kev, mock_wf):
        mock_wf.side_effect = Exception("Wordfence connection timeout")
        mock_kev.return_value = {"status": "success", "inserted": 12}

        results = sync_vulnerability_intelligence_task(source=None)

        self.assertEqual(results["wordfence"]["status"], "failed")
        self.assertEqual(results["cisa_kev"]["status"], "success")
        self.assertEqual(results["cisa_kev"]["records"], 12)

        # SLA freshness check
        kev_freshness = repository.evaluate_intel_freshness("cisa_kev")
        self.assertEqual(kev_freshness["status"], "Fresh")

    # 10. SQLite to PostgreSQL Data Migration Script
    def test_sqlite_to_postgres_migration(self):
        import sqlite3
        source_db_path = f"data/test_src_{uuid.uuid4().hex[:8]}.db"
        target_db_path = f"data/test_migration_{uuid.uuid4().hex[:8]}.db"
        target_url = f"sqlite:///{target_db_path}"

        conn = sqlite3.connect(source_db_path)
        conn.execute("CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT, slug TEXT, status TEXT, created_at TEXT, updated_at TEXT)")
        conn.execute("INSERT INTO tenants VALUES ('t1', 'T1', 't1', 'active', '2026-09-29', '2026-09-29')")
        conn.commit()
        conn.close()

        try:
            success = run_migration(
                sqlite_path=source_db_path,
                postgres_url=target_url,
                dry_run=False
            )
            self.assertTrue(success)
        finally:
            if os.path.exists(source_db_path):
                os.remove(source_db_path)
            if os.path.exists(target_db_path):
                os.remove(target_db_path)


if __name__ == "__main__":
    unittest.main()
