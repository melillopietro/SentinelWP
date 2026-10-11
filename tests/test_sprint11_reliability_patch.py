"""
Sprint 11 reliability patch — SWP-REL-001/002/003 regression tests.
"""
import os
import sys
import uuid
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from core import repository
from core.models import (
    Tenant,
    Asset,
    ScanJob,
    ScanJobStatus,
    ScanResult,
    ScanStatus,
    UserRole,
    UserStatus,
)
from core.auth.passwords import create_user
from core.tasks.scan_tasks import (
    run_scan_task,
    OUTCOME_IDEMPOTENT_SKIP,
    OUTCOME_SSRF_REJECTION,
)


class TestScanSubmissionSsrfPreflight(unittest.TestCase):
    def setUp(self):
        os.environ.pop("DATABASE_URL", None)
        repository.reset_conn()
        repository._allow_operational_sqlite_override = True
        repository.init_db()
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.prefix = uuid.uuid4().hex[:8]
        self.tenant_id = f"rel_t_{self.prefix}"
        repository.save_tenant(
            Tenant(id=self.tenant_id, name="Rel", slug=f"rel-{self.prefix}", status="active")
        )
        self.asset = Asset(
            id=f"asset_{self.prefix}",
            tenant_id=self.tenant_id,
            display_name="Lab",
            canonical_url="https://alpha.example.com",
            status="active",
        )
        repository.save_asset(self.asset)
        user = create_user(
            username=f"analyst_{self.prefix}",
            password="ReliablePatch2026!",
            role=UserRole.ANALYST,
            status=UserStatus.ACTIVE,
        )
        user.tenant_id = self.tenant_id
        repository.save_user(user)
        with self.client.session_transaction() as sess:
            sess["user_id"] = user.id
            sess["username"] = user.username
            sess["role"] = "analyst"
            sess["tenant_id"] = self.tenant_id

    def _count_jobs_for_target(self, target: str) -> int:
        count = 0
        for j in repository.list_scan_jobs(tenant_id=self.tenant_id, limit=500):
            scan = repository.get_scan(j.scan_id, tenant_id=self.tenant_id)
            if scan and scan.target_url == target:
                count += 1
        return count

    @patch("app.SCAN_EXECUTION_BACKEND", "celery")
    @patch("core.tasks.scan_tasks.run_scan_task.delay")
    def test_unsafe_metadata_target_rejected_before_enqueue(self, mock_delay):
        target = "http://169.254.169.254/latest/meta-data/"
        before = self._count_jobs_for_target(target)
        resp = self.client.post(
            "/scan/new",
            data={"target_url": target, "scan_mode": "passive"},
        )
        after = self._count_jobs_for_target(target)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(before, after)
        mock_delay.assert_not_called()
        body = resp.data.lower()
        self.assertTrue(b"169.254" in body or b"private" in body or b"blocked" in body)

    @patch("app.SCAN_EXECUTION_BACKEND", "celery")
    @patch("scanners.async_runner.start_async_scan")
    @patch("core.tasks.scan_tasks.run_scan_task.delay")
    def test_safe_target_still_queues(self, mock_delay, mock_local):
        mock_delay.return_value = MagicMock(id="celery-task-id")
        before = self._count_jobs_for_target("https://alpha.example.com")
        resp = self.client.post(
            "/scan/new",
            data={"target_url": "https://alpha.example.com", "scan_mode": "passive"},
        )
        after = self._count_jobs_for_target("https://alpha.example.com")
        self.assertEqual(resp.status_code, 302)
        self.assertGreater(after, before)
        self.assertTrue(mock_delay.called)
        mock_local.assert_not_called()

    def test_worker_ssrf_still_enforced_for_queued_unsafe_job(self):
        target = "http://169.254.169.254/latest/meta-data/"
        now = datetime.now(timezone.utc).isoformat()
        scan_id = f"scan_{self.prefix}"
        job_id = f"job_{self.prefix}"
        repository.save_scan(
            ScanResult(
                id=scan_id,
                tenant_id=self.tenant_id,
                target_url=target,
                scan_mode="passive",
                status=ScanStatus.PENDING,
            )
        )
        repository.create_scan_job(
            ScanJob(
                id=job_id,
                tenant_id=self.tenant_id,
                scan_id=scan_id,
                status=ScanJobStatus.QUEUED.value,
                queued_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        with patch("core.tasks.scan_tasks._log_scan_task_outcome") as mock_log:
            result = run_scan_task.run(job_id)
        self.assertFalse(result)
        job = repository.get_scan_job(job_id)
        self.assertEqual(job.status, ScanJobStatus.FAILED.value)
        self.assertEqual(job.error_code, "TARGET_BLOCKED")
        outcomes = [c.args[2] for c in mock_log.call_args_list if len(c.args) >= 3]
        self.assertIn(OUTCOME_SSRF_REJECTION, outcomes)

    def test_duplicate_delivery_logs_idempotent_skip(self):
        now = datetime.now(timezone.utc).isoformat()
        scan_id = f"dupscan_{self.prefix}"
        job_id = f"dupjob_{self.prefix}"
        repository.save_scan(
            ScanResult(
                id=scan_id,
                tenant_id=self.tenant_id,
                target_url="https://alpha.example.com",
                scan_mode="passive",
                status=ScanStatus.COMPLETED,
            )
        )
        repository.create_scan_job(
            ScanJob(
                id=job_id,
                tenant_id=self.tenant_id,
                scan_id=scan_id,
                status=ScanJobStatus.COMPLETED.value,
                queued_at=now,
                created_at=now,
                updated_at=now,
                completed_at=now,
            )
        )
        with patch("core.tasks.scan_tasks._log_scan_task_outcome") as mock_log:
            result = run_scan_task.run(job_id)
        self.assertFalse(result)
        outcomes = [c.args[2] for c in mock_log.call_args_list if len(c.args) >= 3]
        self.assertIn(OUTCOME_IDEMPOTENT_SKIP, outcomes)
        self.assertEqual(repository.get_scan_job(job_id).status, ScanJobStatus.COMPLETED.value)


if __name__ == "__main__":
    unittest.main()
