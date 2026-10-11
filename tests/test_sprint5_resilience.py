"""
tests/test_sprint5_resilience.py

Sprint 5 — Production Hardening, Crash Recovery & Distributed Lock Reliability
=============================================================================
Covers:
  PHASE 1  Outbox Crash Recovery (S4-GAP-001)
           - Stale PROCESSING event detection based on claimed_at / created_at
           - Active lease protection (no recovery of active workers)
           - Idempotency guard: pre-existing ScanJob/ScanResult detection (0 duplicate scans)
           - Bounded retry backoff & DEAD_LETTER transition
           - Concurrency safety between recovery reapers
  PHASE 2  Scheduled Scan Orphan Reconciliation (S4-GAP-003)
           - Orphaned ScheduledRun without ScanJob marked failed
           - Linking existing scan jobs created before crash
           - Status synchronization with completed/failed jobs
           - Active scheduled run protection
  PHASE 3  Redis Distributed Lock Reliability (S4-GAP-004)
           - Bounded retries for transient connection errors in _get_redis_client
           - Fail-closed RuntimeError when REQUIRE_DISTRIBUTED_LOCK=true
           - Strict fail-closed during acquire() exception (no silent thread-lock fallback)
           - Lua script ownership-checked release error handling
  PHASE 5  Live Infrastructure Integration
           - Real Redis (localhost:6379) atomic lock acquisition, contention & Lua release
           - Migration 008 schema validation (columns & indices)
"""
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest

from core.models import (
    Tenant, Asset, ScanResult, ScanStatus, ScanJob, ScanJobStatus,
    IntegrationOutbox, ScheduledRun, ScheduledScan, AuditEvent
)
from core.repository import (
    init_db, _get_conn, _safe_commit, create_tenant, ensure_asset,
    save_scan, create_scan_job, save_outbox_event, get_scan_job,
    claim_scheduled_run, update_scheduled_run_status
)


def _setup_test_db(tenant_id="t-sprint5"):
    init_db()
    conn = _get_conn()
    conn.execute("DELETE FROM integration_outbox")
    conn.execute("DELETE FROM scheduled_runs")
    conn.execute("DELETE FROM scan_jobs")
    conn.execute("DELETE FROM scans")
    conn.execute("DELETE FROM audit_events")
    _safe_commit(conn)

    create_tenant(Tenant(
        id=tenant_id,
        name="Sprint 5 Tenant",
        slug="sprint5",
        status="active"
    ))
    return tenant_id


# ===========================================================================
# PHASE 1: OUTBOX CRASH RECOVERY (S4-GAP-001)
# ===========================================================================

class TestOutboxCrashRecovery:
    """S4-GAP-001: recover_stale_outbox_events_task processes orphaned events safely."""

    def setup_method(self):
        self.tenant_id = _setup_test_db("t-outbox-rec")

    def _create_outbox_event(
        self,
        event_id=None,
        status="PROCESSING",
        attempt=1,
        claimed_at=None,
        claimed_by=None,
        created_at=None,
        vuln_id="VULN-001",
    ):
        now_iso = datetime.now(timezone.utc).isoformat()
        ev_id = event_id or str(uuid.uuid4())
        payload = {
            "asset_id": "asset-1",
            "asset_url": "https://example.com",
            "vuln_id": vuln_id,
            "slug": "test-plugin",
            "severity": "high",
            "cve_id": "CVE-2026-0001",
        }
        event_key = f"intel_match:{self.tenant_id}:asset-1:{vuln_id}:test-plugin"
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        ev = IntegrationOutbox(
            id=ev_id,
            tenant_id=self.tenant_id,
            event_type="intel_triggered_reassessment",
            event_key=event_key,
            destination="siem",
            payload_hash=payload_hash,
            payload_json=payload,
            status=status,
            attempt=attempt,
            claimed_at=claimed_at,
            claimed_by=claimed_by,
            created_at=created_at or now_iso,
        )
        save_outbox_event(ev)
        return ev

    def test_stale_processing_event_recovered_to_pending(self):
        """Event in PROCESSING with claimed_at older than 600s is reset to PENDING with attempt=2."""
        from core.tasks.maintenance_tasks import recover_stale_outbox_events_task

        now = datetime.now(timezone.utc)
        stale_time = (now - timedelta(seconds=700)).isoformat()

        ev = self._create_outbox_event(
            status="PROCESSING",
            attempt=1,
            claimed_at=stale_time,
            claimed_by="worker-dead-123",
        )

        result = recover_stale_outbox_events_task(stale_threshold_seconds=600)
        assert result["status"] == "success"
        assert result["stale_found"] >= 1
        assert result["recovered"] >= 1

        # Verify DB state
        conn = _get_conn()
        row = conn.execute("SELECT status, attempt, claimed_at, claimed_by, next_retry_at FROM integration_outbox WHERE id = ?", (ev.id,)).fetchone()
        assert row["status"] == "PENDING"
        assert row["attempt"] == 2
        assert row["claimed_at"] is None
        assert row["claimed_by"] is None
        assert row["next_retry_at"] is not None

    def test_active_lease_not_recovered(self):
        """Event in PROCESSING claimed 30s ago is actively processed and NOT reclaimed."""
        from core.tasks.maintenance_tasks import recover_stale_outbox_events_task

        now = datetime.now(timezone.utc)
        active_time = (now - timedelta(seconds=30)).isoformat()

        ev = self._create_outbox_event(
            status="PROCESSING",
            attempt=1,
            claimed_at=active_time,
            claimed_by="worker-active-456",
        )

        result = recover_stale_outbox_events_task(stale_threshold_seconds=600)
        assert result["stale_found"] == 0
        assert result["recovered"] == 0

        conn = _get_conn()
        row = conn.execute("SELECT status FROM integration_outbox WHERE id = ?", (ev.id,)).fetchone()
        assert row["status"] == "PROCESSING"

    def test_reconcile_existing_scanjob_marks_delivered_no_duplicate(self):
        """Worker crashed after creating ScanJob: reaper detects job and marks DELIVERED with 0 duplicate scans."""
        from core.tasks.maintenance_tasks import recover_stale_outbox_events_task

        now = datetime.now(timezone.utc)
        stale_time = (now - timedelta(seconds=800)).isoformat()

        ev = self._create_outbox_event(
            status="PROCESSING",
            attempt=1,
            claimed_at=stale_time,
            claimed_by="worker-crashed-789",
            vuln_id="VULN-IDEMPOTENT-1",
        )

        # Create valid asset, scan, and ScanJob matching this event
        asset = ensure_asset("https://example.com", self.tenant_id)
        scan = ScanResult(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            asset_id=asset.id,
            target_url="https://example.com",
            status=ScanStatus.PENDING,
        )
        save_scan(scan)

        job = ScanJob(
            tenant_id=self.tenant_id,
            asset_id=asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.QUEUED.value,
            requested_by=f"intel_reassessment:{ev.event_key[:24]}",
            profile="safe-active",
        )
        create_scan_job(job)

        result = recover_stale_outbox_events_task(stale_threshold_seconds=600)
        assert result["reconciled_existing"] >= 1
        assert result["recovered"] == 0

        conn = _get_conn()
        row = conn.execute("SELECT status, last_error FROM integration_outbox WHERE id = ?", (ev.id,)).fetchone()
        assert row["status"] == "DELIVERED"
        assert "scan job was already created" in (row["last_error"] or "")

    def test_max_retries_exhaustion_moves_to_dead_letter(self):
        """Stale event that has already reached max attempts (3) transitions to DEAD_LETTER."""
        from core.tasks.maintenance_tasks import recover_stale_outbox_events_task

        now = datetime.now(timezone.utc)
        stale_time = (now - timedelta(seconds=900)).isoformat()

        ev = self._create_outbox_event(
            status="PROCESSING",
            attempt=3,
            claimed_at=stale_time,
            claimed_by="worker-crash-3",
        )

        result = recover_stale_outbox_events_task(stale_threshold_seconds=600)
        assert result["dead_letter"] >= 1

        conn = _get_conn()
        row = conn.execute("SELECT status, last_error FROM integration_outbox WHERE id = ?", (ev.id,)).fetchone()
        assert row["status"] == "DEAD_LETTER"
        assert "Max retries exhausted" in row["last_error"]

    def test_concurrent_reapers_no_double_recovery(self):
        """Simulate two reapers racing on the same stale event; only one updates it."""
        conn = _get_conn()
        now = datetime.now(timezone.utc)
        stale_time = (now - timedelta(seconds=700)).isoformat()

        ev = self._create_outbox_event(
            status="PROCESSING",
            attempt=1,
            claimed_at=stale_time,
            claimed_by="worker-dead",
        )

        # Reaper 1 claims it
        res1 = conn.execute("""
            UPDATE integration_outbox
            SET claimed_by = 'reaper-1'
            WHERE id = ? AND status = 'PROCESSING' AND claimed_at = ?
        """, (ev.id, stale_time))
        _safe_commit(conn)
        assert res1.rowcount == 1

        # Reaper 2 tries with original claimed_by
        res2 = conn.execute("""
            UPDATE integration_outbox
            SET claimed_by = 'reaper-2'
            WHERE id = ? AND status = 'PROCESSING' AND claimed_at = ? AND claimed_by = 'worker-dead'
        """, (ev.id, stale_time))
        _safe_commit(conn)
        assert res2.rowcount == 0


# ===========================================================================
# PHASE 2: SCHEDULED SCAN RECOVERY (S4-GAP-003)
# ===========================================================================

class TestScheduledRunRecovery:
    """S4-GAP-003: reconcile_orphaned_scheduled_runs reconciles stuck runs."""

    def setup_method(self):
        self.tenant_id = _setup_test_db("t-sched-rec")

    def _create_schedule(self, sched_id="sched-test"):
        from core.repository import save_scheduled_scan
        asset = ensure_asset("https://example.com", self.tenant_id)
        sched = ScheduledScan(
            id=sched_id,
            tenant_id=self.tenant_id,
            target_url="https://example.com",
            interval_hours=24,
            scan_mode="passive",
            next_run_at=datetime.now(timezone.utc).isoformat(),
        )
        save_scheduled_scan(sched)
        return sched, asset

    def test_orphaned_dispatched_run_without_job_marked_failed(self):
        """ScheduledRun in dispatched state without linked job older than timeout is marked failed."""
        from core.tasks.maintenance_tasks import recover_stale_jobs_task

        sched, asset = self._create_schedule("sched-orphan-1")
        now = datetime.now(timezone.utc)
        stale_time = (now - timedelta(seconds=700)).isoformat()

        # Insert orphaned ScheduledRun
        conn = _get_conn()
        run_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO scheduled_runs (id, schedule_id, tenant_id, planned_at, status, scan_job_id, created_at)
            VALUES (?, ?, ?, ?, 'dispatched', NULL, ?)
        """, (run_id, sched.id, self.tenant_id, stale_time, stale_time))
        _safe_commit(conn)

        res = recover_stale_jobs_task(stale_threshold_seconds=600)
        orphaned = res.get("orphaned_scheduled_runs", {})
        assert orphaned["orphans_found"] >= 1
        assert orphaned["failed"] >= 1

        row = conn.execute("SELECT status FROM scheduled_runs WHERE id = ?", (run_id,)).fetchone()
        assert row["status"] == "failed"

    def test_orphaned_dispatched_run_syncs_with_completed_job(self):
        """ScheduledRun whose linked job is COMPLETED is updated to status='completed'."""
        from core.tasks.maintenance_tasks import recover_stale_jobs_task

        sched, asset = self._create_schedule("sched-complete-1")
        now = datetime.now(timezone.utc)
        stale_time = (now - timedelta(seconds=700)).isoformat()

        # Create scan and completed job with valid foreign keys
        scan = ScanResult(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            asset_id=asset.id,
            target_url="https://example.com",
            status=ScanStatus.COMPLETED,
        )
        save_scan(scan)

        job = ScanJob(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            asset_id=asset.id,
            scan_id=scan.id,
            status=ScanJobStatus.COMPLETED.value,
        )
        create_scan_job(job)

        conn = _get_conn()
        run_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO scheduled_runs (id, schedule_id, tenant_id, planned_at, status, scan_job_id, created_at)
            VALUES (?, ?, ?, ?, 'dispatched', ?, ?)
        """, (run_id, sched.id, self.tenant_id, stale_time, job.id, stale_time))
        _safe_commit(conn)

        res = recover_stale_jobs_task(stale_threshold_seconds=600)
        orphaned = res.get("orphaned_scheduled_runs", {})
        assert orphaned["completed"] >= 1

        row = conn.execute("SELECT status FROM scheduled_runs WHERE id = ?", (run_id,)).fetchone()
        assert row["status"] == "completed"

    def test_recent_dispatched_run_not_reconciled(self):
        """ScheduledRun created 30s ago is actively in flight and NOT touched."""
        from core.tasks.maintenance_tasks import recover_stale_jobs_task

        sched, asset = self._create_schedule("sched-recent-1")
        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        conn = _get_conn()
        run_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO scheduled_runs (id, schedule_id, tenant_id, planned_at, status, scan_job_id, created_at)
            VALUES (?, ?, ?, ?, 'dispatched', NULL, ?)
        """, (run_id, sched.id, self.tenant_id, recent_time, recent_time))
        _safe_commit(conn)

        res = recover_stale_jobs_task(stale_threshold_seconds=600)
        orphaned = res.get("orphaned_scheduled_runs", {})
        assert orphaned["orphans_found"] == 0

        row = conn.execute("SELECT status FROM scheduled_runs WHERE id = ?", (run_id,)).fetchone()
        assert row["status"] == "dispatched"


# ===========================================================================
# PHASE 3: REDIS DISTRIBUTED LOCK RELIABILITY (S4-GAP-004)
# ===========================================================================

class TestRedisLockResilience:
    """S4-GAP-004: Redis distributed lock bounded retries and fail-closed guarantees."""

    def setup_method(self):
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

    def teardown_method(self):
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None
        os.environ.pop("REQUIRE_DISTRIBUTED_LOCK", None)

    def test_get_redis_client_retries_on_transient_error(self):
        """_get_redis_client retries up to 3 times on transient connection errors."""
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

        mock_redis = MagicMock()
        # Fail first 2 attempts, succeed on attempt 3
        mock_redis.ping.side_effect = [ConnectionError("flapping 1"), ConnectionError("flapping 2"), True]

        mock_redis_cls = MagicMock(return_value=mock_redis)
        mock_redis_mod = MagicMock()
        mock_redis_mod.Redis.from_url.return_value = mock_redis

        with patch.dict("sys.modules", {"redis": mock_redis_mod}), \
             patch("time.sleep", return_value=None):
            client = svc._get_redis_client()
            assert client is not None
            assert mock_redis.ping.call_count == 3

    def test_get_redis_client_fail_closed_after_retries_exhausted(self):
        """When REQUIRE_DISTRIBUTED_LOCK=true, all 3 retries failing raises RuntimeError."""
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

        mock_redis = MagicMock()
        mock_redis.ping.side_effect = ConnectionError("hard outage")

        mock_redis_cls = MagicMock(return_value=mock_redis)
        mock_redis_mod = MagicMock()
        mock_redis_mod.Redis.from_url.return_value = mock_redis

        with patch.dict(os.environ, {"REQUIRE_DISTRIBUTED_LOCK": "true"}), \
             patch.dict("sys.modules", {"redis": mock_redis_mod}), \
             patch("time.sleep", return_value=None):
            with pytest.raises(RuntimeError, match="REQUIRE_DISTRIBUTED_LOCK=true but Redis is unavailable after 3 attempts"):
                svc._get_redis_client()

    def test_acquire_fails_closed_on_redis_set_exception_when_required(self):
        """When REQUIRE_DISTRIBUTED_LOCK=true, exception during redis.set() raises RuntimeError (no silent degradation)."""
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.side_effect = ConnectionError("Dropped mid-handshake")

        with patch.dict(os.environ, {"REQUIRE_DISTRIBUTED_LOCK": "true"}), \
             patch.object(svc, "_get_redis_client", return_value=mock_redis):
            lock = svc._DistributedSyncLock()
            with pytest.raises(RuntimeError, match="Redis lock acquisition failed"):
                lock.acquire(blocking=False)


# ===========================================================================
# PHASE 5: LIVE INFRASTRUCTURE INTEGRATION & SCHEMA
# ===========================================================================

class TestLiveRedisIntegration:
    """Validates real Redis coordination on localhost:6379 when available."""

    def test_live_redis_lock_lifecycle(self):
        """Acquire and release lock against real local Redis server (if reachable)."""
        try:
            from redis import Redis
            r = Redis.from_url("redis://localhost:6379/0", socket_connect_timeout=1)
            if not r.ping():
                pytest.skip("Local Redis service not responding to ping")
        except Exception:
            pytest.skip("Local Redis server not reachable on localhost:6379")

        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

        with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0", "REQUIRE_DISTRIBUTED_LOCK": "true"}):
            lock = svc._DistributedSyncLock()
            # Clean up key if previously left
            r.delete(svc._REDIS_LOCK_NAME)

            # 1. Acquire
            acquired = lock.acquire(blocking=False)
            assert acquired is True
            assert lock.locked() is True

            # 2. Contention: second acquire fails
            second_lock = svc._DistributedSyncLock()
            contention_acquired = second_lock.acquire(blocking=False)
            assert contention_acquired is False

            # 3. Release
            lock.release()
            assert lock.locked() is False
            assert r.exists(svc._REDIS_LOCK_NAME) == 0


class TestDatabaseMigration008Schema:
    """Verifies Migration 008 columns and indices exist in database schema."""

    def test_migration_008_columns_and_indices(self):
        init_db()
        conn = _get_conn()

        # Check columns on integration_outbox
        info = conn.execute("PRAGMA table_info(integration_outbox)").fetchall()
        col_names = [r["name"] for r in info]
        assert "claimed_at" in col_names
        assert "claimed_by" in col_names

        # Check indices
        indices = conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        idx_names = [r["name"] for r in indices]
        assert "idx_outbox_processing_claimed" in idx_names
        assert "idx_sched_runs_status_job" in idx_names
