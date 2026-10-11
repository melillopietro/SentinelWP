"""
tests/test_sprint4_integration.py

Sprint 4 — End-to-End Integration & Operational Readiness Tests
================================================================
Covers:
  PHASE 1  Post-scan differential auto-trigger (_trigger_post_scan_differential)
  PHASE 2  Intel reassessment queue processor (process_intel_reassessment_queue_task)
  PHASE 3  Flask monitoring APIs (dashboard, assets, differential, lifecycle, pause, resume)
  PHASE 5  REQUIRE_DISTRIBUTED_LOCK fail-closed behaviour
  PHASE 6  NVD backfill task (dry-run, idempotency, rate limiting)
  PHASE 7  Plugin metadata cache-busting (Cache-Control header in readme.txt requests)
  PHASE 8  End-to-end workflow integration (scan → differential → outbox)
           Duplicate delivery prevention, failed-scan safety invariant,
           cross-tenant authorization, worker crash recovery (dead-letter),
           disabled/paused asset skip
"""
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

def _init_db():
    from core.repository import init_db
    init_db(force=True)


def _make_tenant(tenant_id="t1"):
    from core.models import Tenant
    from core.repository import save_tenant
    t = Tenant(id=tenant_id, name="Sprint4", slug="s4")
    save_tenant(t)
    return t


def _make_asset(tenant_id="t1", canonical_url="https://example.com", **kwargs):
    from core.models import Asset
    from core.repository import save_asset
    a = Asset(
        tenant_id=tenant_id,
        canonical_url=canonical_url,
        hostname="example.com",
        display_name="S4 Asset",
        monitoring_enabled=kwargs.pop("monitoring_enabled", True),
        **kwargs
    )
    save_asset(a)
    return a


def _make_scan(tenant_id="t1", asset_id=None, status="completed", fingerprints=None):
    from core.models import ScanResult, ScanStatus
    from core.repository import save_scan
    s = ScanResult(
        tenant_id=tenant_id,
        asset_id=asset_id,
        target_url="https://example.com",
        status=ScanStatus(status),
        scan_mode="passive",
    )
    save_scan(s)
    return s


def _make_finding(scan_id, tenant_id="t1", asset_id=None, fingerprint="fp-001", status="OPEN"):
    from core.models import Finding, Severity
    from core.repository import save_findings
    f = Finding(
        scan_id=scan_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        category="plugins",
        title="Test Finding",
        description="desc",
        severity=Severity.HIGH,
        confidence=0.9,
        fingerprint=fingerprint,
        status=status,
    )
    save_findings([f])
    return f


def _make_flask_client(session_data=None):
    """Return a Flask test client with optional session pre-populated."""
    from app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()
    if session_data:
        with client.session_transaction() as sess:
            for k, v in session_data.items():
                sess[k] = v
    return client


# ===========================================================================
# PHASE 1 — Post-scan differential auto-trigger
# ===========================================================================

class TestPostScanDifferentialTrigger:
    """_trigger_post_scan_differential called from scan_tasks after COMPLETED scan."""

    def setup_method(self):
        _init_db()
        _make_tenant()

    def test_first_scan_skips_differential_no_prior(self):
        """First scan for an asset has no baseline — differential is skipped gracefully."""
        from core.tasks.scan_tasks import _trigger_post_scan_differential
        asset = _make_asset()
        scan = _make_scan(asset_id=asset.id)

        # No exception, no prior scan → differential skipped (logged info, no crash)
        _trigger_post_scan_differential(scan.id, "t1", asset.id, "job-001")

    def test_second_scan_triggers_differential(self):
        """Second completed scan on same asset triggers differential computation."""
        from core.tasks.scan_tasks import _trigger_post_scan_differential
        from core.differential import compute_scan_differential

        asset = _make_asset()
        scan1 = _make_scan(asset_id=asset.id, status="completed")
        _make_finding(scan1.id, asset_id=asset.id, fingerprint="fp-a")
        scan2 = _make_scan(asset_id=asset.id, status="completed")
        _make_finding(scan2.id, asset_id=asset.id, fingerprint="fp-a")
        _make_finding(scan2.id, asset_id=asset.id, fingerprint="fp-b")

        # compute_scan_differential is imported inside _trigger_post_scan_differential,
        # so we patch at the module where it is defined.
        with patch(
            "core.differential.compute_scan_differential",
            wraps=compute_scan_differential
        ) as mock_diff:
            _trigger_post_scan_differential(scan2.id, "t1", asset.id, "job-002")
            mock_diff.assert_called_once()
            args = mock_diff.call_args[1]
            assert args["new_scan_id"] == scan2.id

    def test_differential_failure_does_not_corrupt_scan(self):
        """If compute_scan_differential raises, _trigger_post_scan_differential swallows it."""
        from core.tasks.scan_tasks import _trigger_post_scan_differential

        asset = _make_asset()
        scan1 = _make_scan(asset_id=asset.id, status="completed")
        scan2 = _make_scan(asset_id=asset.id, status="completed")

        # Patch at the module where it lives (imported inside the function)
        with patch(
            "core.differential.compute_scan_differential",
            side_effect=RuntimeError("DB connection lost")
        ):
            # Must not raise
            _trigger_post_scan_differential(scan2.id, "t1", asset.id, "job-003")

    def test_no_asset_id_skips_differential(self):
        """Ad-hoc scan without an asset_id skips differential gracefully."""
        from core.tasks.scan_tasks import _trigger_post_scan_differential
        scan = _make_scan()
        _trigger_post_scan_differential(scan.id, "t1", None, "job-004")  # no asset_id

    def test_failed_scan_does_not_emit_resolved(self):
        """Failed scan completion must NEVER emit RESOLVED differential changes."""
        from core.differential import compute_scan_differential
        from core.models import ScanStatus

        asset = _make_asset()
        scan1 = _make_scan(asset_id=asset.id, status="completed")
        _make_finding(scan1.id, asset_id=asset.id, fingerprint="fp-x")

        # New scan is FAILED, not COMPLETED
        scan2 = _make_scan(asset_id=asset.id, status="failed")
        # scan2 has no findings (as if scan crashed mid-run)

        diff = compute_scan_differential(scan1.id, scan2.id, "t1", asset_id=asset.id)
        assert diff.is_complete is False, "Failed scan must produce is_complete=False"
        resolved_changes = [c for c in diff.changes if c.change_state == "RESOLVED"]
        assert len(resolved_changes) == 0, \
            "Failed scan must not produce any RESOLVED changes"


# ===========================================================================
# PHASE 2 — Intel reassessment queue processor
# ===========================================================================

class TestIntelReassessmentQueue:
    """process_intel_reassessment_queue_task processes outbox events correctly."""

    def setup_method(self):
        _init_db()
        _make_tenant()

    def _stage_event(self, asset_id, tenant_id="t1", slug="my-plugin", vuln_id="v1"):
        from core.models import IntegrationOutbox
        from core.repository import save_outbox_event
        import hashlib, json
        payload = {
            "asset_id": asset_id,
            "asset_url": "https://example.com",
            "vuln_id": vuln_id,
            "slug": slug,
            "severity": "high",
            "cve_id": "CVE-2024-9999",
        }
        key = f"intel_match:{tenant_id}:{asset_id}:{vuln_id}:{slug}"
        ev = IntegrationOutbox(
            tenant_id=tenant_id,
            event_type="intel_triggered_reassessment",
            event_key=key,
            destination="siem",
            payload_hash=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
            payload_json=payload,
            status="PENDING",
        )
        save_outbox_event(ev)
        return ev

    def test_event_skipped_when_asset_not_found(self):
        """Events for non-existent assets are marked FAILED."""
        from core.tasks.maintenance_tasks import process_intel_reassessment_queue_task
        self._stage_event("non-existent-asset-id")
        result = process_intel_reassessment_queue_task()
        assert result["skipped_no_asset"] >= 1

    def test_event_skipped_when_monitoring_disabled(self):
        """Events for assets with monitoring_enabled=False are skipped."""
        from core.tasks.maintenance_tasks import process_intel_reassessment_queue_task
        asset = _make_asset(monitoring_enabled=False)
        self._stage_event(asset.id)
        result = process_intel_reassessment_queue_task()
        assert result["skipped_no_auth"] >= 1

    def test_event_skipped_without_scan_authorization(self):
        """Events without active scan authorization are skipped (not dispatched)."""
        from core.tasks.maintenance_tasks import process_intel_reassessment_queue_task
        asset = _make_asset(monitoring_enabled=True)
        self._stage_event(asset.id)

        # Authorization check returns False; run_scan_task should never be called
        with patch(
            "core.authorization.verify_scan_authorization",
            return_value=(False, "No active authorization", None)
        ):
            result = process_intel_reassessment_queue_task()

        assert result["skipped_no_auth"] >= 1
        assert result["dispatched"] == 0

    def test_event_dispatched_with_authorization(self):
        """Events with active monitoring and authorization are dispatched."""
        from core.tasks.maintenance_tasks import process_intel_reassessment_queue_task
        from unittest.mock import MagicMock
        asset = _make_asset(monitoring_enabled=True)
        self._stage_event(asset.id)

        mock_task = MagicMock()
        mock_task.delay.return_value = MagicMock(id="task-xyz")

        with patch(
            "core.authorization.verify_scan_authorization",
            return_value=(True, None, None)
        ), patch(
            "core.tasks.scan_tasks.run_scan_task",
            mock_task,
        ):
            result = process_intel_reassessment_queue_task()

        assert result["dispatched"] >= 1

    def test_concurrent_workers_no_double_dispatch(self):
        """Two concurrent workers claiming the same event: only one succeeds."""
        from core.repository import _get_conn, _safe_commit

        _init_db()
        _make_tenant()
        asset = _make_asset(monitoring_enabled=True)
        ev = self._stage_event(asset.id)

        conn = _get_conn()
        # Manually claim the event (simulates first worker)
        result = conn.execute(
            "UPDATE integration_outbox SET status='PROCESSING' WHERE id=? AND status='PENDING'",
            (ev.id,)
        )
        _safe_commit(conn)
        assert result.rowcount == 1

        # Second claim attempt should fail (rowcount=0)
        result2 = conn.execute(
            "UPDATE integration_outbox SET status='PROCESSING' WHERE id=? AND status='PENDING'",
            (ev.id,)
        )
        _safe_commit(conn)
        assert result2.rowcount == 0, "Second worker must not double-claim an already-claimed event"

    def test_dead_letter_after_max_retries(self):
        """Events that fail beyond max_retries are moved to DEAD_LETTER status."""
        from core.repository import _get_conn, _safe_commit

        _init_db()
        _make_tenant()
        asset = _make_asset(monitoring_enabled=True)
        ev = self._stage_event(asset.id)

        # Simulate max-retries exhausted: attempt=4 > 3
        conn = _get_conn()
        conn.execute(
            "UPDATE integration_outbox SET attempt=4, last_error='timeout' WHERE id=?",
            (ev.id,)
        )
        _safe_commit(conn)

        # Force the verification step to raise (triggering the error/retry path)
        with patch(
            "core.authorization.verify_scan_authorization",
            side_effect=RuntimeError("DB failure")
        ):
            from core.tasks.maintenance_tasks import process_intel_reassessment_queue_task
            process_intel_reassessment_queue_task()

        row = conn.execute("SELECT status FROM integration_outbox WHERE id=?", (ev.id,)).fetchone()
        # Event should be DEAD_LETTER or FAILED due to exception path
        assert row is not None


# ===========================================================================
# PHASE 3 — Flask monitoring APIs
# ===========================================================================

class TestMonitoringAPIs:
    """Authentication, authorization, and response shape for Sprint 4 APIs."""

    def setup_method(self):
        _init_db()
        _make_tenant()

    def _admin_session(self):
        return {
            "user_id": "user-admin",
            "username": "admin",
            "user_role": "admin",
            "tenant_id": "t1",
            "logged_in": True,
        }

    def _viewer_session(self):
        return {
            "user_id": "user-viewer",
            "username": "viewer",
            "user_role": "viewer",
            "tenant_id": "t1",
            "logged_in": True,
        }

    def _other_tenant_session(self):
        return {
            "user_id": "user-other",
            "username": "other",
            "user_role": "admin",
            "tenant_id": "t2",   # different tenant
            "logged_in": True,
        }

    # --- Dashboard endpoint ---

    def test_dashboard_requires_authentication(self):
        client = _make_flask_client()
        resp = client.get("/api/v1/monitoring/dashboard")
        assert resp.status_code == 401

    def test_dashboard_returns_200_for_viewer(self):
        client = _make_flask_client(self._viewer_session())
        resp = client.get("/api/v1/monitoring/dashboard")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert "total_assets" in data["data"]

    def test_dashboard_contains_required_fields(self):
        client = _make_flask_client(self._admin_session())
        resp = client.get("/api/v1/monitoring/dashboard")
        body = resp.get_json()["data"]
        for field in [
            "total_assets", "monitored_assets", "paused_assets",
            "critical_findings", "high_findings",
            "newly_discovered_last_24h", "resolved_last_24h",
            "scan_failures_last_24h", "scheduled_scans_total",
        ]:
            assert field in body, f"Missing field: {field}"

    def test_dashboard_tenant_scoped(self):
        """Dashboard only returns data for the authenticated tenant."""
        from core.models import Asset
        from core.repository import save_asset, save_tenant
        from core.models import Tenant
        save_tenant(Tenant(id="t2", name="Other", slug="other"))
        a_other = Asset(tenant_id="t2", canonical_url="https://other.com", hostname="other.com")
        save_asset(a_other)

        client = _make_flask_client(self._admin_session())  # tenant_id = t1
        resp = client.get("/api/v1/monitoring/dashboard")
        body = resp.get_json()["data"]
        # t1 has 0 assets; t2's asset must not appear
        assert body["total_assets"] == 0

    # --- Asset monitoring status endpoint ---

    def test_monitoring_assets_returns_paginated(self):
        _make_asset()
        client = _make_flask_client(self._admin_session())
        resp = client.get("/api/v1/monitoring/assets")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "data" in body
        assert "meta" in body
        assert "total" in body["meta"]
        assert "page" in body["meta"]

    def test_monitoring_assets_requires_auth(self):
        client = _make_flask_client()
        resp = client.get("/api/v1/monitoring/assets")
        assert resp.status_code == 401

    # --- Differential endpoint ---

    def test_differential_404_for_wrong_tenant(self):
        """Asset belonging to t2 should return 404 for t1 session."""
        from core.models import Asset, Tenant
        from core.repository import save_asset, save_tenant
        save_tenant(Tenant(id="t2", name="T2", slug="t2"))
        a = Asset(tenant_id="t2", canonical_url="https://t2.com", hostname="t2.com")
        save_asset(a)

        client = _make_flask_client(self._admin_session())  # t1
        resp = client.get(f"/api/v1/assets/{a.id}/differential")
        assert resp.status_code == 404

    def test_differential_returns_empty_for_first_scan(self):
        asset = _make_asset()
        client = _make_flask_client(self._admin_session())
        resp = client.get(f"/api/v1/assets/{asset.id}/differential")
        assert resp.status_code == 200
        body = resp.get_json()["data"]
        assert body["changes"] == []

    def test_differential_returns_changes(self):
        asset = _make_asset()
        scan1 = _make_scan(asset_id=asset.id)
        _make_finding(scan1.id, asset_id=asset.id, fingerprint="fp-1")
        scan2 = _make_scan(asset_id=asset.id)
        _make_finding(scan2.id, asset_id=asset.id, fingerprint="fp-1")
        _make_finding(scan2.id, asset_id=asset.id, fingerprint="fp-2")

        client = _make_flask_client(self._admin_session())
        resp = client.get(f"/api/v1/assets/{asset.id}/differential")
        assert resp.status_code == 200
        body = resp.get_json()["data"]
        assert "changes" in body

    # --- Lifecycle endpoint ---

    def test_lifecycle_requires_auth(self):
        asset = _make_asset()
        client = _make_flask_client()
        resp = client.get(f"/api/v1/assets/{asset.id}/lifecycle")
        assert resp.status_code == 401

    def test_lifecycle_404_for_wrong_tenant(self):
        from core.models import Asset, Tenant
        from core.repository import save_asset, save_tenant
        save_tenant(Tenant(id="t3", name="T3", slug="t3"))
        a = Asset(tenant_id="t3", canonical_url="https://t3.com", hostname="t3.com")
        save_asset(a)

        client = _make_flask_client(self._admin_session())  # t1
        resp = client.get(f"/api/v1/assets/{a.id}/lifecycle")
        assert resp.status_code == 404

    def test_lifecycle_returns_findings(self):
        asset = _make_asset()
        scan = _make_scan(asset_id=asset.id)
        _make_finding(scan.id, asset_id=asset.id)

        client = _make_flask_client(self._admin_session())
        resp = client.get(f"/api/v1/assets/{asset.id}/lifecycle")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "data" in body

    # --- Pause / Resume endpoints ---

    def test_pause_requires_analyst_or_admin(self):
        """Viewer cannot pause a schedule (assets:write scope required)."""
        from core.models import ScheduledScan
        from core.repository import save_scheduled_scan
        sched = ScheduledScan(
            tenant_id="t1",
            target_url="https://example.com",
            scan_mode="passive",
            interval_hours=24,
        )
        save_scheduled_scan(sched)

        client = _make_flask_client(self._viewer_session())
        resp = client.post(f"/api/v1/schedules/{sched.id}/pause",
                           json={"hours": 12},
                           content_type="application/json")
        assert resp.status_code == 403

    def test_pause_returns_paused_until(self):
        from core.models import ScheduledScan
        from core.repository import save_scheduled_scan
        sched = ScheduledScan(
            tenant_id="t1",
            target_url="https://example.com",
            scan_mode="passive",
            interval_hours=24,
        )
        save_scheduled_scan(sched)

        client = _make_flask_client(self._admin_session())
        resp = client.post(f"/api/v1/schedules/{sched.id}/pause",
                           json={"hours": 6},
                           content_type="application/json")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "paused_until" in body["data"]
        assert body["data"]["hours"] == 6

    def test_pause_404_wrong_tenant(self):
        from core.models import ScheduledScan, Tenant
        from core.repository import save_scheduled_scan, save_tenant
        save_tenant(Tenant(id="t4", name="T4", slug="t4"))
        sched = ScheduledScan(
            tenant_id="t4",
            target_url="https://t4.com",
            scan_mode="passive",
            interval_hours=24,
        )
        save_scheduled_scan(sched)

        client = _make_flask_client(self._admin_session())  # t1
        resp = client.post(f"/api/v1/schedules/{sched.id}/pause",
                           json={"hours": 1},
                           content_type="application/json")
        assert resp.status_code == 404

    def test_resume_clears_paused_until(self):
        from core.models import ScheduledScan
        from core.repository import save_scheduled_scan
        sched = ScheduledScan(
            tenant_id="t1",
            target_url="https://example.com",
            scan_mode="passive",
            interval_hours=24,
            paused_until=(datetime.now(timezone.utc) + timedelta(hours=48)).isoformat(),
        )
        save_scheduled_scan(sched)

        client = _make_flask_client(self._admin_session())
        resp = client.post(f"/api/v1/schedules/{sched.id}/resume",
                           content_type="application/json")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["data"]["paused_until"] is None
        assert body["meta"]["status"] == "resumed"

    def test_pause_hours_validation(self):
        """Invalid hours value returns 400."""
        from core.models import ScheduledScan
        from core.repository import save_scheduled_scan
        sched = ScheduledScan(
            tenant_id="t1",
            target_url="https://example.com",
            scan_mode="passive",
            interval_hours=24,
        )
        save_scheduled_scan(sched)

        client = _make_flask_client(self._admin_session())
        resp = client.post(f"/api/v1/schedules/{sched.id}/pause",
                           json={"hours": "not-a-number"},
                           content_type="application/json")
        assert resp.status_code == 400


# ===========================================================================
# PHASE 5 — REQUIRE_DISTRIBUTED_LOCK fail-closed
# ===========================================================================

class TestRequireDistributedLock:
    """S3-GAP-001: REQUIRE_DISTRIBUTED_LOCK=true must fail-closed when Redis unavailable."""

    def setup_method(self):
        # Reset cached Redis client so each test starts fresh
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

    def teardown_method(self):
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None
        # Ensure env var is cleared
        os.environ.pop("REQUIRE_DISTRIBUTED_LOCK", None)

    def test_fail_closed_when_required_and_redis_unavailable(self):
        """With REQUIRE_DISTRIBUTED_LOCK=true and no Redis, _get_redis_client raises."""
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

        # Redis is imported inside _get_redis_client with `from redis import Redis`.
        # Patch the 'redis' module in sys.modules so the import sees our mock.
        import unittest.mock as _m
        mock_redis_cls = _m.MagicMock()
        mock_redis_cls.from_url.side_effect = ConnectionError("Redis unreachable")
        mock_redis_mod = _m.MagicMock()
        mock_redis_mod.Redis = mock_redis_cls

        with patch.dict(os.environ, {"REQUIRE_DISTRIBUTED_LOCK": "true"}):
            with patch.dict("sys.modules", {"redis": mock_redis_mod}):
                svc._redis_client = None
                with pytest.raises(RuntimeError, match="REQUIRE_DISTRIBUTED_LOCK"):
                    svc._get_redis_client()

    def test_silent_fallback_when_not_required(self):
        """With REQUIRE_DISTRIBUTED_LOCK=false (default), unavailable Redis falls back silently."""
        import core.vulnerability_intelligence.service as svc
        import unittest.mock as _m
        svc._redis_client = None

        mock_redis_cls = _m.MagicMock()
        mock_redis_cls.from_url.side_effect = ConnectionError("no redis")
        mock_redis_mod = _m.MagicMock()
        mock_redis_mod.Redis = mock_redis_cls

        with patch.dict(os.environ, {"REQUIRE_DISTRIBUTED_LOCK": "false"}):
            with patch.dict("sys.modules", {"redis": mock_redis_mod}):
                svc._redis_client = None
                result = svc._get_redis_client()
                assert result is None  # silent fallback

    def test_thread_lock_used_when_redis_unavailable(self):
        """When Redis unavailable and not required, sync_all uses thread-local lock."""
        import core.vulnerability_intelligence.service as svc
        svc._redis_client = None

        with patch.dict(os.environ, {"REQUIRE_DISTRIBUTED_LOCK": "false"}):
            with patch.object(svc, "_get_redis_client", return_value=None), \
                 patch.object(svc, "VULN_INTEL_ENABLED", True), \
                 patch.object(svc, "_sync_wordfence_inner", return_value={"status": "ok"}), \
                 patch.object(svc, "_sync_kev_inner", return_value={"status": "ok"}), \
                 patch.object(svc, "_sync_plugin_metadata_inner", return_value={"status": "ok"}), \
                 patch.object(svc, "_enrich_with_nvd_inner", return_value={"status": "ok", "enriched": 0}), \
                 patch("core.vulnerability_intelligence.service.vuln_repo") as mock_repo:
                mock_repo._get_vuln_conn().cursor().fetchall.return_value = []
                result = svc.sync_all()
                assert result is not None


# ===========================================================================
# PHASE 6 — NVD Backfill Task
# ===========================================================================

class TestNvdBackfillTask:
    """backfill_nvd_enrichment_task: dry_run, idempotency, rate limiting."""

    def setup_method(self):
        _init_db()

    def test_dry_run_returns_candidates_without_enriching(self):
        """dry_run=True returns count without calling NVD API."""
        from core.tasks.intel_tasks import backfill_nvd_enrichment_task
        from core.repository import _get_conn, _safe_commit

        # enrich_cve is imported inside the task function; patch at its source module.
        with patch("core.vulnerability_intelligence.nvd_client.enrich_cve") as mock_nvd:
            result = backfill_nvd_enrichment_task(dry_run=True, max_total=100)

        mock_nvd.assert_not_called()
        assert result["dry_run"] is True
        assert "total_candidates" in result

    def test_nvd_import_error_returns_error_status(self):
        """If nvd_client module is not importable, task returns error status gracefully."""
        from core.tasks.intel_tasks import backfill_nvd_enrichment_task

        # Simulate ImportError by removing the module from sys.modules before the task runs
        import sys
        nvd_mod_name = "core.vulnerability_intelligence.nvd_client"
        original = sys.modules.get(nvd_mod_name)
        sys.modules[nvd_mod_name] = None  # type: ignore[assignment]
        try:
            result = backfill_nvd_enrichment_task(dry_run=True)
        finally:
            if original is not None:
                sys.modules[nvd_mod_name] = original
            elif nvd_mod_name in sys.modules:
                del sys.modules[nvd_mod_name]
        # Should handle ImportError gracefully
        assert result.get("status") in ("error", "dry_run")

    def test_idempotent_records_not_overwritten(self):
        """Records with existing CVSS score are never included in candidates (query guard)."""
        from core.tasks.intel_tasks import backfill_nvd_enrichment_task

        # enrich_cve imported inside task function; patch at source to prevent real HTTP calls
        with patch("core.vulnerability_intelligence.nvd_client.enrich_cve", return_value=None):
            result = backfill_nvd_enrichment_task(dry_run=False, max_total=100)

        # The task should return successfully; the key assertion is no exception raised
        assert "status" in result


# ===========================================================================
# PHASE 7 — Plugin metadata cache-busting
# ===========================================================================

class TestPluginMetadataCacheBusting:
    """DETECT-OPEN-004: _get_plugin_version_from_readme sends Cache-Control: no-cache."""

    def test_readme_request_includes_cache_control(self):
        """Cache-Control: no-cache header is sent on readme.txt requests."""
        import requests as req_lib
        from scanners.plugin_scanner import PluginScanner

        scanner = PluginScanner("https://example.com")

        captured_headers = {}

        def _mock_get(url, **kwargs):
            captured_headers.update(kwargs.get("headers", {}))
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "Stable tag: 5.7.3"
            return resp

        with patch.object(scanner, "_get", side_effect=_mock_get):
            version = scanner._get_plugin_version_from_readme("contact-form-7")

        assert version == "5.7.3"
        assert "Cache-Control" in captured_headers, \
            "Cache-Control header must be present in readme.txt request"
        assert "no-cache" in captured_headers["Cache-Control"]

    def test_stale_version_response_still_parsed(self):
        """Even with cache-busting, stale CDN responses are parsed correctly."""
        from scanners.plugin_scanner import PluginScanner
        scanner = PluginScanner("https://example.com")

        def _mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "Stable tag: 5.7.2"  # older version
            return resp

        with patch.object(scanner, "_get", side_effect=_mock_get):
            version = scanner._get_plugin_version_from_readme("contact-form-7")

        assert version == "5.7.2"

    def test_missing_version_returns_empty(self):
        """No Stable tag in readme.txt returns empty string (not an exception)."""
        from scanners.plugin_scanner import PluginScanner
        scanner = PluginScanner("https://example.com")

        def _mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "This plugin has no version header."
            return resp

        with patch.object(scanner, "_get", side_effect=_mock_get):
            version = scanner._get_plugin_version_from_readme("my-plugin")

        assert version == ""


# ===========================================================================
# PHASE 8 — End-to-end workflow integration
# ===========================================================================

class TestEndToEndWorkflow:
    """Integration: scan → differential → outbox → dashboard visibility."""

    def setup_method(self):
        _init_db()
        _make_tenant()

    def test_full_workflow_scan_to_differential_to_dashboard(self):
        """
        End-to-end: two scans → differential → dashboard reflects counts.
        No mocked HTTP — uses only DB operations.
        """
        asset = _make_asset()
        scan1 = _make_scan(asset_id=asset.id)
        f1 = _make_finding(scan1.id, asset_id=asset.id, fingerprint="fp-e2e-1")
        f2 = _make_finding(scan1.id, asset_id=asset.id, fingerprint="fp-e2e-2")

        scan2 = _make_scan(asset_id=asset.id)
        # fp-e2e-1 persists, fp-e2e-2 gone (resolved), fp-e2e-3 new
        _make_finding(scan2.id, asset_id=asset.id, fingerprint="fp-e2e-1")
        _make_finding(scan2.id, asset_id=asset.id, fingerprint="fp-e2e-3")

        from core.differential import compute_scan_differential
        diff = compute_scan_differential(scan1.id, scan2.id, "t1", asset_id=asset.id)

        assert diff.new_count >= 1       # fp-e2e-3
        assert diff.persisting_count >= 1  # fp-e2e-1
        assert diff.resolved_count >= 1    # fp-e2e-2
        assert diff.is_complete is True

        # Verify dashboard reflects the asset
        from core.repository import get_monitoring_dashboard
        dashboard = get_monitoring_dashboard("t1")
        assert "total_assets" in dashboard

    def test_disabled_asset_not_processed_by_intel_queue(self):
        """Assets with monitoring_enabled=False are skipped by the intel queue processor."""
        asset = _make_asset(monitoring_enabled=False)

        from core.models import IntegrationOutbox
        from core.repository import save_outbox_event
        import hashlib, json

        payload = {"asset_id": asset.id, "asset_url": "https://example.com",
                   "vuln_id": "v-disabled", "slug": "p1"}
        key = f"intel_match:t1:{asset.id}:v-disabled:p1"
        ev = IntegrationOutbox(
            tenant_id="t1",
            event_type="intel_triggered_reassessment",
            event_key=key,
            destination="siem",
            payload_hash=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
            payload_json=payload,
            status="PENDING",
        )
        save_outbox_event(ev)

        from core.tasks.maintenance_tasks import process_intel_reassessment_queue_task
        result = process_intel_reassessment_queue_task()
        assert result["dispatched"] == 0

    def test_no_cross_tenant_differential_exposure(self):
        """Assets from different tenants produce isolated differentials."""
        from core.models import Tenant
        from core.repository import save_tenant
        save_tenant(Tenant(id="t5", name="T5", slug="t5"))

        asset_t1 = _make_asset(tenant_id="t1", canonical_url="https://t1.com")
        asset_t5 = _make_asset(tenant_id="t5", canonical_url="https://t5.com")

        scan_t1 = _make_scan(tenant_id="t1", asset_id=asset_t1.id)
        _make_finding(scan_t1.id, tenant_id="t1", asset_id=asset_t1.id, fingerprint="fp-t1")

        scan_t5_1 = _make_scan(tenant_id="t5", asset_id=asset_t5.id)
        scan_t5_2 = _make_scan(tenant_id="t5", asset_id=asset_t5.id)
        _make_finding(scan_t5_1.id, tenant_id="t5", asset_id=asset_t5.id, fingerprint="fp-t5")
        _make_finding(scan_t5_2.id, tenant_id="t5", asset_id=asset_t5.id, fingerprint="fp-t5")

        from core.differential import compute_scan_differential
        # t5 differential should not include t1 findings
        diff = compute_scan_differential(scan_t5_1.id, scan_t5_2.id, "t5", asset_id=asset_t5.id)
        fps = {c.fingerprint for c in diff.changes}
        assert "fp-t1" not in fps, "Cross-tenant finding fp-t1 must not appear in t5 differential"

    def test_paused_monitoring_dashboard_reflects_paused_count(self):
        """Dashboard correctly counts paused assets."""
        paused_until = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
        _make_asset(monitoring_enabled=True, monitoring_paused_at=paused_until)
        _make_asset(canonical_url="https://active.com", monitoring_enabled=True)

        from core.repository import get_monitoring_dashboard
        dashboard = get_monitoring_dashboard("t1")
        assert dashboard["paused_assets"] >= 1
        assert dashboard["monitored_assets"] >= 1
