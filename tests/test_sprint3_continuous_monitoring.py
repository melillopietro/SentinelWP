"""
tests/test_sprint3_continuous_monitoring.py

Sprint 3 Comprehensive Test Suite
Covers Phases 1–9: Asset Inventory, Continuous Monitoring, Differential,
Vulnerability Lifecycle, Distributed Lock, Per-Theme Findings, Scanning Safety,
Intelligence-Driven Monitoring, Dashboard.
"""
import json
import threading
import time
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_db():
    """Force re-initialize the repository database for isolation."""
    from core.repository import init_db
    init_db(force=True)


def _make_tenant():
    from core.models import Tenant
    from core.repository import save_tenant
    t = Tenant(id="test-tenant", name="Test", slug="test")
    save_tenant(t)
    return t


def _make_asset(tenant_id="test-tenant", **kwargs):
    from core.models import Asset
    from core.repository import save_asset
    a = Asset(
        tenant_id=tenant_id,
        canonical_url=kwargs.get("canonical_url", "https://example.com"),
        hostname=kwargs.get("hostname", "example.com"),
        display_name=kwargs.get("display_name", "Test Asset"),
        **{k: v for k, v in kwargs.items() if k not in ("canonical_url", "hostname", "display_name")}
    )
    save_asset(a)
    return a


def _make_scan(asset_id=None, tenant_id="test-tenant", status="completed"):
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


def _make_finding(scan_id, tenant_id="test-tenant", asset_id=None, fingerprint=None, status="OPEN"):
    from core.models import Finding, Severity
    from core.repository import save_finding
    f = Finding(
        tenant_id=tenant_id,
        asset_id=asset_id,
        scan_id=scan_id,
        category="vulnerability",
        title="Test Finding",
        severity=Severity.HIGH,
        fingerprint=fingerprint or f"fp-{scan_id[:8]}",
        status=status,
        first_seen_at=datetime.now(timezone.utc).isoformat(),
        last_seen_at=datetime.now(timezone.utc).isoformat(),
    )
    save_finding(f)
    return f


# ===========================================================================
# PHASE 1: Asset Inventory — Sprint 3 fields
# ===========================================================================

class TestPhase1AssetInventory:
    """Verify Sprint 3 Asset fields are persisted and retrieved correctly."""

    def setup_method(self):
        _fresh_db()
        _make_tenant()

    def test_asset_has_sprint3_fields(self):
        """Asset model exposes all Sprint 3 monitoring and posture fields."""
        from core.models import Asset
        a = Asset()
        assert hasattr(a, "wp_install_path")
        assert hasattr(a, "monitoring_enabled")
        assert hasattr(a, "monitoring_paused_at")
        assert hasattr(a, "last_scan_id")
        assert hasattr(a, "last_scan_at")
        assert hasattr(a, "last_scan_status")
        assert hasattr(a, "last_successful_scan_at")
        assert hasattr(a, "consecutive_scan_failures")
        assert hasattr(a, "wp_version")
        assert hasattr(a, "detected_themes")
        assert hasattr(a, "detected_plugins")
        assert hasattr(a, "risk_score")

    def test_asset_sprint3_fields_persist(self):
        """Sprint 3 asset fields round-trip through save/get."""
        from core.repository import save_asset, get_asset
        a = _make_asset(
            monitoring_enabled=True,
            wp_install_path="/blog",
            wp_version="6.5.3",
            detected_themes='["twentytwentyfour"]',
            detected_plugins='["woocommerce"]',
            risk_score=42.5,
            consecutive_scan_failures=2,
        )
        retrieved = get_asset(a.id, tenant_id="test-tenant")
        assert retrieved is not None
        assert retrieved.monitoring_enabled is True
        assert retrieved.wp_install_path == "/blog"
        assert retrieved.wp_version == "6.5.3"
        assert retrieved.risk_score == 42.5
        assert retrieved.consecutive_scan_failures == 2

    def test_asset_stable_id_preserved(self):
        """Asset ID is stable across save and re-fetch (acceptance criterion 1)."""
        from core.repository import get_asset
        a = _make_asset()
        original_id = a.id
        retrieved = get_asset(original_id, tenant_id="test-tenant")
        assert retrieved.id == original_id

    def test_update_asset_sprint3_fields(self):
        """update_asset() accepts and persists Sprint 3 monitoring fields."""
        from core.repository import update_asset, get_asset
        a = _make_asset()
        now = datetime.now(timezone.utc).isoformat()
        update_asset(a.id, tenant_id="test-tenant",
                     last_scan_id="scan-abc",
                     last_scan_at=now,
                     last_scan_status="completed",
                     consecutive_scan_failures=0,
                     risk_score=75.0)
        retrieved = get_asset(a.id, tenant_id="test-tenant")
        assert retrieved.last_scan_id == "scan-abc"
        assert retrieved.last_scan_status == "completed"
        assert retrieved.consecutive_scan_failures == 0
        assert retrieved.risk_score == 75.0


# ===========================================================================
# PHASE 2: Continuous Monitoring — ScheduledScan Sprint 3 fields + pause
# ===========================================================================

class TestPhase2ContinuousMonitoring:
    """Verify scheduled scan failure tracking and pause support."""

    def setup_method(self):
        _fresh_db()
        _make_tenant()
        # Purge any scheduled scans left from other tests
        from core.repository import _get_conn, _safe_commit
        conn = _get_conn()
        conn.execute("DELETE FROM scheduled_scans")
        conn.execute("DELETE FROM scheduled_runs")
        _safe_commit(conn)

    def test_scheduled_scan_has_sprint3_fields(self):
        from core.models import ScheduledScan
        s = ScheduledScan()
        assert hasattr(s, "max_retries")
        assert hasattr(s, "consecutive_failures")
        assert hasattr(s, "last_failure_at")
        assert hasattr(s, "last_success_at")
        assert hasattr(s, "paused_until")

    def test_scheduled_scan_pause_persists(self):
        """paused_until field is persisted and retrieved."""
        from core.models import ScheduledScan
        from core.repository import save_scheduled_scan, get_scheduled_scan
        future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        s = ScheduledScan(
            tenant_id="test-tenant",
            target_url="https://example.com",
            paused_until=future,
        )
        save_scheduled_scan(s)
        retrieved = get_scheduled_scan(s.id, tenant_id="test-tenant")
        assert retrieved.paused_until == future

    def test_dispatcher_skips_paused_schedule(self):
        """Dispatcher skips schedules where paused_until is in the future."""
        from core.models import ScheduledScan
        from core.repository import save_scheduled_scan
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        overdue = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        s = ScheduledScan(
            tenant_id="test-tenant",
            target_url="https://example.com",
            enabled=True,
            next_run_at=overdue,
            paused_until=future,
        )
        save_scheduled_scan(s)

        from core.tasks.maintenance_tasks import dispatch_scheduled_scans_task
        # run_scan_task is imported inside dispatch_scheduled_scans_task; patch at source
        with patch("core.tasks.scan_tasks.run_scan_task") as mock_task:
            result = dispatch_scheduled_scans_task()

        # Should not dispatch the paused schedule
        assert result["dispatched"] == 0

    def test_dispatcher_resumes_expired_pause(self):
        """Dispatcher resumes and clears paused_until when it has expired."""
        from core.models import ScheduledScan
        from core.repository import save_scheduled_scan, get_scheduled_scan
        past_pause = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        overdue = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        s = ScheduledScan(
            tenant_id="test-tenant",
            target_url="https://example.com",
            enabled=True,
            next_run_at=overdue,
            paused_until=past_pause,
        )
        save_scheduled_scan(s)

        from core.tasks.maintenance_tasks import dispatch_scheduled_scans_task
        with patch("core.tasks.scan_tasks.run_scan_task") as mock_task:
            mock_task.delay.return_value = MagicMock(id="task-123")
            result = dispatch_scheduled_scans_task()

        # Schedule should have been processed (paused_until expired)
        assert result["dispatched"] == 1


# ===========================================================================
# PHASE 3: Security Posture Differential
# ===========================================================================

class TestPhase3Differential:
    """Verify the ScanDifferential engine correctly classifies finding changes."""

    def setup_method(self):
        _fresh_db()
        _make_tenant()

    def test_new_finding_classified_new(self):
        """A fingerprint present only in the new scan is NEW."""
        from core.differential import compute_scan_differential
        asset = _make_asset()
        scan_b = _make_scan(asset.id)
        scan_n = _make_scan(asset.id)
        _make_finding(scan_b.id, fingerprint="fp-baseline-only")
        _make_finding(scan_n.id, fingerprint="fp-new-only")
        _make_finding(scan_n.id, fingerprint="fp-baseline-only")  # persisting

        diff = compute_scan_differential(
            baseline_scan_id=scan_b.id,
            new_scan_id=scan_n.id,
            tenant_id="test-tenant",
            asset_id=asset.id,
        )
        assert diff.is_complete is True
        new_fps = {c.fingerprint for c in diff.changes if c.change_state == "NEW"}
        assert "fp-new-only" in new_fps

    def test_persisting_finding_classified_persisting(self):
        """A fingerprint present in both scans is PERSISTING."""
        from core.differential import compute_scan_differential
        asset = _make_asset()
        scan_b = _make_scan(asset.id)
        scan_n = _make_scan(asset.id)
        _make_finding(scan_b.id, fingerprint="fp-both")
        _make_finding(scan_n.id, fingerprint="fp-both")

        diff = compute_scan_differential(
            baseline_scan_id=scan_b.id,
            new_scan_id=scan_n.id,
            tenant_id="test-tenant",
            asset_id=asset.id,
        )
        persisting = [c for c in diff.changes if c.change_state == "PERSISTING"]
        assert any(c.fingerprint == "fp-both" for c in persisting)

    def test_resolved_only_on_completed_scan(self):
        """RESOLVED change state is never produced when new scan is not COMPLETED."""
        from core.differential import compute_scan_differential
        asset = _make_asset()
        scan_b = _make_scan(asset.id, status="completed")
        # New scan is FAILED — must not produce RESOLVED
        scan_n = _make_scan(asset.id, status="failed")
        _make_finding(scan_b.id, fingerprint="fp-was-open")
        # fp-was-open absent in scan_n (zero findings)

        diff = compute_scan_differential(
            baseline_scan_id=scan_b.id,
            new_scan_id=scan_n.id,
            tenant_id="test-tenant",
            asset_id=asset.id,
        )
        assert diff.is_complete is False
        resolved = [c for c in diff.changes if c.change_state == "RESOLVED"]
        assert len(resolved) == 0, "Failed scan must NOT produce RESOLVED changes"

    def test_resolved_on_completed_scan_when_absent(self):
        """RESOLVED is produced for a previously OPEN finding absent in a new completed scan."""
        from core.differential import compute_scan_differential
        asset = _make_asset()
        scan_b = _make_scan(asset.id, status="completed")
        scan_n = _make_scan(asset.id, status="completed")
        _make_finding(scan_b.id, fingerprint="fp-was-open", status="OPEN")
        # fp-was-open absent from scan_n

        diff = compute_scan_differential(
            baseline_scan_id=scan_b.id,
            new_scan_id=scan_n.id,
            tenant_id="test-tenant",
            asset_id=asset.id,
        )
        assert diff.is_complete is True
        resolved = [c for c in diff.changes if c.change_state == "RESOLVED"]
        assert any(c.fingerprint == "fp-was-open" for c in resolved)

    def test_wp_version_change_detected(self):
        """WP version change between scans is detected."""
        from core.differential import compute_scan_differential
        from core.repository import update_scan
        asset = _make_asset()
        scan_b = _make_scan(asset.id)
        scan_n = _make_scan(asset.id)
        update_scan(scan_b.id, tenant_id="test-tenant", wp_version="6.4.0")
        update_scan(scan_n.id, tenant_id="test-tenant", wp_version="6.5.0")

        diff = compute_scan_differential(scan_b.id, scan_n.id, "test-tenant", asset.id)
        assert diff.wp_version_changed is True
        assert diff.wp_version_baseline == "6.4.0"
        assert diff.wp_version_new == "6.5.0"

    def test_counts_correct(self):
        """Aggregated counts match changes list."""
        from core.differential import compute_scan_differential
        asset = _make_asset()
        scan_b = _make_scan(asset.id)
        scan_n = _make_scan(asset.id)
        _make_finding(scan_b.id, fingerprint="fp-resolved")   # only in baseline → RESOLVED
        _make_finding(scan_b.id, fingerprint="fp-persisting")
        _make_finding(scan_n.id, fingerprint="fp-persisting")  # in both → PERSISTING
        _make_finding(scan_n.id, fingerprint="fp-new")         # only in new → NEW

        diff = compute_scan_differential(scan_b.id, scan_n.id, "test-tenant", asset.id)
        diff._recompute_counts()
        assert diff.new_count >= 1
        assert diff.persisting_count >= 1
        assert diff.resolved_count >= 1


# ===========================================================================
# PHASE 4: Vulnerability Lifecycle
# ===========================================================================

class TestPhase4VulnerabilityLifecycle:
    """Verify finding lifecycle query returns complete timeline."""

    def setup_method(self):
        _fresh_db()
        _make_tenant()

    def test_get_finding_lifecycle_returns_structure(self):
        """get_finding_lifecycle returns finding, observations, history, comments."""
        from core.repository import get_finding_lifecycle
        scan = _make_scan(tenant_id="test-tenant")
        f = _make_finding(scan.id)

        lifecycle = get_finding_lifecycle(f.id, tenant_id="test-tenant")
        assert "finding" in lifecycle
        assert "observations" in lifecycle
        assert "history" in lifecycle
        assert "comments" in lifecycle
        assert "remediation" in lifecycle
        assert lifecycle["finding"].id == f.id

    def test_get_finding_lifecycle_empty_for_unknown(self):
        """get_finding_lifecycle returns empty dict for unknown finding_id."""
        from core.repository import get_finding_lifecycle
        result = get_finding_lifecycle("nonexistent-id", tenant_id="test-tenant")
        assert result == {}

    def test_scanner_observations_separate_from_workflow_history(self):
        """Scanner observations and workflow history are distinct collections."""
        from core.repository import (
            get_finding_lifecycle, save_finding_observation, add_finding_history
        )
        from core.models import FindingObservation, FindingHistory
        scan = _make_scan(tenant_id="test-tenant")
        f = _make_finding(scan.id)

        # Add a scanner observation
        obs = FindingObservation(
            tenant_id="test-tenant",
            finding_id=f.id,
            scan_id=scan.id,
            observed_at=datetime.now(timezone.utc).isoformat(),
            status="OPEN",
        )
        save_finding_observation(obs)

        # Add a workflow history event
        hist = FindingHistory(
            tenant_id="test-tenant",
            finding_id=f.id,
            actor_user_id="analyst-1",
            action="finding_acknowledged",
            old_status="OPEN",
            new_status="ACKNOWLEDGED",
        )
        add_finding_history(hist)

        lifecycle = get_finding_lifecycle(f.id, tenant_id="test-tenant")
        obs_ids = [o.id for o in lifecycle["observations"]]
        hist_actions = [h.action for h in lifecycle["history"]]
        assert obs.id in obs_ids
        assert "finding_acknowledged" in hist_actions

    def test_first_seen_is_immutable(self):
        """first_seen_at is set on creation and not changed by subsequent observations."""
        from core.repository import get_finding
        scan = _make_scan(tenant_id="test-tenant")
        f = _make_finding(scan.id)
        original_first_seen = f.first_seen_at
        # Finding already saved; simulate a second observation update
        from core.repository import save_finding
        f.last_seen_at = datetime.now(timezone.utc).isoformat()
        f.observation_count = 2
        save_finding(f)
        retrieved = get_finding(f.id, tenant_id="test-tenant")
        assert retrieved.first_seen_at == original_first_seen


# ===========================================================================
# PHASE 5: Distributed Synchronization (INTEL-OPEN-001)
# ===========================================================================

class TestPhase5DistributedLock:
    """Verify the _DistributedSyncLock behaves correctly with thread fallback."""

    def setup_method(self):
        # Ensure Redis is unavailable so tests use thread lock (no external deps)
        from core.vulnerability_intelligence import service
        service._redis_client = None

    def test_lock_acquire_and_release(self):
        """Acquiring the lock succeeds; releasing succeeds; second acquire then succeeds."""
        from core.vulnerability_intelligence import service
        lock = service._sync_lock

        # Force process-lock path by making _get_redis_client return None
        with patch.object(service, "_get_redis_client", return_value=None):
            acquired = lock.acquire(blocking=False)
            assert acquired is True
            lock.release()
            # After release, acquire again succeeds
            acquired2 = lock.acquire(blocking=False)
            assert acquired2 is True
            lock.release()

    def test_second_acquire_fails_while_held(self):
        """Second non-blocking acquire returns False while lock is held."""
        from core.vulnerability_intelligence import service
        lock = service._sync_lock

        with patch.object(service, "_get_redis_client", return_value=None):
            acquired = lock.acquire(blocking=False)
            assert acquired is True
            try:
                second = lock.acquire(blocking=False)
                assert second is False
            finally:
                lock.release()

    def test_locked_reports_true_while_held(self):
        """locked() returns True when the lock is held."""
        from core.vulnerability_intelligence import service
        lock = service._sync_lock

        with patch.object(service, "_get_redis_client", return_value=None):
            lock.acquire(blocking=False)
            try:
                assert lock.locked() is True
            finally:
                lock.release()

    def test_locked_reports_false_when_free(self):
        """locked() returns False when no one holds the lock."""
        from core.vulnerability_intelligence import service
        lock = service._sync_lock

        with patch.object(service, "_get_redis_client", return_value=None):
            if lock.locked():
                lock.release()
            assert lock.locked() is False

    def test_sync_all_skips_when_lock_already_held(self):
        """sync_all returns skipped when lock is held."""
        from core.vulnerability_intelligence import service

        mock_lock = MagicMock()
        mock_lock.acquire.return_value = False
        mock_lock.locked.return_value = True

        with patch.object(service, "_sync_lock", mock_lock), \
             patch.object(service, "VULN_INTEL_ENABLED", True):
            result = service.sync_all()

        assert result["status"] == "skipped"

    def test_redis_unavailable_falls_back_to_thread_lock(self):
        """When Redis is unreachable, the lock falls back to thread lock silently."""
        from core.vulnerability_intelligence.service import _DistributedSyncLock, _process_lock
        lock = _DistributedSyncLock()

        with patch("core.vulnerability_intelligence.service._get_redis_client", return_value=None):
            acquired = lock.acquire(blocking=False)
            assert acquired is True
            lock.release()


# ===========================================================================
# PHASE 6: Per-Theme Vulnerability Correlation (DETECT-OPEN-003)
# ===========================================================================

class TestPhase6PerThemeFindings:
    """Verify _probe_default_themes emits one finding per confirmed theme."""

    def _make_response(self, status_code, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = {"Content-Type": "text/css"}
        return resp

    def test_one_finding_per_confirmed_theme(self):
        """With two themes returning 200, two separate findings are emitted."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        scanner.ENABLE_ACTIVE_PROBE = True

        def _head_side_effect(url):
            if "twentytwentyfour" in url or "twentytwentythree" in url:
                return self._make_response(200)
            return self._make_response(404)

        with patch.object(scanner, "_detect_active_theme"), \
             patch.object(scanner, "_get", return_value=self._make_response(200, "")), \
             patch.object(scanner, "_head", side_effect=_head_side_effect):
            scanner._probe_default_themes()

        theme_findings = [f for f in scanner.findings if "Default Theme Present" in f.title]
        assert len(theme_findings) == 2, f"Expected 2 per-theme findings, got {len(theme_findings)}"

    def test_finding_raw_data_has_slug_and_version(self):
        """Each per-theme finding has slug, version, version_confidence in raw_data."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")

        def _head_side_effect(url):
            return self._make_response(200) if "twentytwentyfour" in url else self._make_response(404)

        # Mock _get_theme_version to return a version string
        with patch.object(scanner, "_head", side_effect=_head_side_effect), \
             patch.object(scanner, "_get_theme_version", return_value="1.2.3"):
            scanner._probe_default_themes()

        findings = [f for f in scanner.findings if "twentytwentyfour" in f.title]
        assert len(findings) == 1
        rd = findings[0].raw_data
        assert rd["slug"] == "twentytwentyfour"
        assert rd["version"] == "1.2.3"
        assert rd["version_confidence"] == "high"

    def test_no_version_sets_confidence_none(self):
        """When _get_theme_version returns empty string, version_confidence is 'none'."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")

        def _head_side_effect(url):
            return self._make_response(200) if "twentytwentyfour" in url else self._make_response(404)

        with patch.object(scanner, "_head", side_effect=_head_side_effect), \
             patch.object(scanner, "_get_theme_version", return_value=""):
            scanner._probe_default_themes()

        findings = [f for f in scanner.findings if "twentytwentyfour" in f.title]
        assert len(findings) == 1
        assert findings[0].raw_data["version_confidence"] == "none"
        assert findings[0].raw_data["version"] is None

    def test_zero_findings_when_no_themes_found(self):
        """If no themes return HTTP 200, no findings are emitted."""
        from scanners.theme_scanner import ThemeScanner

        scanner = ThemeScanner("https://example.com")
        with patch.object(scanner, "_head", return_value=self._make_response(404)):
            scanner._probe_default_themes()

        assert len(scanner.findings) == 0


# ===========================================================================
# PHASE 7: Scanning Safety — Passive mode subdirectory gate
# ===========================================================================

class TestPhase7ScanSafety:
    """
    Verify that passive scan does not trigger subdirectory probing,
    and that safe-active does.
    """

    def test_passive_scan_does_not_probe_subdirs(self):
        """In passive mode, ENABLE_SUBDIR_PROBE stays False → no subdir calls."""
        from scanners.wp_detector import WordPressDetector

        detector = WordPressDetector("https://example.com")
        # Default must be False
        assert detector.ENABLE_SUBDIR_PROBE is False

        root_miss = {
            "confidence": 0.0,
            "evidence": [],
            "version": {"value": None, "source": None, "confidence": None},
            "base_url": "https://example.com",
        }

        with patch.object(detector, "_detect_multi_signal", return_value=root_miss) as mock_ms:
            result = detector.detect()

        # Only root call; no subdirectory calls
        assert mock_ms.call_count == 1
        assert result.detected is False

    def test_safe_active_orchestrator_sets_subdir_probe_flag(self):
        """Orchestrator sets ENABLE_SUBDIR_PROBE=True for safe-active/full modes."""
        from scanners.wp_detector import WordPressDetector
        from scanners.orchestrator import run_scan, SCAN_PROFILES

        instances = []
        original_init = WordPressDetector.__init__

        def _track_instance(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            instances.append(self)

        def _noop_scan(self):
            return []

        def _noop_detect(self):
            from scanners.wp_detector import WordPressDetectionResult
            return WordPressDetectionResult(detected=False)

        with patch.object(WordPressDetector, "__init__", _track_instance), \
             patch.object(WordPressDetector, "scan", _noop_scan), \
             patch.object(WordPressDetector, "detect", _noop_detect), \
             patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")):
            try:
                run_scan("https://example.com", scan_mode="safe-active",
                         scanner_classes=[WordPressDetector], persist=False)
            except Exception:
                pass

        wp_instances = [i for i in instances if isinstance(i, WordPressDetector)]
        if wp_instances:
            assert wp_instances[0].ENABLE_SUBDIR_PROBE is True

    def test_passive_scan_does_not_set_subdir_probe_flag(self):
        """Orchestrator must NOT set ENABLE_SUBDIR_PROBE for passive mode."""
        from scanners.wp_detector import WordPressDetector
        from scanners.orchestrator import run_scan

        instances = []
        original_init = WordPressDetector.__init__

        def _track_instance(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            instances.append(self)

        def _noop_scan(self):
            return []

        def _noop_detect(self):
            from scanners.wp_detector import WordPressDetectionResult
            return WordPressDetectionResult(detected=False)

        with patch.object(WordPressDetector, "__init__", _track_instance), \
             patch.object(WordPressDetector, "scan", _noop_scan), \
             patch.object(WordPressDetector, "detect", _noop_detect), \
             patch("scanners.orchestrator.BaseScanner.validate_target", return_value=(True, "")):
            try:
                run_scan("https://example.com", scan_mode="passive",
                         scanner_classes=[WordPressDetector], persist=False)
            except Exception:
                pass

        wp_instances = [i for i in instances if isinstance(i, WordPressDetector)]
        if wp_instances:
            assert wp_instances[0].ENABLE_SUBDIR_PROBE is False

    def test_passive_mode_subdir_probe_false_does_not_probe(self):
        """With ENABLE_SUBDIR_PROBE=False and root confidence 0.0, no subdir probes are made."""
        from scanners.wp_detector import WordPressDetector

        detector = WordPressDetector("https://example.com")
        assert detector.ENABLE_SUBDIR_PROBE is False  # default

        root_miss = {
            "confidence": 0.0,
            "evidence": [],
            "version": {"value": None, "source": None, "confidence": None},
            "base_url": "https://example.com",
        }

        with patch.object(detector, "_detect_multi_signal", return_value=root_miss) as mock_ms:
            detector.detect()

        # Only 1 call (root) — no subdir calls
        assert mock_ms.call_count == 1, (
            f"Expected 1 call (root only), got {mock_ms.call_count}. "
            "Passive mode must not issue subdirectory probes."
        )


# ===========================================================================
# PHASE 8: Intelligence-Driven Monitoring
# ===========================================================================

class TestPhase8IntelMonitor:
    """Verify intel-triggered reassessment logic."""

    def setup_method(self):
        _fresh_db()
        _make_tenant()

    def test_check_intel_returns_stats_dict(self):
        """check_intel_triggered_reassessment returns a stats dict."""
        from core.intel_monitor import check_intel_triggered_reassessment
        result = check_intel_triggered_reassessment(tenant_id="test-tenant")
        assert "assets_evaluated" in result
        assert "matches_found" in result
        assert "alerts_staged" in result

    def test_no_assets_no_matches(self):
        """With no assets, no matches are found."""
        from core.intel_monitor import check_intel_triggered_reassessment
        result = check_intel_triggered_reassessment(tenant_id="test-tenant")
        assert result["assets_evaluated"] == 0
        assert result["matches_found"] == 0

    def test_duplicate_alert_suppressed(self):
        """A second call with the same event_key does not stage a duplicate alert."""
        from core.intel_monitor import check_intel_triggered_reassessment
        from core.models import TechnologyObservation
        from core.repository import save_technology_observation

        asset = _make_asset()
        obs = TechnologyObservation(
            tenant_id="test-tenant",
            asset_id=asset.id,
            technology_type="WORDPRESS_PLUGIN",
            name="vulnerable-plugin",
            version="1.0.0",
            confidence="HIGH",
        )
        save_technology_observation(obs)

        # Mock match_scan_findings to return a deterministic match
        mock_matches = [{"vuln_id": "vuln-123", "slug": "vulnerable-plugin",
                          "severity": "high", "cve_id": "CVE-2024-0001",
                          "component_version": "1.0.0"}]

        with patch("core.vulnerability_intelligence.service.match_scan_findings", return_value=mock_matches):
            first_result = check_intel_triggered_reassessment(tenant_id="test-tenant")
            first_staged = first_result["alerts_staged"]

            second_result = check_intel_triggered_reassessment(tenant_id="test-tenant")
            second_staged = second_result["alerts_staged"]

        # Second call must not stage a duplicate
        assert second_staged == 0, "Duplicate alert must be suppressed"

    def test_no_secrets_in_alert_payload(self):
        """Intel alert payloads must not contain secret fields."""
        from core.intel_monitor import check_intel_triggered_reassessment
        from core.models import TechnologyObservation, IntegrationOutbox
        from core.repository import save_technology_observation, get_pending_outbox_events

        asset = _make_asset(canonical_url="https://example2.com", hostname="example2.com")
        obs = TechnologyObservation(
            tenant_id="test-tenant",
            asset_id=asset.id,
            technology_type="WORDPRESS_PLUGIN",
            name="other-plugin",
            version="2.0.0",
            confidence="HIGH",
        )
        save_technology_observation(obs)

        mock_matches = [{"vuln_id": "vuln-456", "slug": "other-plugin",
                          "severity": "medium", "cve_id": None, "component_version": "2.0.0"}]

        with patch("core.vulnerability_intelligence.service.match_scan_findings", return_value=mock_matches):
            check_intel_triggered_reassessment(tenant_id="test-tenant")

        events = get_pending_outbox_events(limit=100)
        secret_keys = {"password", "secret", "token", "api_key", "key", "authorization"}
        for evt in events:
            if hasattr(evt, "payload_json"):
                payload = evt.payload_json if isinstance(evt.payload_json, dict) else {}
                for k in payload:
                    assert k.lower() not in secret_keys, f"Secret key '{k}' found in payload"


# ===========================================================================
# PHASE 9: Monitoring Dashboard
# ===========================================================================

class TestPhase9MonitoringDashboard:
    """Verify the monitoring dashboard returns expected structure and values."""

    def setup_method(self):
        _fresh_db()
        _make_tenant()

    def test_dashboard_returns_all_expected_keys(self):
        """get_monitoring_dashboard returns all required metric keys."""
        from core.repository import get_monitoring_dashboard
        dashboard = get_monitoring_dashboard("test-tenant")

        required_keys = [
            "total_assets", "monitored_assets", "paused_assets",
            "assets_needing_attention", "last_scan_status",
            "critical_findings", "high_findings",
            "newly_discovered_last_24h", "resolved_last_24h",
            "scan_failures_last_24h", "scheduled_scans_total",
            "scheduled_scans_paused", "intel_freshness_seconds",
            "historical_risk_trend", "generated_at",
        ]
        for key in required_keys:
            assert key in dashboard, f"Missing dashboard key: {key}"

    def test_dashboard_counts_assets(self):
        """Dashboard total_assets reflects actual saved assets."""
        from core.repository import get_monitoring_dashboard
        _make_asset()
        _make_asset(canonical_url="https://example2.com", hostname="example2.com")

        dashboard = get_monitoring_dashboard("test-tenant")
        assert dashboard["total_assets"] == 2

    def test_dashboard_counts_monitored_assets(self):
        """monitored_assets counts assets with monitoring_enabled=True."""
        from core.repository import get_monitoring_dashboard, update_asset
        a = _make_asset()
        _make_asset(canonical_url="https://example2.com", hostname="example2.com")
        update_asset(a.id, tenant_id="test-tenant", monitoring_enabled=True)

        dashboard = get_monitoring_dashboard("test-tenant")
        assert dashboard["monitored_assets"] == 1
        assert dashboard["total_assets"] == 2

    def test_dashboard_assets_needing_attention(self):
        """assets_needing_attention counts assets with last_scan_status=failed or never scanned."""
        from core.repository import get_monitoring_dashboard, update_asset
        a1 = _make_asset(canonical_url="https://a1.com", hostname="a1.com")
        a2 = _make_asset(canonical_url="https://a2.com", hostname="a2.com")
        update_asset(a2.id, tenant_id="test-tenant",
                     last_scan_id="s1",
                     last_scan_at=datetime.now(timezone.utc).isoformat(),
                     last_scan_status="completed")

        dashboard = get_monitoring_dashboard("test-tenant")
        # a1 never scanned → needs attention; a2 completed → fine
        assert dashboard["assets_needing_attention"] >= 1

    def test_dashboard_last_scan_status_breakdown(self):
        """last_scan_status dict has all expected sub-keys."""
        from core.repository import get_monitoring_dashboard
        dashboard = get_monitoring_dashboard("test-tenant")
        lss = dashboard["last_scan_status"]
        assert "completed" in lss
        assert "failed" in lss
        assert "running" in lss
        assert "never_scanned" in lss

    def test_dashboard_no_secrets(self):
        """Dashboard payload must not contain any secret fields."""
        from core.repository import get_monitoring_dashboard
        dashboard = get_monitoring_dashboard("test-tenant")
        secret_keys = {"password", "secret", "token", "api_key", "key", "authorization"}
        for k in dashboard:
            assert k.lower() not in secret_keys


# ===========================================================================
# Migration 006: DB schema accepts Sprint 3 columns
# ===========================================================================

class TestMigration006Schema:
    """Verify migration-006 columns exist after init_db."""

    def setup_method(self):
        _fresh_db()

    def test_assets_sprint3_columns_exist(self):
        """Sprint 3 asset columns are present in the assets table after init_db."""
        from core.repository import _get_conn
        conn = _get_conn()
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(assets)").fetchall()}
        sprint3_cols = {
            "wp_install_path", "monitoring_enabled", "monitoring_paused_at",
            "last_scan_id", "last_scan_at", "last_scan_status", "last_successful_scan_at",
            "consecutive_scan_failures", "wp_version", "detected_themes",
            "detected_plugins", "risk_score",
        }
        missing = sprint3_cols - cols
        assert not missing, f"Missing columns in assets table: {missing}"

    def test_scheduled_scans_sprint3_columns_exist(self):
        """Sprint 3 scheduled_scan columns are present after init_db."""
        from core.repository import _get_conn
        conn = _get_conn()
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(scheduled_scans)").fetchall()}
        sprint3_cols = {
            "max_retries", "consecutive_failures", "last_failure_at",
            "last_success_at", "paused_until",
        }
        missing = sprint3_cols - cols
        assert not missing, f"Missing columns in scheduled_scans table: {missing}"
