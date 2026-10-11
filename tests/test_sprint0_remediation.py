"""
Sprint 0 Remediation Regression Tests — SentinelWP v3.7.0

Covers:
  SEC-001 — Admin password policy (validate_admin_password)
  SEC-002 — Rate limiter failure mode correctness (NOT CONFIRMED as defect; verified working)
  SEC-003/CODE-001 — Evidence size guard (docstring fix — guard must execute)
  SEC-005 — Audit log purge opt-in (purge_expired_records_task must NOT delete audit_events by default)
  CODE-003 — Concurrency gate boundary (>= not >)
  SEC-004 — CEF extension value escaping
  DEPLOY-001 — Alembic migration file exists and is well-formed
"""
import os
import sys
import pytest

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("TESTING", "1")
os.environ.setdefault("ENVIRONMENT", "development")


# ─────────────────────────────────────────────────────────────────────────────
# SEC-001 — Admin password policy
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminPasswordPolicy:
    """validate_admin_password must reject weak/short/empty passwords."""

    def _validate(self, password):
        from config import validate_admin_password
        return validate_admin_password(password)

    def test_empty_password_rejected(self):
        ok, reason = self._validate("")
        assert not ok
        assert "empty" in reason.lower() or "must not" in reason.lower()

    def test_short_password_rejected(self):
        ok, reason = self._validate("short1")
        assert not ok
        assert "12" in reason or "characters" in reason.lower()

    def test_known_weak_password_admin_rejected(self):
        ok, reason = self._validate("admin")
        assert not ok

    def test_known_weak_password_password_rejected(self):
        ok, reason = self._validate("password")
        assert not ok

    def test_known_weak_password_changeme_rejected(self):
        ok, reason = self._validate("changeme")
        assert not ok

    def test_known_weak_password_123456_rejected(self):
        ok, reason = self._validate("123456")
        assert not ok

    def test_known_weak_password_wordpress_rejected(self):
        ok, reason = self._validate("wordpress")
        assert not ok

    def test_strong_password_accepted(self):
        ok, reason = self._validate("Tr0ub4dor&3-sentinel")
        assert ok, f"Expected acceptance, got: {reason}"

    def test_minimum_length_boundary_accepted(self):
        # Exactly 12 chars, not in weak list
        ok, reason = self._validate("aB3!xY9#mK2@")
        assert ok, f"Expected acceptance at min length, got: {reason}"

    def test_exactly_one_below_minimum_rejected(self):
        # 11 chars — should fail length check
        ok, reason = self._validate("aB3!xY9#mK2")
        assert not ok
        assert "12" in reason or "characters" in reason.lower()

    def test_case_insensitive_weak_check(self):
        # "Admin" matches "admin" in lowercase comparison
        ok, reason = self._validate("Admin")
        # short + weak — both should fail
        assert not ok

    def test_default_admin_password_env_is_empty(self):
        """ADMIN_PASSWORD default must not be 'admin'."""
        from config import ADMIN_PASSWORD
        assert ADMIN_PASSWORD != "admin", (
            "ADMIN_PASSWORD default must not be 'admin' — SEC-001 remediation failed"
        )


# ─────────────────────────────────────────────────────────────────────────────
# SEC-002 — Rate limiter failure modes
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimiterFailureModes:
    """Verify each failure mode behaves as documented."""

    def _make_limiter(self, fail_mode):
        from core.rate_limiter import DistributedRateLimiter
        # redis_client=False forces in-memory mode; fail_mode overrides
        limiter = DistributedRateLimiter(redis_client=False, fail_mode=fail_mode)
        return limiter

    def test_fallback_mode_allows_requests_within_limit(self):
        limiter = self._make_limiter("fallback")
        allowed, retry_after = limiter.is_allowed("test_key", max_requests=5, window_seconds=60)
        assert allowed is True
        assert retry_after == 0

    def test_fallback_mode_blocks_after_limit(self):
        limiter = self._make_limiter("fallback")
        for _ in range(5):
            limiter.is_allowed("flood_key", max_requests=5, window_seconds=60)
        allowed, retry_after = limiter.is_allowed("flood_key", max_requests=5, window_seconds=60)
        assert allowed is False
        assert retry_after >= 1

    def test_fail_closed_no_redis_denies_requests(self):
        """With no Redis and fail_mode=closed (non-test env), requests should be denied."""
        from core.rate_limiter import DistributedRateLimiter
        # Temporarily remove TESTING to simulate production behaviour
        old = os.environ.pop("TESTING", None)
        try:
            limiter = DistributedRateLimiter(redis_client=None, fail_mode="closed")
            # No redis_client initialized means fail-closed path
            allowed, retry_after = limiter.is_allowed("denied_key", max_requests=5, window_seconds=60)
            assert allowed is False
            assert retry_after == 60
        finally:
            if old is not None:
                os.environ["TESTING"] = old
            else:
                os.environ["TESTING"] = "1"

    def test_open_mode_allows_requests_in_memory(self):
        """fail_mode=open with no Redis falls through to in-memory; should allow requests."""
        limiter = self._make_limiter("open")
        allowed, _ = limiter.is_allowed("open_key", max_requests=5, window_seconds=60)
        assert allowed is True

    def test_reset_clears_in_memory_state(self):
        limiter = self._make_limiter("fallback")
        for _ in range(5):
            limiter.is_allowed("reset_key", max_requests=5, window_seconds=60)
        limiter.reset()
        allowed, _ = limiter.is_allowed("reset_key", max_requests=5, window_seconds=60)
        assert allowed is True


# ─────────────────────────────────────────────────────────────────────────────
# SEC-003 / CODE-001 — Evidence size guard must be executable code
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidenceSizeGuard:
    """The size guard in EvidenceStore.record_evidence must execute (not be in a docstring)."""

    def _make_store(self):
        from core.evidence.store import EvidenceStore
        return EvidenceStore(tenant_id="test-tenant")

    def test_size_guard_is_not_in_docstring(self):
        """
        Inspect the source of record_evidence to confirm the size check is executable.
        If the guard is inside the docstring the source will contain it as a string literal;
        if it's executable it will appear after the closing triple-quote.
        """
        import inspect
        from core.evidence.store import EvidenceStore
        source = inspect.getsource(EvidenceStore.record_evidence)

        # The docstring must be closed before the guard code appears
        # Split on first closing triple-quote after method def
        lines = source.splitlines()
        in_docstring = False
        docstring_closed = False
        size_guard_line = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not in_docstring and stripped.startswith('"""'):
                in_docstring = True
                # Single-line docstring?
                if stripped.count('"""') >= 2 and len(stripped) > 3:
                    in_docstring = False
                    docstring_closed = True
                continue
            if in_docstring:
                if '"""' in stripped:
                    in_docstring = False
                    docstring_closed = True
                continue
            if docstring_closed and "MAX_EVIDENCE_SIZE_BYTES" in line:
                size_guard_line = i
                break

        assert size_guard_line is not None, (
            "SEC-003/CODE-001: MAX_EVIDENCE_SIZE_BYTES guard not found in executable section of "
            "record_evidence(). The docstring fix may not have been applied."
        )

    def test_size_guard_raises_on_oversized_payload(self, monkeypatch):
        """
        record_evidence must raise ValueError when payload exceeds the configured limit.
        Uses monkeypatching to avoid real DB operations.
        """
        from core.evidence import store as evidence_store_module
        from core.evidence.store import EvidenceStore

        # Patch repository functions to avoid DB dependency
        monkeypatch.setattr(evidence_store_module.repository, "log_audit_event", lambda *a, **kw: None)

        ev_store = EvidenceStore(tenant_id="test-tenant")

        # Temporarily lower the limit to 10 bytes for this test
        monkeypatch.setenv("MAX_EVIDENCE_SIZE_BYTES", "10")
        # Force config re-read
        import importlib, config as cfg_module
        importlib.reload(cfg_module)

        oversized_payload = "x" * 20  # 20 bytes > 10 byte limit

        with pytest.raises(ValueError, match="exceeds maximum permitted limit"):
            ev_store.record_evidence(
                raw_payload=oversized_payload,
                source="test_scanner",
            )

        # Restore
        importlib.reload(cfg_module)

    def test_size_guard_allows_payload_at_limit(self, monkeypatch):
        """
        record_evidence must proceed when payload is exactly at the limit.
        Uses monkeypatching to avoid full DB setup.
        """
        from core.evidence import store as evidence_store_module
        from core.evidence.store import EvidenceStore, sanitize_payload, compute_content_hash

        recorded = []

        def fake_get_evidence_by_hash(tenant_id, content_hash):
            return None

        def fake_save_evidence(ev):
            recorded.append(ev)

        monkeypatch.setattr(evidence_store_module.repository, "log_audit_event", lambda *a, **kw: None)
        monkeypatch.setattr(evidence_store_module.repository, "get_evidence_by_hash", fake_get_evidence_by_hash)
        monkeypatch.setattr(evidence_store_module.repository, "save_evidence", fake_save_evidence)

        ev_store = EvidenceStore(tenant_id="test-tenant")

        # Set limit to 100 bytes
        monkeypatch.setenv("MAX_EVIDENCE_SIZE_BYTES", "100")
        import importlib, config as cfg_module
        importlib.reload(cfg_module)

        # Payload at exactly 100 bytes should not raise
        payload_100 = "a" * 100
        # record_evidence should not raise
        try:
            ev_store.record_evidence(raw_payload=payload_100, source="test_scanner")
        except ValueError:
            pytest.fail("record_evidence raised ValueError for payload at the size limit.")
        finally:
            importlib.reload(cfg_module)


# ─────────────────────────────────────────────────────────────────────────────
# SEC-004 — CEF extension escaping
# ─────────────────────────────────────────────────────────────────────────────

class TestCEFEscaping:
    """format_cef_event must produce spec-compliant CEF output."""

    def _format(self, event_type, severity, extension_data, **kwargs):
        from core.integrations.siem import format_cef_event
        return format_cef_event(event_type, severity, extension_data, **kwargs)

    def test_clean_values_produce_valid_cef(self):
        result = self._format("FindingDetected", "high", {"msg": "clean message", "src": "1.2.3.4"})
        assert result.startswith("CEF:0|")
        assert "FindingDetected" in result
        assert "msg=clean message" in result

    def test_equals_sign_in_value_is_escaped(self):
        result = self._format("Test", "info", {"query": "key=value"})
        assert "query=key\\=value" in result, f"Equals not escaped in: {result}"

    def test_newline_in_value_is_escaped(self):
        result = self._format("Test", "info", {"desc": "line1\nline2"})
        assert "\n" not in result, "Literal newline found in CEF output — log injection risk"
        assert "\\n" in result

    def test_carriage_return_in_value_is_escaped(self):
        result = self._format("Test", "info", {"desc": "line1\r\nline2"})
        assert "\r" not in result
        assert "\n" not in result

    def test_backslash_in_value_is_double_escaped(self):
        result = self._format("Test", "info", {"path": "C:\\Users\\test"})
        assert "C:\\\\Users\\\\test" in result, f"Backslash not double-escaped in: {result}"

    def test_pipe_in_header_is_escaped(self):
        result = self._format("Type|Injection", "info", {})
        # The event_type appears in header positions 4 and 5
        header_part = result.split("|")[4] if result.count("|") >= 5 else ""
        assert "\\|" in header_part or "Injection" not in result.split("|")[4], (
            f"Pipe in header not escaped: {result}"
        )

    def test_severity_mapping_critical(self):
        result = self._format("Event", "critical", {})
        assert "|10|" in result

    def test_severity_mapping_high(self):
        result = self._format("Event", "high", {})
        assert "|7|" in result

    def test_severity_mapping_unknown_defaults_to_1(self):
        result = self._format("Event", "unknown_sev", {})
        assert "|1|" in result

    def test_none_values_omitted_from_extension(self):
        result = self._format("Event", "info", {"present": "yes", "absent": None})
        assert "present=yes" in result
        assert "absent" not in result

    def test_helper_cef_escape_extension_coverage(self):
        from core.integrations.siem import _cef_escape_extension
        assert _cef_escape_extension("key=val") == "key\\=val"
        assert _cef_escape_extension("a\\b") == "a\\\\b"
        assert _cef_escape_extension("a\nb") == "a\\nb"
        assert _cef_escape_extension("a\r\nb") == "a\\nb"
        assert _cef_escape_extension("clean") == "clean"

    def test_helper_cef_escape_header_coverage(self):
        from core.integrations.siem import _cef_escape_header
        assert _cef_escape_header("pipe|char") == "pipe\\|char"
        assert _cef_escape_header("back\\slash") == "back\\\\slash"
        assert _cef_escape_header("clean") == "clean"


# ─────────────────────────────────────────────────────────────────────────────
# SEC-005 — Audit log purge is opt-in
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditLogPurgePolicy:
    """purge_expired_records_task must NOT delete audit_events unless explicitly enabled."""

    def test_purge_task_does_not_delete_audit_events_by_default(self, monkeypatch):
        """
        When AUDIT_LOG_PURGE_ENABLED is not set (default), no DELETE should execute
        on the audit_events table.
        """
        monkeypatch.delenv("AUDIT_LOG_PURGE_ENABLED", raising=False)
        monkeypatch.delenv("AUDIT_LOG_PURGE_RETENTION_DAYS", raising=False)

        deleted_tables = []

        class MockConn:
            def execute(self, sql, params=()):
                sql_upper = sql.strip().upper()
                if sql_upper.startswith("DELETE") and "AUDIT_EVENTS" in sql_upper:
                    deleted_tables.append("audit_events")
                return MockCursor()

        class MockCursor:
            def fetchall(self):
                return []

        from core.tasks import maintenance_tasks as mt
        import importlib
        from config import SCAN_JOB_RETENTION_DAYS

        monkeypatch.setattr(mt, "find_stale_scan_jobs", lambda **kw: [])  # not used here

        # Patch internal imports used inside the task
        import unittest.mock as mock
        with mock.patch("core.repository._get_conn", return_value=MockConn()), \
             mock.patch("core.repository._safe_commit", return_value=None):
            result = mt.purge_expired_records_task()

        assert "audit_events" not in deleted_tables, (
            "SEC-005: audit_events were deleted even though AUDIT_LOG_PURGE_ENABLED was not set"
        )
        assert result["audit_purge_enabled"] is False
        assert result["audit_purged"] == 0

    def test_purge_task_respects_opt_in_flag(self, monkeypatch):
        """When AUDIT_LOG_PURGE_ENABLED=true is set, the task is permitted to delete."""
        monkeypatch.setenv("AUDIT_LOG_PURGE_ENABLED", "true")
        monkeypatch.setenv("AUDIT_LOG_PURGE_RETENTION_DAYS", "730")

        from core.tasks.maintenance_tasks import purge_expired_records_task
        import unittest.mock as mock

        class MockCursor:
            def fetchall(self):
                return []  # Nothing to purge

        with mock.patch("core.repository._get_conn") as mock_conn, \
             mock.patch("core.repository._safe_commit"):
            mock_conn.return_value.execute.return_value = MockCursor()
            result = purge_expired_records_task()

        # When enabled but nothing to purge, audit_purge_enabled should be True
        assert result["audit_purge_enabled"] is True

    def test_purge_task_rejects_invalid_retention_days(self, monkeypatch):
        """AUDIT_LOG_PURGE_RETENTION_DAYS set to non-integer must not cause purge."""
        monkeypatch.setenv("AUDIT_LOG_PURGE_ENABLED", "true")
        monkeypatch.setenv("AUDIT_LOG_PURGE_RETENTION_DAYS", "notanumber")

        deleted_audit = []

        import unittest.mock as mock
        from core.tasks.maintenance_tasks import purge_expired_records_task

        class MockCursor:
            def fetchall(self):
                return []

        class MockConn:
            def execute(self, sql, params=()):
                if "audit_events" in sql.lower() and sql.strip().upper().startswith("DELETE"):
                    deleted_audit.append(sql)
                return MockCursor()

        with mock.patch("core.repository._get_conn", return_value=MockConn()), \
             mock.patch("core.repository._safe_commit"):
            result = purge_expired_records_task()

        assert len(deleted_audit) == 0, "Audit events should not be deleted with invalid retention days"


# ─────────────────────────────────────────────────────────────────────────────
# CODE-003 — Concurrency gate boundary condition
# ─────────────────────────────────────────────────────────────────────────────

class TestConcurrencyGateBoundary:
    """
    The concurrency gate uses >= (MAX + 1) to account for the current job being
    counted in the active queue. Verify the source contains >= not >.
    """

    def test_concurrency_gate_uses_gte_not_gt(self):
        """
        Inspect scan_tasks source to ensure boundary is >= not >.
        This is a static source check that will catch the off-by-one regression.
        """
        import inspect
        from core.tasks import scan_tasks
        source = inspect.getsource(scan_tasks.run_scan_task)

        # The original bug used `> MAX_CONCURRENT_SCANS_PER_ASSET + 1`
        # The fix uses `>= MAX_CONCURRENT_SCANS_PER_ASSET + 1`
        assert "> MAX_CONCURRENT_SCANS_PER_ASSET + 1" not in source or \
               ">= MAX_CONCURRENT_SCANS_PER_ASSET + 1" in source, (
            "CODE-003: asset concurrency gate still uses '>' instead of '>=' — off-by-one not fixed"
        )
        assert ">= MAX_CONCURRENT_SCANS_PER_ASSET + 1" in source, (
            "CODE-003: asset concurrency gate should use '>=' comparison"
        )
        assert ">= MAX_CONCURRENT_SCANS_PER_TENANT + 1" in source, (
            "CODE-003: tenant concurrency gate should use '>=' comparison"
        )
        assert ">= MAX_CONCURRENT_SCANS_GLOBAL + 1" in source, (
            "CODE-003: global concurrency gate should use '>=' comparison"
        )


# ─────────────────────────────────────────────────────────────────────────────
# DEPLOY-001 — Alembic migration exists and is well-formed
# ─────────────────────────────────────────────────────────────────────────────

class TestAlembicMigration:
    """Migration 005 must exist, chain correctly, and define upgrade/downgrade."""

    def test_migration_file_exists(self):
        migration_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "migrations", "versions", "005_phase7_pilot_readiness_indices.py"
        )
        assert os.path.isfile(migration_path), (
            "DEPLOY-001: migration 005_phase7_pilot_readiness_indices.py not found"
        )

    def test_migration_is_importable(self):
        import importlib.util
        migration_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "migrations", "versions", "005_phase7_pilot_readiness_indices.py"
        )
        spec = importlib.util.spec_from_file_location("migration_005", migration_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "upgrade"), "Migration 005 missing upgrade() function"
        assert hasattr(mod, "downgrade"), "Migration 005 missing downgrade() function"
        assert callable(mod.upgrade)
        assert callable(mod.downgrade)

    def test_migration_revision_chain(self):
        import importlib.util
        migration_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "migrations", "versions", "005_phase7_pilot_readiness_indices.py"
        )
        spec = importlib.util.spec_from_file_location("migration_005", migration_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.revision == "005_phase7_pilot_readiness_indices"
        assert mod.down_revision == "004_product_maturity_easm", (
            f"Migration 005 down_revision should be '004_product_maturity_easm', got {mod.down_revision!r}"
        )
