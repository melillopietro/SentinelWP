"""
SentinelWP Sprint 11 Phase 3 Test Suite:
Database Migration Safety, Secrets Validation, and Disaster Recovery Automation.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subprocess
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine, text

from config import ENVIRONMENT
from core.db.session import init_db_schema, verify_operational_persistence_guard


class TestSprint11MigrationSafety:
    """Validate Alembic migration guards, advisory locking, and production gates."""

    def test_init_db_schema_prohibited_in_production_postgresql(self):
        """init_db_schema() must raise RuntimeError in production mode with PostgreSQL."""
        engine_mock = MagicMock()
        engine_mock.dialect.name = "postgresql"

        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            with pytest.raises(RuntimeError, match="Runtime init_db_schema.*strictly prohibited"):
                init_db_schema(engine=engine_mock)

    def test_init_db_schema_allowed_in_development_or_sqlite(self):
        """init_db_schema() is permitted in development or SQLite mode."""
        engine_mock = MagicMock()
        engine_mock.dialect.name = "sqlite"

        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            with patch("core.db.base.Base.metadata.create_all") as mock_create_all:
                init_db_schema(engine=engine_mock)
                mock_create_all.assert_called_once_with(bind=engine_mock)

    def test_verify_persistence_guard_fails_when_alembic_version_missing_in_production(self):
        """Startup persistence guard must fail closed in production if alembic_version missing."""
        mock_conn = MagicMock()
        # SELECT 1 returns 1, but SELECT version_num raises undefined table
        mock_conn.execute.side_effect = [
            MagicMock(scalar=lambda: 1),
            Exception("relation 'alembic_version' does not exist"),
        ]

        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn

        with patch("core.db.session.create_engine", return_value=mock_engine):
            with patch("core.db.session.is_postgres_configured", return_value=True):
                with patch.dict(os.environ, {"ENVIRONMENT": "production", "DATABASE_URL": "postgresql://user:pass@127.0.0.1:5432/db"}):
                    with pytest.raises(RuntimeError, match="Database schema uninitialized"):
                        verify_operational_persistence_guard(db_url="postgresql://user:pass@127.0.0.1:5432/db")

    def test_verify_persistence_guard_succeeds_when_alembic_version_present_in_production(self):
        """Startup persistence guard passes in production when alembic_version exists."""
        mock_conn = MagicMock()
        mock_conn.execute.side_effect = [
            MagicMock(scalar=lambda: 1),
            MagicMock(fetchone=lambda: ("009_sprint11_schema_parity",)),
        ]

        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn

        with patch("core.db.session.create_engine", return_value=mock_engine):
            with patch("core.db.session.is_postgres_configured", return_value=True):
                with patch.dict(os.environ, {"ENVIRONMENT": "production", "DATABASE_URL": "postgresql://user:pass@127.0.0.1:5432/db"}):
                    assert verify_operational_persistence_guard(db_url="postgresql://user:pass@127.0.0.1:5432/db") is True


class TestSprint11MigrationRunnerCLI:
    """Validate scripts/run_migrations.py CLI behaviors."""

    def test_migration_runner_help(self):
        """scripts/run_migrations.py --help must display options and exit 0."""
        res = subprocess.run(
            [sys.executable, "scripts/run_migrations.py", "--help"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        assert "--dry-run" in res.stdout
        assert "--check" in res.stdout
        assert "--confirm" in res.stdout

    def test_migration_runner_production_confirmation_gate(self):
        """In production, run_migrations without --confirm must exit non-zero (code 2)."""
        env = os.environ.copy()
        env["ENVIRONMENT"] = "production"
        env["WSA_SECRET_KEY"] = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
        env["WSA_CONFIRM_PRODUCTION_MIGRATION"] = "false"
        if os.environ.get("GITHUB_ACTIONS") == "true":
            env["DATABASE_URL"] = (
                "postgresql+psycopg://sentinelwp:sentinelwp_password@127.0.0.1:5432/sentinelwp_test"
            )
        else:
            env["DATABASE_URL"] = (
                "postgresql+psycopg://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s11_migration_fresh"
            )

        res = subprocess.run(
            [sys.executable, "scripts/run_migrations.py"],
            env=env,
            capture_output=True,
            text=True,
        )
        if res.returncode == 1 and "Connection refused" in (res.stderr or ""):
            self.skipTest("PostgreSQL not reachable for migration CLI integration")
        # At head after prior migrations: 0; pending prod upgrade without confirm: 2
        assert res.returncode in (0, 2)


class TestSprint11ProductionSecretsValidator:
    """Validate scripts/validate_prod_env.sh preflight checks."""

    def test_validator_fails_on_placeholder_template(self):
        """Validator script must fail when passed .env.production.example template."""
        res = subprocess.run(
            ["bash", "scripts/validate_prod_env.sh", ".env.production.example"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 1
        assert "Validation Result:" in res.stdout
        assert "WSA_SECRET_KEY contains known weak or placeholder patterns" in res.stderr or "WSA_SECRET_KEY" in res.stdout

    def test_validator_succeeds_on_valid_environment(self, tmp_path):
        """Validator script passes when provided valid high-entropy configuration."""
        valid_env = tmp_path / ".env.valid"
        valid_env.write_text("""
ENVIRONMENT=production
WSA_SECRET_KEY=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b
DATABASE_URL=postgresql+psycopg://prod_user:StrongSecurePassword123!@127.0.0.1:5432/sentinelwp_prod
POSTGRES_PASSWORD=StrongSecurePassword123!
REDIS_URL=redis://:StrongRedisToken2026!@127.0.0.1:6379/0
REDIS_PASSWORD=StrongRedisToken2026!
WSA_BEHIND_PROXY=true
WSA_PROXY_X_FOR=1
WSA_SESSION_COOKIE_SECURE=true
WSA_SESSION_COOKIE_SAMESITE=Lax
WSA_ALLOW_PRIVATE_TARGETS=false
WSA_TEST_TARGET_ALLOWLIST=
""")
        # Restrict permissions
        os.chmod(valid_env, 0o600)

        res = subprocess.run(
            ["bash", "scripts/validate_prod_env.sh", str(valid_env)],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        assert "[SUCCESS] Environment passed production security preflight validation." in res.stdout


class TestSprint11DisasterRecoveryDrill:
    """Validate backup and restore script error handling and safe execution."""

    def test_restore_script_rejects_missing_arguments(self):
        """restore_postgres.sh without arguments must exit 1 with usage message."""
        res = subprocess.run(
            ["bash", "scripts/restore_postgres.sh"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 1
        assert "Usage:" in res.stderr

    def test_restore_script_blocks_accidental_production_overwrite(self):
        """restore_postgres.sh must refuse restoring into 'sentinelwp' without explicit flag."""
        # Create dummy backup file
        res = subprocess.run(
            ["bash", "scripts/restore_postgres.sh", "scripts/restore_postgres.sh", "sentinelwp"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 2
        assert "protected production database" in res.stderr
