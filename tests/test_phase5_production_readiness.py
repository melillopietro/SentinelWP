"""
Test Suite for SentinelWP Phase 5: Enterprise Production Readiness.
Covers OIDC/SSO, Secrets Provider abstraction, Production Configuration Validation,
Sliding-Window Rate Limiting, API Key Rotation, Backup/Restore DR,
Structured JSON Logging, and Tenant Lifecycle Offboarding.
"""
import base64
import json
import logging
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from core.auth.oidc import OIDCClient, OIDCConfig
from core.secrets.provider import (
    EnvSecretProvider, FileSecretProvider, VaultSecretProvider,
    CompositeSecretProvider, get_secret
)
from core.rate_limiter import DistributedRateLimiter
from core.logging_config import JSONFormatter
from core.tenant_lifecycle import soft_delete_tenant, hard_delete_tenant
from core import repository
from core.models import Tenant, Asset, ScanResult, ScanStatus, APIKey, ScheduledScan
from config import validate_production_config


class TestOIDCAuthentication(unittest.TestCase):
    """Verifies Enterprise SSO / OIDC flows, state/nonce protection, role mapping, and tenant routing."""

    def setUp(self):
        self.config = OIDCConfig(
            enabled=True,
            issuer_url="https://sso.enterprise.test",
            client_id="sentinelwp-client-id",
            client_secret="sentinelwp-client-secret",
            redirect_uri="https://sentinelwp.enterprise.test/auth/oidc/callback",
            scopes=["openid", "profile", "email", "groups"],
            roles_claim="groups",
            tenant_claim="tenant_id",
            default_role="viewer"
        )
        self.client = OIDCClient(self.config)

    def test_authorization_url_generation_with_security_params(self):
        url, state, nonce = self.client.get_authorization_url()
        self.assertTrue(url.startswith("https://sso.enterprise.test/protocol/openid-connect/auth"))
        self.assertIn("response_type=code", url)
        self.assertIn(f"client_id={self.config.client_id}", url)
        self.assertIn(f"state={state}", url)
        self.assertIn(f"nonce={nonce}", url)
        self.assertTrue(len(state) >= 16)
        self.assertTrue(len(nonce) >= 16)

    def test_state_validation_guards_against_csrf(self):
        self.assertTrue(self.client.validate_state("expected-state", "expected-state"))
        self.assertFalse(self.client.validate_state("expected-state", "tampered-state"))
        self.assertFalse(self.client.validate_state("", "tampered-state"))

    def test_role_mapping_hierarchy(self):
        # Admin mapping
        claims_admin = {"groups": ["marketing", "sentinelwp_admins"]}
        self.assertEqual(self.client.map_role_from_claims(claims_admin), "admin")

        # Analyst mapping
        claims_analyst = {"groups": ["security-engineers"]}
        self.assertEqual(self.client.map_role_from_claims(claims_analyst), "analyst")

        # Highest privilege wins when multiple match
        claims_both = {"groups": ["analysts", "admins"]}
        self.assertEqual(self.client.map_role_from_claims(claims_both), "admin")

        # Fallback to default role
        claims_none = {"groups": ["contractors"]}
        self.assertEqual(self.client.map_role_from_claims(claims_none), "viewer")

    def test_tenant_routing_from_claims(self):
        claims = {"tenant_id": "enterprise-tenant-alpha", "sub": "user-123"}
        self.assertEqual(self.client.extract_tenant_from_claims(claims), "enterprise-tenant-alpha")

        # Fallback when missing
        self.assertEqual(self.client.extract_tenant_from_claims({}), "default-tenant")


class TestSecretsProviderAbstraction(unittest.TestCase):
    """Verifies pluggable secret retrieval with Vault, File, and Env precedence."""

    def test_env_secret_provider(self):
        os.environ["SENTINELWP_TEST_VAR"] = "secret-val-123"
        provider = EnvSecretProvider()
        self.assertEqual(provider.get("SENTINELWP_TEST_VAR"), "secret-val-123")
        self.assertIsNone(provider.get("NON_EXISTENT_VAR"))
        del os.environ["SENTINELWP_TEST_VAR"]

    def test_file_secret_provider(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = os.path.join(tmpdir, "db_password")
            with open(secret_file, "w") as f:
                f.write("super-vault-file-secret\n")

            provider = FileSecretProvider(base_path=tmpdir)
            self.assertEqual(provider.get("db_password"), "super-vault-file-secret")
            self.assertIsNone(provider.get("unknown_secret"))

    def test_composite_provider_precedence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "API_KEY"), "w") as f:
                f.write("file-secret")

            os.environ["API_KEY"] = "env-secret"

            # Precedence: File first, then Env
            file_first = CompositeSecretProvider([FileSecretProvider(tmpdir), EnvSecretProvider()])
            self.assertEqual(file_first.get("API_KEY"), "file-secret")

            # Precedence: Env first, then File
            env_first = CompositeSecretProvider([EnvSecretProvider(), FileSecretProvider(tmpdir)])
            self.assertEqual(env_first.get("API_KEY"), "env-secret")

            del os.environ["API_KEY"]


class TestProductionConfigValidation(unittest.TestCase):
    """Verifies fail-fast configuration checks for production deployments."""

    def test_passes_in_development(self):
        with patch.dict(os.environ, {"ENVIRONMENT": "development", "SECRET_KEY": "dev"}):
            self.assertTrue(validate_production_config(enforce=False))

    def test_fails_in_production_with_insecure_defaults(self):
        env_vars = {
            "ENVIRONMENT": "production",
            "SECRET_KEY": "change-me-in-production-use-a-strong-random-key",
            "DATABASE_URL": "sqlite:///data/sentinelwp.db",
            "SCAN_EXECUTION_BACKEND": "local",
        }
        with patch.dict(os.environ, env_vars):
            with self.assertRaises(ValueError) as ctx:
                validate_production_config(enforce=True)
            self.assertIn("Production configuration validation failed", str(ctx.exception))


class TestDistributedRateLimiter(unittest.TestCase):
    """Verifies sliding window rate limiting."""

    def test_in_memory_sliding_window_limiting(self):
        limiter = DistributedRateLimiter(redis_client=False)
        key = "test-rate-limit-client"

        # 3 requests allowed in 60s
        self.assertTrue(limiter.check_rate_limit(key, max_requests=3, window_seconds=60))
        self.assertTrue(limiter.check_rate_limit(key, max_requests=3, window_seconds=60))
        self.assertTrue(limiter.check_rate_limit(key, max_requests=3, window_seconds=60))

        # 4th request must be rejected
        self.assertFalse(limiter.check_rate_limit(key, max_requests=3, window_seconds=60))


class TestAPIKeyRotation(unittest.TestCase):
    """Verifies zero-downtime API key rotation and grace period handling."""

    def setUp(self):
        repository.init_db()
        self.tenant_id = "test-rot-tenant"
        self.tenant = Tenant(id=self.tenant_id, name="Rotation Test Tenant", slug="rot-tenant")
        repository.save_tenant(self.tenant)

        self.key = APIKey(
            id="key-old-123",
            tenant_id=self.tenant_id,
            name="CI Pipeline Key",
            key_hash="old-hash-abc",
            key_prefix="wsa_old1",
            scopes=["read", "scan"],
            status="active"
        )
        repository.create_api_key(self.key)

    def test_rotate_with_grace_period(self):
        grace_expiry = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        self.key.expires_at = grace_expiry
        repository.update_api_key(self.key)

        retrieved = repository.get_api_key(self.key.id, tenant_id=self.tenant_id)
        self.assertEqual(retrieved.expires_at, grace_expiry)
        self.assertEqual(retrieved.status, "active")

    def test_rotate_immediate_revocation(self):
        repository.revoke_api_key(self.key.id, tenant_id=self.tenant_id)
        retrieved = repository.get_api_key(self.key.id, tenant_id=self.tenant_id)
        self.assertEqual(retrieved.status, "revoked")


class TestStructuredJSONLogging(unittest.TestCase):
    """Verifies structured JSON log formatting and correlation context."""

    def test_json_formatter_structure(self):
        formatter = JSONFormatter(service_name="sentinelwp-test")
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="app.py",
            lineno=42,
            msg="User login successful",
            args=(),
            exc_info=None
        )
        record.request_id = "req-uuid-999"
        record.tenant_id = "tenant-enterprise-1"
        record.user_id = "admin-1"

        output = formatter.format(record)
        log_json = json.loads(output)

        self.assertEqual(log_json["level"], "INFO")
        self.assertEqual(log_json["service"], "sentinelwp-test")
        self.assertEqual(log_json["message"], "User login successful")
        self.assertEqual(log_json["request_id"], "req-uuid-999")
        self.assertEqual(log_json["tenant_id"], "tenant-enterprise-1")
        self.assertEqual(log_json["user_id"], "admin-1")
        self.assertIn("timestamp", log_json)


class TestBackupAndDisasterRecovery(unittest.TestCase):
    """Verifies database backup and restore scripts with SHA-256 integrity."""

    def test_backup_and_checksum_verification(self):
        from pathlib import Path
        from scripts.backup_db import run_backup, compute_sha256
        from scripts.restore_db import verify_backup_integrity

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_path = run_backup(output_dir=tmpdir)
            self.assertTrue(backup_path.exists())
            self.assertTrue(Path(f"{backup_path}.manifest.json").exists())
            self.assertTrue(Path(f"{backup_path}.sha256").exists())

            # Verification succeeds
            self.assertTrue(verify_backup_integrity(backup_path))

            # Tampered file fails verification
            with open(backup_path, "ab") as f:
                f.write(b"corrupted-data")

            with self.assertRaises(ValueError):
                verify_backup_integrity(backup_path)


class TestTenantLifecycleManagement(unittest.TestCase):
    """Verifies soft-offboarding and hard-purging of tenants with cascading cleanup."""

    def setUp(self):
        import uuid
        repository.init_db()
        self.tenant_id = f"offboard-tenant-{uuid.uuid4().hex[:12]}"
        self.tenant = Tenant(id=self.tenant_id, name="Offboard Target", slug=f"slug-{self.tenant_id}")
        repository.save_tenant(self.tenant)

        # Create child assets, keys, schedules
        self.asset = Asset(
            tenant_id=self.tenant_id,
            canonical_url=f"https://{self.tenant_id}.example.com",
            hostname=f"{self.tenant_id}.example.com",
            status="active"
        )
        repository.save_asset(self.asset)

        self.key = APIKey(
            id=f"key-{self.tenant_id}",
            tenant_id=self.tenant_id,
            name="Tenant Key",
            key_hash=f"hash-{uuid.uuid4().hex}",
            key_prefix="wsa_test",
            status="active"
        )
        repository.create_api_key(self.key)

        self.schedule = ScheduledScan(
            id=f"sched-{self.tenant_id}",
            tenant_id=self.tenant_id,
            target_url=f"https://{self.tenant_id}.example.com",
            enabled=True
        )
        repository.save_scheduled_scan(self.schedule)

    def test_soft_delete_tenant(self):
        result = soft_delete_tenant(self.tenant_id, actor_id="admin-user", reason="Contract terminated")
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(result["revoked_api_keys"], 1)
        self.assertEqual(result["disabled_schedules"], 1)

        # Check tenant status
        t = repository.get_tenant_by_id(self.tenant_id)
        self.assertEqual(t.status, "disabled")

        # Check key revoked
        k = repository.get_api_key(self.key.id, tenant_id=self.tenant_id)
        self.assertEqual(k.status, "revoked")

    def test_hard_delete_tenant_requires_exact_confirmation(self):
        with self.assertRaises(ValueError):
            hard_delete_tenant(self.tenant_id, actor_id="admin-user", confirmation="wrong-id")

    def test_hard_delete_tenant_purges_data(self):
        result = hard_delete_tenant(self.tenant_id, actor_id="admin-user", confirmation=self.tenant_id)
        self.assertEqual(result["status"], "deleted")

        # Tenant record must no longer exist
        t = repository.get_tenant_by_id(self.tenant_id)
        self.assertIsNone(t)

    def test_cannot_delete_default_tenant(self):
        with self.assertRaises(ValueError):
            soft_delete_tenant("default-tenant", actor_id="admin")
        with self.assertRaises(ValueError):
            hard_delete_tenant("default-tenant", actor_id="admin", confirmation="default-tenant")
