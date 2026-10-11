"""
SentinelWP Sprint 11 Enterprise Packaging & Security Controls Test Suite.
Verifies production container configuration, ProxyFix trusted hop count,
fail-closed SSRF allowlist rejection in production, secret governance,
and Docker Compose security topology.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from config import (
    get_validated_secret_key,
    is_weak_secret,
    validate_admin_password,
    KNOWN_WEAK_SECRETS,
)
from scanners.base import is_safe_target_url


class TestSprint11ProxyFixAndIngress:
    """Validate Werkzeug ProxyFix trusted hop count and header security."""

    def test_proxyfix_single_hop_trusted_client_ip(self):
        """Ensure ProxyFix with x_for=1 extracts only the immediate upstream client IP."""
        test_app = Flask(__name__)
        test_app.config["TESTING"] = True

        @test_app.route("/test-ip")
        def test_ip():
            return {
                "remote_addr": request.remote_addr,
                "is_secure": request.is_secure,
                "scheme": request.scheme,
                "host": request.host,
            }

        # Mount ProxyFix with strictly 1 trusted hop
        test_app.wsgi_app = ProxyFix(test_app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
        client = test_app.test_client()

        # Legitimate client IP passed by Nginx
        resp = client.get(
            "/test-ip",
            headers={
                "X-Forwarded-For": "203.0.113.50",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "sentinel.enterprise.corp",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["remote_addr"] == "203.0.113.50"
        assert data["is_secure"] is True
        assert data["scheme"] == "https"
        assert data["host"] == "sentinel.enterprise.corp"

    def test_proxyfix_rejects_spoofed_multi_hop_forged_headers(self):
        """Ensure spoofed client headers prior to the trusted proxy hop are discarded."""
        test_app = Flask(__name__)
        test_app.config["TESTING"] = True

        @test_app.route("/test-ip")
        def test_ip():
            return {"remote_addr": request.remote_addr}

        # x_for=1 means only 1 hop (the rightmost IP) is trusted
        test_app.wsgi_app = ProxyFix(test_app.wsgi_app, x_for=1)
        client = test_app.test_client()

        # Attacker injects forged IP: "198.51.100.99" (spoofed), "203.0.113.50" (real proxy hop)
        resp = client.get(
            "/test-ip",
            headers={"X-Forwarded-For": "198.51.100.99, 203.0.113.50"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        # Werkzeug ProxyFix with x_for=1 takes the 1st IP from the right
        assert data["remote_addr"] == "203.0.113.50"


class TestSprint11ProductionSSRFEnforcement:
    """Verify fail-closed SSRF allowlist rejection in production."""

    def test_production_rejects_test_target_allowlist_for_private_ips(self):
        """In production, WSA_TEST_TARGET_ALLOWLIST must not bypass private IP blocks."""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "WSA_TEST_TARGET_ALLOWLIST": "127.0.0.1,192.168.1.50,10.0.0.1",
            "WSA_ALLOW_PRIVATE_TARGETS": "false",
        }):
            # Scanning loopback must be rejected fail-closed
            valid, reason = is_safe_target_url("http://127.0.0.1:8080", resolve_dns=False)
            assert valid is False
            assert any(term in reason.lower() for term in ("blocked", "not allowed", "private or reserved"))

            # Scanning RFC1918 private IP must be rejected fail-closed
            valid_priv, reason_priv = is_safe_target_url("http://192.168.1.50:80", resolve_dns=False)
            assert valid_priv is False
            assert any(term in reason_priv.lower() for term in ("blocked", "not allowed", "private or reserved"))

            valid_priv2, reason_priv2 = is_safe_target_url("http://10.0.0.1:80", resolve_dns=False)
            assert valid_priv2 is False
            assert any(term in reason_priv2.lower() for term in ("blocked", "not allowed", "private or reserved"))

    def test_non_production_allows_test_target_allowlist(self):
        """In development/test, test allowlist is permitted for local lab instances."""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "development",
            "WSA_TEST_TARGET_ALLOWLIST": "192.168.1.50",
            "WSA_ALLOW_PRIVATE_TARGETS": "false",
        }):
            valid, reason = is_safe_target_url("http://192.168.1.50", resolve_dns=False)
            assert valid is True
            assert reason == ""


class TestSprint11SecretsAndGovernance:
    """Verify production secrets validation and cookie policy enforcement."""

    def test_weak_secret_detection_patterns(self):
        """Test is_weak_secret catches all placeholder and weak patterns."""
        assert is_weak_secret("") is True
        assert is_weak_secret("short") is True
        assert is_weak_secret("admin123") is True
        assert is_weak_secret("CHANGE-ME-IN-PRODUCTION-USE-RANDOM-32-BYTES") is True
        assert is_weak_secret("REPLACE_WITH_64_CHAR_HEX_SECRET_KEY_FOR_PRODUCTION") is True
        assert is_weak_secret("sentinelwp_dev_password_1234567890123") is True
        assert is_weak_secret("my_insecure_key_that_is_32_characters_long_now") is True

        # Valid 32+ character high-entropy key
        valid_key = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
        assert is_weak_secret(valid_key) is False

    def test_production_refuses_weak_or_placeholder_secret_key(self):
        """get_validated_secret_key must raise ValueError in production for weak keys."""
        with patch.dict(os.environ, {"WSA_SECRET_KEY": ""}):
            with pytest.raises(ValueError, match="Production mode requires a secure WSA_SECRET_KEY"):
                get_validated_secret_key(environment="production")

        with patch.dict(os.environ, {"WSA_SECRET_KEY": "REPLACE_WITH_SECURE_SECRET_KEY_1234567890"}):
            with pytest.raises(ValueError, match="Production mode requires a secure WSA_SECRET_KEY"):
                get_validated_secret_key(environment="production")

    def test_production_accepts_strong_secret_key(self):
        """get_validated_secret_key accepts 32+ char strong random key."""
        strong_key = "d7f6c3a1e9b24850123456789abcdef0123456789abcdef0123456789abcdef0"
        with patch.dict(os.environ, {"WSA_SECRET_KEY": strong_key}):
            validated = get_validated_secret_key(environment="production")
            assert validated == strong_key

    def test_admin_password_policy_enforcement(self):
        """validate_admin_password rejects short and common passwords."""
        valid, _ = validate_admin_password("short")
        assert valid is False

        valid, _ = validate_admin_password("password123456")
        assert valid is False

        valid, _ = validate_admin_password("StrongEnterpriseAdminPassword2026!")
        assert valid is True


class TestSprint11ReadinessEndpointSanitization:
    """Verify /ready endpoint never leaks credentials or sensitive traces on error."""

    def test_ready_endpoint_does_not_leak_database_credentials_on_failure(self):
        """When DB check fails, response returns connection_failed and no raw password."""
        from app import app
        with app.test_client() as client:
            with patch("core.repository.get_tenant_by_id", side_effect=Exception("FATAL: password authentication failed for user sentinelwp:secret_pass_123")):
                with patch("config.is_postgres_configured", return_value=False):
                    resp = client.get("/ready")
                    assert resp.status_code == 503
                    data = resp.get_json()
                    assert data["status"] == "not_ready"
                    assert data["checks"]["database"] == "error: connection_failed"
                    # Ensure secret password is not in payload
                    assert "secret_pass_123" not in resp.get_data(as_text=True)


class TestSprint11TopologyAndComposeIntegrity:
    """Verify docker-compose.prod.yml, Dockerfile.prod, and .dockerignore conformance."""

    def test_compose_prod_contains_eight_services_and_no_database_ports(self):
        """Validate docker-compose.prod.yml structure and network isolation."""
        compose_path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.prod.yml")
        assert os.path.exists(compose_path)

        with open(compose_path, "r") as f:
            content = f.read()

        # Check required services
        required_services = [
            "gateway:", "migrate:", "postgres:", "redis:",
            "web:", "worker-scan:", "worker-intel:", "beat:"
        ]
        for svc in required_services:
            assert svc in content, f"Missing required service {svc} in docker-compose.prod.yml"

        # Check that NO database or redis host ports are published
        # postgres service block
        pg_match = re.search(r"postgres:\s*\n(.*?)(?=\n  [a-z0-9_-]+:|\nnetworks:|\Z)", content, re.DOTALL)
        assert pg_match is not None
        assert "ports:" not in pg_match.group(1), "SECURITY VIOLATION: postgres must not publish host ports!"

        # redis service block
        redis_match = re.search(r"redis:\s*\n(.*?)(?=\n  [a-z0-9_-]+:|\nnetworks:|\Z)", content, re.DOTALL)
        assert redis_match is not None
        assert "ports:" not in redis_match.group(1), "SECURITY VIOLATION: redis must not publish host ports!"

        # web service block
        web_match = re.search(r"web:\s*\n(.*?)(?=\n  [a-z0-9_-]+:|\nnetworks:|\Z)", content, re.DOTALL)
        assert web_match is not None
        assert "ports:" not in web_match.group(1), "SECURITY VIOLATION: web must not publish host ports directly!"

        # Verify ONLY gateway publishes host ports
        gw_match = re.search(r"gateway:\s*\n(.*?)(?=\n  [a-z0-9_-]+:|\nnetworks:|\Z)", content, re.DOTALL)
        assert gw_match is not None
        assert "ports:" in gw_match.group(1), "gateway must publish ingress ports"

    def test_dockerignore_excludes_sensitive_files(self):
        """Validate .dockerignore prevents sensitive files from entering build context."""
        dockerignore_path = os.path.join(os.path.dirname(__file__), "..", ".dockerignore")
        assert os.path.exists(dockerignore_path)

        with open(dockerignore_path, "r") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        assert ".git" in lines
        assert "data/*.db" in lines
        assert ".env*" in lines
        assert "tests" in lines or "tests/" in lines

    def test_requirements_prod_is_fully_pinned(self):
        """Validate requirements-prod.txt contains only strictly pinned packages (==)."""
        req_path = os.path.join(os.path.dirname(__file__), "..", "requirements-prod.txt")
        assert os.path.exists(req_path)

        with open(req_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                assert "==" in line, f"Dependency '{line}' is not strictly pinned with '=='!"
                assert not line.startswith(">="), f"Unpinned dependency '{line}' found in requirements-prod.txt!"
