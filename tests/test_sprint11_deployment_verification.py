"""Sprint 11 Deployment Verification and Smoke Testing Suite.

Validates the deployment verification script (scripts/verify_deployment.sh),
testing Compose port isolation checks, CLI flag parsing, response validation,
and fail-closed exit code semantics.
"""

import os
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
VERIFY_SCRIPT = os.path.join(SCRIPTS_DIR, "verify_deployment.sh")
COMPOSE_PROD = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docker-compose.prod.yml"))


class MockGatewayHandler(BaseHTTPRequestHandler):
    """Mock HTTP/HTTPS server for deployment verification tests."""

    def do_HEAD(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
        elif self.path == "/":
            self.send_response(301)
            self.send_header("Location", "https://localhost:443/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "version": "4.1.0", "backend": "celery"}')
        elif self.path == "/ready":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
            self.wfile.write(b'{"ready": true, "checks": {"database": "ok", "redis": "ok"}}')
        elif self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
            self.wfile.write(b"# HELP sentinelwp_requests_total\nsentinelwp_requests_total 42\n")
        elif self.path == "/":
            self.send_response(301)
            self.send_header("Location", "https://localhost:443/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class TestSprint11DeploymentVerification:
    """Test suite for deployment verification tooling."""

    def test_verify_deployment_script_exists_and_executable(self):
        """Verify the script exists and has executable permissions."""
        assert os.path.exists(VERIFY_SCRIPT), "verify_deployment.sh must exist"
        assert os.access(VERIFY_SCRIPT, os.X_OK), "verify_deployment.sh must be executable"

    def test_verify_deployment_help_flag(self):
        """Verify --help flag displays usage and exits with 0."""
        result = subprocess.run(
            ["bash", VERIFY_SCRIPT, "--help"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "Usage:" in result.stdout
        assert "--host" in result.stdout
        assert "--skip-docker" in result.stdout

    def test_compose_definition_port_isolation(self):
        """Verify that verify_deployment.sh checks compose file port isolation."""
        result = subprocess.run(
            [
                "bash", VERIFY_SCRIPT,
                "--compose-file", COMPOSE_PROD,
                "--skip-docker",
                "--skip-port-scan"
            ],
            capture_output=True,
            text=True
        )
        assert "Database service 'db' has zero host ports mapped" in result.stdout
        assert "Redis service 'redis' has zero host ports mapped" in result.stdout
        assert "Web service 'web' has zero host ports mapped" in result.stdout

    def test_mock_gateway_endpoint_verification(self):
        """Test endpoint checks against a live local mock server."""
        server = HTTPServer(("127.0.0.1", 0), MockGatewayHandler)
        port = server.server_port
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            result = subprocess.run(
                [
                    "bash", VERIFY_SCRIPT,
                    "--compose-file", COMPOSE_PROD,
                    "--host", "127.0.0.1",
                    "--http-port", str(port),
                    "--https-port", str(port),
                    "--skip-docker",
                    "--skip-port-scan",
                    "-k"
                ],
                capture_output=True,
                text=True
            )
            assert "HTTP on port" in result.stdout
            assert "HTTP redirects to HTTPS" in result.stdout
            assert result.returncode == 0
        finally:
            server.shutdown()

    def test_unknown_cli_argument_fails(self):
        """Verify unknown CLI options cause immediate failure."""
        result = subprocess.run(
            ["bash", VERIFY_SCRIPT, "--invalid-flag-12345"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 1
        assert "Unknown argument" in result.stdout
