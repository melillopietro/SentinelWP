"""
TLS/SSL Scanner - certificate and protocol validation
"""
import ssl
import socket
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse
from scanners.base import BaseScanner
from core.models import Severity


class TLSScanner(BaseScanner):
    def scan(self) -> list:
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            # Check if HTTPS is available
            self._add_finding(
                category="encryption",
                title="Site Not Using HTTPS",
                description=f"The target URL uses HTTP instead of HTTPS. All traffic is unencrypted.",
                severity=Severity.CRITICAL,
                confidence=0.95,
                remediation="Configure TLS/SSL certificate and redirect all HTTP traffic to HTTPS.",
            )
            # Try HTTPS anyway
            port = 443

        self._check_certificate(hostname, port)
        self._check_protocols(hostname, port)
        return self.findings

    def _check_certificate(self, hostname: str, port: int):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Check expiry
                        not_after = cert.get("notAfter")
                        if not_after:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            days_left = (expiry - datetime.now(timezone.utc)).days
                            if days_left < 0:
                                self._add_finding(
                                    category="encryption",
                                    title="SSL Certificate Expired",
                                    description=f"Certificate expired {abs(days_left)} days ago ({not_after}).",
                                    severity=Severity.CRITICAL,
                                    confidence=0.99,
                                    remediation="Renew the SSL/TLS certificate immediately.",
                                    raw_data={"expiry": not_after, "days_left": days_left}
                                )
                            elif days_left < 30:
                                self._add_finding(
                                    category="encryption",
                                    title="SSL Certificate Expiring Soon",
                                    description=f"Certificate expires in {days_left} days ({not_after}).",
                                    severity=Severity.MEDIUM,
                                    confidence=0.9,
                                    remediation="Renew the certificate before expiration.",
                                    raw_data={"expiry": not_after, "days_left": days_left}
                                )
        except ssl.SSLCertVerificationError as e:
            self._add_finding(
                category="encryption",
                title="SSL Certificate Verification Failed",
                description=f"Certificate verification error: {str(e)[:200]}",
                severity=Severity.HIGH,
                confidence=0.9,
                remediation="Fix the certificate chain, ensure it is signed by a trusted CA.",
            )
        except (socket.timeout, socket.error, OSError):
            pass

    def _check_protocols(self, hostname: str, port: int):
        """Check for deprecated TLS versions.

        SCAN-GAP-004: The deprecated ssl.PROTOCOL_TLSv1 / ssl.PROTOCOL_TLSv1_1 constants
        are replaced with ssl.TLSVersion-based minimum/maximum version constraints where
        available (Python 3.7+). This eliminates deprecation warnings on Python 3.14.

        Approach: create an SSLContext that explicitly constrains the negotiated TLS version
        to the target legacy version. If the handshake succeeds, the server supports that
        deprecated protocol and a finding is emitted.
        """
        deprecated_versions = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
        ]

        for name, tls_version in deprecated_versions:
            if tls_version is None:
                # TLSVersion enum value not available on this Python build (already removed).
                # Attempt legacy PROTOCOL_* fallback for older Python versions.
                legacy_proto = getattr(ssl, f"PROTOCOL_{name.replace('.', 'v').replace('v1v', 'v1_')}", None)
                if legacy_proto is None:
                    continue
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        ctx = ssl.SSLContext(legacy_proto)  # type: ignore[arg-type]
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock) as _:
                            self._emit_deprecated_protocol_finding(name)
                except (ssl.SSLError, socket.error, OSError):
                    pass
                continue

            # Modern path: use TLSVersion min/max constraints (no deprecation warnings)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx.minimum_version = tls_version
                    ctx.maximum_version = tls_version
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as _:
                        self._emit_deprecated_protocol_finding(name)
            except (ssl.SSLError, socket.error, OSError):
                pass

    def _emit_deprecated_protocol_finding(self, protocol_name: str):
        """Emit a finding for a confirmed deprecated TLS protocol."""
        self._add_finding(
            category="encryption",
            title=f"Deprecated Protocol Supported: {protocol_name}",
            description=(
                f"The server accepts connections using {protocol_name}, "
                f"which is deprecated and insecure (RFC 8996)."
            ),
            severity=Severity.HIGH,
            confidence=0.9,
            remediation=f"Disable {protocol_name} in your web server TLS configuration. Only allow TLS 1.2+.",
            reference="https://datatracker.ietf.org/doc/html/rfc8996"
        )
