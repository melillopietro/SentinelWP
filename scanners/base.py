"""
Base scanner class - all scanners inherit from this
Includes hardened SSRF protection, hop-by-hop redirect re-validation,
request helpers, and structured logging.
"""
import os
import re
import socket
import ipaddress
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse, urljoin
import requests

from core.models import Finding
from config import REQUEST_TIMEOUT, USER_AGENT, MAX_HTTP_RESPONSE_BYTES

logger = logging.getLogger("sentinelwp.scanners.base")

# ---------------------------------------------------------------------------
# SSRF Protection: block private/reserved IPs, local hostnames, and metadata
# ---------------------------------------------------------------------------
_BLOCKED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified (RFC 4291)
    ipaddress.ip_network("::1/128"),            # Loopback (RFC 4291)
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6 (RFC 4291)
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation (RFC 6052)
    ipaddress.ip_network("100::/64"),           # Discard prefix (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]

_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "instance-data",
}

_BLOCKED_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".localdomain",
    ".lan",
    ".home.arpa",
)


def _strict_dns_resolution() -> bool:
    try:
        from config import strict_dns_resolution_required
        return strict_dns_resolution_required()
    except Exception:
        return os.getenv("WSA_STRICT_DNS", "false").lower() in ("true", "1", "yes")


ALLOW_PRIVATE_TARGETS = os.getenv("WSA_ALLOW_PRIVATE_TARGETS", "false").lower() in ("true", "1", "yes")


def _check_ip_safety(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Validate a single IP address against all blocked networks and reserved attributes."""
    # Always block cloud metadata link-local
    metadata_v4 = ipaddress.ip_network("169.254.0.0/16")
    if isinstance(ip, ipaddress.IPv4Address) and ip in metadata_v4:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped and ip.ipv4_mapped in metadata_v4:
        return False

    if ALLOW_PRIVATE_TARGETS:
        return True

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    # Also check mapped IPv4 for IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        mapped_v4 = ip.ipv4_mapped
        if (
            mapped_v4.is_private
            or mapped_v4.is_loopback
            or mapped_v4.is_link_local
            or mapped_v4.is_multicast
            or mapped_v4.is_reserved
            or mapped_v4.is_unspecified
        ):
            return False
        for net in _BLOCKED_NETWORKS:
            if mapped_v4 in net:
                return False

    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return False

    return True


def is_safe_target_url(url: str, resolve_dns: bool = True) -> Tuple[bool, str]:
    """
    Validate that a URL is safe against SSRF attacks:
    - Only http/https schemes
    - Not a local/reserved hostname
    - Not a private/reserved/cloud metadata IP address
    - All resolved DNS addresses must be public and safe
    """
    if not url or not url.strip():
        return False, "Target URL is required."

    # Prepend scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http and https schemes are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: no hostname found."

    clean_host = hostname.lower().strip("[]")
    target_netloc = parsed.netloc.lower()

    # Narrowly scoped test target allowlist (for controlled laboratory environments only)
    allowlist_raw = os.getenv("WSA_TEST_TARGET_ALLOWLIST", "")
    env = os.getenv("ENVIRONMENT", os.getenv("WSA_ENV", os.getenv("FLASK_ENV", "development"))).lower()
    is_prod = env in ("production", "prod")

    if is_prod and allowlist_raw:
        logger.warning(
            "WSA_TEST_TARGET_ALLOWLIST is strictly prohibited in production mode; bypass is disabled fail-closed."
        )
        test_allowlist = set()
    else:
        test_allowlist = {x.strip().lower() for x in allowlist_raw.split(",") if x.strip()}

    if test_allowlist and (target_netloc in test_allowlist or clean_host in test_allowlist):
        metadata_v4 = ipaddress.ip_network("169.254.0.0/16")
        # Even with test allowlist, strictly prohibit cloud metadata link-local addresses
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            if (isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in metadata_v4) or \
               (isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped and ip_obj.ipv4_mapped in metadata_v4):
                return False, f"Cloud metadata IP address strictly blocked: {ip_obj}"
        except ValueError:
            # If not an IP literal, verify DNS resolution does not point to metadata (anti-rebinding)
            if resolve_dns:
                try:
                    infos = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    for _, _, _, _, sockaddr in infos:
                        res_ip = ipaddress.ip_address(sockaddr[0])
                        if (isinstance(res_ip, ipaddress.IPv4Address) and res_ip in metadata_v4) or \
                           (isinstance(res_ip, ipaddress.IPv6Address) and res_ip.ipv4_mapped and res_ip.ipv4_mapped in metadata_v4):
                            return False, f"Cloud metadata IP address strictly blocked: {res_ip}"
                except Exception:
                    pass
        if clean_host in ("metadata.google.internal", "instance-data"):
            return False, f"Cloud metadata hostname strictly blocked: {clean_host}"
        return True, ""

    # Hostname pattern checks
    if clean_host in ("metadata.google.internal", "instance-data"):
        return False, f"Cloud metadata hostname blocked: {clean_host}"

    if not ALLOW_PRIVATE_TARGETS:
        if clean_host in _BLOCKED_HOSTNAMES:
            return False, f"Local or metadata hostname blocked: {clean_host}"

        for suffix in _BLOCKED_SUFFIXES:
            if clean_host.endswith(suffix):
                return False, f"Internal domain suffix blocked: {suffix}"

    # Check direct IP literal
    is_ip_literal = False
    try:
        ip = ipaddress.ip_address(clean_host)
        is_ip_literal = True
        if not _check_ip_safety(ip):
            return False, f"Target IP address is private or reserved: {ip}"
        return True, ""
    except ValueError:
        pass  # Not an IP literal, proceed to DNS check

    dns_resolved_safe = False
    if resolve_dns:
        try:
            infos = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not infos:
                if _strict_dns_resolution():
                    return False, f"DNS resolution yielded no address records for: {clean_host}"
            else:
                for family, _, _, _, sockaddr in infos:
                    ip = ipaddress.ip_address(sockaddr[0])
                    if not _check_ip_safety(ip):
                        return False, f"Target hostname resolved to private or reserved IP: {ip}"
                dns_resolved_safe = True
        except socket.gaierror as e:
            if _strict_dns_resolution():
                return False, f"DNS resolution failed for hostname '{clean_host}': {e}"
            logger.debug("DNS resolution unavailable for %s: %s (offline/test environment)", clean_host, e)
        except Exception as e:
            if _strict_dns_resolution():
                return False, f"Target resolution error: {e}"

    if resolve_dns and not is_ip_literal and _strict_dns_resolution() and not dns_resolved_safe:
        return False, f"DNS resolution required but no safe addresses validated for: {clean_host}"

    return True, ""


# Backward-compatible helper
def _is_safe_target(url: str) -> bool:
    safe, _ = is_safe_target_url(url, resolve_dns=True)
    return safe


class BaseScanner(ABC):
    MAX_REDIRECTS = 5

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = os.getenv("WSA_SCANNER_TLS_VERIFY", "false").lower() in ("true", "1", "yes")
        self.findings: list = []
        self.scan_log: list = []

        self._log("Scanner initialized", scanner=self.__class__.__name__)

    def _log(self, message: str, **kwargs):
        """Append a structured log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": kwargs.get("scanner", self.__class__.__name__),
            "target": self.target_url,
            "message": message,
        }
        entry.update(kwargs)
        self.scan_log.append(entry)

    @abstractmethod
    def scan(self) -> list:
        pass

    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Execute an HTTP request with hop-by-hop SSRF validation.
        Manual redirect chain traversal ensures every redirect destination
        is resolved and validated against SSRF blocklists before execution.
        """
        allow_redirects = kwargs.pop("allow_redirects", True)
        timeout = kwargs.pop("timeout", REQUEST_TIMEOUT)
        current_url = url
        redirect_count = 0
        current_method = method.upper()

        while True:
            # SSRF check before every outbound hop
            safe, err_msg = is_safe_target_url(current_url, resolve_dns=True)
            if not safe:
                logger.warning("SSRF check blocked outbound request to %s: %s", current_url, err_msg)
                self._log(f"SSRF blocked outbound request: {err_msg}", target_hop=current_url)
                return None

            try:
                req_kwargs = dict(kwargs)
                req_kwargs["timeout"] = timeout
                req_kwargs["allow_redirects"] = False

                if current_method == "GET":
                    resp = self.session.get(current_url, **req_kwargs)
                elif current_method == "POST":
                    resp = self.session.post(current_url, **req_kwargs)
                elif current_method == "HEAD":
                    resp = self.session.head(current_url, **req_kwargs)
                else:
                    resp = self.session.request(current_method, current_url, **req_kwargs)
            except requests.RequestException as e:
                logger.debug("Request exception for %s: %s", current_url, e)
                return None

            if resp is None:
                return None

            # Response size guardrail (Content-Length pre-check + actual body size)
            try:
                cl_header = resp.headers.get("Content-Length")
                if cl_header is not None and int(cl_header) > MAX_HTTP_RESPONSE_BYTES:
                    logger.warning(
                        "Response Content-Length %s exceeds limit %s for %s",
                        cl_header,
                        MAX_HTTP_RESPONSE_BYTES,
                        current_url,
                    )
                    resp.close()
                    return None
                if len(resp.content or b"") > MAX_HTTP_RESPONSE_BYTES:
                    logger.warning(
                        "Response body exceeds limit %s bytes for %s",
                        MAX_HTTP_RESPONSE_BYTES,
                        current_url,
                    )
                    resp.close()
                    return None
            except (ValueError, TypeError):
                pass

            # Handle redirects manually if allowed
            is_redirect = getattr(resp, "is_redirect", False) or getattr(resp, "status_code", 0) in (301, 302, 303, 307, 308)
            headers = getattr(resp, "headers", {})
            if allow_redirects and is_redirect and headers and "Location" in headers:
                redirect_count += 1
                if redirect_count > self.MAX_REDIRECTS:
                    logger.warning("Maximum redirect limit (%d) exceeded for %s", self.MAX_REDIRECTS, url)
                    return resp

                location = headers["Location"]
                next_url = urljoin(current_url, location)

                # Standard redirect behavior: 301/302/303 converts POST to GET
                if getattr(resp, "status_code", 0) in (301, 302, 303) and current_method == "POST":
                    current_method = "GET"
                    kwargs.pop("data", None)
                    kwargs.pop("json", None)

                current_url = next_url
                continue

            return resp

    def _get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self._safe_request("GET", url, **kwargs)

    def _head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self._safe_request("HEAD", url, **kwargs)

    def _post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self._safe_request("POST", url, **kwargs)

    def _add_finding(self, **kwargs):
        f = Finding(**kwargs)
        self.findings.append(f)
        return f

    # SCAN-GAP-001: soft-404 detection ----------------------------------------

    def is_soft_404(self, probe_url: str, baseline_url: Optional[str] = None) -> bool:
        """
        Determine whether a URL returns a soft-404 (HTTP 200 that is actually an error page).

        Strategy:
          1. If the response has an unexpected Content-Type (not text/html), it is probably real.
          2. Fetch a clearly non-existent sentinel URL to establish the 404 baseline.
          3. Compare the probe response body length and content similarity to the sentinel.
          4. If body length similarity exceeds SOFT_404_SIMILARITY_THRESHOLD, classify as soft-404.

        Returns True if the response is a soft-404, False if the probe URL returns genuine content
        or if the sentinel request itself fails (fail-open to avoid false negatives).

        Only called from active probing paths (safe-active / full modes).
        The sentinel URL is derived from target_url and does not introduce external requests.
        """
        import uuid

        # Fetch the probe URL
        probe_resp = self._get(probe_url)
        if probe_resp is None:
            return False
        if probe_resp.status_code != 200:
            return False

        content_type = probe_resp.headers.get("Content-Type", "")
        # Non-HTML responses (CSS, JS, ZIP) are generally real content — not soft-404
        if "text/html" not in content_type and content_type:
            return False

        probe_body = probe_resp.text or ""
        probe_len = len(probe_body)

        # Build a sentinel URL that no real server should have
        sentinel_path = f"/wp-content/plugins/sentinelwp-does-not-exist-{uuid.uuid4().hex[:8]}/"
        sentinel_url = baseline_url or (self.target_url.rstrip("/") + sentinel_path)
        sentinel_resp = self._get(sentinel_url)

        if sentinel_resp is None or sentinel_resp.status_code != 200:
            # Sentinel returned a real 404 / connection error → soft-404 system not in use
            return False

        sentinel_body = sentinel_resp.text or ""
        sentinel_len = len(sentinel_body)

        # Length similarity check: if both are within ±10% of each other and both non-empty
        if probe_len == 0 and sentinel_len == 0:
            return True  # Both empty → soft-404
        if probe_len == 0 or sentinel_len == 0:
            return False  # One empty, one not → different responses

        ratio = min(probe_len, sentinel_len) / max(probe_len, sentinel_len)
        # Content similarity: check for shared marker phrases from sentinel_body
        similarity_threshold = float(
            __import__("os").getenv("SOFT_404_SIMILARITY_THRESHOLD", "0.85")
        )
        if ratio >= similarity_threshold:
            return True

        # Secondary: check if both responses share >50% of 100-char substrings from sentinel
        # This catches identical template pages with different dynamic content
        if sentinel_len >= 200 and probe_len >= 200:
            sample = sentinel_body[:500]
            # Count shared 50-char windows
            chunks = [sample[i:i+50] for i in range(0, min(len(sample), 450), 50)]
            if chunks:
                matches = sum(1 for c in chunks if len(c) == 50 and c in probe_body)
                if matches / len(chunks) >= 0.8:
                    return True

        return False

    @staticmethod
    def validate_target(url: str) -> Tuple[bool, str]:
        """
        Validate a target URL before scanning.
        Returns (is_valid: bool, error_message: str).
        """
        return is_safe_target_url(url, resolve_dns=True)
