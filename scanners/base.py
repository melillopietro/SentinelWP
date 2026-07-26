"""
Base scanner class - all scanners inherit from this
Includes SSRF protection, request helpers, and structured logging.
"""
import re
import socket
import ipaddress
import requests
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from core.models import Finding
from config import REQUEST_TIMEOUT, USER_AGENT


# ---------------------------------------------------------------------------
# SSRF Protection: block private/reserved IPs and local hostnames
# ---------------------------------------------------------------------------
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def _is_safe_target(url: str) -> bool:
    """
    Validate that a target URL is safe to scan:
    - Only http/https schemes
    - Not a private/reserved IP
    - Not a local hostname
    """
    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Local hostname check
    if hostname.lower() in _LOCAL_HOSTNAMES or hostname.lower().endswith(".local"):
        return False

    # Resolve hostname and check IP
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    return False
    except (socket.gaierror, ValueError):
        # If we can't resolve, allow the request (DNS might fail for valid targets)
        pass

    return True


class BaseScanner(ABC):
    MAX_REDIRECTS = 5

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.session.max_redirects = self.MAX_REDIRECTS
        self.findings: list = []
        self.scan_log: list = []

        # Log scan start
        self._log("Scanner initialized", scanner=self.__class__.__name__)

    def _log(self, message: str, **kwargs):
        """Append a structured log entry."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "scanner": kwargs.get("scanner", self.__class__.__name__),
            "target": self.target_url,
            "message": message,
        }
        entry.update(kwargs)
        self.scan_log.append(entry)

    @abstractmethod
    def scan(self) -> list:
        pass

    def _get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault("timeout", REQUEST_TIMEOUT)
            kwargs.setdefault("allow_redirects", True)
            resp = self.session.get(url, **kwargs)
            return resp
        except requests.RequestException:
            return None

    def _head(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault("timeout", REQUEST_TIMEOUT)
            resp = self.session.head(url, **kwargs)
            return resp
        except requests.RequestException:
            return None

    def _post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """POST request helper with timeout defaults."""
        try:
            kwargs.setdefault("timeout", REQUEST_TIMEOUT)
            kwargs.setdefault("allow_redirects", True)
            resp = self.session.post(url, **kwargs)
            return resp
        except requests.RequestException:
            return None

    def _add_finding(self, **kwargs):
        f = Finding(**kwargs)
        self.findings.append(f)
        return f

    @staticmethod
    def validate_target(url: str) -> tuple:
        """
        Validate a target URL before scanning.
        Returns (is_valid: bool, error_message: str).
        """
        if not url or not url.strip():
            return False, "Target URL is required."

        # Ensure scheme
        if not url.startswith("http"):
            url = "https://" + url

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False, "Only http and https schemes are allowed."

        if not parsed.hostname:
            return False, "Invalid URL: no hostname found."

        if not _is_safe_target(url):
            return False, "Target resolves to a private/local address. Scanning blocked (SSRF protection)."

        return True, ""
