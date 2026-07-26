"""
XML-RPC Method Enumeration and Brute-Force Detection Scanner
- Enumerates available XML-RPC methods via system.listMethods
- Checks for multicall availability (brute-force amplification)
- Tests pingback for DDoS potential
"""
from scanners.base import BaseScanner
from core.models import Severity


DANGEROUS_METHODS = [
    "system.multicall",
    "wp.getUsersBlogs",
    "wp.getUsers",
    "pingback.ping",
    "pingback.extensions.getPingbacks",
]


class XMLRPCScanner(BaseScanner):
    def scan(self) -> list:
        self._enumerate_methods()
        return self.findings

    def _enumerate_methods(self):
        url = f"{self.target_url}/xmlrpc.php"
        # system.listMethods request
        payload = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
        try:
            resp = self._post(url, data=payload,
                              headers={"Content-Type": "text/xml"})
        except Exception:
            return

        if not resp or resp.status_code != 200:
            return

        if "<methodResponse>" not in resp.text:
            return

        # Parse methods from response
        import re
        methods = re.findall(r"<string>([^<]+)</string>", resp.text)

        if not methods:
            return

        # Check for dangerous methods
        dangerous_found = [m for m in methods if m in DANGEROUS_METHODS]

        if "system.multicall" in methods:
            self._add_finding(
                category="authentication",
                title="XML-RPC system.multicall Available",
                description="system.multicall is enabled, allowing attackers to attempt "
                            "thousands of password guesses in a single HTTP request. "
                            f"Total methods available: {len(methods)}.",
                severity=Severity.HIGH,
                confidence=0.95,
                remediation="Disable XML-RPC or specifically block system.multicall. "
                            "Use a security plugin to disable multicall or rate-limit attempts.",
                reference="https://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html",
                raw_data={"methods_count": len(methods), "dangerous": dangerous_found}
            )

        if "pingback.ping" in methods:
            self._add_finding(
                category="exposure",
                title="XML-RPC Pingback Available (DDoS Vector)",
                description="pingback.ping method is available. This can be abused "
                            "for DDoS amplification and internal port scanning (SSRF).",
                severity=Severity.MEDIUM,
                confidence=0.9,
                remediation="Disable pingbacks: add_filter('xmlrpc_methods', function($methods) { "
                            "unset($methods['pingback.ping']); return $methods; });",
                reference="https://blog.sucuri.net/2014/03/more-than-162000-wordpress-sites-used-for-distributed-denial-of-service-attack.html",
                raw_data={"method": "pingback.ping"}
            )

        if "wp.getUsersBlogs" in methods or "wp.getUsers" in methods:
            self._add_finding(
                category="enumeration",
                title="XML-RPC User Methods Available",
                description="User-related XML-RPC methods are available (wp.getUsersBlogs, wp.getUsers). "
                            "These can be used for credential testing.",
                severity=Severity.MEDIUM,
                confidence=0.85,
                remediation="Disable XML-RPC or restrict these methods via security plugin.",
                raw_data={"user_methods": [m for m in methods if "user" in m.lower() or "User" in m]}
            )

        # General method enumeration finding
        self._add_finding(
            category="information_disclosure",
            title=f"XML-RPC Methods Enumerated: {len(methods)} methods",
            description=f"system.listMethods returned {len(methods)} available methods.",
            severity=Severity.LOW,
            confidence=0.95,
            remediation="Disable system.listMethods or restrict XML-RPC access entirely.",
            raw_data={"methods": methods[:50], "total": len(methods)}
        )
