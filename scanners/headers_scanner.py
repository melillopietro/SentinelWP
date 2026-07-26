"""
HTTP Security Headers & Configuration Scanner
- Missing security headers (as hardening recommendations, not WP-specific vulns)
- Unwanted information disclosure headers
- HTTPS redirect verification
- PHP error exposure detection
- Server version detail detection
"""
import re
from scanners.base import BaseScanner
from core.models import Severity


EXPECTED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS header missing. Browser may allow HTTP connections, enabling MITM attacks.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP header missing. The site is more vulnerable to XSS and injection attacks.",
        "remediation": "Implement a Content-Security-Policy header appropriate for your site."
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Content-Type-Options header missing. Browser may MIME-sniff responses.",
        "remediation": "Add header: X-Content-Type-Options: nosniff"
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header missing. The site may be vulnerable to clickjacking.",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed internally)."
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header missing. Full URL may be sent as referrer to third parties.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header missing. Browser features are not explicitly restricted.",
        "remediation": "Add a Permissions-Policy header to restrict unnecessary browser features (camera, microphone, geolocation)."
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection header missing (relevant for older browsers).",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block (or 0 if CSP is properly configured)."
    },
}

UNWANTED_HEADERS = {
    "Server": {
        "severity": Severity.LOW,
        "description": "Server header exposes web server software and version.",
        "remediation": "Remove or obfuscate the Server header in your web server configuration."
    },
    "X-Powered-By": {
        "severity": Severity.LOW,
        "description": "X-Powered-By header exposes backend technology.",
        "remediation": "Remove the X-Powered-By header. PHP: expose_php = Off in php.ini."
    },
    "X-AspNet-Version": {
        "severity": Severity.LOW,
        "description": "X-AspNet-Version header exposes ASP.NET version.",
        "remediation": "Remove this header in web.config."
    },
}

# Patterns that indicate PHP errors exposed in page content
_PHP_ERROR_PATTERNS = [
    r"Fatal error:",
    r"Warning:\s+\w+",
    r"Notice:\s+\w+",
    r"Parse error:",
    r"Deprecated:\s+\w+",
    r"Strict Standards:",
    r"<b>Fatal error</b>:",
    r"<b>Warning</b>:",
    r"Stack trace:",
    r"Uncaught exception",
]


class HeadersScanner(BaseScanner):
    def scan(self) -> list:
        resp = self._get(self.target_url)
        if not resp:
            self._add_finding(
                category="headers",
                title="Unable to Retrieve Headers",
                description=f"Could not connect to {self.target_url} to analyze response headers.",
                severity=Severity.INFO,
                confidence=0.5,
            )
            return self.findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers (reported as hardening recommendations)
        for header, info in EXPECTED_HEADERS.items():
            if header.lower() not in headers:
                self._add_finding(
                    category="headers",
                    title=f"Missing Security Header: {header}",
                    description=info["description"]
                                + " (Note: this is a general hardening recommendation, not a WordPress-specific vulnerability.)",
                    severity=info["severity"],
                    confidence=0.9,
                    remediation=info["remediation"],
                    raw_data={"header": header, "present": False}
                )

        # Check unwanted headers
        for header, info in UNWANTED_HEADERS.items():
            if header.lower() in headers:
                value = headers[header.lower()]
                self._add_finding(
                    category="headers",
                    title=f"Information Disclosure Header: {header}",
                    description=f"{info['description']} Value: {value}",
                    severity=info["severity"],
                    confidence=0.85,
                    remediation=info["remediation"],
                    raw_data={"header": header, "value": value}
                )

        # Server banner version detail check
        server_value = headers.get("server", "")
        if server_value and re.search(r'[\d.]+', server_value):
            self._add_finding(
                category="headers",
                title="Server Banner Reveals Version Details",
                description=f"The Server header contains version information: '{server_value}'. "
                            "This assists attackers in identifying exploitable software versions.",
                severity=Severity.MEDIUM,
                confidence=0.9,
                remediation="Configure the web server to suppress version numbers. "
                            "Apache: ServerTokens Prod. Nginx: server_tokens off;",
                raw_data={"server_banner": server_value}
            )

        # HTTPS redirect check
        self._check_https_redirect()

        # PHP error detection in page body
        self._check_php_errors(resp.text)

        return self.findings

    def _check_https_redirect(self):
        """Check if HTTP requests are properly redirected to HTTPS."""
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        if parsed.scheme == "https":
            # Test the HTTP version
            http_url = self.target_url.replace("https://", "http://", 1)
            resp = self._get(http_url, allow_redirects=False)
            if resp:
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location.startswith("https://"):
                        self._add_finding(
                            category="headers",
                            title="HTTP to HTTPS Redirect Configured",
                            description=f"HTTP requests are properly redirected to HTTPS (HTTP {resp.status_code}).",
                            severity=Severity.INFO,
                            confidence=0.95,
                            remediation="No action needed — redirect is correctly configured.",
                            raw_data={"redirect_status": resp.status_code, "location": location}
                        )
                    else:
                        self._add_finding(
                            category="headers",
                            title="HTTP Redirect Does Not Point to HTTPS",
                            description=f"HTTP redirects to '{location}' which is not HTTPS.",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            remediation="Configure redirect to use HTTPS URL.",
                            raw_data={"redirect_status": resp.status_code, "location": location}
                        )
                elif resp.status_code == 200:
                    self._add_finding(
                        category="headers",
                        title="No HTTP to HTTPS Redirect",
                        description="The site serves content over HTTP without redirecting to HTTPS. "
                                    "Users accessing via HTTP will have unencrypted connections.",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        remediation="Add a redirect rule: Apache: RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]. "
                                    "Nginx: return 301 https://$server_name$request_uri;",
                    )

    def _check_php_errors(self, body: str):
        """Check if the page body contains PHP error messages."""
        errors_found = []
        for pattern in _PHP_ERROR_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                errors_found.extend(matches[:3])  # Limit to 3 matches per pattern

        if errors_found:
            self._add_finding(
                category="headers",
                title="PHP Error Messages Visible in Page Output",
                description=f"The page contains visible PHP error/warning messages ({len(errors_found)} found). "
                            "These may reveal file paths, database details, and application internals. "
                            "Examples: " + ", ".join(errors_found[:5]),
                severity=Severity.MEDIUM,
                confidence=0.85,
                remediation="Set display_errors = Off in php.ini for production. "
                            "Use error_log to log errors to a file instead. "
                            "In wp-config.php: define('WP_DEBUG_DISPLAY', false);",
                raw_data={"error_count": len(errors_found), "sample_patterns": errors_found[:5]}
            )
