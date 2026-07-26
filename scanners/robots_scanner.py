"""
Robots.txt and Sitemap Scanner
- Parses robots.txt for sensitive Disallow paths
- Detects sitemap references
- Identifies potential hidden admin paths
"""
import re
from scanners.base import BaseScanner
from core.models import Severity


SENSITIVE_PATHS = [
    "/wp-admin", "/admin", "/administrator", "/backup",
    "/database", "/db", "/dump", "/config", "/private",
    "/secret", "/hidden", "/staging", "/dev", "/test",
    "/old", "/temp", "/tmp", "/log", "/logs",
    "/cgi-bin", "/includes", "/sql", "/phpmyadmin",
]


class RobotsScanner(BaseScanner):
    def scan(self) -> list:
        self._check_robots_txt()
        self._check_sitemap()
        return self.findings

    def _check_robots_txt(self):
        url = f"{self.target_url}/robots.txt"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            self._add_finding(
                category="configuration",
                title="robots.txt Not Found",
                description="No robots.txt file found. While not a vulnerability, "
                            "it may indicate incomplete server configuration.",
                severity=Severity.INFO,
                confidence=0.6,
                remediation="Create a robots.txt to control crawler behavior.",
            )
            return

        content = resp.text
        disallow_paths = re.findall(r"Disallow:\s*(.+)", content, re.IGNORECASE)
        disallow_paths = [p.strip() for p in disallow_paths if p.strip()]

        # Check for sensitive paths in Disallow
        sensitive_found = []
        for path in disallow_paths:
            path_lower = path.lower()
            for sp in SENSITIVE_PATHS:
                if sp in path_lower:
                    sensitive_found.append(path)
                    break

        if sensitive_found:
            self._add_finding(
                category="information_disclosure",
                title="robots.txt Reveals Sensitive Paths",
                description="robots.txt contains Disallow entries for potentially sensitive paths: "
                            + ", ".join(sensitive_found[:10]),
                severity=Severity.LOW,
                confidence=0.75,
                remediation="Sensitive paths in robots.txt are visible to attackers. "
                            "Use authentication/authorization instead of relying on robots.txt for security.",
                raw_data={"sensitive_paths": sensitive_found, "all_disallow": disallow_paths}
            )

        # Check for Sitemap references
        sitemaps = re.findall(r"Sitemap:\s*(.+)", content, re.IGNORECASE)
        if sitemaps:
            self._add_finding(
                category="information_disclosure",
                title="Sitemap URL Found in robots.txt",
                description="Sitemap(s) referenced: " + ", ".join(s.strip() for s in sitemaps[:5]),
                severity=Severity.INFO,
                confidence=0.9,
                remediation="Review sitemap content to ensure no sensitive URLs are exposed.",
                raw_data={"sitemaps": [s.strip() for s in sitemaps]}
            )

    def _check_sitemap(self):
        """Check common sitemap paths"""
        sitemap_paths = ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]
        for path in sitemap_paths:
            url = f"{self.target_url}{path}"
            resp = self._get(url)
            if resp and resp.status_code == 200 and "xml" in resp.headers.get("content-type", "").lower():
                # Count URLs in sitemap
                url_count = resp.text.count("<loc>")
                self._add_finding(
                    category="information_disclosure",
                    title=f"Sitemap Found: {path}",
                    description=f"XML Sitemap accessible at {path} with approximately {url_count} URL(s).",
                    severity=Severity.INFO,
                    confidence=0.9,
                    remediation="Ensure sitemap does not expose admin or private URLs.",
                    raw_data={"path": path, "url_count": url_count}
                )
                break  # One sitemap finding is enough
