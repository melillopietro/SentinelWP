"""
WordPress core security posture checks (non-exploitative).

Adds contextual signals for recent critical core issues such as CVE-2026-87902.
The curated intelligence pipeline emits the primary CVE finding; this scanner
reports theme preconditions cited in public advisories.
"""
import re
from typing import List, Set

from core.models import Severity
from core.wordpress_version import is_version_less_than, normalize_wp_version_label
from scanners.base import BaseScanner

_ELEVATED_RCE_THEME_SLUGS = frozenset(
    {
        "twentytwelve",
        "twentyfourteen",
        "neve",
        "hestia",
        "sydney",
    }
)


class CoreSecurityScanner(BaseScanner):
    def scan(self) -> list:
        resp = self._get(self.target_url)
        if not resp:
            return self.findings

        body = resp.text or ""
        wp_version = self._extract_version(body)
        if not wp_version or not is_version_less_than(wp_version, "7.1.2"):
            return self.findings

        themes = self._detect_theme_slugs(body)
        risky = sorted(themes & _ELEVATED_RCE_THEME_SLUGS)
        if not risky:
            return self.findings

        self._add_finding(
            category="configuration",
            title="CVE-2026-87902: Elevated-risk theme precondition detected",
            description=(
                f"WordPress {wp_version} is below patched 7.1.2. Active theme(s) "
                f"{', '.join(risky)} were cited in public analysis as increasing "
                "exposure to the page template local PHP inclusion issue (CVE-2026-87902)."
            ),
            severity=Severity.HIGH,
            confidence=0.75,
            remediation=(
                "Upgrade to WordPress 7.1.2+ and review theme template handling; "
                "consider restricting untrusted template resolution paths."
            ),
            reference="https://wordpress.org/news/2026/09/wordpress-7-1-2-release/",
            raw_data={
                "cve": "CVE-2026-87902",
                "detected_version": wp_version,
                "themes": risky,
            },
        )
        return self.findings

    @staticmethod
    def _extract_version(body: str) -> str | None:
        meta = re.search(
            r'<meta[^>]+content=["\']WordPress\s*([\d.]+)["\']',
            body,
            re.IGNORECASE,
        )
        if meta:
            return normalize_wp_version_label(meta.group(1))
        return None

    @staticmethod
    def _detect_theme_slugs(body: str) -> Set[str]:
        return set(re.findall(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", body))
