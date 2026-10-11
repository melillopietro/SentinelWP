"""
WordPress Theme Enumeration Scanner
- Passive detection from page source HTML
- Active probing of default WordPress themes
"""
import re
from scanners.base import BaseScanner
from core.models import Severity


# Default WordPress themes to probe actively
DEFAULT_THEMES = [
    "twentytwentyfour",
    "twentytwentythree",
    "twentytwentytwo",
    "twentytwentyone",
    "twentytwenty",
    "twentynineteen",
    "twentyeighteen",
    "twentyseventeen",
    "twentysixteen",
    "twentyfifteen",
    "twentyfourteen",
    "twentythirteen",
    "twentytwelve",
]


class ThemeScanner(BaseScanner):
    # DETECT-GAP-003: active probe is disabled in passive mode.
    # Set to True only when the orchestrator passes scan_mode='safe-active' or 'full'.
    ENABLE_ACTIVE_PROBE: bool = False

    def scan(self) -> list:
        self._detect_active_theme()
        if self.ENABLE_ACTIVE_PROBE:
            self._probe_default_themes()
        return self.findings

    def _detect_active_theme(self):
        """Passive: detect active theme from page HTML source.
        No additional HTTP requests beyond the homepage fetch.
        """
        resp = self._get(self.target_url)
        if not resp:
            return
        # Find all theme references in HTML
        themes_found = set(re.findall(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", resp.text))
        for theme in themes_found:
            version = self._get_theme_version(theme)
            # EVI-GAP-002: expose version_confidence for consistency with plugin findings
            version_confidence = "high" if version else "none"
            desc = f"Active theme detected from page source: {theme}"
            if version:
                desc += f" (version {version}, confidence: {version_confidence})"
            self._add_finding(
                category="information_disclosure",
                title=f"Theme Identified: {theme}",
                description=desc,
                severity=Severity.INFO,
                confidence=0.9,
                remediation="Consider hiding theme paths with a security plugin.",
                raw_data={
                    "theme": theme,
                    "version": version,
                    "version_confidence": version_confidence,
                    "method": "passive",
                }
            )

    def _probe_default_themes(self):
        """Active: probe default WP themes via style.css.

        DETECT-OPEN-003: emits one finding per confirmed default theme with
        its own raw_data carrying slug, version, and confidence.  This enables
        per-theme CVE correlation downstream (e.g. a specific version of
        twentytwentytwo may have a known vulnerability).
        """
        import datetime as _dt
        now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()
        for theme in DEFAULT_THEMES:
            url = f"{self.target_url}/wp-content/themes/{theme}/style.css"
            resp = self._head(url)
            if not (resp and resp.status_code == 200):
                continue

            # Fetch version — best-effort; no version if GET fails
            version = self._get_theme_version(theme)
            version_confidence = "high" if version else "none"

            # Only populate CVE-matchable raw_data when version is known;
            # do NOT attempt CVE match when version is unknown (DETECT-OPEN-003).
            self._add_finding(
                category="information_disclosure",
                title=f"Default Theme Present: {theme}",
                description=(
                    f"Default WordPress theme '{theme}' detected on server"
                    + (f" (version {version}, confidence: {version_confidence})" if version else "")
                    + ". Unused themes should be removed to reduce attack surface."
                ),
                severity=Severity.LOW,
                confidence=0.85,
                remediation=f"Delete unused default theme '{theme}' from wp-content/themes/ if not in use.",
                raw_data={
                    "theme": theme,
                    "slug": theme,
                    "version": version or None,
                    "version_confidence": version_confidence,
                    "method": "active_probe",
                    "evidence_url": url,
                    "observed_at": now_iso,
                }
            )

    def _get_theme_version(self, theme: str) -> str:
        """Try to extract version from style.css"""
        url = f"{self.target_url}/wp-content/themes/{theme}/style.css"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return ""
        match = re.search(r"Version:\s*([\d.]+)", resp.text, re.IGNORECASE)
        return match.group(1) if match else ""
