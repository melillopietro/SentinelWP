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
    def scan(self) -> list:
        self._detect_active_theme()
        self._probe_default_themes()
        return self.findings

    def _detect_active_theme(self):
        """Passive: detect active theme from page HTML source"""
        resp = self._get(self.target_url)
        if not resp:
            return
        # Find all theme references in HTML
        themes_found = set(re.findall(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", resp.text))
        for theme in themes_found:
            version = self._get_theme_version(theme)
            desc = f"Active theme detected from page source: {theme}"
            if version:
                desc += f" (version {version})"
            self._add_finding(
                category="information_disclosure",
                title=f"Theme Identified: {theme}",
                description=desc,
                severity=Severity.INFO,
                confidence=0.9,
                remediation="Consider hiding theme paths with a security plugin.",
                raw_data={"theme": theme, "version": version, "method": "passive"}
            )

    def _probe_default_themes(self):
        """Active: probe default WP themes via style.css"""
        found = []
        for theme in DEFAULT_THEMES:
            url = f"{self.target_url}/wp-content/themes/{theme}/style.css"
            resp = self._head(url)
            if resp and resp.status_code == 200:
                found.append(theme)
        if found:
            self._add_finding(
                category="information_disclosure",
                title=f"Default Themes Present: {len(found)}",
                description="Default WordPress themes found on server: " + ", ".join(found) + ". "
                            "Unused themes should be removed to reduce attack surface.",
                severity=Severity.LOW,
                confidence=0.85,
                remediation="Delete unused default themes from wp-content/themes/.",
                raw_data={"default_themes": found}
            )

    def _get_theme_version(self, theme: str) -> str:
        """Try to extract version from style.css"""
        url = f"{self.target_url}/wp-content/themes/{theme}/style.css"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return ""
        match = re.search(r"Version:\s*([\d.]+)", resp.text, re.IGNORECASE)
        return match.group(1) if match else ""
