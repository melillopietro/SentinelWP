"""
WordPress Plugin Enumeration Scanner
- Passive detection: extracts plugin slugs from homepage HTML
- Active probing: checks common plugin directories (safe-active mode only)
- Version detection with confidence rating
"""
import re
from scanners.base import BaseScanner
from core.models import Severity
from scanners.extended_plugins import EXTENDED_PLUGINS


# Additional well-known plugins to merge with extended list
_ACTIVE_PROBE_PLUGINS = list(set(EXTENDED_PLUGINS + [
    "akismet", "jetpack", "wordfence", "yoast-seo", "wordpress-seo",
    "contact-form-7", "woocommerce", "elementor", "classic-editor",
    "all-in-one-seo-pack", "wp-super-cache", "w3-total-cache",
    "really-simple-ssl", "updraftplus", "duplicate-post",
    "wp-mail-smtp", "redirection", "sucuri-scanner",
    "litespeed-cache", "wp-fastest-cache", "autoptimize",
    "google-analytics-for-wordpress", "wp-statistics",
    "better-wp-security", "ithemes-security-pro",
    "all-in-one-wp-migration", "duplicator",
    "wp-file-manager", "revslider", "js_composer",
    "easy-wp-smtp", "loginizer", "limit-login-attempts-reloaded",
]))


class PluginScanner(BaseScanner):
    # Flag to control whether active probing runs (set by orchestrator via scan mode)
    ENABLE_ACTIVE_PROBE = True

    def scan(self) -> list:
        # Always run passive enumeration from HTML
        passive_slugs = self._passive_enumerate()
        # Only run active probing if enabled
        if self.ENABLE_ACTIVE_PROBE:
            self._active_enumerate(exclude=passive_slugs)
        return self.findings

    def _passive_enumerate(self) -> set:
        """Extract plugin slugs from homepage HTML assets (zero extra requests)."""
        resp = self._get(self.target_url)
        if not resp or resp.status_code != 200:
            return set()

        slugs = set(re.findall(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/', resp.text))

        for slug in slugs:
            version = None
            version_confidence = "low"
            source = "page HTML"

            # Try to extract ?ver= from the matched asset URLs
            ver_match = re.search(
                rf'/wp-content/plugins/{re.escape(slug)}/[^"\']*[?&]ver=([\d.]+)',
                resp.text
            )
            if ver_match:
                version = ver_match.group(1)
                version_confidence = "low"
                source = "HTML asset ?ver= parameter"

            # Try readme.txt for higher-confidence version
            readme_ver = self._get_plugin_version_from_readme(slug)
            if readme_ver:
                version = readme_ver
                version_confidence = "high"
                source = "readme.txt Stable tag"

            severity = Severity.INFO
            desc = f"Plugin detected (passive): {slug}"
            if version:
                desc += f" (version {version}, confidence: {version_confidence}, source: {source})"

            if slug in ("wp-file-manager", "revslider", "js_composer", "easy-wp-smtp"):
                severity = Severity.MEDIUM
                desc += ". This plugin has a history of critical vulnerabilities."

            self._add_finding(
                category="plugins",
                title=f"Plugin Detected: {slug}",
                description=desc,
                severity=severity,
                confidence=0.9,
                remediation="Ensure the plugin is updated to the latest version. "
                            "Remove unused plugins. Monitor for known CVEs.",
                raw_data={
                    "type": "plugin",
                    "slug": slug,
                    "version": version,
                    "version_confidence": version_confidence,
                    "source": source,
                    "detection_method": "passive",
                }
            )

        return slugs

    def _active_enumerate(self, exclude: set = None):
        """Probe known plugin directories via HEAD requests (safe-active mode)."""
        exclude = exclude or set()
        found_plugins = []

        for plugin in _ACTIVE_PROBE_PLUGINS:
            if plugin in exclude:
                continue
            url = f"{self.target_url}/wp-content/plugins/{plugin}/"
            resp = self._head(url)
            if not resp:
                continue
            if resp.status_code in (200, 403):
                version = self._get_plugin_version_from_readme(plugin)
                found_plugins.append({"name": plugin, "version": version})

                severity = Severity.INFO
                desc = f"Plugin detected (active probe): {plugin}"
                if version:
                    desc += f" (version {version})"
                if plugin in ("wp-file-manager", "revslider", "js_composer", "easy-wp-smtp"):
                    severity = Severity.MEDIUM
                    desc += ". This plugin has a history of critical vulnerabilities."

                self._add_finding(
                    category="plugins",
                    title=f"Plugin Detected: {plugin}",
                    description=desc,
                    severity=severity,
                    confidence=0.85,
                    remediation="Ensure the plugin is updated to the latest version. "
                                "Remove unused plugins. Monitor for known CVEs.",
                    raw_data={
                        "type": "plugin",
                        "slug": plugin,
                        "version": version,
                        "version_confidence": "high" if version else None,
                        "source": "readme.txt Stable tag" if version else "directory probe",
                        "detection_method": "active",
                    }
                )

        if found_plugins:
            self._add_finding(
                category="plugins",
                title=f"Active Plugin Enumeration Summary: {len(found_plugins)} additional plugins found",
                description=f"Enumerated {len(found_plugins)} plugins via directory probing: "
                            + ", ".join(p["name"] for p in found_plugins[:15]),
                severity=Severity.LOW,
                confidence=0.9,
                remediation="Block direct access to plugin directories. "
                            "Use security headers to prevent enumeration.",
                raw_data={"plugins": found_plugins}
            )

    def _get_plugin_version_from_readme(self, plugin: str) -> str:
        """Try to read version from readme.txt (Stable tag)."""
        url = f"{self.target_url}/wp-content/plugins/{plugin}/readme.txt"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return ""
        # Standard WP readme format: Stable tag: X.Y.Z
        match = re.search(r"Stable tag:\s*([\d.]+)", resp.text, re.IGNORECASE)
        if match:
            return match.group(1)
        # Fallback: Version: X.Y.Z
        match = re.search(r"Version:\s*([\d.]+)", resp.text, re.IGNORECASE)
        if match:
            return match.group(1)
        return ""
