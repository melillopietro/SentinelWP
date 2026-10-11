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
        """Probe known plugin directories via HEAD requests (safe-active mode).

        SCAN-GAP-001: performs a soft-404 check before accepting any HTTP 200 response
        as plugin confirmation. This prevents false positives on WordPress sites using
        custom 404 templates that return HTTP 200 for all unknown URLs.

        HTTP 403 responses are accepted as plugin-confirmed (directory listing denied).
        """
        exclude = exclude or set()
        found_plugins = []
        _soft404_checked = False
        _is_soft404_site = False

        for plugin in _ACTIVE_PROBE_PLUGINS:
            if plugin in exclude:
                continue
            url = f"{self.target_url}/wp-content/plugins/{plugin}/"
            resp = self._head(url)
            if not resp:
                continue

            if resp.status_code == 403:
                # HTTP 403 = directory listing denied = plugin present; no soft-404 risk
                version = self._get_plugin_version_from_readme(plugin)
            elif resp.status_code == 200:
                # HTTP 200 requires soft-404 verification (SCAN-GAP-001)
                if not _soft404_checked:
                    _is_soft404_site = self.is_soft_404(url)
                    _soft404_checked = True
                if _is_soft404_site:
                    # Site returns 200 for non-existent paths → skip to avoid false positive
                    continue
                version = self._get_plugin_version_from_readme(plugin)
            else:
                continue

            # Emit finding for confirmed plugin
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
        """Try to read version from readme.txt (Stable tag).

        DETECT-OPEN-004: Sends Cache-Control: no-cache to bypass CDN/proxy stale
        caches that may serve an outdated readme.txt. This is targeted to this
        specific version-evidence request only — it does not affect other scanner
        requests or enumeration probes.
        """
        url = f"{self.target_url}/wp-content/plugins/{plugin}/readme.txt"
        # Cache-Control: no-cache requests a fresh copy from the origin server,
        # bypassing CDN edge caches that may hold stale plugin readme files.
        resp = self._get(url, headers={"Cache-Control": "no-cache", "Pragma": "no-cache"})
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
