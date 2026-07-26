"""
WordPress Exposure Scanner
- wp-admin / wp-login.php accessibility
- xmlrpc.php exposure
- wp-cron.php exposure
- debug.log exposure
- wp-config.php backup files
- install.php accessible
- readme.html / license.txt exposure
- directory listing (uploads, plugins, themes)
"""
import re
from scanners.base import BaseScanner
from core.models import Severity


class ExposureScanner(BaseScanner):
    def scan(self) -> list:
        self._check_wp_admin()
        self._check_xmlrpc()
        self._check_debug_log()
        self._check_wp_config_backups()
        self._check_install_php()
        self._check_readme_license()
        self._check_directory_listing()
        self._check_wp_cron()
        return self.findings

    def _check_wp_admin(self):
        """Check if wp-admin is publicly accessible without restriction"""
        url = f"{self.target_url}/wp-admin/"
        resp = self._get(url, allow_redirects=False)
        if not resp:
            return
        # If it redirects to wp-login.php, that's expected (not logged in)
        if resp.status_code in (301, 302):
            location = resp.headers.get("Location", "")
            if "wp-login.php" in location:
                self._add_finding(
                    category="exposure",
                    title="wp-admin Publicly Accessible (Login Required)",
                    description="The /wp-admin/ path is publicly reachable and redirects to login. "
                                "Consider restricting access by IP or VPN.",
                    severity=Severity.LOW,
                    confidence=0.7,
                    remediation="Restrict /wp-admin/ access via .htaccess IP whitelist, "
                                "VPN requirement, or a WAF rule. Example: "
                                "<Files wp-login.php> Order Deny,Allow Deny from all Allow from YOUR_IP </Files>",
                )
                return
        if resp.status_code == 200:
            self._add_finding(
                category="exposure",
                title="wp-admin Dashboard Publicly Accessible",
                description="The WordPress admin dashboard is accessible without authentication redirect. "
                            "This may indicate misconfiguration or a publicly visible admin panel.",
                severity=Severity.HIGH,
                confidence=0.85,
                remediation="Restrict /wp-admin/ access by IP whitelist, require VPN, or ensure authentication is enforced.",
            )

    def _check_xmlrpc(self):
        """Check if xmlrpc.php is accessible and accepts POST"""
        url = f"{self.target_url}/xmlrpc.php"
        resp = self._get(url)
        if not resp:
            return
        if resp.status_code == 200 and "XML-RPC server accepts POST requests only" in resp.text:
            self._add_finding(
                category="exposure",
                title="XML-RPC Interface Enabled",
                description="xmlrpc.php is publicly accessible. This is informational — "
                            "whether it poses a risk depends on which methods are enabled "
                            "(checked separately by the XML-RPC method scanner).",
                severity=Severity.INFO,
                confidence=0.95,
                remediation="Disable XML-RPC if not needed: add_filter('xmlrpc_enabled', '__return_false'); "
                            "Or restrict via .htaccess or WAF rules.",
                reference="https://kinsta.com/blog/xmlrpc-php/",
                raw_data={"url": url, "status": resp.status_code}
            )
        elif resp.status_code == 405:
            self._add_finding(
                category="exposure",
                title="XML-RPC Interface Active (405 on GET)",
                description="xmlrpc.php responds with 405 Method Not Allowed on GET, confirming it is active.",
                severity=Severity.INFO,
                confidence=0.8,
                remediation="Disable XML-RPC if not required for external integrations.",
            )

    def _check_debug_log(self):
        """Check if debug.log is publicly accessible"""
        url = f"{self.target_url}/wp-content/debug.log"
        resp = self._get(url)
        if not resp:
            return
        if resp.status_code == 200 and len(resp.text) > 50:
            self._add_finding(
                category="exposure",
                title="Debug Log Publicly Accessible",
                description="wp-content/debug.log is readable. It may contain sensitive information "
                            "such as file paths, database errors, plugin errors, and stack traces. "
                            "Content not stored — credentials and secrets redacted.",
                severity=Severity.CRITICAL,
                confidence=0.95,
                remediation="Remove debug.log from the public directory. Set WP_DEBUG_LOG to a non-public path. "
                            "Block access via .htaccess: <Files debug.log> Order Deny,Allow Deny from all </Files>",
                raw_data={"url": url, "size_bytes": len(resp.content), "content_redacted": True}
            )

    def _check_wp_config_backups(self):
        """Check for common wp-config backup files"""
        backup_names = [
            "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
            "wp-config.php.swp", "wp-config.php~", "wp-config.bak",
            "wp-config.old", "wp-config.txt"
        ]
        for name in backup_names:
            url = f"{self.target_url}/{name}"
            resp = self._head(url)
            if resp and resp.status_code == 200:
                self._add_finding(
                    category="exposure",
                    title=f"wp-config Backup File Accessible: {name}",
                    description=f"A backup of wp-config.php ({name}) is publicly downloadable. "
                                f"This file contains database credentials, auth keys, and salts. "
                                f"Content not stored — credentials and secrets must be immediately rotated.",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    remediation="Delete all backup copies of wp-config.php from the webroot immediately. "
                                "Block access to .php.* extensions via server configuration. "
                                "Rotate all database passwords, auth keys, and salts.",
                    raw_data={"url": url, "filename": name, "content_redacted": True}
                )
                break  # One finding is enough

    def _check_install_php(self):
        """Check if install.php is accessible"""
        url = f"{self.target_url}/wp-admin/install.php"
        resp = self._get(url)
        if not resp:
            return
        if resp.status_code == 200:
            if "already installed" in resp.text.lower():
                self._add_finding(
                    category="exposure",
                    title="install.php Accessible (Already Installed)",
                    description="wp-admin/install.php is publicly accessible. While WordPress reports "
                                "already installed, this endpoint should be blocked.",
                    severity=Severity.LOW,
                    confidence=0.7,
                    remediation="Block access to install.php via .htaccess or server rules.",
                )
            elif "setup" in resp.text.lower() or "install" in resp.text.lower():
                self._add_finding(
                    category="exposure",
                    title="WordPress Installation Page Exposed",
                    description="The WordPress installation wizard is accessible. "
                                "An attacker could potentially reinstall WordPress.",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    remediation="Complete the installation or block access to install.php immediately.",
                )

    def _check_readme_license(self):
        """Check for readme.html and license.txt which may reveal version"""
        for path in ["readme.html", "license.txt"]:
            url = f"{self.target_url}/{path}"
            resp = self._get(url)
            if resp and resp.status_code == 200:
                if "wordpress" in resp.text.lower():
                    ver = None
                    ver_match = re.search(r"Version\s+([\d.]+)", resp.text)
                    if ver_match:
                        ver = ver_match.group(1)
                    self._add_finding(
                        category="information_disclosure",
                        title=f"WordPress {path} Accessible",
                        description=f"{path} is publicly readable and confirms WordPress installation."
                                    + (f" Version reference found: {ver}" if ver else ""),
                        severity=Severity.LOW,
                        confidence=0.8,
                        remediation=f"Delete or block access to {path} via server configuration.",
                        raw_data={"path": path, "version": ver}
                    )

    def _check_directory_listing(self):
        """Check for directory listing on common WP directories"""
        dirs = ["wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/"]
        for d in dirs:
            url = f"{self.target_url}/{d}"
            resp = self._get(url)
            if not resp:
                continue
            if resp.status_code == 200:
                if "<title>Index of" in resp.text or "Parent Directory" in resp.text:
                    self._add_finding(
                        category="exposure",
                        title=f"Directory Listing Enabled: /{d}",
                        description=f"Directory listing is enabled on /{d}. "
                                    f"Attackers can browse all files in this directory.",
                        severity=Severity.MEDIUM,
                        confidence=0.95,
                        remediation="Disable directory listing in web server config. "
                                    "Apache: Options -Indexes. Nginx: autoindex off;",
                        raw_data={"url": url}
                    )

    def _check_wp_cron(self):
        """Check if wp-cron.php is publicly accessible"""
        url = f"{self.target_url}/wp-cron.php"
        resp = self._get(url)
        if resp and resp.status_code == 200:
            self._add_finding(
                category="exposure",
                title="wp-cron.php Publicly Accessible",
                description="wp-cron.php is accessible. On high-traffic sites this can be used for DoS. "
                            "It also reveals that WordPress is installed.",
                severity=Severity.LOW,
                confidence=0.7,
                remediation="Disable wp-cron via wp-config.php (define('DISABLE_WP_CRON', true)) "
                            "and use a system cron job instead. Block public access via .htaccess.",
            )
