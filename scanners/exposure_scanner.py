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
    @staticmethod
    def _is_soft_404(resp) -> bool:
        """
        Verify if a 200 OK response is actually a custom Soft 404 HTML error page.
        """
        if not resp:
            return True
        content_type = resp.headers.get("content-type", "").lower()
        body = resp.text.lower() if hasattr(resp, "text") else ""

        # Obvious HTML error page markers
        if "text/html" in content_type:
            soft_404_markers = [
                "<title>page not found",
                "<title>404",
                "<title>not found",
                "<title>error 404",
                "class=\"error404\"",
                "class='error404'",
                "not found on this server",
                "the requested url was not found",
                "it looks like nothing was found at this location",
                "page cannot be found",
            ]
            if any(marker in body for marker in soft_404_markers):
                return True
        return False

    def scan(self) -> list:
        self._check_wp_admin()
        self._check_xmlrpc()
        self._check_git_exposure()
        self._check_env_exposure()
        self._check_adminer_and_tools()
        self._check_debug_log()
        self._check_wp_config_backups()
        self._check_wp_config_sample()
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

    def _check_git_exposure(self):
        """Check if .git directory is publicly exposed (/.git/HEAD, /.git/config)"""
        head_url = f"{self.target_url}/.git/HEAD"
        resp = self._get(head_url)
        if not resp or resp.status_code != 200 or self._is_soft_404(resp):
            return

        text = resp.text.strip()
        # Valid git HEAD starts with 'ref: refs/' or is a 40-char commit SHA
        is_git_head = text.startswith("ref: refs/") or bool(re.match(r"^[0-9a-fA-F]{40}$", text))
        if is_git_head:
            self._add_finding(
                category="exposure",
                title="Git Repository Exposed (/.git/HEAD)",
                description="The .git repository is publicly accessible. Attackers can reconstruct "
                            "the full source code, commit history, and sensitive credentials in wp-config.php.",
                severity=Severity.CRITICAL,
                confidence=0.99,
                remediation="Block access to all hidden dot-directories in your web server config. "
                            "Nginx: location ~ /\\.git { deny all; } "
                            "Apache: <DirectoryMatch \"/\\.git\"> Order Deny,Allow Deny from all </DirectoryMatch>",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Webpage_Content_for_Information_Leakage",
                raw_data={"url": head_url, "content_preview": text[:80]}
            )

    def _check_env_exposure(self):
        """Check for exposed environment files (/.env, /.env.local, /.env.production)"""
        env_files = [".env", ".env.local", ".env.production", ".env.backup", ".env.stage"]
        for env_name in env_files:
            url = f"{self.target_url}/{env_name}"
            resp = self._get(url)
            if not resp or resp.status_code != 200 or self._is_soft_404(resp):
                continue

            text = resp.text
            # Anti-false-positive: ensure it is not HTML
            if "<!doctype" in text.lower() or "<html" in text.lower() or "<head" in text.lower():
                continue

            # Look for environment variable patterns: KEY=VALUE
            if re.search(r"^(DB_|APP_|WORDPRESS_|MYSQL_|SECRET_|API_|AWS_|JWT_|ENVIRONMENT=|PORT=)", text, re.MULTILINE):
                self._add_finding(
                    category="exposure",
                    title=f"Environment Configuration File Exposed: /{env_name}",
                    description=f"A dotenv file (/{env_name}) is publicly readable. "
                                f"It typically contains database credentials, application secrets, and API keys.",
                    severity=Severity.CRITICAL,
                    confidence=0.98,
                    remediation=f"Delete or block public access to /{env_name} immediately. "
                                "Rotate all credentials and secret keys defined within the file.",
                    raw_data={"file": env_name, "content_redacted": True}
                )
                break  # One env file finding is sufficient

    def _check_adminer_and_tools(self):
        """Check for standalone database managers and diagnostic scripts left in webroot"""
        # Adminer check
        adminer_url = f"{self.target_url}/adminer.php"
        resp = self._get(adminer_url)
        if resp and resp.status_code == 200 and not self._is_soft_404(resp):
            text_lower = resp.text.lower()
            if "adminer" in text_lower or "auth[username]" in text_lower or "auth[driver]" in text_lower:
                self._add_finding(
                    category="exposure",
                    title="Database Management Tool Exposed: /adminer.php",
                    description="The standalone database management script Adminer is publicly accessible in the web root. "
                                "Attackers can use this to connect to local or remote databases or exploit known Adminer vulnerabilities.",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    remediation="Remove adminer.php from the web server immediately.",
                    raw_data={"url": adminer_url}
                )

        # phpinfo check
        phpinfo_url = f"{self.target_url}/phpinfo.php"
        resp = self._get(phpinfo_url)
        if resp and resp.status_code == 200 and not self._is_soft_404(resp):
            text_lower = resp.text.lower()
            if "php version" in text_lower and ("php license" in text_lower or "configuration" in text_lower or "server api" in text_lower):
                self._add_finding(
                    category="information_disclosure",
                    title="PHP Diagnostic Script Exposed (phpinfo.php)",
                    description="phpinfo() output is publicly viewable, revealing PHP compilation details, "
                                "system environment variables, extension versions, and server paths.",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    remediation="Remove phpinfo.php from the web server immediately.",
                    raw_data={"url": phpinfo_url}
                )

    def _check_debug_log(self):
        """Check if debug.log is publicly accessible"""
        url = f"{self.target_url}/wp-content/debug.log"
        resp = self._get(url)
        if not resp or resp.status_code != 200 or self._is_soft_404(resp):
            return

        text = resp.text
        # Anti-false-positive: must not be an HTML page and must look like log entries
        if "<!doctype" in text.lower() or "<html" in text.lower():
            return

        if len(text) > 50 and any(p in text for p in ("[", "PHP Fatal", "PHP Warning", "PHP Notice", "WordPress database error", "wp-content/")):
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
        """Check for common wp-config backup files with anti-false-positive validation"""
        backup_names = [
            "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
            "wp-config.php.swp", "wp-config.php~", "wp-config.bak",
            "wp-config.old", "wp-config.txt"
        ]
        for name in backup_names:
            url = f"{self.target_url}/{name}"
            resp = self._get(url)
            if not resp or resp.status_code != 200 or self._is_soft_404(resp):
                continue

            text = resp.text
            # Anti-false-positive: must not be an HTML template
            if "<!doctype html" in text.lower() or "<html" in text.lower():
                continue

            # Must contain wp-config style content
            is_valid_backup = any(token in text for token in ("DB_NAME", "DB_PASSWORD", "DB_USER", "AUTH_KEY", "table_prefix", "<?php"))
            if is_valid_backup:
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

    def _check_wp_config_sample(self):
        """Check if wp-config-sample.php is exposed and whether it contains live secrets"""
        url = f"{self.target_url}/wp-config-sample.php"
        resp = self._get(url)
        if not resp or resp.status_code != 200 or self._is_soft_404(resp):
            return

        text = resp.text
        if "DB_NAME" in text:
            # Check if someone filled real credentials into sample file
            if "database_name_here" not in text and "password_here" not in text and "DB_PASSWORD" in text:
                self._add_finding(
                    category="exposure",
                    title="Live Credentials in wp-config-sample.php",
                    description="wp-config-sample.php contains live database credentials rather than default placeholders.",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    remediation="Remove or sanitize wp-config-sample.php immediately. Rotate database credentials.",
                    raw_data={"url": url, "content_redacted": True}
                )
            else:
                self._add_finding(
                    category="information_disclosure",
                    title="wp-config-sample.php Accessible",
                    description="wp-config-sample.php is publicly readable. While it contains default placeholders, "
                                "it confirms the underlying WordPress file structure.",
                    severity=Severity.LOW,
                    confidence=0.85,
                    remediation="Delete wp-config-sample.php from the webroot.",
                    raw_data={"url": url}
                )

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
