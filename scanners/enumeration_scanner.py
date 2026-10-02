"""
WordPress User Enumeration Scanner
- REST API user listing (/wp-json/wp/v2/users)
- Author archive enumeration (?author=N)
- Login error message oracle
- oembed author leakage
"""
import re
import json
from scanners.base import BaseScanner
from core.models import Severity


class EnumerationScanner(BaseScanner):
    MAX_AUTHORS = 20

    def scan(self) -> list:
        self._check_open_registration()
        self._check_rest_api_users()
        self._check_author_archives()
        self._check_login_oracle()
        self._check_oembed_author()
        return self.findings

    def _check_open_registration(self):
        """Check if public user registration is enabled (users_can_register)"""
        reg_url = f"{self.target_url}/wp-login.php?action=register"
        resp = self._get(reg_url)
        if not resp or resp.status_code != 200:
            return

        if "registration=disabled" in getattr(resp, "url", "").lower():
            return

        text_lower = resp.text.lower()
        if "registration is currently not allowed" in text_lower or "user registration is currently not allowed" in text_lower:
            return

        if (
            'id="registerform"' in text_lower or "id='registerform'" in text_lower
            or 'name="registerform"' in text_lower or "name='registerform'" in text_lower
            or ("user_login" in text_lower and ("register" in text_lower or "registration" in text_lower))
        ):
            self._add_finding(
                category="configuration",
                title="Open User Registration Enabled",
                description="Public user registration is enabled on this WordPress site (users_can_register is active). "
                            "Unauthenticated visitors can freely register accounts. "
                            "This significantly increases the attack surface for subscriber-to-admin privilege escalation exploits.",
                severity=Severity.HIGH,
                confidence=0.95,
                remediation="If public user accounts are not needed, disable 'Anyone can register' in WordPress Settings -> General. "
                            "If registration is required, enforce CAPTCHA, email verification, and strict role permissions.",
                reference="https://developer.wordpress.org/advanced-administration/security/hardening/",
                raw_data={"url": reg_url}
            )

    def _check_rest_api_users(self):
        """Check if /wp-json/wp/v2/users endpoint or ?rest_route= bypass exposes user data"""
        url = f"{self.target_url}/wp-json/wp/v2/users"
        resp = self._get(url)
        primary_exposed = False

        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list) and len(users) > 0:
                    primary_exposed = True
                    usernames = [u.get("slug", u.get("name", "unknown")) for u in users[:20]]
                    self._add_finding(
                        category="enumeration",
                        title="REST API User Enumeration",
                        description=f"The WordPress REST API exposes user information publicly. "
                                    f"Found {len(users)} user(s): {', '.join(usernames[:10])}",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        remediation="Disable the /wp/v2/users endpoint for unauthenticated requests. "
                                    "Use a security plugin or add a filter: "
                                    "add_filter('rest_endpoints', function($endpoints) { "
                                    "unset($endpoints['/wp/v2/users']); return $endpoints; });",
                        reference="https://developer.wordpress.org/rest-api/reference/users/",
                        raw_data={"users": usernames, "endpoint": url}
                    )
            except (json.JSONDecodeError, ValueError):
                pass
        elif resp and resp.status_code in (401, 403):
            self._add_finding(
                category="enumeration",
                title=f"REST API Users Endpoint Protected ({resp.status_code})",
                description=f"The /wp-json/wp/v2/users endpoint returns {resp.status_code}, indicating authentication is required or access is blocked.",
                severity=Severity.INFO,
                confidence=0.8,
                remediation="No action needed - endpoint is protected.",
            )

        # Query parameter rewrite bypass check: ?rest_route=/wp/v2/users
        bypass_url = f"{self.target_url}/?rest_route=/wp/v2/users"
        bypass_resp = self._get(bypass_url)
        if bypass_resp and bypass_resp.status_code == 200:
            try:
                bypass_users = bypass_resp.json()
                if isinstance(bypass_users, list) and len(bypass_users) > 0:
                    bypass_usernames = [u.get("slug", u.get("name", "unknown")) for u in bypass_users[:20]]
                    if not primary_exposed:
                        # WAF / URL rewrite bypass discovered!
                        self._add_finding(
                            category="enumeration",
                            title="REST API WAF/Rewrite Bypass for User Enumeration (?rest_route=/wp/v2/users)",
                            description="Path-based blocking on /wp-json/wp/v2/users was bypassed using the query parameter "
                                        f"?rest_route=/wp/v2/users. Disclosed {len(bypass_users)} user(s): {', '.join(bypass_usernames[:10])}",
                            severity=Severity.HIGH,
                            confidence=0.95,
                            remediation="Ensure WAF and rewrite rules inspect both URL paths and query parameters (?rest_route=). "
                                        "Disable the endpoint at application level using the rest_endpoints filter.",
                            reference="https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/",
                            raw_data={"users": bypass_usernames, "bypass_url": bypass_url}
                        )
            except (json.JSONDecodeError, ValueError):
                pass

    def _check_author_archives(self):
        """Enumerate users via ?author=N parameter and RSS feed leakage"""
        found_users = []
        for i in range(1, self.MAX_AUTHORS + 1):
            url = f"{self.target_url}/?author={i}"
            resp = self._get(url, allow_redirects=False)
            if not resp:
                continue
            # WordPress redirects to /author/slug/ on valid authors
            if resp.status_code in (301, 302):
                location = resp.headers.get("Location", "")
                slug_match = re.search(r"/author/([^/]+)/?", location)
                if slug_match:
                    found_users.append(slug_match.group(1))
            elif resp.status_code == 200:
                # Check page body for author slug
                slug_match = re.search(r'class="[^"]*author-([a-zA-Z0-9_-]+)', resp.text)
                if slug_match:
                    found_users.append(slug_match.group(1))

        # Check main RSS feed for dc:creator username leakage
        feed_url = f"{self.target_url}/feed/"
        feed_resp = self._get(feed_url)
        if feed_resp and feed_resp.status_code == 200:
            creators = re.findall(r"<dc:creator><!\[CDATA\[([^\]]+)\]\]></dc:creator>", feed_resp.text)
            creators.extend(re.findall(r"<dc:creator>([^<]+)</dc:creator>", feed_resp.text))
            for creator in creators:
                creator = creator.strip()
                if creator and creator not in found_users:
                    found_users.append(creator)

        if found_users:
            self._add_finding(
                category="enumeration",
                title="Author Archive User Enumeration",
                description=f"User enumeration via author archives or RSS feeds is possible. "
                            f"Found {len(found_users)} user(s): {', '.join(found_users[:10])}",
                severity=Severity.HIGH,
                confidence=0.9,
                remediation="Disable author archives or redirect them. Add to .htaccess: "
                            "RewriteCond %{QUERY_STRING} ^author= [NC] "
                            "RewriteRule .* - [F,L]. "
                            "Alternatively use a plugin to disable author enumeration.",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                raw_data={"users": found_users, "method": "author_archive_or_feed"}
            )

    def _check_login_oracle(self):
        """Check if wp-login.php reveals valid/invalid usernames via error messages"""
        url = f"{self.target_url}/wp-login.php"
        # Try a known-invalid user
        data = {"log": "wsa_nonexistent_user_probe_xz99", "pwd": "wrongpass", "wp-submit": "Log In"}
        try:
            resp = self._post(url, data=data, allow_redirects=True)
        except Exception:
            return
        if not resp or resp.status_code != 200:
            return
        body = resp.text.lower()
        # WordPress default: "Unknown username" vs "The password you entered for the username X is incorrect"
        if "unknown username" in body or "invalid username" in body:
            self._add_finding(
                category="enumeration",
                title="Login Form Username Oracle",
                description="The login page reveals whether a username exists via distinct error messages. "
                            "An attacker can enumerate valid usernames by observing response differences.",
                severity=Severity.MEDIUM,
                confidence=0.85,
                remediation="Use a plugin or custom filter to return a generic error message for login failures. "
                            "add_filter('login_errors', function() { return 'Invalid credentials.'; });",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                raw_data={"method": "login_error_oracle"}
            )

    def _check_oembed_author(self):
        """Check if oembed endpoint leaks author info"""
        url = f"{self.target_url}/wp-json/oembed/1.0/embed?url={self.target_url}"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
            author = data.get("author_name")
            if author:
                self._add_finding(
                    category="enumeration",
                    title="oEmbed Author Information Leakage",
                    description=f"The oEmbed endpoint exposes author information: {author}",
                    severity=Severity.LOW,
                    confidence=0.8,
                    remediation="Disable oEmbed or filter out author data from the response.",
                    raw_data={"author": author, "endpoint": url}
                )
        except (json.JSONDecodeError, ValueError):
            pass
