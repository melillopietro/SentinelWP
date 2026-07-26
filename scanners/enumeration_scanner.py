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
        self._check_rest_api_users()
        self._check_author_archives()
        self._check_login_oracle()
        self._check_oembed_author()
        return self.findings

    def _check_rest_api_users(self):
        """Check if /wp-json/wp/v2/users endpoint exposes user data"""
        url = f"{self.target_url}/wp-json/wp/v2/users"
        resp = self._get(url)
        if not resp:
            return
        if resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list) and len(users) > 0:
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
        elif resp.status_code == 401:
            self._add_finding(
                category="enumeration",
                title="REST API Users Endpoint Protected (401)",
                description="The /wp-json/wp/v2/users endpoint returns 401, indicating authentication is required.",
                severity=Severity.INFO,
                confidence=0.8,
                remediation="No action needed - endpoint is protected.",
            )

    def _check_author_archives(self):
        """Enumerate users via ?author=N parameter"""
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

        if found_users:
            self._add_finding(
                category="enumeration",
                title="Author Archive User Enumeration",
                description=f"User enumeration via author archives (?author=N) is possible. "
                            f"Found {len(found_users)} user(s): {', '.join(found_users[:10])}",
                severity=Severity.HIGH,
                confidence=0.9,
                remediation="Disable author archives or redirect them. Add to .htaccess: "
                            "RewriteCond %{QUERY_STRING} ^author= [NC] "
                            "RewriteRule .* - [F,L]. "
                            "Alternatively use a plugin to disable author enumeration.",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                raw_data={"users": found_users, "method": "author_archive"}
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
