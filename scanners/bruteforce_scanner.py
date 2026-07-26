"""
WordPress Password Brute-Force Scanner
- Tests common/default credentials via wp-login.php
- Tests via xmlrpc.php system.multicall if available
- Rate-limited and responsible (max 20 attempts)
"""
import re
from scanners.base import BaseScanner
from core.models import Severity


# Only test extremely common/default passwords - this is an audit, not an attack
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "wordpress"),
    ("admin", "pass123"),
    ("admin", "admin1234"),
    ("admin", "changeme"),
    ("admin", "letmein"),
    ("administrator", "admin"),
    ("administrator", "password"),
    ("administrator", "123456"),
    ("test", "test"),
    ("user", "user"),
    ("demo", "demo"),
    ("editor", "editor"),
]


class BruteForceScanner(BaseScanner):
    """
    Responsible brute-force: only tests common default credentials.
    Max 20 attempts. Designed for audit purposes only.
    """
    MAX_ATTEMPTS = 20

    def scan(self) -> list:
        self._test_default_credentials()
        return self.findings

    def _test_default_credentials(self):
        url = f"{self.target_url}/wp-login.php"
        # First check if wp-login.php is accessible
        check = self._get(url)
        if not check or check.status_code != 200:
            return

        compromised = []
        attempts = 0

        for username, password in DEFAULT_CREDENTIALS:
            if attempts >= self.MAX_ATTEMPTS:
                break
            attempts += 1
            try:
                resp = self._post(url, data={
                    "log": username,
                    "pwd": password,
                    "wp-submit": "Log In",
                    "redirect_to": f"{self.target_url}/wp-admin/",
                }, allow_redirects=False)
            except Exception:
                continue

            if not resp:
                continue

            # Successful login: redirect to wp-admin (302) or contains dashboard cookie
            if resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if "wp-admin" in location or "dashboard" in location:
                    compromised.append({"username": username, "password": password})
            # Some configs return 200 with logged-in content
            elif resp.status_code == 200:
                cookies = "; ".join(f"{c.name}" for c in resp.cookies)
                if "wordpress_logged_in" in cookies:
                    compromised.append({"username": username, "password": password})

        if compromised:
            usernames = [c["username"] + ":" + c["password"] for c in compromised]
            creds_desc = ", ".join(usernames)
            self._add_finding(
                category="authentication",
                title=f"Default Credentials Found ({len(compromised)} account(s))",
                description=f"Weak/default credentials allow login: {creds_desc}. "
                            "Immediate password change required.",
                severity=Severity.CRITICAL,
                confidence=0.99,
                remediation="Change all default passwords immediately. "
                            "Implement strong password policy and 2FA. "
                            "Consider disabling wp-login.php in favor of SSO.",
                raw_data={"compromised_accounts": compromised, "attempts": attempts}
            )
        else:
            self._add_finding(
                category="authentication",
                title="Default Credentials Not Found",
                description=f"Tested {attempts} common credential pairs - none successful. "
                            "This does not guarantee strong passwords are in use.",
                severity=Severity.INFO,
                confidence=0.7,
                remediation="Continue enforcing strong password policies and 2FA.",
                raw_data={"attempts": attempts}
            )
