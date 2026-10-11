"""
WordPress Password Brute-Force Scanner (Controlled Credential Verification)
- Tests common/default credentials via wp-login.php
- Rate-limited and responsible (max 20 attempts)
- P0 Hardening: Strict zero-password persistence policy.
  Passwords and cleartext credentials are NEVER saved in findings, descriptions,
  raw_data, databases, logs, or reports.
"""
import hashlib
from datetime import datetime, timezone
from scanners.base import BaseScanner
from core.models import Severity

# Common default credentials audit dictionary
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
    Controlled Credential Verification Scanner.

    DEPRECATED (FUNC-003, Sprint 1): This scanner is excluded from all automated
    scan profiles (passive, safe-active, full) and will be removed in a future
    release. It must only be invoked with explicit written authorization for the
    target system.  Calling scan() without setting ALLOW_BRUTEFORCE = True raises
    RuntimeError to prevent accidental execution.
    """
    MAX_ATTEMPTS = 20
    # Callers must explicitly opt in; this is never True in normal operation.
    ALLOW_BRUTEFORCE: bool = False

    def scan(self) -> list:
        if not self.ALLOW_BRUTEFORCE:
            raise RuntimeError(
                "BruteForceScanner is deprecated and disabled. "
                "Set ALLOW_BRUTEFORCE = True only after obtaining explicit written "
                "authorization for the target system."
            )
        self._test_default_credentials()
        return self.findings

    def _test_default_credentials(self):
        url = f"{self.target_url}/wp-login.php"
        check = self._get(url)
        if not check or check.status_code != 200:
            return

        compromised_usernames = []
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

            # Check if login succeeded (redirect to wp-admin or session cookie set)
            login_success = False
            if resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if "wp-admin" in location or "dashboard" in location:
                    login_success = True
            elif resp.status_code == 200:
                cookies = "; ".join(f"{c.name}" for c in resp.cookies)
                if "wordpress_logged_in" in cookies:
                    login_success = True

            if login_success:
                if username not in compromised_usernames:
                    compromised_usernames.append(username)

        # Non-reversible account identifier hashes
        account_hashes = [
            hashlib.sha256(u.encode("utf-8")).hexdigest()[:16]
            for u in compromised_usernames
        ]

        if compromised_usernames:
            self._add_finding(
                category="authentication",
                title=f"Weak Default Credentials Verified ({len(compromised_usernames)} account(s))",
                description=(
                    f"Controlled credential verification identified {len(compromised_usernames)} account(s) "
                    "using weak or default passwords. Immediate credential rotation, account review, and "
                    "multi-factor authentication (2FA) enforcement are required."
                ),
                severity=Severity.CRITICAL,
                confidence=0.99,
                remediation=(
                    "Rotate all passwords immediately. Enforce a strong password policy and mandatory 2FA. "
                    "Consider restricting wp-login.php access by IP or implementing Single Sign-On (SSO)."
                ),
                raw_data={
                    "credential_control_failed": True,
                    "account_identifier_hashes": account_hashes,
                    "attempt_count": attempts,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        else:
            self._add_finding(
                category="authentication",
                title="Default Credentials Not Found",
                description=(
                    f"Tested {attempts} common credential baseline pairs; none were accepted. "
                    "This verifies default passwords are not present, but does not guarantee strong entropy."
                ),
                severity=Severity.INFO,
                confidence=0.7,
                remediation="Continue enforcing strong password policies and multi-factor authentication (2FA).",
                raw_data={
                    "credential_control_failed": False,
                    "attempt_count": attempts,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
