"""
Cookie Security Scanner
Analyzes HTTP response cookies from target URL and /wp-login.php for security flags:
- Secure
- HttpOnly
- SameSite
"""
from typing import Dict, List
from scanners.base import BaseScanner
from core.models import Severity


class CookieSecurityScanner(BaseScanner):
    def scan(self) -> list:
        # 1. Make GET request to self.target_url
        resp_root = self._get(self.target_url)

        # 2. Make GET request to self.target_url + '/wp-login.php'
        login_url = f"{self.target_url}/wp-login.php"
        resp_login = self._get(login_url)

        all_cookies: List[dict] = []

        if resp_root:
            all_cookies.extend(self._extract_cookies(resp_root))

        if resp_login:
            all_cookies.extend(self._extract_cookies(resp_login))

        # Deduplicate and aggregate cookie security flags by (name, domain, path)
        unique_cookies: Dict[tuple, dict] = {}
        for c in all_cookies:
            key = (c["name"], c["domain"], c["path"])
            if key not in unique_cookies:
                unique_cookies[key] = c
            else:
                existing = unique_cookies[key]
                # If any instance of a cookie is missing a security attribute, treat it as missing
                existing["secure"] = existing["secure"] and c["secure"]
                existing["httponly"] = existing["httponly"] and c["httponly"]
                existing["samesite"] = existing["samesite"] and c["samesite"]
                if not existing["samesite_value"] and c["samesite_value"]:
                    existing["samesite_value"] = c["samesite_value"]

        if not unique_cookies:
            return self.findings

        # 3. Check for security issues per issue type
        missing_secure = [c for c in unique_cookies.values() if not c["secure"]]
        missing_httponly = [c for c in unique_cookies.values() if not c["httponly"]]
        missing_samesite = [c for c in unique_cookies.values() if not c["samesite"]]

        # 4. Report findings (group insecure cookies per issue type)

        # Issue 1: Cookie without Secure flag -> MEDIUM severity
        if missing_secure:
            cookie_names = ", ".join(sorted(set(c["name"] for c in missing_secure)))
            self._add_finding(
                category="configuration",
                title="Cookies Missing Secure Flag",
                description=f"The following cookie(s) are missing the 'Secure' flag: {cookie_names}. "
                            "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections, "
                            "exposing sensitive data to interception via man-in-the-middle (MITM) attacks.",
                severity=Severity.MEDIUM,
                confidence=0.9,
                remediation="Configure the server to include the 'Secure' attribute for all Set-Cookie headers.",
                reference="https://owasp.org/www-community/controls/SecureCookieAttribute",
                raw_data={"cookies": missing_secure, "cookie_names": [c["name"] for c in missing_secure]},
            )

        # Issue 2: Cookie without HttpOnly flag -> MEDIUM severity
        if missing_httponly:
            cookie_names = ", ".join(sorted(set(c["name"] for c in missing_httponly)))
            self._add_finding(
                category="configuration",
                title="Cookies Missing HttpOnly Flag",
                description=f"The following cookie(s) are missing the 'HttpOnly' flag: {cookie_names}. "
                            "Cookies without HttpOnly can be accessed by client-side JavaScript, "
                            "making them vulnerable to theft via Cross-Site Scripting (XSS) attacks.",
                severity=Severity.MEDIUM,
                confidence=0.9,
                remediation="Set the 'HttpOnly' attribute on all cookies, especially session cookies.",
                reference="https://owasp.org/www-community/HttpOnly",
                raw_data={"cookies": missing_httponly, "cookie_names": [c["name"] for c in missing_httponly]},
            )

        # Issue 3: Cookie without SameSite -> LOW severity
        if missing_samesite:
            cookie_names = ", ".join(sorted(set(c["name"] for c in missing_samesite)))
            self._add_finding(
                category="configuration",
                title="Cookies Missing SameSite Attribute",
                description=f"The following cookie(s) are missing the 'SameSite' attribute: {cookie_names}. "
                            "Without SameSite, cookies may be included in cross-site requests, "
                            "increasing vulnerability to Cross-Site Request Forgery (CSRF) attacks.",
                severity=Severity.LOW,
                confidence=0.85,
                remediation="Set the 'SameSite' attribute ('Strict' or 'Lax') on all cookies.",
                reference="https://owasp.org/www-community/SameSite",
                raw_data={"cookies": missing_samesite, "cookie_names": [c["name"] for c in missing_samesite]},
            )

        # Issue 4: All cookies properly flagged -> INFO (positive finding)
        if not missing_secure and not missing_httponly and not missing_samesite:
            cookie_names = ", ".join(sorted(set(c["name"] for c in unique_cookies.values())))
            self._add_finding(
                category="configuration",
                title="All Cookies Properly Flagged",
                description=f"All cookie(s) set by the target application ({cookie_names}) have "
                            "the Secure, HttpOnly, and SameSite attributes properly configured.",
                severity=Severity.INFO,
                confidence=0.95,
                remediation="No remediation needed. Maintain proper cookie security practices.",
                raw_data={"cookies": list(unique_cookies.values()), "cookie_names": [c["name"] for c in unique_cookies.values()]},
            )

        return self.findings

    def _extract_cookies(self, resp) -> List[dict]:
        """
        Extract cookie security attributes from a requests Response object.
        """
        cookies_info = []

        responses = list(resp.history) + [resp] if hasattr(resp, "history") else [resp]

        for r in responses:
            if not hasattr(r, "cookies") or not r.cookies:
                continue

            for cookie in r.cookies:
                c_info = self._analyze_cookie(cookie, r.url)
                cookies_info.append(c_info)

        return cookies_info

    def _analyze_cookie(self, cookie, source_url: str) -> dict:
        """
        Inspect a single http.cookiejar.Cookie object for Secure, HttpOnly, and SameSite attributes.
        """
        rest_keys = {}
        if hasattr(cookie, "_rest"):
            rest_keys = {k.lower(): (k, v) for k, v in cookie._rest.items()}

        # Check Secure flag
        has_secure = bool(getattr(cookie, "secure", False)) or ("secure" in rest_keys)

        # Check HttpOnly flag
        has_httponly = "httponly" in rest_keys

        # Check SameSite attribute and value
        has_samesite = "samesite" in rest_keys
        samesite_value = None
        if has_samesite:
            _, val = rest_keys["samesite"]
            samesite_value = val if val is not None else "Lax"

        return {
            "name": cookie.name,
            "domain": getattr(cookie, "domain", ""),
            "path": getattr(cookie, "path", "/"),
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": has_samesite,
            "samesite_value": samesite_value,
            "source_url": source_url,
        }
