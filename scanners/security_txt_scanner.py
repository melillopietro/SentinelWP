"""
WordPress Security Policy File (security.txt) Scanner
- Checks for presence of /security.txt and /.well-known/security.txt
- Validates the presence of the required 'Contact:' field
- Reports missing or correctly configured security policy files
"""
from scanners.base import BaseScanner
from core.models import Severity


class SecurityTxtScanner(BaseScanner):
    def scan(self) -> list:
        paths = ["/.well-known/security.txt", "/security.txt"]
        found = False
        
        for path in paths:
            url = f"{self.target_url}{path}"
            resp = self._get(url)
            
            if resp and resp.status_code == 200:
                body = resp.text
                if "contact:" in body.lower():
                    found = True
                    self._add_finding(
                        category="configuration",
                        title="Security Policy File (security.txt) Found",
                        description=f"A valid security policy file (security.txt) is publicly accessible at {path}. "
                                    "This complies with RFC 9116 and allows researchers to report security vulnerabilities responsibly.",
                        severity=Severity.INFO,
                        confidence=1.0,
                        remediation="No remediation needed. Maintain and review contact details periodically.",
                        reference="https://securitytxt.org/",
                        raw_data={"path": path, "content_preview": body[:1000]}
                    )
                    break
                    
        if not found:
            self._add_finding(
                category="configuration",
                title="Missing Security Policy File (security.txt)",
                description="No security policy file (security.txt) was found in /.well-known/security.txt or /security.txt. "
                            "It is a best practice to publish contact info for vulnerability disclosure.",
                severity=Severity.LOW,
                confidence=0.9,
                remediation="Create a security.txt file adhering to RFC 9116 and place it in the /.well-known/ directory.",
                reference="https://securitytxt.org/",
                raw_data={"checked_paths": paths}
            )
            
        return self.findings
