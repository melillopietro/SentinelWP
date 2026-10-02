"""
WAF (Web Application Firewall) Detection Scanner
Fingerprints common WAFs via response headers and behavior
"""
from scanners.base import BaseScanner
from core.models import Severity


WAF_SIGNATURES = {
    "cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": ""},
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "sucuri": {
        "headers": {"server": "sucuri", "x-sucuri-id": ""},
        "cookies": ["sucuri_cloudproxy"],
    },
    "wordfence": {
        "headers": {},
        "cookies": ["wfwaf-authcookie"],
    },
    "akamai": {
        "headers": {"server": "akamai", "x-akamai-transformed": ""},
        "cookies": ["akamai_"],
    },
    "aws-waf": {
        "headers": {"x-amzn-requestid": "", "x-amz-cf-id": ""},
        "cookies": ["awsalb"],
    },
    "modsecurity": {
        "headers": {"server": "mod_security"},
        "cookies": [],
    },
    "imperva": {
        "headers": {"x-iinfo": ""},
        "cookies": ["incap_ses", "visid_incap"],
    },
    "f5-bigip": {
        "headers": {"server": "bigip", "x-cnection": ""},
        "cookies": ["bigipserver"],
    },
}


class WAFScanner(BaseScanner):
    def scan(self) -> list:
        self._detect_waf()
        return self.findings

    def _detect_waf(self):
        resp = self._get(self.target_url)
        if not resp:
            return

        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookies_str = "; ".join(f"{c.name}={c.value}" for c in resp.cookies).lower()
        detected_wafs = []

        for waf_name, sigs in WAF_SIGNATURES.items():
            detected = False
            # Check headers
            for hdr_key, hdr_val in sigs.get("headers", {}).items():
                if hdr_key in headers_lower:
                    if not hdr_val or hdr_val in headers_lower.get(hdr_key, ""):
                        detected = True
                        break
            # Check cookies
            if not detected:
                for cookie_prefix in sigs.get("cookies", []):
                    if cookie_prefix.lower() in cookies_str:
                        detected = True
                        break
            if detected:
                detected_wafs.append(waf_name)

        if detected_wafs:
            self._add_finding(
                category="configuration",
                title="WAF Detected: " + ", ".join(detected_wafs),
                description="Web Application Firewall detected: " + ", ".join(detected_wafs) + ". "
                            "This may affect scan accuracy as some probes could be blocked.",
                severity=Severity.INFO,
                confidence=0.8,
                remediation="WAF presence is positive for security. Ensure rules are up to date.",
                raw_data={"wafs": detected_wafs}
            )
        else:
            self._add_finding(
                category="configuration",
                title="No WAF Detected",
                description="No Web Application Firewall was detected. "
                            "The application may be directly exposed to attacks.",
                severity=Severity.MEDIUM,
                confidence=0.6,
                remediation="Consider deploying a WAF (Cloudflare, Sucuri, AWS WAF, or ModSecurity).",
                raw_data={"wafs": []}
            )

        # Test with malicious-looking request to trigger WAF
        test_url = self.target_url + "/?s=<script>alert(1)</script>"
        blocked_resp = self._get(test_url)
        if blocked_resp and blocked_resp.status_code in (403, 406, 501):
            self._add_finding(
                category="configuration",
                title="WAF Actively Blocking Malicious Requests",
                description="The server returned HTTP " + str(blocked_resp.status_code) + " for a test XSS payload, "
                            "indicating active WAF protection.",
                severity=Severity.INFO,
                confidence=0.85,
                remediation="No action needed - WAF is actively protecting.",
            )
