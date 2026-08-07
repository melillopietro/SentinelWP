"""
Passive DNS Security Posture Scanner (SPF & DMARC)
- Uses public Google DNS-over-HTTPS (DoH) API to query TXT records
- Checks for existence and validity of SPF (Sender Policy Framework) record
- Checks for existence and enforcement level of DMARC record
"""
from urllib.parse import urlparse
from scanners.base import BaseScanner
from core.models import Severity


class DNSScanner(BaseScanner):
    def scan(self) -> list:
        parsed = urlparse(self.target_url)
        domain = parsed.hostname or self.target_url
        if domain.lower().startswith("www."):
            domain = domain[4:]
            
        self._log("Starting DNS security check", domain=domain)
        
        self._check_spf(domain)
        self._check_dmarc(domain)
        return self.findings

    def _query_doh_txt(self, name: str) -> list:
        """Query DNS TXT records using Google's DNS-over-HTTPS API."""
        url = f"https://dns.google/resolve?name={name}&type=TXT"
        try:
            resp = self._get(url, timeout=5)
            if resp and resp.status_code == 200:
                data = resp.json()
                records = []
                for answer in data.get("Answer", []):
                    if answer.get("type") == 16:  # TXT record type
                        val = answer.get("data", "")
                        # Google DoH might wrap TXT records in quotes
                        records.append(val.strip('"'))
                return records
        except Exception as e:
            self._log(f"DoH query failed for {name}: {str(e)}")
        return []

    def _check_spf(self, domain: str):
        records = self._query_doh_txt(domain)
        spf_records = [r for r in records if r.lower().startswith("v=spf1")]
        
        if not spf_records:
            self._add_finding(
                category="encryption",
                title="Missing SPF Record",
                description=f"Domain {domain} is missing an SPF (Sender Policy Framework) TXT record. "
                            "Spammers can spoof email originating from this domain, damaging brand reputation.",
                severity=Severity.HIGH,
                confidence=0.95,
                remediation="Create a TXT record for the domain with a valid SPF configuration (e.g., 'v=spf1 include:_spf.example.com ~all').",
                reference="https://support.google.com/a/answer/33786",
                raw_data={"spf_present": False}
            )
        else:
            self._add_finding(
                category="encryption",
                title="SPF Record Configured",
                description=f"Domain {domain} has SPF configured: '{spf_records[0]}'",
                severity=Severity.INFO,
                confidence=0.95,
                remediation="Ensure the SPF records accurately reflect all authorized sending IPs and services.",
                raw_data={"spf_present": True, "spf_record": spf_records[0]}
            )

    def _check_dmarc(self, domain: str):
        dmarc_domain = f"_dmarc.{domain}"
        records = self._query_doh_txt(dmarc_domain)
        dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]
        
        if not dmarc_records:
            self._add_finding(
                category="encryption",
                title="Missing DMARC Record",
                description=f"Domain {domain} is missing a DMARC record. "
                            "This increases vulnerability to email phishing, spoofing, and brand abuse.",
                severity=Severity.HIGH,
                confidence=0.95,
                remediation="Add a TXT record at _dmarc.yourdomain.com with policy settings, e.g., 'v=DMARC1; p=quarantine; pct=100; rua=mailto:security@yourdomain.com'.",
                reference="https://dmarc.org/",
                raw_data={"dmarc_present": False}
            )
        else:
            record = dmarc_records[0]
            # Parse policy setting p=...
            p = "unknown"
            if "p=reject" in record.lower():
                p = "reject"
            elif "p=quarantine" in record.lower():
                p = "quarantine"
            elif "p=none" in record.lower():
                p = "none"
                
            severity = Severity.LOW if p in ("reject", "quarantine") else Severity.MEDIUM
            desc = f"DMARC record found for {domain}: '{record}'. Policy is set to '{p}'."
            if p == "none":
                desc += " A policy of 'none' does not block or quarantine unauthorized emails (only monitor)."
                
            self._add_finding(
                category="encryption",
                title=f"DMARC Configured (Policy: {p.upper()})",
                description=desc,
                severity=severity,
                confidence=0.95,
                remediation="If the policy is set to 'none', plan to migrate to 'quarantine' or 'reject' to prevent domain spoofing.",
                reference="https://dmarc.org/",
                raw_data={"dmarc_present": True, "dmarc_record": record, "policy": p}
            )
