"""
WordPress WHOIS Reconnaissance Scanner
- Queries TLD WHOIS servers natively on port 43 (no external dependencies)
- Extracts Domain Registrar and Expiry Date
- Attaches WHOIS information to ScanResult
"""
import re
import socket
from urllib.parse import urlparse
from scanners.base import BaseScanner
from core.models import Severity


def get_root_domain(hostname: str) -> str:
    """Extract root domain to query WHOIS (e.g. sub.example.com -> example.com)"""
    if not hostname:
        return ""
    # Remove www.
    if hostname.lower().startswith("www."):
        hostname = hostname[4:]
    
    parts = hostname.split('.')
    if len(parts) > 2:
        # Common multi-level TLD checks
        if parts[-2] in ("co", "com", "net", "org", "edu", "gov", "mil", "ac"):
            return ".".join(parts[-3:])
        else:
            return ".".join(parts[-2:])
    return hostname


def query_whois_raw(domain: str) -> str:
    """Natively query WHOIS servers on port 43."""
    if not domain:
        return ""
    try:
        # 1. Query IANA for the TLD WHOIS server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.iana.org", 43))
        s.sendall(f"{domain}\r\n".encode("utf-8"))
        
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        
        res_text = response.decode("utf-8", errors="ignore")
        
        # 2. Extract refer whois server
        refer = None
        for line in res_text.splitlines():
            line_str = line.strip().lower()
            if line_str.startswith("refer:") or line_str.startswith("whois:"):
                refer = line.split(":", 1)[1].strip()
                break
        
        if refer:
            # 3. Query the specific WHOIS server
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(5)
            s2.connect((refer, 43))
            s2.sendall(f"{domain}\r\n".encode("utf-8"))
            
            response2 = b""
            while True:
                chunk = s2.recv(4096)
                if not chunk:
                    break
                response2 += chunk
            s2.close()
            return response2.decode("utf-8", errors="ignore")
        
        return res_text
    except Exception as e:
        return f"WHOIS query failed: {str(e)}"


def parse_whois_data(raw_text: str) -> dict:
    """Parse Registrar and Expiry Date from WHOIS raw response."""
    registrar = None
    expiry = None
    lines = raw_text.splitlines()
    for i, line in enumerate(lines):
        line_lower = line.lower().strip()
        
        # Check for Expire Date / Expiry Date / Expiration Date / Expires
        if any(x in line_lower for x in ("expire date", "expiry date", "expiration date", "expires", "expire", "paid-till", "record expires on")):
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    val = parts[1].strip()
                    cleaned = val.split("T")[0].split(" ")[0].strip()
                    if cleaned and not expiry:
                        expiry = cleaned
                        
        # Check for Registrar
        if "registrar" in line_lower:
            has_val = False
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    val = parts[1].strip()
                    if val and not val.lower().startswith("http") and not val.endswith(".net") and not val.endswith(".com"):
                        if not registrar:
                            registrar = val
                            has_val = True
            
            if not has_val:
                # Look ahead up to 5 lines for Organization or Name
                for j in range(i+1, min(i+6, len(lines))):
                    sub_line = lines[j].strip()
                    sub_lower = sub_line.lower()
                    if "organization:" in sub_lower or "name:" in sub_lower:
                        sub_parts = sub_line.split(":", 1)
                        if len(sub_parts) > 1:
                            val = sub_parts[1].strip()
                            if val and not registrar:
                                registrar = val
                                break
                                
    return {
        "registrar": registrar or "Unknown",
        "expiry": expiry or "Unknown"
    }


class WhoisScanner(BaseScanner):
    def scan(self) -> list:
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or self.target_url
        root_domain = get_root_domain(hostname)
        
        self._log("Starting WHOIS lookup", domain=root_domain)
        
        raw_text = query_whois_raw(root_domain)
        parsed_info = parse_whois_data(raw_text)
        
        registrar = parsed_info["registrar"]
        expiry = parsed_info["expiry"]
        whois_str = f"{registrar} (Expires: {expiry})" if registrar != "Unknown" or expiry != "Unknown" else "Unknown"
        
        self._add_finding(
            category="information_disclosure",
            title="WHOIS Information Retrieved",
            description=f"WHOIS lookup succeeded for {root_domain}. Registrar: {registrar} | Expiration Date: {expiry}.",
            severity=Severity.INFO,
            confidence=1.0,
            remediation="No remediation needed. Keep domain registration details updated.",
            raw_data={
                "whois_info": whois_str,
                "registrar": registrar,
                "expiry_date": expiry,
                "raw_whois": raw_text[:2000] # Cap size
            }
        )
        
        return self.findings
