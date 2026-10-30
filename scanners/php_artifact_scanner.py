"""
PHP artifact / webshell indicator scanner (read-only, safe-active / full).

Enterprise constraints:
  - Does not execute uploaded code.
  - Bounded probe budget (predictable request count).
  - Soft-404 site detection aborts probing to avoid mass false positives.
  - Findings require manual verification — never "confirmed compromise" from HTTP alone.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from core.models import Severity
from scanners.base import BaseScanner
from scanners.php_artifact_signatures import analyze_php_artifact
from scanners.soft404 import response_is_soft_404


def default_probe_paths(now: datetime | None = None) -> List[str]:
    """Bounded, year-aware probe set (uploads + common drop locations)."""
    year = (now or datetime.now(timezone.utc)).year
    years = sorted({year, year - 1})
    paths: List[str] = [
        "/shell.php",
        "/c99.php",
        "/r57.php",
        "/wso.php",
        "/b374k.php",
        "/alfa.php",
        "/cmd.php",
        "/x.php",
        "/wp-content/uploads/shell.php",
        "/wp-content/uploads/x.php",
        "/wp-content/uploads/temp.php",
        "/wp-content/uploads/cmd.php",
        "/wp-content/plugins/shell.php",
        "/wp-includes/shell.php",
    ]
    for y in years:
        paths.extend(
            [
                f"/wp-content/uploads/{y}/shell.php",
                f"/wp-content/uploads/{y}/x.php",
                f"/wp-content/uploads/{y}/01/shell.php",
            ]
        )
    # Deduplicate while preserving order
    seen = set()
    ordered: List[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


# Stable export for docs / tests
DEFAULT_PROBE_PATHS: List[str] = default_probe_paths()


class PhpArtifactScanner(BaseScanner):
    """Detect publicly reachable suspicious PHP files (manual verification required)."""

    MAX_BODY_BYTES = 65536
    MAX_PROBES = 24

    def scan(self) -> list:
        import uuid

        canary = (
            f"{self.target_url.rstrip('/')}/wp-content/plugins/sentinelwp-canary-{uuid.uuid4().hex[:8]}/"
        )
        # Site-wide soft-404: abort — every probe would look like a hit.
        if self.is_soft_404(canary):
            return self.findings

        probes = default_probe_paths()[: self.MAX_PROBES]
        for rel in probes:
            url = f"{self.target_url.rstrip('/')}{rel}"
            resp = self._get(url)
            if not resp or resp.status_code != 200:
                continue

            if response_is_soft_404(resp):
                continue

            body = resp.text or ""
            ctype = (resp.headers.get("Content-Type") or "").lower()

            # Skip generic HTML pages that are not PHP source / shell UIs.
            # Obfuscated shells often still contain <?php or signature primitives.
            if "text/html" in ctype and "<?php" not in body[:1200]:
                # Allow through if strong content signatures may still apply later
                # (analyze_php_artifact will return none without evidence).
                pass

            if len(body.encode("utf-8", errors="ignore")) > self.MAX_BODY_BYTES:
                body = body[: self.MAX_BODY_BYTES]

            assessment = analyze_php_artifact(rel, body)
            if assessment.verdict == "none":
                continue

            if assessment.verdict == "likely_artifact":
                title = f"Likely PHP webshell artifact: {rel}"
                severity = Severity.CRITICAL
            else:
                title = f"Suspicious PHP artifact (verify manually): {rel}"
                severity = Severity.HIGH

            desc = (
                "A publicly reachable PHP resource matched conservative webshell heuristics. "
                "This is not a confirmed compromise — validate on the server (filesystem hash, "
                "EDR, backup comparison) before incident escalation."
            )
            if assessment.signature_hits:
                desc += f" Signature hits: {', '.join(assessment.signature_hits)}."

            self._add_finding(
                category="compromise_indicator",
                title=title,
                description=desc,
                severity=severity,
                confidence=assessment.confidence,
                remediation=(
                    "Quarantine the file, preserve forensic copies, rotate credentials if confirmed "
                    "malicious, and review upload/WAF controls. Do not execute the file for analysis."
                ),
                reference="https://owasp.org/www-community/attacks/Webshell",
                raw_data={
                    "path": rel,
                    "url": url,
                    "verdict": assessment.verdict,
                    "signature_hits": assessment.signature_hits,
                    "verification_required": assessment.verification_required,
                    "detection_method": "php_artifact_probe",
                    "rationale": assessment.rationale,
                    "content_redacted": True,
                },
            )

        return self.findings
