"""
Scan submission guardrails shared by web and API enqueue paths.
Uses the same SSRF policy as scanner execution (is_safe_target_url).
"""
from __future__ import annotations

from scanners.base import is_safe_target_url


def validate_scan_target_for_submission(target_url: str) -> tuple[bool, str]:
    """
    Fail-closed target validation before Scan / ScanJob persistence or Celery enqueue.

    Returns (allowed, client_message). When allowed is False, client_message is safe
    to show to analysts (no internal secrets).
    """
    safe, reason = is_safe_target_url(target_url, resolve_dns=True)
    if safe:
        return True, ""
    msg = (reason or "Target URL blocked by security policy.").strip()
    if not msg.lower().startswith("target"):
        msg = f"Target blocked: {msg}"
    return False, msg
