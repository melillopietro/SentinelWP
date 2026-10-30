"""
Shared soft-404 heuristics for exposure and compromise-indicator scanners.

Enterprise rule: prefer false negatives over alarming false positives when a
custom theme returns HTTP 200 for missing paths.
"""
from __future__ import annotations

from typing import Any, Optional

SOFT_404_MARKERS = (
    "<title>page not found",
    "<title>404",
    "<title>not found",
    "<title>error 404",
    'class="error404"',
    "class='error404'",
    "not found on this server",
    "the requested url was not found",
    "it looks like nothing was found at this location",
    "page cannot be found",
    "oops! that page can’t be found",
    "oops! that page can't be found",
)


def response_is_soft_404(resp: Optional[Any]) -> bool:
    """
    Return True when a 200 OK body looks like a themed 404 / error page.

    Does not perform network I/O — operates on an already-fetched response.
    """
    if not resp:
        return True
    content_type = (resp.headers.get("content-type") or resp.headers.get("Content-Type") or "").lower()
    body = (resp.text or "").lower() if hasattr(resp, "text") else ""

    if "text/html" in content_type or body.lstrip().startswith("<!doctype") or "<html" in body[:500]:
        if any(marker in body for marker in SOFT_404_MARKERS):
            return True
    return False
