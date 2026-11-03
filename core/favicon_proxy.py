"""
Safe favicon resolution for registered assets.

Never fetches arbitrary user-supplied URLs. Only hostnames from tenant-owned
assets are used, and outbound requests go through public icon CDNs or a
SSRF-validated origin fetch as a last resort.
"""
from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import requests

from core.scan_submission import validate_scan_target_for_submission

logger = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "favicon_cache"
_CACHE_TTL = 7 * 24 * 3600  # 7 days
_TIMEOUT = 4
_MAX_BYTES = 128 * 1024

# 1x1 transparent PNG fallback
_FALLBACK_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _hostname_from_asset_url(canonical_url: str, hostname: str = "") -> str:
    host = (hostname or "").strip().lower()
    if host:
        return host.split(":")[0]
    try:
        parsed = urlparse(canonical_url if "://" in canonical_url else f"https://{canonical_url}")
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _cache_path(hostname: str) -> Path:
    digest = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:32]
    return _CACHE_DIR / f"{digest}.bin"


def _read_cache(hostname: str) -> Optional[Tuple[bytes, str]]:
    path = _cache_path(hostname)
    meta = path.with_suffix(".meta")
    if not path.exists() or not meta.exists():
        return None
    try:
        age = time.time() - path.stat().st_mtime
        if age > _CACHE_TTL:
            return None
        ctype = meta.read_text(encoding="utf-8").strip() or "image/png"
        return path.read_bytes(), ctype
    except Exception:
        return None


def _write_cache(hostname: str, data: bytes, content_type: str) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _cache_path(hostname)
        path.write_bytes(data)
        path.with_suffix(".meta").write_text(content_type or "image/png", encoding="utf-8")
    except Exception as exc:
        logger.debug("favicon cache write failed: %s", exc)


def _fetch_bytes(url: str) -> Optional[Tuple[bytes, str]]:
    try:
        resp = requests.get(
            url,
            timeout=_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "SentinelWP-Favicon/5.0"},
            stream=True,
        )
        if resp.status_code != 200:
            return None
        ctype = (resp.headers.get("Content-Type") or "image/png").split(";")[0].strip()
        if not ctype.startswith("image/") and "icon" not in ctype and ctype != "application/octet-stream":
            return None
        buf = b""
        for chunk in resp.iter_content(8192):
            buf += chunk
            if len(buf) > _MAX_BYTES:
                return None
        if len(buf) < 16:
            return None
        return buf, ctype if ctype.startswith("image/") else "image/png"
    except Exception:
        return None


def resolve_favicon(canonical_url: str, hostname: str = "") -> Tuple[bytes, str]:
    """
    Return (bytes, content_type) for an asset favicon.
    Always returns a valid image (transparent PNG fallback).
    """
    host = _hostname_from_asset_url(canonical_url, hostname)
    if not host or host in ("localhost", "127.0.0.1", "::1"):
        return _FALLBACK_PNG, "image/png"

    cached = _read_cache(host)
    if cached:
        return cached

    # Prefer public icon CDNs (hostname only — no SSRF to private ranges).
    candidates = [
        f"https://www.google.com/s2/favicons?domain={host}&sz=64",
        f"https://icons.duckduckgo.com/ip3/{host}.ico",
    ]

    # Optional direct fetch only when the asset URL itself is SSRF-safe.
    origin = canonical_url if "://" in (canonical_url or "") else f"https://{host}"
    allowed, _ = validate_scan_target_for_submission(origin)
    if allowed:
        candidates.extend(
            [
                f"https://{host}/favicon.ico",
                f"https://{host}/favicon.png",
            ]
        )

    for url in candidates:
        hit = _fetch_bytes(url)
        if hit:
            _write_cache(host, hit[0], hit[1])
            return hit

    _write_cache(host, _FALLBACK_PNG, "image/png")
    return _FALLBACK_PNG, "image/png"
