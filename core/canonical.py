"""
URL canonicalization and asset identity helper for SentinelWP Enterprise.
"""
from urllib.parse import urlparse, urlunparse
import re


def canonicalize_url(url: str) -> tuple[str, str]:
    """
    Canonicalize a target URL and extract (canonical_url, hostname).
    Rules:
    - Normalizes scheme (defaults to https:// if missing)
    - Lowercase hostname
    - Strip default ports (80 for http, 443 for https)
    - Strip query parameters and fragments for asset identity
    - Normalize path (remove double slashes, strip trailing slash unless root)
    - Preserve non-root subpath if WordPress resides in a subdirectory
    """
    url = (url or "").strip()
    if not url:
        return "", ""

    # If scheme missing, prepend https://
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc or ""

    # Handle host and port
    if "@" in netloc:
        # Strip credentials if accidentally supplied
        netloc = netloc.split("@")[-1]

    if ":" in netloc:
        host, port_str = netloc.split(":", 1)
        try:
            port = int(port_str)
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = host.lower()
            else:
                netloc = f"{host.lower()}:{port}"
        except ValueError:
            netloc = host.lower()
    else:
        netloc = netloc.lower()

    hostname = netloc.split(":")[0]

    # Normalize path: collapse multi-slashes
    path = parsed.path or ""
    path = re.sub(r"/+", "/", path)

    # Strip trailing slash unless path is just "/"
    if path.endswith("/") and len(path) > 1:
        path = path.rstrip("/")

    # If path is empty, make it empty or root?
    # Standard: root asset is https://example.com (no trailing slash for canonical base)
    if path == "/":
        path = ""

    canonical = urlunparse((scheme, netloc, path, "", "", ""))
    return canonical, hostname
