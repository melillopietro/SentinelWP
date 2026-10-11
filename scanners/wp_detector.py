"""
WordPress detection and version fingerprinting — multi-signal confidence scoring.

Assigns a confidence score (0.0–1.0) based on multiple independent signals
rather than treating any single indicator as definitive proof.
Fingerprints WordPress core version using verified passive and safe inspection techniques:
- Meta generator tag parsing (all attribute orderings & formats)
- WordPress core scripts and stylesheets (wp-includes)
- RSS / Atom feed generator tags
- Documentation files (readme.html)
- WordPress REST API discovery and namespaces (/wp-json/)
"""
import re
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
from collections import Counter
from scanners.base import BaseScanner
from core.models import Severity

logger = logging.getLogger(__name__)


@dataclass
class WordPressDetectionResult:
    """Strongly-typed detection and fingerprinting result contract."""
    detected: bool = False
    version: Optional[str] = None
    version_source: Optional[str] = None
    version_confidence: Optional[str] = None
    base_url: Optional[str] = None
    confidence_score: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary providing both canonical and backward-compatible alias keys."""
        return {
            "detected": self.detected,
            "wordpress_detected": self.detected,
            "is_wordpress": self.detected,
            "version": self.version,
            "wordpress_version": self.version,
            "wp_version": self.version,
            "version_source": self.version_source,
            "wordpress_version_source": self.version_source,
            "wp_version_source": self.version_source,
            "version_confidence": self.version_confidence,
            "wordpress_version_confidence": self.version_confidence,
            "wp_version_confidence": self.version_confidence,
            "source": self.version_source,
            "confidence": self.version_confidence,
            "wp_confidence": self.confidence_score,
            "confidence_score": self.confidence_score,
            "base_url": self.base_url,
            "evidence": self.evidence,
        }


# Signals and their weights for confidence scoring
_DETECTION_SIGNALS = {
    "meta_generator":   0.35,
    "wp_content":       0.15,
    "wp_includes":      0.15,
    "rest_api_link":    0.15,
    "wp_json_ns":       0.15,
    "wp_cookie":        0.10,
    "wp_login":         0.10,
    "rss_generator":    0.10,
    "core_assets":      0.15,
}

# Version source reliability
_VERSION_CONFIDENCE = {
    "meta_generator":  "high",
    "rss_feed":        "high",
    "asset_ver_param": "high",
    "readme_html":     "medium",
    "rest_api":        "medium",
}

# Precedence policy: explicit generator > feed > core asset > readme > rest_api
SOURCE_PRECEDENCE = {
    "meta_generator": 5,
    "rss_feed": 4,
    "asset_ver_param": 3,
    "readme_html": 2,
    "rest_api": 1,
}

# Known 3rd-party libraries bundled in wp-includes that must NOT be confused with WP core
_EXCLUDED_WP_INCLUDES_SCRIPTS = (
    "jquery", "tinymce", "codemirror", "zxcvbn", "twemoji",
    "imagesloaded", "masonry", "underscore", "backbone",
    "plupload", "cropper", "clipboard", "polyfill", "regenerator",
    "react", "react-dom", "moment", "chart",
)

# Known WordPress Core scripts/styles that carry the core WP version as ?ver=
_CORE_WP_ASSET_REGEXES = [
    re.compile(r'/wp-includes/css/dist/block-library/(?:style|theme)(?:\.min)?\.css[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)', re.IGNORECASE),
    re.compile(r'/wp-includes/css/dashicons(?:\.min)?\.css[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)', re.IGNORECASE),
    re.compile(r'/wp-includes/css/classic-themes(?:\.min)?\.css[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)', re.IGNORECASE),
    re.compile(r'/wp-includes/js/wp-embed(?:\.min)?\.js[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)', re.IGNORECASE),
    re.compile(r'/wp-includes/js/wp-emoji-release(?:\.min)?\.js[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)', re.IGNORECASE),
    re.compile(r'wp-emoji-release(?:\.min)?\.js[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)', re.IGNORECASE),
    re.compile(r'/wp-includes/js/wp-util(?:\.min)?\.js[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)', re.IGNORECASE),
]


def _clean_version(raw: Optional[str]) -> Optional[str]:
    """Clean and validate extracted version candidate."""
    if not raw:
        return None
    val = raw.strip().strip("'\"").strip()
    if not val or not val[0].isdigit():
        return None
    if re.match(r'^\d+(\.\d+)*(?:-[a-zA-Z0-9.]+)?$', val):
        return val
    return None


# DETECT-GAP-001: Bounded list of common subdirectory paths for WordPress installations.
# Only probed when the root returns no WP signals. This list is intentionally conservative
# to avoid unbounded directory enumeration. Users can supply additional paths via the
# WSA_WP_SUBDIR_HINTS environment variable (comma-separated).
_DEFAULT_WP_SUBDIRS = [
    "/blog",
    "/wordpress",
    "/wp",
    "/cms",
    "/site",
]


def _get_subdir_hints() -> List[str]:
    """Return the bounded list of subdirectory hints to try, including user-configured extras."""
    import os
    extra = os.getenv("WSA_WP_SUBDIR_HINTS", "").strip()
    extra_paths = [p.strip() for p in extra.split(",") if p.strip()] if extra else []
    # Normalize: ensure each starts with /
    normalized = [p if p.startswith("/") else f"/{p}" for p in extra_paths]
    # Merge with defaults, deduplicate, cap at 10 to bound requests
    combined = list(dict.fromkeys(_DEFAULT_WP_SUBDIRS + normalized))[:10]
    return combined


class WordPressDetector(BaseScanner):
    # Sprint 3 PHASE 7 (DETECT-GAP-001 gate):
    # Subdirectory probing issues additional HTTP requests beyond the root GET.
    # In passive mode the scanner must not issue extra probes.
    # The orchestrator sets this to True for safe-active and full modes.
    ENABLE_SUBDIR_PROBE: bool = False

    def detect(self) -> WordPressDetectionResult:
        """Execute fingerprinting and return structured WordPressDetectionResult.

        DETECT-GAP-001: If the root-level probe returns no WordPress signals AND
        ENABLE_SUBDIR_PROBE is True (safe-active / full mode), the detector tries
        a bounded list of common subdirectory paths (e.g. /blog, /wordpress, /wp).
        This handles WordPress installations mounted at a path rather than the root.

        In passive mode (ENABLE_SUBDIR_PROBE=False) only the root URL is probed —
        consistent with the single-GET passive contract.  This prevents implicit
        subdirectory enumeration on sites that don't have WP at the root.

        The subdirectory list is intentionally bounded to prevent unbounded
        enumeration.  SSRF protections apply to every probe request.
        """
        raw_detection = self._detect_multi_signal()
        confidence = raw_detection["confidence"]
        evidence = raw_detection["evidence"]
        version_info = raw_detection["version"]
        base_url = raw_detection.get("base_url", self.target_url.rstrip("/"))

        # If nothing found at root AND subdirectory probing is authorized,
        # try common subdirectory paths (DETECT-GAP-001, gated to safe-active+)
        if confidence < 0.15 and self.ENABLE_SUBDIR_PROBE:
            for subdir in _get_subdir_hints():
                candidate_url = self.target_url.rstrip("/") + subdir
                sub_detection = self._detect_multi_signal(override_url=candidate_url)
                if sub_detection["confidence"] >= 0.15:
                    logger.info(
                        "WordPress detected in subdirectory '%s' (confidence %.0f%%) for %s",
                        subdir, sub_detection["confidence"] * 100, self.target_url
                    )
                    confidence = sub_detection["confidence"]
                    evidence = sub_detection["evidence"] + [f"Detected in subdirectory: {subdir}"]
                    version_info = sub_detection["version"]
                    base_url = sub_detection.get("base_url", candidate_url.rstrip("/"))
                    break  # First matching subdirectory wins; stop probing

        is_detected = confidence >= 0.15
        return WordPressDetectionResult(
            detected=is_detected,
            version=version_info["value"] if is_detected else None,
            version_source=version_info["source"] if is_detected else None,
            version_confidence=version_info["confidence"] if is_detected else None,
            base_url=base_url,
            confidence_score=confidence,
            evidence=evidence,
        )

    def scan(self) -> list:
        result = self.detect()

        if result.detected:
            desc = f"WordPress detected at {self.target_url} (confidence: {result.confidence_score:.0%})"
            if result.version:
                desc += f" — Version: {result.version} (source: {result.version_source}, reliability: {result.version_confidence})"

            self._add_finding(
                category="information_disclosure",
                title="WordPress CMS Detected",
                description=desc,
                severity=Severity.INFO,
                confidence=result.confidence_score,
                remediation="Remove version meta tags and generator references from page source.",
                raw_data=result.to_dict()
            )

            if result.version:
                self._add_finding(
                    category="information_disclosure",
                    title=f"WordPress Version Exposed: {result.version}",
                    description=f"WordPress version ({result.version}) is publicly visible. "
                                f"Source: {result.version_source} (reliability: {result.version_confidence}). "
                                f"This enables targeted exploit research.",
                    severity=Severity.MEDIUM,
                    confidence=0.9 if result.version_confidence == "high" else 0.6,
                    remediation="Remove the generator meta tag. Use security plugins to hide version info.",
                    reference="https://developer.wordpress.org/advanced-administration/security/hardening/",
                    raw_data=result.to_dict()
                )

        return self.findings

    def _detect_multi_signal(self, override_url: Optional[str] = None) -> dict:
        """
        Check multiple independent signals and compute an aggregate confidence score.
        Returns dict with: confidence (float), evidence (list[str]), version (dict), base_url (str).

        override_url: if provided, probe this URL instead of self.target_url.
        Used for subdirectory detection (DETECT-GAP-001).
        """
        signals_found = {}
        evidence = []
        version = {"value": None, "source": None, "confidence": None}
        versions_candidates: List[Tuple[str, str, str]] = []  # (value, source, confidence)

        probe_url = (override_url or self.target_url).rstrip("/")
        base_url = probe_url

        # --- Fetch homepage ---
        resp = self._get(probe_url)
        if not resp:
            return {"confidence": 0.0, "evidence": [], "version": version, "base_url": base_url}

        # Follow canonical redirect location if response URL changed
        if getattr(resp, "url", None) and resp.url:
            canonical_base = resp.url.split("?")[0].split("#")[0].rstrip("/")
            if canonical_base.startswith("http"):
                base_url = canonical_base

        body = resp.text or ""
        cookies_str = "; ".join(f"{c.name}" for c in resp.cookies).lower()
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Meta generator tag (check various attribute orderings and quotes)
        meta_gen_matches = list(re.finditer(
            r'<meta\s+[^>]*?(?:name=["\']generator["\'][^>]*?content=["\']WordPress\s*([^"\']*)["\']|content=["\']WordPress\s*([^"\']*)["\'][^>]*?name=["\']generator["\'])[^>]*>',
            body,
            re.IGNORECASE
        ))
        found_gen = False
        for mg in meta_gen_matches:
            found_gen = True
            raw_v = (mg.group(1) or mg.group(2) or "").strip()
            clean_v = _clean_version(raw_v)
            if clean_v:
                versions_candidates.append((clean_v, "meta_generator", "high"))

        if not found_gen:
            simple_meta = re.search(r'<meta[^>]+content=["\']WordPress\s*([^"\']*)["\']', body, re.IGNORECASE)
            if simple_meta:
                found_gen = True
                clean_v = _clean_version(simple_meta.group(1))
                if clean_v:
                    versions_candidates.append((clean_v, "meta_generator", "high"))

        if found_gen:
            signals_found["meta_generator"] = True
            evidence.append("Meta generator tag contains 'WordPress'")

        # 2. Targeted WordPress core assets in /wp-includes/
        core_asset_found = False
        for pat in _CORE_WP_ASSET_REGEXES:
            for m in pat.finditer(body):
                core_asset_found = True
                clean_v = _clean_version(m.group(1))
                if clean_v:
                    versions_candidates.append((clean_v, "asset_ver_param", "high"))

        if core_asset_found:
            signals_found["core_assets"] = True
            evidence.append("WordPress core scripts/stylesheets detected in /wp-includes/")

        # 3. Secondary /wp-includes/ asset check (excluding third-party bundled scripts)
        wp_inc_assets = re.findall(
            r'/wp-includes/(?:css|js)/([^"\'\s>]+)[?&]ver=([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?|\d+)',
            body,
            re.IGNORECASE
        )
        wp_inc_candidates = []
        for asset_path, ver_str in wp_inc_assets:
            lower_path = asset_path.lower()
            if any(exc in lower_path for exc in _EXCLUDED_WP_INCLUDES_SCRIPTS):
                continue
            clean_v = _clean_version(ver_str)
            if clean_v:
                wp_inc_candidates.append(clean_v)

        if wp_inc_candidates:
            most_common_inc = Counter(wp_inc_candidates).most_common(1)[0][0]
            versions_candidates.append((most_common_inc, "asset_ver_param", "medium"))

        # 4. /wp-content/ in HTML
        if "/wp-content/" in body:
            signals_found["wp_content"] = True
            evidence.append("HTML references /wp-content/")

        # 5. /wp-includes/ in HTML
        if "/wp-includes/" in body:
            signals_found["wp_includes"] = True
            evidence.append("HTML references /wp-includes/")

        # 6. REST API discovery link in HTML or HTTP Link header
        link_header = headers.get("link", "")
        if ('rel="https://api.w.org/"' in body or
            "rel='https://api.w.org/'" in body or
            'rel="https://api.w.org/"' in link_header or
            "rel='https://api.w.org/'" in link_header):
            signals_found["rest_api_link"] = True
            evidence.append("REST API discovery link found (<link rel='https://api.w.org/'>)")

        # 7. WordPress cookies
        if any(kw in cookies_str for kw in ("wordpress_", "wp-settings")):
            signals_found["wp_cookie"] = True
            evidence.append("WordPress session cookie detected")

        # 8. /wp-json/ namespace check
        if signals_found.get("rest_api_link") or signals_found.get("wp_content") or signals_found.get("wp_includes"):
            json_resp = self._get(f"{base_url}/wp-json/")
            if json_resp and json_resp.status_code == 200:
                try:
                    data = json_resp.json()
                    if isinstance(data, dict):
                        if "namespaces" in data or "name" in data or "routes" in data:
                            signals_found["wp_json_ns"] = True
                            evidence.append("/wp-json/ returned a WordPress namespace")
                        gm = data.get("generator")
                        if gm and "wordpress" in str(gm).lower():
                            ver_match = re.search(r'([\d.]+(?:-[a-zA-Z0-9.]+)?|\d+)', str(gm))
                            if ver_match:
                                clean_v = _clean_version(ver_match.group(1))
                                if clean_v:
                                    versions_candidates.append((clean_v, "rest_api", "medium"))
                except Exception:
                    pass

        # 9. wp-login.php accessibility
        login_resp = self._head(f"{base_url}/wp-login.php")
        if login_resp and login_resp.status_code == 200:
            signals_found["wp_login"] = True
            evidence.append("wp-login.php is accessible (HTTP 200)")

        # 10. RSS feed generator
        feed_resp = self._get(f"{base_url}/feed/")
        if feed_resp and feed_resp.status_code == 200:
            feed_text = feed_resp.text or ""
            if "wordpress" in feed_text.lower():
                signals_found["rss_generator"] = True
                evidence.append("RSS feed contains WordPress generator reference")
                ver_match = re.search(r'<generator>\s*https?://wordpress\.org/\?v=([^\s<]+)\s*</generator>', feed_text, re.IGNORECASE)
                if not ver_match:
                    ver_match = re.search(r'generator>https?://wordpress\.org/\?v=([\d.]+(?:-[a-zA-Z0-9.]+)?|\d+)<', feed_text, re.IGNORECASE)
                if ver_match:
                    clean_v = _clean_version(ver_match.group(1))
                    if clean_v:
                        versions_candidates.append((clean_v, "rss_feed", "high"))

        # 11. readme.html version
        if signals_found.get("wp_content") or signals_found.get("meta_generator") or signals_found.get("wp_includes"):
            readme_resp = self._get(f"{base_url}/readme.html")
            if readme_resp and readme_resp.status_code == 200 and "wordpress" in (readme_resp.text or "").lower():
                ver_match = re.search(r'(?:<br\s*/?>\s*)?Version\s+([\d.]+(?:-[a-zA-Z0-9.]+)?|\d+)', readme_resp.text, re.IGNORECASE)
                if ver_match:
                    clean_v = _clean_version(ver_match.group(1))
                    if clean_v:
                        versions_candidates.append((clean_v, "readme_html", "medium"))

        # --- Compute aggregate confidence ---
        total_confidence = 0.0
        for signal_name, weight in _DETECTION_SIGNALS.items():
            if signal_name in signals_found:
                total_confidence += weight
        total_confidence = min(1.0, total_confidence)

        # --- Check for multi-source version discrepancies and log precedence application ---
        distinct_versions = {c[0] for c in versions_candidates}
        if len(distinct_versions) > 1:
            sources_list = [c[1] for c in versions_candidates]
            logger.info(
                "Multiple distinct WordPress versions detected: %s from sources: %s. "
                "Applying precedence policy: meta_generator > rss_feed > asset_ver_param > readme_html > rest_api",
                list(distinct_versions),
                sources_list
            )

        # --- Pick best version candidate by reliability and documented precedence ---
        reliability_order = {"high": 3, "medium": 2, "low": 1}
        versions_candidates.sort(
            key=lambda x: (reliability_order.get(x[2], 0), SOURCE_PRECEDENCE.get(x[1], 0)),
            reverse=True
        )
        if versions_candidates:
            best = versions_candidates[0]
            version = {"value": best[0], "source": best[1], "confidence": best[2]}

        return {
            "confidence": round(total_confidence, 2),
            "evidence": evidence,
            "version": version,
            "base_url": base_url,
        }
