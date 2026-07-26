"""
WordPress detection and version fingerprinting — multi-signal confidence scoring.

Assigns a confidence score (0.0–1.0) based on multiple independent signals
rather than treating any single indicator as definitive proof.
"""
import re
from scanners.base import BaseScanner
from core.models import Severity


# Signals and their weights for confidence scoring
_DETECTION_SIGNALS = {
    "meta_generator":   0.35,
    "wp_content":       0.15,
    "wp_includes":      0.10,
    "rest_api_link":    0.15,
    "wp_json_ns":       0.10,
    "wp_cookie":        0.05,
    "wp_login":         0.05,
    "rss_generator":    0.05,
}

# Version source reliability
_VERSION_CONFIDENCE = {
    "meta_generator":  "high",
    "rss_feed":        "high",
    "readme_html":     "medium",
    "rest_api":        "medium",
    "asset_ver_param": "low",
}


class WordPressDetector(BaseScanner):
    def scan(self) -> list:
        detection = self._detect_multi_signal()
        confidence = detection["confidence"]
        evidence = detection["evidence"]
        version_info = detection["version"]

        if confidence >= 0.15:
            desc = f"WordPress detected at {self.target_url} (confidence: {confidence:.0%})"
            if version_info["value"]:
                desc += f" — Version: {version_info['value']} (source: {version_info['source']}, reliability: {version_info['confidence']})"

            self._add_finding(
                category="information_disclosure",
                title="WordPress CMS Detected",
                description=desc,
                severity=Severity.INFO,
                confidence=confidence,
                remediation="Remove version meta tags and generator references from page source.",
                raw_data={
                    "is_wordpress": True,
                    "wp_confidence": confidence,
                    "evidence": evidence,
                    "version": version_info["value"],
                    "version_source": version_info["source"],
                    "version_confidence": version_info["confidence"],
                }
            )

            if version_info["value"]:
                self._add_finding(
                    category="information_disclosure",
                    title=f"WordPress Version Exposed: {version_info['value']}",
                    description=f"WordPress version ({version_info['value']}) is publicly visible. "
                                f"Source: {version_info['source']} (reliability: {version_info['confidence']}). "
                                f"This enables targeted exploit research.",
                    severity=Severity.MEDIUM,
                    confidence=0.9 if version_info["confidence"] == "high" else 0.6,
                    remediation="Remove the generator meta tag. Use security plugins to hide version info.",
                    reference="https://developer.wordpress.org/advanced-administration/security/hardening/",
                    raw_data={"version": version_info["value"], "source": version_info["source"]}
                )

        return self.findings

    def _detect_multi_signal(self) -> dict:
        """
        Check multiple independent signals and compute an aggregate confidence score.
        Returns dict with: confidence (float), evidence (list[str]), version (dict).
        """
        signals_found = {}
        evidence = []
        version = {"value": None, "source": None, "confidence": None}
        versions_candidates = []  # (value, source, confidence)

        # --- Fetch homepage ---
        resp = self._get(self.target_url)
        if not resp:
            return {"confidence": 0.0, "evidence": [], "version": version}

        body = resp.text
        cookies_str = "; ".join(f"{c.name}" for c in resp.cookies).lower()

        # 1. Meta generator tag
        meta_match = re.search(r'<meta[^>]+content=["\']WordPress\s*([\d.]*)["\']', body, re.IGNORECASE)
        if meta_match:
            signals_found["meta_generator"] = True
            evidence.append("Meta generator tag contains 'WordPress'")
            ver = meta_match.group(1)
            if ver:
                versions_candidates.append((ver, "meta_generator", "high"))

        # 2. /wp-content/ in HTML
        if "/wp-content/" in body:
            signals_found["wp_content"] = True
            evidence.append("HTML references /wp-content/")

        # 3. /wp-includes/ in HTML
        if "/wp-includes/" in body:
            signals_found["wp_includes"] = True
            evidence.append("HTML references /wp-includes/")

        # 4. REST API discovery link
        if 'rel="https://api.w.org/"' in body or "rel='https://api.w.org/'" in body:
            signals_found["rest_api_link"] = True
            evidence.append("REST API discovery link found (<link rel='https://api.w.org/'>)")

        # 5. WordPress cookies
        if any(kw in cookies_str for kw in ("wordpress_", "wp-settings")):
            signals_found["wp_cookie"] = True
            evidence.append("WordPress session cookie detected")

        # 6. /wp-json/ namespace check
        if signals_found.get("rest_api_link") or signals_found.get("wp_content"):
            json_resp = self._get(f"{self.target_url}/wp-json/")
            if json_resp and json_resp.status_code == 200:
                try:
                    data = json_resp.json()
                    if "namespaces" in data or "name" in data:
                        signals_found["wp_json_ns"] = True
                        evidence.append("/wp-json/ returned a WordPress namespace")
                        # REST API can sometimes reveal version
                        if isinstance(data, dict):
                            gm = data.get("generator")
                            if gm and "wordpress" in str(gm).lower():
                                ver_match = re.search(r'([\d.]+)', str(gm))
                                if ver_match:
                                    versions_candidates.append((ver_match.group(1), "rest_api", "medium"))
                except (ValueError, KeyError):
                    pass

        # 7. wp-login.php accessibility
        login_resp = self._head(f"{self.target_url}/wp-login.php")
        if login_resp and login_resp.status_code == 200:
            signals_found["wp_login"] = True
            evidence.append("wp-login.php is accessible (HTTP 200)")

        # 8. RSS feed generator
        feed_resp = self._get(f"{self.target_url}/feed/")
        if feed_resp and feed_resp.status_code == 200:
            feed_text = feed_resp.text
            if "wordpress" in feed_text.lower():
                signals_found["rss_generator"] = True
                evidence.append("RSS feed contains WordPress generator reference")
                ver_match = re.search(r'generator>https?://wordpress\.org/\?v=([\d.]+)<', feed_text)
                if ver_match:
                    versions_candidates.append((ver_match.group(1), "rss_feed", "high"))

        # --- Extract ?ver= from assets (low confidence, could be theme/plugin) ---
        ver_params = re.findall(r'[?&]ver=([\d.]+)', body)
        if ver_params and signals_found:
            # Only consider if other WP signals exist; pick most common
            from collections import Counter
            common = Counter(ver_params).most_common(1)[0]
            versions_candidates.append((common[0], "asset_ver_param", "low"))

        # --- readme.html version (medium confidence) ---
        if signals_found.get("wp_content") or signals_found.get("meta_generator"):
            readme_resp = self._get(f"{self.target_url}/readme.html")
            if readme_resp and readme_resp.status_code == 200 and "wordpress" in readme_resp.text.lower():
                ver_match = re.search(r"Version\s+([\d.]+)", readme_resp.text)
                if ver_match:
                    versions_candidates.append((ver_match.group(1), "readme_html", "medium"))

        # --- Compute aggregate confidence ---
        total_confidence = 0.0
        for signal_name, weight in _DETECTION_SIGNALS.items():
            if signal_name in signals_found:
                total_confidence += weight
        total_confidence = min(1.0, total_confidence)

        # --- Pick best version candidate (prefer highest confidence) ---
        reliability_order = {"high": 3, "medium": 2, "low": 1}
        versions_candidates.sort(key=lambda x: reliability_order.get(x[2], 0), reverse=True)
        if versions_candidates:
            best = versions_candidates[0]
            version = {"value": best[0], "source": best[1], "confidence": best[2]}

        return {
            "confidence": round(total_confidence, 2),
            "evidence": evidence,
            "version": version,
        }
