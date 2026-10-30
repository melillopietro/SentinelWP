"""
Conservative PHP webshell / backdoor artifact heuristics.

Enterprise policy: never claim definitive compromise from HTTP content alone.
Findings require manual verification (filesystem, EDR, backup diff).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

# Filenames commonly dropped by attackers (not normal WordPress core paths).
KNOWN_SUSPICIOUS_FILENAMES = frozenset(
    {
        "c99.php",
        "r57.php",
        "wso.php",
        "wso2.php",
        "b374k.php",
        "alfa.php",
        "indoxploit.php",
        "mini.php",
        "x.php",
        "xx.php",
        "up.php",
        "uploader.php",
        "cmd.php",
        "backdoor.php",
        "shell.php",
        "phpshell.php",
        "p.php",
        "1.php",
        "404.php",
        "about.php",
    }
)

# Strong obfuscation / execution chains (each hit is meaningful).
STRONG_CONTENT_PATTERNS: Sequence[Tuple[re.Pattern[str], str]] = (
    (re.compile(r"eval\s*\(\s*base64_decode\s*\(", re.I), "eval_base64_decode"),
    (re.compile(r"eval\s*\(\s*gzinflate\s*\(", re.I), "eval_gzinflate"),
    (re.compile(r"eval\s*\(\s*str_rot13\s*\(", re.I), "eval_str_rot13"),
    (re.compile(r"assert\s*\(\s*\$\{?", re.I), "assert_dynamic"),
    (re.compile(r"preg_replace\s*\([^)]*\/e['\"]", re.I), "preg_replace_e_modifier"),
    (re.compile(r"\$\w+\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE)", re.I), "dynamic_superglobal_call"),
    (re.compile(r"(shell_exec|passthru|proc_open|popen)\s*\(", re.I), "shell_process_primitive"),
    (re.compile(r"move_uploaded_file\s*\(\s*\$\_(FILES|POST)", re.I), "upload_handler_superglobal"),
    (re.compile(r"(FilesMan|WSO\s*2|b374k|C99Shell|r57shell)", re.I), "known_shell_branding"),
)

# Legitimate WordPress/plugin markers — suppress content-only alerts.
LEGITIMATE_MARKERS = (
    "Plugin Name:",
    "Theme Name:",
    "WordPress",
    "wp_enqueue_script",
    "ABSPATH",
)


@dataclass(frozen=True)
class PhpArtifactAssessment:
    """Structured result for scanners and validation reports."""

    verdict: str  # none | indicator | likely_artifact
    confidence: float
    signature_hits: List[str]
    filename: str
    verification_required: bool
    rationale: str


def _basename(path: str) -> str:
    return path.rstrip("/").split("/")[-1].lower()


def analyze_php_artifact(path: str, body: str, max_scan_bytes: int = 65536) -> PhpArtifactAssessment:
    """
    Analyze response body for webshell indicators.

    Returns 'none' when evidence is insufficient — prefer false negatives over alarmist FP.
    """
    filename = _basename(path)
    snippet = (body or "")[:max_scan_bytes]
    lower = snippet.lower()

    if not snippet.strip():
        return PhpArtifactAssessment(
            verdict="none",
            confidence=0.0,
            signature_hits=[],
            filename=filename,
            verification_required=False,
            rationale="empty_body",
        )

    # HTML error pages are not PHP artifacts.
    if "<!doctype html" in lower or ("<html" in lower and "<?php" not in lower[:500]):
        return PhpArtifactAssessment(
            verdict="none",
            confidence=0.0,
            signature_hits=[],
            filename=filename,
            verification_required=False,
            rationale="html_not_php",
        )

    hits = [name for pattern, name in STRONG_CONTENT_PATTERNS if pattern.search(snippet)]
    has_legit_marker = any(m in snippet for m in LEGITIMATE_MARKERS)
    known_name = filename in KNOWN_SUSPICIOUS_FILENAMES

    if known_name and len(hits) >= 2:
        return PhpArtifactAssessment(
            verdict="likely_artifact",
            confidence=0.92,
            signature_hits=hits,
            filename=filename,
            verification_required=True,
            rationale="known_filename_and_strong_signatures",
        )

    if known_name and len(hits) == 1:
        return PhpArtifactAssessment(
            verdict="indicator",
            confidence=0.78,
            signature_hits=hits,
            filename=filename,
            verification_required=True,
            rationale="known_filename_and_one_signature",
        )

    if known_name and "<?php" in snippet and not has_legit_marker:
        return PhpArtifactAssessment(
            verdict="indicator",
            confidence=0.72,
            signature_hits=hits,
            filename=filename,
            verification_required=True,
            rationale="known_filename_suspicious_php",
        )

    if not known_name and len(hits) >= 3 and not has_legit_marker:
        return PhpArtifactAssessment(
            verdict="likely_artifact",
            confidence=0.88,
            signature_hits=hits,
            filename=filename,
            verification_required=True,
            rationale="multiple_strong_signatures",
        )

    if not known_name and len(hits) == 2 and not has_legit_marker:
        return PhpArtifactAssessment(
            verdict="indicator",
            confidence=0.65,
            signature_hits=hits,
            filename=filename,
            verification_required=True,
            rationale="dual_signatures",
        )

    return PhpArtifactAssessment(
        verdict="none",
        confidence=0.0,
        signature_hits=hits,
        filename=filename,
        verification_required=False,
        rationale="insufficient_evidence",
    )
