from unittest.mock import patch

from core.models import Finding, ScanResult, Severity
from core.scan_pipeline import extract_scan_metadata, finalize_and_score_scan


def test_extract_scan_metadata_ignores_plugin_version():
    findings = [
        Finding(category="plugins", title="Plugin", raw_data={"slug": "akismet", "version": "5.0"}),
        Finding(
            category="information_disclosure",
            title="WordPress CMS Detected",
            raw_data={"is_wordpress": True, "version": "6.4.2", "version_source": "meta_generator"},
        ),
    ]
    is_wp, wp_version, _ = extract_scan_metadata(findings)
    assert is_wp is True
    assert wp_version == "6.4.2"


def test_finalize_and_score_scan_sets_consistent_fields():
    scan = ScanResult(target_url="https://example.com")
    findings = [
        Finding(
            scan_id=scan.id,
            category="exposure",
            title="Test exposure",
            severity=Severity.MEDIUM,
            confidence=0.9,
        )
    ]
    with patch("core.scan_pipeline.apply_vulnerability_intelligence", side_effect=lambda f, *_: f):
        with patch("core.scan_pipeline.add_core_maintenance_findings", side_effect=lambda f, *_: f):
            out = finalize_and_score_scan(findings, scan)
    assert out is scan.findings
    assert scan.score is not None
    assert scan.grade is not None
