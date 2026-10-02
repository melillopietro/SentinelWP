from core.models import Finding
from core.wordpress_version import (
    extract_wordpress_version,
    is_version_less_than,
    recommended_security_release,
)
from core.vulnerability_intelligence.curated_advisories import seed_curated_advisories
from core.vulnerability_intelligence.service import match_scan_findings


def test_wp_version_ordering_7_1_branch():
    assert is_version_less_than("7.1.1", "7.1.2") is True
    assert is_version_less_than("7.1.2", "7.1.2") is False
    assert recommended_security_release("7.1.0") == "7.1.2"


def test_extract_wordpress_version_prefers_core_detector():
    findings = [
        Finding(
            category="plugins",
            title="Plugin",
            raw_data={"slug": "akismet", "version": "5.3"},
        ),
        Finding(
            category="information_disclosure",
            title="WordPress CMS Detected",
            raw_data={"is_wordpress": True, "version": "7.1.1", "version_source": "meta_generator"},
        ),
    ]
    assert extract_wordpress_version(findings) == "7.1.1"


def test_curated_cve_2026_87902_matches_vulnerable_core(tmp_path, monkeypatch):
    monkeypatch.setenv("WSA_DATABASE_PATH", str(tmp_path / "test.db"))
    from core.vulnerability_intelligence import repository as vuln_repo

    vuln_repo._vuln_conn = None
    vuln_repo.init_vuln_intel_db()
    seed_curated_advisories(force=True)

    matches = match_scan_findings("7.1.1", [])
    cves = {m.get("cve") for m in matches}
    assert "CVE-2026-87902" in cves

    patched = match_scan_findings("7.1.2", [])
    assert not any(m.get("cve") == "CVE-2026-87902" for m in patched)
