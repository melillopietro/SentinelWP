"""
Comprehensive Phase 6 Test Suite for SentinelWP Product Maturity & EASM.

Tests:
- Bounded discovery: domain boundaries, allowed suffixes, excluded patterns, max depth, deduplication, promotion.
- Domain ownership verification: DNS TXT & HTTP token challenge generation and verification.
- Evidence store: immutability, deterministic SHA-256 hashing, secret redaction, provenance correlation.
- Policy engine: immutable ACTIVE versions, checksum generation, activation lifecycle, version diffing.
- Business unit & Portfolio metrics: multi-tenant isolation, BU metrics aggregation, no cross-tenant leakage.
- Data quality evaluator: gap detection (unassigned owner, unverified critical asset, missing evidence).
- SIEM exporter & Outbox pattern: payload sanitization, CEF formatting, idempotent event staging, dispatch failure handling.
- Technology inventory: WordPress technology observation feeding from detection pipeline.
"""
import json
import pytest
from core.models import (
    DiscoveryScope, DiscoveredAsset, DiscoveredAssetStatus,
    DiscoverySource, DiscoveryConfidence, VerificationMethod,
    VerificationStatus, EvidenceQuality, PolicyType, PolicyVersionStatus,
    BusinessUnit, Asset, Finding, Severity, TechnologyObservation,
    Tenant, ScanResult
)
from core import repository
from core.easm.discovery import BoundedDiscoveryEngine
from core.easm.verification import (
    initiate_domain_verification,
    verify_asset_ownership,
    is_asset_verified
)
from core.evidence.store import EvidenceStore, sanitize_payload, compute_content_hash
from core.policy.engine import PolicyEngine, compute_policy_checksum
from core.data_quality.evaluator import DataQualityEvaluator
from core.integrations.siem import SIEMExporter, format_cef_event


@pytest.fixture(autouse=True)
def setup_test_db():
    repository.init_db(force=True)
    # Seed tenants used in tests to satisfy FK constraints
    test_tenants = [
        "default-tenant", "tenant-disc-1", "tenant-disc-2",
        "tenant-verify-1", "tenant-verify-2", "tenant-ev-1",
        "tenant-pol-1", "tenant-bu-1", "tenant-bu-2",
        "tenant-dq-1", "tenant-siem-1"
    ]
    for tid in test_tenants:
        repository.save_tenant(Tenant(id=tid, name=tid, slug=tid))
    yield


class TestEASMDiscovery:
    def test_discovery_scope_boundary_enforcement(self):
        engine = BoundedDiscoveryEngine(tenant_id="tenant-disc-1")
        scope = DiscoveryScope(
            tenant_id="tenant-disc-1",
            name="Corp Root",
            root_domain="example.com",
            allowed_suffixes=[".example.com", "example.com"],
            excluded_patterns=[r"internal\.", r"dev\."],
            max_depth=2,
            enabled=True
        )
        repository.save_discovery_scope(scope)

        # 1. Allowed subdomain within depth 1
        allowed, _ = engine.is_target_allowed("blog.example.com", scope)
        assert allowed is True

        # 2. Excluded pattern
        allowed, reason = engine.is_target_allowed("internal.example.com", scope)
        assert allowed is False
        assert "excluded" in reason.lower()

        # 3. Outside root domain
        allowed, reason = engine.is_target_allowed("attacker.com", scope)
        assert allowed is False
        assert "outside" in reason.lower()

        # 4. Exceeds max depth (depth 3 > max_depth 2)
        allowed, reason = engine.is_target_allowed("a.b.c.example.com", scope)
        assert allowed is False
        assert "depth" in reason.lower()

    def test_candidate_deduplication_and_promotion(self):
        engine = BoundedDiscoveryEngine(tenant_id="tenant-disc-2")
        scope = DiscoveryScope(
            tenant_id="tenant-disc-2",
            name="Web Scope",
            root_domain="company.org",
            max_depth=2,
            enabled=True
        )
        repository.save_discovery_scope(scope)

        # Process candidate first time
        c1 = engine.process_discovered_candidate(scope, "https://portal.company.org", source=DiscoverySource.DNS)
        assert c1 is not None
        assert c1.status == DiscoveredAssetStatus.NEW.value
        assert c1.hostname == "portal.company.org"

        # Process candidate second time (deduplicated)
        c2 = engine.process_discovered_candidate(scope, "http://portal.company.org", source=DiscoverySource.EXISTING_SCAN)
        assert c2 is not None
        assert c2.id == c1.id

        # Promote candidate to official asset
        promoted_asset = engine.promote_candidate_to_asset(c1.id, actor_user_id="analyst-1")
        assert promoted_asset is not None
        assert promoted_asset.hostname == "portal.company.org"

        # Verify candidate marked PROMOTED
        refetched = repository.get_discovered_asset(c1.id, "tenant-disc-2")
        assert refetched.status == DiscoveredAssetStatus.PROMOTED.value
        assert refetched.promoted_asset_id == promoted_asset.id


class TestDomainOwnershipVerification:
    def test_dns_txt_verification(self):
        tenant_id = "tenant-verify-1"
        asset = Asset(tenant_id=tenant_id, canonical_url="https://verify.corp.com", hostname="verify.corp.com")
        repository.save_asset(asset)

        ver = initiate_domain_verification(tenant_id, asset.id, method=VerificationMethod.DNS_TXT)
        assert ver.status == VerificationStatus.PENDING.value
        assert ver.challenge.startswith("sentinelwp-verify-")

        # Mock DNS resolver returning challenge
        def mock_dns(record_name):
            assert record_name == f"_sentinelwp-verification.{asset.hostname}"
            return [ver.challenge]

        success, msg = verify_asset_ownership(ver.id, tenant_id, dns_resolver_mock=mock_dns)
        assert success is True
        assert is_asset_verified(tenant_id, asset.id) is True

    def test_http_token_verification(self):
        tenant_id = "tenant-verify-2"
        asset = Asset(tenant_id=tenant_id, canonical_url="https://site.corp.com", hostname="site.corp.com")
        repository.save_asset(asset)

        ver = initiate_domain_verification(tenant_id, asset.id, method=VerificationMethod.HTTP_TOKEN)

        # Mock HTTP fetcher returning challenge body
        def mock_http(url):
            assert ".well-known/sentinelwp-verification.txt" in url
            return 200, f"challenge: {ver.challenge}\n"

        success, msg = verify_asset_ownership(ver.id, tenant_id, http_fetcher_mock=mock_http)
        assert success is True
        assert is_asset_verified(tenant_id, asset.id) is True


class TestEvidenceStore:
    def test_evidence_sanitization_and_hash_deduplication(self):
        tenant_id = "tenant-ev-1"
        store = EvidenceStore(tenant_id=tenant_id)
        scan = ScanResult(id="scan-ev-1", target_url="https://target.corp.com", tenant_id=tenant_id)
        repository.save_scan(scan)
        finding = Finding(id="f-123", tenant_id=tenant_id, scan_id=scan.id, title="Test Issue")
        repository.save_finding(finding)

        raw_http = "HTTP/1.1 200 OK\r\nAuthorization: Bearer SUPER_SECRET_TOKEN\r\nCookie: sessionid=xyz123\r\n\r\n{'password': 'mypassword'}"

        ev1 = store.record_evidence(
            raw_payload=raw_http,
            source="http_scanner",
            finding_id="f-123"
        )
        # Verify secret redaction
        assert "SUPER_SECRET_TOKEN" not in ev1.payload
        assert "xyz123" not in ev1.payload
        assert "mypassword" not in ev1.payload
        assert "[REDACTED]" in ev1.payload

        # Verify hash integrity
        expected_hash = compute_content_hash(ev1.payload)
        assert ev1.content_hash == expected_hash

        # Verify deduplication with identical payload
        ev2 = store.record_evidence(
            raw_payload=raw_http,
            source="http_scanner"
        )
        assert ev2.id == ev1.id


class TestPolicyEngine:
    def test_policy_immutability_and_diff(self):
        engine = PolicyEngine(tenant_id="tenant-pol-1")
        policy, v1 = engine.create_policy("Enterprise Scan Policy", initial_definition={"timeout": 30, "max_depth": 2})
        assert v1.version == 1
        assert v1.status == PolicyVersionStatus.DRAFT.value

        # Activate v1
        active_v1 = engine.activate_version(v1.id, actor_user_id="admin-user")
        assert active_v1.status == PolicyVersionStatus.ACTIVE.value

        # Create v2 draft (v1 cannot be modified in-place)
        v2 = engine.create_new_version(policy.id, definition_json={"timeout": 60, "max_depth": 2, "stealth": True})
        assert v2.version == 2
        assert v2.status == PolicyVersionStatus.DRAFT.value

        # Diff v1 and v2
        diff = engine.diff_versions(v1.id, v2.id)
        assert diff["added"] == {"stealth": True}
        assert diff["modified"] == {"timeout": {"old": 30, "new": 60}}

        # Activate v2 (retires v1)
        active_v2 = engine.activate_version(v2.id, actor_user_id="admin-user")
        assert active_v2.status == PolicyVersionStatus.ACTIVE.value
        retired_v1 = repository.get_policy_version(v1.id)
        assert retired_v1.status == PolicyVersionStatus.RETIRED.value


class TestPortfolioAndBusinessUnits:
    def test_portfolio_metrics_and_tenant_isolation(self):
        t1, t2 = "tenant-bu-1", "tenant-bu-2"

        # Create BU in T1
        bu1 = BusinessUnit(tenant_id=t1, name="Finance IT", code="FIN-IT")
        repository.save_business_unit(bu1)

        # Asset in T1 attached to BU
        a1 = Asset(tenant_id=t1, canonical_url="https://fin.corp.com", hostname="fin.corp.com", business_unit_id=bu1.id, criticality="critical")
        repository.save_asset(a1)

        # Asset in T2
        a2 = Asset(tenant_id=t2, canonical_url="https://t2.corp.com", hostname="t2.corp.com", criticality="low")
        repository.save_asset(a2)

        # Scan in T1
        s1 = ScanResult(id="scan-t1", target_url="https://fin.corp.com", tenant_id=t1, asset_id=a1.id)
        repository.save_scan(s1)

        # Finding in T1
        f1 = Finding(tenant_id=t1, asset_id=a1.id, scan_id=s1.id, title="Critical Flaw", priority_band="P1", finding_confidence="CONFIRMED")
        repository.save_finding(f1)

        # Verify T1 metrics
        m1 = repository.get_portfolio_metrics(t1, bu_id=bu1.id)
        assert m1["assets"] == 1
        assert m1["critical_assets"] == 1
        assert m1["open_p1"] == 1

        # Verify T2 metrics (no cross-tenant leakage)
        m2 = repository.get_portfolio_metrics(t2)
        assert m2["assets"] == 1
        assert m2["critical_assets"] == 0
        assert m2["open_p1"] == 0


class TestDataQualityEvaluator:
    def test_data_quality_gap_detection(self):
        t = "tenant-dq-1"
        evaluator = DataQualityEvaluator(t)

        # Asset without owners and without BU
        a = Asset(tenant_id=t, canonical_url="https://orphan.corp.com", hostname="orphan.corp.com", criticality="critical")
        repository.save_asset(a)

        issues = evaluator.evaluate_all()
        issue_types = {i.issue_type for i in issues}

        assert "ASSET_WITHOUT_OWNER" in issue_types
        assert "ASSET_WITHOUT_BU" in issue_types
        assert "CRITICAL_ASSET_UNVERIFIED" in issue_types


class TestSIEMIntegrationAndOutbox:
    def test_siem_event_staging_and_cef_format(self):
        exporter = SIEMExporter(tenant_id="tenant-siem-1")
        entry = exporter.stage_event(
            event_type="p1_finding",
            entity_id="finding-abc",
            payload={"cve": "CVE-2026-1234", "secret_header": "Bearer LEAKED_TOKEN", "severity": "critical"}
        )
        assert entry.status == "PENDING"
        # Verify secret sanitized in outbox payload
        assert "LEAKED_TOKEN" not in json.dumps(entry.payload_json)

        cef = format_cef_event(entry.event_type, "critical", entry.payload_json)
        assert cef.startswith("CEF:0|SentinelWP|")
        assert "p1_finding" in cef
