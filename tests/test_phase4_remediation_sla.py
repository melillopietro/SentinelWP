"""
Phase 4 Enterprise Test Suite:
Exposure Management, Vulnerability Prioritization, Finding Lifecycle,
Remediation Governance, SLA Management, Risk Acceptance, Ticketing,
Webhooks, Scoped API Keys, and Multi-Tenant Isolation.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import uuid
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from app import app
from core import repository
from core.models import (
    Tenant, Asset, ScanResult, Finding, Severity, ScanStatus,
    SLAPolicy, RiskAcceptance, Integration,
    FindingObservation, Remediation, APIKey
)
from core.fingerprint import compute_finding_fingerprint
from core.prioritization import calculate_priority_score
from core.sla import calculate_sla_due_date, evaluate_finding_sla_status
from core.lifecycle import (
    FindingStatus, SLAStatus, InvalidStateTransitionError, OptimisticLockError
)
from core.api_auth import generate_api_key, verify_api_key
from core.integrations.webhook import compute_webhook_signature, deliver_webhook_payload
from core.integrations.jira import JiraIntegration
from core.tasks.remediation_tasks import (
    evaluate_sla_breaches,
    expire_risk_acceptances,
    generate_daily_risk_snapshot,
)


class TestPhase4ExposureAndRemediationGovernance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository.init_db()

    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

        # Two distinct workspaces to test tenant isolation & IDOR
        self.tenant_a = f"tenant-alpha-{uuid.uuid4().hex[:6]}"
        self.tenant_b = f"tenant-beta-{uuid.uuid4().hex[:6]}"
        repository.create_tenant(Tenant(id=self.tenant_a, name="Alpha Corp", slug=f"alpha-{uuid.uuid4().hex[:4]}"))
        repository.create_tenant(Tenant(id=self.tenant_b, name="Beta Corp", slug=f"beta-{uuid.uuid4().hex[:4]}"))

        self.asset_a = repository.ensure_asset("https://alpha.example.com", self.tenant_a)
        self.asset_b = repository.ensure_asset("https://beta.example.com", self.tenant_b)

        # Baseline scans
        self.scan_a = ScanResult(
            tenant_id=self.tenant_a,
            asset_id=self.asset_a.id,
            target_url="https://alpha.example.com",
            status=ScanStatus.COMPLETED,
        )
        repository.save_scan(self.scan_a)

        self.scan_b = ScanResult(
            tenant_id=self.tenant_b,
            asset_id=self.asset_b.id,
            target_url="https://beta.example.com",
            status=ScanStatus.COMPLETED,
        )
        repository.save_scan(self.scan_b)

    def _login(self, client, role="analyst", user_id="user-1", tenant_id=None):
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = f"test_{role}"
            sess["role"] = role
            sess["tenant_id"] = tenant_id or self.tenant_a

    # =================================================================
    # 1. Deterministic Fingerprinting & Observation Correlation
    # =================================================================
    def test_fingerprint_deterministic_and_non_volatile(self):
        """Fingerprint remains identical across different scans, timestamps, and transient evidence."""
        fp1 = compute_finding_fingerprint(
            tenant_id=self.tenant_a,
            asset_id=self.asset_a.id,
            scanner_id="vulnerable_plugin",
            finding_type="vulnerable_plugin",
            location="/wp-content/plugins/contact-form-7/",
            identifier="CVE-2023-1234"
        )
        fp2 = compute_finding_fingerprint(
            tenant_id=self.tenant_a,
            asset_id=self.asset_a.id,
            scanner_id="VULNERABLE_PLUGIN",
            finding_type="vulnerable_plugin",
            location="https://alpha.example.com/wp-content/plugins/contact-form-7?nonce=abc123#ref",
            identifier="cve-2023-1234"
        )
        self.assertEqual(fp1, fp2)

        # Different tenant produces distinct fingerprint
        fp_b = compute_finding_fingerprint(
            tenant_id=self.tenant_b,
            asset_id=self.asset_b.id,
            scanner_id="vulnerable_plugin",
            finding_type="vulnerable_plugin",
            location="/wp-content/plugins/contact-form-7/",
            identifier="CVE-2023-1234"
        )
        self.assertNotEqual(fp1, fp_b)

    def test_process_scan_findings_observation_tracking_and_reopening(self):
        """Recurring scan observes existing finding, increments observation count, and auto-reopens verified finding."""
        raw_f = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a.id,
            asset_id=self.asset_a.id,
            title="Outdated WordPress Core",
            category="core",
            severity=Severity.HIGH,
            cve_id="CVE-2024-9999",
            raw_data={"scanner": "core", "finding_type": "outdated_core", "location": "/"},
        )
        processed = repository.process_scan_findings(self.scan_a.id, self.tenant_a, self.asset_a.id, [raw_f])
        self.assertEqual(len(processed), 1)
        first_finding = processed[0]
        self.assertEqual(first_finding.status, "OPEN")
        self.assertEqual(first_finding.observation_count, 1)

        # Mark as REMEDIATED then VERIFIED
        repository.transition_finding_status(
            finding_id=first_finding.id,
            new_status="REMEDIATED",
            actor_user_id="user-dev",
            tenant_id=self.tenant_a,
            comment="Fix deployed"
        )
        repository.transition_finding_status(
            finding_id=first_finding.id,
            new_status="VERIFIED",
            actor_user_id="user-qa",
            tenant_id=self.tenant_a,
            comment="Fix verified"
        )
        verified_f = repository.get_finding(first_finding.id, tenant_id=self.tenant_a)
        self.assertEqual(verified_f.status, "VERIFIED")

        # Second scan discovers the same vulnerability again
        scan_2 = ScanResult(tenant_id=self.tenant_a, asset_id=self.asset_a.id, target_url="https://alpha.example.com")
        repository.save_scan(scan_2)

        raw_f2 = Finding(
            tenant_id=self.tenant_a,
            scan_id=scan_2.id,
            asset_id=self.asset_a.id,
            title="Outdated WordPress Core",
            category="core",
            severity=Severity.HIGH,
            cve_id="CVE-2024-9999",
            raw_data={"scanner": "core", "finding_type": "outdated_core", "location": "/"},
        )
        processed_2 = repository.process_scan_findings(scan_2.id, self.tenant_a, self.asset_a.id, [raw_f2])
        self.assertEqual(len(processed_2), 1)
        reopened_f = processed_2[0]

        # Automatic reopening assertion
        self.assertEqual(reopened_f.id, first_finding.id)
        self.assertEqual(reopened_f.status, "REOPENED")
        self.assertEqual(reopened_f.observation_count, 2)

        # Observations table verification
        obs = repository.get_observations_for_finding(first_finding.id, tenant_id=self.tenant_a)
        self.assertEqual(len(obs), 2)

    # =================================================================
    # 2. Prioritization Algorithm & SLA Policy
    # =================================================================
    def test_multi_factor_prioritization(self):
        """Calculates correct score & bands incorporating KEV (+25), Criticality (+15), EPSS, CVSS."""
        # Non-critical issue
        score_low, band_low = calculate_priority_score(
            severity="low",
            asset_criticality="low",
            asset_internet_facing=False
        )
        self.assertEqual(band_low, "P4")
        self.assertTrue(score_low < 40.0)

        # Critical + KEV issue -> Must escalate to P1
        score_p1, band_p1 = calculate_priority_score(
            severity="critical",
            cvss_score=9.8,
            epss_score=0.92,
            kev=True,
            asset_criticality="critical",
            asset_internet_facing=True,
            ransomware_relevance=True,
        )
        self.assertEqual(band_p1, "P1")
        self.assertTrue(score_p1 >= 90.0)

    def test_sla_status_evaluation_and_breach(self):
        """Correctly detects ON_TRACK, WARNING, and BREACHED SLA states."""
        now = datetime.now(timezone.utc)
        finding_on_track = Finding(
            tenant_id=self.tenant_a,
            status="OPEN",
            priority_band="P3",
            sla_due_at=(now + timedelta(days=20)).isoformat(),
        )
        self.assertEqual(evaluate_finding_sla_status(finding_on_track, now=now), SLAStatus.ON_TRACK.value)

        # Inside warning window (due in 2 days, warning window is 7 days for P3)
        finding_warning = Finding(
            tenant_id=self.tenant_a,
            status="OPEN",
            priority_band="P3",
            sla_due_at=(now + timedelta(days=2)).isoformat(),
        )
        self.assertEqual(evaluate_finding_sla_status(finding_warning, now=now), SLAStatus.WARNING.value)

        # Breached (due yesterday)
        finding_breached = Finding(
            tenant_id=self.tenant_a,
            status="OPEN",
            priority_band="P1",
            sla_due_at=(now - timedelta(days=1)).isoformat(),
        )
        self.assertEqual(evaluate_finding_sla_status(finding_breached, now=now), SLAStatus.BREACHED.value)

        # Closed finding is complied
        finding_breached.status = "CLOSED"
        self.assertEqual(evaluate_finding_sla_status(finding_breached, now=now), SLAStatus.COMPLIED.value)

    # =================================================================
    # 3. State Machine & Optimistic Locking
    # =================================================================
    def test_state_machine_invalid_transition_rejected(self):
        """Illegal state transitions are rejected with InvalidStateTransitionError and HTTP 400."""
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="Test FP", status="OPEN")
        repository.save_finding(finding)

        # Illegal: OPEN directly to VERIFIED without remediation/verification_pending
        with self.assertRaises(InvalidStateTransitionError):
            repository.transition_finding_status(finding.id, "VERIFIED", actor_user_id="user-1", tenant_id=self.tenant_a)

    def test_optimistic_locking_prevents_lost_updates_returns_409(self):
        """Concurrent modification with stale expected_version triggers HTTP 409 Conflict."""
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="Race Condition Test", status="OPEN", version=1)
        repository.save_finding(finding)

        # User A transitions to IN_PROGRESS (version becomes 2)
        repository.transition_finding_status(
            finding_id=finding.id,
            new_status="IN_PROGRESS",
            actor_user_id="user-A",
            tenant_id=self.tenant_a,
            expected_version=1,
        )

        # User B tries to update using stale version 1 via Web route
        self._login(self.client, role="analyst", user_id="user-B", tenant_id=self.tenant_a)
        resp = self.client.post(f"/finding/{finding.id}/status", data={
            "new_status": "REMEDIATED",
            "expected_version": "1",  # Stale version!
            "comment": "User B submitting fix"
        })
        self.assertEqual(resp.status_code, 409)

    # =================================================================
    # 4. Risk Acceptance Two-Person Rule & Expiration Task
    # =================================================================
    def test_risk_acceptance_two_person_rule(self):
        """Self-approval of risk acceptance is strictly rejected (Two-Person Rule)."""
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="Risk Accept Test", status="OPEN")
        repository.save_finding(finding)

        # Analyst requests risk acceptance
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
        ra = RiskAcceptance(
            tenant_id=self.tenant_a,
            finding_id=finding.id,
            requested_by="analyst-1",
            reason="Legacy architectural dependency",
            valid_until=future_date,
            status="PENDING",
        )
        repository.create_risk_acceptance(ra)

        # Analyst-1 tries to approve their own request -> Must be rejected with 400
        self._login(self.client, role="admin", user_id="analyst-1", tenant_id=self.tenant_a)
        resp_self = self.client.post(f"/risk-acceptance/{ra.id}/action", data={"action": "approve"})
        self.assertEqual(resp_self.status_code, 400)

        # Independent Admin-2 approves -> Succeeds and pauses SLA
        self._login(self.client, role="admin", user_id="admin-2", tenant_id=self.tenant_a)
        resp_admin = self.client.post(f"/risk-acceptance/{ra.id}/action", data={"action": "approve"})
        self.assertEqual(resp_admin.status_code, 302)

        # Finding status must now be RISK_ACCEPTED with SLA paused
        updated_f = repository.get_finding(finding.id, tenant_id=self.tenant_a)
        self.assertEqual(updated_f.status, "RISK_ACCEPTED")
        self.assertEqual(updated_f.sla_status, "PAUSED")

    def test_risk_acceptance_expiration_background_task(self):
        """expire_risk_acceptances task transitions expired records to EXPIRED and reopens finding."""
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="Expired Exception Test", status="RISK_ACCEPTED")
        repository.save_finding(finding)

        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        ra = RiskAcceptance(
            tenant_id=self.tenant_a,
            finding_id=finding.id,
            requested_by="analyst-1",
            approved_by="admin-2",
            reason="Temporary grace period",
            valid_until=yesterday,
            status="APPROVED",
        )
        repository.create_risk_acceptance(ra)

        # Run background task
        res = expire_risk_acceptances()
        self.assertTrue(res["expired"] >= 1)

        # Finding must be reopened and RA marked EXPIRED
        updated_ra = repository.get_risk_acceptance(ra.id, tenant_id=self.tenant_a)
        self.assertEqual(updated_ra.status, "EXPIRED")

        updated_f = repository.get_finding(finding.id, tenant_id=self.tenant_a)
        self.assertEqual(updated_f.status, "REOPENED")
        self.assertIsNone(updated_f.sla_paused_at)

    # =================================================================
    # 5. Integrations: Jira Adapter & Webhook HMAC Signing
    # =================================================================
    def test_jira_integration_creates_ticket_reference(self):
        """Jira adapter creates external ticket reference without exposing secrets."""
        integ = Integration(
            tenant_id=self.tenant_a,
            type="jira",
            name="Alpha Jira",
            config_reference={"url": "https://jira.alpha.corp", "project_key": "SEC"},
            secret_reference="JIRA_TOKEN_ENV",
        )
        repository.create_integration(integ)

        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="SQLi in Custom Plugin", priority_band="P1")
        repository.save_finding(finding)

        adapter = JiraIntegration(integ)
        ticket_ref = adapter.create_ticket(finding)
        self.assertTrue(ticket_ref.external_ticket_id.startswith("SEC-"))
        self.assertIn("https://jira.alpha.corp/browse/", ticket_ref.external_url)

    def test_webhook_hmac_sha256_signature_verification(self):
        """Webhook dispatcher computes and attaches valid X-Sentinel-Signature (HMAC-SHA256)."""
        secret = "super-secret-webhook-key-999"
        payload = {"event": "finding.created", "tenant_id": self.tenant_a, "finding_id": "test-123"}
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        sig = compute_webhook_signature(secret, payload_bytes)
        self.assertTrue(sig.startswith("sha256="))

        # Deliver to simulated receiver
        integ = Integration(
            tenant_id=self.tenant_a,
            type="webhook",
            name="Slack Webhook",
            config_reference={"url": "https://httpbin.org/post"},
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_urlopen.return_value.__enter__.return_value = mock_resp

            delivery = deliver_webhook_payload(integ, "finding.created", payload, secret_token=secret)
            self.assertEqual(delivery.status, "delivered")

    # =================================================================
    # 6. REST API v1, Scoped API Keys, and IDOR Prevention
    # =================================================================
    def test_api_key_generation_authentication_and_scope_enforcement(self):
        """REST API validates hashed bearer keys and enforces scope restrictions."""
        api_key, raw_token = generate_api_key(
            name="CI Pipeline Key",
            tenant_id=self.tenant_a,
            scopes=["findings:read"]
        )
        repository.create_api_key(api_key)
        self.assertTrue(raw_token.startswith("swp_live_"))

        # Raw token resolves correctly via verify_api_key
        verified = verify_api_key(raw_token)
        self.assertIsNotNone(verified)
        self.assertEqual(verified.id, api_key.id)

        # GET /api/v1/findings with findings:read scope -> Allowed (200)
        resp = self.client.get(
            "/api/v1/findings",
            headers={"Authorization": f"Bearer {raw_token}"}
        )
        self.assertEqual(resp.status_code, 200)

        # POST /api/v1/findings/<id>/status requires findings:write -> Forbidden (403)
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="Scope Test Finding")
        repository.save_finding(finding)

        resp_write = self.client.post(
            f"/api/v1/findings/{finding.id}/status",
            headers={"Authorization": f"Bearer {raw_token}"},
            json={"status": "IN_PROGRESS"}
        )
        self.assertEqual(resp_write.status_code, 403)

    def test_cross_tenant_idor_protection_returns_404(self):
        """Cross-tenant access to findings or exceptions returns HTTP 404 Not Found."""
        finding_beta = Finding(
            tenant_id=self.tenant_b,
            scan_id=self.scan_b.id,
            title="Confidential Beta Vulnerability"
        )
        repository.save_finding(finding_beta)

        # User logged in tenant_a attempts to access tenant_b's finding
        self._login(self.client, role="analyst", user_id="user-alpha", tenant_id=self.tenant_a)
        resp = self.client.get(f"/finding/{finding_beta.id}")
        self.assertEqual(resp.status_code, 404)

        # REST API caller from tenant_a attempts to access tenant_b's finding
        api_key_a, raw_token_a = generate_api_key(name="Alpha Token", tenant_id=self.tenant_a, scopes=["findings:read"])
        repository.create_api_key(api_key_a)

        api_resp = self.client.get(
            f"/api/v1/findings/{finding_beta.id}",
            headers={"Authorization": f"Bearer {raw_token_a}"}
        )
        self.assertEqual(api_resp.status_code, 404)

    # =================================================================
    # 7. Daily Risk Snapshot & Background Reporting
    # =================================================================
    def test_generate_daily_risk_snapshot_task(self):
        """Daily risk snapshot task correctly aggregates exposure metrics."""
        f_p1 = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="P1 Issue", priority_band="P1", priority_score=88.0, kev=True)
        f_p2 = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a.id, title="P2 Issue", priority_band="P2", priority_score=65.0)
        repository.save_finding(f_p1)
        repository.save_finding(f_p2)

        res = generate_daily_risk_snapshot()
        self.assertTrue(res["snapshots_generated"] >= 1)

        snapshots = repository.get_daily_risk_snapshots(self.tenant_a)
        self.assertTrue(len(snapshots) >= 1)
        latest = snapshots[0]
        self.assertTrue(latest.p1_count >= 1)
        self.assertTrue(latest.kev_count >= 1)
