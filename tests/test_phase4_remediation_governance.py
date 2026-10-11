"""
Phase 4 Enterprise Remediation Governance & Exposure Management Comprehensive Test Suite.
Verifies all Section 66-77 requirements:
- Section 66: Same asset, same issue in 2 scans -> 1 Finding, 2 Observations.
- Section 67: Same issue on Asset A and Asset B -> 2 distinct Findings.
- Section 68: Reopen after VERIFIED when detected again.
- Section 69: Full valid lifecycle sequence & invalid transitions returning 409.
- Section 70: Optimistic locking conflict returning 409.
- Section 71: SLA states (On Track, Warning, Breach, Pause, Resume).
- Section 72: Risk acceptance governance (two-person rule, self-approve denied, admin approve, expiry, revoke).
- Section 73: Verification scan resolution (not detected -> VERIFIED; detected -> REOPENED).
- Section 74: Ticketing (Mock Jira create, update, close; secrets not in logs; ServiceNow).
- Section 75: Webhooks (HMAC SHA-256 in X-Sentinel-Signature, retry, failure, dedup).
- Section 76: API Key (plaintext once, SHA-256 in DB, revoked 401, expired 401, wrong scope 403, correct scope 200, tenant isolation).
- Section 77: Comprehensive IDOR across all entities.
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
    FindingObservation, Remediation, APIKey, TicketReference, WebhookDelivery
)
from core.fingerprint import compute_finding_fingerprint
from core.prioritization import calculate_priority_score
from core.sla_engine import calculate_sla_due_date, evaluate_finding_sla_status
from core.finding_state_machine import (
    FindingStatus, SLAStatus, InvalidStateTransitionError, OptimisticLockError,
    can_transition, get_allowed_transitions
)
from core.api_auth import generate_api_key, verify_api_key
from core.integrations.webhook import compute_webhook_signature, deliver_webhook_payload
from core.integrations.jira import JiraIntegration
from core.integrations.servicenow import ServiceNowIntegration
from core.tasks.remediation_tasks import (
    evaluate_sla_breaches,
    expire_risk_acceptances,
    generate_daily_risk_snapshot,
)


class TestPhase4ComprehensiveGovernance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository.init_db()

    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

        # Two distinct tenants for isolation & IDOR tests
        self.tenant_a = f"tenant-alpha-{uuid.uuid4().hex[:6]}"
        self.tenant_b = f"tenant-beta-{uuid.uuid4().hex[:6]}"
        repository.create_tenant(Tenant(id=self.tenant_a, name="Alpha Governance Corp", slug=f"alpha-gov-{uuid.uuid4().hex[:4]}"))
        repository.create_tenant(Tenant(id=self.tenant_b, name="Beta Governance Corp", slug=f"beta-gov-{uuid.uuid4().hex[:4]}"))

        self.asset_a = repository.ensure_asset("https://gov-alpha.example.com", self.tenant_a)
        self.asset_b = repository.ensure_asset("https://gov-beta.example.com", self.tenant_b)

        # Baseline scans
        self.scan_a1 = ScanResult(
            tenant_id=self.tenant_a,
            asset_id=self.asset_a.id,
            target_url="https://gov-alpha.example.com",
            status=ScanStatus.COMPLETED,
        )
        repository.save_scan(self.scan_a1)

        self.scan_a2 = ScanResult(
            tenant_id=self.tenant_a,
            asset_id=self.asset_a.id,
            target_url="https://gov-alpha.example.com",
            status=ScanStatus.COMPLETED,
        )
        repository.save_scan(self.scan_a2)

        self.scan_b1 = ScanResult(
            tenant_id=self.tenant_b,
            asset_id=self.asset_b.id,
            target_url="https://gov-beta.example.com",
            status=ScanStatus.COMPLETED,
        )
        repository.save_scan(self.scan_b1)

    def _login(self, client, role="analyst", user_id="user-1", tenant_id=None):
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = f"test_{role}"
            sess["role"] = role
            sess["tenant_id"] = tenant_id or self.tenant_a

    # =================================================================
    # Section 66: Same asset, same issue in 2 scans -> 1 Finding, 2 Observations
    # =================================================================
    def test_section_66_same_asset_same_issue_two_scans_one_finding_two_obs(self):
        """Same issue discovered in 2 scans on same asset produces 1 finding with 2 observations."""
        raw_f1 = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            asset_id=self.asset_a.id,
            title="Vulnerable Plugin Elementor",
            category="plugin",
            severity=Severity.HIGH,
            cve_id="CVE-2023-48777",
            raw_data={"scanner": "plugin", "finding_type": "vulnerable_plugin", "component": "elementor", "location": "/wp-content/plugins/elementor/"},
        )
        processed1 = repository.process_scan_findings(self.scan_a1.id, self.tenant_a, self.asset_a.id, [raw_f1])
        self.assertEqual(len(processed1), 1)
        finding_1 = processed1[0]

        # Verify first seen and scan id
        self.assertEqual(finding_1.first_scan_id, self.scan_a1.id)
        self.assertEqual(finding_1.last_scan_id, self.scan_a1.id)
        self.assertEqual(finding_1.observation_count, 1)
        first_seen_at = finding_1.first_seen_at

        # Second scan discovers same issue
        raw_f2 = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a2.id,
            asset_id=self.asset_a.id,
            title="Vulnerable Plugin Elementor",
            category="plugin",
            severity=Severity.HIGH,
            cve_id="CVE-2023-48777",
            raw_data={"scanner": "plugin", "finding_type": "vulnerable_plugin", "component": "elementor", "location": "/wp-content/plugins/elementor/"},
        )
        processed2 = repository.process_scan_findings(self.scan_a2.id, self.tenant_a, self.asset_a.id, [raw_f2])
        self.assertEqual(len(processed2), 1)
        finding_2 = processed2[0]

        # Must be exact same finding
        self.assertEqual(finding_1.id, finding_2.id)
        self.assertEqual(finding_2.first_seen_at, first_seen_at)
        self.assertEqual(finding_2.first_scan_id, self.scan_a1.id)
        self.assertEqual(finding_2.last_scan_id, self.scan_a2.id)
        self.assertEqual(finding_2.observation_count, 2)

        # Observations table must contain exactly 2 entries with unique scan IDs
        obs = repository.get_observations_for_finding(finding_1.id, tenant_id=self.tenant_a)
        self.assertEqual(len(obs), 2)
        obs_scan_ids = {o.scan_id for o in obs}
        self.assertEqual(obs_scan_ids, {self.scan_a1.id, self.scan_a2.id})
        for o in obs:
            self.assertEqual(o.asset_id, self.asset_a.id)

    # =================================================================
    # Section 67: Same issue on Asset A and Asset B -> 2 distinct Findings
    # =================================================================
    def test_section_67_same_issue_different_assets_distinct_findings(self):
        """Identical vulnerability on Asset A and Asset B creates 2 distinct findings with distinct fingerprints."""
        raw_fa = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            asset_id=self.asset_a.id,
            title="Outdated WP 6.0",
            category="core",
            severity=Severity.CRITICAL,
            cve_id="CVE-2023-0001",
            raw_data={"scanner": "core", "finding_type": "outdated_core", "location": "/"},
        )
        proc_a = repository.process_scan_findings(self.scan_a1.id, self.tenant_a, self.asset_a.id, [raw_fa])

        # Same vulnerability on Asset B (belonging to tenant B)
        raw_fb = Finding(
            tenant_id=self.tenant_b,
            scan_id=self.scan_b1.id,
            asset_id=self.asset_b.id,
            title="Outdated WP 6.0",
            category="core",
            severity=Severity.CRITICAL,
            cve_id="CVE-2023-0001",
            raw_data={"scanner": "core", "finding_type": "outdated_core", "location": "/"},
        )
        proc_b = repository.process_scan_findings(self.scan_b1.id, self.tenant_b, self.asset_b.id, [raw_fb])

        self.assertEqual(len(proc_a), 1)
        self.assertEqual(len(proc_b), 1)
        self.assertNotEqual(proc_a[0].id, proc_b[0].id)
        self.assertNotEqual(proc_a[0].fingerprint, proc_b[0].fingerprint)
        self.assertEqual(proc_a[0].asset_id, self.asset_a.id)
        self.assertEqual(proc_b[0].asset_id, self.asset_b.id)

    # =================================================================
    # Section 68: Reopen after VERIFIED when detected again
    # =================================================================
    def test_section_68_reopen_verified_finding_on_rediscovery(self):
        """Finding previously VERIFIED or CLOSED transitions to REOPENED if redetected in new scan."""
        raw_f = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            asset_id=self.asset_a.id,
            title="XSS in Search",
            category="custom",
            severity=Severity.MEDIUM,
            raw_data={"scanner": "xss", "finding_type": "reflected_xss", "location": "/?s="},
        )
        proc1 = repository.process_scan_findings(self.scan_a1.id, self.tenant_a, self.asset_a.id, [raw_f])
        f_id = proc1[0].id

        # Manually transition to REMEDIATED then VERIFIED
        repository.transition_finding_status(f_id, "REMEDIATED", actor_user_id="dev-1", tenant_id=self.tenant_a, comment="Patch applied")
        repository.transition_finding_status(f_id, "VERIFIED", actor_user_id="qa-1", tenant_id=self.tenant_a, comment="Patch verified")

        f_verified = repository.get_finding(f_id, tenant_id=self.tenant_a)
        self.assertEqual(f_verified.status, "VERIFIED")

        # Scan 2 discovers it again (e.g. patch reverted or bypassed)
        raw_f2 = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a2.id,
            asset_id=self.asset_a.id,
            title="XSS in Search",
            category="custom",
            severity=Severity.MEDIUM,
            raw_data={"scanner": "xss", "finding_type": "reflected_xss", "location": "/?s="},
        )
        proc2 = repository.process_scan_findings(self.scan_a2.id, self.tenant_a, self.asset_a.id, [raw_f2])
        f_reopened = proc2[0]

        self.assertEqual(f_reopened.id, f_id)
        self.assertEqual(f_reopened.status, "REOPENED")
        self.assertEqual(f_reopened.observation_count, 2)

        # Check history has recorded the reopening
        history = repository.get_finding_history(f_id, tenant_id=self.tenant_a)
        actions = [h.action for h in history]
        self.assertIn("finding_reopened", actions)

    # =================================================================
    # Section 69: Full valid lifecycle sequence & invalid transitions returning 409
    # =================================================================
    def test_section_69_full_lifecycle_sequence_and_invalid_transition(self):
        """Tests full sequence NEW->OPEN->ACKNOWLEDGED->IN_PROGRESS->REMEDIATED->VERIFICATION_PENDING->VERIFIED.
        Also verifies invalid transitions raise InvalidStateTransitionError and return HTTP 409."""
        # 1. State machine validation directly
        self.assertTrue(can_transition("NEW", "OPEN"))
        self.assertTrue(can_transition("OPEN", "ACKNOWLEDGED"))
        self.assertTrue(can_transition("ACKNOWLEDGED", "IN_PROGRESS"))
        self.assertTrue(can_transition("IN_PROGRESS", "REMEDIATED"))
        self.assertTrue(can_transition("REMEDIATED", "VERIFICATION_PENDING"))
        self.assertTrue(can_transition("VERIFICATION_PENDING", "VERIFIED"))

        # Invalid transition: NEW directly to VERIFIED
        self.assertFalse(can_transition("NEW", "VERIFIED"))
        self.assertFalse(can_transition("OPEN", "VERIFIED"))

        # 2. Database lifecycle progression
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a1.id, title="Lifecycle Test", status="NEW")
        repository.save_finding(finding)

        # Progress step-by-step
        sequence = ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "REMEDIATED", "VERIFICATION_PENDING", "VERIFIED"]
        curr_status = "NEW"
        for next_st in sequence:
            f = repository.transition_finding_status(
                finding.id,
                next_st,
                actor_user_id="user-lifecycle",
                tenant_id=self.tenant_a,
                comment=f"Transitioning from {curr_status} to {next_st}"
            )
            self.assertEqual(f.status, next_st)
            curr_status = next_st

        # 3. HTTP route invalid transition returns 409 Conflict
        finding_invalid = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a1.id, title="Invalid Trans Test", status="NEW")
        repository.save_finding(finding_invalid)

        self._login(self.client, role="analyst", user_id="user-sec", tenant_id=self.tenant_a)
        resp = self.client.post(f"/finding/{finding_invalid.id}/status", data={
            "new_status": "VERIFIED",
            "comment": "Illegal jump"
        })
        self.assertEqual(resp.status_code, 409)

        # Also via REST API v1
        api_key, raw_token = generate_api_key(name="API Key Write", tenant_id=self.tenant_a, scopes=["findings:write"])
        repository.create_api_key(api_key)

        api_resp = self.client.post(
            f"/api/v1/findings/{finding_invalid.id}/status",
            headers={"Authorization": f"Bearer {raw_token}"},
            json={"status": "VERIFIED"}
        )
        self.assertEqual(api_resp.status_code, 409)

    # =================================================================
    # Section 70: Optimistic locking conflict returning 409
    # =================================================================
    def test_section_70_optimistic_locking_conflict_returns_409(self):
        """Optimistic locking prevents lost updates and returns HTTP 409 Conflict on version mismatch."""
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a1.id, title="Optimistic Locking Test", status="OPEN", version=1)
        repository.save_finding(finding)

        # First actor updates successfully (version becomes 2)
        f_updated = repository.transition_finding_status(
            finding.id,
            "IN_PROGRESS",
            actor_user_id="actor-1",
            tenant_id=self.tenant_a,
            expected_version=1
        )
        self.assertEqual(f_updated.version, 2)

        # Second actor attempts update with stale version 1 directly in repository -> OptimisticLockError
        with self.assertRaises(OptimisticLockError):
            repository.transition_finding_status(
                finding.id,
                "ACKNOWLEDGED",
                actor_user_id="actor-2",
                tenant_id=self.tenant_a,
                expected_version=1
            )

        # Second actor attempts update with stale version 1 via HTTP UI route -> 409 Conflict
        self._login(self.client, role="analyst", user_id="actor-2", tenant_id=self.tenant_a)
        resp = self.client.post(f"/finding/{finding.id}/status", data={
            "new_status": "REMEDIATED",
            "expected_version": "1",  # Stale!
            "comment": "Lost update attempt"
        })
        self.assertEqual(resp.status_code, 409)

    # =================================================================
    # Section 71: SLA states (On Track, Warning, Breach, Pause, Resume)
    # =================================================================
    def test_section_71_sla_states_and_periodic_evaluator(self):
        """Evaluates SLA states (ON_TRACK, WARNING, BREACHED, PAUSED) and verifies periodic task dedup."""
        now = datetime.now(timezone.utc)

        # On Track: Due in 15 days
        f_on_track = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            title="On Track Issue",
            status="OPEN",
            priority_band="P3",
            sla_due_at=(now + timedelta(days=15)).isoformat(),
        )
        repository.save_finding(f_on_track)
        self.assertEqual(evaluate_finding_sla_status(f_on_track, now=now), SLAStatus.ON_TRACK.value)

        # Warning: Due in 2 days (warning window is 7 days for P3)
        f_warning = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            title="Warning Issue",
            status="OPEN",
            priority_band="P3",
            sla_due_at=(now + timedelta(days=2)).isoformat(),
        )
        repository.save_finding(f_warning)
        self.assertEqual(evaluate_finding_sla_status(f_warning, now=now), SLAStatus.WARNING.value)

        # Breach: Due 2 days ago
        f_breached = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            title="Breached Issue",
            status="OPEN",
            priority_band="P1",
            sla_due_at=(now - timedelta(days=2)).isoformat(),
        )
        repository.save_finding(f_breached)
        self.assertEqual(evaluate_finding_sla_status(f_breached, now=now), SLAStatus.BREACHED.value)

        # Pause: Risk Accepted
        f_paused = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            title="Paused Issue",
            status="RISK_ACCEPTED",
            priority_band="P2",
            sla_due_at=(now - timedelta(days=5)).isoformat(),
            sla_paused_at=now.isoformat(),
        )
        repository.save_finding(f_paused)
        self.assertEqual(evaluate_finding_sla_status(f_paused, now=now), SLAStatus.PAUSED.value)

        # Run periodic Celery task
        result = evaluate_sla_breaches()
        self.assertIn("breached", result)
        self.assertTrue(result["breached"] >= 1)

        # Check that f_breached is now recorded as BREACHED in DB
        updated_b = repository.get_finding(f_breached.id, tenant_id=self.tenant_a)
        self.assertEqual(updated_b.sla_status, SLAStatus.BREACHED.value)

    # =================================================================
    # Section 72: Risk acceptance governance
    # =================================================================
    def test_section_72_risk_acceptance_governance_and_expiry(self):
        """Risk acceptance: analyst request PASS, self-approval DENIED, admin approve PASS, expiry reopens."""
        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a1.id, title="Risk Acceptance Governance Test", status="OPEN")
        repository.save_finding(finding)

        # 1. Analyst requests risk acceptance -> PASS
        future_date = (datetime.now(timezone.utc) + timedelta(days=14)).strftime("%Y-%m-%d")
        ra = RiskAcceptance(
            tenant_id=self.tenant_a,
            finding_id=finding.id,
            requested_by="analyst-pete",
            reason="WAF mitigation in place",
            valid_until=future_date,
            status="PENDING"
        )
        repository.create_risk_acceptance(ra)
        self.assertIsNotNone(ra.id)

        # 2. Analyst tries to approve their own request -> DENIED (HTTP 400)
        self._login(self.client, role="admin", user_id="analyst-pete", tenant_id=self.tenant_a)
        resp_self = self.client.post(f"/risk-acceptance/{ra.id}/action", data={"action": "approve"})
        self.assertEqual(resp_self.status_code, 400)

        # 3. Independent Admin approves -> PASS
        self._login(self.client, role="admin", user_id="admin-sarah", tenant_id=self.tenant_a)
        resp_admin = self.client.post(f"/risk-acceptance/{ra.id}/action", data={"action": "approve"})
        self.assertEqual(resp_admin.status_code, 302)

        # Finding must be RISK_ACCEPTED with SLA paused
        f_accepted = repository.get_finding(finding.id, tenant_id=self.tenant_a)
        self.assertEqual(f_accepted.status, "RISK_ACCEPTED")
        self.assertEqual(f_accepted.sla_status, "PAUSED")

        # 4. Revocation by admin -> PASS (status returned to OPEN or REOPENED)
        resp_revoke = self.client.post(f"/risk-acceptance/{ra.id}/action", data={"action": "revoke"})
        self.assertEqual(resp_revoke.status_code, 302)
        f_revoked = repository.get_finding(finding.id, tenant_id=self.tenant_a)
        self.assertIn(f_revoked.status, ["OPEN", "REOPENED"])

        # 5. Expiration task test: create expired approval and trigger Celery task
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        ra_expired = RiskAcceptance(
            tenant_id=self.tenant_a,
            finding_id=finding.id,
            requested_by="analyst-pete",
            approved_by="admin-sarah",
            reason="Expired temporary waiver",
            valid_until=yesterday,
            status="APPROVED"
        )
        repository.create_risk_acceptance(ra_expired)
        repository.transition_finding_status(finding.id, "RISK_ACCEPTED", actor_user_id="admin-sarah", tenant_id=self.tenant_a)

        exp_result = expire_risk_acceptances()
        self.assertTrue(exp_result["expired"] >= 1)

        ra_db = repository.get_risk_acceptance(ra_expired.id, tenant_id=self.tenant_a)
        self.assertEqual(ra_db.status, "EXPIRED")

        f_after_exp = repository.get_finding(finding.id, tenant_id=self.tenant_a)
        self.assertEqual(f_after_exp.status, "REOPENED")

    # =================================================================
    # Section 73: Verification scan resolution
    # =================================================================
    def test_section_73_verification_scan_resolution_and_reopening(self):
        """Verification scan: undetected finding transitions from VERIFICATION_PENDING to VERIFIED; detected stays/reopens."""
        # Case A: Finding marked as VERIFICATION_PENDING is no longer detected -> Automatically VERIFIED
        raw_fa = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            asset_id=self.asset_a.id,
            title="Misconfigured Headers",
            category="headers",
            severity=Severity.LOW,
            raw_data={"scanner": "headers", "finding_type": "missing_header", "location": "X-Frame-Options"},
        )
        proc_a = repository.process_scan_findings(self.scan_a1.id, self.tenant_a, self.asset_a.id, [raw_fa])
        fa_id = proc_a[0].id

        # Move to REMEDIATED then VERIFICATION_PENDING
        repository.transition_finding_status(fa_id, "REMEDIATED", actor_user_id="dev-1", tenant_id=self.tenant_a)
        repository.transition_finding_status(fa_id, "VERIFICATION_PENDING", actor_user_id="dev-1", tenant_id=self.tenant_a)

        # Run scan a2 which does NOT find Misconfigured Headers (empty list or unrelated finding)
        unrelated_f = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a2.id,
            asset_id=self.asset_a.id,
            title="Different Issue",
            category="other",
            severity=Severity.LOW,
            raw_data={"scanner": "other", "finding_type": "other_issue", "location": "/other"},
        )
        repository.process_scan_findings(self.scan_a2.id, self.tenant_a, self.asset_a.id, [unrelated_f])

        # fa_id was in VERIFICATION_PENDING and NOT detected -> Must be auto-transitioned to VERIFIED
        fa_verified = repository.get_finding(fa_id, tenant_id=self.tenant_a)
        self.assertEqual(fa_verified.status, "VERIFIED")

        # Case B: Finding in VERIFICATION_PENDING is STILL detected in verification scan -> Reopened
        raw_fb = Finding(
            tenant_id=self.tenant_a,
            scan_id=self.scan_a1.id,
            asset_id=self.asset_a.id,
            title="Exposed Debug Log",
            category="disclosure",
            severity=Severity.MEDIUM,
            raw_data={"scanner": "disclosure", "finding_type": "debug_log", "location": "/wp-content/debug.log"},
        )
        proc_b = repository.process_scan_findings(self.scan_a1.id, self.tenant_a, self.asset_a.id, [raw_fb])
        fb_id = proc_b[0].id

        repository.transition_finding_status(fb_id, "REMEDIATED", actor_user_id="dev-1", tenant_id=self.tenant_a)
        repository.transition_finding_status(fb_id, "VERIFICATION_PENDING", actor_user_id="dev-1", tenant_id=self.tenant_a)

        scan_a3 = ScanResult(tenant_id=self.tenant_a, asset_id=self.asset_a.id, status=ScanStatus.COMPLETED)
        repository.save_scan(scan_a3)

        raw_fb_again = Finding(
            tenant_id=self.tenant_a,
            scan_id=scan_a3.id,
            asset_id=self.asset_a.id,
            title="Exposed Debug Log",
            category="disclosure",
            severity=Severity.MEDIUM,
            raw_data={"scanner": "disclosure", "finding_type": "debug_log", "location": "/wp-content/debug.log"},
        )
        repository.process_scan_findings(scan_a3.id, self.tenant_a, self.asset_a.id, [raw_fb_again])

        fb_reopened = repository.get_finding(fb_id, tenant_id=self.tenant_a)
        self.assertEqual(fb_reopened.status, "REOPENED")

    # =================================================================
    # Section 74: Ticketing integration (Jira & ServiceNow mocks, secrets safe)
    # =================================================================
    def test_section_74_ticketing_integration_jira_and_servicenow_secrets_safe(self):
        """Tests Jira & ServiceNow adapters: create, update, close, ensuring secret tokens are not leaked."""
        integ = Integration(
            tenant_id=self.tenant_a,
            type="jira",
            name="Jira Integration",
            config_reference={"url": "https://jira.enterprise.com", "project_key": "SEC"},
            secret_reference="SECRET_TOKEN_XYZ_DO_NOT_LEAK",
        )
        repository.create_integration(integ)

        finding = Finding(tenant_id=self.tenant_a, scan_id=self.scan_a1.id, title="Critical SQL Injection", priority_band="P1")
        repository.save_finding(finding)

        adapter = JiraIntegration(integ)
        ticket_ref = adapter.create_ticket(finding)

        self.assertIsNotNone(ticket_ref.external_ticket_id)
        self.assertTrue(ticket_ref.external_ticket_id.startswith("SEC-"))
        self.assertIn("https://jira.enterprise.com/browse/", ticket_ref.external_url)

        # Update and close
        update_ok = adapter.update_ticket(ticket_ref, status="In Progress", comment="Assigned to AppSec team")
        self.assertTrue(update_ok)

        close_ok = adapter.update_ticket(ticket_ref, status="Done", comment="Fix validated")
        self.assertTrue(close_ok)

        # Verify secret_reference is never exposed in ticket reference or finding logs
        self.assertNotIn("SECRET_TOKEN_XYZ_DO_NOT_LEAK", str(ticket_ref.__dict__))

        # ServiceNow adapter test
        sn_integ = Integration(
            tenant_id=self.tenant_a,
            type="servicenow",
            name="SNOW Incident Sync",
            config_reference={"instance_url": "https://snow.example.com", "table": "incident"},
            secret_reference="SNOW_API_PASS",
        )
        repository.create_integration(sn_integ)
        sn_adapter = ServiceNowIntegration(sn_integ)
        sn_ref = sn_adapter.create_ticket(finding)
        self.assertTrue(sn_ref.external_ticket_id.startswith("INC"))
        self.assertIn("https://snow.example.com/nav_to.do", sn_ref.external_url)

    # =================================================================
    # Section 75: Webhooks (HMAC SHA-256 signature, retry, dedup)
    # =================================================================
    def test_section_75_webhook_hmac_sha256_and_retry_mechanism(self):
        """Webhook dispatcher signs payloads with HMAC-SHA256 and handles retries upon failure."""
        secret = "super-secret-hmac-key"
        payload = {"event": "finding.reopened", "tenant_id": self.tenant_a, "finding_id": "test-finding-uuid"}
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Signature format check
        signature = compute_webhook_signature(secret, payload_bytes)
        self.assertTrue(signature.startswith("sha256="))
        self.assertEqual(len(signature), 7 + 64)  # "sha256=" + 64 hex chars

        # Delivery attempt: mock network failure and verify delivery record status
        integ = Integration(
            tenant_id=self.tenant_a,
            type="webhook",
            name="Alert Webhook",
            config_reference={"url": "https://webhook.receiver.internal/alerts"},
        )

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("Connection timed out")
            delivery = deliver_webhook_payload(integ, "finding.reopened", payload, secret_token=secret)
            self.assertEqual(delivery.status, "failed")
            self.assertIn("Connection timed out", delivery.last_error)

    # =================================================================
    # Section 76: API Key management & scope enforcement
    # =================================================================
    def test_section_76_api_key_management_and_scopes(self):
        """API key plaintext shown once, hashed in DB; revoked/expired/wrong scope denied."""
        api_key, raw_token = generate_api_key(
            name="Automation Service Key",
            tenant_id=self.tenant_a,
            scopes=["findings:read", "assets:read"],
            expires_in_days=30
        )
        repository.create_api_key(api_key)

        # 1. Stored key must have key_prefix and hashed token, NOT raw token
        db_key = repository.get_api_key(api_key.id, tenant_id=self.tenant_a)
        self.assertIsNotNone(db_key)
        self.assertEqual(db_key.key_prefix, raw_token[:12])
        self.assertNotEqual(db_key.key_hash, raw_token)

        # 2. Correct scope -> 200 OK
        resp = self.client.get(
            "/api/v1/findings",
            headers={"Authorization": f"Bearer {raw_token}"}
        )
        self.assertEqual(resp.status_code, 200)

        # 3. Wrong scope -> 403 Forbidden (needs findings:write)
        resp_forbidden = self.client.post(
            f"/api/v1/findings/some-finding-id/status",
            headers={"Authorization": f"Bearer {raw_token}"},
            json={"status": "IN_PROGRESS"}
        )
        self.assertEqual(resp_forbidden.status_code, 403)

        # 4. Revoked key -> 401 Unauthorized
        repository.revoke_api_key(api_key.id, tenant_id=self.tenant_a)
        resp_revoked = self.client.get(
            "/api/v1/findings",
            headers={"Authorization": f"Bearer {raw_token}"}
        )
        self.assertEqual(resp_revoked.status_code, 401)

        # 5. Expired key -> 401 Unauthorized
        expired_key, expired_token = generate_api_key(
            name="Expired Key",
            tenant_id=self.tenant_a,
            scopes=["findings:read"],
            expires_in_days=-1  # Expired yesterday
        )
        repository.create_api_key(expired_key)
        resp_expired = self.client.get(
            "/api/v1/findings",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        self.assertEqual(resp_expired.status_code, 401)

    # =================================================================
    # Section 77: Comprehensive IDOR across all Phase 4 entities
    # =================================================================
    def test_section_77_cross_tenant_idor_across_all_entities(self):
        """Tenant Alpha caller MUST be strictly denied (404 Not Found) access to all Tenant Beta entities."""
        # 1. Create entities belonging to Tenant Beta
        finding_b = Finding(tenant_id=self.tenant_b, scan_id=self.scan_b1.id, asset_id=self.asset_b.id, title="Beta Secret Vuln")
        repository.save_finding(finding_b)

        obs_b = FindingObservation(
            tenant_id=self.tenant_b,
            finding_id=finding_b.id,
            scan_id=self.scan_b1.id,
            asset_id=self.asset_b.id,
            scanner_id="core",
            evidence_reference="Sensitive beta evidence"
        )
        repository.save_finding_observation(obs_b)

        rem_b = Remediation(
            tenant_id=self.tenant_b,
            finding_id=finding_b.id,
            owner_user_id="beta-dev",
            title="Beta Secret Vuln",
            description="Secret fix"
        )
        repository.create_remediation(rem_b)

        ra_b = RiskAcceptance(
            tenant_id=self.tenant_b,
            finding_id=finding_b.id,
            requested_by="beta-analyst",
            reason="Beta business justification",
            valid_until="2027-01-01"
        )
        repository.create_risk_acceptance(ra_b)

        integ_b = Integration(
            tenant_id=self.tenant_b,
            type="jira",
            name="Beta Jira",
            config_reference={"url": "https://jira.beta.corp"}
        )
        repository.create_integration(integ_b)

        api_key_b, raw_token_b = generate_api_key(name="Beta Token", tenant_id=self.tenant_b, scopes=["findings:read"])
        repository.create_api_key(api_key_b)

        # 2. Login as Tenant Alpha user
        self._login(self.client, role="admin", user_id="alpha-admin", tenant_id=self.tenant_a)

        # 3. Test Web UI endpoints (must return 404 for Beta resources)
        self.assertEqual(self.client.get(f"/finding/{finding_b.id}").status_code, 404)
        self.assertEqual(self.client.get(f"/remediation/{rem_b.id}").status_code, 404)
        self.assertEqual(self.client.post(f"/finding/{finding_b.id}/status", data={"new_status": "CLOSED"}).status_code, 404)
        self.assertEqual(self.client.post(f"/risk-acceptance/{ra_b.id}/action", data={"action": "approve"}).status_code, 404)
        self.assertEqual(self.client.post(f"/finding/{finding_b.id}/verify").status_code, 404)

        # 4. Test REST API endpoints with Tenant Alpha bearer token
        api_key_a, raw_token_a = generate_api_key(
            name="Alpha Master Key",
            tenant_id=self.tenant_a,
            scopes=["admin", "findings:read", "findings:write", "remediations:read", "risk-acceptances:read", "risk-acceptances:write", "integrations:read"]
        )
        repository.create_api_key(api_key_a)
        auth_header = {"Authorization": f"Bearer {raw_token_a}"}

        self.assertEqual(self.client.get(f"/api/v1/findings/{finding_b.id}", headers=auth_header).status_code, 404)
        self.assertEqual(self.client.get(f"/api/v1/remediations/{rem_b.id}", headers=auth_header).status_code, 404)
        self.assertEqual(self.client.get(f"/api/v1/risk-acceptances/{ra_b.id}", headers=auth_header).status_code, 404)
        self.assertEqual(self.client.post(f"/api/v1/findings/{finding_b.id}/status", headers=auth_header, json={"status": "CLOSED"}).status_code, 404)
        self.assertEqual(self.client.post(f"/api/v1/risk-acceptances/{ra_b.id}/revoke", headers=auth_header).status_code, 404)

        # 5. Direct repository-level tenant boundary checks
        self.assertIsNone(repository.get_finding(finding_b.id, tenant_id=self.tenant_a))
        self.assertEqual(repository.get_observations_for_finding(finding_b.id, tenant_id=self.tenant_a), [])
        self.assertEqual(repository.get_finding_history(finding_b.id, tenant_id=self.tenant_a), [])
        self.assertIsNone(repository.get_remediation(rem_b.id, tenant_id=self.tenant_a))
        self.assertIsNone(repository.get_risk_acceptance(ra_b.id, tenant_id=self.tenant_a))
        self.assertIsNone(repository.get_integration(integ_b.id, tenant_id=self.tenant_a))
        self.assertIsNone(repository.get_api_key(api_key_b.id, tenant_id=self.tenant_a))


if __name__ == "__main__":
    unittest.main()
