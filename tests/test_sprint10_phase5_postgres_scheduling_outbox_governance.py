"""
Sprint 10 - Phase 5: PostgreSQL Scheduling, Outbox, Governance and Integration Completion
Integration and Parity Test Suite for Real PostgreSQL 16 Execution.

Validates all 13 required scenarios:
1. Schedule Creation, Retrieval, and Listing
2. Scheduled Scan Claiming & Run Execution (0 duplicate dispatch guarantee)
3. Outbox Event Creation & Direct SQL Verification
4. Concurrent Outbox Claiming (SELECT FOR UPDATE SKIP LOCKED)
5. Outbox Retry Backoff and Dead-Letter Routing
6. Stale Event Recovery (crash / timeout recovery)
7. API Key Lifecycle (SHA-256 hash, lookup, update, revocation)
8. Policy and Policy Versioning (immutability, version ordering)
9. Webhook Subscription and Delivery Lifecycle
10. Cross-Tenant Isolation across all Phase 5 entities
11. Transaction Rollback on Failure
12. Database Outage / Fail-Closed Behavior
13. SQLite vs PostgreSQL behavioral parity
"""
import hashlib
import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import text

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models import (
    Tenant, Asset, ScheduledScan, ScheduledRun,
    IntegrationOutbox, OutboxStatus,
    APIKey, Policy, PolicyVersion, PolicyVersionStatus,
    Integration, WebhookDelivery, RiskAcceptance
)
from core.db.session import get_engine, init_db_schema, session_scope, reset_engine
from core.db.repositories.outbox_repo import OutboxRepository
from core.db.repositories.scheduler_repo import SchedulerRepository
from core.db.repositories.governance_repo import GovernanceRepository
from core import repository
from tests.postgres_integration import get_sprint10_postgres_url


class TestSprint10Phase5PostgresSchedulingOutboxGovernance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize schema in live isolated PostgreSQL 16 container
        cls.engine = get_engine(get_sprint10_postgres_url())
        init_db_schema(cls.engine)

    def setUp(self):
        # Force PostgreSQL mode for test execution
        self.orig_db_url = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = get_sprint10_postgres_url()
        reset_engine()
        repository.reset_conn()
        repository._allow_operational_sqlite_override = False

        self.test_prefix = f"s10_p5_{uuid.uuid4().hex[:6]}"
        self.tenant_id = f"tenant_{self.test_prefix}"
        self.tenant_slug = f"slug_{self.test_prefix}"

        # Provision parent tenant and asset in PostgreSQL
        tenant = Tenant(
            id=self.tenant_id,
            name="Sprint 10 Phase 5 Tenant",
            slug=self.tenant_slug,
            status="active"
        )
        repository.save_tenant(tenant)

        self.asset = repository.ensure_asset(
            target_url=f"https://{self.test_prefix}.example.com",
            tenant_id=self.tenant_id,
            display_name=f"Asset {self.test_prefix}"
        )

    def tearDown(self):
        if self.orig_db_url is not None:
            os.environ["DATABASE_URL"] = self.orig_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        reset_engine()
        repository.reset_conn()
        repository._allow_operational_sqlite_override = False

    # -------------------------------------------------------------------------
    # Scenario 1: Schedule Creation, Retrieval, and Listing
    # -------------------------------------------------------------------------
    def test_01_schedule_creation_retrieval_and_listing(self):
        sched_id = f"sched_{self.test_prefix}"
        sched = ScheduledScan(
            id=sched_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=f"https://{self.test_prefix}.example.com",
            scan_mode="passive",
            interval_hours=12,
            enabled=True,
            created_by="admin_test",
            max_retries=3
        )
        saved = repository.save_scheduled_scan(sched)
        self.assertEqual(saved.id, sched_id)
        self.assertEqual(saved.tenant_id, self.tenant_id)
        self.assertEqual(saved.interval_hours, 12)

        # Retrieve by ID
        retrieved = repository.get_scheduled_scan(sched_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.target_url, f"https://{self.test_prefix}.example.com")
        self.assertTrue(retrieved.enabled)

        # List schedules
        schedules = repository.list_scheduled_scans(tenant_id=self.tenant_id)
        self.assertTrue(any(s.id == sched_id for s in schedules))

        # Update schedule
        retrieved.interval_hours = 48
        retrieved.scan_mode = "aggressive"
        repository.update_scheduled_scan(retrieved)
        updated = repository.get_scheduled_scan(sched_id, tenant_id=self.tenant_id)
        self.assertEqual(updated.interval_hours, 48)
        self.assertEqual(updated.scan_mode, "aggressive")

        # Direct SQL verification
        with session_scope() as session:
            row = session.execute(
                text("SELECT id, tenant_id, interval_hours, scan_mode FROM scheduled_scans WHERE id = :id"),
                {"id": sched_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row.interval_hours, 48)
            self.assertEqual(row.scan_mode, "aggressive")

        # Delete schedule
        del_res = repository.delete_scheduled_scan(sched_id, tenant_id=self.tenant_id)
        self.assertTrue(del_res)
        self.assertIsNone(repository.get_scheduled_scan(sched_id, tenant_id=self.tenant_id))

    # -------------------------------------------------------------------------
    # Scenario 2: Scheduled Scan Claiming & Run Execution (Duplicate Prevention)
    # -------------------------------------------------------------------------
    def test_02_scheduled_scan_claiming_and_run_execution(self):
        sched_id = f"sched_run_{self.test_prefix}"
        sched = ScheduledScan(
            id=sched_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=f"https://{self.test_prefix}.example.com",
            scan_mode="passive",
            interval_hours=24,
            enabled=True
        )
        repository.save_scheduled_scan(sched)

        planned_slot = "2026-10-11T12:00:00+00:00"

        # Claim run slot 1
        run1 = repository.claim_scheduled_run(
            schedule_id=sched_id,
            tenant_id=self.tenant_id,
            planned_at=planned_slot
        )
        self.assertIsNotNone(run1)
        self.assertEqual(run1.schedule_id, sched_id)
        self.assertEqual(run1.status, "dispatched")

        # Attempt duplicate claim for same slot -> MUST return None (0 duplicate runs)
        run2 = repository.claim_scheduled_run(
            schedule_id=sched_id,
            tenant_id=self.tenant_id,
            planned_at=planned_slot
        )
        self.assertIsNone(run2, "Duplicate claim for identical (schedule_id, planned_at) slot must be prevented")

        # Transition run status: dispatched -> running
        res = repository.update_scheduled_run_status(run1.id, "running")
        self.assertTrue(res)

        # Transition run status: running -> completed with scan_job_id
        res2 = repository.update_scheduled_run_status(run1.id, "completed", scan_job_id=f"job_{self.test_prefix}")
        self.assertTrue(res2)

        # Direct SQL verification of completed run
        with session_scope() as session:
            row = session.execute(
                text("SELECT id, schedule_id, status, scan_job_id, started_at, completed_at FROM scheduled_runs WHERE id = :id"),
                {"id": run1.id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row.status, "completed")
            self.assertEqual(row.scan_job_id, f"job_{self.test_prefix}")
            self.assertIsNotNone(row.started_at)
            self.assertIsNotNone(row.completed_at)

    # -------------------------------------------------------------------------
    # Scenario 3: Outbox Event Creation & Direct SQL Verification
    # -------------------------------------------------------------------------
    def test_03_outbox_event_creation_direct_sql_verification(self):
        ev_id = f"outbox_{self.test_prefix}"
        payload = {"scan_id": "scan_123", "target": "https://example.com", "findings_count": 2}
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        event = IntegrationOutbox(
            id=ev_id,
            tenant_id=self.tenant_id,
            event_type="scan.completed",
            event_key=f"key_{self.test_prefix}",
            destination="siem",
            payload_hash=payload_hash,
            payload_json=payload,
            status=OutboxStatus.PENDING.value,
            attempt=1
        )
        saved = repository.save_outbox_event(event)
        self.assertEqual(saved.id, ev_id)
        self.assertEqual(saved.status, "PENDING")

        # Direct SQL bypass query
        with session_scope() as session:
            row = session.execute(
                text("""
                    SELECT id, tenant_id, event_type, event_key, destination,
                           payload_hash, payload_json, status, attempt
                    FROM integration_outbox WHERE id = :id
                """),
                {"id": ev_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row.event_type, "scan.completed")
            self.assertEqual(row.payload_hash, payload_hash)
            raw_payload = json.loads(row.payload_json) if isinstance(row.payload_json, str) else row.payload_json
            self.assertEqual(raw_payload, payload)
            self.assertEqual(row.status, "PENDING")
            self.assertEqual(row.attempt, 1)

    # -------------------------------------------------------------------------
    # Scenario 4: Concurrent Outbox Claiming (SELECT FOR UPDATE SKIP LOCKED)
    # -------------------------------------------------------------------------
    def test_04_concurrent_outbox_claiming_skip_locked(self):
        # Create 4 distinct pending outbox events
        event_ids = []
        for i in range(4):
            ev_id = f"outbox_claim_{self.test_prefix}_{i}"
            event_ids.append(ev_id)
            repository.save_outbox_event(IntegrationOutbox(
                id=ev_id,
                tenant_id=self.tenant_id,
                event_type="notification.alert",
                event_key=f"key_claim_{self.test_prefix}_{i}",
                destination="webhook",
                payload_hash="hash123",
                payload_json={"index": i},
                status=OutboxStatus.PENDING.value
            ))

        # Worker 1 claims 2 events in Session 1
        with session_scope() as session1:
            repo1 = OutboxRepository(session1)
            claimed1 = repo1.claim_events(
                worker_id="worker_alpha",
                batch_size=2,
                tenant_id=self.tenant_id
            )
            claimed1_ids = {e.id for e in claimed1}
            self.assertEqual(len(claimed1_ids), 2)
            for e in claimed1:
                self.assertEqual(e.status, "PROCESSING")
                self.assertEqual(e.claimed_by, "worker_alpha")
                self.assertIsNotNone(e.claimed_at)

        # Worker 2 claims remaining events in Session 2
        with session_scope() as session2:
            repo2 = OutboxRepository(session2)
            claimed2 = repo2.claim_events(
                worker_id="worker_beta",
                batch_size=2,
                tenant_id=self.tenant_id
            )
            claimed2_ids = {e.id for e in claimed2}
            self.assertEqual(len(claimed2_ids), 2)
            for e in claimed2:
                self.assertEqual(e.status, "PROCESSING")
                self.assertEqual(e.claimed_by, "worker_beta")
                self.assertIsNotNone(e.claimed_at)

        # Verification: Sets of claimed events are completely DISJOINT
        self.assertTrue(claimed1_ids.isdisjoint(claimed2_ids), "Worker 1 and Worker 2 must claim mutually exclusive events")
        self.assertEqual(claimed1_ids.union(claimed2_ids), set(event_ids))

    # -------------------------------------------------------------------------
    # Scenario 5: Outbox Retry Backoff and Dead-Letter Routing
    # -------------------------------------------------------------------------
    def test_05_outbox_retry_backoff_and_dead_letter_routing(self):
        ev_id = f"outbox_retry_{self.test_prefix}"
        repository.save_outbox_event(IntegrationOutbox(
            id=ev_id,
            tenant_id=self.tenant_id,
            event_type="finding.created",
            event_key=f"key_retry_{self.test_prefix}",
            destination="jira",
            payload_hash="hash_retry",
            payload_json={"test": True},
            status=OutboxStatus.PENDING.value,
            attempt=1
        ))

        with session_scope() as session:
            repo = OutboxRepository(session)
            # Attempt 1 -> 2: Failed with RETRYING
            ok = repo.mark_failed(ev_id, error="Jira API 500 error", max_retries=3, backoff_seconds=10)
            self.assertTrue(ok)

        # Verify state after first failure: attempt=2, status=RETRYING, next_retry_at calculated
        ev = repository.get_outbox_event(ev_id, tenant_id=self.tenant_id)
        self.assertEqual(ev.status, "RETRYING")
        self.assertEqual(ev.attempt, 2)
        self.assertEqual(ev.last_error, "Jira API 500 error")
        self.assertIsNotNone(ev.next_retry_at)

        with session_scope() as session:
            repo = OutboxRepository(session)
            # Attempt 2 -> 3: Reaches max_retries (3) -> routes to DEAD_LETTER
            ok2 = repo.mark_failed(ev_id, error="Jira API 503 Service Unavailable", max_retries=3, backoff_seconds=10)
            self.assertTrue(ok2)

        # Verify DEAD_LETTER state
        ev_dead = repository.get_outbox_event(ev_id, tenant_id=self.tenant_id)
        self.assertEqual(ev_dead.status, "DEAD_LETTER")
        self.assertEqual(ev_dead.attempt, 3)
        self.assertIsNone(ev_dead.next_retry_at)
        self.assertIn("503", ev_dead.last_error)

    # -------------------------------------------------------------------------
    # Scenario 6: Stale Event Recovery (Crash / Timeout Recovery)
    # -------------------------------------------------------------------------
    def test_06_stale_event_recovery(self):
        ev_id = f"outbox_stale_{self.test_prefix}"
        # Event stranded in PROCESSING from 10 minutes ago
        stranded_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        repository.save_outbox_event(IntegrationOutbox(
            id=ev_id,
            tenant_id=self.tenant_id,
            event_type="asset.verified",
            event_key=f"key_stale_{self.test_prefix}",
            destination="siem",
            payload_hash="hash_stale",
            payload_json={"stale": True},
            status="PROCESSING",
            claimed_at=stranded_time,
            claimed_by="crashed_worker_99"
        ))

        # Run recovery with 300-second (5 min) timeout threshold
        recovered_count = repository.recover_stale_outbox_events(timeout_seconds=300)
        self.assertGreaterEqual(recovered_count, 1)

        # Verify recovered event is reset to RETRYING with claimed fields cleared
        ev_recovered = repository.get_outbox_event(ev_id, tenant_id=self.tenant_id)
        self.assertEqual(ev_recovered.status, "RETRYING")
        self.assertIsNone(ev_recovered.claimed_at)
        self.assertIsNone(ev_recovered.claimed_by)

    # -------------------------------------------------------------------------
    # Scenario 7: API Key Lifecycle
    # -------------------------------------------------------------------------
    def test_07_api_key_lifecycle(self):
        raw_token = f"swp_live_{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        key_id = f"key_{self.test_prefix}"

        api_key = APIKey(
            id=key_id,
            tenant_id=self.tenant_id,
            name="CI/CD Integration Key",
            key_prefix="swp_live_ci",
            key_hash=token_hash,
            scopes=["scans:read", "scans:write", "findings:read"],
            status="active"
        )
        saved = repository.create_api_key(api_key)
        self.assertEqual(saved.id, key_id)
        self.assertEqual(saved.key_hash, token_hash)

        # Raw key is never stored in DB
        with session_scope() as session:
            raw_check = session.execute(
                text("SELECT key_hash, key_prefix FROM api_keys WHERE id = :id"),
                {"id": key_id}
            ).fetchone()
            self.assertEqual(raw_check.key_hash, token_hash)
            self.assertNotIn(raw_token, raw_check.key_hash)

        # Lookup by hash
        found = repository.get_api_key_by_hash(token_hash)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, key_id)
        self.assertEqual(found.scopes, ["scans:read", "scans:write", "findings:read"])

        # Update last_used_at
        used_time = datetime.now(timezone.utc).isoformat()
        found.last_used_at = used_time
        repository.update_api_key(found)
        updated = repository.get_api_key(key_id, tenant_id=self.tenant_id)
        self.assertEqual(updated.last_used_at, used_time)

        # Revoke API key
        revoked_ok = repository.revoke_api_key(key_id, tenant_id=self.tenant_id)
        self.assertTrue(revoked_ok)
        revoked_key = repository.get_api_key(key_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(revoked_key.revoked_at)

    # -------------------------------------------------------------------------
    # Scenario 8: Policy and Policy Versioning
    # -------------------------------------------------------------------------
    def test_08_policy_and_policy_versioning(self):
        policy_id = f"pol_{self.test_prefix}"
        policy = Policy(
            id=policy_id,
            tenant_id=self.tenant_id,
            name=f"Custom Profile {self.test_prefix}",
            type="SCAN_PROFILE",
            enabled=True
        )
        saved_policy = repository.save_policy(policy)
        self.assertEqual(saved_policy.id, policy_id)

        # Version 1
        v1_id = f"v1_{self.test_prefix}"
        def_v1 = {"max_depth": 3, "allowed_ports": [80, 443]}
        cs_v1 = hashlib.sha256(json.dumps(def_v1, sort_keys=True).encode()).hexdigest()
        v1 = PolicyVersion(
            id=v1_id,
            policy_id=policy_id,
            version=1,
            status=PolicyVersionStatus.ACTIVE.value,
            definition_json=def_v1,
            checksum=cs_v1,
            created_by="secops"
        )
        repository.save_policy_version(v1)

        # Version 2
        v2_id = f"v2_{self.test_prefix}"
        def_v2 = {"max_depth": 5, "allowed_ports": [80, 443, 8080]}
        cs_v2 = hashlib.sha256(json.dumps(def_v2, sort_keys=True).encode()).hexdigest()
        v2 = PolicyVersion(
            id=v2_id,
            policy_id=policy_id,
            version=2,
            status=PolicyVersionStatus.DRAFT.value,
            definition_json=def_v2,
            checksum=cs_v2,
            created_by="secops"
        )
        repository.save_policy_version(v2)

        # List policy versions
        versions = repository.list_policy_versions(policy_id)
        self.assertEqual(len(versions), 2)
        # Descending order by version number
        self.assertEqual(versions[0].version, 2)
        self.assertEqual(versions[1].version, 1)

        # Immutability check: v1 remains completely unchanged
        v1_retrieved = repository.get_policy_version(v1_id)
        self.assertEqual(v1_retrieved.definition_json, def_v1)
        self.assertEqual(v1_retrieved.checksum, cs_v1)

    # -------------------------------------------------------------------------
    # Scenario 9: Webhook Subscription and Delivery Lifecycle
    # -------------------------------------------------------------------------
    def test_09_webhook_subscription_and_delivery_lifecycle(self):
        integration_id = f"integ_{self.test_prefix}"
        integration = Integration(
            id=integration_id,
            tenant_id=self.tenant_id,
            type="webhook",
            name="SIEM Webhook Integration",
            enabled=True,
            config_reference={"url": "https://siem.corp.internal/hooks"},
            secret_reference="SIEM_AUTH_TOKEN"
        )
        saved_integ = repository.create_integration(integration)
        self.assertEqual(saved_integ.id, integration_id)

        # Create delivery attempt
        deliv_id = f"deliv_{self.test_prefix}"
        deliv = WebhookDelivery(
            id=deliv_id,
            tenant_id=self.tenant_id,
            integration_id=integration_id,
            event="finding.critical",
            payload_hash="hash_crit_123",
            status="pending",
            attempt=1
        )
        saved_deliv = repository.create_webhook_delivery(deliv)
        self.assertEqual(saved_deliv.id, deliv_id)

        # Update delivery to delivered
        saved_deliv.status = "delivered"
        repository.update_webhook_delivery(saved_deliv)

        retrieved_deliv = repository.get_webhook_delivery(deliv_id, tenant_id=self.tenant_id)
        self.assertEqual(retrieved_deliv.status, "delivered")

        # List deliveries for tenant
        deliveries = repository.list_webhook_deliveries(self.tenant_id)
        self.assertTrue(any(d.id == deliv_id for d in deliveries))

    # -------------------------------------------------------------------------
    # Scenario 10: Cross-Tenant Isolation
    # -------------------------------------------------------------------------
    def test_10_cross_tenant_isolation(self):
        # Create second tenant B
        tenant_b_id = f"tenant_b_{self.test_prefix}"
        repository.save_tenant(Tenant(
            id=tenant_b_id,
            name="Tenant B Isolation Test",
            slug=f"slug_b_{self.test_prefix}",
            status="active"
        ))

        # Schedule under Tenant A
        sched_a = ScheduledScan(
            id=f"sched_iso_{self.test_prefix}",
            tenant_id=self.tenant_id,
            target_url="https://tenant-a.internal"
        )
        repository.save_scheduled_scan(sched_a)

        # API Key under Tenant A
        key_a = APIKey(
            id=f"key_iso_{self.test_prefix}",
            tenant_id=self.tenant_id,
            name="Tenant A Key",
            key_hash=hashlib.sha256(f"token_a_{self.test_prefix}".encode()).hexdigest()
        )
        repository.create_api_key(key_a)

        # Policy under Tenant A
        policy_a = Policy(
            id=f"pol_iso_{self.test_prefix}",
            tenant_id=self.tenant_id,
            name=f"Policy A {self.test_prefix}"
        )
        repository.save_policy(policy_a)

        # Outbox event under Tenant A
        outbox_a = IntegrationOutbox(
            id=f"outbox_iso_{self.test_prefix}",
            tenant_id=self.tenant_id,
            event_type="test",
            event_key=f"key_iso_{self.test_prefix}",
            payload_hash="iso_hash"
        )
        repository.save_outbox_event(outbox_a)

        # --- Assertions: Tenant B must NOT access Tenant A resources ---
        # 1. Schedules
        self.assertIsNone(repository.get_scheduled_scan(sched_a.id, tenant_id=tenant_b_id))
        schedules_b = repository.list_scheduled_scans(tenant_id=tenant_b_id)
        self.assertFalse(any(s.id == sched_a.id for s in schedules_b))

        # 2. API Keys
        self.assertIsNone(repository.get_api_key(key_a.id, tenant_id=tenant_b_id))
        keys_b = repository.list_api_keys(tenant_b_id)
        self.assertFalse(any(k.id == key_a.id for k in keys_b))

        # 3. Policies
        self.assertIsNone(repository.get_policy(policy_a.id, tenant_id=tenant_b_id))
        policies_b = repository.list_policies(tenant_b_id)
        self.assertFalse(any(p.id == policy_a.id for p in policies_b))

        # 4. Outbox
        self.assertIsNone(repository.get_outbox_event(outbox_a.id, tenant_id=tenant_b_id))

    # -------------------------------------------------------------------------
    # Scenario 11: Transaction Rollback on Failure
    # -------------------------------------------------------------------------
    def test_11_transaction_rollback_on_failure(self):
        # Attempt to insert an outbox event referencing non-existent tenant (FK violation)
        bad_outbox = IntegrationOutbox(
            id=f"bad_outbox_{self.test_prefix}",
            tenant_id="non_existent_tenant_999999",
            event_type="error.test",
            event_key=f"bad_key_{self.test_prefix}",
            payload_hash="bad_hash"
        )

        with self.assertRaises(Exception):
            repository.save_outbox_event(bad_outbox)

        # Direct SQL verify nothing was inserted / clean state
        with session_scope() as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM integration_outbox WHERE id = :id"),
                {"id": bad_outbox.id}
            ).scalar()
            self.assertEqual(count, 0, "Failed transaction must not leave orphan records")

    # -------------------------------------------------------------------------
    # Scenario 12: Database Outage / Fail-Closed Behavior
    # -------------------------------------------------------------------------
    def test_12_database_outage_fail_closed_behavior(self):
        # Switch DATABASE_URL to an unreachable port
        unreachable_url = "postgresql+psycopg://s10_user:s10_dev_password_123@127.0.0.1:9999/sentinelwp_s10"
        os.environ["DATABASE_URL"] = unreachable_url
        reset_engine()
        repository.reset_conn()

        try:
            # Operation must raise exception and NOT fall back silently to SQLite
            with self.assertRaises(Exception) as ctx:
                repository.list_scheduled_scans(tenant_id=self.tenant_id)
            err = str(ctx.exception).lower()
            self.assertTrue(
                "connection" in err or "refused" in err or "operational" in err or "error" in err,
                f"Expected explicit connection error, got: {err}"
            )
        finally:
            os.environ["DATABASE_URL"] = get_sprint10_postgres_url()
            reset_engine()
            repository.reset_conn()

    # -------------------------------------------------------------------------
    # Scenario 13: SQLite Regression / Parity
    # -------------------------------------------------------------------------
    def test_13_sqlite_parity_when_postgres_unconfigured(self):
        # Unset DATABASE_URL to simulate native SQLite operational mode
        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("WSA_DATABASE_URL", None)
        os.environ.pop("SENTINELWP_SPRINT10_PG_URL", None)
        reset_engine()
        repository.reset_conn()
        repository._allow_operational_sqlite_override = True
        repository.init_db(force=True)

        try:
            # Schedule in SQLite
            sqlite_sched_id = f"sched_sqlite_{self.test_prefix}"
            sched = ScheduledScan(
                id=sqlite_sched_id,
                tenant_id="default-tenant",
                target_url="https://sqlite.internal",
                scan_mode="passive",
                interval_hours=24
            )
            repository.save_scheduled_scan(sched)
            retrieved = repository.get_scheduled_scan(sqlite_sched_id, tenant_id="default-tenant")
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.target_url, "https://sqlite.internal")

            # Outbox in SQLite
            sqlite_ev_id = f"outbox_sqlite_{self.test_prefix}"
            ev = IntegrationOutbox(
                id=sqlite_ev_id,
                tenant_id="default-tenant",
                event_type="test.sqlite",
                event_key=f"key_sqlite_{self.test_prefix}",
                payload_hash="sqlite_hash"
            )
            repository.save_outbox_event(ev)
            outbox_retrieved = repository.get_outbox_event(sqlite_ev_id, tenant_id="default-tenant")
            self.assertIsNotNone(outbox_retrieved)
            self.assertEqual(outbox_retrieved.event_type, "test.sqlite")
        finally:
            os.environ["DATABASE_URL"] = get_sprint10_postgres_url()
            reset_engine()
            repository.reset_conn()
            repository._allow_operational_sqlite_override = False


if __name__ == "__main__":
    unittest.main()
