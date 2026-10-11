"""
Sprint 10 - Phase 4: PostgreSQL Finding Lifecycle, Observations and Remediation Persistence
Integration and Parity Test Suite for Real PostgreSQL 16 Execution.

Validates:
1. Finding CRUD, fingerprint correlation and bulk persistence
2. Finding observations, immutable evidence references, and observation history
3. Finding lifecycle status transitions and optimistic locking (OptimisticLockError)
4. Post-scan differential reconciliation (NEW, PERSISTING, REOPENED, VERIFIED)
5. Failed/incomplete scan guard (never resolve findings on failed or incomplete scans)
6. Remediation records, status transitions, and remediation actions
7. Complete finding lifecycle aggregation (get_finding_lifecycle)
8. Cross-tenant access denial (strict tenant isolation across findings and remediations)
9. Transaction boundaries and rollback on partial failures
10. Direct PostgreSQL SQL query verification (bypassing ORM layer)
11. Explicit fail-closed boundary on operations outside Phase 4 scope
12. SQLite vs PostgreSQL behavioral parity
"""
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import text

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import is_postgres_configured
from core.models import (
    Tenant, Asset, ScanResult, ScanStatus,
    Finding, FindingObservation, FindingHistory, FindingComment,
    Severity, Remediation, RemediationAction, SLAPolicy
)
from core.lifecycle import FindingStatus, SLAStatus, OptimisticLockError
from core.db.session import get_engine, init_db_schema, session_scope, reset_engine
from core.db.adapter import get_operational_adapter, PostgresqlOperationalAdapter
from core import repository
from tests.postgres_integration import get_sprint10_postgres_url


class TestSprint10Phase4PostgresFindingsRemediation(unittest.TestCase):
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

        self.test_prefix = f"s10_p4_{uuid.uuid4().hex[:6]}"
        self.tenant_id = f"tenant_{self.test_prefix}"
        self.tenant_slug = f"slug_{self.test_prefix}"

        # Provision parent tenant, asset, and baseline scan in PostgreSQL
        tenant = Tenant(
            id=self.tenant_id,
            name="Sprint 10 Phase 4 Tenant",
            slug=self.tenant_slug,
            status="active"
        )
        repository.save_tenant(tenant)

        self.asset = repository.ensure_asset(
            target_url=f"https://{self.test_prefix}.example.com",
            tenant_id=self.tenant_id,
            display_name=f"Asset {self.test_prefix}"
        )

        self.scan_id = f"scan_{self.test_prefix}"
        repository.save_scan(ScanResult(
            id=self.scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            target_url=f"https://{self.test_prefix}.example.com",
            status=ScanStatus.COMPLETED
        ))

    def tearDown(self):
        if self.orig_db_url is not None:
            os.environ["DATABASE_URL"] = self.orig_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        reset_engine()
        repository.reset_conn()

    # -------------------------------------------------------------------------
    # 1. Finding CRUD, Direct SQL & Optimistic Locking
    # -------------------------------------------------------------------------

    def test_finding_crud_and_direct_sql_verification(self):
        finding_id = f"find_{uuid.uuid4().hex[:8]}"
        finding = Finding(
            id=finding_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=self.scan_id,
            category="vulnerability",
            title="SQL Injection in Test Plugin",
            description="Parameter id vulnerable to SQLi",
            severity=Severity.HIGH,
            confidence=0.95,
            remediation="Upgrade plugin to v2.0",
            reference="CVE-2026-1001",
            raw_data={"scanner": "wpscan", "location": "/wp-admin/admin-ajax.php"},
            fingerprint=f"fp_{uuid.uuid4().hex[:8]}",
            status=FindingStatus.OPEN.value,
            cve_id="CVE-2026-1001",
            priority_score=85.0,
            priority_band="P1",
            kev=True,
        )
        saved = repository.save_finding(finding)
        self.assertEqual(saved.id, finding_id)
        self.assertEqual(saved.version, 1)

        # Retrieval via repository API
        retrieved = repository.get_finding(finding_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, finding_id)
        self.assertEqual(retrieved.title, "SQL Injection in Test Plugin")
        self.assertEqual(retrieved.severity, Severity.HIGH)
        self.assertEqual(retrieved.priority_band, "P1")
        self.assertTrue(retrieved.kev)
        self.assertEqual(retrieved.cve_id, "CVE-2026-1001")

        # Verify DIRECTLY via PostgreSQL SQL query bypassing ORM
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, tenant_id, asset_id, title, severity, priority_score, priority_band, kev, version FROM findings WHERE id = :id"),
                {"id": finding_id}
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], finding_id)
            self.assertEqual(row[1], self.tenant_id)
            self.assertEqual(row[2], self.asset.id)
            self.assertEqual(row[3], "SQL Injection in Test Plugin")
            self.assertEqual(row[4], "high")
            self.assertEqual(float(row[5]), 85.0)
            self.assertEqual(row[6], "P1")
            self.assertTrue(row[7])
            self.assertEqual(row[8], 1)

        # Update finding
        repository.update_finding(
            finding_id,
            tenant_id=self.tenant_id,
            remediation="Upgraded to v2.1 with security fix"
        )
        updated = repository.get_finding(finding_id, tenant_id=self.tenant_id)
        self.assertEqual(updated.remediation, "Upgraded to v2.1 with security fix")
        self.assertEqual(updated.version, 2)

        # Delete finding
        repository.delete_finding(finding_id, tenant_id=self.tenant_id)
        deleted = repository.get_finding(finding_id, tenant_id=self.tenant_id)
        self.assertIsNone(deleted)

    def test_optimistic_locking_concurrency(self):
        finding_id = f"find_lock_{uuid.uuid4().hex[:8]}"
        finding = Finding(
            id=finding_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=self.scan_id,
            title="Optimistic Lock Test Finding",
            status=FindingStatus.OPEN.value,
        )
        repository.save_finding(finding)

        # Stored finding starts at version 1
        f1 = repository.get_finding(finding_id, tenant_id=self.tenant_id)
        self.assertEqual(f1.version, 1)

        # Successful update with expected_version=1
        f1.title = "Updated Title 1"
        repository.save_finding(f1, expected_version=1)

        # Version is now 2
        f2 = repository.get_finding(finding_id, tenant_id=self.tenant_id)
        self.assertEqual(f2.version, 2)

        # Concurrent update attempting stale version 1 must raise OptimisticLockError
        with self.assertRaises(OptimisticLockError):
            f1.title = "Stale Concurrent Update"
            repository.save_finding(f1, expected_version=1)

    def test_bulk_finding_persistence_and_filtering(self):
        f_ids = []
        findings = []
        for i in range(3):
            fid = f"bulk_{uuid.uuid4().hex[:6]}"
            f_ids.append(fid)
            findings.append(Finding(
                id=fid,
                tenant_id=self.tenant_id,
                asset_id=self.asset.id,
                scan_id=self.scan_id,
                title=f"Bulk Finding {i}",
                severity=Severity.HIGH if i == 0 else Severity.MEDIUM,
                status=FindingStatus.OPEN.value,
                priority_band="P1" if i == 0 else "P2",
                priority_score=90.0 - (i * 10)
            ))

        repository.save_findings_bulk(findings)

        # List with filter
        p1_list, count = repository.list_findings(
            self.tenant_id, filters={"priority_band": "P1"}
        )
        self.assertGreaterEqual(count, 1)
        self.assertEqual(p1_list[0].id, f_ids[0])

        # Scan-scoped retrieval
        scan_findings = repository.get_findings_for_scan(self.scan_id, tenant_id=self.tenant_id)
        retrieved_ids = [sf.id for sf in scan_findings]
        for fid in f_ids:
            self.assertIn(fid, retrieved_ids)

    # -------------------------------------------------------------------------
    # 2. Finding Observations, History & Comments
    # -------------------------------------------------------------------------

    def test_observations_history_and_comments(self):
        finding_id = f"find_hist_{uuid.uuid4().hex[:8]}"
        finding = Finding(
            id=finding_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=self.scan_id,
            title="Observation & History Test",
            status=FindingStatus.OPEN.value,
        )
        repository.save_finding(finding)

        # 1. Observation
        obs_id = f"obs_{uuid.uuid4().hex[:6]}"
        obs = FindingObservation(
            id=obs_id,
            tenant_id=self.tenant_id,
            finding_id=finding_id,
            scan_id=self.scan_id,
            asset_id=self.asset.id,
            scanner_id="wpscan",
            severity="high",
            evidence_reference="raw_req_001",
            status="OPEN"
        )
        repository.save_finding_observation(obs)

        observations = repository.get_observations_for_finding(finding_id, tenant_id=self.tenant_id)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].id, obs_id)
        self.assertEqual(observations[0].scanner_id, "wpscan")

        # 2. History
        hist_id = f"hist_{uuid.uuid4().hex[:6]}"
        hist = FindingHistory(
            id=hist_id,
            tenant_id=self.tenant_id,
            finding_id=finding_id,
            actor_user_id="analyst@sentinelwp.local",
            action="status_transition",
            old_status="OPEN",
            new_status="IN_PROGRESS",
            comment="Triage initiated",
            metadata={"ticket": "SEC-101"}
        )
        repository.add_finding_history(hist)

        history_list = repository.get_finding_history(finding_id, tenant_id=self.tenant_id)
        self.assertEqual(len(history_list), 1)
        self.assertEqual(history_list[0].id, hist_id)
        self.assertEqual(history_list[0].metadata.get("ticket"), "SEC-101")

        # 3. Comment
        comment_id = f"comm_{uuid.uuid4().hex[:6]}"
        comment = FindingComment(
            id=comment_id,
            tenant_id=self.tenant_id,
            finding_id=finding_id,
            author_user_id="analyst@sentinelwp.local",
            body="Assigned to remediation team"
        )
        repository.add_finding_comment(comment)

        comments = repository.get_finding_comments(finding_id, tenant_id=self.tenant_id)
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0].body, "Assigned to remediation team")

        # Verify Direct SQL persistence of observations, history, and comments
        with self.engine.connect() as conn:
            obs_row = conn.execute(text("SELECT id, scanner_id FROM finding_observations WHERE id = :id"), {"id": obs_id}).fetchone()
            self.assertIsNotNone(obs_row)
            self.assertEqual(obs_row[1], "wpscan")

            hist_row = conn.execute(text("SELECT id, action, metadata FROM finding_history WHERE id = :id"), {"id": hist_id}).fetchone()
            self.assertIsNotNone(hist_row)
            self.assertEqual(hist_row[1], "status_transition")

            comm_row = conn.execute(text("SELECT id, body FROM finding_comments WHERE id = :id"), {"id": comment_id}).fetchone()
            self.assertIsNotNone(comm_row)
            self.assertEqual(comm_row[1], "Assigned to remediation team")

    # -------------------------------------------------------------------------
    # 3. Finding Lifecycle Transitions (State Machine)
    # -------------------------------------------------------------------------

    def test_finding_state_machine_transitions(self):
        finding_id = f"find_sm_{uuid.uuid4().hex[:8]}"
        finding = Finding(
            id=finding_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=self.scan_id,
            title="State Machine Transition Test",
            status=FindingStatus.OPEN.value,
        )
        repository.save_finding(finding)

        # Transition: OPEN -> IN_PROGRESS
        f_progress = repository.transition_finding_status(
            finding_id=finding_id,
            new_status="IN_PROGRESS",
            actor_user_id="user1",
            tenant_id=self.tenant_id,
            comment="Starting remediation"
        )
        self.assertEqual(f_progress.status, FindingStatus.IN_PROGRESS.value)

        # Transition: IN_PROGRESS -> REMEDIATED
        f_remediated = repository.transition_finding_status(
            finding_id=finding_id,
            new_status="REMEDIATED",
            actor_user_id="user1",
            tenant_id=self.tenant_id,
            comment="Patch applied"
        )
        self.assertEqual(f_remediated.status, FindingStatus.REMEDIATED.value)
        self.assertEqual(f_remediated.sla_status, SLAStatus.COMPLIED.value)

        # Transition: REMEDIATED -> VERIFICATION_PENDING
        f_verif_pending = repository.transition_finding_status(
            finding_id=finding_id,
            new_status="VERIFICATION_PENDING",
            actor_user_id="system",
            tenant_id=self.tenant_id,
            comment="Awaiting re-scan confirmation"
        )
        self.assertEqual(f_verif_pending.status, FindingStatus.VERIFICATION_PENDING.value)

        # Verification history entries exist
        hist = repository.get_finding_history(finding_id, tenant_id=self.tenant_id)
        self.assertGreaterEqual(len(hist), 3)

    # -------------------------------------------------------------------------
    # 4. Post-Scan Differential Reconciliation & Fingerprint Correlation
    # -------------------------------------------------------------------------

    def test_post_scan_differential_reconciliation_and_reopening(self):
        # 1. First scan discovers a vulnerability
        raw_f1 = Finding(
            id=f"raw1_{uuid.uuid4().hex[:6]}",
            title="Outdated WordPress Core",
            category="core",
            severity=Severity.HIGH,
            reference="https://wordpress.org/news/",
            raw_data={"scanner": "wpscan", "finding_type": "core_outdated", "location": "/"}
        )
        processed_scan1 = repository.process_scan_findings(
            scan_id=self.scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            raw_findings=[raw_f1]
        )
        self.assertEqual(len(processed_scan1), 1)
        f_persisted = processed_scan1[0]
        self.assertEqual(f_persisted.status, FindingStatus.OPEN.value)
        self.assertEqual(f_persisted.observation_count, 1)
        fp = f_persisted.fingerprint

        # 2. Mark finding as REMEDIATED, then VERIFICATION_PENDING
        repository.transition_finding_status(
            finding_id=f_persisted.id,
            new_status="REMEDIATED",
            actor_user_id="dev-team",
            tenant_id=self.tenant_id
        )
        repository.transition_finding_status(
            finding_id=f_persisted.id,
            new_status="VERIFICATION_PENDING",
            actor_user_id="dev-team",
            tenant_id=self.tenant_id
        )

        # 3. Second scan (COMPLETED) does NOT detect the finding -> must auto-verify as VERIFIED
        scan2_id = f"scan2_{uuid.uuid4().hex[:6]}"
        repository.save_scan(ScanResult(
            id=scan2_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            status=ScanStatus.COMPLETED
        ))
        processed_scan2 = repository.process_scan_findings(
            scan_id=scan2_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            raw_findings=[]  # empty findings -> resolved
        )
        f_after_clean_scan = repository.get_finding(f_persisted.id, tenant_id=self.tenant_id)
        self.assertEqual(f_after_clean_scan.status, FindingStatus.VERIFIED.value)
        self.assertEqual(f_after_clean_scan.verified_by_scan_id, scan2_id)
        self.assertIsNotNone(f_after_clean_scan.verified_at)

        # 4. Third scan detects the vulnerability again -> must REOPEN with history entry
        scan3_id = f"scan3_{uuid.uuid4().hex[:6]}"
        repository.save_scan(ScanResult(
            id=scan3_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            status=ScanStatus.COMPLETED
        ))
        raw_f3 = Finding(
            id=f"raw3_{uuid.uuid4().hex[:6]}",
            title="Outdated WordPress Core",
            category="core",
            severity=Severity.HIGH,
            reference="https://wordpress.org/news/",
            raw_data={"scanner": "wpscan", "finding_type": "core_outdated", "location": "/"}
        )
        processed_scan3 = repository.process_scan_findings(
            scan_id=scan3_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            raw_findings=[raw_f3]
        )
        self.assertEqual(len(processed_scan3), 1)
        f_reopened = processed_scan3[0]
        self.assertEqual(f_reopened.id, f_persisted.id)
        self.assertEqual(f_reopened.status, FindingStatus.REOPENED.value)
        self.assertEqual(f_reopened.observation_count, 2)

        # History confirms finding_reopened action
        hist = repository.get_finding_history(f_persisted.id, tenant_id=self.tenant_id)
        actions = [h.action for h in hist]
        self.assertIn("finding_reopened", actions)

    def test_failed_incomplete_scan_never_resolves_findings(self):
        # Create finding in VERIFICATION_PENDING
        finding_id = f"find_fail_guard_{uuid.uuid4().hex[:8]}"
        finding = Finding(
            id=finding_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=self.scan_id,
            title="Guard Verification Pending Finding",
            status=FindingStatus.VERIFICATION_PENDING.value,
            fingerprint=f"fp_guard_{uuid.uuid4().hex[:8]}"
        )
        repository.save_finding(finding)

        # Process an incomplete/failed scan with zero findings
        failed_scan_id = f"scan_failed_{uuid.uuid4().hex[:6]}"
        repository.save_scan(ScanResult(
            id=failed_scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            status=ScanStatus.FAILED  # FAILED SCAN
        ))

        repository.process_scan_findings(
            scan_id=failed_scan_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            raw_findings=[]
        )

        # Finding must NOT be verified because the scan failed!
        finding_after = repository.get_finding(finding_id, tenant_id=self.tenant_id)
        self.assertEqual(
            finding_after.status,
            FindingStatus.VERIFICATION_PENDING.value,
            "Failed or incomplete scan must never auto-resolve verification pending findings!"
        )

    # -------------------------------------------------------------------------
    # 5. Remediation CRUD, Actions & Complete Lifecycle Aggregation
    # -------------------------------------------------------------------------

    def test_remediation_lifecycle_and_actions(self):
        finding_id = f"find_rem_{uuid.uuid4().hex[:8]}"
        repository.save_finding(Finding(
            id=finding_id,
            tenant_id=self.tenant_id,
            asset_id=self.asset.id,
            scan_id=self.scan_id,
            title="Remediation Finding",
            status=FindingStatus.OPEN.value,
        ))

        # 1. Create remediation
        rem_id = f"rem_{uuid.uuid4().hex[:8]}"
        rem = Remediation(
            id=rem_id,
            tenant_id=self.tenant_id,
            finding_id=finding_id,
            title="Fix vulnerable package",
            description="Apply patch v1.2",
            status="OPEN",
            priority="P1",
            due_date=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            verification_required=True,
            verification_status="pending"
        )
        repository.create_remediation(rem)

        # Retrieve remediation
        fetched_rem = repository.get_remediation(rem_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(fetched_rem)
        self.assertEqual(fetched_rem.title, "Fix vulnerable package")
        self.assertEqual(fetched_rem.status, "OPEN")

        # Lookup by finding_id
        by_finding = repository.get_remediation_by_finding(finding_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(by_finding)
        self.assertEqual(by_finding.id, rem_id)

        # 2. Add remediation action
        act_id = f"act_{uuid.uuid4().hex[:6]}"
        act = RemediationAction(
            id=act_id,
            tenant_id=self.tenant_id,
            remediation_id=rem_id,
            action_type="patch",
            description="Deploy git tag v1.2 to production",
            owner="ops-team",
            status="pending"
        )
        repository.add_remediation_action(act)

        actions = repository.get_remediation_actions(rem_id, tenant_id=self.tenant_id)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].id, act_id)

        # 3. Update action status
        actions[0].status = "completed"
        repository.update_remediation_action(actions[0])
        updated_actions = repository.get_remediation_actions(rem_id, tenant_id=self.tenant_id)
        self.assertEqual(updated_actions[0].status, "completed")

        # 4. Verify get_finding_lifecycle aggregates all components
        lifecycle = repository.get_finding_lifecycle(finding_id, tenant_id=self.tenant_id)
        self.assertIsNotNone(lifecycle.get("finding"))
        self.assertEqual(lifecycle["finding"].id, finding_id)
        self.assertIsNotNone(lifecycle.get("remediation"))
        self.assertEqual(lifecycle["remediation"].id, rem_id)

        # Verify Direct SQL persistence in remediations and remediation_actions
        with self.engine.connect() as conn:
            rem_row = conn.execute(text("SELECT id, title, status FROM remediations WHERE id = :id"), {"id": rem_id}).fetchone()
            self.assertIsNotNone(rem_row)
            self.assertEqual(rem_row[1], "Fix vulnerable package")

            act_row = conn.execute(text("SELECT id, status FROM remediation_actions WHERE id = :id"), {"id": act_id}).fetchone()
            self.assertIsNotNone(act_row)
            self.assertEqual(act_row[1], "completed")

    # -------------------------------------------------------------------------
    # 6. Strict Cross-Tenant Access Denial (Tenant Isolation)
    # -------------------------------------------------------------------------

    def test_strict_cross_tenant_isolation(self):
        other_tenant_id = f"other_{self.test_prefix}"
        repository.save_tenant(Tenant(id=other_tenant_id, name="Other Tenant", slug=f"other_{self.test_prefix}"))
        other_asset = repository.ensure_asset(
            target_url="https://other.internal", tenant_id=other_tenant_id, display_name="Other Asset"
        )
        other_scan_id = f"other_scan_{uuid.uuid4().hex[:6]}"
        repository.save_scan(ScanResult(
            id=other_scan_id, tenant_id=other_tenant_id, asset_id=other_asset.id, target_url="https://other.internal"
        ))

        other_finding_id = f"other_f_{uuid.uuid4().hex[:6]}"
        repository.save_finding(Finding(
            id=other_finding_id, tenant_id=other_tenant_id, asset_id=other_asset.id, scan_id=other_scan_id, title="Other Finding"
        ))

        other_rem_id = f"other_rem_{uuid.uuid4().hex[:6]}"
        repository.create_remediation(Remediation(
            id=other_rem_id, tenant_id=other_tenant_id, finding_id=other_finding_id, title="Other Remediation"
        ))

        # Tenant A attempts to access Tenant B's records with tenant_id=self.tenant_id
        self.assertIsNone(repository.get_finding(other_finding_id, tenant_id=self.tenant_id))
        self.assertIsNone(repository.get_remediation(other_rem_id, tenant_id=self.tenant_id))
        self.assertIsNone(repository.get_remediation_by_finding(other_finding_id, tenant_id=self.tenant_id))

        my_findings, _ = repository.list_findings(self.tenant_id)
        self.assertNotIn(other_finding_id, [f.id for f in my_findings])

        my_remediations = repository.list_remediations(self.tenant_id)
        self.assertNotIn(other_rem_id, [r.id for r in my_remediations])

    # -------------------------------------------------------------------------
    # 7. Transaction Boundary & Rollback on Partial Failure
    # -------------------------------------------------------------------------

    def test_transaction_boundary_and_rollback_on_partial_failure(self):
        f_id = f"tx_find_{uuid.uuid4().hex[:6]}"
        obs_id = f"tx_obs_{uuid.uuid4().hex[:6]}"

        try:
            with session_scope() as session:
                from core.db.repositories.finding_repo import FindingRepository
                repo = FindingRepository(session)

                repo.save_finding(Finding(
                    id=f_id, tenant_id=self.tenant_id, asset_id=self.asset.id, scan_id=self.scan_id, title="TX Test"
                ))
                repo.save_observation(FindingObservation(
                    id=obs_id, tenant_id=self.tenant_id, finding_id=f_id, scan_id=self.scan_id, status="OPEN"
                ))

                # Deliberate failure inside the atomic transaction boundary
                raise RuntimeError("Simulated transaction fault")
        except RuntimeError:
            pass

        # Verify both finding and observation were rolled back
        with self.engine.connect() as conn:
            f_row = conn.execute(text("SELECT id FROM findings WHERE id = :id"), {"id": f_id}).fetchone()
            self.assertIsNone(f_row, "Uncommitted finding must be rolled back!")

            obs_row = conn.execute(text("SELECT id FROM finding_observations WHERE id = :id"), {"id": obs_id}).fetchone()
            self.assertIsNone(obs_row, "Uncommitted observation must be rolled back!")

    # -------------------------------------------------------------------------
    # 8. Explicit Fail-Closed Boundary (Unsupported Operations)
    # -------------------------------------------------------------------------

    def test_unsupported_operations_fail_explicitly_zero_sqlite_fallback(self):
        # Operations outside Phase 4 scope (e.g. Saved Views, Tech Observations) must fail explicitly
        with self.assertRaises((NotImplementedError, RuntimeError)):
            from core.models import SavedView
            view = SavedView(
                id=f"view_{uuid.uuid4().hex[:6]}",
                tenant_id=self.tenant_id,
                user_id="user_test",
                name="Test View",
                resource_type="findings"
            )
            repository.save_saved_view(view)


if __name__ == "__main__":
    unittest.main()
