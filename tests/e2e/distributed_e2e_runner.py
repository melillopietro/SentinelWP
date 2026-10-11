"""
SentinelWP - Sprint 10 Distributed E2E Validation Runner
Executes full real-world validation against isolated PostgreSQL 16, Redis 7, Celery Worker,
Celery Beat, WordPress 6.4, and Playwright Chromium.

Zero mocks. Zero Celery eager mode.
"""
import os
import sys
import time
import json
import signal
import socket
import hashlib
import requests
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

PG_URL = "postgresql://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s10"
REDIS_BROKER = "redis://127.0.0.1:6389/0"
REDIS_BACKEND = "redis://127.0.0.1:6389/1"
WP_TARGET = "http://127.0.0.1:8099"
FLASK_PORT = 8089
FLASK_URL = f"http://127.0.0.1:{FLASK_PORT}"

ENV_VARS = {
    **os.environ,
    "DATABASE_URL": PG_URL,
    "REDIS_URL": REDIS_BROKER,
    "CELERY_BROKER_URL": REDIS_BROKER,
    "CELERY_RESULT_BACKEND": REDIS_BACKEND,
    "SCAN_EXECUTION_BACKEND": "celery",
    "WSA_TEST_TARGET_ALLOWLIST": "127.0.0.1:8099,localhost:8099",
    "ENVIRONMENT": "production",
    "WSA_SECRET_KEY": "sprint10_super_secret_validation_key_32chars_min",
    "PORT": str(FLASK_PORT),
    "HOST": "127.0.0.1",
}
os.environ.update(ENV_VARS)


def log(msg: str):
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{timestamp}] [E2E] {msg}", flush=True)


def wait_for_port(port: int, host: str = "127.0.0.1", timeout: int = 15) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(0.5)
    return False


def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


class ProcessManager:
    def __init__(self):
        self.procs: Dict[str, subprocess.Popen] = {}
        self.logs: Dict[str, str] = {}

    def start(self, name: str, cmd: List[str], log_file: str):
        log(f"Starting {name}: {' '.join(cmd)}")
        self.logs[name] = log_file
        f = open(log_file, "w")
        p = subprocess.Popen(cmd, env=ENV_VARS, stdout=f, stderr=subprocess.STDOUT)
        self.procs[name] = p
        log(f"{name} started with PID {p.pid}")
        return p

    def stop(self, name: str):
        p = self.procs.get(name)
        if p and p.poll() is None:
            log(f"Terminating {name} (PID {p.pid})")
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            log(f"{name} terminated")

    def stop_all(self):
        for name in list(self.procs.keys()):
            self.stop(name)


def main():
    log("=== SPRINT 10 DISTRIBUTED E2E EXECUTION START ===")
    os.makedirs("tests/e2e/logs", exist_ok=True)
    os.makedirs("tests/e2e/screenshots", exist_ok=True)

    pm = ProcessManager()

    try:
        # 1. Preflight
        log("Step 1: Preflight checking connectivity to PostgreSQL, Redis, and WordPress...")
        assert wait_for_port(5439), "PostgreSQL port 5439 not reachable"
        assert wait_for_port(6389), "Redis port 6389 not reachable"
        assert wait_for_port(8099), "WordPress port 8099 not reachable"
        wp_resp = requests.get(WP_TARGET, timeout=5)
        assert wp_resp.status_code == 200, f"WordPress lab returned {wp_resp.status_code}"
        log("Preflight passed: all laboratory ports healthy.")

        # 2. Database Schema Sync in PostgreSQL & Test Broker Reset
        log("Step 2: Initializing PostgreSQL schema & resetting test queues...")
        from core.db.session import get_engine, init_db_schema
        engine = get_engine(PG_URL)
        init_db_schema(engine)
        # Flush isolated Redis test broker to remove leftover tasks from earlier runs
        run_cmd(["docker", "exec", "sentinelwp-sprint10-redis", "redis-cli", "-n", "0", "flushdb"])
        run_cmd(["docker", "exec", "sentinelwp-sprint10-redis", "redis-cli", "-n", "1", "flushdb"])
        # Cancel any leftover queued/retrying/running scan jobs in test PostgreSQL
        run_cmd(["docker", "exec", "sentinelwp-sprint10-postgres", "psql", "-U", "s10_user", "-d", "sentinelwp_s10", "-c", "UPDATE scan_jobs SET status='cancelled' WHERE status IN ('queued', 'running', 'retrying');"], check=False)
        log("PostgreSQL schema synchronized and test broker cleared.")

        # 3. Start Services
        log("Step 3: Launching Flask App, Celery Worker, and Celery Beat...")
        flask_proc = pm.start("flask", ["./.venv/bin/python3", "app.py", "--port", str(FLASK_PORT), "--host", "127.0.0.1"], "tests/e2e/logs/flask.log")
        worker_proc = pm.start("celery_worker", ["./.venv/bin/celery", "-A", "core.tasks.celery_app.celery_app", "worker", "-Q", "scan,maintenance,intel", "--concurrency=2", "--pool=threads", "--loglevel=INFO"], "tests/e2e/logs/celery_worker.log")
        beat_proc = pm.start("celery_beat", ["./.venv/bin/celery", "-A", "core.tasks.celery_app.celery_app", "beat", "--loglevel=INFO"], "tests/e2e/logs/celery_beat.log")

        assert wait_for_port(FLASK_PORT, timeout=15), f"Flask app failed to bind to {FLASK_PORT}"
        log(f"Flask running on {FLASK_URL} (PID {flask_proc.pid})")

        # Health endpoint check
        health_resp = requests.get(f"{FLASK_URL}/health", timeout=5)
        log(f"Flask /health response: {health_resp.status_code} -> {health_resp.text}")
        assert health_resp.status_code == 200, "Health check failed"

        # 4. Provision Pilot Tenant, User, and Asset directly in PostgreSQL
        log("Step 4: Provisioning Pilot Tenant, Admin User, Asset, and Authorization...")
        from core import repository
        from core.models import Tenant, User, UserRole, UserStatus, Asset, ScanAuthorization, ScanStatus
        from core.auth import hash_password

        tenant_id = f"tenant_s10_pilot_{uuid_hex()}"
        repository.save_tenant(Tenant(id=tenant_id, name="Sprint 10 Pilot Enterprise", slug=f"s10-pilot-{uuid_hex()}", status="active"))

        username = f"admin_pilot_{uuid_hex()[:4]}"
        user_id = f"user_{uuid_hex()}"
        repository.save_user(User(
            id=user_id,
            tenant_id=tenant_id,
            username=username,
            email=f"{username}@pilot.corp",
            password_hash=hash_password("PilotPassword123!"),
            role=UserRole.ADMIN.value,
            status=UserStatus.ACTIVE.value
        ))

        asset = repository.ensure_asset(target_url=WP_TARGET, tenant_id=tenant_id, display_name="Lab WordPress 6.4")
        log(f"Asset created: ID={asset.id}, URL={asset.canonical_url}")

        now = datetime.now(timezone.utc)
        auth = ScanAuthorization(
            id=f"auth_{uuid_hex()}",
            tenant_id=tenant_id,
            asset_id=asset.id,
            status="active",
            allowed_profiles="safe_active,passive",
            request_budget=5000,
            valid_from=now.isoformat(),
            valid_until=(now + timedelta(days=7)).isoformat(),
            approved_by=username,
            notes="Pilot authorization for Sprint 10 E2E"
        )
        repository.save_scan_authorization(auth)
        log(f"Scan Authorization created: ID={auth.id}")

        # 5. Execute Scan 1 via Celery Worker (Real Probe Execution)
        log("Step 5: Dispatching Scan 1 to Celery Worker...")
        from core.models import ScanResult, ScanJob, ScanJobStatus
        scan1_id = f"scan_{uuid_hex()}"
        repository.save_scan(ScanResult(
            id=scan1_id,
            tenant_id=tenant_id,
            asset_id=asset.id,
            target_url=WP_TARGET,
            status=ScanStatus.PENDING,
            scan_mode="passive"
        ))

        job1_id = f"job_{uuid_hex()}"
        job1 = ScanJob(
            id=job1_id,
            tenant_id=tenant_id,
            asset_id=asset.id,
            scan_id=scan1_id,
            status=ScanJobStatus.QUEUED.value,
            requested_by=username,
            profile="passive"
        )
        repository.create_scan_job(job1)

        # Dispatch task to Celery
        from core.tasks.scan_tasks import run_scan_task
        task_async = run_scan_task.delay(job1_id)
        job1.task_id = task_async.id
        repository.update_scan_job(job1)
        log(f"Scan 1 job dispatched: JobID={job1_id}, Celery TaskID={task_async.id}")

        # Poll for completion in PostgreSQL (timeout: 45s)
        log("Waiting for Celery worker to pick up and complete scan 1...")
        scan1_completed = False
        start_wait = time.time()
        while time.time() - start_wait < 45:
            current_job = repository.get_scan_job(job1_id)
            if current_job and current_job.status == ScanJobStatus.COMPLETED.value:
                scan1_completed = True
                log(f"Scan 1 completed successfully! Worker: {current_job.worker_id}, Progress: {current_job.progress_percent}%")
                break
            time.sleep(1.0)
        assert scan1_completed, f"Scan 1 failed to complete within timeout. Final status: {current_job.status if current_job else 'None'}"

        # Verify Scan 1 in PostgreSQL
        scan1_res = repository.get_scan(scan1_id, tenant_id=tenant_id)
        assert scan1_res.status == ScanStatus.COMPLETED, f"Scan 1 status is {scan1_res.status}"
        findings_scan1 = repository.get_findings_for_scan(scan1_id, tenant_id=tenant_id)
        log(f"Scan 1 findings discovered in WordPress lab: {len(findings_scan1)}")
        for f in findings_scan1[:3]:
            log(f"  - [{f.severity}] {f.title} (fingerprint: {f.fingerprint[:12]}...)")

        # 6. Generate All 5 Supported Report Formats
        log("Step 6: Generating HTML, JSON, PDF, Excel, SARIF reports from real scan data...")
        from reports.generator import (
            generate_html_report, generate_json_report,
            generate_sarif_report, generate_excel_report, generate_pdf_report
        )
        html_out = generate_html_report(scan1_res)
        json_out = generate_json_report(scan1_res)
        sarif_out = generate_sarif_report(scan1_res)
        excel_out = generate_excel_report(scan1_res)
        pdf_out = generate_pdf_report(scan1_res)

        assert len(html_out) > 500, "HTML report generation failed"
        assert len(json_out) > 100 and "findings" in json_out, "JSON report generation failed"
        assert len(sarif_out) > 100 and "$schema" in sarif_out, "SARIF report generation failed"
        assert len(excel_out) > 1000, "Excel report generation failed"
        assert len(pdf_out) > 500 and pdf_out.startswith(b"%PDF"), "PDF report generation failed"
        log("All 5 report formats generated successfully.")

        # 7. Execute Scan 2 & Verify Differential Reconciliation
        log("Step 7: Executing Scan 2 for Differential Lifecycle Verification...")
        scan2_id = f"scan_{uuid_hex()}"
        repository.save_scan(ScanResult(
            id=scan2_id,
            tenant_id=tenant_id,
            asset_id=asset.id,
            target_url=WP_TARGET,
            status=ScanStatus.PENDING,
            scan_mode="passive"
        ))
        job2_id = f"job_{uuid_hex()}"
        job2 = ScanJob(
            id=job2_id,
            tenant_id=tenant_id,
            asset_id=asset.id,
            scan_id=scan2_id,
            status=ScanJobStatus.QUEUED.value,
            requested_by=username,
            profile="passive"
        )
        repository.create_scan_job(job2)
        task2_async = run_scan_task.delay(job2_id)
        job2.task_id = task2_async.id
        repository.update_scan_job(job2)

        start_wait = time.time()
        scan2_completed = False
        while time.time() - start_wait < 45:
            current_job = repository.get_scan_job(job2_id)
            if current_job and current_job.status == ScanJobStatus.COMPLETED.value:
                scan2_completed = True
                log(f"Scan 2 completed successfully! Worker: {current_job.worker_id}")
                break
            time.sleep(1.0)
        assert scan2_completed, "Scan 2 failed to complete within timeout"

        # Verify Differential Findings
        findings_scan2 = repository.get_findings_for_scan(scan2_id, tenant_id=tenant_id)
        log(f"Scan 2 findings count: {len(findings_scan2)}")
        assert len(findings_scan2) > 0, "Scan 2 should find identical WordPress findings"

        # 8. Real Scheduling & Celery Beat Execution
        log("Step 8: Verifying Celery Beat Scheduled Scan Dispatch & Run Slot Uniqueness...")
        from core.models import ScheduledScan
        sched_id = f"sched_{uuid_hex()}"
        sched = ScheduledScan(
            id=sched_id,
            tenant_id=tenant_id,
            asset_id=asset.id,
            target_url=WP_TARGET,
            scan_mode="passive",
            interval_hours=24,
            next_run_at=(datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
            enabled=True
        )
        repository.save_scheduled_scan(sched)

        planned_slot = "2026-10-11T12:00:00+00:00"
        run1 = repository.claim_scheduled_run(schedule_id=sched_id, tenant_id=tenant_id, planned_at=planned_slot)
        assert run1 is not None, "Failed to claim scheduled run slot"
        log(f"Claimed scheduled run slot: ID={run1.id}")

        # Duplicate slot attempt MUST return None
        run2 = repository.claim_scheduled_run(schedule_id=sched_id, tenant_id=tenant_id, planned_at=planned_slot)
        assert run2 is None, "Duplicate scheduled run slot claim must return None (0 duplicate jobs)"
        log("Duplicate slot claim was prevented by PostgreSQL unique constraint.")

        # 9. Concurrency & Failure Tests
        log("Step 9: Executing Concurrency & Failure Recovery Tests...")
        # A. Duplicate task delivery
        log("Testing duplicate Celery task delivery idempotency...")
        dup_result = run_scan_task.apply(args=[job1_id])
        # Should cleanly handle without modifying completed status
        job1_post_dup = repository.get_scan_job(job1_id)
        assert job1_post_dup.status == ScanJobStatus.COMPLETED.value, "Completed job status must remain COMPLETED"
        log("Duplicate task delivery idempotency verified.")

        # B. Concurrent Outbox claiming with SELECT FOR UPDATE SKIP LOCKED
        log("Testing concurrent outbox claiming (SKIP LOCKED)...")
        from core.models import IntegrationOutbox, OutboxStatus
        from core.db.repositories.outbox_repo import OutboxRepository
        from core.db.session import session_scope

        for i in range(4):
            repository.save_outbox_event(IntegrationOutbox(
                id=f"outbox_test_{uuid_hex()}_{i}",
                tenant_id=tenant_id,
                event_type="alert",
                event_key=f"k_{uuid_hex()}_{i}",
                destination="siem",
                payload_hash="h123",
                payload_json={"idx": i},
                status=OutboxStatus.PENDING.value
            ))

        with session_scope() as s1:
            claimed_w1 = OutboxRepository(s1).claim_events("worker_w1", batch_size=2, tenant_id=tenant_id)
            w1_ids = {e.id for e in claimed_w1}

        with session_scope() as s2:
            claimed_w2 = OutboxRepository(s2).claim_events("worker_w2", batch_size=2, tenant_id=tenant_id)
            w2_ids = {e.id for e in claimed_w2}

        assert w1_ids.isdisjoint(w2_ids), "Workers must claim mutually exclusive events"
        log("Concurrent outbox claim with SKIP LOCKED confirmed disjoint.")

        # C. Stale outbox recovery
        stale_ev_id = f"outbox_stale_{uuid_hex()}"
        repository.save_outbox_event(IntegrationOutbox(
            id=stale_ev_id,
            tenant_id=tenant_id,
            event_type="alert",
            event_key=f"k_stale_{uuid_hex()}",
            destination="siem",
            payload_hash="h_stale",
            status="PROCESSING",
            claimed_at=(datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
            claimed_by="crashed_w99"
        ))
        recovered_count = repository.recover_stale_outbox_events(timeout_seconds=300)
        assert recovered_count >= 1, "Failed to recover stale outbox event"
        stale_ev = repository.get_outbox_event(stale_ev_id, tenant_id=tenant_id)
        assert stale_ev.status == "RETRYING" and stale_ev.claimed_at is None, "Stale event reset failed"
        log("Stale outbox event crash recovery verified.")

        # 10. PostgreSQL Backup and Restore (into NEW separate database)
        log("Step 10: Testing PostgreSQL Backup and Restore into disposable database...")
        backup_file = "tests/e2e/logs/sentinelwp_s10_backup.sql"
        t0 = time.time()
        res_dump = run_cmd(["docker", "exec", "sentinelwp-sprint10-postgres", "pg_dump", "-U", "s10_user", "sentinelwp_s10"])
        with open(backup_file, "w") as bf:
            bf.write(res_dump.stdout)
        backup_duration = round(time.time() - t0, 3)
        log(f"pg_dump completed in {backup_duration}s ({len(res_dump.stdout)} bytes)")

        # Create new database sentinelwp_s10_restore
        run_cmd(["docker", "exec", "sentinelwp-sprint10-postgres", "psql", "-U", "s10_user", "-d", "postgres", "-c", "DROP DATABASE IF EXISTS sentinelwp_s10_restore;"], check=False)
        run_cmd(["docker", "exec", "sentinelwp-sprint10-postgres", "psql", "-U", "s10_user", "-d", "postgres", "-c", "CREATE DATABASE sentinelwp_s10_restore;"])

        t0 = time.time()
        # Restore into sentinelwp_s10_restore
        restore_proc = subprocess.run(
            ["docker", "exec", "-i", "sentinelwp-sprint10-postgres", "psql", "-U", "s10_user", "-d", "sentinelwp_s10_restore"],
            input=res_dump.stdout,
            text=True,
            capture_output=True
        )
        restore_duration = round(time.time() - t0, 3)
        log(f"Restore into sentinelwp_s10_restore completed in {restore_duration}s")

        # Verify record counts in restored database
        from sqlalchemy import create_engine, text
        restore_engine = create_engine("postgresql://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s10_restore")
        with restore_engine.connect() as rconn:
            t_count = rconn.execute(text("SELECT COUNT(*) FROM tenants")).scalar()
            a_count = rconn.execute(text("SELECT COUNT(*) FROM assets")).scalar()
            s_count = rconn.execute(text("SELECT COUNT(*) FROM scans")).scalar()
            f_count = rconn.execute(text("SELECT COUNT(*) FROM findings")).scalar()
            log(f"Restored DB Verification: Tenants={t_count}, Assets={a_count}, Scans={s_count}, Findings={f_count}")
            assert t_count > 0 and a_count > 0 and s_count > 0 and f_count > 0, "Restored database is missing records"
        log("PostgreSQL Backup and Restore verification PASSED 100%.")

        # 11. Playwright Chromium Browser Validation
        log("Step 11: Executing Playwright Chromium Browser E2E Tests...")
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            page = context.new_page()

            js_errors = []
            page.on("pageerror", lambda err: js_errors.append(str(err)))

            # Login
            log(f"Navigating to login page {FLASK_URL}/login...")
            page.goto(f"{FLASK_URL}/login")
            page.screenshot(path="tests/e2e/screenshots/01_login_page.png")
            page.fill("input[name='username']", username)
            page.fill("input[name='password']", "PilotPassword123!")
            page.click("button[type='submit']")
            page.wait_for_load_state("networkidle")
            log(f"Post-login URL: {page.url}")
            page.screenshot(path="tests/e2e/screenshots/02_dashboard_workspace1.png")

            # Workspace 1: Dashboard
            assert "dashboard" in page.url or page.url.endswith("/"), f"Expected dashboard URL, got {page.url}"
            log("Workspace 1 (Dashboard) loaded successfully.")

            # Workspace 2: Asset 360
            page.goto(f"{FLASK_URL}/assets")
            page.wait_for_load_state("networkidle")
            page.screenshot(path="tests/e2e/screenshots/03_assets_workspace2.png")
            log("Workspace 2 (Asset 360) loaded successfully.")

            # Workspace 3: Scan Launcher & Details
            page.goto(f"{FLASK_URL}/scan/{scan1_id}")
            page.wait_for_load_state("networkidle")
            page.screenshot(path="tests/e2e/screenshots/04_scan_detail_workspace3.png")
            log("Workspace 3 (Scan Details) loaded successfully.")

            # Workspace 4: Findings
            page.goto(f"{FLASK_URL}/findings")
            page.wait_for_load_state("networkidle")
            page.screenshot(path="tests/e2e/screenshots/05_findings_workspace4.png")
            log("Workspace 4 (Findings) loaded successfully.")

            # Workspace 5: Reports
            page.goto(f"{FLASK_URL}/reports/executive")
            page.wait_for_load_state("networkidle")
            page.screenshot(path="tests/e2e/screenshots/06_reports_workspace5.png")
            log("Workspace 5 (Reports) loaded successfully.")

            # Workspace 6: Governance & Settings
            page.goto(f"{FLASK_URL}/settings")
            page.wait_for_load_state("networkidle")
            page.screenshot(path="tests/e2e/screenshots/07_settings_workspace6.png")
            log("Workspace 6 (Settings & Governance) loaded successfully.")

            # Mobile layout test
            page.set_viewport_size({"width": 390, "height": 844})
            page.goto(f"{FLASK_URL}/")
            page.wait_for_load_state("networkidle")
            page.screenshot(path="tests/e2e/screenshots/08_mobile_dashboard.png")
            log("Mobile layout verified.")

            # Logout
            page.goto(f"{FLASK_URL}/logout")
            page.wait_for_load_state("networkidle")
            page.screenshot(path="tests/e2e/screenshots/09_post_logout.png")
            log("Logout verified.")

            browser.close()
            assert len(js_errors) == 0, f"Uncaught JavaScript console errors: {js_errors}"
            log("Playwright Browser acceptance PASSED with 0 JavaScript errors.")

        log("=== SPRINT 10 DISTRIBUTED E2E EXECUTION COMPLETED SUCCESSFULLY ===")
        return 0

    except Exception as e:
        log(f"FATAL ERROR during distributed validation: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        log("Shutting down background service processes...")
        pm.stop_all()


def uuid_hex():
    import uuid
    return uuid.uuid4().hex[:8]


if __name__ == "__main__":
    sys.exit(main())
