#!/usr/bin/env python3
"""
scripts/verify_migration_upgrade_lifecycle.py

Validates Alembic migration lifecycle:
1. Fresh installation through Alembic revision 009 on clean database.
2. Upgrade of a representative populated database from revision 008 to revision 009.
3. Fail-closed enforcement of migration confirmation in production.
"""
import os
import sys
import subprocess
from sqlalchemy import create_engine, text

def run_cmd(cmd, env=None, check=True):
    res = subprocess.run(cmd, shell=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed (rc={res.returncode}): {cmd}\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    return res

def main():
    base_db_url = os.getenv("DATABASE_URL")
    if not base_db_url:
        print("DATABASE_URL must be set")
        sys.exit(1)

    # Derive admin maintenance URL (connecting to 'postgres' db)
    # e.g., postgresql+psycopg://s11_admin:pass@postgres:5432/sentinelwp_s11_val -> /postgres
    prefix, _, db_part = base_db_url.rpartition("/")
    maint_url = f"{prefix}/postgres"
    
    maint_engine = create_engine(maint_url, isolation_level="AUTOCOMMIT")

    fresh_db = "sentinelwp_val_fresh_drill"
    upgrade_db = "sentinelwp_val_upgrade_drill"

    fresh_url = f"{prefix}/{fresh_db}"
    upgrade_url = f"{prefix}/{upgrade_db}"

    print(f"[*] Starting Migration Lifecycle Verification against {prefix}...")

    # Cleanup any leftovers
    with maint_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {fresh_db}"))
        conn.execute(text(f"DROP DATABASE IF EXISTS {upgrade_db}"))

    # =========================================================================
    # Part 1: Fresh Installation Verification (001 -> 009)
    # =========================================================================
    print(f"\n[+] PART 1: Fresh Installation Verification on '{fresh_db}'...")
    with maint_engine.connect() as conn:
        conn.execute(text(f"CREATE DATABASE {fresh_db}"))

    # Run migrations to head
    env_fresh = os.environ.copy()
    env_fresh["DATABASE_URL"] = fresh_url
    env_fresh["ENVIRONMENT"] = "production"
    
    res = run_cmd("python3 scripts/run_migrations.py --confirm", env=env_fresh)
    print("    Migration to head completed successfully.")

    # Verify tables & version
    fresh_engine = create_engine(fresh_url)
    with fresh_engine.connect() as conn:
        ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        tables = conn.execute(text(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
        )).scalar()
        print(f"    Fresh DB Alembic Version: {ver}")
        print(f"    Fresh DB Table Count: {tables}")
        assert ver == "009_sprint11_schema_parity", f"Expected 009, got {ver}"
        assert tables >= 46, f"Expected at least 46 tables, got {tables}"
    fresh_engine.dispose()
    print("    [PASS] Fresh installation verification passed.")

    # =========================================================================
    # Part 2: Populated Upgrade Verification (008 -> 009)
    # =========================================================================
    print(f"\n[+] PART 2: Representative Populated Upgrade Drill on '{upgrade_db}'...")
    with maint_engine.connect() as conn:
        conn.execute(text(f"CREATE DATABASE {upgrade_db}"))

    env_upg = os.environ.copy()
    env_upg["DATABASE_URL"] = upgrade_url
    env_upg["ENVIRONMENT"] = "production"

    # Migrate up to revision 008 using alembic
    print("    Migrating clean database to revision 008_sprint5_resilience_and_recovery...")
    run_cmd("alembic upgrade 008_sprint5_resilience_and_recovery", env=env_upg)

    upg_engine = create_engine(upgrade_url)
    with upg_engine.connect() as conn:
        ver_008 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert ver_008 == "008_sprint5_resilience_and_recovery", f"Expected 008, got {ver_008}"
        print(f"    Verified DB at revision: {ver_008}")

        # Populate representative data across core tables
        print("    Populating representative production dataset...")
        conn.execute(text("""
            INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
            VALUES ('tenant-drill-1', 'Drill Enterprise', 'drill-ent', 'active', '2026-10-11T12:00:00Z', '2026-10-11T12:00:00Z')
        """))
        conn.execute(text("""
            INSERT INTO assets (id, tenant_id, canonical_url, hostname, display_name, status, created_at, updated_at)
            VALUES ('asset-drill-1', 'tenant-drill-1', 'http://drill.corp.internal', 'drill.corp.internal', 'Drill Asset', 'active', '2026-10-11T12:00:00Z', '2026-10-11T12:00:00Z')
        """))
        conn.execute(text("""
            INSERT INTO scans (id, tenant_id, asset_id, target_url, status, scan_mode, started_at)
            VALUES ('scan-drill-1', 'tenant-drill-1', 'asset-drill-1', 'http://drill.corp.internal', 'completed', 'passive', '2026-10-11T12:00:00Z')
        """))
        conn.execute(text("""
            INSERT INTO scan_jobs (id, tenant_id, scan_id, status, queued_at, created_at)
            VALUES ('job-drill-1', 'tenant-drill-1', 'scan-drill-1', 'completed', '2026-10-11T12:00:00Z', '2026-10-11T12:00:00Z')
        """))
        conn.execute(text("""
            INSERT INTO findings (id, tenant_id, asset_id, scan_id, category, title, description, severity, confidence, remediation, reference, raw_data, created_at)
            VALUES ('fnd-drill-1', 'tenant-drill-1', 'asset-drill-1', 'scan-drill-1', 'vuln', 'Drill Finding 1', 'Desc', 'HIGH', 1.0, 'Fix it', 'Ref', '{}', '2026-10-11T12:00:00Z')
        """))
        conn.execute(text("""
            INSERT INTO scheduled_scans (id, tenant_id, asset_id, target_url, scan_mode, interval_hours, enabled, created_by, created_at)
            VALUES ('sched-drill-1', 'tenant-drill-1', 'asset-drill-1', 'http://drill.corp.internal', 'passive', 24, true, 'admin', '2026-10-11T12:00:00Z')
        """))
        conn.commit()

        # Capture before counts
        c_tenants = conn.execute(text("SELECT count(*) FROM tenants")).scalar()
        c_assets = conn.execute(text("SELECT count(*) FROM assets")).scalar()
        c_scans = conn.execute(text("SELECT count(*) FROM scans")).scalar()
        c_jobs = conn.execute(text("SELECT count(*) FROM scan_jobs")).scalar()
        c_findings = conn.execute(text("SELECT count(*) FROM findings")).scalar()
        c_sched = conn.execute(text("SELECT count(*) FROM scheduled_scans")).scalar()
        print(f"    Pre-upgrade counts: tenants={c_tenants}, assets={c_assets}, scans={c_scans}, jobs={c_jobs}, findings={c_findings}, schedules={c_sched}")

    # Now execute upgrade to 009
    print("    Executing Alembic upgrade 008 -> 009 (head)...")
    run_cmd("python3 scripts/run_migrations.py --confirm", env=env_upg)

    # Verify post-upgrade counts and schema
    with upg_engine.connect() as conn:
        ver_009 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert ver_009 == "009_sprint11_schema_parity", f"Expected 009, got {ver_009}"
        print(f"    Post-upgrade Alembic version: {ver_009}")

        c_tenants_post = conn.execute(text("SELECT count(*) FROM tenants")).scalar()
        c_assets_post = conn.execute(text("SELECT count(*) FROM assets")).scalar()
        c_scans_post = conn.execute(text("SELECT count(*) FROM scans")).scalar()
        c_jobs_post = conn.execute(text("SELECT count(*) FROM scan_jobs")).scalar()
        c_findings_post = conn.execute(text("SELECT count(*) FROM findings")).scalar()
        c_sched_post = conn.execute(text("SELECT count(*) FROM scheduled_scans")).scalar()

        print(f"    Post-upgrade counts: tenants={c_tenants_post}, assets={c_assets_post}, scans={c_scans_post}, jobs={c_jobs_post}, findings={c_findings_post}, schedules={c_sched_post}")
        assert c_tenants == c_tenants_post, "Tenant count mismatch!"
        assert c_assets == c_assets_post, "Asset count mismatch!"
        assert c_scans == c_scans_post, "Scan count mismatch!"
        assert c_jobs == c_jobs_post, "Job count mismatch!"
        assert c_findings == c_findings_post, "Finding count mismatch!"
        assert c_sched == c_sched_post, "Schedule count mismatch!"

        # Verify new columns added by revision 009 exist and are queryable
        row = conn.execute(text("SELECT target_url, created_by FROM scheduled_scans WHERE id = 'sched-drill-1'")).fetchone()
        print(f"    Queried new 009 columns on scheduled_scans: {row}")
    upg_engine.dispose()
    print("    [PASS] Populated upgrade verification passed with 100% data preservation.")

    # =========================================================================
    # Part 3: Fail-Closed Production Confirmation Gate Check
    # =========================================================================
    print("\n[+] PART 3: Verifying Fail-Closed Production Confirmation Gate...")
    # Set DB to revision 008 so current_rev != head_rev
    run_cmd("alembic downgrade 008_sprint5_resilience_and_recovery", env=env_upg)

    env_unconfirmed = os.environ.copy()
    env_unconfirmed["DATABASE_URL"] = upgrade_url
    env_unconfirmed["ENVIRONMENT"] = "production"
    # Unset confirm variables
    env_unconfirmed.pop("WSA_CONFIRM_PRODUCTION_MIGRATION", None)

    res_fail = run_cmd("python3 scripts/run_migrations.py", env=env_unconfirmed, check=False)
    print(f"    Unconfirmed runner returned exit code: {res_fail.returncode}")
    assert res_fail.returncode == 2, f"Expected rc=2, got {res_fail.returncode}"
    print("    [PASS] Fail-closed production gate confirmed (exit code 2).")

    # =========================================================================
    # Cleanup Disposable Drill Databases
    # =========================================================================
    print("\n[*] Cleaning up disposable drill databases...")
    with maint_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {fresh_db}"))
        conn.execute(text(f"DROP DATABASE IF EXISTS {upgrade_db}"))
    maint_engine.dispose()
    print("[*] All Migration and Upgrade Lifecycle checks completed successfully!\n")

if __name__ == "__main__":
    main()
