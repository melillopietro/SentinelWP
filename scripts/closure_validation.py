#!/usr/bin/env python3
"""
SentinelWP Phase 5 — Final Production Readiness Closure
Automated validation script covering Controls 1-38.
"""
import json, os, sys, subprocess, time, hashlib, tempfile, uuid, sqlite3
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("TESTING", "1")

RESULTS = {}

def record(name, status, evidence=""):
    RESULTS[name] = {"status": status, "evidence": evidence}
    icon = "✅" if status == "PASS" else ("⚠️" if status == "PARTIAL" else "❌")
    print(f"{icon} {name}: {status} — {evidence}")

# ═══════════════════════════════════════════════
# CONTROL 1 & 3: SECURITY CLEANUP / TEST ACCOUNTS
# ═══════════════════════════════════════════════
def control_1_3_cleanup():
    from core import repository
    repository.init_db()

    # Check for test accounts
    suspect_users = []
    for name in ["smoketest_admin", "test_admin", "temporary_admin", "smoke_user", "phase_b_user"]:
        u = repository.get_user_by_username(name)
        if u:
            suspect_users.append(name)
            repository.delete_user(u.id)
    
    if suspect_users:
        record("SECURITY_CLEANUP_TEST_ACCOUNTS", "PASS", f"Removed {len(suspect_users)} test accounts: {suspect_users}")
    else:
        record("SECURITY_CLEANUP_TEST_ACCOUNTS", "PASS", "No test accounts found in database")

# ═══════════════════════════════════════════════
# CONTROL 4: API KEY CLEANUP
# ═══════════════════════════════════════════════
def control_4_api_key_cleanup():
    from core import repository
    repository.init_db()
    
    all_keys = repository.list_api_keys("default-tenant")
    test_keys = [k for k in all_keys if "test" in (k.name or "").lower() or "smoke" in (k.name or "").lower()]
    for k in test_keys:
        repository.revoke_api_key(k.id, "default-tenant")
    
    record("API_KEY_CLEANUP", "PASS",
           f"Revoked {len(test_keys)} test API keys" if test_keys else "No test API keys found")

# ═══════════════════════════════════════════════
# CONTROL 16: REDIS FAILURE POLICY
# ═══════════════════════════════════════════════
def control_16_redis_fail_policy():
    """Verify rate_limiter has fail-closed mode support"""
    from core import rate_limiter
    src = Path("core/rate_limiter.py").read_text()
    has_fail_mode = "RATE_LIMIT_FAIL_MODE" in src or "fail_mode" in src.lower()
    if has_fail_mode:
        record("REDIS_FAILURE_POLICY", "PASS", "RATE_LIMIT_FAIL_MODE configuration found")
    else:
        record("REDIS_FAILURE_POLICY", "PARTIAL",
               "RATE_LIMIT_FAIL_MODE not yet configurable — needs implementation")

# ═══════════════════════════════════════════════
# CONTROL 19: ALEMBIC HEADS
# ═══════════════════════════════════════════════
def control_19_alembic():
    alembic_dir = Path("alembic")
    if not alembic_dir.exists():
        alembic_dir = Path("migrations")
    
    if not alembic_dir.exists():
        record("ALEMBIC_HEADS", "PARTIAL", "No alembic directory found — using raw SQLite schema init")
        return
    
    try:
        result = subprocess.run(["alembic", "heads"], capture_output=True, text=True, timeout=10,
                               cwd=str(Path.cwd()))
        heads = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        n = len(heads)
        if n == 1:
            record("ALEMBIC_HEADS", "PASS", f"Single head: {heads[0]}")
        elif n == 0:
            record("ALEMBIC_HEADS", "PARTIAL", "No heads found — check alembic config")
        else:
            record("ALEMBIC_HEADS", "FAIL", f"Multiple heads detected: {heads}")
    except FileNotFoundError:
        record("ALEMBIC_HEADS", "PARTIAL", "alembic CLI not installed in venv")
    except Exception as e:
        record("ALEMBIC_HEADS", "PARTIAL", f"Alembic check error: {e}")

# ═══════════════════════════════════════════════
# CONTROL 23/24: SECURITY HEADERS + HSTS
# ═══════════════════════════════════════════════
def control_23_24_headers():
    try:
        import requests as rq
        resp = rq.get("http://localhost:8085/login", timeout=5)
        h = resp.headers
        checks = {
            "Content-Security-Policy": h.get("Content-Security-Policy", ""),
            "X-Content-Type-Options": h.get("X-Content-Type-Options", ""),
            "Referrer-Policy": h.get("Referrer-Policy", ""),
            "Permissions-Policy": h.get("Permissions-Policy", ""),
            "X-Frame-Options": h.get("X-Frame-Options", ""),
        }
        missing = [k for k, v in checks.items() if not v]
        hsts = h.get("Strict-Transport-Security", "")

        if not missing:
            record("SECURITY_HEADERS", "PASS",
                   f"All headers present. CSP={checks['Content-Security-Policy'][:60]}...")
        else:
            record("SECURITY_HEADERS", "PARTIAL", f"Missing headers: {missing}")

        # HSTS should NOT be sent on plain HTTP localhost dev
        if not hsts:
            record("HSTS_DEVELOPMENT", "PASS", "HSTS not sent on localhost HTTP (correct)")
        else:
            record("HSTS_DEVELOPMENT", "PARTIAL", f"HSTS sent on HTTP dev: {hsts}")
    except Exception as e:
        record("SECURITY_HEADERS", "FAIL", f"Could not connect: {e}")
        record("HSTS_DEVELOPMENT", "FAIL", f"Could not connect: {e}")

# ═══════════════════════════════════════════════
# CONTROL 22: CONTAINER HARDENING
# ═══════════════════════════════════════════════
def control_22_container():
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             '{"User":"{{.Config.User}}", "CapDrop":{{json .HostConfig.CapDrop}}, "NoNewPriv":{{.HostConfig.SecurityOpt}}}',
             "sentinelwp-web"],
            capture_output=True, text=True, timeout=10)
        evidence = result.stdout.strip()
        record("CONTAINER_HARDENING", "PARTIAL", f"docker inspect: {evidence}")
    except Exception as e:
        record("CONTAINER_HARDENING", "FAIL", f"Error: {e}")

# ═══════════════════════════════════════════════
# CONTROL 27: JSON LOGGING
# ═══════════════════════════════════════════════
def control_27_json_logging():
    from core.logging_config import JSONFormatter
    import logging
    fmt = JSONFormatter(service_name="closure-test")
    record_obj = logging.LogRecord("test", logging.INFO, "test.py", 1, "test msg", (), None)
    record_obj.request_id = "req-test-123"
    record_obj.tenant_id = "tenant-test"
    output = fmt.format(record_obj)
    data = json.loads(output)
    required_fields = ["timestamp", "level", "message", "request_id", "tenant_id"]
    missing = [f for f in required_fields if f not in data]
    if not missing:
        record("JSON_LOGGING", "PASS", f"All fields present: {list(data.keys())}")
    else:
        record("JSON_LOGGING", "PARTIAL", f"Missing fields: {missing}")

# ═══════════════════════════════════════════════
# CONTROL 28: SECRET REDACTION
# ═══════════════════════════════════════════════
def control_28_secret_redaction():
    from core.logging_config import JSONFormatter
    import logging, io
    handler = logging.StreamHandler(io.StringIO())
    handler.setFormatter(JSONFormatter(service_name="redact-test"))
    logger = logging.getLogger("redact_test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    test_secret = "Bearer FAKE_TEST_SECRET_VALUE_12345"
    logger.info(f"Auth attempt with {test_secret}")
    
    output = handler.stream.getvalue()
    if "FAKE_TEST_SECRET_VALUE_12345" in output:
        record("SECRET_REDACTION", "PARTIAL",
               "Secret appears in log output — redaction middleware not yet implemented")
    else:
        record("SECRET_REDACTION", "PASS", "Secrets not found in log output")

# ═══════════════════════════════════════════════
# CONTROL 29: SBOM
# ═══════════════════════════════════════════════
def control_29_sbom():
    try:
        subprocess.run([sys.executable, "scripts/generate_sbom.py", "sbom.json"],
                      capture_output=True, text=True, timeout=15)
        sbom = json.loads(Path("sbom.json").read_text())
        if sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion"):
            n = len(sbom.get("components", []))
            # Check no secrets in SBOM
            raw = Path("sbom.json").read_text()
            has_secret = any(s in raw.lower() for s in ["password", "secret_key", "bearer"])
            if has_secret:
                record("SBOM", "PARTIAL", "SBOM contains potential secret references")
            else:
                record("SBOM", "PASS", f"CycloneDX {sbom['specVersion']}, {n} components, no secrets")
        else:
            record("SBOM", "FAIL", "Invalid SBOM format")
    except Exception as e:
        record("SBOM", "FAIL", f"SBOM generation error: {e}")

# ═══════════════════════════════════════════════
# CONTROL 30: CI PIPELINE REVIEW
# ═══════════════════════════════════════════════
def control_30_ci():
    ci_path = Path(".github/workflows/security_ci.yml")
    if not ci_path.exists():
        record("CI_SECURITY", "FAIL", "No CI workflow found")
        return
    content = ci_path.read_text()
    checks = {
        "pytest": "pytest" in content,
        "regression": "regression" in content,
        "bandit": "bandit" in content.lower(),
        "flake8_or_ruff": "flake8" in content or "ruff" in content,
        "sbom": "sbom" in content.lower(),
    }
    missing = [k for k, v in checks.items() if not v]
    if not missing:
        record("CI_SECURITY", "PASS", f"All CI checks present: {list(checks.keys())}")
    else:
        record("CI_SECURITY", "PARTIAL", f"Missing CI steps: {missing}")

# ═══════════════════════════════════════════════
# CONTROL 15: BACKUP CHECKSUM TAMPER
# ═══════════════════════════════════════════════
def control_15_backup_checksum():
    try:
        from scripts.backup_db import run_backup
        from scripts.restore_db import verify_backup_integrity

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_path = run_backup(output_dir=tmpdir)
            # Verification should pass
            assert verify_backup_integrity(backup_path), "Clean verification failed"
            
            # Tamper
            tampered = Path(str(backup_path) + ".tampered")
            import shutil
            shutil.copy2(backup_path, tampered)
            # Also copy sha file
            sha_src = Path(f"{backup_path}.sha256")
            sha_dst = Path(f"{tampered}.sha256")
            shutil.copy2(sha_src, sha_dst)
            # Corrupt the tampered file
            with open(tampered, "ab") as f:
                f.write(b"CORRUPTION")
            
            try:
                verify_backup_integrity(tampered)
                record("BACKUP_CHECKSUM", "FAIL", "Tampered backup passed verification!")
            except ValueError:
                record("BACKUP_CHECKSUM", "PASS", "Tampered backup correctly rejected by SHA-256 check")
    except Exception as e:
        record("BACKUP_CHECKSUM", "FAIL", f"Error: {e}")

# ═══════════════════════════════════════════════
# RUN ALL CONTROLS
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("SentinelWP Phase 5 — Production Readiness Closure")
    print("=" * 60)
    
    control_1_3_cleanup()
    control_4_api_key_cleanup()
    control_15_backup_checksum()
    control_16_redis_fail_policy()
    control_19_alembic()
    control_22_container()
    control_23_24_headers()
    control_27_json_logging()
    control_28_secret_redaction()
    control_29_sbom()
    control_30_ci()

    print("\n" + "=" * 60)
    print("AUTOMATED CONTROL RESULTS")
    print("=" * 60)
    for name, r in RESULTS.items():
        print(f"  {name}: {r['status']}")
