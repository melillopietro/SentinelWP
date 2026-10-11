#!/usr/bin/env python3
"""
SentinelWP Enterprise Backup Utility.
Performs durable, transactional database backups for PostgreSQL and SQLite.
Generates SHA-256 integrity checksums and verification manifests.
"""
import os
import sys
import gzip
import hashlib
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DATABASE_URL, DATABASE_PATH

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger("sentinelwp.backup")


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def count_database_records() -> dict:
    """Collect record counts across core tables for integrity verification."""
    from core import repository
    conn = repository._get_conn()
    tables = [
        "tenants", "users", "assets", "scan_authorizations",
        "scans", "findings", "finding_observations", "remediations",
        "sla_policies", "risk_acceptances", "audit_events"
    ]
    counts = {}
    for tbl in tables:
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
            counts[tbl] = row[0] if row else 0
        except Exception:
            counts[tbl] = 0
    return counts


def backup_sqlite(target_dir: Path) -> Path:
    """Create a consistent SQLite backup using the backup API."""
    import sqlite3
    db_file = Path(DATABASE_PATH)
    if not db_file.exists():
        raise FileNotFoundError(f"SQLite database not found at {db_file}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = target_dir / f"sentinelwp_backup_{ts}.db"
    
    logger.info(f"Initiating online SQLite backup from {db_file} to {backup_file}...")
    src_conn = sqlite3.connect(str(db_file), timeout=60.0)
    dst_conn = sqlite3.connect(str(backup_file))
    with dst_conn:
        src_conn.backup(dst_conn, pages=100)
    dst_conn.close()
    src_conn.close()

    # Compress backup
    gz_file = target_dir / f"sentinelwp_backup_{ts}.db.gz"
    with open(backup_file, "rb") as f_in, gzip.open(gz_file, "wb") as f_out:
        while chunk := f_in.read(65536):
            f_out.write(chunk)
    
    # Remove uncompressed file
    backup_file.unlink()
    return gz_file


def backup_postgres(target_dir: Path) -> Path:
    """Create a transactional PostgreSQL backup via pg_dump."""
    from urllib.parse import urlparse
    parsed = urlparse(DATABASE_URL.replace("postgresql+psycopg://", "postgresql://"))
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = target_dir / f"sentinelwp_pg_{ts}.sql.gz"

    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = parsed.password

    cmd = [
        "pg_dump",
        "-h", parsed.hostname or "localhost",
        "-p", str(parsed.port or 5432),
        "-U", parsed.username or "sentinelwp",
        "-d", parsed.path.lstrip("/") or "sentinelwp",
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
    ]

    logger.info(f"Executing pg_dump to {backup_file}...")
    with gzip.open(backup_file, "wb") as gz_out:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {stderr.decode('utf-8')}")
        gz_out.write(stdout)

    return backup_file


def run_backup(output_dir: str = "backups") -> Path:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    counts_before = count_database_records()
    logger.info(f"Database pre-backup inventory: {counts_before}")

    if "postgresql" in DATABASE_URL:
        try:
            backup_path = backup_postgres(target_dir)
        except Exception as e:
            logger.warning(f"PostgreSQL pg_dump failed ({e}), falling back to SQLite backup...")
            backup_path = backup_sqlite(target_dir)
    else:
        backup_path = backup_sqlite(target_dir)

    checksum = compute_sha256(str(backup_path))
    sha_file = Path(f"{backup_path}.sha256")
    sha_file.write_text(f"{checksum}  {backup_path.name}\n", encoding="utf-8")

    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "backup_file": backup_path.name,
        "sha256": checksum,
        "size_bytes": backup_path.stat().st_size,
        "counts": counts_before,
    }
    manifest_file = Path(f"{backup_path}.manifest.json")
    manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    logger.info(f"Backup completed successfully: {backup_path}")
    logger.info(f"Integrity checksum SHA-256: {checksum}")
    return backup_path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "backups"
    run_backup(out)
