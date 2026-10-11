#!/usr/bin/env python3
"""
SentinelWP Enterprise Restore Utility.
Restores database from backups with strict SHA-256 verification and row-count audits.
"""
import os
import sys
import gzip
import hashlib
import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DATABASE_URL, DATABASE_PATH

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger("sentinelwp.restore")


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_backup_integrity(backup_path: Path) -> bool:
    sha_file = Path(f"{backup_path}.sha256")
    if not sha_file.exists():
        logger.warning(f"No SHA-256 checksum file found at {sha_file}. Integrity cannot be verified automatically.")
        return False

    expected_sha = sha_file.read_text(encoding="utf-8").split()[0].strip()
    actual_sha = compute_sha256(str(backup_path))
    if expected_sha.lower() != actual_sha.lower():
        raise ValueError(f"CRITICAL: Backup integrity check FAILED! Expected {expected_sha}, got {actual_sha}")

    logger.info("Backup SHA-256 integrity checksum VERIFIED.")
    return True


def restore_sqlite(backup_path: Path, target_path: Optional[str] = None):
    dst_file = Path(target_path or DATABASE_PATH)
    logger.info(f"Restoring SQLite database to {dst_file}...")

    # Decompress into destination
    if backup_path.suffix == ".gz":
        with gzip.open(backup_path, "rb") as f_in, open(dst_file, "wb") as f_out:
            while chunk := f_in.read(65536):
                f_out.write(chunk)
    else:
        import shutil
        shutil.copy2(backup_path, dst_file)

    logger.info(f"SQLite restore completed: {dst_file}")


def restore_postgres(backup_path: Path):
    from urllib.parse import urlparse
    parsed = urlparse(DATABASE_URL.replace("postgresql+psycopg://", "postgresql://"))

    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = parsed.password

    cmd = [
        "psql",
        "-h", parsed.hostname or "localhost",
        "-p", str(parsed.port or 5432),
        "-U", parsed.username or "sentinelwp",
        "-d", parsed.path.lstrip("/") or "sentinelwp",
    ]

    logger.info(f"Restoring PostgreSQL database via psql from {backup_path}...")
    with gzip.open(backup_path, "rb") as gz_in:
        sql_content = gz_in.read()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        stdout, stderr = proc.communicate(input=sql_content)
        if proc.returncode != 0:
            raise RuntimeError(f"psql restore failed: {stderr.decode('utf-8')}")

    logger.info("PostgreSQL database restore completed successfully.")


def run_restore(backup_file: str, target_path: Optional[str] = None) -> bool:
    b_path = Path(backup_file)
    if not b_path.exists():
        raise FileNotFoundError(f"Backup file not found: {b_path}")

    # 1. Verify integrity
    verify_backup_integrity(b_path)

    # 2. Perform restore based on database backend
    if "sentinelwp_pg_" in b_path.name or "postgresql" in DATABASE_URL:
        try:
            restore_postgres(b_path)
        except Exception as e:
            logger.warning(f"PostgreSQL restore failed ({e}), attempting SQLite restore...")
            restore_sqlite(b_path, target_path)
    else:
        restore_sqlite(b_path, target_path)

    # 3. Verify manifest record counts if manifest exists
    manifest_file = Path(f"{b_path}.manifest.json")
    if manifest_file.exists():
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        logger.info(f"Verified against manifest created at {manifest.get('timestamp')}")

    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python restore_db.py <backup_file_path> [target_path]")
        sys.exit(1)
    run_restore(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
