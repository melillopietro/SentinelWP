"""
SQLite to PostgreSQL Enterprise Data Migration Script for SentinelWP
Copy-based, idempotent, non-destructive to source SQLite database.
Validates counts on completion and exits non-zero if discrepancy is found.
"""
import sys
import os
import sqlite3
import argparse
import logging
from typing import Dict, Any, List
from sqlalchemy import create_engine, text, Table, MetaData
from sqlalchemy.orm import sessionmaker

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import DATABASE_PATH, DATABASE_URL
from core.db.session import init_db_schema
from core.db.base import Base

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinelwp.migration")

CRITICAL_TABLES = [
    "tenants",
    "users",
    "assets",
    "scan_authorizations",
    "scans",
    "findings",
    "scheduled_scans",
    "scheduled_runs",
    "scan_jobs",
    "audit_events",
    "intelligence_sync_status",
    "vulnerability_records",
    "vulnerability_software",
    "vulnerability_affected_ranges",
    "vulnerability_references",
    "plugin_metadata",
    "cisa_kev_records",
    "vulnerability_sync_state",
    "vuln_intel_settings",
]


def table_exists_in_sqlite(conn: sqlite3.Connection, table_name: str) -> bool:
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
    )
    return cursor.fetchone() is not None


def get_sqlite_count(conn: sqlite3.Connection, table_name: str) -> int:
    if not table_exists_in_sqlite(conn, table_name):
        return 0
    cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
    return cursor.fetchone()[0]


def get_target_count(engine, table_name: str) -> int:
    with engine.connect() as connection:
        res = connection.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
        return res.scalar() or 0


def migrate_table(
    sqlite_conn: sqlite3.Connection,
    target_engine,
    target_metadata: MetaData,
    table_name: str,
) -> tuple[int, int]:
    if not table_exists_in_sqlite(sqlite_conn, table_name):
        return 0, 0

    cursor = sqlite_conn.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    if not rows:
        return 0, 0

    col_names = [description[0] for description in cursor.description]
    target_table = target_metadata.tables.get(table_name)
    if target_table is None:
        target_table = Table(table_name, target_metadata, autoload_with=target_engine)

    target_cols = {c.name for c in target_table.columns}
    primary_keys = [c.name for c in target_table.primary_key.columns]

    with target_engine.begin() as connection:
        existing_pks = set()
        if primary_keys and len(primary_keys) == 1:
            pk_col = primary_keys[0]
            existing_pks = set(
                r[0] for r in connection.execute(text(f"SELECT {pk_col} FROM {table_name}")).fetchall()
            )

        to_insert = []
        for row in rows:
            row_dict = {col: val for col, val in zip(col_names, row) if col in target_cols}

            if primary_keys:
                if len(primary_keys) == 1:
                    pk_val = row_dict.get(primary_keys[0])
                    if pk_val in existing_pks:
                        continue
                    existing_pks.add(pk_val)
                else:
                    pk_conditions = " AND ".join([f"{pk} = :{pk}" for pk in primary_keys])
                    pk_params = {pk: row_dict[pk] for pk in primary_keys if pk in row_dict}
                    if len(pk_params) == len(primary_keys):
                        exists = connection.execute(
                            text(f"SELECT 1 FROM {table_name} WHERE {pk_conditions}"), pk_params
                        ).scalar()
                        if exists:
                            continue

            to_insert.append(row_dict)

        # Batch insert in chunks of 1000
        inserted = 0
        chunk_size = 1000
        for i in range(0, len(to_insert), chunk_size):
            chunk = to_insert[i:i + chunk_size]
            if chunk:
                connection.execute(target_table.insert(), chunk)
                inserted += len(chunk)

    return len(rows), inserted


def run_migration(sqlite_path: str, postgres_url: str, dry_run: bool = False) -> bool:
    logger.info(f"Starting migration from SQLite ({sqlite_path}) to Target ({postgres_url})")

    if not os.path.exists(sqlite_path):
        logger.error(f"Source SQLite database not found at: {sqlite_path}")
        return False

    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    target_engine = create_engine(postgres_url, future=True)

    # Ensure target tables exist
    init_db_schema(target_engine)

    metadata = MetaData()
    metadata.reflect(bind=target_engine)

    # Copy data in ordered dependencies
    for table in CRITICAL_TABLES:
        if table in metadata.tables:
            src_count = get_sqlite_count(sqlite_conn, table)
            if dry_run:
                logger.info(f"[DRY-RUN] Table {table}: {src_count} source records to copy")
            else:
                total, newly_inserted = migrate_table(sqlite_conn, target_engine, metadata, table)
                logger.info(f"Table {table}: {newly_inserted} newly inserted (total source: {total})")

    # Migration Validation
    logger.info("==========================================")
    logger.info("MIGRATION VALIDATION: Verifying row counts")
    logger.info("==========================================")
    validation_passed = True
    for table in CRITICAL_TABLES:
        if table_exists_in_sqlite(sqlite_conn, table):
            src_c = get_sqlite_count(sqlite_conn, table)
            tgt_c = get_target_count(target_engine, table)
            print(f"{table}: {src_c} -> {tgt_c}")
            if src_c != tgt_c:
                logger.error(f"COUNT MISMATCH for {table}: source={src_c} != target={tgt_c}")
                validation_passed = False

    sqlite_conn.close()

    if not validation_passed:
        logger.error("Migration validation FAILED: table counts differ!")
        return False

    logger.info("Migration validation PASSED: all table row counts match exactly.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Migrate SentinelWP SQLite database to PostgreSQL")
    parser.add_argument("--sqlite", default=DATABASE_PATH, help="Path to source SQLite database")
    parser.add_argument("--postgres", default=DATABASE_URL, help="Target PostgreSQL database URL")
    parser.add_argument("--dry-run", action="store_true", help="Inspect counts without writing")
    args = parser.parse_args()

    success = run_migration(args.sqlite, args.postgres, dry_run=args.dry_run)
    if not success:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
