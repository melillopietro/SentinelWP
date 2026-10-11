#!/usr/bin/env python3
"""
SentinelWP Enterprise Safe Migration Runner
Ensures atomic, distributed-safe schema migrations with PostgreSQL advisory locking,
production operator confirmation gates, dry-run capabilities, and credential-safe logging.
"""
import os
import sys
import argparse
import logging
from urllib.parse import urlsplit

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, text

from config import DATABASE_URL, sanitize_db_url, ENVIRONMENT, is_postgres_configured

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [sentinelwp.migrate] %(message)s"
)
logger = logging.getLogger("sentinelwp.migrate")

# Unique 64-bit integer advisory lock key for SentinelWP migrations
ADVISORY_LOCK_ID = 85504753


def get_current_revision(engine) -> str | None:
    """Retrieve the active revision hash from alembic_version table."""
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            return context.get_current_revision()
    except Exception:
        return None


def get_head_revision(alembic_cfg: Config) -> str:
    """Retrieve the latest head revision from migration scripts."""
    script_dir = ScriptDirectory.from_config(alembic_cfg)
    return script_dir.get_current_head()


def acquire_advisory_lock(conn) -> bool:
    """Attempt to acquire PostgreSQL advisory lock to prevent concurrent migrations."""
    result = conn.execute(text(f"SELECT pg_try_advisory_lock({ADVISORY_LOCK_ID})")).scalar()
    return bool(result)


def release_advisory_lock(conn) -> None:
    """Release PostgreSQL advisory lock."""
    try:
        conn.execute(text(f"SELECT pg_advisory_unlock({ADVISORY_LOCK_ID})"))
    except Exception as e:
        logger.warning(f"Error releasing advisory lock: {e}")


def main():
    parser = argparse.ArgumentParser(description="SentinelWP Enterprise Safe Migration Runner")
    parser.add_argument("--dry-run", action="store_true", help="Preview SQL DDL migrations without applying them")
    parser.add_argument("--check", action="store_true", help="Check schema compatibility and exit non-zero if out of date")
    parser.add_argument("--confirm", action="store_true", help="Explicit confirmation for production schema upgrade")
    args = parser.parse_args()

    target_url = os.getenv("DATABASE_URL", DATABASE_URL)
    sanitized_url = sanitize_db_url(target_url)
    is_prod = ENVIRONMENT in ("production", "prod")

    logger.info(f"Target database: {sanitized_url} (Environment: {ENVIRONMENT})")

    # Load Alembic configuration
    ini_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alembic.ini")
    alembic_cfg = Config(ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", target_url)

    engine = create_engine(target_url)
    current_rev = get_current_revision(engine)
    head_rev = get_head_revision(alembic_cfg)

    logger.info(f"Current DB revision: {current_rev or 'None (Uninitialized)'} | Head revision: {head_rev}")

    # Compatibility check mode
    if args.check:
        if current_rev != head_rev:
            logger.error(
                f"Schema version mismatch: current '{current_rev}' != head '{head_rev}'. "
                f"Database migration required before starting services."
            )
            sys.exit(1)
        logger.info("Schema compatibility verified: database is up-to-date with head revision.")
        sys.exit(0)

    # Dry-run mode
    if args.dry_run:
        logger.info("Executing dry-run migration (generating static SQL preview)...")
        try:
            command.upgrade(alembic_cfg, f"{head_rev}", sql=True)
            logger.info("Dry-run preview completed successfully.")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Dry-run migration failed: {e}")
            sys.exit(1)

    # Production Confirmation Gate
    confirmed = args.confirm or os.getenv("WSA_CONFIRM_PRODUCTION_MIGRATION", "").lower() in ("true", "1", "yes")
    if is_prod and current_rev is not None and current_rev != head_rev and not confirmed:
        logger.error(
            "FATAL: Production schema upgrade requires explicit operator confirmation. "
            "Set WSA_CONFIRM_PRODUCTION_MIGRATION=true or pass --confirm to apply migrations."
        )
        sys.exit(2)

    # Distributed Locking for PostgreSQL
    is_pg = is_postgres_configured(target_url)
    lock_conn = None
    if is_pg:
        logger.info("Acquiring distributed PostgreSQL migration advisory lock...")
        lock_conn = engine.connect()
        if not acquire_advisory_lock(lock_conn):
            logger.error(
                "Another migration process currently holds the advisory lock (ID %s). "
                "Aborting migration to prevent concurrent execution conflicts.", ADVISORY_LOCK_ID
            )
            lock_conn.close()
            sys.exit(3)
        logger.info("Advisory lock acquired successfully.")

    try:
        logger.info("Applying migrations to head revision (%s)...", head_rev)
        command.upgrade(alembic_cfg, "head")
        new_rev = get_current_revision(engine)
        logger.info("Migration successful. Database is now at revision: %s", new_rev)
    except Exception as e:
        logger.error("Migration execution failed: %s", e)
        sys.exit(1)
    finally:
        if lock_conn:
            release_advisory_lock(lock_conn)
            lock_conn.close()
            logger.info("Advisory lock released.")


if __name__ == "__main__":
    main()
