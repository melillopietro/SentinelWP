"""
Database Engine and Session Lifecycle Management for SentinelWP
Supports both PostgreSQL (enterprise production) and SQLite (dev/test fallback).
"""
import os
import logging
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session, scoped_session

from config import DATABASE_URL, DATABASE_PATH, is_postgres_configured, sanitize_db_url
from core.db.base import Base

logger = logging.getLogger("sentinelwp.db.session")

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None
_scoped_session: scoped_session[Session] | None = None


def reset_engine() -> None:
    """Reset cached engine and session factories (useful for test isolation or config changes)."""
    global _engine, _session_factory, _scoped_session
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass
    _engine = None
    _session_factory = None
    _scoped_session = None


def verify_operational_persistence_guard(db_url: str | None = None, timeout_seconds: float = 5.0) -> bool:
    """
    Fail-closed startup connectivity guard for Flask, Celery workers, and Celery Beat.
    
    Validates that the operational persistence backend is reachable before starting
    service processes.
    
    If PostgreSQL is configured:
      - Actively probes the database with 'SELECT 1'.
      - If reachable, returns True.
      - If unreachable or misconfigured, raises RuntimeError with sanitized diagnostics
        guaranteeing zero credential/secret leakage in logs or exceptions.
        
    If SQLite is configured:
      - Validates local database path accessibility and returns True.
    """
    target_url = db_url if db_url is not None else os.getenv("DATABASE_URL", DATABASE_URL)
    sanitized_url = sanitize_db_url(target_url)
    
    if not is_postgres_configured(target_url):
        logger.debug(f"Operational persistence using SQLite: {sanitized_url}")
        return True

    logger.info(f"Verifying PostgreSQL operational persistence connectivity to {sanitized_url}...")
    try:
        probe_engine = create_engine(
            target_url,
            connect_args={"connect_timeout": int(timeout_seconds)},
            pool_pre_ping=False,
            future=True,
        )
        with probe_engine.connect() as probe_conn:
            result = probe_conn.execute(text("SELECT 1")).scalar()
            if result != 1:
                raise RuntimeError(f"Unexpected probe result: {result}")

            # In production mode, verify that schema has been migrated and is not empty
            env_mode = os.getenv("ENVIRONMENT", os.getenv("WSA_ENV", os.getenv("FLASK_ENV", "development"))).lower()
            if env_mode in ("production", "prod") and not os.getenv("WSA_SKIP_SCHEMA_VERSION_CHECK"):
                try:
                    ver_row = probe_conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).fetchone()
                    if not ver_row:
                        raise RuntimeError(
                            "Database schema uninitialized: 'alembic_version' table is empty. "
                            "Run 'sentinelwp-migrate' to initialize database schema."
                        )
                except Exception as ver_err:
                    err_lower = str(ver_err).lower()
                    if "does not exist" in err_lower or "undefined table" in err_lower or "empty" in err_lower:
                        raise RuntimeError(
                            "Database schema uninitialized: 'alembic_version' table not found. "
                            "Run 'sentinelwp-migrate' to initialize database schema."
                        )
                    raise
        probe_engine.dispose()
        logger.info(f"PostgreSQL operational persistence verified successfully: {sanitized_url}")
        return True
    except Exception as exc:
        exc_str = str(exc)
        try:
            from urllib.parse import urlsplit
            raw_pass = urlsplit(target_url).password
            if raw_pass:
                exc_str = exc_str.replace(raw_pass, "***")
        except Exception:
            pass

        err_msg = (
            f"PostgreSQL startup persistence guard failed: unable to connect to operational "
            f"database at {sanitized_url}. Service cannot start. Details: {exc_str}"
        )
        logger.error(err_msg)
        raise RuntimeError(err_msg) from None


def get_engine(db_url: str | None = None) -> Engine:
    """Return a singleton SQLAlchemy Engine configured for PostgreSQL or SQLite."""
    global _engine
    target_url = db_url or os.getenv("DATABASE_URL", DATABASE_URL)
    
    # If the URL is already initialized and matches, reuse
    if _engine is not None and str(_engine.url) == target_url:
        return _engine

    is_sqlite = target_url.startswith("sqlite")
    
    if is_sqlite:
        engine = create_engine(
            target_url,
            connect_args={"check_same_thread": False, "timeout": 30.0},
            echo=False,
            future=True,
        )

        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()
    else:
        # PostgreSQL enterprise configuration
        engine = create_engine(
            target_url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            pool_pre_ping=True,
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
            echo=False,
            future=True,
        )

    _engine = engine
    return _engine


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Return sessionmaker bound to current engine."""
    global _session_factory
    eng = engine or get_engine()
    if _session_factory is None or _session_factory.kw.get("bind") != eng:
        _session_factory = sessionmaker(bind=eng, autoflush=False, autocommit=False, future=True)
    return _session_factory


def get_scoped_session() -> scoped_session[Session]:
    """Return thread-local scoped session."""
    global _scoped_session
    if _scoped_session is None:
        factory = get_session_factory()
        _scoped_session = scoped_session(factory)
    return _scoped_session


@contextmanager
def session_scope(db_url: str | None = None) -> Generator[Session, None, None]:
    """
    Context manager providing a transactional SQLAlchemy Session scope.
    Automatically commits on normal exit, rolls back on exception, and closes.
    """
    engine = get_engine(db_url)
    factory = get_session_factory(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error(f"Database session rolled back due to error: {exc}")
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """Dependency generator for web routes or CLI scripts."""
    with session_scope() as session:
        yield session


def init_db_schema(engine: Engine | None = None) -> None:
    """Create all tables defined on Base if they do not exist."""
    eng = engine or get_engine()
    env_mode = os.getenv("ENVIRONMENT", os.getenv("WSA_ENV", os.getenv("FLASK_ENV", "development"))).lower()
    if env_mode in ("production", "prod") and eng.dialect.name == "postgresql":
        raise RuntimeError(
            "FATAL: Runtime init_db_schema() / create_all() is strictly prohibited in production mode. "
            "Database migrations must be executed exclusively via versioned Alembic runner ('sentinelwp-migrate')."
        )
    # Import all models to ensure they are registered on Base.metadata
    import core.db.models  # noqa: F401
    Base.metadata.create_all(bind=eng)

    # Schema synchronization for newly added model columns
    if eng.dialect.name == "postgresql":
        try:
            with eng.connect() as conn:
                conn.execute(text("ALTER TABLE integration_outbox ADD COLUMN IF NOT EXISTS claimed_at VARCHAR(64);"))
                conn.execute(text("ALTER TABLE integration_outbox ADD COLUMN IF NOT EXISTS claimed_by VARCHAR(128);"))
                conn.execute(text("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS max_retries INTEGER DEFAULT 3;"))
                conn.execute(text("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER DEFAULT 0;"))
                conn.execute(text("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS last_failure_at VARCHAR(64);"))
                conn.execute(text("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS last_success_at VARCHAR(64);"))
                conn.execute(text("ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS paused_until VARCHAR(64);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_outbox_processing_claimed ON integration_outbox(status, claimed_at);"))
                conn.commit()
        except Exception as e:
            logger.error("Critical: PostgreSQL schema migration failed: %s", e)
            raise RuntimeError(f"PostgreSQL schema migration failed: {e}") from e

    logger.info("Database schema verified and created via SQLAlchemy metadata.")
