"""Global pytest hooks for isolated, reproducible test runs."""
import os
import sys
import subprocess

# Must be set before app/scheduler modules initialize background threads.
os.environ.setdefault("SENTINELWP_DISABLE_BACKGROUND", "1")

import pytest

_POSTGRES_SCHEMA_READY = False


def _postgres_configured() -> bool:
    url = os.environ.get("DATABASE_URL", os.environ.get("WSA_DATABASE_URL", ""))
    return url.strip().lower().startswith(("postgresql://", "postgres://", "postgresql+"))


def pytest_sessionstart(session):
    """Ensure CI/lab PostgreSQL has Alembic schema before adapter-backed tests run."""
    global _POSTGRES_SCHEMA_READY
    if not _postgres_configured() or _POSTGRES_SCHEMA_READY:
        return
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    subprocess.run(
        [sys.executable, os.path.join(root, "scripts", "run_migrations.py"), "--confirm"],
        cwd=root,
        check=True,
        env=os.environ.copy(),
    )
    _POSTGRES_SCHEMA_READY = True


def _postgres_url_reachable(url: str) -> bool:
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    """Skip Sprint 10 PostgreSQL suites when no integration database is reachable."""
    from tests.postgres_integration import get_sprint10_postgres_url

    if _postgres_url_reachable(get_sprint10_postgres_url()):
        return
    skip = pytest.mark.skip(reason="Sprint 10 PostgreSQL integration URL not reachable")
    for item in items:
        path = item.nodeid.split("::")[0]
        if "test_sprint10_phase" in path:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _reset_sqlite_connections():
    yield
    try:
        from core.vulnerability_intelligence import repository as vuln_repo
        if vuln_repo._vuln_conn is not None:
            vuln_repo._vuln_conn.close()
            vuln_repo._vuln_conn = None
    except Exception:
        pass
    try:
        import core.repository as core_repo
        if core_repo._conn is not None:
            core_repo._conn.close()
            core_repo._conn = None
    except Exception:
        pass
