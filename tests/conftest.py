"""Global pytest hooks for isolated, reproducible test runs."""
import os

# Must be set before app/scheduler modules initialize background threads.
os.environ.setdefault("SENTINELWP_DISABLE_BACKGROUND", "1")

import pytest


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
