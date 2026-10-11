"""Shared PostgreSQL URLs for Sprint 10 integration and CI disposable services."""
import os

# Isolated Sprint 10 lab (docker-compose.sprint10.yml, port 5439)
SPRINT10_LAB_URL = (
    "postgresql+psycopg://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s10"
)

# GitHub Actions / generic CI service container (port 5432)
CI_INTEGRATION_URL = (
    "postgresql+psycopg://sentinelwp:sentinelwp_password@127.0.0.1:5432/sentinelwp_test"
)


def get_sprint10_postgres_url() -> str:
    """
    URL for Sprint 10 PostgreSQL integration tests.
    CI must set SENTINELWP_SPRINT10_PG_URL explicitly (do not rely on DATABASE_URL).
    """
    explicit = os.environ.get("SENTINELWP_SPRINT10_PG_URL", "").strip()
    if explicit:
        return explicit
    return SPRINT10_LAB_URL
