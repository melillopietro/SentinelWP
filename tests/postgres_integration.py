"""Shared PostgreSQL URLs for Sprint 10 integration and CI disposable services."""
import os

# Isolated Sprint 10 lab (docker-compose.sprint10.yml, port 5439)
SPRINT10_LAB_URL = (
    "postgresql://s10_user:s10_dev_password_123@127.0.0.1:5439/sentinelwp_s10"
)

# GitHub Actions / generic CI service container (port 5432)
CI_INTEGRATION_URL = (
    "postgresql+psycopg://sentinelwp:sentinelwp_password@127.0.0.1:5432/sentinelwp_test"
)


def get_sprint10_postgres_url() -> str:
    """
    URL for Sprint 10 PostgreSQL integration tests.
    Prefer explicit SENTINELWP_SPRINT10_PG_URL, then CI DATABASE_URL, then lab default.
    """
    explicit = os.environ.get("SENTINELWP_SPRINT10_PG_URL", "").strip()
    if explicit:
        return explicit
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return os.environ.get("DATABASE_URL", CI_INTEGRATION_URL)
    db = os.environ.get("DATABASE_URL", "").strip()
    if db.lower().startswith(("postgresql://", "postgres://", "postgresql+")):
        return db
    return SPRINT10_LAB_URL
