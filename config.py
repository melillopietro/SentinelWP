"""
WordPress Security Auditor Pro - Configuration & Enterprise Hardening
"""
import os
import sys
import logging
from pathlib import Path

logger = logging.getLogger("sentinelwp.config")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Environment: development, test, or production
ENVIRONMENT = os.getenv("ENVIRONMENT", os.getenv("WSA_ENV", os.getenv("FLASK_ENV", "development"))).lower()


def strict_dns_resolution_required() -> bool:
    """
    When True, hostnames must resolve to at least one safe public address before scanning.
    Defaults to True in production; development/test may set WSA_STRICT_DNS=false explicitly.
    """
    explicit = os.getenv("WSA_STRICT_DNS")
    if explicit is not None:
        return explicit.lower() in ("true", "1", "yes")
    return ENVIRONMENT in ("production", "prod")

DATABASE_PATH = os.getenv("WSA_DATABASE_PATH", str(DATA_DIR / "wsa.db"))
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")


def is_postgres_configured(url: str | None = None) -> bool:
    """
    Deterministically determines if the application is configured to use PostgreSQL.
    Checks explicit url parameter, or DATABASE_URL / WSA_DATABASE_URL environment variables.
    Returns True for 'postgresql://', 'postgres://', 'postgresql+psycopg://', etc.
    """
    target = url if url is not None else os.getenv("DATABASE_URL", os.getenv("WSA_DATABASE_URL", DATABASE_URL))
    if not target:
        return False
    target = target.strip().lower()
    return target.startswith(("postgresql://", "postgres://", "postgresql+"))


def sanitize_db_url(url: str | None = None) -> str:
    """
    Sanitize database URL for logging, diagnostic messages, and error reporting,
    redacting sensitive credentials (passwords, tokens).
    """
    target = url if url is not None else os.getenv("DATABASE_URL", os.getenv("WSA_DATABASE_URL", DATABASE_URL))
    if not target:
        return ""
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(target)
        if not parts.scheme:
            return target
        if parts.password or parts.username:
            netloc = parts.hostname or ""
            if parts.port:
                netloc = f"{netloc}:{parts.port}"
            user = parts.username or ""
            if parts.password:
                user_info = f"{user}:***@" if user else "***@"
            else:
                user_info = f"{user}@" if user else ""
            netloc = f"{user_info}{netloc}"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        return target
    except Exception:
        import re
        return re.sub(r":([^@]+)@", r":***@", target)


IS_POSTGRES = is_postgres_configured()

# Celery & Redis Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

# Execution Backend: 'celery' in production, or 'local' for standalone/tests fallback
SCAN_EXECUTION_BACKEND = os.getenv(
    "SCAN_EXECUTION_BACKEND",
    "celery" if ENVIRONMENT in ("production", "prod") else "local"
).lower()

from core.version import __version__, APP_NAME, RELEASE_CODENAME

# Scan Execution Governance, Concurrency & Timeouts
SCAN_MAX_RETRIES = int(os.getenv("SCAN_MAX_RETRIES", "3"))
SCAN_SOFT_TIME_LIMIT = int(os.getenv("SCAN_SOFT_TIME_LIMIT", "1200"))  # 20 minutes
SCAN_HARD_TIME_LIMIT = int(os.getenv("SCAN_HARD_TIME_LIMIT", "1500"))  # 25 minutes
MAX_CONCURRENT_SCANS_PER_TENANT = int(os.getenv("MAX_CONCURRENT_SCANS_PER_TENANT", "5"))
MAX_CONCURRENT_SCANS_GLOBAL = int(os.getenv("MAX_CONCURRENT_SCANS_GLOBAL", "25"))
MAX_CONCURRENT_SCANS_PER_ASSET = int(os.getenv("MAX_CONCURRENT_SCANS_PER_ASSET", "1"))
SCAN_STATUS_POLL_SECONDS = int(os.getenv("SCAN_STATUS_POLL_SECONDS", "5"))

# Evidence Payload Guardrails
MAX_EVIDENCE_SIZE_BYTES = int(os.getenv("MAX_EVIDENCE_SIZE_BYTES", str(10 * 1024 * 1024)))  # 10MB default
# Outbound scanner HTTP response size cap (SSRF/DoS mitigation)
MAX_HTTP_RESPONSE_BYTES = int(os.getenv("WSA_MAX_HTTP_RESPONSE_BYTES", str(10 * 1024 * 1024)))

# Database & Redis Connection Pool Sizing
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
REDIS_POOL_MAX_CONNECTIONS = int(os.getenv("REDIS_POOL_MAX_CONNECTIONS", "50"))

INTEL_FRESHNESS_SLA_HOURS = float(os.getenv("INTEL_FRESHNESS_SLA_HOURS", "24.0"))
SCAN_JOB_RETENTION_DAYS = int(os.getenv("SCAN_JOB_RETENTION_DAYS", "90"))
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "365"))

# --- Secret Key & Session Hardening ---
DEFAULT_INSECURE_SECRET = "CHANGE-ME-IN-PRODUCTION-USE-RANDOM-32-BYTES"
KNOWN_WEAK_SECRETS = {
    DEFAULT_INSECURE_SECRET.lower(),
    "secret",
    "admin",
    "password",
    "changeme",
    "123456",
}


def is_weak_secret(secret: str) -> bool:
    """Return True if secret is empty, too short, known weak, or placeholder."""
    if not secret or len(secret) < 32:
        return True
    s_lower = secret.lower()
    if s_lower in KNOWN_WEAK_SECRETS:
        return True
    if any(pat in s_lower for pat in ("replace_with_", "change-me", "dev_password", "insecure", "example")):
        return True
    return False

# --- Admin Password Policy (SEC-001) ---
# Passwords rejected during initial setup regardless of source.
ADMIN_PASSWORD_MIN_LENGTH = int(os.getenv("ADMIN_PASSWORD_MIN_LENGTH", "12"))
KNOWN_WEAK_PASSWORDS = {
    "admin", "admin123", "admin1234", "administrator", "password", "password1",
    "password123", "password123456", "changeme", "letmein", "welcome", "123456", "12345678",
    "qwerty", "sentinelwp", "wordpress", "default",
}


def validate_admin_password(password: str) -> tuple[bool, str]:
    """
    Validates a candidate admin password against the platform password policy.
    Returns (is_valid: bool, reason: str).
    Policy: minimum ADMIN_PASSWORD_MIN_LENGTH characters, not in known-weak list.
    """
    if not password:
        return False, "Password must not be empty."
    if len(password) < ADMIN_PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {ADMIN_PASSWORD_MIN_LENGTH} characters."
    if password.lower() in KNOWN_WEAK_PASSWORDS:
        return False, "Password is too common. Please choose a unique password."
    return True, ""


def get_validated_secret_key(environment: str | None = None) -> str:
    """
    Validate WSA_SECRET_KEY against production security baselines.
    In production: refuses startup if missing, default, placeholder, or < 32 chars.
    In development/test: allows startup with prominent security warning.
    """
    env = (environment or os.getenv("ENVIRONMENT", os.getenv("WSA_ENV", os.getenv("FLASK_ENV", "development")))).lower()
    raw_key = os.getenv("WSA_SECRET_KEY", "").strip()
    is_prod = env in ("production", "prod")

    if is_weak_secret(raw_key):
        if is_prod:
            raise ValueError(
                "FATAL: Production mode requires a secure WSA_SECRET_KEY environment variable "
                "with at least 32 characters. Default or weak secrets are strictly rejected."
            )
        # Development / test permissive fallback
        if not raw_key:
            raw_key = DEFAULT_INSECURE_SECRET
        logger.warning(
            "SECURITY WARNING: Running in non-production environment with insecure or default secret key. "
            "Set WSA_SECRET_KEY to a secure 32+ character random string for production deployments."
        )

    return raw_key


SECRET_KEY = get_validated_secret_key()

# Session Cookie Hardening
SESSION_COOKIE_SECURE = os.getenv(
    "WSA_SESSION_COOKIE_SECURE",
    "true" if ENVIRONMENT in ("production", "prod") else "false"
).lower() in ("true", "1", "yes")

if ENVIRONMENT in ("production", "prod") and not SESSION_COOKIE_SECURE:
    raise ValueError(
        "FATAL: Production mode requires WSA_SESSION_COOKIE_SECURE=true. "
        "Insecure session cookies are strictly prohibited in production."
    )

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = os.getenv("WSA_SESSION_COOKIE_SAMESITE", "Lax")
SESSION_EXPIRY_HOURS = int(os.getenv("WSA_SESSION_EXPIRY_HOURS", "8"))

# Network & App Server Settings
PORT = int(os.getenv("PORT", os.getenv("WSA_PORT", "8080")))
HOST = os.getenv("HOST", os.getenv("WSA_HOST", "0.0.0.0"))
REQUEST_TIMEOUT = int(os.getenv("WSA_REQUEST_TIMEOUT", "15"))
MAX_CONCURRENT_SCANS = int(os.getenv("WSA_MAX_CONCURRENT_SCANS", "5"))
WSA_MAX_SCHEDULE_TARGETS = int(os.getenv("WSA_MAX_SCHEDULE_TARGETS", "100"))

USER_AGENT = os.getenv(
    "WSA_USER_AGENT",
    "Mozilla/5.0 (compatible; SentinelWP-Auditor/2.0; +https://github.com/wuerth-it/sentinel-wp)"
)
CONFIDENCE_THRESHOLD = float(os.getenv("WSA_CONFIDENCE_THRESHOLD", "0.3"))
NORMALIZATION_FACTOR = float(os.getenv("WSA_NORMALIZATION_FACTOR", "150.0"))

# Default Admin Credentials
# NOTE: ADMIN_PASSWORD has no safe default. Callers must validate via validate_admin_password()
# before use. The setup wizard enforces password policy; programmatic callers should check
# WSA_ADMIN_PASSWORD is set and passes policy before creating an admin account.
ADMIN_USERNAME = os.getenv("WSA_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("WSA_ADMIN_PASSWORD", "")

# --- Vulnerability Intelligence ---
WORDFENCE_API_KEY = os.getenv("WORDFENCE_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
VULN_INTEL_ENABLED = os.getenv("VULN_INTEL_ENABLED", "true").lower() in ("true", "1", "yes")
VULN_INTEL_SYNC_INTERVAL_MINUTES = int(os.getenv("VULN_INTEL_SYNC_INTERVAL_MINUTES", "30"))
VULN_INTEL_RETENTION_MONTHS = int(os.getenv("VULN_INTEL_RETENTION_MONTHS", "24"))
VULN_INTEL_STALE_AFTER_HOURS = float(os.getenv("VULN_INTEL_STALE_AFTER_HOURS", "0.5"))
POPULAR_PLUGIN_MIN_ACTIVE_INSTALLS = int(os.getenv("POPULAR_PLUGIN_MIN_ACTIVE_INSTALLS", "100000"))
PLUGIN_METADATA_CACHE_HOURS = int(os.getenv("PLUGIN_METADATA_CACHE_HOURS", "168"))
# Off by default: live OSV HTTP calls make scan output depend on external network state.
OSV_LIVE_ENRICHMENT_ENABLED = os.getenv("OSV_LIVE_ENRICHMENT_ENABLED", "false").lower() in (
    "true",
    "1",
    "yes",
)


def validate_production_config(enforce: bool = False) -> tuple[bool, list[str]]:
    """
    Validates enterprise production baseline compliance.
    Returns (is_valid: bool, issues: list[str]).
    If enforce=True and issues are found, raises ValueError.
    """
    issues = []
    env = os.getenv("ENVIRONMENT", os.getenv("WSA_ENV", os.getenv("FLASK_ENV", "development"))).lower()
    is_prod = env in ("production", "prod")

    # 1. Secret key validation
    raw_key = os.getenv("WSA_SECRET_KEY", "").strip()
    if not raw_key or raw_key in KNOWN_WEAK_SECRETS or len(raw_key) < 32:
        if is_prod:
            issues.append("WSA_SECRET_KEY must be set to a secure random string of at least 32 characters in production.")

    # 2. Database URL validation
    db_url = os.getenv("DATABASE_URL", "")
    if is_prod:
        if not db_url or "sqlite" in db_url.lower():
            issues.append("Production requires an enterprise PostgreSQL database (DATABASE_URL starting with postgresql:// or postgresql+psycopg://). SQLite is not permitted in production.")

    # 3. Execution backend validation
    backend = os.getenv("SCAN_EXECUTION_BACKEND", "celery" if is_prod else "local").lower()
    if is_prod and backend != "celery":
        issues.append("SCAN_EXECUTION_BACKEND must be set to 'celery' in production for distributed asynchronous scan execution.")

    # 4. Celery broker and Redis validation
    redis_url = os.getenv("REDIS_URL", "")
    broker_url = os.getenv("CELERY_BROKER_URL", redis_url)
    if is_prod and not broker_url:
        issues.append("CELERY_BROKER_URL or REDIS_URL must be configured for Celery task queuing in production.")

    is_valid = len(issues) == 0
    if not is_valid:
        msg = f"Production configuration validation failed with {len(issues)} issues: " + "; ".join(issues)
        if enforce:
            raise ValueError(msg)
        logger.warning(msg)

    return is_valid, issues

