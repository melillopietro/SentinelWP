#!/usr/bin/env bash
# ==============================================================================
# SentinelWP Enterprise Production Environment Preflight Validator
# Validates production secrets, SSL/TLS, network controls, and fail-closed security.
# Usage: ./scripts/validate_prod_env.sh [path_to_env_file]
# ==============================================================================
set -euo pipefail

ENV_FILE="${1:-.env.production}"
ERRORS=0
WARNINGS=0

log_pass() { echo "  [PASS] $1"; }
log_fail() { echo "  [FAIL] $1" >&2; ERRORS=$((ERRORS + 1)); }
log_warn() { echo "  [WARN] $1"; WARNINGS=$((WARNINGS + 1)); }

echo "=============================================================================="
echo " SentinelWP Production Preflight Environment Validation"
echo " Target File: ${ENV_FILE}"
echo "=============================================================================="

if [ -f "${ENV_FILE}" ]; then
    # Check file permissions (should not be world/group readable in production)
    PERMS=$(stat -f "%OLp" "${ENV_FILE}" 2>/dev/null || stat -c "%a" "${ENV_FILE}" 2>/dev/null || echo "")
    if [ -n "${PERMS}" ]; then
        if [ "${PERMS}" -le 600 ]; then
            log_pass "File permissions restricted: ${PERMS}"
        else
            log_warn "File permissions (${PERMS}) are broader than 600. Recommended: chmod 600 ${ENV_FILE}"
        fi
    fi
    # Source environment variables in a subshell or export safely
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
else
    log_warn "Env file '${ENV_FILE}' not found on disk; validating current process environment."
fi

# 1. Environment Mode Check
echo "--- 1. Environment Mode ---"
if [ "${ENVIRONMENT:-}" = "production" ] || [ "${ENVIRONMENT:-}" = "prod" ]; then
    log_pass "ENVIRONMENT is explicitly set to '${ENVIRONMENT}'"
else
    log_fail "ENVIRONMENT must be set to 'production' (found: '${ENVIRONMENT:-not set}')"
fi

# 2. Flask Application Secret Key (WSA_SECRET_KEY)
echo "--- 2. Application Secret Key ---"
SECRET_KEY="${WSA_SECRET_KEY:-}"
if [ -z "${SECRET_KEY}" ]; then
    log_fail "WSA_SECRET_KEY is empty or not set."
elif [ "${#SECRET_KEY}" -lt 32 ]; then
    log_fail "WSA_SECRET_KEY length (${#SECRET_KEY} chars) is less than required 32 characters."
elif echo "${SECRET_KEY}" | grep -qiE "replace_with|change-me|dev_password|insecure|example|secret|admin|password"; then
    log_fail "WSA_SECRET_KEY contains known weak or placeholder patterns."
else
    log_pass "WSA_SECRET_KEY entropy verified (length: ${#SECRET_KEY} chars, no placeholder patterns)"
fi

# 3. PostgreSQL Credentials & Connection
echo "--- 3. PostgreSQL Configuration ---"
PG_URL="${DATABASE_URL:-}"
PG_PASS="${POSTGRES_PASSWORD:-}"
if [ -z "${PG_URL}" ]; then
    log_fail "DATABASE_URL is not set."
elif echo "${PG_URL}" | grep -q "sqlite"; then
    log_fail "DATABASE_URL cannot use SQLite in production mode."
elif ! echo "${PG_URL}" | grep -qiE "^postgresql(\+psycopg)?://"; then
    log_fail "DATABASE_URL must be a PostgreSQL connection string."
elif echo "${PG_URL}" | grep -qiE "sentinelwp_dev_password|replace_with|:password123@|:admin123@|:dev_password@|:changeme@"; then
    log_fail "DATABASE_URL contains known default development password."
else
    log_pass "DATABASE_URL configured for PostgreSQL with non-default credentials."
fi

if [ -n "${PG_PASS}" ]; then
    if [ "${#PG_PASS}" -lt 12 ]; then
        log_fail "POSTGRES_PASSWORD length (${#PG_PASS} chars) is less than required 12 characters."
    elif echo "${PG_PASS}" | grep -qiE "replace_with|sentinelwp_dev_password|^admin123$|^password123$|^changeme$"; then
        log_fail "POSTGRES_PASSWORD contains known placeholder or weak patterns."
    else
        log_pass "POSTGRES_PASSWORD strength verified (length >= 12, non-default)"
    fi
fi

# 4. Redis Authentication & Broker
echo "--- 4. Redis Task Broker Configuration ---"
R_URL="${REDIS_URL:-}"
R_PASS="${REDIS_PASSWORD:-}"
if [ -z "${R_URL}" ]; then
    log_fail "REDIS_URL is not set."
elif echo "${R_URL}" | grep -qiE "replace_with"; then
    log_fail "REDIS_URL contains placeholder password."
else
    log_pass "REDIS_URL configured."
fi

if [ -z "${R_PASS}" ]; then
    log_fail "REDIS_PASSWORD is not set (Redis must require authentication in production)."
elif [ "${#R_PASS}" -lt 12 ]; then
    log_fail "REDIS_PASSWORD length (${#R_PASS} chars) is less than required 12 characters."
elif echo "${R_PASS}" | grep -qiE "replace_with|password|admin"; then
    log_fail "REDIS_PASSWORD contains known placeholder or weak patterns."
else
    log_pass "REDIS_PASSWORD strength verified (length >= 12, non-default)"
fi

# 5. Reverse Proxy & Trusted Hop Settings
echo "--- 5. Reverse Proxy & Trusted Ingress ---"
if [ "${WSA_BEHIND_PROXY:-}" = "true" ] || [ "${WSA_BEHIND_PROXY:-}" = "1" ]; then
    log_pass "WSA_BEHIND_PROXY enabled for Werkzeug ProxyFix."
    if [ "${WSA_PROXY_X_FOR:-1}" -eq 1 ]; then
        log_pass "WSA_PROXY_X_FOR hop count strictly set to 1 (rejects spoofed hops)."
    else
        log_warn "WSA_PROXY_X_FOR is set to '${WSA_PROXY_X_FOR}'. Ensure upstream hops match architecture."
    fi
else
    log_warn "WSA_BEHIND_PROXY is not enabled. In production with Nginx, this should be 'true'."
fi

# 6. Session Security & Cookie Policies
echo "--- 6. Session Security ---"
if [ "${WSA_SESSION_COOKIE_SECURE:-}" = "true" ] || [ "${WSA_SESSION_COOKIE_SECURE:-}" = "1" ]; then
    log_pass "WSA_SESSION_COOKIE_SECURE enabled (HTTPS only cookies)."
else
    log_fail "WSA_SESSION_COOKIE_SECURE must be 'true' in production."
fi

SAMESITE="${WSA_SESSION_COOKIE_SAMESITE:-Lax}"
if [ "${SAMESITE}" = "Lax" ] || [ "${SAMESITE}" = "Strict" ]; then
    log_pass "WSA_SESSION_COOKIE_SAMESITE set to '${SAMESITE}'."
else
    log_warn "WSA_SESSION_COOKIE_SAMESITE set to '${SAMESITE}'. 'Lax' or 'Strict' is recommended."
fi

# 7. SSRF Protection & Private Target Blocking
echo "--- 7. SSRF & Network Security ---"
ALLOW_PRIV="${WSA_ALLOW_PRIVATE_TARGETS:-false}"
if [ "${ALLOW_PRIV}" = "false" ] || [ "${ALLOW_PRIV}" = "0" ]; then
    log_pass "WSA_ALLOW_PRIVATE_TARGETS is 'false' (RFC1918 addresses blocked)."
else
    log_warn "WSA_ALLOW_PRIVATE_TARGETS is '${ALLOW_PRIV}'. Internal targets will be scannable!"
fi

TEST_ALLOWLIST="${WSA_TEST_TARGET_ALLOWLIST:-}"
if [ -z "${TEST_ALLOWLIST}" ]; then
    log_pass "WSA_TEST_TARGET_ALLOWLIST is empty (fail-closed in production)."
else
    log_warn "WSA_TEST_TARGET_ALLOWLIST is set to '${TEST_ALLOWLIST}'. Note: SentinelWP disables test allowlists in production."
fi

# 8. TLS Certificate Configuration
echo "--- 8. TLS Configuration ---"
TLS_DIR="${TLS_CERT_DIR:-nginx/certs}"
if [ -f "${TLS_DIR}/tls.crt" ] && [ -f "${TLS_DIR}/tls.key" ]; then
    log_pass "TLS certificate and key exist in ${TLS_DIR}"
else
    log_warn "TLS certificate/key not found in ${TLS_DIR}. Run scripts/generate_self_signed_cert.sh or mount production certificates."
fi

# 9. Summary
echo "=============================================================================="
echo " Validation Result: ${ERRORS} Error(s), ${WARNINGS} Warning(s)"
echo "=============================================================================="

if [ "${ERRORS}" -gt 0 ]; then
    echo " [FATAL] Environment failed production security preflight validation." >&2
    exit 1
else
    echo " [SUCCESS] Environment passed production security preflight validation."
    exit 0
fi
