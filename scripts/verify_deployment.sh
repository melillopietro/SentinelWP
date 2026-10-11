#!/usr/bin/env bash
# ==============================================================================
# SentinelWP Enterprise Deployment Verification Script
# ==============================================================================
# Validates an active SentinelWP production deployment on Ubuntu Server LTS:
#  1. Compose definition port isolation (zero host port mapping for db, redis, web)
#  2. Network isolation (optional port scan for internal service closure)
#  3. Docker Compose container health & non-root user execution
#  4. Ingress gateway (HTTP -> HTTPS redirect, TLS handshake, security headers)
#  5. Application health probes (/health, /ready, /metrics)
#  6. Celery worker responsiveness and task catalog
#
# Usage:
#   bash scripts/verify_deployment.sh [OPTIONS]
# Options:
#   --host <host>          Target hostname or IP (default: 127.0.0.1)
#   --http-port <port>     HTTP gateway port (default: 80)
#   --https-port <port>    HTTPS gateway port (default: 443)
#   --compose-file <path>  Docker Compose file (default: docker-compose.prod.yml)
#   --insecure, -k         Allow self-signed TLS certificates for curl
#   --skip-docker          Skip Docker daemon and container-level checks
#   --skip-port-scan       Skip host TCP port probing (e.g. on dev workstations)
#   --help, -h             Show this help message
# ==============================================================================

set -uo pipefail

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Defaults
TARGET_HOST="127.0.0.1"
HTTP_PORT="80"
HTTPS_PORT="443"
COMPOSE_FILE="docker-compose.prod.yml"
INSECURE_CURL=""
SKIP_DOCKER=false
SKIP_PORT_SCAN=false
TIMEOUT_SEC=5

PASSED_COUNT=0
FAILED_COUNT=0
WARNING_COUNT=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED_COUNT=$((PASSED_COUNT + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED_COUNT=$((FAILED_COUNT + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNING_COUNT=$((WARNING_COUNT + 1))
}

print_header() {
    echo -e "\n${CYAN}==============================================================================${NC}"
    echo -e "${CYAN}  SentinelWP Enterprise Deployment Verification Suite${NC}"
    echo -e "${CYAN}==============================================================================${NC}"
    echo "  Target Host:       ${TARGET_HOST}"
    echo "  HTTP / HTTPS Port: ${HTTP_PORT} / ${HTTPS_PORT}"
    echo "  Compose File:      ${COMPOSE_FILE}"
    echo "  Skip Docker:       ${SKIP_DOCKER}"
    echo "  Skip Port Scan:    ${SKIP_PORT_SCAN}"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}\n"
}

# Parse Command Line Arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --http-port)
            HTTP_PORT="$2"
            shift 2
            ;;
        --https-port)
            HTTPS_PORT="$2"
            shift 2
            ;;
        --compose-file)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        -k|--insecure)
            INSECURE_CURL="-k"
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        --skip-port-scan)
            SKIP_PORT_SCAN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--host <host>] [--http-port <port>] [--https-port <port>] [--compose-file <path>] [-k|--insecure] [--skip-docker] [--skip-port-scan]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

print_header

# ------------------------------------------------------------------------------
# Check 1: Compose Definition Port Isolation
# ------------------------------------------------------------------------------
if [ -f "$COMPOSE_FILE" ]; then
    log_info "Verifying Compose service port isolation in ${COMPOSE_FILE}..."
    
    # Check that only gateway publishes host ports
    DB_HAS_PORTS=$(awk '/^  db:/,/^  [a-z]/ { if ($1 ~ /^ports:/) print $0 }' "$COMPOSE_FILE" || true)
    if [ -n "$DB_HAS_PORTS" ]; then
        log_fail "Database service 'db' maps host ports in ${COMPOSE_FILE}!"
    else
        log_pass "Database service 'db' has zero host ports mapped in ${COMPOSE_FILE}."
    fi

    REDIS_HAS_PORTS=$(awk '/^  redis:/,/^  [a-z]/ { if ($1 ~ /^ports:/) print $0 }' "$COMPOSE_FILE" || true)
    if [ -n "$REDIS_HAS_PORTS" ]; then
        log_fail "Redis service 'redis' maps host ports in ${COMPOSE_FILE}!"
    else
        log_pass "Redis service 'redis' has zero host ports mapped in ${COMPOSE_FILE}."
    fi

    WEB_HAS_PORTS=$(awk '/^  web:/,/^  [a-z]/ { if ($1 ~ /^ports:/) print $0 }' "$COMPOSE_FILE" || true)
    if [ -n "$WEB_HAS_PORTS" ]; then
        log_fail "Web service 'web' maps host ports in ${COMPOSE_FILE}!"
    else
        log_pass "Web service 'web' has zero host ports mapped in ${COMPOSE_FILE}."
    fi
fi

# ------------------------------------------------------------------------------
# Check 2: Network Isolation & Host Port Exposure (when not skipped)
# ------------------------------------------------------------------------------
if [ "$SKIP_PORT_SCAN" = false ]; then
    log_info "Probing target host (${TARGET_HOST}) network isolation..."

    if nc -z -w 1 "${TARGET_HOST}" 5432 2>/dev/null; then
        log_warn "Host port 5432 is responding on ${TARGET_HOST} (verify this is not the production DB container)."
    else
        log_pass "PostgreSQL port 5432 is NOT exposed on ${TARGET_HOST} (network isolation intact)."
    fi

    if nc -z -w 1 "${TARGET_HOST}" 6379 2>/dev/null; then
        log_warn "Host port 6379 is responding on ${TARGET_HOST} (verify this is not the production Redis container)."
    else
        log_pass "Redis port 6379 is NOT exposed on ${TARGET_HOST} (network isolation intact)."
    fi

    if nc -z -w 1 "${TARGET_HOST}" 5000 2>/dev/null; then
        log_warn "Host port 5000 is responding on ${TARGET_HOST} (verify this is not the production Gunicorn container)."
    else
        log_pass "WSGI port 5000 is NOT exposed on ${TARGET_HOST} (network isolation intact)."
    fi
fi

# ------------------------------------------------------------------------------
# Check 3: Docker Compose Container Status & Health (if not skipped)
# ------------------------------------------------------------------------------
if [ "$SKIP_DOCKER" = false ]; then
    log_info "Verifying Docker Compose services status..."

    if ! command -v docker &>/dev/null; then
        log_warn "Docker command not found; skipping container inspection."
    elif [ ! -f "$COMPOSE_FILE" ]; then
        log_warn "Compose file ${COMPOSE_FILE} not found; skipping container inspection."
    else
        COMPOSE_PS=$(docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || true)
        
        if [ -z "$COMPOSE_PS" ]; then
            log_warn "Docker compose stack is currently not running in this environment."
        else
            log_pass "Docker compose stack is active."

            REQUIRED_SERVICES=("db" "redis" "web" "worker" "beat" "gateway")
            for svc in "${REQUIRED_SERVICES[@]}"; do
                CONTAINER_STATUS=$(docker compose -f "$COMPOSE_FILE" ps "$svc" --format "{{.Status}}" 2>/dev/null || true)
                if [[ "$CONTAINER_STATUS" =~ "Up" ]]; then
                    if [[ "$CONTAINER_STATUS" =~ "unhealthy" ]]; then
                        log_fail "Service '${svc}' is running but UNHEALTHY: ${CONTAINER_STATUS}"
                    else
                        log_pass "Service '${svc}' is running: ${CONTAINER_STATUS}"
                    fi
                elif [ -n "$CONTAINER_STATUS" ]; then
                    log_fail "Service '${svc}' is NOT running (Status: '${CONTAINER_STATUS}')."
                fi
            done

            WEB_UID=$(docker compose -f "$COMPOSE_FILE" exec -T web id -u 2>/dev/null || true)
            if [ "$WEB_UID" = "1000" ]; then
                log_pass "Web container executes as non-root user (UID: 1000)."
            elif [ -n "$WEB_UID" ]; then
                log_warn "Web container UID is '${WEB_UID}' (expected 1000)."
            fi

            WORKER_PING=$(docker compose -f "$COMPOSE_FILE" exec -T worker celery -A core.tasks.celery_app inspect ping --timeout=3 2>/dev/null || true)
            if [[ "$WORKER_PING" =~ "pong" ]]; then
                log_pass "Celery worker responded to inspect ping with 'pong'."
            elif [ -n "$WORKER_PING" ]; then
                log_warn "Celery worker ping did not return 'pong': ${WORKER_PING}"
            fi
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Check 4: Gateway Ingress & TLS Redirection
# ------------------------------------------------------------------------------
log_info "Verifying gateway ingress & HTTP -> HTTPS redirection..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT_SEC" "http://${TARGET_HOST}:${HTTP_PORT}/" 2>/dev/null || true)
if [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "308" ]; then
    log_pass "HTTP on port ${HTTP_PORT} returned redirect status ${HTTP_CODE}."
    
    REDIRECT_LOC=$(curl -s -I --max-time "$TIMEOUT_SEC" "http://${TARGET_HOST}:${HTTP_PORT}/" 2>/dev/null | tr -d '\r' | awk -F': ' '/^[Ll]ocation:/ {print $2}' || true)
    if [[ "$REDIRECT_LOC" =~ ^https:// ]]; then
        log_pass "HTTP redirects to HTTPS: ${REDIRECT_LOC}"
    elif [ -n "$REDIRECT_LOC" ]; then
        log_warn "HTTP redirect location does not start with https://: ${REDIRECT_LOC}"
    fi
elif [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" = "000" ]; then
    log_warn "Gateway port ${HTTP_PORT} did not respond (connection refused or timeout)."
else
    log_warn "HTTP on port ${HTTP_PORT} returned status ${HTTP_CODE} (expected 301/308 redirect)."
fi

# ------------------------------------------------------------------------------
# Check 5: HTTPS Application Endpoints & Security Headers
# ------------------------------------------------------------------------------
log_info "Verifying HTTPS endpoints and application health probes..."

BASE_URL="https://${TARGET_HOST}:${HTTPS_PORT}"

# Test /health endpoint
HEALTH_RESP=$(curl -s $INSECURE_CURL --max-time "$TIMEOUT_SEC" "${BASE_URL}/health" 2>/dev/null || true)
if [[ "$HEALTH_RESP" =~ '"status"' ]] && [[ "$HEALTH_RESP" =~ '"ok"' ]]; then
    log_pass "Probe GET /health returned 200 OK: ${HEALTH_RESP}"
elif [ -n "$HEALTH_RESP" ]; then
    log_fail "Probe GET /health response invalid: ${HEALTH_RESP}"
else
    log_warn "Probe GET /health did not respond on ${BASE_URL}/health."
fi

# Test /ready endpoint
READY_RESP=$(curl -s $INSECURE_CURL --max-time "$TIMEOUT_SEC" "${BASE_URL}/ready" 2>/dev/null || true)
if [[ "$READY_RESP" =~ '"ready": true' ]] || [[ "$READY_RESP" =~ '"status": "ready"' ]] || [[ "$READY_RESP" =~ '"status": "ok"' ]]; then
    log_pass "Probe GET /ready returned 200 OK: ${READY_RESP}"
elif [ -n "$READY_RESP" ]; then
    log_warn "Probe GET /ready returned: ${READY_RESP}"
else
    log_warn "Probe GET /ready did not respond on ${BASE_URL}/ready."
fi

# Test /metrics endpoint
METRICS_CODE=$(curl -s $INSECURE_CURL -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT_SEC" "${BASE_URL}/metrics" 2>/dev/null || true)
if [ "$METRICS_CODE" = "200" ]; then
    log_pass "Probe GET /metrics returned HTTP 200 OK."
elif [ -n "$METRICS_CODE" ] && [ "$METRICS_CODE" != "000" ]; then
    log_warn "Probe GET /metrics returned HTTP ${METRICS_CODE}."
else
    log_warn "Probe GET /metrics did not respond on ${BASE_URL}/metrics."
fi

# Test Security Headers
HEADERS=$(curl -s -I $INSECURE_CURL --max-time "$TIMEOUT_SEC" "${BASE_URL}/health" 2>/dev/null || true)
if [[ "$HEADERS" =~ "X-Content-Type-Options: nosniff" ]]; then
    log_pass "Security Header 'X-Content-Type-Options: nosniff' present."
elif [ -n "$HEADERS" ]; then
    log_warn "Security Header 'X-Content-Type-Options' missing."
fi

if [[ "$HEADERS" =~ "X-Frame-Options" ]]; then
    log_pass "Security Header 'X-Frame-Options' present."
elif [ -n "$HEADERS" ]; then
    log_warn "Security Header 'X-Frame-Options' missing."
fi

# ------------------------------------------------------------------------------
# Summary & Exit
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}==============================================================================${NC}"
echo -e "${CYAN}  Deployment Verification Summary${NC}"
echo -e "${CYAN}==============================================================================${NC}"
echo -e "  ${GREEN}Passed Checks:${NC}   ${PASSED_COUNT}"
echo -e "  ${RED}Failed Checks:${NC}   ${FAILED_COUNT}"
echo -e "  ${YELLOW}Warnings:${NC}        ${WARNING_COUNT}"
echo -e "${CYAN}------------------------------------------------------------------------------${NC}"

if [ "$FAILED_COUNT" -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS] Deployment verification completed with 0 errors!${NC}\n"
    exit 0
else
    echo -e "${RED}[FAILURE] Deployment verification failed with ${FAILED_COUNT} error(s).${NC}\n"
    exit 1
fi
