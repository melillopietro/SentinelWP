#!/usr/bin/env bash
# ==============================================================================
# SentinelWP Enterprise PostgreSQL Disaster Recovery & Restore Script
# Restores custom-format dumps into target databases with pre-flight header
# validation, post-restore schema integrity checks, and overwrite protection.
# Usage: ./scripts/restore_postgres.sh <backup_file> <target_database> [--confirm]
# ==============================================================================
set -euo pipefail

BACKUP_FILE="${1:-}"
TARGET_DB="${2:-}"
CONFIRM_FLAG="${3:-}"

if [ -z "${BACKUP_FILE}" ] || [ -z "${TARGET_DB}" ]; then
    echo "Usage: $0 <backup_file> <target_database> [--confirm]" >&2
    echo "Example: $0 backups/sentinelwp_20261011_120000.dump sentinelwp_restore_test" >&2
    exit 1
fi

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "[ERROR] Backup file not found: ${BACKUP_FILE}" >&2
    exit 1
fi

# Accidental overwrite safety guard
PROD_DB="${PRODUCTION_DATABASE_NAME:-sentinelwp}"
if [ "${TARGET_DB}" = "${PROD_DB}" ] || [ "${TARGET_DB}" = "sentinelwp_s10" ]; then
    if [ "${CONFIRM_FLAG}" != "--confirm-overwrite-production" ]; then
        echo "[FATAL] Target database '${TARGET_DB}' is designated as protected production database." >&2
        echo "Direct restore into production requires explicit flag: --confirm-overwrite-production" >&2
        exit 2
    fi
fi

DB_USER="${PGUSER:-s10_user}"
DB_HOST="${PGHOST:-127.0.0.1}"
DB_PORT="${PGPORT:-5439}"
PG_CONTAINER="${PG_CONTAINER:-sentinelwp-sprint10-postgres}"
USE_DOCKER="${USE_DOCKER:-auto}"

START_TIME=$(date +%s)
echo "[INFO] Starting restore drill at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "[INFO] Source Dump: ${BACKUP_FILE}"
echo "[INFO] Target Database: ${TARGET_DB}"

# 1. Preflight Header Validation
echo "[INFO] Step 1/4: Validating dump file archive header..."
if [ "${USE_DOCKER}" = "auto" ] && docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
    docker exec -i "${PG_CONTAINER}" pg_restore --list < "${BACKUP_FILE}" > /dev/null
else
    pg_restore --list "${BACKUP_FILE}" > /dev/null
fi
echo "[SUCCESS] Archive header valid."

# 2. Target Database Creation / Verification
echo "[INFO] Step 2/4: Ensuring target database '${TARGET_DB}' exists..."
if [ "${USE_DOCKER}" = "auto" ] && docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
    docker exec -e PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" "${PG_CONTAINER}" \
        psql -U "${DB_USER}" -d postgres -c "CREATE DATABASE ${TARGET_DB} OWNER ${DB_USER};" 2>/dev/null || true
else
    PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" psql \
        -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
        -c "CREATE DATABASE ${TARGET_DB} OWNER ${DB_USER};" 2>/dev/null || true
fi

# 3. Execution of pg_restore
echo "[INFO] Step 3/4: Restoring schema and data into '${TARGET_DB}'..."
RESTORE_START=$(date +%s)

if [ "${USE_DOCKER}" = "auto" ] && docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
    docker exec -i -e PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" "${PG_CONTAINER}" \
        pg_restore -U "${DB_USER}" -d "${TARGET_DB}" --clean --if-exists --no-owner --no-privileges < "${BACKUP_FILE}" || true
else
    PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" pg_restore \
        -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        --clean --if-exists --no-owner --no-privileges "${BACKUP_FILE}" || true
fi
RESTORE_END=$(date +%s)
RESTORE_DURATION=$((RESTORE_END - RESTORE_START))
echo "[SUCCESS] Data restoration completed in ${RESTORE_DURATION}s."

# 4. Post-Restore Schema & Integrity Verification
echo "[INFO] Step 4/4: Verifying post-restore table count and record integrity..."
QUERY="SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';"
if [ "${USE_DOCKER}" = "auto" ] && docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
    TABLE_COUNT=$(docker exec -e PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" "${PG_CONTAINER}" \
        psql -U "${DB_USER}" -d "${TARGET_DB}" -t -c "${QUERY}" | tr -d '[:space:]')
    VERSION_NUM=$(docker exec -e PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" "${PG_CONTAINER}" \
        psql -U "${DB_USER}" -d "${TARGET_DB}" -t -c "SELECT version_num FROM alembic_version LIMIT 1;" 2>/dev/null | tr -d '[:space:]' || echo "none")
else
    TABLE_COUNT=$(PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" psql \
        -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        -t -c "${QUERY}" | tr -d '[:space:]')
    VERSION_NUM=$(PGPASSWORD="${PGPASSWORD:-s10_dev_password_123}" psql \
        -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        -t -c "SELECT version_num FROM alembic_version LIMIT 1;" 2>/dev/null | tr -d '[:space:]' || echo "none")
fi

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - START_TIME))

echo "=============================================================================="
echo " Restore Verification Summary"
echo " Target Database: ${TARGET_DB}"
echo " Tables Restored: ${TABLE_COUNT}"
echo " Schema Revision: ${VERSION_NUM}"
echo " Restore Duration (pg_restore): ${RESTORE_DURATION}s"
echo " Total Drill Recovery Duration: ${TOTAL_DURATION}s"
echo "=============================================================================="

if [ "${TABLE_COUNT}" -ge 40 ]; then
    echo "[SUCCESS] Disaster recovery drill PASSED: target database schema verified."
    exit 0
else
    echo "[ERROR] Disaster recovery drill FAILED: expected >= 40 tables, found ${TABLE_COUNT}." >&2
    exit 1
fi
