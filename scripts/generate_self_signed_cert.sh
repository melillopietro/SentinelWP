#!/usr/bin/env bash
# Generates local self-signed TLS certificates for development/testing
# Enterprise deployments should replace these with corporate CA or ACME certs.
set -euo pipefail

CERT_DIR="${1:-nginx/certs}"
mkdir -p "${CERT_DIR}"

if [ -f "${CERT_DIR}/tls.crt" ] && [ -f "${CERT_DIR}/tls.key" ]; then
    echo "[INFO] TLS certificates already exist in ${CERT_DIR}."
    exit 0
fi

echo "[INFO] Generating self-signed TLS certificate in ${CERT_DIR}..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${CERT_DIR}/tls.key" \
    -out "${CERT_DIR}/tls.crt" \
    -subj "/CN=sentinelwp.local/O=SentinelWP Enterprise/C=US"

chmod 600 "${CERT_DIR}/tls.key"
chmod 644 "${CERT_DIR}/tls.crt"
echo "[SUCCESS] Generated self-signed TLS certificate."
