# Evidence Model & Provenance Architecture

## Overview
SentinelWP implements an immutable, cryptographically verifiable Evidence Store that records raw scanner observations, HTTP transactions, and vulnerability artifacts while enforcing strict redaction and privacy controls.

## Evidence Model

### Core Schema
- `id`: Unique identifier (UUIDv4).
- `tenant_id`: Multi-tenant ownership.
- `finding_id`: Linked vulnerability finding (optional).
- `asset_id`: Linked target asset.
- `scan_id`: Associated scan result.
- `content_hash`: SHA-256 deterministic hash of sanitized payload.
- `storage_reference`: Pointer `sha256:<hash>` for content-addressable storage.
- `retention_class`: `STANDARD` (90 days), `LONG_TERM` (365 days), `PERMANENT` (regulatory audit).
- `quality`: Quality assessment (`STRONG`, `MEDIUM`, `WEAK`).
- `provenance`: Contextual metadata capturing scanner ID, version, policy version, request ID, source URL, and capture timestamp.
- `payload`: Redacted, sanitized raw response body or evidence record.

## Secret Redaction & Sanitization
Before any evidence payload is hashed and persisted, it passes through the deterministic redaction pipeline:
1. `Authorization: Bearer <token>` headers -> `Authorization: Bearer [REDACTED]`
2. `Cookie` / `Set-Cookie` session identifiers -> `Cookie: [REDACTED]`
3. JSON / URL credentials matching `password`, `token`, `api_key`, `secret_key` -> `[REDACTED]`

## Cryptographic Deduplication & Immutability
- Deduplication is achieved by checking `content_hash` within the tenant before persisting new records.
- Evidence records are append-only. No UPDATE or in-place modification endpoints are exposed.
- All evidence retrievals and access requests are logged to the immutable `audit_events` ledger.
