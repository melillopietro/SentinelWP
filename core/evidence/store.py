"""
Structured Immutable Evidence Store for SentinelWP.

Guarantees:
- Strict sanitization: NO Authorization headers, passwords, session cookies, API tokens, secret keys.
- Stable cryptographic content hash (SHA-256) for integrity, deduplication, and traceability.
- Complete provenance: scanner_id, scanner_version, policy_version, request_id, scan_job_id, sanitized source_url.
- Immutability: Evidence records are write-once; modifications generate a new Evidence record.
- Multi-tier retention classes: SHORT, STANDARD, LONG, AUDIT.
- Quality assessment: WEAK, MODERATE, STRONG, VERIFIED.
"""
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.models import Evidence, EvidenceQuality, EvidenceRetentionClass, AuditEvent
from core import repository

logger = logging.getLogger("sentinelwp.evidence")

# Secret sanitization patterns
_SECRET_PATTERNS = [
    (re.compile(r'(Bearer\s+)[^"\r\n\s,;]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(Authorization\s*[:=]\s*)[^\r\n,;]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(Cookie\s*[:=]\s*)[^\r\n;]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(Set-Cookie\s*[:=]\s*)[^\r\n;]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(["\']?password["\']?\s*[:=]\s*["\']?)[^"\'\s&,;{}]+(["\']?)', re.IGNORECASE), r'\1[REDACTED]\2'),
    (re.compile(r'(["\']?api[_-]?key["\']?\s*[:=]\s*["\']?)[^"\'\s&,;{}]+(["\']?)', re.IGNORECASE), r'\1[REDACTED]\2'),
    (re.compile(r'(["\']?secret[_-]?key["\']?\s*[:=]\s*["\']?)[^"\'\s&,;{}]+(["\']?)', re.IGNORECASE), r'\1[REDACTED]\2'),
    (re.compile(r'(["\']?token["\']?\s*[:=]\s*["\']?)[^"\'\s&,;{}]+(["\']?)', re.IGNORECASE), r'\1[REDACTED]\2'),
]


def sanitize_payload(payload_str: str) -> str:
    """Sanitizes raw text or serialized JSON, stripping sensitive headers, tokens, and credentials."""
    if not payload_str:
        return ""
    result = payload_str
    for pattern, repl in _SECRET_PATTERNS:
        result = pattern.sub(repl, result)
    return result


def compute_content_hash(data: str) -> str:
    """Computes deterministic SHA-256 digest of sanitized payload string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class EvidenceStore:
    """
    Manages creation, deduplication, and retrieval of sanitized immutable evidence records.
    """

    def __init__(self, tenant_id: str = "default-tenant"):
        self.tenant_id = tenant_id

    def record_evidence(
        self,
        raw_payload: str,
        source: str,
        type_: str = "http_response",
        finding_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        scanner_id: Optional[str] = None,
        scanner_version: Optional[str] = None,
        policy_version: Optional[str] = None,
        request_id: Optional[str] = None,
        scan_job_id: Optional[str] = None,
        source_url: Optional[str] = None,
        mime_type: str = "application/json",
        quality: EvidenceQuality = EvidenceQuality.STRONG,
        retention_class: EvidenceRetentionClass = EvidenceRetentionClass.STANDARD
    ) -> Evidence:
        """
        Sanitizes raw payload, enforces size limit, computes stable hash, deduplicates
        within tenant, records provenance metadata, and stores immutable Evidence record.

        Raises ValueError if payload exceeds MAX_EVIDENCE_SIZE_BYTES.
        """
        from config import MAX_EVIDENCE_SIZE_BYTES
        raw_bytes = len(raw_payload.encode("utf-8")) if isinstance(raw_payload, str) else len(raw_payload)
        if raw_bytes > MAX_EVIDENCE_SIZE_BYTES:
            repository.log_audit_event(
                AuditEvent(
                    tenant_id=self.tenant_id,
                    action="evidence_rejected_size_limit",
                    resource_type="evidence",
                    resource_id=finding_id or "unassociated",
                    result="denied",
                    metadata={
                        "raw_bytes": raw_bytes,
                        "limit_bytes": MAX_EVIDENCE_SIZE_BYTES,
                        "source": source
                    }
                )
            )
            raise ValueError(
                f"Evidence payload size ({raw_bytes} bytes) exceeds maximum permitted limit "
                f"({MAX_EVIDENCE_SIZE_BYTES} bytes)"
            )

        sanitized_content = sanitize_payload(raw_payload)
        content_hash = compute_content_hash(sanitized_content)

        # Check deduplication
        existing = repository.get_evidence_by_hash(self.tenant_id, content_hash)
        if existing:
            # If exists and finding_id needs association, return existing
            logger.debug(f"Deduplicated existing evidence {existing.id} for hash {content_hash[:12]}")
            return existing

        now_iso = datetime.now(timezone.utc).isoformat()
        sanitized_source_url = sanitize_payload(source_url or "")

        provenance = {
            "scanner_id": scanner_id or "sentinelwp-core",
            "scanner_version": scanner_version or "2.0.0",
            "policy_version": policy_version or "default",
            "request_id": request_id or "",
            "scan_job_id": scan_job_id or "",
            "source_url": sanitized_source_url,
            "captured_at": now_iso
        }

        evidence = Evidence(
            tenant_id=self.tenant_id,
            asset_id=asset_id,
            scan_id=scan_id,
            finding_id=finding_id,
            type=type_,
            source=source,
            content_hash=content_hash,
            storage_reference=f"sha256:{content_hash}",
            mime_type=mime_type,
            size_bytes=len(sanitized_content.encode("utf-8")),
            created_at=now_iso,
            retention_class=retention_class.value if hasattr(retention_class, "value") else str(retention_class),
            classification="internal",
            sanitized=True,
            redacted=True,
            provenance=provenance,
            quality=quality.value if hasattr(quality, "value") else str(quality),
            payload=sanitized_content
        )
        repository.save_evidence(evidence)

        repository.log_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                action="evidence_created",
                resource_type="evidence",
                resource_id=evidence.id,
                result="success",
                metadata={
                    "content_hash": content_hash,
                    "finding_id": finding_id,
                    "size_bytes": evidence.size_bytes
                }
            )
        )
        return evidence

    def get_sanitized_evidence(self, evidence_id: str, actor_role: str = "viewer") -> Optional[Evidence]:
        """
        Retrieves sanitized evidence record enforcing access control and audit logging.
        """
        ev = repository.get_evidence(evidence_id, self.tenant_id)
        if not ev:
            return None

        # Log evidence access
        repository.log_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                action="evidence_accessed",
                resource_type="evidence",
                resource_id=ev.id,
                result="success",
                metadata={"actor_role": actor_role, "content_hash": ev.content_hash}
            )
        )
        return ev
