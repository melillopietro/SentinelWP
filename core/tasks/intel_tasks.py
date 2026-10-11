"""
Celery Vulnerability Intelligence Sync Tasks for SentinelWP.
Executed in dedicated 'intel' queue workers. Guarantees source isolation so
Wordfence failures never block CISA KEV or plugin metadata ingestion.
Updates persistent SLA freshness records and logs security audit events.
"""
import logging
from typing import Optional, Dict, Any

from core.tasks.celery_app import celery_app
from core.models import AuditEvent
from core.repository import (
    update_intel_sync_status,
    log_audit_event,
)
from core.vulnerability_intelligence.service import (
    sync_wordfence,
    sync_kev,
    sync_plugin_metadata,
)

logger = logging.getLogger("sentinelwp.tasks.intel")


@celery_app.task(
    name="core.tasks.intel_tasks.sync_vulnerability_intelligence_task",
    queue="intel",
)
def sync_vulnerability_intelligence_task(source: Optional[str] = None) -> Dict[str, Any]:
    """
    Synchronizes threat intelligence feeds with per-source isolation.
    """
    logger.info(f"Starting vulnerability intelligence sync task (target source: {source or 'ALL'})")

    log_audit_event(AuditEvent(
        tenant_id="default-tenant",
        actor_user_id="celery_beat",
        actor_username="scheduler",
        action="intel_sync_started",
        resource_type="threat_intel",
        resource_id=source or "all_sources",
        result="success",
        metadata={"target_source": source},
    ))

    results = {}

    # 1. Wordfence Intelligence Sync
    if source in (None, "wordfence"):
        try:
            update_intel_sync_status("wordfence", status="running")
            wf_res = sync_wordfence()
            if wf_res.get("status") == "success":
                inserted = wf_res.get("inserted", 0)
                update_intel_sync_status("wordfence", status="success", records_processed=inserted)
                results["wordfence"] = {"status": "success", "records": inserted}
            else:
                err = wf_res.get("error", "Unknown error")
                update_intel_sync_status("wordfence", status="failed", error_code="SYNC_ERROR", error_message=err)
                results["wordfence"] = {"status": "failed", "error": err}
        except Exception as exc:
            logger.exception(f"Isolated failure in Wordfence sync: {exc}")
            update_intel_sync_status("wordfence", status="failed", error_code="EXCEPTION", error_message=str(exc))
            results["wordfence"] = {"status": "failed", "error": str(exc)}

    # 2. CISA KEV Sync (ISOLATED: runs even if Wordfence fails)
    if source in (None, "cisa_kev"):
        try:
            update_intel_sync_status("cisa_kev", status="running")
            kev_res = sync_kev()
            if kev_res.get("status") == "success":
                inserted = kev_res.get("inserted", 0)
                update_intel_sync_status("cisa_kev", status="success", records_processed=inserted)
                results["cisa_kev"] = {"status": "success", "records": inserted}
            else:
                err = kev_res.get("error", "Unknown error")
                update_intel_sync_status("cisa_kev", status="failed", error_code="SYNC_ERROR", error_message=err)
                results["cisa_kev"] = {"status": "failed", "error": err}
        except Exception as exc:
            logger.exception(f"Isolated failure in CISA KEV sync: {exc}")
            update_intel_sync_status("cisa_kev", status="failed", error_code="EXCEPTION", error_message=str(exc))
            results["cisa_kev"] = {"status": "failed", "error": str(exc)}

    # Audit final state
    has_failures = any(r.get("status") == "failed" for r in results.values())
    log_audit_event(AuditEvent(
        tenant_id="default-tenant",
        actor_user_id="celery_beat",
        actor_username="scheduler",
        action="intel_sync_completed" if not has_failures else "intel_sync_failed",
        resource_type="threat_intel",
        resource_id=source or "all_sources",
        result="success" if not has_failures else "warning",
        metadata={"results": results},
    ))

    logger.info(f"Vulnerability intelligence sync finished: {results}")
    return results


@celery_app.task(
    name="core.tasks.intel_tasks.backfill_nvd_enrichment_task",
    queue="intel",
)
def backfill_nvd_enrichment_task(
    dry_run: bool = False,
    batch_size: int = 10,
    max_total: int = 500,
    offset: int = 0,
) -> Dict[str, Any]:
    """
    INTEL-OPEN-002: Backfill NVD CVSS scores for historical vulnerability records
    that are missing CVSS data.

    This is a one-time or periodic management operation — separate from the regular
    per-sync enrichment (which only processes up to 10/40 records per sync cycle).
    For deployments with thousands of records missing CVSS scores, this task allows
    controlled bulk enrichment with configurable batching.

    Args:
        dry_run:    If True, identify records needing enrichment without calling NVD.
        batch_size: Records per NVD API call batch (default 10; max safe without key).
        max_total:  Maximum records to process in this invocation (checkpoint support).
        offset:     Starting offset for cursor-based pagination (resume support).

    Idempotency:
        Only processes records with cvss_score IS NULL or = 0. Records that already
        have a CVSS score are never overwritten. Re-running the task is safe.

    Rate limit handling:
        Without NVD API key: 5 req/30s → 10 records per invocation default.
        With NVD_API_KEY: 50 req/30s → batch_size can be set up to 40-50.

    Returns dict with: total_candidates, enriched, skipped, errors, dry_run, next_offset.
    """
    logger.info(
        "NVD backfill task started: dry_run=%s batch_size=%d max_total=%d offset=%d",
        dry_run, batch_size, max_total, offset
    )

    try:
        from core.vulnerability_intelligence.nvd_client import enrich_cve, _get_nvd_api_key
    except ImportError:
        return {"status": "error", "reason": "NVD client module not available"}

    # Use the vulnerability intel repository (separate DB from main app DB)
    from core.vulnerability_intelligence import repository as vuln_repo

    api_key = _get_nvd_api_key()
    conn = vuln_repo._get_vuln_conn()

    # Query records missing CVSS (cursor-based for resume support)
    # The vuln intel schema uses the 'cve' column (not 'cve_id').
    try:
        candidates = conn.execute("""
            SELECT id, cve FROM vulnerability_records
            WHERE cve IS NOT NULL AND cve != ''
              AND (cvss_score IS NULL OR cvss_score = 0)
            ORDER BY id
            LIMIT ? OFFSET ?
        """, (max_total, offset)).fetchall()
    except Exception as exc:
        # Graceful degradation: if the DB/column doesn't exist, return cleanly
        logger.warning("NVD backfill: could not query vulnerability_records: %s", exc)
        return {"status": "error", "reason": str(exc)}

    total_candidates = len(candidates)
    enriched = 0
    skipped = 0
    errors = 0

    if dry_run:
        logger.info(
            "NVD backfill DRY RUN: found %d records needing enrichment at offset %d",
            total_candidates, offset
        )
        return {
            "status": "dry_run",
            "total_candidates": total_candidates,
            "enriched": 0,
            "skipped": 0,
            "errors": 0,
            "dry_run": True,
            "next_offset": offset + total_candidates if total_candidates == max_total else None,
        }

    for i, row in enumerate(candidates):
        record_id = row[0] if isinstance(row, (list, tuple)) else row["id"]
        cve_val = row[1] if isinstance(row, (list, tuple)) else row["cve"]
        if not cve_val or not str(cve_val).startswith("CVE-"):
            skipped += 1
            continue
        try:
            nvd_data = enrich_cve(cve_val)
            if nvd_data and nvd_data.get("cvss_score"):
                conn.execute("""
                    UPDATE vulnerability_records
                    SET cvss_score = ?, cvss_vector = ?
                    WHERE id = ? AND (cvss_score IS NULL OR cvss_score = 0)
                """, (
                    nvd_data.get("cvss_score"),
                    nvd_data.get("cvss_vector", ""),
                    record_id,
                ))
                conn.commit()
                enriched += 1
                logger.debug("NVD backfill: enriched %s (score=%s)", cve_val, nvd_data["cvss_score"])
            else:
                skipped += 1
                logger.debug("NVD backfill: no CVSS data for %s", cve_val)

            # Rate limit: sleep between requests to respect NVD limits
            import time
            sleep_secs = 0.7 if api_key else 6.5
            time.sleep(sleep_secs)

        except Exception as exc:
            errors += 1
            logger.warning("NVD backfill: failed for %s: %s", cve_val, exc)
            # Continue with next record — per-record errors are non-fatal

    next_offset = offset + total_candidates if total_candidates == max_total else None

    logger.info(
        "NVD backfill complete: total=%d enriched=%d skipped=%d errors=%d next_offset=%s",
        total_candidates, enriched, skipped, errors, next_offset
    )

    log_audit_event(AuditEvent(
        tenant_id="default-tenant",
        actor_user_id="celery_worker",
        actor_username="intel_backfill",
        action="nvd_backfill_completed",
        resource_type="vulnerability_intel",
        resource_id="nvd_backfill",
        result="success" if errors == 0 else "warning",
        metadata={
            "total_candidates": total_candidates,
            "enriched": enriched,
            "skipped": skipped,
            "errors": errors,
            "next_offset": next_offset,
        },
    ))

    return {
        "status": "success",
        "total_candidates": total_candidates,
        "enriched": enriched,
        "skipped": skipped,
        "errors": errors,
        "dry_run": False,
        "next_offset": next_offset,
    }
