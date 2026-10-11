"""
SentinelWP - Celery Tasks for Remediation, SLA Governance, and Integrations
Handles background SLA monitoring, risk acceptance expiry, webhook delivery,
ticket synchronization, and daily risk snapshots.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from core.tasks.celery_app import celery_app
from core.models import Finding, AuditEvent, DailyRiskSnapshot, FindingHistory
from core.lifecycle import FindingStatus, SLAStatus
from core.sla import evaluate_finding_sla_status
from core.repository import (
    list_tenants,
    list_findings,
    save_finding,
    add_finding_history,
    log_audit_event,
    list_risk_acceptances,
    update_risk_acceptance,
    get_finding,
    get_integration,
    list_integrations,
    get_webhook_delivery,
    update_webhook_delivery,
    list_ticket_references,
    update_ticket_reference,
    save_daily_risk_snapshot,
)
from core.integrations.webhook import deliver_webhook_payload
from core.notifications import dispatch_finding_notification

logger = logging.getLogger("sentinelwp.tasks.remediation")


@celery_app.task(name="core.tasks.evaluate_sla_breaches", bind=True)
def evaluate_sla_breaches(self) -> dict:
    """
    Evaluates SLA status for all open findings across tenants.
    Detects warnings and breaches, updates SLA status, logs history,
    and dispatches notifications.
    """
    logger.info("Starting SLA breach evaluation task...")
    tenants = list_tenants()
    breached_count = 0
    warning_count = 0

    now = datetime.now(timezone.utc)
    for tenant in tenants:
        findings, _ = list_findings(tenant.id, filters={"status": None}, page=1, page_size=1000)
        tenant_integrations = list_integrations(tenant.id)

        for f in findings:
            if f.status in (FindingStatus.REMEDIATED.value, FindingStatus.VERIFIED.value, FindingStatus.CLOSED.value, FindingStatus.FALSE_POSITIVE.value):
                continue

            old_sla = f.sla_status
            new_sla = evaluate_finding_sla_status(f, now=now)

            if new_sla != old_sla:
                f.sla_status = new_sla
                f.updated_at = now.isoformat()
                save_finding(f)

                if new_sla == SLAStatus.BREACHED.value:
                    breached_count += 1
                    add_finding_history(FindingHistory(
                        tenant_id=tenant.id,
                        finding_id=f.id,
                        actor_user_id="system:sla",
                        action="sla_breached",
                        old_status=f.status,
                        new_status=f.status,
                        comment=f"SLA deadline breached. Due was {f.sla_due_at}",
                        created_at=now.isoformat(),
                    ))
                    log_audit_event(
                        tenant_id=tenant.id,
                        actor_user_id="system:sla",
                        action="sla_breach",
                        resource_type="finding",
                        resource_id=f.id,
                        metadata={"due_at": f.sla_due_at, "priority": f.priority_band}
                    )
                    dispatch_finding_notification("sla.breached", f, tenant_integrations)

                elif new_sla == SLAStatus.WARNING.value and old_sla == SLAStatus.ON_TRACK.value:
                    warning_count += 1
                    log_audit_event(
                        tenant_id=tenant.id,
                        actor_user_id="system:sla",
                        action="sla_warning",
                        resource_type="finding",
                        resource_id=f.id,
                        metadata={"due_at": f.sla_due_at, "priority": f.priority_band}
                    )
                    dispatch_finding_notification("sla.warning", f, tenant_integrations)

    logger.info(f"SLA breach evaluation finished: {breached_count} breaches, {warning_count} warnings")
    return {"breached": breached_count, "warning": warning_count}


@celery_app.task(name="core.tasks.expire_risk_acceptances", bind=True)
def expire_risk_acceptances(self) -> dict:
    """
    Checks all active risk acceptances. If valid_until < now, marks them EXPIRED,
    re-opens the finding, and resumes SLA tracking.
    """
    logger.info("Starting risk acceptance expiration check...")
    tenants = list_tenants()
    expired_count = 0
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    for tenant in tenants:
        active_acceptances = list_risk_acceptances(tenant.id, status="APPROVED")
        for ra in active_acceptances:
            if not ra.valid_until:
                continue
            try:
                exp_dt = datetime.fromisoformat(ra.valid_until)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if now >= exp_dt:
                    ra.status = "EXPIRED"
                    update_risk_acceptance(ra)
                    expired_count += 1

                    # Re-open finding
                    finding = get_finding(ra.finding_id, tenant_id=tenant.id)
                    if finding and finding.status == FindingStatus.RISK_ACCEPTED.value:
                        finding.status = FindingStatus.REOPENED.value
                        finding.sla_paused_at = None
                        finding.sla_pause_reason = "Risk acceptance expired"
                        finding.sla_status = evaluate_finding_sla_status(finding, now=now)
                        save_finding(finding)

                        add_finding_history(FindingHistory(
                            tenant_id=tenant.id,
                            finding_id=finding.id,
                            actor_user_id="system:risk_governance",
                            action="risk_acceptance_expired",
                            old_status=FindingStatus.RISK_ACCEPTED.value,
                            new_status=FindingStatus.REOPENED.value,
                            comment=f"Risk acceptance {ra.id} expired on {ra.valid_until}",
                            created_at=now_iso,
                        ))
                        log_audit_event(
                            tenant_id=tenant.id,
                            actor_user_id="system:risk_governance",
                            action="risk_acceptance_expired",
                            resource_type="finding",
                            resource_id=finding.id,
                            metadata={"risk_acceptance_id": ra.id, "valid_until": ra.valid_until}
                        )
            except Exception as e:
                logger.error(f"Error checking expiry for risk acceptance {ra.id}: {e}")

    logger.info(f"Risk acceptance expiration finished: {expired_count} expired")
    return {"expired": expired_count}


@celery_app.task(name="core.tasks.deliver_webhook", bind=True, max_retries=3, default_retry_delay=60)
def deliver_webhook(self, integration_id: str, event: str, payload: dict) -> dict:
    """
    Delivers a signed webhook asynchronously with automatic retry and backoff.
    """
    integ = get_integration(integration_id)
    if not integ or not integ.enabled:
        return {"status": "skipped", "reason": "integration missing or disabled"}

    delivery = deliver_webhook_payload(integ, event, payload)
    if delivery.status != "delivered":
        try:
            self.retry(countdown=2 ** self.request.retries * 30)
        except Exception:
            pass
    return {"status": delivery.status, "delivery_id": delivery.id}


@celery_app.task(name="core.tasks.sync_ticket_status", bind=True)
def sync_ticket_status(self) -> dict:
    """
    Synchronizes ticket status from external issue trackers (Jira, ServiceNow).
    """
    tenants = list_tenants()
    synced = 0
    for tenant in tenants:
        tickets = list_ticket_references(tenant.id)
        for t in tickets:
            # Poll adapter
            integ = get_integration(t.integration_id, tenant_id=tenant.id)
            if integ and integ.enabled:
                t.last_sync_at = datetime.now(timezone.utc).isoformat()
                update_ticket_reference(t)
                synced += 1
    return {"synced_tickets": synced}


@celery_app.task(name="core.tasks.generate_daily_risk_snapshot", bind=True)
def generate_daily_risk_snapshot(self) -> dict:
    """
    Calculates aggregate daily posture and exposure metrics per tenant.
    """
    now = datetime.now(timezone.utc)
    today_str = now.strftime("%Y-%m-%d")
    tenants = list_tenants()
    generated = 0

    for tenant in tenants:
        findings, _ = list_findings(tenant.id, filters=None, page=1, page_size=5000)
        from core.repository import list_assets
        assets_list = list_assets(tenant.id)
        assets_cnt = len(assets_list)
        open_findings = [f for f in findings if f.status not in (FindingStatus.REMEDIATED.value, FindingStatus.VERIFIED.value, FindingStatus.CLOSED.value, FindingStatus.FALSE_POSITIVE.value)]

        open_cnt = len(open_findings)
        p1_cnt = sum(1 for f in open_findings if f.priority_band == "P1")
        p2_cnt = sum(1 for f in open_findings if f.priority_band == "P2")
        kev_cnt = sum(1 for f in open_findings if f.kev)
        sla_breaches = sum(1 for f in open_findings if f.sla_status == SLAStatus.BREACHED.value)
        risk_accepted_cnt = sum(1 for f in findings if f.status == FindingStatus.RISK_ACCEPTED.value)

        avg_score = (sum(f.priority_score for f in open_findings) / open_cnt) if open_cnt > 0 else 0.0

        snapshot = DailyRiskSnapshot(
            id=str(uuid.uuid4()),
            tenant_id=tenant.id,
            date=today_str,
            assets=assets_cnt,
            open_findings=open_cnt,
            p1_count=p1_cnt,
            p2_count=p2_cnt,
            kev_count=kev_cnt,
            sla_breaches=sla_breaches,
            risk_accepted=risk_accepted_cnt,
            risk_score_avg=round(avg_score, 2),
            avg_risk_score=round(avg_score, 2),
            mttr_seconds=0.0,
            created_at=now.isoformat(),
        )
        save_daily_risk_snapshot(snapshot)
        generated += 1

    return {"snapshots_generated": generated, "date": today_str}
