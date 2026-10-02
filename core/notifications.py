"""
Notification & Alerting Dispatcher for SentinelWP.
Supports Email (SMTP) and HTTP Webhooks (Slack/Teams/Generic).
"""
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from typing import Optional
from core.models import ScanResult, Severity


def _send_email_notification(scan: ScanResult, critical_high_findings: list):
    """Send summary email via SMTP if configured in environment."""
    smtp_host = os.getenv("WSA_SMTP_HOST") or os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("WSA_SMTP_PORT") or os.getenv("SMTP_PORT") or "587")
    smtp_user = os.getenv("WSA_SMTP_USER") or os.getenv("SMTP_USER")
    smtp_pass = os.getenv("WSA_SMTP_PASS") or os.getenv("SMTP_PASS")
    recipient = os.getenv("WSA_ALERT_RECIPIENT") or os.getenv("ALERT_RECIPIENT")

    if not smtp_host or not recipient:
        return  # SMTP not configured

    subject = f"[SentinelWP Security Alert] High Risk Target: {scan.target_url} (Grade {scan.grade})"
    
    body = f"""SentinelWP Security Assessment Alert

Target: {scan.target_url}
Risk Score: {scan.score}/100 (Grade: {scan.grade})
Scan Mode: {scan.scan_mode}
Date: {scan.completed_at}

Critical & High Findings ({len(critical_high_findings)}):
"""
    for f in critical_high_findings:
        body += f"\n- [{f.severity.upper()}] {f.title}: {f.description[:120]}"

    body += "\n\nPlease review the full report in the SentinelWP Dashboard."

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user or "sentinelwp@wsa.local"
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception:
        pass


def _send_webhook_notification(scan: ScanResult, critical_high_findings: list):
    """Send webhook alert via HTTP POST if configured."""
    webhook_url = os.getenv("WSA_WEBHOOK_URL") or os.getenv("WEBHOOK_URL")
    if not webhook_url:
        return

    payload = {
        "text": f"🚨 *SentinelWP Security Alert* for <{scan.target_url}>\n"
                f"*Score*: {scan.score} | *Grade*: {scan.grade} | *Findings*: {len(scan.findings)}\n"
                f"*Critical/High Issues*: {len(critical_high_findings)}",
        "attachments": [
            {
                "color": "#dc2626" if scan.grade in ("E", "F") else "#f59e0b",
                "title": f.title,
                "text": f.description,
            } for f in critical_high_findings[:5]
        ]
    }

    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass


def dispatch_scan_notifications(scan: ScanResult):
    """
    Check if scan results warrant notifications and dispatch to active channels.
    """
    critical_high = [
        f for f in scan.findings
        if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) in ("critical", "high")
    ]

    # Send alerts if score >= 40 or if critical/high findings exist
    if (scan.score and scan.score >= 40.0) or len(critical_high) > 0:
        _send_email_notification(scan, critical_high)
        _send_webhook_notification(scan, critical_high)
