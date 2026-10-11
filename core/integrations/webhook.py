"""
SentinelWP - Secure Webhook Dispatcher
Signs payloads with HMAC-SHA256 (X-Sentinel-Signature) and provides delivery tracking.
"""
import hashlib
import hmac
import json
import os
import time
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional, Any
from core.models import Integration, WebhookDelivery


def compute_webhook_signature(secret: str, payload_bytes: bytes) -> str:
    """Computes HMAC-SHA256 signature in format 'sha256=<hex>'."""
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def deliver_webhook_payload(
    integration: Integration,
    event: str,
    payload: dict,
    secret_token: Optional[str] = None,
    timeout_seconds: int = 10,
) -> WebhookDelivery:
    """
    Delivers a signed webhook payload to the destination URL.
    Generates WebhookDelivery record with status and delivery metadata.
    """
    secret = secret_token
    if not secret and integration.secret_reference:
        secret = os.environ.get(integration.secret_reference, "")
    if not secret:
        raise ValueError("Webhook secret must be provided either via secret_token or valid secret_reference")

    cfg = integration.config_reference or {}
    target_url = cfg.get("url")

    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_bytes = payload_json.encode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    signature = compute_webhook_signature(secret, payload_bytes)
    timestamp = str(int(time.time()))

    delivery_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    delivery = WebhookDelivery(
        id=delivery_id,
        tenant_id=integration.tenant_id,
        integration_id=integration.id,
        event=event,
        payload_hash=payload_hash,
        status="pending",
        attempt=1,
        created_at=now_iso,
    )

    if not target_url:
        delivery.status = "failed"
        delivery.last_error = "Missing destination URL in integration config"
        return delivery

    req = urllib.request.Request(target_url, data=payload_bytes, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "SentinelWP-Webhook/2.0")
    req.add_header("X-Sentinel-Event", event)
    req.add_header("X-Sentinel-Delivery", delivery_id)
    req.add_header("X-Sentinel-Timestamp", timestamp)
    req.add_header("X-Sentinel-Signature", signature)

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            if 200 <= resp.status < 300:
                delivery.status = "delivered"
            else:
                delivery.status = "failed"
                delivery.last_error = f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        delivery.status = "failed"
        delivery.last_error = f"HTTP {e.code}: {e.reason}"
    except Exception as exc:
        delivery.status = "failed"
        delivery.last_error = str(exc)

    return delivery
