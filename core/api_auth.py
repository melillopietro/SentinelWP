"""
SentinelWP - REST API Authentication & Scoped Authorization
Validates bearer API keys (swp_live_...) using SHA-256 hashes against tenant boundaries.
"""
import hashlib
import os
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Optional
from flask import request, jsonify, g, session
from core.models import APIKey
from core.auth.session_roles import get_session_role


def generate_api_key(
    name: str,
    tenant_id: str,
    scopes: list[str],
    expires_at: Optional[str] = None,
    expires_in_days: Optional[int] = None,
) -> tuple[APIKey, str]:
    """
    Generates a secure random API key.
    Returns (APIKey_record_with_hash, raw_secret_token_string).
    The raw token is displayed ONCE to the user and never stored.
    """
    token_suffix = secrets.token_hex(24)
    raw_token = f"swp_live_{token_suffix}"
    key_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    now_iso = datetime.now(timezone.utc).isoformat()
    if expires_in_days is not None and not expires_at:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()

    api_key = APIKey(
        tenant_id=tenant_id,
        name=name,
        key_prefix=raw_token[:12],
        key_hash=key_hash,
        scopes=scopes or ["findings:read"],
        expires_at=expires_at,
        created_at=now_iso,
    )
    return api_key, raw_token


def verify_api_key(raw_token: str) -> Optional[APIKey]:
    """Hashes the provided token and queries active API keys."""
    if not raw_token or not raw_token.startswith("swp_live_"):
        return None
    token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

    from core.repository import get_api_key_by_hash
    api_key = get_api_key_by_hash(token_hash)
    if not api_key:
        return None

    if api_key.revoked_at:
        return None

    if api_key.expires_at:
        try:
            exp_dt = datetime.fromisoformat(api_key.expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                return None
        except Exception:
            return None

    return api_key


def require_scope(*required_scopes: str):
    """
    Decorator for REST API endpoints.
    Allows authentication via API Key (Bearer / X-API-Key) or existing logged-in session.
    Verifies that the caller has sufficient permissions/scopes.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # 1. Try API Key Header
            auth_header = request.headers.get("Authorization", "")
            raw_token = None
            if auth_header.startswith("Bearer "):
                raw_token = auth_header[7:].strip()
            elif "X-API-Key" in request.headers:
                raw_token = request.headers.get("X-API-Key", "").strip()

            if raw_token:
                api_key = verify_api_key(raw_token)
                if not api_key:
                    return jsonify({"error": "Unauthorized", "detail": "Invalid, revoked, or expired API key"}), 401

                # Check scopes
                key_scopes = set(api_key.scopes or [])
                if "admin" not in key_scopes and not set(required_scopes).issubset(key_scopes):
                    return jsonify({"error": "Forbidden", "detail": f"Missing required scopes: {list(required_scopes)}"}), 403

                # Set tenant context
                g.api_key = api_key
                g.tenant_id = api_key.tenant_id
                g.user_id = f"apikey:{api_key.id}"
                g.auth_mode = "api_key"
                return f(*args, **kwargs)

            # 2. Try Web Session (role from session['role'], never from request body)
            user_id = session.get("user_id")
            if user_id:
                user_role = get_session_role("viewer")
                session_tenant = session.get("tenant_id", "default-tenant")
                g.tenant_id = session_tenant
                g.user_id = user_id
                g.role = user_role
                g.auth_mode = "session"

                # Admin has all scopes
                if user_role == "admin":
                    return f(*args, **kwargs)

                # Analyst has read and write scopes, but not admin
                if user_role == "analyst":
                    disallowed = {"admin", "tenant:write"}
                    if any(req in disallowed for req in required_scopes):
                        return jsonify({"error": "Forbidden", "detail": "Admin role required"}), 403
                    return f(*args, **kwargs)

                # Viewer only has read scopes
                if user_role == "viewer":
                    write_scopes = {s for s in required_scopes if "write" in s or "run" in s or "admin" in s}
                    if write_scopes:
                        return jsonify({"error": "Forbidden", "detail": f"Write scopes not permitted for viewer: {list(write_scopes)}"}), 403
                    return f(*args, **kwargs)

                return jsonify({"error": "Forbidden", "detail": "Unknown or unsupported session role"}), 403

            return jsonify({"error": "Unauthorized", "detail": "Authentication credentials required (Bearer token or session)"}), 401
        return wrapper
    return decorator
