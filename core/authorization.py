"""
Centralized Enterprise Authorization and Tenant Enforcement Service for SentinelWP.
Enforces multi-tenant isolation, role-based access control (RBAC),
and object-level authorization (IDOR prevention).
"""
import functools
from datetime import datetime, timezone
from typing import Optional, Any
from flask import session, redirect, url_for, abort, flash

from core.models import UserRole, Asset, ScanResult, Finding, ScheduledScan, ScanAuthorization
from core import repository
from core.canonical import canonicalize_url


# --- Role & Tenant Context Helpers ---

def get_current_user_id() -> Optional[str]:
    return session.get("user_id")


def get_current_username() -> str:
    return session.get("username", "anonymous")


def get_current_role() -> str:
    return session.get("role", "viewer")


def get_current_tenant_id() -> str:
    """Return active tenant ID from session, defaulting to 'default-tenant'."""
    return session.get("tenant_id", "default-tenant")


# --- Object-Level Access Control (IDOR Prevention) ---

def check_tenant_access(resource_tenant_id: Optional[str], user_tenant_id: Optional[str] = None) -> bool:
    """
    Verify whether the current tenant matches the resource's tenant.
    Returns True if matches, False otherwise.
    """
    if not resource_tenant_id:
        return False
    active_tenant = user_tenant_id or get_current_tenant_id()
    return resource_tenant_id == active_tenant


def enforce_tenant_object(resource: Any, user_tenant_id: Optional[str] = None):
    """
    Enforce tenant-level boundary on an entity.
    If resource is None or belongs to a different tenant, aborts with HTTP 404 (Not Found)
    to prevent cross-tenant resource enumeration / existence disclosure.
    """
    if resource is None:
        abort(404)
    
    res_tenant = getattr(resource, "tenant_id", None)
    if not res_tenant:
        abort(404)

    active_tenant = user_tenant_id or get_current_tenant_id()
    if res_tenant != active_tenant:
        abort(404)


# --- Route Decorators ---

def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def analyst_required(f):
    """Requires at least Analyst or Admin role (blocks Viewer from mutations)."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "analyst"):
            abort(403)
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """Requires Admin role."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# --- Scan Authorization Guardrail ---

def verify_scan_authorization(
    tenant_id: str,
    target_url: str = "",
    scan_mode: str = "safe-active",
    profile: Optional[str] = None,
) -> tuple[bool, str, Optional[Asset]]:
    """
    Enforce Scan Authorization guardrails.
    - If scan_mode == 'safe-active' (or 'safe_active'):
      requires an active, unexpired ScanAuthorization record for the asset.
      Fail-closed if missing, revoked, or expired.
    - If scan_mode == 'passive':
      allowed for all valid assets/targets.
    - If scan_mode == 'full':
      blocked (deprecated and removed).
    
    Returns (is_authorized, reason_message, asset).
    """
    if profile:
        scan_mode = profile

    if tenant_id.startswith("http://") or tenant_id.startswith("https://"):
        tenant_id, target_url = target_url, tenant_id

    norm_mode = scan_mode.replace("-", "_").lower()

    if norm_mode == "offensive":
        return False, "Offensive scan mode is not supported.", None

    canonical_url, _ = canonicalize_url(target_url)
    if not canonical_url:
        return False, "Invalid target URL format.", None

    # Retrieve or ensure asset exists within this tenant
    asset = repository.get_asset_by_url(tenant_id, canonical_url)
    if not asset:
        asset = repository.ensure_asset_for_target(tenant_id, target_url)

    if asset.status == "disabled":
        return False, f"Asset {asset.hostname} is disabled.", asset

    # Passive scans are permitted for any active tenant asset
    if norm_mode == "passive":
        return True, "Passive scan authorized.", asset

    if norm_mode in ("safe_active", "full"):
        # Check active scan authorizations
        auth = repository.get_active_authorization(asset.id, tenant_id=tenant_id)
        mode_label = "Full" if norm_mode == "full" else "Safe Active"
        if not auth:
            return False, f"{mode_label} scan blocked: No active authorization found for asset '{asset.hostname}'. Please register a valid authorization window.", asset
        
        # Verify valid window
        now_iso = datetime.now(timezone.utc).isoformat()
        if auth.status != "active":
            return False, f"{mode_label} scan blocked: Authorization for '{asset.hostname}' is {auth.status}.", asset
        if auth.valid_until and auth.valid_until < now_iso:
            return False, f"{mode_label} scan blocked: Authorization for '{asset.hostname}' expired at {auth.valid_until}.", asset
        if auth.valid_from and auth.valid_from > now_iso:
            return False, f"{mode_label} scan blocked: Authorization for '{asset.hostname}' is not valid until {auth.valid_from}.", asset

        # Check allowed profiles
        allowed_profiles = [p.strip().replace("-", "_").lower() for p in (auth.allowed_profiles or "").split(",") if p.strip()]
        if norm_mode not in allowed_profiles and "safe_active" not in allowed_profiles and "full" not in allowed_profiles and "*" not in allowed_profiles:
            return False, f"{mode_label} scan blocked: Profile '{norm_mode}' is not permitted in authorization for '{asset.hostname}'.", asset

        return True, f"{mode_label} scan authorized.", asset

    # Default reject unknown modes
    return False, f"Unknown scan mode '{scan_mode}'.", asset
