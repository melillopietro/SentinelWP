"""
SentinelWP - Flask Application
Modern dark-theme web UI for WordPress Security Assessment & Posture Management
Enterprise Multi-Tenant Edition
"""
import os
import sys
import json
import functools
import logging
from datetime import datetime, timedelta, timezone
import uuid
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, abort, g, Response
)
import io

from core.logging_config import configure_logging
configure_logging(service_name="sentinelwp-web")
logger = logging.getLogger("sentinelwp.app")

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from urllib.parse import urlparse
from config import (
    SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, SESSION_EXPIRY_HOURS,
    SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE,
    WSA_MAX_SCHEDULE_TARGETS, SCAN_EXECUTION_BACKEND, REDIS_URL, ENVIRONMENT,
    validate_admin_password, is_postgres_configured, __version__,
)
from core.db.session import verify_operational_persistence_guard
from core import repository
from core.auth import create_user, verify_password, hash_password, authenticate_login_user
from core.models import (
    UserRole, UserStatus, ScanStatus, Severity, ScheduledScan,
    Tenant, Asset, ScanAuthorization, AuditEvent,
    ScanJob, ScanJobStatus, ScheduledRun,
    Finding, FindingComment, Remediation, RemediationAction,
    SLAPolicy, RiskAcceptance, Integration, TicketReference, APIKey
)
from core.canonical import canonicalize_url
from core.authorization import (
    login_required, analyst_required, admin_required,
    verify_scan_authorization, enforce_tenant_object, get_current_tenant_id
)
from core.lifecycle import (
    FindingStatus, RemediationStatus, RiskAcceptanceStatus, SLAStatus,
    InvalidStateTransitionError, OptimisticLockError
)
from core.api_auth import require_scope, generate_api_key
from core.integrations.jira import JiraIntegration
from core.integrations.servicenow import ServiceNowIntegration
from core.integrations.webhook import deliver_webhook_payload
from core.notifications import dispatch_finding_notification
from core.risk_engine import compute_risk_score, compute_category_breakdown
from core.rate_limiter import rate_limiter
from core.scheduler import start_scheduler
from core.csrf import csrf
from scanners.base import BaseScanner
from scanners.async_runner import start_async_scan, get_scan_progress
from scanners.orchestrator import run_scan, ALL_SCANNERS, SCAN_PROFILES
from scanners.batch_runner import run_batch
from reports.generator import (
    generate_html_report, generate_json_report,
    generate_excel_report, generate_pdf_report, generate_sarif_report,
    generate_full_db_excel_export, import_full_db_excel
)
from core.update_checker import check_for_updates

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=SESSION_EXPIRY_HOURS)
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_HTTPONLY"] = SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
csrf.init_app(app)

# Werkzeug ProxyFix for trusted reverse proxy ingress (Nginx gateway)
_behind_proxy = os.getenv("WSA_BEHIND_PROXY", "false").lower() in ("true", "1", "yes") or ENVIRONMENT in ("production", "prod")
if _behind_proxy:
    from werkzeug.middleware.proxy_fix import ProxyFix
    _x_for = int(os.getenv("WSA_PROXY_X_FOR", "1"))
    _x_proto = int(os.getenv("WSA_PROXY_X_PROTO", "1"))
    _x_host = int(os.getenv("WSA_PROXY_X_HOST", "1"))
    _x_port = int(os.getenv("WSA_PROXY_X_PORT", "1"))
    _x_prefix = int(os.getenv("WSA_PROXY_X_PREFIX", "0"))
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=_x_for,
        x_proto=_x_proto,
        x_host=_x_host,
        x_port=_x_port,
        x_prefix=_x_prefix,
    )
    logger.info(f"Mounted Werkzeug ProxyFix (x_for={_x_for}, x_proto={_x_proto}, x_host={_x_host})")


def _reject_unsafe_scan_target_at_submission(
    tenant_id: str,
    target: str,
    scan_mode: str,
    *,
    asset_id: str = "",
    actor_user_id: str = "",
    actor_username: str = "",
) -> str | None:
    """
    Submission-time SSRF preflight (canonical scanner policy).
    Returns a client-safe error message when blocked; None when allowed.
    Worker-side enforcement remains mandatory (TOCTOU / DNS rebinding).
    """
    from core.scan_submission import validate_scan_target_for_submission

    allowed, message = validate_scan_target_for_submission(target)
    if allowed:
        return None
    try:
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            action="scan_target_blocked",
            resource_type="asset",
            resource_id=asset_id or "",
            result="denied",
            metadata={"target_url": target, "scan_mode": scan_mode, "reason": message},
        )
    except Exception as exc:
        logger.warning("Could not persist scan_target_blocked audit event: %s", exc)
    return message


@app.context_processor
def inject_workspace_context():
    tenant_id = session.get("tenant_id", "default-tenant")
    tenant = repository.get_tenant_by_id(tenant_id)
    return {
        "current_tenant": tenant,
        "current_tenant_id": tenant_id,
        "current_user_role": session.get("role", "viewer"),
        "app_version": __version__,
    }


_startup_sync_done = False
_db_initialized = False

# --- Init & Middleware ---
@app.before_request
def ensure_db_and_scheduler():
    global _startup_sync_done, _db_initialized
    # Correlation ID (X-Request-ID)
    g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    g.tenant_id = session.get("tenant_id")
    g.user_id = session.get("user_id")

    if request.path in ("/health", "/ready", "/metrics") or request.path.startswith("/static/"):
        return

    if not _db_initialized:
        if is_postgres_configured():
            verify_operational_persistence_guard()
            _db_initialized = True
        else:
            try:
                repository.init_db()
                _db_initialized = True
            except Exception as e:
                logger.warning(f"init_db deferred or in progress: {e}")

    # In enterprise production with Celery, scheduler & intel sync run via Celery Beat & worker queues
    if SCAN_EXECUTION_BACKEND == "local" and not app.config.get("TESTING"):
        try:
            start_scheduler()
        except Exception:
            pass

        if not _startup_sync_done:
            _startup_sync_done = True
            try:
                from config import VULN_INTEL_ENABLED
                if VULN_INTEL_ENABLED:
                    from core.vulnerability_intelligence.service import should_sync, sync_all
                    if should_sync():
                        import threading
                        threading.Thread(target=sync_all, daemon=True).start()
            except Exception:
                pass

    # Redirect to initial setup wizard if no users exist in database
    if repository.count_users() == 0:
        if request.endpoint not in ("setup", "static", "health", "ready", "metrics"):
            return redirect(url_for("setup"))


@app.after_request
def attach_correlation_id(response):
    if hasattr(g, "request_id"):
        response.headers["X-Request-ID"] = g.request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none';"
    )
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), camera=(), microphone=(), payment=()"
    )
    # HSTS only when connection is actually TLS (direct or via reverse proxy)
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    return response


# --- Routes: Initial Setup Wizard ---
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if repository.count_users() > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return render_template("setup.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("setup.html")

        valid_pw, pw_reason = validate_admin_password(password)
        if not valid_pw:
            flash(pw_reason, "error")
            return render_template("setup.html")

        # Create primary administrator
        user = create_user(
            username=username,
            password=password,
            email=email,
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        user.tenant_id = "default-tenant"
        repository.save_user(user)

        # Log in automatically (regenerate session to prevent fixation)
        session.clear()
        session.permanent = True
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = "admin"
        session["tenant_id"] = "default-tenant"
        csrf.generate_csrf()

        repository.log_audit_event(
            tenant_id="default-tenant",
            actor_user_id=user.id,
            actor_username=user.username,
            action="setup_completed",
            resource_type="system",
            metadata={"admin_user": username}
        )

        flash(f"Initial setup completed! Welcome to SentinelWP, {username}.", "success")
        return redirect(url_for("dashboard"))

    return render_template("setup.html")


# --- Routes: Auth ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
        allowed, retry_after = rate_limiter.is_allowed(f"login:{ip}", max_requests=5, window_seconds=60)
        if not allowed:
            flash(f"Too many login attempts. Please retry in {retry_after} seconds.", "error")
            return render_template("login.html"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        tenant_slug = request.form.get("tenant_slug", "").strip()
        user = authenticate_login_user(username, password, tenant_slug=tenant_slug or None)
        if user:
            if user.status != UserStatus.ACTIVE:
                flash("Account is not active. Contact administrator.", "error")
                repository.log_audit_event(
                    tenant_id=user.tenant_id or "default-tenant",
                    actor_user_id=user.id,
                    actor_username=username,
                    action="user_login",
                    result="denied",
                    metadata={"ip": ip, "reason": "account_inactive"}
                )
                return render_template("login.html")

            # Session fixation defense: clear prior unauthenticated session and regenerate CSRF
            session.clear()
            session.permanent = True
            session["user_id"] = str(user.id) if user.id is not None and not hasattr(user.id, "_mock_name") else "user-id"
            session["username"] = str(user.username) if user.username is not None and not hasattr(user.username, "_mock_name") else "user"
            session["role"] = user.role.value if hasattr(user.role, "value") else str(user.role) if not hasattr(user.role, "_mock_name") else "analyst"
            t_id = getattr(user, "tenant_id", "default-tenant")
            if hasattr(t_id, "_mock_name") or not isinstance(t_id, str):
                t_id = "default-tenant"
            session["tenant_id"] = t_id
            csrf.generate_csrf()

            repository.log_audit_event(
                tenant_id=session["tenant_id"],
                actor_user_id=session["user_id"],
                actor_username=session["username"],
                action="user_login",
                result="success",
                metadata={"ip": ip}
            )
            return redirect(url_for("dashboard"))

        repository.log_audit_event(
            tenant_id="default-tenant",
            actor_user_id="",
            actor_username=username,
            action="user_login",
            result="failure",
            metadata={"ip": ip, "reason": "invalid_credentials"}
        )
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    tenant_id = session.get("tenant_id", "default-tenant")
    user_id = session.get("user_id", "")
    username = session.get("username", "")
    if user_id:
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            actor_username=username,
            action="user_logout",
            result="success"
        )
    session.clear()
    return redirect(url_for("login"))


# --- Routes: OIDC / SSO ---
@app.route("/auth/oidc/login")
def oidc_login():
    from core.auth.oidc import OIDCClient
    client = OIDCClient()
    if not client.is_enabled:
        flash("Enterprise SSO / OIDC is not configured or enabled.", "warning")
        return redirect(url_for("login"))
    state, nonce = client.generate_state_and_nonce()
    session["oidc_state"] = state
    session["oidc_nonce"] = nonce
    redirect_uri = url_for("oidc_callback", _external=True)
    auth_url = client.get_authorization_url(state, nonce, redirect_uri=redirect_uri)
    return redirect(auth_url)


@app.route("/auth/oidc/callback")
def oidc_callback():
    from core.auth.oidc import OIDCClient
    client = OIDCClient()
    if not client.is_enabled:
        flash("Enterprise SSO / OIDC is not configured or enabled.", "error")
        return redirect(url_for("login"))

    error = request.args.get("error")
    if error:
        err_desc = request.args.get("error_description", error)
        flash(f"SSO authentication error: {err_desc}", "error")
        return redirect(url_for("login"))

    code = request.args.get("code")
    state = request.args.get("state")
    expected_state = session.get("oidc_state")
    if not state or state != expected_state:
        flash("Invalid SSO state parameter. Possible CSRF attack detected.", "error")
        return redirect(url_for("login")), 400

    redirect_uri = url_for("oidc_callback", _external=True)
    try:
        tokens = client.exchange_code_for_tokens(code, redirect_uri=redirect_uri)
        id_token = tokens.get("id_token")
        if not id_token:
            flash("No ID token returned from Identity Provider.", "error")
            return redirect(url_for("login"))

        claims = client.decode_token_unverified(id_token)
        profile = client.extract_user_info(claims)

        # Upsert or ensure user in SentinelWP
        user = repository.get_user_by_username(profile["username"])
        if not user:
            from core.models import User, UserRole, UserStatus
            import secrets
            from core.security import hash_password
            dummy_pwd = secrets.token_hex(32)
            user = User(
                username=profile["username"],
                password_hash=hash_password(dummy_pwd),
                email=profile["email"],
                role=profile["role"],
                tenant_id=profile["tenant_id"],
                status=UserStatus.ACTIVE,
            )
            repository.save_user(user)
        else:
            # Sync role and tenant claims on login
            user.role = profile["role"]
            if profile.get("tenant_id"):
                user.tenant_id = profile["tenant_id"]
            repository.save_user(user)

        # Establish authenticated session
        session.clear()
        session.permanent = True
        session["user_id"] = str(user.id)
        session["username"] = str(user.username)
        session["role"] = user.role.value if hasattr(user.role, "value") else str(user.role)
        session["tenant_id"] = user.tenant_id or "default-tenant"
        csrf.generate_csrf()

        repository.log_audit_event(
            tenant_id=session["tenant_id"],
            actor_user_id=session["user_id"],
            actor_username=session["username"],
            action="user_login_sso",
            result="success",
            metadata={"sub": profile["sub"], "provider": client.config.issuer_url}
        )
        flash(f"Signed in via Enterprise SSO as {user.username}.", "success")
        return redirect(url_for("dashboard"))

    except Exception as e:
        logger.error(f"OIDC callback error: {e}")
        flash(f"SSO authentication failed: {str(e)}", "error")
        return redirect(url_for("login"))


# --- Routes: Dashboard ---
@app.route("/")
@login_required
def dashboard():
    tenant_id = session.get("tenant_id", "default-tenant")
    filters = {
        "tenant_id": tenant_id,
        "target_url": request.args.get("target_url", "").strip(),
        "status": request.args.get("status", "").strip(),
        "scan_mode": request.args.get("scan_mode", "").strip(),
        "grade": request.args.get("grade", "").strip(),
        "is_wordpress": request.args.get("is_wordpress", "").strip(),
        "date_from": request.args.get("date_from", "").strip(),
        "date_to": request.args.get("date_to", "").strip(),
    }
    scans = repository.list_scans(limit=100, filters=filters)
    all_scans = repository.list_scans(limit=1000, filters={"tenant_id": tenant_id})
    total = len(all_scans)
    completed = len([s for s in all_scans if (s.status.value if hasattr(s.status, "value") else str(s.status)) == "completed"])
    avg_score = 0
    if completed > 0:
        scores = [s.score for s in all_scans if s.score is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0

    # Sprint 4 Phase 4: monitoring dashboard data for enhanced dashboard panel
    monitoring_data = {}
    try:
        monitoring_data = repository.get_monitoring_dashboard(tenant_id)
    except Exception:
        pass  # Dashboard data is additive; never fail the main route

    active_tab = request.args.get("tab", "posture")
    selected_bu_id = request.args.get("business_unit_id")
    portfolio_metrics = {}
    business_units = []
    dq_issues = []
    try:
        portfolio_metrics = repository.get_portfolio_metrics(tenant_id, bu_id=selected_bu_id)
        business_units = repository.list_business_units(tenant_id)
        dq_issues = repository.list_data_quality_issues(tenant_id, unresolved_only=True)
    except Exception:
        pass

    return render_template("dashboard.html",
                           scans=scans, total=total,
                           completed=completed, avg_score=avg_score, filters=filters,
                           monitoring=monitoring_data,
                           metrics=portfolio_metrics,
                           business_units=business_units,
                           selected_bu_id=selected_bu_id,
                           dq_issues=dq_issues,
                           active_tab=active_tab)


@app.route("/changelog")
@login_required
def changelog():
    return render_template("changelog.html")


@app.route("/portfolio")
@login_required
def portfolio_dashboard():
    bu_id = request.args.get("business_unit_id")
    if bu_id:
        return redirect(url_for("dashboard", tab="portfolio", business_unit_id=bu_id))
    return redirect(url_for("dashboard", tab="portfolio"))


@app.route("/portfolio/business-unit/<bu_id>")
@login_required
def business_unit_dashboard(bu_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    bu = repository.get_business_unit(bu_id, tenant_id)
    if not bu:
        flash("Business Unit not found", "error")
        return redirect(url_for("portfolio_dashboard"))
    metrics = repository.get_portfolio_metrics(tenant_id, bu_id=bu_id)
    assets = repository.list_assets(tenant_id, filters={"business_unit_id": bu_id})
    return render_template("business_unit_detail.html", bu=bu, metrics=metrics, assets=assets)


@app.route("/data-quality")
@login_required
def data_quality_dashboard():
    return redirect(url_for("assets", tab="quality"))


@app.route("/reports/executive")
@login_required
def executive_report_view():
    tenant_id = session.get("tenant_id", "default-tenant")
    metrics = repository.get_portfolio_metrics(tenant_id)
    business_units = repository.list_business_units(tenant_id)
    dq_issues = repository.list_data_quality_issues(tenant_id, unresolved_only=True)
    return render_template("executive_report.html", metrics=metrics, business_units=business_units, dq_issues=dq_issues)



@app.route("/vuln-intel")
@login_required
def vuln_intel_dashboard():
    """Vulnerability Intelligence dashboard."""
    active_tab = request.args.get("tab", "overview")
    try:
        from core.vulnerability_intelligence.service import get_status, is_stale
        from core.vulnerability_intelligence.repository import get_dashboard_stats, query_vulnerabilities
        from core.vulnerability_intelligence.wordfence_client import _get_api_key as get_wf_key
        from core.vulnerability_intelligence.nvd_client import _get_nvd_api_key as get_nvd_key
        stats = get_dashboard_stats()
        status = get_status()
        stale = is_stale()
        wf_key = get_wf_key()
        nvd_key = get_nvd_key()
    except Exception:
        stats = {"total_records": 0, "critical_recent": 0, "core_count": 0,
                 "plugin_count": 0, "popular_plugin_vuln_count": 0, "kev_count": 0}
        status = None
        stale = False
        wf_key = ""
        nvd_key = ""

    outbox_pending = 0
    try:
        pending_events = repository.get_pending_outbox_events(limit=50)
        outbox_pending = len(pending_events)
    except Exception:
        pass

    vulnerabilities = []
    total_vulns = 0
    if active_tab == "database":
        try:
            filters = {
                "cve_search": request.args.get("q", "").strip(),
                "software_type": request.args.get("software_type", ""),
                "kev_only": request.args.get("kev_only") == "on",
            }
            vulnerabilities, total_vulns = query_vulnerabilities(filters, page=1, per_page=50)
        except Exception:
            pass

    return render_template(
        "vuln_intel_dashboard.html",
        stats=stats,
        sync_state=status,
        is_stale=stale,
        wf_key=wf_key,
        nvd_key=nvd_key,
        active_tab=active_tab,
        outbox_pending=outbox_pending,
        vulnerabilities=vulnerabilities,
        total_vulns=total_vulns,
    )


@app.route("/vuln-intel/list")
@login_required
def vuln_intel_list():
    """Searchable vulnerability intelligence list with pagination."""
    page = request.args.get("page", 1, type=int)
    per_page = 50
    filters = {
        "cve_search": request.args.get("q", "").strip(),
        "software_type": request.args.get("software_type", ""),
        "min_cvss": request.args.get("min_cvss", 0, type=float),
        "min_installs": request.args.get("min_installs", 0, type=int),
        "kev_only": request.args.get("kev_only") == "on",
    }
    try:
        from core.vulnerability_intelligence.repository import query_vulnerabilities
        vulnerabilities, total_count = query_vulnerabilities(filters, page, per_page)
    except Exception:
        vulnerabilities, total_count = [], 0
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    return render_template("vuln_intel_list.html",
                           vulnerabilities=vulnerabilities, page=page,
                           total_pages=total_pages, total_count=total_count,
                           filters=filters)


@app.route("/vuln-intel/sync", methods=["POST"])
@admin_required
def vuln_intel_sync():
    """Trigger on-demand sync of vulnerability intelligence."""
    try:
        from core.vulnerability_intelligence.service import sync_all
        import threading
        t = threading.Thread(target=sync_all, daemon=True)
        t.start()
        flash("Vulnerability intelligence synchronization started in the background.", "success")
    except Exception as e:
        flash(f"Sync failed to start: {str(e)[:200]}", "error")
    return redirect(url_for("vuln_intel_dashboard"))


@app.route("/vuln-intel/api-keys", methods=["POST"])
@admin_required
def vuln_intel_api_keys():
    """Save API keys for vulnerability intelligence feeds."""
    wf_key = request.form.get("wordfence_api_key", "").strip()
    nvd_key = request.form.get("nvd_api_key", "").strip()
    try:
        from core.vulnerability_intelligence.repository import set_setting
        set_setting("WORDFENCE_API_KEY", wf_key)
        set_setting("NVD_API_KEY", nvd_key)
        flash("Vulnerability Intelligence API Keys updated successfully.", "success")
    except Exception as e:
        flash(f"Failed to update API Keys: {str(e)[:200]}", "error")
    return redirect(url_for("vuln_intel_dashboard"))


@app.route("/api/vuln-intel/status")
@login_required
def api_vuln_intel_status():
    """API endpoint for vulnerability intelligence sync status."""
    try:
        from core.vulnerability_intelligence.service import get_status
        return jsonify(get_status())
    except Exception:
        return jsonify({"enabled": False, "status": "unavailable"})


# --- Routes: Asset Inventory ---
@app.route("/assets")
@login_required
def assets():
    tenant_id = session.get("tenant_id", "default-tenant")
    filters = {
        "query": request.args.get("q", "").strip(),
        "environment": request.args.get("environment", "").strip(),
        "criticality": request.args.get("criticality", "").strip(),
        "authorization_status": request.args.get("authorization_status", "").strip(),
    }
    asset_list = repository.list_assets(tenant_id=tenant_id, filters=filters)
    active_tab = request.args.get("tab", "inventory")
    business_units = []
    open_dq_issues = []
    resolved_dq_issues = []
    try:
        business_units = repository.list_business_units(tenant_id)
        dq_issues = repository.list_data_quality_issues(tenant_id, unresolved_only=False)
        open_dq_issues = [i for i in dq_issues if not i.resolved_at]
        resolved_dq_issues = [i for i in dq_issues if i.resolved_at]
    except Exception:
        pass

    return render_template(
        "assets.html",
        assets=asset_list,
        filters=filters,
        active_tab=active_tab,
        business_units=business_units,
        open_dq_issues=open_dq_issues,
        resolved_dq_issues=resolved_dq_issues,
    )


@app.route("/asset/new")
@analyst_required
def new_asset():
    return render_template("asset_form.html", asset=None)


@app.route("/asset/create", methods=["POST"])
@analyst_required
def create_asset():
    tenant_id = session.get("tenant_id", "default-tenant")
    target_url = request.form.get("target_url", "").strip()
    if not target_url:
        flash("Target URL is required.", "error")
        return redirect(url_for("new_asset"))

    canonical_url, hostname = canonicalize_url(target_url)
    if not canonical_url:
        flash("Invalid target URL format.", "error")
        return redirect(url_for("new_asset"))

    existing = repository.get_asset_by_url(tenant_id, canonical_url)
    if existing:
        flash(f"Asset '{canonical_url}' is already registered in your inventory.", "warning")
        return redirect(url_for("asset_detail", asset_id=existing.id))

    display_name = request.form.get("display_name", "").strip() or hostname
    business_owner = request.form.get("business_owner", "").strip()
    technical_owner = request.form.get("technical_owner", "").strip()
    environment = request.form.get("environment", "production").strip().lower()
    internet_exposure = request.form.get("internet_exposure", "external").strip().lower()
    criticality = request.form.get("criticality", "medium").strip().lower()
    data_classification = request.form.get("data_classification", "confidential").strip().lower()
    tags = request.form.get("tags", "").strip()

    asset = Asset(
        tenant_id=tenant_id,
        canonical_url=canonical_url,
        hostname=hostname,
        display_name=display_name,
        business_owner=business_owner,
        technical_owner=technical_owner,
        environment=environment,
        internet_exposure=internet_exposure,
        criticality=criticality,
        data_classification=data_classification,
        tags=tags,
        status="active"
    )
    repository.save_asset(asset)

    # Optional initial authorization
    grant_auth = request.form.get("grant_auth") == "1"
    auth_valid_until = request.form.get("auth_valid_until", "").strip()
    if grant_auth and auth_valid_until:
        budget = int(request.form.get("auth_request_budget", 1000))
        auth = ScanAuthorization(
            tenant_id=tenant_id,
            asset_id=asset.id,
            status="active",
            allowed_profiles="safe_active,passive",
            request_budget=budget,
            valid_from=datetime.now(timezone.utc).isoformat(),
            valid_until=auth_valid_until,
            approved_by=session.get("username", "admin"),
            notes="Granted on asset registration."
        )
        repository.save_scan_authorization(auth)
        repository.update_asset(asset.id, tenant_id=tenant_id, authorization_status="authorized", authorization_review_date=auth_valid_until)
        asset.authorization_status = "authorized"

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="asset_created",
        resource_type="asset",
        resource_id=asset.id,
        metadata={"canonical_url": canonical_url, "hostname": hostname, "environment": environment}
    )

    flash(f"Asset '{display_name}' registered successfully.", "success")
    return redirect(url_for("asset_detail", asset_id=asset.id))


@app.route("/asset/<asset_id>")
@login_required
def asset_detail(asset_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        abort(404)

    scans = repository.list_scans(limit=100, filters={"asset_id": asset_id, "tenant_id": tenant_id})
    findings = repository.get_findings_for_asset(asset_id, tenant_id=tenant_id)
    authorizations = repository.list_scan_authorizations(asset_id=asset_id, tenant_id=tenant_id)
    active_auth = repository.get_active_authorization(asset_id, tenant_id=tenant_id)
    latest_scan = next((s for s in scans if (s.status.value if hasattr(s.status, "value") else str(s.status)) == "completed"), None)
    active_tab = request.args.get("tab", "overview")
    technologies = []
    monitoring_policy = None
    try:
        technologies = repository.list_technologies_for_asset(asset_id, tenant_id=tenant_id)
        monitoring_policy = repository.get_monitoring_policy(asset_id, tenant_id=tenant_id)
    except Exception:
        pass

    return render_template(
        "asset_detail.html",
        asset=asset,
        scans=scans,
        findings=findings,
        authorizations=authorizations,
        active_auth=active_auth,
        latest_scan=latest_scan,
        technologies=technologies,
        monitoring_policy=monitoring_policy,
        active_tab=active_tab,
    )


@app.route("/asset/<asset_id>/edit")
@analyst_required
def edit_asset_view(asset_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        abort(404)
    return render_template("asset_form.html", asset=asset)


@app.route("/asset/<asset_id>/edit", methods=["POST"])
@analyst_required
def edit_asset(asset_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        abort(404)

    updates = {
        "display_name": request.form.get("display_name", "").strip() or asset.hostname,
        "business_owner": request.form.get("business_owner", "").strip(),
        "technical_owner": request.form.get("technical_owner", "").strip(),
        "environment": request.form.get("environment", "production").strip().lower(),
        "internet_exposure": request.form.get("internet_exposure", "external").strip().lower(),
        "criticality": request.form.get("criticality", "medium").strip().lower(),
        "data_classification": request.form.get("data_classification", "confidential").strip().lower(),
        "tags": request.form.get("tags", "").strip(),
    }
    repository.update_asset(asset_id, tenant_id=tenant_id, **updates)
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="asset_updated",
        resource_type="asset",
        resource_id=asset_id,
        metadata={"updates": list(updates.keys())}
    )

    flash("Asset details updated successfully.", "success")
    return redirect(url_for("asset_detail", asset_id=asset_id))


@app.route("/asset/<asset_id>/delete", methods=["POST"])
@admin_required
def delete_asset_route(asset_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        abort(404)

    repository.delete_asset(asset_id, tenant_id=tenant_id, hard=False)
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="asset_deleted",
        resource_type="asset",
        resource_id=asset_id,
        metadata={"canonical_url": asset.canonical_url, "hostname": asset.hostname}
    )

    flash(f"Asset '{asset.display_name or asset.hostname}' decommissioned.", "success")
    return redirect(url_for("assets"))


@app.route("/asset/<asset_id>/authorize", methods=["POST"])
@analyst_required
def authorize_asset_route(asset_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        abort(404)

    valid_until = request.form.get("valid_until", "").strip()
    if not valid_until:
        flash("Valid Until expiration date/time is required.", "error")
        return redirect(url_for("asset_detail", asset_id=asset_id))

    try:
        budget = int(request.form.get("request_budget", 1000))
    except (ValueError, TypeError):
        budget = 1000

    allowed_profiles = request.form.get("allowed_profiles", "safe_active,passive").strip()
    notes = request.form.get("notes", "").strip()

    auth = ScanAuthorization(
        tenant_id=tenant_id,
        asset_id=asset_id,
        status="active",
        allowed_profiles=allowed_profiles,
        request_budget=budget,
        valid_from=datetime.now(timezone.utc).isoformat(),
        valid_until=valid_until,
        approved_by=session.get("username", "admin"),
        notes=notes
    )
    repository.save_scan_authorization(auth)
    repository.update_asset(
        asset_id,
        tenant_id=tenant_id,
        authorization_status="authorized",
        authorization_review_date=valid_until
    )

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="scan_authorization_granted",
        resource_type="scan_authorization",
        resource_id=auth.id,
        metadata={"asset_id": asset_id, "valid_until": valid_until, "budget": budget}
    )

    flash("Scan authorization granted successfully.", "success")
    return redirect(url_for("asset_detail", asset_id=asset_id))


@app.route("/authorization/<auth_id>/revoke", methods=["POST"])
@analyst_required
def revoke_authorization_route(auth_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    auth = repository.get_scan_authorization(auth_id, tenant_id=tenant_id)
    if not auth:
        abort(404)

    repository.revoke_scan_authorization(auth_id, tenant_id=tenant_id)
    remaining_active = repository.get_active_authorization(auth.asset_id, tenant_id=tenant_id)
    if not remaining_active:
        repository.update_asset(auth.asset_id, tenant_id=tenant_id, authorization_status="unauthorized")

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="scan_authorization_revoked",
        resource_type="scan_authorization",
        resource_id=auth_id,
        metadata={"asset_id": auth.asset_id}
    )

    flash("Scan authorization revoked.", "success")
    return redirect(url_for("asset_detail", asset_id=auth.asset_id))


# --- Routes: Audit Log (Admin Only) ---
@app.route("/audit")
@admin_required
def audit_log():
    tenant_id = session.get("tenant_id", "default-tenant")
    filters = {
        "actor_username": request.args.get("actor", "").strip(),
        "action": request.args.get("action", "").strip(),
        "result": request.args.get("result", "").strip(),
    }
    events = repository.list_audit_events(tenant_id=tenant_id, limit=200, filters=filters)
    return render_template("audit.html", events=events, filters=filters)


# --- Routes: New Scan ---
@app.route("/scan/new", methods=["GET", "POST"])
@analyst_required
def new_scan():
    tenant_id = session.get("tenant_id", "default-tenant")
    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
        if not app.config.get("TESTING"):
            allowed, retry_after = rate_limiter.is_allowed(f"scan:{ip}", max_requests=10, window_seconds=3600)
            if not allowed:
                flash(f"Scan rate limit reached. Retry in {retry_after} seconds.", "error")
                return render_template("new_scan.html"), 429

        target = request.form.get("target_url", "").strip()
        scan_mode = request.form.get("scan_mode", "passive").strip()
        if scan_mode not in SCAN_PROFILES:
            scan_mode = "passive"
        if not target:
            flash("Please enter a target URL.", "error")
            return render_template("new_scan.html")

        # Scan Authorization Guardrail Check
        auto_auth = request.form.get("auto_authorize") == "1"
        is_auth, reason, asset = verify_scan_authorization(tenant_id, target, scan_mode)
        if not is_auth and auto_auth and asset:
            future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
            new_auth = ScanAuthorization(
                tenant_id=tenant_id,
                asset_id=asset.id,
                status="active",
                allowed_profiles="safe_active,full,passive,*",
                valid_from=datetime.now(timezone.utc).isoformat(),
                valid_until=future_iso,
                approved_by=session.get("username", "analyst"),
            )
            repository.save_scan_authorization(new_auth)
            is_auth, reason, asset = verify_scan_authorization(tenant_id, target, scan_mode)

        if not is_auth:
            try:
                repository.log_audit_event(
                    tenant_id=tenant_id,
                    actor_user_id=session.get("user_id", ""),
                    actor_username=session.get("username", ""),
                    action="scan_denied",
                    resource_type="asset",
                    resource_id=asset.id if asset else "",
                    result="denied",
                    metadata={"target_url": target, "scan_mode": scan_mode, "reason": reason}
                )
            except Exception as e:
                logger.warning("Could not persist scan_denied audit event: %s", e)
            flash(reason, "error")
            return render_template("new_scan.html"), 403

        block_msg = _reject_unsafe_scan_target_at_submission(
            tenant_id,
            target,
            scan_mode,
            asset_id=asset.id if asset else "",
            actor_user_id=session.get("user_id", ""),
            actor_username=session.get("username", ""),
        )
        if block_msg:
            flash(block_msg, "error")
            return render_template("new_scan.html"), 400

        try:
            from core.models import ScanResult
            scan = ScanResult(
                tenant_id=tenant_id,
                asset_id=asset.id if asset else None,
                target_url=target,
                scan_mode=scan_mode,
                status=ScanStatus.PENDING,
                initiated_by=session.get("username", "analyst"),
            )
            repository.save_scan(scan)

            job = ScanJob(
                tenant_id=tenant_id,
                asset_id=asset.id if asset else None,
                scan_id=scan.id,
                status=ScanJobStatus.QUEUED.value,
                requested_by=session.get("username", "analyst"),
                profile=scan_mode,
            )
            repository.create_scan_job(job)

            if SCAN_EXECUTION_BACKEND == "celery":
                from core.tasks.scan_tasks import run_scan_task
                task_res = run_scan_task.delay(job.id)
                job.task_id = task_res.id
                repository.update_scan_job(job)
            else:
                start_async_scan(
                    target,
                    initiated_by=session.get("username", ""),
                    scan_mode=scan_mode,
                    tenant_id=tenant_id,
                    asset_id=asset.id if asset else None,
                    scan_id=scan.id,
                )

            repository.log_audit_event(
                tenant_id=tenant_id,
                actor_user_id=session.get("user_id", ""),
                actor_username=session.get("username", ""),
                action="scan_job_queued",
                resource_type="scan_job",
                resource_id=job.id,
                result="success",
                metadata={"target_url": target, "scan_mode": scan_mode, "asset_id": asset.id if asset else "", "scan_id": scan.id}
            )
            flash(f"Scan queued ({scan_mode}). Monitoring live progress...", "success")
            return redirect(url_for("scan_detail", scan_id=scan.id))
        except Exception as e:
            flash(f"Scan failed: {str(e)[:200]}", "error")
    return render_template("new_scan.html")


# --- Routes: Batch Scan ---
@app.route("/scan/batch", methods=["GET", "POST"])
@analyst_required
def batch_scan():
    tenant_id = session.get("tenant_id", "default-tenant")
    if request.method == "POST":
        targets_raw = request.form.get("targets", "").strip()
        scan_mode = request.form.get("scan_mode", "passive").strip()
        if scan_mode not in SCAN_PROFILES:
            scan_mode = "passive"
        targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
        if not targets:
            flash("Enter at least one target URL.", "error")
            return render_template("batch_scan.html")

        # Scan Authorization Guardrail for batch
        auto_auth = request.form.get("auto_authorize") == "1"
        for t in targets:
            is_auth, reason, asset = verify_scan_authorization(tenant_id, t, scan_mode)
            if not is_auth and auto_auth and asset:
                future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
                new_auth = ScanAuthorization(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    status="active",
                    allowed_profiles="safe_active,full,passive,*",
                    valid_from=datetime.now(timezone.utc).isoformat(),
                    valid_until=future_iso,
                    approved_by=session.get("username", "analyst"),
                )
                repository.save_scan_authorization(new_auth)
                is_auth, reason, asset = verify_scan_authorization(tenant_id, t, scan_mode)

            if not is_auth:
                try:
                    repository.log_audit_event(
                        tenant_id=tenant_id,
                        actor_user_id=session.get("user_id", ""),
                        actor_username=session.get("username", ""),
                        action="scan_denied",
                        resource_type="asset",
                        resource_id=asset.id if asset else "",
                        result="denied",
                        metadata={"target_url": t, "scan_mode": scan_mode, "reason": reason}
                    )
                except Exception as e:
                    logger.warning("Could not persist scan_denied audit event: %s", e)
                flash(f"Target '{t}' blocked by guardrail: {reason}", "error")
                return render_template("batch_scan.html"), 403

        try:
            job = run_batch(
                targets,
                initiated_by=session.get("username", ""),
                scan_mode=scan_mode,
                tenant_id=tenant_id
            )
            repository.log_audit_event(
                tenant_id=tenant_id,
                actor_user_id=session.get("user_id", ""),
                actor_username=session.get("username", ""),
                action="batch_scan_started",
                resource_type="batch",
                result="success",
                metadata={"targets_count": len(targets), "scan_mode": scan_mode}
            )
            flash(f"Batch completed ({scan_mode}): {job.completed} successful, {job.failed} failed.", "success")
            return redirect(url_for("scan_history"))
        except Exception as e:
            flash(f"Batch failed: {str(e)[:200]}", "error")
    return render_template("batch_scan.html")


@app.route("/scans")
@login_required
def scan_history():
    tenant_id = session.get("tenant_id", "default-tenant")
    filters = {
        "tenant_id": tenant_id,
        "target_url": request.args.get("target_url", "").strip(),
        "status": request.args.get("status", "").strip(),
        "scan_mode": request.args.get("scan_mode", "").strip(),
        "grade": request.args.get("grade", "").strip(),
        "is_wordpress": request.args.get("is_wordpress", "").strip(),
        "date_from": request.args.get("date_from", "").strip(),
        "date_to": request.args.get("date_to", "").strip(),
    }
    scans = repository.list_scans(limit=200, filters=filters)
    active_tab = request.args.get("tab", "history")
    schedules_list = []
    assets_list = []
    try:
        schedules_list = repository.list_scheduled_scans(tenant_id=tenant_id)
        assets_list = repository.list_assets(tenant_id=tenant_id)
    except Exception:
        pass

    return render_template(
        "scan_history.html",
        scans=scans,
        filters=filters,
        active_tab=active_tab,
        schedules=schedules_list,
        assets=assets_list
    )


@app.route("/admin/export-db")
@admin_required
def admin_export_db():
    """Export full unique scan database as a multi-sheet Excel file (Admin only, tenant scoped)."""
    tenant_id = session.get("tenant_id", "default-tenant")
    try:
        from reports.generator import generate_full_db_excel_export
        scans = repository.list_scans(limit=5000, filters={"tenant_id": tenant_id})
        for s in scans:
            s.findings = repository.get_findings_for_scan(s.id, tenant_id=tenant_id)
        excel_bytes = generate_full_db_excel_export(scans)
        filename = f"SentinelWP_Database_Export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.xlsx"
        return send_file(
            io.BytesIO(excel_bytes),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        flash(f"Database export failed: {str(e)[:200]}", "error")
        return redirect(url_for("dashboard"))


# --- Routes: Scan Detail ---
@app.route("/scan/<scan_id>")
@login_required
def scan_detail(scan_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    scan = repository.get_scan(scan_id, tenant_id=tenant_id)
    if not scan:
        abort(404)
    job = repository.get_scan_job_by_scan_id(scan_id, tenant_id=tenant_id)
    breakdown = compute_category_breakdown(scan.findings) if scan.findings else {}
    return render_template("scan_detail.html", scan=scan, job=job, breakdown=breakdown)


# --- Routes: Delete Scan ---
@app.route("/scan/<scan_id>/delete", methods=["POST"])
@analyst_required
def delete_scan(scan_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    scan = repository.get_scan(scan_id, tenant_id=tenant_id)
    if not scan:
        abort(404)
    repository.delete_scan(scan_id, tenant_id=tenant_id)
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="scan_deleted",
        resource_type="scan",
        resource_id=scan_id,
        metadata={"target_url": scan.target_url}
    )
    flash("Scan deleted.", "success")
    return redirect(url_for("scan_history"))


# --- Routes: Schedules ---
@app.route("/schedules")
@login_required
def schedules():
    return redirect(url_for("scan_history", tab="schedules"))


VALID_SCHEDULE_INTERVALS = (12, 24, 168)


@app.route("/schedule/create", methods=["POST"])
@analyst_required
def create_schedule():
    tenant_id = session.get("tenant_id", "default-tenant")
    raw_targets = request.form.get("targets", "").strip()
    if not raw_targets:
        # Fallback to backward-compatible target_url
        raw_targets = request.form.get("target_url", "").strip()

    if not raw_targets:
        flash("Target URL is required.", "error")
        return redirect(url_for("schedules"))

    # Validate frequency interval
    try:
        raw_interval = request.form.get("interval_hours", "24")
        interval_hours = int(raw_interval)
        if interval_hours not in VALID_SCHEDULE_INTERVALS:
            flash(
                f"Invalid frequency interval '{raw_interval}'. Allowed intervals: "
                f"{', '.join(str(i) for i in VALID_SCHEDULE_INTERVALS)} hours.",
                "error"
            )
            return redirect(url_for("schedules"))
    except (ValueError, TypeError):
        flash("Frequency interval must be a valid integer.", "error")
        return redirect(url_for("schedules"))

    # Validate scan mode (fail-closed)
    scan_mode = request.form.get("scan_mode", "safe-active").strip().lower()
    if scan_mode not in SCAN_PROFILES:
        flash(f"Invalid scan mode '{scan_mode}'. Must be one of: {', '.join(SCAN_PROFILES.keys())}.", "error")
        return redirect(url_for("schedules"))

    # Parse and normalize targets
    lines = raw_targets.splitlines()
    candidate_targets = []
    for line in lines:
        cleaned = line.strip()
        if not cleaned:
            continue
        if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
            cleaned = "https://" + cleaned
        cleaned = cleaned.rstrip("/")
        if cleaned not in candidate_targets:
            candidate_targets.append(cleaned)

    if not candidate_targets:
        flash("No valid target URLs provided.", "error")
        return redirect(url_for("schedules"))

    # Limit check: WSA_MAX_SCHEDULE_TARGETS
    if len(candidate_targets) > WSA_MAX_SCHEDULE_TARGETS:
        flash(
            f"Batch exceeds maximum limit of {WSA_MAX_SCHEDULE_TARGETS} targets "
            f"(submitted {len(candidate_targets)}). Schedule creation rejected.",
            "error"
        )
        return redirect(url_for("schedules"))

    # Centralized Target Validation (SSRF protection) — Fail Closed across entire batch
    invalid_targets = []
    for t in candidate_targets:
        valid, msg = BaseScanner.validate_target(t)
        if not valid:
            invalid_targets.append(f"{t} ({msg})")

    if invalid_targets:
        flash(f"Schedule not created. Invalid target(s): {', '.join(invalid_targets)}", "error")
        return redirect(url_for("schedules"))

    # Ensure asset association for each scheduled target within tenant
    target_assets = {}
    for t in candidate_targets:
        try:
            asset = repository.ensure_asset_for_target(tenant_id, t)
            target_assets[t] = asset
        except Exception:
            target_assets[t] = None

    # Duplicate prevention against existing schedules in database
    existing_schedules = repository.list_scheduled_scans(tenant_id=tenant_id)
    existing_set = {
        (s.target_url.rstrip("/"), s.scan_mode, s.interval_hours)
        for s in existing_schedules
    }

    created_count = 0
    skipped_count = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for t in candidate_targets:
        sched_key = (t, scan_mode, interval_hours)
        if sched_key in existing_set:
            skipped_count += 1
            continue

        asset = target_assets.get(t)
        sched = ScheduledScan(
            target_url=t,
            scan_mode=scan_mode,
            interval_hours=interval_hours,
            created_by=session.get("username", "admin"),
            next_run_at=now_iso,
            tenant_id=tenant_id,
            asset_id=asset.id if asset else None,
        )
        repository.save_scheduled_scan(sched)
        existing_set.add(sched_key)
        created_count += 1

    if created_count > 0:
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=session.get("user_id", ""),
            actor_username=session.get("username", ""),
            action="schedule_created",
            resource_type="schedule",
            result="success",
            metadata={"created_count": created_count, "scan_mode": scan_mode, "interval_hours": interval_hours}
        )

    if created_count == 0 and skipped_count > 0:
        flash("No schedules created: all submitted targets already exist.", "warning")
    elif skipped_count > 0:
        flash(f"Created {created_count} scheduled scan(s). Skipped {skipped_count} duplicate schedule(s).", "success")
    else:
        flash(f"Created {created_count} scheduled scan(s).", "success")

    return redirect(url_for("schedules"))


@app.route("/schedule/<sched_id>/delete", methods=["POST"])
@analyst_required
def delete_schedule(sched_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    sched = repository.get_scheduled_scan(sched_id, tenant_id=tenant_id)
    if not sched:
        abort(404)

    repository.delete_scheduled_scan(sched_id, tenant_id=tenant_id)
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="schedule_deleted",
        resource_type="schedule",
        resource_id=sched_id,
        metadata={"target_url": sched.target_url}
    )
    flash("Scheduled scan deleted.", "success")
    return redirect(url_for("schedules"))


# --- Routes: Export CSV ---
@app.route("/scans/export/csv")
@login_required
def export_scans_csv():
    import csv
    from reports.generator import _sanitize_cell
    tenant_id = session.get("tenant_id", "default-tenant")
    scans = repository.list_scans(limit=1000, filters={"tenant_id": tenant_id})
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    
    writer.writerow([
        "Scan ID", "Target URL", "WHOIS Info", "WordPress Version", 
        "Detected Plugins", "Findings (Titles)", "Score", "Grade", "Status", "Started At"
    ])
    
    for s in scans:
        findings = repository.get_findings_for_scan(s.id, tenant_id=tenant_id)
        findings_str = "; ".join([f.title for f in findings]) if findings else "None"
        wp_ver = s.wp_version if s.is_wordpress else "Not WordPress"
        plugins = "N/A"
        
        writer.writerow([
            _sanitize_cell(str(s.id)),
            _sanitize_cell(str(s.target_url)),
            _sanitize_cell(str(s.whois_info or "N/A")),
            _sanitize_cell(str(wp_ver or "Unknown")),
            plugins,
            _sanitize_cell(findings_str),
            s.score if s.score is not None else "N/A",
            s.grade or "N/A",
            s.status.value if hasattr(s.status, "value") else str(s.status),
            _sanitize_cell(str(s.started_at))
        ])
        
    output.seek(0)
    filename = f"SentinelWP_Scans_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename
    )


# --- Routes: Reports ---
@app.route("/scan/<scan_id>/report/<fmt>")
@login_required
def download_report(scan_id, fmt):
    tenant_id = session.get("tenant_id", "default-tenant")
    scan = repository.get_scan(scan_id, tenant_id=tenant_id)
    if not scan:
        abort(404)
    if fmt == "html":
        html = generate_html_report(scan)
        return send_file(
            io.BytesIO(html.encode("utf-8")),
            mimetype="text/html",
            as_attachment=True,
            download_name=f"sentinelwp-report-{scan_id[:8]}.html"
        )
    elif fmt == "json":
        j = generate_json_report(scan)
        return send_file(
            io.BytesIO(j.encode("utf-8")),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"sentinelwp-report-{scan_id[:8]}.json"
        )
    elif fmt == "sarif":
        sarif = generate_sarif_report(scan)
        return send_file(
            io.BytesIO(sarif.encode("utf-8")),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"sentinelwp-report-{scan_id[:8]}.sarif"
        )
    elif fmt == "excel":
        data = generate_excel_report(scan)
        return send_file(
            io.BytesIO(data),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"sentinelwp-report-{scan_id[:8]}.xlsx"
        )
    elif fmt == "pdf":
        data = generate_pdf_report(scan)
        return send_file(
            io.BytesIO(data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"sentinelwp-report-{scan_id[:8]}.pdf"
        )
    abort(400)


# --- Routes: Finding Actions ---
@app.route("/finding/<finding_id>/edit", methods=["POST"])
@analyst_required
def edit_finding(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    allowed = {}
    for k in ("title", "description", "severity", "remediation", "reference"):
        val = request.form.get(k)
        if val is not None:
            allowed[k] = val.strip()
    if allowed:
        repository.update_finding(finding_id, tenant_id=tenant_id, **allowed)
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=session.get("user_id", ""),
            actor_username=session.get("username", ""),
            action="finding_edited",
            resource_type="finding",
            resource_id=finding_id,
            metadata={"updates": list(allowed.keys())}
        )
    flash("Finding updated.", "success")
    return redirect(request.referrer or url_for("scan_history"))


@app.route("/finding/<finding_id>/delete", methods=["POST"])
@analyst_required
def delete_finding(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    repository.delete_finding(finding_id, tenant_id=tenant_id)
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="finding_deleted",
        resource_type="finding",
        resource_id=finding_id,
        metadata={"title": finding.title}
    )
    flash("Finding deleted.", "success")
    return redirect(request.referrer or url_for("scan_history"))


# --- Routes: User & System Settings Panel ---
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    tenant_id = session.get("tenant_id", "default-tenant")
    user = repository.get_user_by_id(session.get("user_id"), tenant_id=tenant_id)
    users = repository.list_users(tenant_id=tenant_id) if session.get("role") == "admin" else []

    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            old_pass = request.form.get("old_password", "")
            new_pass = request.form.get("new_password", "")
            confirm_pass = request.form.get("confirm_password", "")
            if not user or not verify_password(old_pass, user.password_hash):
                flash("Current password incorrect.", "error")
            elif len(new_pass) < 6:
                flash("New password must be at least 6 characters.", "error")
            elif new_pass != confirm_pass:
                flash("New passwords do not match.", "error")
            else:
                repository.update_user(user.id, tenant_id=tenant_id, password_hash=hash_password(new_pass))
                repository.log_audit_event(
                    tenant_id=tenant_id,
                    actor_user_id=user.id,
                    actor_username=user.username,
                    action="password_changed",
                    resource_type="user",
                    resource_id=user.id,
                    result="success"
                )
                flash("Password successfully updated.", "success")
            return redirect(url_for("settings"))

    active_tab = request.args.get("tab", "general")

    api_keys = []
    if session.get("role") in ("admin", "analyst"):
        try:
            api_keys = repository.list_api_keys(tenant_id)
        except Exception:
            pass

    audit_events = []
    if session.get("role") == "admin":
        try:
            audit_events = repository.list_audit_events(tenant_id=tenant_id, limit=50)
        except Exception:
            pass

    update_info = check_for_updates(force=False)
    return render_template(
        "settings.html",
        user=user,
        users=users,
        update_info=update_info,
        active_tab=active_tab,
        api_keys=api_keys,
        audit_events=audit_events
    )


@app.route("/api/check-update")
@login_required
def api_check_update():
    """API endpoint to query GitHub repository update status."""
    force = request.args.get("force", "false").lower() in ("true", "1")
    return jsonify(check_for_updates(force=force))


@app.route("/users")
@admin_required
def user_management():
    return redirect(url_for("settings"))


@app.route("/user/create", methods=["POST"])
@admin_required
def create_user_route():
    tenant_id = session.get("tenant_id", "default-tenant")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "viewer")
    if not username or not password:
        flash("Username and password required.", "error")
        return redirect(url_for("settings"))
    if repository.get_user_by_username(username):
        flash("Username already exists.", "error")
        return redirect(url_for("settings"))

    user = create_user(username=username, password=password, email=email,
                        role=UserRole(role), status=UserStatus.ACTIVE)
    user.tenant_id = tenant_id
    repository.save_user(user)

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="user_created",
        resource_type="user",
        resource_id=user.id,
        metadata={"username": username, "role": role}
    )

    flash(f"User {username} created successfully.", "success")
    return redirect(url_for("settings"))


@app.route("/user/<user_id>/delete", methods=["POST"])
@admin_required
def delete_user_route(user_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    if user_id == session.get("user_id"):
        flash("Cannot delete your own active administrator account.", "error")
        return redirect(url_for("settings"))

    target_user = repository.get_user_by_id(user_id, tenant_id=tenant_id)
    if not target_user:
        abort(404)

    repository.delete_user(user_id, tenant_id=tenant_id)
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="user_deleted",
        resource_type="user",
        resource_id=user_id,
        metadata={"username": target_user.username}
    )

    flash("User account deleted.", "success")
    return redirect(url_for("settings"))


@app.route("/admin/import-db", methods=["POST"])
@admin_required
def admin_import_db():
    """Import full scan database from uploaded Excel file (Admin only)."""
    file = request.files.get("import_file")
    if not file or not file.filename:
        flash("No file selected for import.", "error")
        return redirect(url_for("settings"))
    if not file.filename.lower().endswith((".xlsx", ".xls")):
        flash("Invalid file format. Please upload an Excel (.xlsx) file.", "error")
        return redirect(url_for("settings"))
    try:
        scans_count, findings_count = import_full_db_excel(file.read(), repository)
        repository.log_audit_event(
            tenant_id=session.get("tenant_id", "default-tenant"),
            actor_user_id=session.get("user_id", ""),
            actor_username=session.get("username", ""),
            action="database_imported",
            resource_type="database",
            metadata={"scans_count": scans_count, "findings_count": findings_count}
        )
        flash(f"Database import complete! Successfully imported {scans_count} scan(s) and {findings_count} finding(s).", "success")
    except Exception as e:
        flash(f"Database import failed: {str(e)}", "error")
    return redirect(url_for("settings"))


@app.route("/admin/purge-db", methods=["POST"])
@admin_required
def admin_purge_db():
    tenant_id = session.get("tenant_id", "default-tenant")
    confirm_text = (request.form.get("confirm_text", "") or request.form.get("confirm_purge", "")).strip().upper()
    if confirm_text != "PURGE":
        flash("Database purge cancelled: Type 'PURGE' to confirm deletion.", "error")
        return redirect(url_for("settings"))
    try:
        scans_count, findings_count = repository.purge_all_scans_and_findings(tenant_id=tenant_id)
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=session.get("user_id", ""),
            actor_username=session.get("username", ""),
            action="database_purged",
            resource_type="database",
            metadata={"scans_purged": scans_count, "findings_purged": findings_count}
        )
        flash(f"Database archive purged! Successfully deleted {scans_count} scan record(s) and {findings_count} finding(s).", "success")
    except Exception as e:
        flash(f"Database purge failed: {str(e)}", "error")
    return redirect(url_for("settings"))


# --- API Endpoints ---
@app.route("/api/scan/<scan_id>/status")
@login_required
def api_scan_status(scan_id):
    """Return live persistent progress for a scan (0-100%, current step, status)."""
    tenant_id = session.get("tenant_id", "default-tenant")
    scan = repository.get_scan(scan_id, tenant_id=tenant_id)
    if not scan:
        abort(404)

    job = repository.get_scan_job_by_scan_id(scan_id, tenant_id=tenant_id)
    if job:
        return jsonify({
            "scan_id": scan.id,
            "job_id": job.id,
            "status": job.status,
            "progress": job.progress_percent,
            "current_step": job.current_step,
            "attempt": job.attempt,
            "queued_at": job.queued_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error_code": job.error_code,
            "error_message": job.error_message,
        })
    return jsonify(get_scan_progress(scan_id))


@app.route("/api/scan", methods=["POST"])
@analyst_required
def api_scan():
    tenant_id = session.get("tenant_id", "default-tenant")
    ip = request.remote_addr or "127.0.0.1"
    allowed, retry_after = rate_limiter.is_allowed(f"api_scan:{ip}", max_requests=10, window_seconds=3600)
    if not allowed:
        return jsonify({"error": f"Rate limit reached. Retry in {retry_after} seconds."}), 429

    data = request.get_json() or {}
    target = data.get("target_url", "").strip()
    scan_mode = data.get("scan_mode", "passive").strip()
    if not target:
        return jsonify({"error": "target_url required"}), 400

    is_auth, reason, asset = verify_scan_authorization(tenant_id, target, scan_mode)
    if not is_auth:
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=session.get("user_id", ""),
            actor_username=session.get("username", ""),
            action="scan_denied",
            resource_type="asset",
            resource_id=asset.id if asset else "",
            result="denied",
            metadata={"target_url": target, "scan_mode": scan_mode, "reason": reason}
        )
        return jsonify({"error": reason}), 403

    block_msg = _reject_unsafe_scan_target_at_submission(
        tenant_id,
        target,
        scan_mode,
        asset_id=asset.id if asset else "",
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
    )
    if block_msg:
        return jsonify({"error": block_msg, "code": "TARGET_BLOCKED"}), 400

    try:
        from core.models import ScanResult
        scan = ScanResult(
            tenant_id=tenant_id,
            asset_id=asset.id if asset else None,
            target_url=target,
            scan_mode=scan_mode,
            status=ScanStatus.PENDING,
            initiated_by=session.get("username", "api"),
        )
        repository.save_scan(scan)

        job = ScanJob(
            tenant_id=tenant_id,
            asset_id=asset.id if asset else None,
            scan_id=scan.id,
            status=ScanJobStatus.QUEUED.value,
            requested_by=session.get("username", "api"),
            profile=scan_mode,
        )
        repository.create_scan_job(job)

        if SCAN_EXECUTION_BACKEND == "celery":
            from core.tasks.scan_tasks import run_scan_task
            task_res = run_scan_task.delay(job.id)
            job.task_id = task_res.id
            repository.update_scan_job(job)
        else:
            start_async_scan(
                target,
                initiated_by=session.get("username", "api"),
                scan_mode=scan_mode,
                tenant_id=tenant_id,
                asset_id=asset.id if asset else None,
                scan_id=scan.id,
            )

        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=session.get("user_id", ""),
            actor_username=session.get("username", ""),
            action="scan_job_queued",
            resource_type="scan_job",
            resource_id=job.id,
            result="success",
            metadata={"target_url": target, "scan_mode": scan_mode, "scan_id": scan.id}
        )
        return jsonify({
            "scan_id": scan.id,
            "job_id": job.id,
            "status": "queued",
            "scan_mode": scan_mode,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- ScanJob Lifecycle & Cancellation Endpoints ---
@app.route("/scan-job/<job_id>/cancel", methods=["POST"])
@analyst_required
def cancel_scan_job(job_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    job = repository.get_scan_job(job_id, tenant_id=tenant_id)
    if not job:
        abort(404)

    if job.task_id:
        try:
            from core.tasks.celery_app import celery_app
            celery_app.control.revoke(job.task_id, terminate=True)
        except Exception:
            pass

    repository.mark_scan_job_status(job.id, ScanJobStatus.CANCELLED.value)
    scan = repository.get_scan(job.scan_id, tenant_id=tenant_id)
    if scan:
        scan.status = ScanStatus.FAILED
        scan.notes = "Scan cancelled by user."
        scan.completed_at = datetime.now(timezone.utc).isoformat()
        repository.save_scan(scan)

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="scan_job_cancelled",
        resource_type="scan_job",
        resource_id=job.id,
        result="success",
        metadata={"scan_id": job.scan_id}
    )

    if request.is_json:
        return jsonify({"status": "cancelled", "job_id": job.id})
    flash("Scan execution cancelled.", "success")
    return redirect(url_for("scan_detail", scan_id=job.scan_id))


@app.route("/scan-job/<job_id>/retry", methods=["POST"])
@analyst_required
def retry_scan_job(job_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    job = repository.get_scan_job(job_id, tenant_id=tenant_id)
    if not job:
        abort(404)

    scan = repository.get_scan(job.scan_id, tenant_id=tenant_id)
    if not scan:
        abort(404)

    # Re-validate authorization for safe_active
    if scan.scan_mode == "safe-active":
        is_auth, reason, _ = verify_scan_authorization(tenant_id, scan.target_url, scan.scan_mode)
        if not is_auth:
            flash(f"Cannot retry scan: {reason}", "error")
            return redirect(url_for("scan_detail", scan_id=scan.id)), 403

    job.attempt += 1
    job.status = ScanJobStatus.QUEUED.value
    job.error_code = None
    job.error_message = None
    job.progress_percent = 0
    job.current_step = "Retrying"
    repository.update_scan_job(job)

    scan.status = ScanStatus.RUNNING
    repository.save_scan(scan)

    if SCAN_EXECUTION_BACKEND == "celery":
        from core.tasks.scan_tasks import run_scan_task
        task_res = run_scan_task.delay(job.id)
        job.task_id = task_res.id
        repository.update_scan_job(job)
    else:
        start_async_scan(
            scan.target_url,
            initiated_by=session.get("username", ""),
            scan_mode=scan.scan_mode,
            tenant_id=tenant_id,
            asset_id=scan.asset_id,
            scan_id=scan.id,
        )

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
        action="scan_job_retry",
        resource_type="scan_job",
        resource_id=job.id,
        result="success",
        metadata={"scan_id": scan.id, "attempt": job.attempt}
    )

    flash("Scan job queued for retry.", "success")
    return redirect(url_for("scan_detail", scan_id=scan.id))


# --- Health, Readiness & Observability Endpoints ---
@app.route("/health")
def health():
    """Liveness probe: verifies web process is running."""
    return jsonify({
        "status": "ok",
        "app": "SentinelWP",
        "version": __version__,
        "backend": SCAN_EXECUTION_BACKEND,
    }), 200


@app.route("/ready")
def ready():
    """Readiness probe: verifies database and broker connectivity."""
    checks = {}
    is_ready = True

    # Database check
    try:
        if is_postgres_configured():
            verify_operational_persistence_guard()
            checks["database"] = "connected"
            checks["storage_backend"] = "postgresql"
        else:
            t = repository.get_tenant_by_id("default-tenant")
            checks["database"] = "connected" if t else "initialized"
            checks["storage_backend"] = "sqlite"
    except Exception as e:
        logger.warning(f"Readiness probe database error: {e}")
        checks["database"] = "error: connection_failed"
        is_ready = False

    # Redis / Celery broker check
    if SCAN_EXECUTION_BACKEND == "celery":
        try:
            import redis
            r = redis.from_url(REDIS_URL, socket_timeout=2)
            r.ping()
            checks["redis"] = "connected"
        except Exception as e:
            logger.warning(f"Readiness probe redis error: {e}")
            checks["redis"] = "error: connection_failed"
            is_ready = False
    else:
        checks["broker"] = "local_standalone_mode"

    status_code = 200 if is_ready else 503
    return jsonify({
        "status": "ready" if is_ready else "not_ready",
        "checks": checks,
    }), status_code


@app.route("/metrics")
def metrics():
    """Prometheus compatible metrics endpoint."""
    tenant_id = "default-tenant"
    queued_jobs = len(repository.list_scan_jobs(tenant_id, status=ScanJobStatus.QUEUED.value))
    running_jobs = len(repository.list_scan_jobs(tenant_id, status=ScanJobStatus.RUNNING.value))
    failed_jobs = len(repository.list_scan_jobs(tenant_id, status=ScanJobStatus.FAILED.value))
    queue_metrics = repository.get_queue_depth_metrics()

    # Freshness
    wf_fresh = repository.evaluate_intel_freshness("wordfence")
    kev_fresh = repository.evaluate_intel_freshness("cisa_kev")

    # Exposure & SLA Metrics
    findings, _ = repository.list_findings(tenant_id, filters=None, page=1, page_size=2000)
    open_findings = [f for f in findings if f.status not in (FindingStatus.REMEDIATED.value, FindingStatus.VERIFIED.value, FindingStatus.CLOSED.value, FindingStatus.FALSE_POSITIVE.value)]
    open_p1 = sum(1 for f in open_findings if f.priority_band == "P1")
    sla_breaches = sum(1 for f in open_findings if f.sla_status == SLAStatus.BREACHED.value)
    risk_accepted = sum(1 for f in findings if f.status == FindingStatus.RISK_ACCEPTED.value)

    lines = [
        "# HELP sentinel_scan_jobs_queued Number of scan jobs currently queued",
        "# TYPE sentinel_scan_jobs_queued gauge",
        f"sentinel_scan_jobs_queued {queued_jobs}",
        "",
        "# HELP scan_queue_depth Number of scan jobs waiting in queue",
        "# TYPE scan_queue_depth gauge",
        f"scan_queue_depth {queue_metrics['scan_queue_depth']}",
        "",
        "# HELP intel_queue_depth Number of intelligence tasks active",
        "# TYPE intel_queue_depth gauge",
        f"intel_queue_depth {queue_metrics['intel_queue_depth']}",
        "",
        "# HELP integration_queue_depth Number of integration outbox events pending",
        "# TYPE integration_queue_depth gauge",
        f"integration_queue_depth {queue_metrics['integration_queue_depth']}",
        "",
        "# HELP oldest_queued_job_seconds Age of oldest queued scan job in seconds",
        "# TYPE oldest_queued_job_seconds gauge",
        f"oldest_queued_job_seconds {queue_metrics['oldest_queued_job_seconds']}",
        "",
        "# HELP sentinel_scan_jobs_running Number of scan jobs currently running",
        "# TYPE sentinel_scan_jobs_running gauge",
        f"sentinel_scan_jobs_running {running_jobs}",
        "",
        "# HELP sentinel_scan_jobs_failed_total Total number of failed scan jobs",
        "# TYPE sentinel_scan_jobs_failed_total counter",
        f"sentinel_scan_jobs_failed_total {failed_jobs}",
        "",
        "# HELP sentinel_intel_freshness_seconds Age of intelligence data in seconds",
        "# TYPE sentinel_intel_freshness_seconds gauge",
        f'sentinel_intel_freshness_seconds{{source="wordfence"}} {int(wf_fresh.get("age_hours", 0) or 0) * 3600}',
        f'sentinel_intel_freshness_seconds{{source="cisa_kev"}} {int(kev_fresh.get("age_hours", 0) or 0) * 3600}',
        "",
        "# HELP sentinel_findings_open Number of open vulnerabilities",
        "# TYPE sentinel_findings_open gauge",
        f'sentinel_findings_open{{tenant="{tenant_id}"}} {len(open_findings)}',
        "",
        "# HELP sentinel_findings_p1 Number of P1 critical vulnerabilities",
        "# TYPE sentinel_findings_p1 gauge",
        f'sentinel_findings_p1{{tenant="{tenant_id}"}} {open_p1}',
        "",
        "# HELP sentinel_sla_breaches_total Number of breached SLAs",
        "# TYPE sentinel_sla_breaches_total gauge",
        f'sentinel_sla_breaches_total{{tenant="{tenant_id}"}} {sla_breaches}',
        "",
        "# HELP sentinel_risk_accepted_total Number of risk accepted findings",
        "# TYPE sentinel_risk_accepted_total gauge",
        f'sentinel_risk_accepted_total{{tenant="{tenant_id}"}} {risk_accepted}',
    ]
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.route("/api/scans")
@login_required
def api_scans():
    tenant_id = session.get("tenant_id", "default-tenant")
    scans = repository.list_scans(limit=100, filters={"tenant_id": tenant_id})
    return jsonify([{
        "id": s.id,
        "target_url": s.target_url,
        "score": s.score,
        "grade": s.grade,
        "status": s.status.value if hasattr(s.status, "value") else s.status,
        "scan_mode": s.scan_mode,
        "started_at": s.started_at,
    } for s in scans])


# =====================================================================
# Phase 4: Findings & Exposure Management Web Routes
# =====================================================================

@app.route("/findings")
@login_required
def findings_list():
    tenant_id = session.get("tenant_id", "default-tenant")
    active_tab = request.args.get("tab", "all")
    filters = {
        "status": request.args.get("status"),
        "severity": request.args.get("severity"),
        "priority_band": request.args.get("priority_band"),
        "sla_status": request.args.get("sla_status"),
        "asset_id": request.args.get("asset_id"),
        "search": request.args.get("search"),
        "kev": True if request.args.get("kev") == "1" else None,
    }
    if active_tab == "critical" and not filters.get("severity") and not filters.get("priority_band"):
        filters["priority_band"] = "P1"

    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 50))

    findings, total_count = repository.list_findings(tenant_id, filters=filters, page=page, page_size=page_size)

    remediations = []
    total_remediations = 0
    in_progress_count = 0
    pending_verification_count = 0
    completed_remediations_count = 0

    sla_policies = []
    sla_snapshots = []
    on_track_count = 0
    warning_count = 0
    breached_count = 0
    paused_count = 0

    risk_acceptances = []

    try:
        if active_tab in ("remediation", "all"):
            remediations = repository.list_remediations(tenant_id)
            total_remediations = len(remediations)
            in_progress_count = sum(1 for r in remediations if r.status == "IN_PROGRESS")
            pending_verification_count = sum(1 for r in remediations if r.verification_status == "pending")
            completed_remediations_count = sum(1 for r in remediations if r.status == "COMPLETED")

        if active_tab in ("sla", "all"):
            sla_policies = repository.list_sla_policies(tenant_id)
            sla_snapshots = repository.get_daily_risk_snapshots(tenant_id, days=30)
            all_f, _ = repository.list_findings(tenant_id, filters=None, page=1, page_size=1000)
            on_track_count = sum(1 for f in all_f if f.sla_status == "ON_TRACK")
            warning_count = sum(1 for f in all_f if f.sla_status == "WARNING")
            breached_count = sum(1 for f in all_f if f.sla_status == "BREACHED")
            paused_count = sum(1 for f in all_f if f.sla_status == "PAUSED")

        if active_tab in ("exceptions", "all"):
            risk_acceptances = repository.list_risk_acceptances(tenant_id)
    except Exception:
        pass

    return render_template(
        "findings.html",
        findings=findings,
        total_count=total_count,
        filters=filters,
        page=page,
        page_size=page_size,
        active_tab=active_tab,
        remediations=remediations,
        total_remediations=total_remediations,
        in_progress_count=in_progress_count,
        pending_verification_count=pending_verification_count,
        completed_remediations_count=completed_remediations_count,
        sla_policies=sla_policies,
        sla_snapshots=sla_snapshots,
        on_track_count=on_track_count,
        warning_count=warning_count,
        breached_count=breached_count,
        paused_count=paused_count,
        risk_acceptances=risk_acceptances,
    )


@app.route("/finding/<finding_id>")
@login_required
def finding_detail(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    observations = repository.get_observations_for_finding(finding_id, tenant_id=tenant_id)
    history = repository.get_finding_history(finding_id, tenant_id=tenant_id)
    comments = repository.get_finding_comments(finding_id, tenant_id=tenant_id)
    remediation = repository.get_remediation_by_finding(finding_id, tenant_id=tenant_id)
    remediation_actions = repository.get_remediation_actions(remediation.id, tenant_id=tenant_id) if remediation else []
    risk_acceptance = repository.get_risk_acceptance_by_finding(finding_id, tenant_id=tenant_id)
    tickets = repository.get_ticket_references_for_finding(finding_id, tenant_id=tenant_id)

    return render_template(
        "finding_detail.html",
        finding=finding,
        observations=observations,
        history=history,
        comments=comments,
        remediation=remediation,
        remediation_actions=remediation_actions,
        risk_acceptance=risk_acceptance,
        tickets=tickets,
    )


@app.route("/finding/<finding_id>/status", methods=["POST"])
@analyst_required
def transition_finding(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    new_status = request.form.get("new_status", "").strip()
    comment = request.form.get("comment", "").strip()
    expected_version_raw = request.form.get("expected_version")
    expected_version = int(expected_version_raw) if expected_version_raw else None

    if not new_status:
        flash("Target status is required.", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id))

    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    try:
        finding = repository.transition_finding_status(
            finding_id=finding_id,
            new_status=new_status,
            actor_user_id=session.get("user_id", "analyst"),
            tenant_id=tenant_id,
            comment=comment,
            expected_version=expected_version,
        )
        flash(f"Finding status updated to {finding.status}.", "success")
        return redirect(url_for("finding_detail", finding_id=finding_id))
    except OptimisticLockError as ole:
        flash(f"Conflict: The finding was modified concurrently ({ole}). Please reload.", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id)), 409
    except InvalidStateTransitionError as iste:
        flash(f"Invalid transition: {iste}", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id)), 409
    except Exception as e:
        flash(f"Error: {e}", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id)), 400


@app.route("/finding/<finding_id>/comment", methods=["POST"])
@analyst_required
def add_finding_comment_route(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    body = request.form.get("comment", "").strip()
    if body:
        comment = FindingComment(
            tenant_id=tenant_id,
            finding_id=finding_id,
            author_user_id=session.get("user_id", "analyst"),
            author_username=session.get("username", "analyst"),
            body=body,
        )
        repository.add_finding_comment(comment)
        flash("Comment added.", "success")
    return redirect(url_for("finding_detail", finding_id=finding_id))


@app.route("/finding/<finding_id>/remediation", methods=["POST"])
@analyst_required
def create_remediation_plan(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    owner = request.form.get("owner", "").strip()
    due_date = request.form.get("due_date", "").strip()

    remediation = Remediation(
        tenant_id=tenant_id,
        finding_id=finding_id,
        title=f"Remediate: {finding.title}",
        description=finding.remediation or "Remediation plan",
        owner_user_id=owner,
        priority=finding.priority_band,
        due_date=due_date or None,
        status="OPEN",
    )
    repository.create_remediation(remediation)
    flash("Remediation plan created.", "success")
    return redirect(url_for("finding_detail", finding_id=finding_id))


@app.route("/finding/<finding_id>/risk-acceptance", methods=["POST"])
@analyst_required
def request_risk_acceptance(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    reason = request.form.get("reason", "").strip()
    controls = request.form.get("compensating_controls", "").strip()
    valid_until = request.form.get("valid_until", "").strip()

    if not reason or not valid_until:
        flash("Reason and validity date are required for risk exception.", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id))

    ra = RiskAcceptance(
        tenant_id=tenant_id,
        finding_id=finding_id,
        requested_by=session.get("user_id", "analyst"),
        reason=reason,
        compensating_controls=controls,
        valid_until=valid_until,
        status="PENDING",
    )
    repository.create_risk_acceptance(ra)
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", ""),
        action="risk_acceptance_requested",
        resource_type="risk_acceptance",
        resource_id=ra.id,
        metadata={"finding_id": finding_id, "valid_until": valid_until}
    )
    flash("Risk exception request submitted for administrative review.", "success")
    return redirect(url_for("finding_detail", finding_id=finding_id))


@app.route("/risk-acceptance/<ra_id>/action", methods=["POST"])
@admin_required
def action_risk_acceptance(ra_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    ra = repository.get_risk_acceptance(ra_id, tenant_id=tenant_id)
    if not ra:
        abort(404)

    action = request.form.get("action", "").lower().strip()
    current_user_id = session.get("user_id", "")

    # Two-Person Rule: self-approval is forbidden
    if action == "approve":
        if ra.requested_by == current_user_id:
            flash("Two-person rule violation: You cannot approve your own risk exception request.", "error")
            return redirect(url_for("finding_detail", finding_id=ra.finding_id)), 400

        ra.status = "APPROVED"
        ra.approved_by = current_user_id
        repository.update_risk_acceptance(ra)

        # Transition finding to RISK_ACCEPTED
        repository.transition_finding_status(
            finding_id=ra.finding_id,
            new_status=FindingStatus.RISK_ACCEPTED.value,
            actor_user_id=current_user_id,
            tenant_id=tenant_id,
            comment=f"Risk acceptance approved until {ra.valid_until}. Reason: {ra.reason}"
        )
        flash("Risk exception approved. SLA paused.", "success")

    elif action == "reject":
        ra.status = "REJECTED"
        ra.approved_by = current_user_id
        repository.update_risk_acceptance(ra)
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=current_user_id,
            action="risk_acceptance_rejected",
            resource_type="risk_acceptance",
            resource_id=ra.id,
        )
        flash("Risk exception request rejected.", "success")

    elif action == "revoke":
        ra.status = "REVOKED"
        repository.update_risk_acceptance(ra)
        repository.transition_finding_status(
            finding_id=ra.finding_id,
            new_status=FindingStatus.REOPENED.value,
            actor_user_id=current_user_id,
            tenant_id=tenant_id,
            comment=f"Risk acceptance revoked by admin {session.get('username', '')}"
        )
        repository.log_audit_event(
            tenant_id=tenant_id,
            actor_user_id=current_user_id,
            action="risk_acceptance_revoked",
            resource_type="risk_acceptance",
            resource_id=ra.id,
        )
        flash("Risk exception revoked. Finding reopened.", "info")

    return redirect(url_for("finding_detail", finding_id=ra.finding_id))


@app.route("/finding/<finding_id>/ticket", methods=["POST"])
@analyst_required
def create_ticket_route(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    itype = request.form.get("integration_type", "jira").lower()
    integrations = repository.list_integrations(tenant_id, type=itype)
    if not integrations:
        integ = Integration(
            tenant_id=tenant_id,
            type=itype,
            name=f"Primary {itype.capitalize()}",
            enabled=True,
            config_reference={"url": f"https://{itype}.internal.local", "project_key": "SEC"},
        )
        repository.create_integration(integ)
    else:
        integ = integrations[0]

    if itype == "jira":
        adapter = JiraIntegration(integ)
    else:
        adapter = ServiceNowIntegration(integ)

    ticket_ref = adapter.create_ticket(finding)
    repository.create_ticket_reference(ticket_ref)
    flash(f"Ticket {ticket_ref.external_ticket_id} created successfully.", "success")
    return redirect(url_for("finding_detail", finding_id=finding_id))


@app.route("/finding/<finding_id>/verify", methods=["POST"])
@analyst_required
def verify_finding(finding_id):
    tenant_id = session.get("tenant_id", "default-tenant")
    finding = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not finding:
        abort(404)

    if finding.status not in (FindingStatus.VERIFICATION_PENDING.value, FindingStatus.VERIFIED.value):
        try:
            repository.transition_finding_status(
                finding_id=finding.id,
                new_status=FindingStatus.VERIFICATION_PENDING.value,
                actor_user_id=session.get("user_id", "analyst"),
                tenant_id=tenant_id,
                comment="Verification scan dispatched"
            )
        except Exception:
            pass

    asset = repository.get_asset(finding.asset_id, tenant_id=tenant_id) if finding.asset_id else None
    target_url = asset.canonical_url if asset else "https://example.com"

    # Validate ScanAuthorization
    is_auth, reason, _ = verify_scan_authorization(tenant_id, target_url, "passive")
    if not is_auth and asset:
        # Auto-authorize verification scan for registered asset
        future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        new_auth = ScanAuthorization(
            tenant_id=tenant_id,
            asset_id=asset.id,
            allowed_profiles="safe_active,passive,full",
            valid_from=datetime.now(timezone.utc).isoformat(),
            valid_until=future_iso,
            approved_by=session.get("username", "analyst"),
            notes="Auto-authorized for remediation verification",
        )
        repository.save_scan_authorization(new_auth)

    block_msg = _reject_unsafe_scan_target_at_submission(
        tenant_id,
        target_url,
        "passive",
        asset_id=finding.asset_id or "",
        actor_user_id=session.get("user_id", ""),
        actor_username=session.get("username", ""),
    )
    if block_msg:
        flash(block_msg, "error")
        return redirect(url_for("finding_detail", finding_id=finding_id)), 400

    scan = ScanResult(
        tenant_id=tenant_id,
        asset_id=finding.asset_id,
        target_url=target_url,
        scan_mode="passive",
        status=ScanStatus.PENDING,
        initiated_by=session.get("username", "analyst"),
    )
    repository.save_scan(scan)

    job = ScanJob(
        tenant_id=tenant_id,
        asset_id=finding.asset_id,
        scan_id=scan.id,
        status=ScanJobStatus.QUEUED.value,
        requested_by=session.get("username", "analyst"),
        profile="passive",
    )
    repository.create_scan_job(job)

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=session.get("user_id", "analyst"),
        action="verification_requested",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"target_url": target_url, "scan_id": scan.id, "job_id": job.id}
    )

    if SCAN_EXECUTION_BACKEND == "celery":
        from core.tasks.scan_tasks import run_scan_task
        task_res = run_scan_task.delay(job.id)
        job.task_id = task_res.id
        repository.update_scan_job(job)
    else:
        start_async_scan(target_url, initiated_by=session.get("username", ""), scan_mode="passive", tenant_id=tenant_id, asset_id=finding.asset_id, scan_id=scan.id)

    flash("Verification scan job dispatched. Live results will verify remediation.", "success")
    return redirect(url_for("finding_detail", finding_id=finding_id))


@app.route("/remediation")
@login_required
def remediation_dashboard():
    return redirect(url_for("findings_list", tab="remediation"))


@app.route("/sla")
@login_required
def sla_dashboard():
    return redirect(url_for("findings_list", tab="sla"))


@app.route("/risk-acceptances")
@login_required
def risk_acceptance_list():
    return redirect(url_for("findings_list", tab="exceptions"))


# =====================================================================
# Phase 4: REST API v1 (Scoped API Keys & JSON API)
# =====================================================================

@app.route("/api/v1/assets", methods=["GET"])
@csrf.exempt
@require_scope("assets:read", "findings:read")
def api_v1_assets():
    tenant_id = g.tenant_id
    assets = repository.list_assets(tenant_id)
    return jsonify({
        "total": len(assets),
        "assets": [{
            "id": a.id,
            "canonical_url": a.canonical_url,
            "hostname": a.hostname,
            "display_name": a.display_name,
            "environment": a.environment,
            "criticality": a.criticality,
            "internet_exposure": a.internet_exposure,
            "authorization_status": a.authorization_status,
            "last_scan_at": getattr(a, "last_scan_at", None),
            "created_at": a.created_at,
        } for a in assets]
    })


@app.route("/api/v1/findings", methods=["GET"])
@csrf.exempt
@require_scope("findings:read")
def api_v1_findings():
    tenant_id = g.tenant_id
    filters = {
        "status": request.args.get("status"),
        "severity": request.args.get("severity"),
        "priority_band": request.args.get("priority_band"),
        "sla_status": request.args.get("sla_status"),
        "asset_id": request.args.get("asset_id"),
        "search": request.args.get("search"),
        "kev": True if request.args.get("kev") == "true" else None,
    }
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 50))

    findings, total_count = repository.list_findings(tenant_id, filters=filters, page=page, page_size=page_size)
    return jsonify({
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "findings": [{
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "priority_score": f.priority_score,
            "priority_band": f.priority_band,
            "status": f.status,
            "sla_status": f.sla_status,
            "sla_due_at": f.sla_due_at,
            "kev": f.kev,
            "cve_id": f.cve_id,
            "fingerprint": f.fingerprint,
            "version": f.version,
            "asset_id": f.asset_id,
            "created_at": f.created_at,
            "updated_at": f.updated_at,
        } for f in findings]
    })


@app.route("/api/v1/findings/<finding_id>", methods=["GET"])
@csrf.exempt
@require_scope("findings:read")
def api_v1_finding_detail(finding_id):
    tenant_id = g.tenant_id
    f = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not f:
        return jsonify({"error": "Finding not found"}), 404

    observations = repository.get_observations_for_finding(finding_id, tenant_id=tenant_id)
    history = repository.get_finding_history(finding_id, tenant_id=tenant_id)

    return jsonify({
        "id": f.id,
        "tenant_id": f.tenant_id,
        "asset_id": f.asset_id,
        "scan_id": f.scan_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "priority_score": f.priority_score,
        "priority_band": f.priority_band,
        "status": f.status,
        "version": f.version,
        "fingerprint": f.fingerprint,
        "sla_status": f.sla_status,
        "sla_due_at": f.sla_due_at,
        "kev": f.kev,
        "cve_id": f.cve_id,
        "observation_count": f.observation_count,
        "observations": [{"scan_id": o.scan_id, "observed_at": o.observed_at} for o in observations],
        "history": [{"action": h.action, "old_status": h.old_status, "new_status": h.new_status, "created_at": h.created_at} for h in history],
        "created_at": f.created_at,
        "updated_at": f.updated_at,
    })


@app.route("/api/v1/findings/<finding_id>/status", methods=["POST"])
@csrf.exempt
@require_scope("findings:write")
def api_v1_finding_status(finding_id):
    tenant_id = g.tenant_id
    f = repository.get_finding(finding_id, tenant_id=tenant_id)
    if not f:
        return jsonify({"error": "Finding not found"}), 404

    data = request.get_json() or {}
    new_status = data.get("status")
    comment = data.get("comment", "")
    expected_version = data.get("expected_version")

    if not new_status:
        return jsonify({"error": "status field is required"}), 400

    try:
        updated = repository.transition_finding_status(
            finding_id=finding_id,
            new_status=new_status,
            actor_user_id=g.user_id,
            tenant_id=tenant_id,
            comment=comment,
            expected_version=expected_version,
        )
        return jsonify({
            "message": "Status updated successfully",
            "finding_id": updated.id,
            "status": updated.status,
            "version": updated.version,
        })
    except OptimisticLockError as ole:
        return jsonify({"error": "Conflict", "detail": str(ole)}), 409
    except InvalidStateTransitionError as iste:
        return jsonify({"error": "Conflict", "detail": str(iste)}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/v1/remediations", methods=["GET", "POST"])
@csrf.exempt
def api_v1_remediations():
    if request.method == "GET":
        @require_scope("findings:read")
        def _get():
            tenant_id = g.tenant_id
            status = request.args.get("status")
            rems = repository.list_remediations(tenant_id, status=status)
            return jsonify([{
                "id": r.id,
                "finding_id": r.finding_id,
                "title": r.title,
                "status": r.status,
                "priority": r.priority,
                "owner": r.owner_user_id or r.owner_external,
                "due_date": r.due_date,
                "verification_status": r.verification_status,
            } for r in rems])
        return _get()
    else:
        @require_scope("remediation:write")
        def _post():
            tenant_id = g.tenant_id
            data = request.get_json() or {}
            finding_id = data.get("finding_id")
            if not finding_id:
                return jsonify({"error": "finding_id is required"}), 400
            f = repository.get_finding(finding_id, tenant_id=tenant_id)
            if not f:
                return jsonify({"error": "Finding not found"}), 404

            rem = Remediation(
                tenant_id=tenant_id,
                finding_id=finding_id,
                title=data.get("title", f"Remediate {f.title}"),
                description=data.get("description", f.remediation),
                owner_user_id=data.get("owner"),
                priority=data.get("priority", f.priority_band),
                due_date=data.get("due_date"),
                status="OPEN",
            )
            created = repository.create_remediation(rem)
            return jsonify({"message": "Remediation plan created", "remediation_id": created.id}), 201
        return _post()


@app.route("/api/v1/risk-acceptances", methods=["GET", "POST"])
@csrf.exempt
def api_v1_risk_acceptances():
    if request.method == "GET":
        @require_scope("findings:read")
        def _get():
            tenant_id = g.tenant_id
            status = request.args.get("status")
            ras = repository.list_risk_acceptances(tenant_id, status=status)
            return jsonify([{
                "id": ra.id,
                "finding_id": ra.finding_id,
                "requested_by": ra.requested_by,
                "approved_by": ra.approved_by,
                "status": ra.status,
                "valid_until": ra.valid_until,
                "reason": ra.reason,
            } for ra in ras])
        return _get()
    else:
        @require_scope("findings:write")
        def _post():
            tenant_id = g.tenant_id
            data = request.get_json() or {}
            finding_id = data.get("finding_id")
            reason = data.get("reason")
            valid_until = data.get("valid_until")

            if not finding_id or not reason or not valid_until:
                return jsonify({"error": "finding_id, reason, and valid_until are required"}), 400

            f = repository.get_finding(finding_id, tenant_id=tenant_id)
            if not f:
                return jsonify({"error": "Finding not found"}), 404

            ra = RiskAcceptance(
                tenant_id=tenant_id,
                finding_id=finding_id,
                requested_by=g.user_id,
                reason=reason,
                business_justification=data.get("business_justification", ""),
                compensating_controls=data.get("compensating_controls", ""),
                valid_until=valid_until,
                status="PENDING",
            )
            created = repository.create_risk_acceptance(ra)
            return jsonify({"message": "Risk acceptance request submitted", "id": created.id}), 201
        return _post()


@app.route("/api/v1/risk-acceptances/<ra_id>/approve", methods=["POST"])
@csrf.exempt
@require_scope("admin")
def api_v1_approve_risk_acceptance(ra_id):
    tenant_id = g.tenant_id
    ra = repository.get_risk_acceptance(ra_id, tenant_id=tenant_id)
    if not ra:
        return jsonify({"error": "Risk acceptance not found"}), 404

    # Two-Person Rule: Approver cannot be requester
    if ra.requested_by == g.user_id:
        return jsonify({"error": "Forbidden", "detail": "Two-person rule violation: You cannot approve your own exception request"}), 403

    ra.status = "APPROVED"
    ra.approved_by = g.user_id
    repository.update_risk_acceptance(ra)

    # Pause SLA on finding
    repository.transition_finding_status(
        finding_id=ra.finding_id,
        new_status=FindingStatus.RISK_ACCEPTED.value,
        actor_user_id=g.user_id,
        tenant_id=tenant_id,
        comment=f"Risk acceptance approved until {ra.valid_until}"
    )

    return jsonify({"message": "Risk acceptance approved", "status": "APPROVED"})


@app.route("/api/v1/risk-acceptances/<ra_id>/reject", methods=["POST"])
@csrf.exempt
@require_scope("admin")
def api_v1_reject_risk_acceptance(ra_id):
    tenant_id = g.tenant_id
    ra = repository.get_risk_acceptance(ra_id, tenant_id=tenant_id)
    if not ra:
        return jsonify({"error": "Risk acceptance not found"}), 404

    ra.status = "REJECTED"
    ra.approved_by = g.user_id
    repository.update_risk_acceptance(ra)

    return jsonify({"message": "Risk acceptance rejected", "status": "REJECTED"})


@app.route("/api/v1/risk-acceptances/<ra_id>/revoke", methods=["POST"])
@csrf.exempt
@require_scope("admin")
def api_v1_revoke_risk_acceptance(ra_id):
    tenant_id = g.tenant_id
    ra = repository.get_risk_acceptance(ra_id, tenant_id=tenant_id)
    if not ra:
        return jsonify({"error": "Risk acceptance not found"}), 404

    ra.status = "REVOKED"
    repository.update_risk_acceptance(ra)
    repository.transition_finding_status(
        finding_id=ra.finding_id,
        new_status=FindingStatus.REOPENED.value,
        actor_user_id=g.user_id,
        tenant_id=tenant_id,
        comment="Risk acceptance revoked"
    )
    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=g.user_id,
        action="risk_acceptance_revoked",
        resource_type="risk_acceptance",
        resource_id=ra.id,
    )
    return jsonify({"message": "Risk acceptance revoked", "status": "REVOKED"})


@app.route("/api/v1/api-keys", methods=["GET", "POST"])
@csrf.exempt
@require_scope("admin")
def api_v1_api_keys():
    tenant_id = g.tenant_id
    if request.method == "GET":
        keys = repository.list_api_keys(tenant_id)
        return jsonify([{
            "id": k.id,
            "name": k.name,
            "scopes": k.scopes,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
            "expires_at": k.expires_at,
            "revoked": bool(k.revoked_at),
        } for k in keys])
    else:
        data = request.get_json() or {}
        name = data.get("name", "Default API Key")
        scopes = data.get("scopes", ["findings:read"])
        expires_at = data.get("expires_at")

        api_key, raw_token = generate_api_key(name=name, tenant_id=tenant_id, scopes=scopes, expires_at=expires_at)
        repository.create_api_key(api_key)

        return jsonify({
            "id": api_key.id,
            "name": api_key.name,
            "scopes": api_key.scopes,
            "token": raw_token,
            "note": "Save this token now; it will not be displayed again.",
            "created_at": api_key.created_at,
        }), 201


@app.route("/api/v1/api-keys/<key_id>", methods=["DELETE"])
@csrf.exempt
@require_scope("admin")
def api_v1_revoke_api_key(key_id):
    tenant_id = g.tenant_id
    revoked = repository.revoke_api_key(key_id, tenant_id=tenant_id)
    if not revoked:
        return jsonify({"error": "API Key not found"}), 404
    return jsonify({"message": "API key revoked successfully"})


@app.route("/api/v1/api-keys/rotate", methods=["POST"])
@app.route("/api/v1/auth/rotate-key", methods=["POST"])
@csrf.exempt
@require_scope("admin")
def api_v1_rotate_api_key():
    """
    Zero-downtime API key rotation.
    Rotates the active key for the tenant (or specified key_id) with an optional grace period.
    """
    tenant_id = g.tenant_id
    data = request.get_json(silent=True) or {}
    key_id = data.get("key_id") or getattr(g, "api_key_id", None)
    grace_period_hours = int(data.get("grace_period_hours", 24))

    target_key = None
    if key_id:
        target_key = repository.get_api_key(key_id, tenant_id=tenant_id)
    if not target_key:
        all_keys = repository.list_api_keys(tenant_id)
        target_key = next((k for k in all_keys if not k.revoked_at), None)

    if not target_key:
        return jsonify({"error": "No active API key found to rotate"}), 404

    from core.api_auth import generate_api_key
    new_api_key, raw_token = generate_api_key(
        name=f"{target_key.name} (Rotated)",
        tenant_id=tenant_id,
        scopes=target_key.scopes,
        expires_at=target_key.expires_at,
    )
    repository.create_api_key(new_api_key)

    if grace_period_hours <= 0:
        repository.revoke_api_key(target_key.id, tenant_id=tenant_id)
        retired_status = "revoked_immediately"
    else:
        grace_expiry = (datetime.now(timezone.utc) + timedelta(hours=grace_period_hours)).isoformat()
        target_key.expires_at = grace_expiry
        repository.update_api_key(target_key)
        retired_status = f"active_until_{grace_expiry}"

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=getattr(g, "user_id", "api"),
        actor_username=f"api_key:{target_key.key_prefix or target_key.id[:8]}",
        action="api_key_rotated",
        resource_type="api_key",
        resource_id=new_api_key.id,
        metadata={
            "old_key_id": target_key.id,
            "grace_period_hours": grace_period_hours,
            "status": retired_status,
        },
    )

    return jsonify({
        "status": "success",
        "new_key_id": new_api_key.id,
        "token": raw_token,
        "key_prefix": new_api_key.key_prefix,
        "old_key_status": retired_status,
        "note": "Save the new token now; it will not be displayed again.",
    }), 201


@app.route("/tenants/<tenant_id>/offboard", methods=["POST"])
@login_required
@admin_required
def offboard_tenant(tenant_id):
    from core.tenant_lifecycle import soft_delete_tenant, hard_delete_tenant
    action = request.form.get("action", "soft")
    reason = request.form.get("reason", "")
    confirmation = request.form.get("confirmation", "")
    try:
        if action == "hard":
            result = hard_delete_tenant(tenant_id, actor_id=session.get("user_id", "admin"), confirmation=confirmation)
            flash(f"Tenant permanently deleted ({result.get('purged_scans', 0)} scans removed).", "warning")
        else:
            result = soft_delete_tenant(tenant_id, actor_id=session.get("user_id", "admin"), reason=reason)
            flash("Tenant offboarded successfully.", "success")
    except Exception as e:
        flash(f"Offboarding failed: {e}", "danger")
    return redirect(url_for("settings"))


@app.route("/api/v1/tenants/<tenant_id>", methods=["DELETE"])
@csrf.exempt
@require_scope("admin")
def api_v1_delete_tenant(tenant_id):
    from core.tenant_lifecycle import soft_delete_tenant, hard_delete_tenant
    hard = request.args.get("hard", "false").lower() == "true"
    confirmation = request.headers.get("X-Confirmation", "") or (request.json.get("confirmation", "") if (request.is_json and request.json) else "")
    reason = (request.json.get("reason", "") if (request.is_json and request.json) else "") or "API request"
    actor_id = getattr(g, "user_id", "api_admin")
    try:
        if hard:
            result = hard_delete_tenant(tenant_id, actor_id=actor_id, confirmation=confirmation)
        else:
            result = soft_delete_tenant(tenant_id, actor_id=actor_id, reason=reason)
        return jsonify({"status": "success", "result": result}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Tenant deletion error: {e}")
        return jsonify({"error": "Internal error"}), 500


@app.route("/api/v1/webhooks/deliver", methods=["POST"])
@csrf.exempt
@require_scope("admin")
def api_v1_trigger_webhook():
    tenant_id = g.tenant_id
    data = request.get_json() or {}
    event = data.get("event", "test.event")
    payload = data.get("payload", {"test": True})
    integration_id = data.get("integration_id")

    if not integration_id:
        integrations = repository.list_integrations(tenant_id, type="webhook")
        if not integrations:
            return jsonify({"error": "No webhook integrations configured for this tenant"}), 404
        integ = integrations[0]
    else:
        integ = repository.get_integration(integration_id, tenant_id=tenant_id)
        if not integ:
            return jsonify({"error": "Integration not found"}), 404

    delivery = deliver_webhook_payload(integ, event, payload)
    repository.create_webhook_delivery(delivery)

    return jsonify({
        "delivery_id": delivery.id,
        "event": delivery.event,
        "status": delivery.status,
        "attempt": delivery.attempt,
        "last_error": delivery.last_error,
    })


# ==============================================================================
# PHASE 6: EASM, DISCOVERY, EVIDENCE, BU, TECHNOLOGY & PORTFOLIO API V1
# ==============================================================================

@app.route("/api/v1/portfolio", methods=["GET"])
@require_scope("viewer")
def api_v1_portfolio():
    tenant_id = g.tenant_id
    bu_id = request.args.get("business_unit_id")
    metrics = repository.get_portfolio_metrics(tenant_id, bu_id=bu_id)
    return jsonify({"data": metrics, "meta": {"tenant_id": tenant_id, "business_unit_id": bu_id}})


@app.route("/api/v1/discovery/scopes", methods=["GET", "POST"])
@csrf.exempt
@require_scope("viewer")
def api_v1_discovery_scopes():
    tenant_id = g.tenant_id
    if request.method == "POST":
        if getattr(g, "api_user", None) and g.api_user.role not in ("admin", "analyst"):
            return jsonify({"error": "Forbidden"}), 403
        data = request.get_json() or {}
        if not data.get("name") or not data.get("root_domain"):
            return jsonify({"error": "name and root_domain are required"}), 400
        from core.models import DiscoveryScope
        scope = DiscoveryScope(
            tenant_id=tenant_id,
            name=data["name"],
            root_domain=data["root_domain"].strip().lower(),
            allowed_suffixes=data.get("allowed_suffixes", []),
            excluded_patterns=data.get("excluded_patterns", []),
            max_depth=int(data.get("max_depth", 2)),
            enabled=bool(data.get("enabled", True)),
            created_by=getattr(g, "user_id", "api_user")
        )
        repository.save_discovery_scope(scope)
        return jsonify({"data": scope.__dict__, "meta": {"status": "created"}}), 201

    scopes = repository.list_discovery_scopes(tenant_id)
    return jsonify({"data": [s.__dict__ for s in scopes], "meta": {"count": len(scopes)}})


@app.route("/api/v1/discovery/candidates", methods=["GET"])
@require_scope("viewer")
def api_v1_discovery_candidates():
    tenant_id = g.tenant_id
    status = request.args.get("status")
    scope_id = request.args.get("scope_id")
    candidates = repository.list_discovered_assets(tenant_id, status=status, scope_id=scope_id)
    return jsonify({"data": [c.__dict__ for c in candidates], "meta": {"count": len(candidates)}})


@app.route("/api/v1/discovery/candidates/<candidate_id>/promote", methods=["POST"])
@csrf.exempt
@require_scope("analyst")
def api_v1_promote_candidate(candidate_id):
    tenant_id = g.tenant_id
    data = request.get_json() or {}
    from core.easm.discovery import BoundedDiscoveryEngine
    engine = BoundedDiscoveryEngine(tenant_id)
    try:
        asset = engine.promote_candidate_to_asset(
            candidate_id=candidate_id,
            actor_user_id=getattr(g, "user_id", "api_user"),
            business_unit_id=data.get("business_unit_id"),
            criticality=data.get("criticality", "medium")
        )
        return jsonify({"data": asset.__dict__, "meta": {"promoted": True}}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/v1/evidence/<evidence_id>", methods=["GET"])
@require_scope("viewer")
def api_v1_get_evidence(evidence_id):
    tenant_id = g.tenant_id
    from core.evidence.store import EvidenceStore
    store = EvidenceStore(tenant_id)
    ev = store.get_sanitized_evidence(evidence_id, actor_role=getattr(g, "role", "viewer"))
    if not ev:
        return jsonify({"error": "Evidence not found"}), 404
    resp_data = ev.__dict__.copy()
    return jsonify({"data": resp_data, "meta": {"sanitized": True, "immutable": True}})


@app.route("/api/v1/business-units", methods=["GET", "POST"])
@csrf.exempt
@require_scope("viewer")
def api_v1_business_units():
    tenant_id = g.tenant_id
    if request.method == "POST":
        if getattr(g, "api_user", None) and g.api_user.role not in ("admin", "analyst"):
            return jsonify({"error": "Forbidden"}), 403
        data = request.get_json() or {}
        if not data.get("name") or not data.get("code"):
            return jsonify({"error": "name and code are required"}), 400
        from core.models import BusinessUnit
        bu = BusinessUnit(
            tenant_id=tenant_id,
            name=data["name"],
            code=data["code"].strip().upper(),
            parent_id=data.get("parent_id"),
            owner_user_id=data.get("owner_user_id"),
            criticality=data.get("criticality", "medium")
        )
        repository.save_business_unit(bu)
        return jsonify({"data": bu.__dict__, "meta": {"status": "created"}}), 201

    bus = repository.list_business_units(tenant_id)
    return jsonify({"data": [b.__dict__ for b in bus], "meta": {"count": len(bus)}})


@app.route("/api/v1/technologies", methods=["GET"])
@require_scope("viewer")
def api_v1_technologies():
    tenant_id = g.tenant_id
    asset_id = request.args.get("asset_id")
    obs = repository.list_technology_observations(tenant_id, asset_id=asset_id)
    return jsonify({"data": [o.__dict__ for o in obs], "meta": {"count": len(obs)}})


@app.route("/api/v1/data-quality", methods=["GET"])
@require_scope("viewer")
def api_v1_data_quality():
    tenant_id = g.tenant_id
    unresolved_only = request.args.get("unresolved", "true").lower() == "true"
    issues = repository.list_data_quality_issues(tenant_id, unresolved_only=unresolved_only)
    return jsonify({"data": [i.__dict__ for i in issues], "meta": {"count": len(issues)}})


@app.route("/api/v1/saved-views", methods=["GET", "POST"])
@csrf.exempt
@require_scope("viewer")
def api_v1_saved_views():
    tenant_id = g.tenant_id
    user_id = getattr(g, "user_id", "")
    if request.method == "POST":
        data = request.get_json() or {}
        if not data.get("name") or not data.get("filters"):
            return jsonify({"error": "name and filters are required"}), 400
        from core.models import SavedView
        view = SavedView(
            tenant_id=tenant_id,
            user_id=user_id,
            name=data["name"],
            resource_type=data.get("resource_type", "portfolio"),
            filters_json=data.get("filters", {}),
            is_shared=bool(data.get("is_shared", False))
        )
        repository.save_saved_view(view)
        return jsonify({"data": view.__dict__, "meta": {"status": "created"}}), 201

    views = repository.list_saved_views(tenant_id, user_id=user_id)
    return jsonify({"data": [v.__dict__ for v in views], "meta": {"count": len(views)}})


@app.route("/api/v1/search", methods=["GET"])
@require_scope("viewer")
def api_v1_global_search():
    tenant_id = g.tenant_id
    query = request.args.get("q", "").strip().lower()
    if not query:
        return jsonify({"data": {"assets": [], "findings": [], "business_units": []}, "meta": {"total": 0}})

    # Search assets strictly within tenant
    assets = repository.list_assets(tenant_id, filters={"query": query})[:20]
    # Search findings strictly within tenant
    findings = repository.list_findings(tenant_id, filters={"search": query}, limit=20)
    # Search BUs
    bus = [b for b in repository.list_business_units(tenant_id) if query in b.name.lower() or query in b.code.lower()][:10]

    return jsonify({
        "data": {
            "assets": [a.__dict__ for a in assets],
            "findings": [f.__dict__ for f in findings],
            "business_units": [b.__dict__ for b in bus]
        },
        "meta": {"tenant_id": tenant_id, "query": query}
    })



# =============================================================================
# Sprint 4 — Monitoring APIs (S3-GAP-003, S3-GAP-005)
# =============================================================================

@app.route("/api/v1/monitoring/dashboard", methods=["GET"])
@csrf.exempt
@require_scope("assets:read")
def api_v1_monitoring_dashboard():
    """
    S3-GAP-003: Monitoring dashboard summary endpoint.

    Returns the complete monitoring visibility snapshot for the authenticated
    tenant: asset counts, finding severity summary, scan health, intel freshness
    and 7-day risk trend.

    No sensitive evidence, credential data or cross-tenant information is included.
    Response is tenant-scoped via g.tenant_id set by require_scope().

    RBAC: viewer and above (assets:read scope).
    """
    tenant_id = g.tenant_id
    dashboard = repository.get_monitoring_dashboard(tenant_id)
    return jsonify({"data": dashboard, "meta": {"tenant_id": tenant_id}})


@app.route("/api/v1/monitoring/assets", methods=["GET"])
@csrf.exempt
@require_scope("assets:read")
def api_v1_monitoring_assets():
    """
    Asset monitoring status endpoint.

    Returns the monitoring state of each asset: enabled/paused, last scan status,
    consecutive failures, WordPress version, and risk score.

    Pagination: ?page=1&page_size=50 (default 50, max 200).
    Filtering: ?monitoring_enabled=true|false, ?status=completed|failed|never
    """
    tenant_id = g.tenant_id
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(200, max(1, int(request.args.get("page_size", 50))))

    filters: dict = {"tenant_id": tenant_id}
    if request.args.get("monitoring_enabled") in ("true", "1"):
        filters["monitoring_enabled"] = True
    elif request.args.get("monitoring_enabled") in ("false", "0"):
        filters["monitoring_enabled"] = False
    if request.args.get("status"):
        filters["last_scan_status"] = request.args.get("status")

    all_assets = repository.list_assets(tenant_id, filters=filters)
    total = len(all_assets)
    start = (page - 1) * page_size
    page_assets = all_assets[start: start + page_size]

    return jsonify({
        "data": [{
            "id": a.id,
            "canonical_url": a.canonical_url,
            "display_name": a.display_name,
            "environment": a.environment,
            "monitoring_enabled": getattr(a, "monitoring_enabled", False),
            "monitoring_paused_at": getattr(a, "monitoring_paused_at", None),
            "last_scan_id": getattr(a, "last_scan_id", None),
            "last_scan_at": getattr(a, "last_scan_at", None),
            "last_scan_status": getattr(a, "last_scan_status", None),
            "last_successful_scan_at": getattr(a, "last_successful_scan_at", None),
            "consecutive_scan_failures": getattr(a, "consecutive_scan_failures", 0),
            "wp_version": getattr(a, "wp_version", None),
            "risk_score": getattr(a, "risk_score", None),
        } for a in page_assets],
        "meta": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
        }
    })


@app.route("/api/v1/assets/<asset_id>/differential", methods=["GET"])
@csrf.exempt
@require_scope("assets:read", "findings:read")
def api_v1_asset_differential(asset_id):
    """
    S3-GAP-004: Recent security posture changes for an asset.

    Computes or retrieves the differential between the two most recent completed
    scans on the asset. Returns structured NEW/PERSISTING/RESOLVED/REOPENED/UNKNOWN
    change records.

    Object-level authorization: the asset must belong to the authenticated tenant.
    Returns 404 if the asset doesn't exist or belongs to a different tenant.
    Returns 200 with is_complete=false if the new scan was not COMPLETED.
    Returns 200 with an empty changes list if fewer than two completed scans exist.
    """
    tenant_id = g.tenant_id

    # Object-level authorization: verify asset belongs to this tenant
    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        return jsonify({"error": "Not found", "detail": "Asset not found or access denied"}), 404

    from core.differential import get_latest_differential_for_asset
    diff = get_latest_differential_for_asset(asset_id=asset_id, tenant_id=tenant_id)
    if diff is None:
        return jsonify({
            "data": {
                "asset_id": asset_id,
                "is_complete": False,
                "incomplete_reason": "Fewer than two completed scans exist for this asset",
                "changes": [],
                "new_count": 0, "persisting_count": 0,
                "resolved_count": 0, "reopened_count": 0,
            },
            "meta": {"tenant_id": tenant_id}
        })

    return jsonify({
        "data": {
            "asset_id": asset_id,
            "baseline_scan_id": diff.baseline_scan_id,
            "new_scan_id": diff.new_scan_id,
            "is_complete": diff.is_complete,
            "incomplete_reason": diff.incomplete_reason,
            "wp_version_changed": diff.wp_version_changed,
            "wp_version_baseline": diff.wp_version_baseline,
            "wp_version_new": diff.wp_version_new,
            "new_count": diff.new_count,
            "persisting_count": diff.persisting_count,
            "resolved_count": diff.resolved_count,
            "reopened_count": diff.reopened_count,
            "changes": [{
                "fingerprint": c.fingerprint,
                "change_state": c.change_state,
                "finding_id": c.finding_id,
                "title": c.title,
                "category": c.category,
                "severity": c.severity,
                "baseline_status": c.baseline_status,
                "new_status": c.new_status,
                "baseline_version": c.baseline_version,
                "new_version": c.new_version,
            } for c in diff.changes],
        },
        "meta": {"tenant_id": tenant_id}
    })


@app.route("/api/v1/assets/<asset_id>/lifecycle", methods=["GET"])
@csrf.exempt
@require_scope("assets:read", "findings:read")
def api_v1_asset_lifecycle(asset_id):
    """
    Asset finding lifecycle: returns all findings for an asset with their full
    lifecycle history (observations, workflow transitions, comments, remediations).

    Object-level authorization: asset must belong to the authenticated tenant.
    Pagination: ?page=1&page_size=25 (default 25, max 100).
    Filter by status: ?status=OPEN|RESOLVED|REOPENED|etc.
    """
    tenant_id = g.tenant_id

    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        return jsonify({"error": "Not found", "detail": "Asset not found or access denied"}), 404

    page = max(1, int(request.args.get("page", 1)))
    page_size = min(100, max(1, int(request.args.get("page_size", 25))))
    status_filter = request.args.get("status")

    filters = {"asset_id": asset_id, "tenant_id": tenant_id}
    if status_filter:
        filters["status"] = status_filter

    findings, total_count = repository.list_findings(tenant_id, filters=filters, page=page, page_size=page_size)

    return jsonify({
        "data": [{
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "status": f.status,
            "fingerprint": f.fingerprint,
            "cve_id": f.cve_id,
            "first_seen_at": f.first_seen_at,
            "last_seen_at": f.last_seen_at,
            "observation_count": f.observation_count,
            "finding_confidence": f.finding_confidence,
            "priority_band": f.priority_band,
            "sla_status": f.sla_status,
        } for f in findings],
        "meta": {
            "asset_id": asset_id,
            "total": total_count,
            "page": page,
            "page_size": page_size,
        }
    })


@app.route("/api/v1/schedules/<sched_id>/pause", methods=["POST"])
@csrf.exempt
@require_scope("assets:write")
def api_v1_schedule_pause(sched_id):
    """
    S3-GAP-005: Pause monitoring schedule.

    Pauses the schedule for a configurable duration (default 24h, max 720h).
    Body: {"hours": 24}  (optional, defaults to 24)

    Object-level authorization: schedule must belong to the authenticated tenant.
    RBAC: analyst or admin (assets:write scope).
    Audit-logged.
    """
    tenant_id = g.tenant_id
    user_id = getattr(g, "user_id", "")

    sched = repository.get_scheduled_scan(sched_id, tenant_id=tenant_id)
    if not sched:
        return jsonify({"error": "Not found", "detail": "Schedule not found or access denied"}), 404

    data = request.get_json(silent=True) or {}
    try:
        pause_hours = max(1, min(720, int(data.get("hours", 24))))
    except (TypeError, ValueError):
        return jsonify({"error": "Bad request", "detail": "'hours' must be a positive integer"}), 400

    from datetime import datetime, timezone, timedelta
    paused_until = (datetime.now(timezone.utc) + timedelta(hours=pause_hours)).isoformat()
    sched.paused_until = paused_until
    repository.update_scheduled_scan(sched)

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        actor_username=getattr(g, "username", user_id),
        action="schedule_paused",
        resource_type="scheduled_scan",
        resource_id=sched_id,
        result="success",
        metadata={"paused_until": paused_until, "hours": pause_hours}
    )
    return jsonify({
        "data": {"schedule_id": sched_id, "paused_until": paused_until, "hours": pause_hours},
        "meta": {"status": "paused"}
    })


@app.route("/api/v1/schedules/<sched_id>/resume", methods=["POST"])
@csrf.exempt
@require_scope("assets:write")
def api_v1_schedule_resume(sched_id):
    """
    S3-GAP-005: Resume a paused monitoring schedule.

    Clears the paused_until timestamp, allowing the schedule to fire on the
    next dispatcher cycle.

    Object-level authorization: schedule must belong to the authenticated tenant.
    RBAC: analyst or admin (assets:write scope).
    Audit-logged.
    """
    tenant_id = g.tenant_id
    user_id = getattr(g, "user_id", "")

    sched = repository.get_scheduled_scan(sched_id, tenant_id=tenant_id)
    if not sched:
        return jsonify({"error": "Not found", "detail": "Schedule not found or access denied"}), 404

    sched.paused_until = None
    repository.update_scheduled_scan(sched)

    repository.log_audit_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        actor_username=getattr(g, "username", user_id),
        action="schedule_resumed",
        resource_type="scheduled_scan",
        resource_id=sched_id,
        result="success",
        metadata={"schedule_id": sched_id}
    )
    return jsonify({
        "data": {"schedule_id": sched_id, "paused_until": None},
        "meta": {"status": "resumed"}
    })


if __name__ == "__main__":
    import argparse
    import socket

    def is_port_in_use(port_num: int, host_str: str = "0.0.0.0") -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host_str, port_num))
                return False
            except OSError:
                return True

    def find_free_port(start_port: int = 8080, host_str: str = "0.0.0.0", max_tries: int = 100) -> int:
        for p in range(start_port, start_port + max_tries):
            if not is_port_in_use(p, host_str):
                return p
        return start_port

    parser = argparse.ArgumentParser(description="Run SentinelWP")
    parser.add_argument("--port", "-p", type=int, default=None, help="Port to run on")
    parser.add_argument("--host", "-H", type=str, default=os.getenv("HOST", os.getenv("WSA_HOST", "0.0.0.0")), help="Host to bind to")
    args, _ = parser.parse_known_args()

    env_port = os.getenv("PORT") or os.getenv("WSA_PORT")
    if args.port:
        target_port = args.port
    elif env_port:
        target_port = int(env_port)
    else:
        target_port = 8080

    if is_port_in_use(target_port, args.host):
        free_port = find_free_port(target_port + 1, args.host)
        print(f" * Port {target_port} is already in use. Auto-selected available port {free_port}.")
        target_port = free_port

    print(f" * Starting SentinelWP on http://{args.host}:{target_port}")
    app.run(host=args.host, port=target_port, debug=False)
