"""
SentinelWP - Flask Application
Modern dark-theme web UI for WordPress Security Assessment & Posture Management
"""
import os
import sys
import json
import functools
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, abort
)
import io

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, SESSION_EXPIRY_HOURS
from core import repository
from core.auth import create_user, verify_password, hash_password
from core.models import UserRole, UserStatus, ScanStatus, Severity, ScheduledScan
from core.risk_engine import compute_risk_score, compute_category_breakdown
from core.rate_limiter import rate_limiter
from core.scheduler import start_scheduler
from scanners.async_runner import start_async_scan, get_scan_progress
from scanners.orchestrator import run_scan, ALL_SCANNERS, SCAN_PROFILES
from scanners.batch_runner import run_batch
from reports.generator import (
    generate_html_report, generate_json_report,
    generate_excel_report, generate_pdf_report, generate_sarif_report,
    generate_full_db_excel_export, import_full_db_excel
)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=SESSION_EXPIRY_HOURS)


# --- Auth helpers ---
def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


_startup_sync_done = False

# --- Init & Middleware ---
@app.before_request
def ensure_db_and_scheduler():
    global _startup_sync_done
    repository.init_db()

    # Start background scheduler daemon
    try:
        start_scheduler()
    except Exception:
        pass

    # Trigger Threat Intelligence sync on app startup (once)
    if not _startup_sync_done:
        _startup_sync_done = True
        try:
            from config import VULN_INTEL_ENABLED
            if VULN_INTEL_ENABLED:
                from core.vulnerability_intelligence.service import sync_all
                import threading
                threading.Thread(target=sync_all, daemon=True).start()
        except Exception:
            pass

    # Redirect to initial setup wizard if no users exist in database
    if repository.count_users() == 0:
        if request.endpoint not in ("setup", "static"):
            return redirect(url_for("setup"))


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

        if not password or len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("setup.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("setup.html")

        # Create primary administrator
        user = create_user(
            username=username,
            password=password,
            email=email,
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        repository.save_user(user)

        # Log in automatically
        session.permanent = True
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = "admin"

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
        user = repository.get_user_by_username(username)
        if user and verify_password(password, user.password_hash):
            if user.status != UserStatus.ACTIVE:
                flash("Account is not active. Contact administrator.", "error")
                return render_template("login.html")
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role.value if hasattr(user.role, "value") else user.role
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Routes: Dashboard ---
@app.route("/")
@login_required
def dashboard():
    filters = {
        "target_url": request.args.get("target_url", "").strip(),
        "status": request.args.get("status", "").strip(),
        "scan_mode": request.args.get("scan_mode", "").strip(),
        "grade": request.args.get("grade", "").strip(),
        "is_wordpress": request.args.get("is_wordpress", "").strip(),
        "date_from": request.args.get("date_from", "").strip(),
        "date_to": request.args.get("date_to", "").strip(),
    }
    scans = repository.list_scans(limit=100, filters=filters)
    all_scans = repository.list_scans(limit=1000)
    total = len(all_scans)
    completed = len([s for s in all_scans if (s.status.value if hasattr(s.status, "value") else str(s.status)) == "completed"])
    avg_score = 0
    if completed > 0:
        scores = [s.score for s in all_scans if s.score is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
    return render_template("dashboard.html",
                           scans=scans, total=total,
                           completed=completed, avg_score=avg_score, filters=filters)


@app.route("/changelog")
@login_required
def changelog():
    return render_template("changelog.html")


@app.route("/vuln-intel")
@login_required
def vuln_intel_dashboard():
    """Vulnerability Intelligence dashboard."""
    try:
        from core.vulnerability_intelligence.service import get_status, is_stale
        from core.vulnerability_intelligence.repository import get_dashboard_stats
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
    return render_template("vuln_intel_dashboard.html", stats=stats, sync_state=status, is_stale=stale, wf_key=wf_key, nvd_key=nvd_key)


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
    """Trigger manual vulnerability intelligence synchronisation (Admin only)."""
    try:
        from core.vulnerability_intelligence.service import sync_all
        import threading
        t = threading.Thread(target=sync_all, daemon=True)
        t.start()
        flash("Vulnerability intelligence synchronisation started in background.", "success")
    except Exception as e:
        flash(f"Sync failed to start: {str(e)[:200]}", "error")
    return redirect(url_for("vuln_intel_dashboard"))


@app.route("/vuln-intel/settings", methods=["POST"])
@admin_required
def vuln_intel_save_settings():
    """Save API Keys via GUI (Admin only)."""
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


# --- Routes: New Scan ---
@app.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
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
        try:
            # Launch background async scan
            result = start_async_scan(target, initiated_by=session.get("username", ""), scan_mode=scan_mode)
            flash(f"Scan queued ({scan_mode}). Monitoring live progress...", "success")
            return redirect(url_for("scan_detail", scan_id=result.id))
        except Exception as e:
            flash(f"Scan failed: {str(e)[:200]}", "error")
    return render_template("new_scan.html")


# --- Routes: Batch Scan ---
@app.route("/scan/batch", methods=["GET", "POST"])
@login_required
def batch_scan():
    if request.method == "POST":
        targets_raw = request.form.get("targets", "").strip()
        scan_mode = request.form.get("scan_mode", "passive").strip()
        if scan_mode not in SCAN_PROFILES:
            scan_mode = "passive"
        targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
        if not targets:
            flash("Enter at least one target URL.", "error")
            return render_template("batch_scan.html")
        try:
            job = run_batch(targets, initiated_by=session.get("username", ""), scan_mode=scan_mode)
            flash(f"Batch completed ({scan_mode}): {job.completed} successful, {job.failed} failed.", "success")
            return redirect(url_for("scan_history"))
        except Exception as e:
            flash(f"Batch failed: {str(e)[:200]}", "error")
    return render_template("batch_scan.html")


# --- Routes: Scan History ---
@app.route("/scans")
@login_required
def scan_history():
    filters = {
        "target_url": request.args.get("target_url", "").strip(),
        "status": request.args.get("status", "").strip(),
        "scan_mode": request.args.get("scan_mode", "").strip(),
        "grade": request.args.get("grade", "").strip(),
        "is_wordpress": request.args.get("is_wordpress", "").strip(),
        "date_from": request.args.get("date_from", "").strip(),
        "date_to": request.args.get("date_to", "").strip(),
    }
    scans = repository.list_scans(limit=200, filters=filters)
    return render_template("scan_history.html", scans=scans, filters=filters)


@app.route("/admin/export-db")
@admin_required
def admin_export_db():
    """Export full unique scan database as a multi-sheet Excel file (Admin only)."""
    try:
        from reports.generator import generate_full_db_excel_export
        scans = repository.list_scans(limit=5000)
        for s in scans:
            s.findings = repository.get_findings_for_scan(s.id)
        excel_bytes = generate_full_db_excel_export(scans)
        filename = f"SentinelWP_Database_Export_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
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
    scan = repository.get_scan(scan_id)
    if not scan:
        abort(404)
    breakdown = compute_category_breakdown(scan.findings) if scan.findings else {}
    return render_template("scan_detail.html", scan=scan, breakdown=breakdown)


# --- Routes: Delete Scan ---
@app.route("/scan/<scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    repository.delete_scan(scan_id)
    flash("Scan deleted.", "success")
    return redirect(url_for("scan_history"))


# --- Routes: Schedules ---
@app.route("/schedules")
@login_required
def schedules():
    scheds = repository.list_scheduled_scans()
    return render_template("schedules.html", schedules=scheds)


@app.route("/schedule/create", methods=["POST"])
@login_required
def create_schedule():
    target = request.form.get("target_url", "").strip()
    scan_mode = request.form.get("scan_mode", "passive").strip()
    interval_hours = int(request.form.get("interval_hours", "24"))

    if not target:
        flash("Target URL is required.", "error")
        return redirect(url_for("schedules"))

    sched = ScheduledScan(
        target_url=target,
        scan_mode=scan_mode,
        interval_hours=interval_hours,
        created_by=session.get("username", "admin"),
        next_run_at=datetime.utcnow().isoformat()
    )
    repository.save_scheduled_scan(sched)
    flash(f"Scheduled scan created for {target} (every {interval_hours}h).", "success")
    return redirect(url_for("schedules"))


@app.route("/schedule/<sched_id>/delete", methods=["POST"])
@login_required
def delete_schedule(sched_id):
    repository.delete_scheduled_scan(sched_id)
    flash("Scheduled scan deleted.", "success")
    return redirect(url_for("schedules"))


# --- Routes: Export CSV ---
@app.route("/scans/export/csv")
@login_required
def export_scans_csv():
    import csv
    scans = repository.list_scans(limit=1000)
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    
    writer.writerow([
        "Scan ID", "Target URL", "WHOIS Info", "WordPress Version", 
        "Detected Plugins", "Findings (Titles)", "Score", "Grade", "Status", "Started At"
    ])
    
    for s in scans:
        findings = repository.get_findings_for_scan(s.id)
        
        plugins_list = []
        findings_list = []
        for f in findings:
            if f.category == "plugins":
                slug = f.raw_data.get("slug") or f.title.replace("Plugin Detected: ", "")
                ver = f.raw_data.get("version")
                plugin_str = f"{slug} (v{ver})" if ver else slug
                plugins_list.append(plugin_str)
            else:
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                findings_list.append(f"[{sev_val.upper()}] {f.title}")
                
        plugins_str = ", ".join(plugins_list) if plugins_list else "None"
        findings_str = "; ".join(findings_list) if findings_list else "None"
        
        writer.writerow([
            s.id,
            s.target_url,
            s.whois_info or "Unknown/Not Checked",
            s.wp_version or "Not Detected",
            plugins_str,
            findings_str,
            s.score if s.score is not None else "N/A",
            s.grade or "N/A",
            s.status.value if hasattr(s.status, "value") else str(s.status),
            s.started_at
        ])
        
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="sentinelwp-scans-export.csv"
    )


# --- Routes: Reports ---
@app.route("/scan/<scan_id>/report/<fmt>")
@login_required
def download_report(scan_id, fmt):
    scan = repository.get_scan(scan_id)
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


# --- Routes: Edit Finding ---
@app.route("/finding/<finding_id>/edit", methods=["POST"])
@login_required
def edit_finding(finding_id):
    data = request.form.to_dict()
    allowed = {}
    if "severity" in data:
        allowed["severity"] = data["severity"]
    if "remediation" in data:
        allowed["remediation"] = data["remediation"]
    if "title" in data:
        allowed["title"] = data["title"]
    if allowed:
        repository.update_finding(finding_id, **allowed)
        flash("Finding updated.", "success")
    return redirect(request.referrer or url_for("scan_history"))


# --- Routes: Delete Finding ---
@app.route("/finding/<finding_id>/delete", methods=["POST"])
@login_required
def delete_finding(finding_id):
    repository.delete_finding(finding_id)
    flash("Finding deleted.", "success")
    return redirect(request.referrer or url_for("scan_history"))


# --- Routes: User & System Settings Panel ---
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = repository.get_user_by_id(session.get("user_id"))
    users = repository.list_users() if session.get("role") == "admin" else []

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
                repository.update_user(user.id, password_hash=hash_password(new_pass))
                flash("Password successfully updated.", "success")
            return redirect(url_for("settings"))

    return render_template("settings.html", user=user, users=users)


@app.route("/users")
@admin_required
def user_management():
    return redirect(url_for("settings"))


@app.route("/user/create", methods=["POST"])
@admin_required
def create_user_route():
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
    repository.save_user(user)
    flash(f"User {username} created successfully.", "success")
    return redirect(url_for("settings"))


@app.route("/user/<user_id>/delete", methods=["POST"])
@admin_required
def delete_user_route(user_id):
    if user_id == session.get("user_id"):
        flash("Cannot delete your own account.", "error")
        return redirect(url_for("settings"))
    repository.delete_user(user_id)
    flash("User deleted.", "success")
    return redirect(url_for("settings"))


@app.route("/admin/import-db", methods=["POST"])
@admin_required
def admin_import_db():
    if "db_file" not in request.files:
        flash("No file selected for import.", "error")
        return redirect(url_for("settings"))
    file = request.files["db_file"]
    if not file or not file.filename.endswith(".xlsx"):
        flash("Invalid file. Please upload a valid SentinelWP Excel backup (.xlsx).", "error")
        return redirect(url_for("settings"))
    try:
        scans_count, findings_count = import_full_db_excel(file.read(), repository)
        flash(f"Database import complete! Successfully imported {scans_count} scan(s) and {findings_count} finding(s).", "success")
    except Exception as e:
        flash(f"Database import failed: {str(e)}", "error")
    return redirect(url_for("settings"))


# --- API Endpoints ---
@app.route("/api/scan/<scan_id>/status")
@login_required
def api_scan_status(scan_id):
    """Return live progress for a scan (0-100%, current step, status)."""
    return jsonify(get_scan_progress(scan_id))


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    ip = request.remote_addr or "127.0.0.1"
    allowed, retry_after = rate_limiter.is_allowed(f"api_scan:{ip}", max_requests=10, window_seconds=3600)
    if not allowed:
        return jsonify({"error": f"Rate limit reached. Retry in {retry_after} seconds."}), 429

    data = request.get_json() or {}
    target = data.get("target_url", "").strip()
    scan_mode = data.get("scan_mode", "passive").strip()
    if not target:
        return jsonify({"error": "target_url required"}), 400
    try:
        result = start_async_scan(target, initiated_by=session.get("username", ""), scan_mode=scan_mode)
        return jsonify({
            "scan_id": result.id,
            "status": "queued",
            "scan_mode": scan_mode,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scans")
@login_required
def api_scans():
    scans = repository.list_scans(limit=100)
    return jsonify([{
        "id": s.id,
        "target_url": s.target_url,
        "score": s.score,
        "grade": s.grade,
        "status": s.status.value if hasattr(s.status, "value") else s.status,
        "scan_mode": s.scan_mode,
        "started_at": s.started_at,
    } for s in scans])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
