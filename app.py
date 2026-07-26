"""
WSA Pro - Flask Application
Modern web UI with dark theme, no Streamlit dependency
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
from core.models import UserRole, UserStatus, ScanStatus, Severity
from core.risk_engine import compute_risk_score, compute_category_breakdown
from scanners.orchestrator import run_scan, ALL_SCANNERS
from scanners.batch_runner import run_batch
from reports.generator import (
    generate_html_report, generate_json_report,
    generate_excel_report, generate_pdf_report
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


# --- Init ---
@app.before_request
def ensure_db():
    repository.init_db()
    admin = repository.get_user_by_username(ADMIN_USERNAME)
    if not admin:
        user = create_user(
            username=ADMIN_USERNAME,
            password=ADMIN_PASSWORD,
            email="admin@wsa.local",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        repository.save_user(user)


# --- Routes: Auth ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
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
    scans = repository.list_scans(limit=50)
    total = len(scans)
    completed = len([s for s in scans if s.status == ScanStatus.COMPLETED])
    avg_score = 0
    if completed > 0:
        scores = [s.score for s in scans if s.score is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
    return render_template("dashboard.html",
                           scans=scans[:10], total=total,
                           completed=completed, avg_score=avg_score)


# --- Routes: New Scan ---
@app.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        target = request.form.get("target_url", "").strip()
        scan_mode = request.form.get("scan_mode", "passive").strip()
        if scan_mode not in ("passive", "safe-active", "full"):
            scan_mode = "passive"
        if not target:
            flash("Please enter a target URL.", "error")
            return render_template("new_scan.html")
        try:
            result = run_scan(target, initiated_by=session.get("username", ""), scan_mode=scan_mode)
            flash(f"Scan completed ({scan_mode}). Score: {result.score} ({result.grade})", "success")
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
        targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
        if not targets:
            flash("Enter at least one target URL.", "error")
            return render_template("batch_scan.html")
        try:
            job = run_batch(targets, initiated_by=session.get("username", ""))
            flash(f"Batch completed: {job.completed} successful, {job.failed} failed.", "success")
            return redirect(url_for("scan_history"))
        except Exception as e:
            flash(f"Batch failed: {str(e)[:200]}", "error")
    return render_template("batch_scan.html")


# --- Routes: Scan History ---
@app.route("/scans")
@login_required
def scan_history():
    scans = repository.list_scans(limit=200)
    return render_template("scan_history.html", scans=scans)


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
            download_name=f"wsa-report-{scan_id[:8]}.html"
        )
    elif fmt == "json":
        j = generate_json_report(scan)
        return send_file(
            io.BytesIO(j.encode("utf-8")),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"wsa-report-{scan_id[:8]}.json"
        )
    elif fmt == "excel":
        data = generate_excel_report(scan)
        return send_file(
            io.BytesIO(data),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"wsa-report-{scan_id[:8]}.xlsx"
        )
    elif fmt == "pdf":
        data = generate_pdf_report(scan)
        return send_file(
            io.BytesIO(data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"wsa-report-{scan_id[:8]}.pdf"
        )
    abort(400)


# --- Routes: User Management (admin only) ---
@app.route("/users")
@admin_required
def user_management():
    users = repository.list_users()
    return render_template("users.html", users=users)


@app.route("/users/create", methods=["POST"])
@admin_required
def create_user_route():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "viewer")
    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("user_management"))
    existing = repository.get_user_by_username(username)
    if existing:
        flash("Username already exists.", "error")
        return redirect(url_for("user_management"))
    user = create_user(username=username, password=password, email=email,
                       role=UserRole(role), status=UserStatus.ACTIVE)
    repository.save_user(user)
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("user_management"))


@app.route("/users/<user_id>/update", methods=["POST"])
@admin_required
def update_user_route(user_id):
    data = request.form.to_dict()
    updates = {}
    if "role" in data:
        updates["role"] = data["role"]
    if "status" in data:
        updates["status"] = data["status"]
    if "email" in data:
        updates["email"] = data["email"]
    if data.get("new_password"):
        updates["password_hash"] = hash_password(data["new_password"])
    if updates:
        repository.update_user(user_id, **updates)
        flash("User updated.", "success")
    return redirect(url_for("user_management"))


@app.route("/users/<user_id>/delete", methods=["POST"])
@admin_required
def delete_user_route(user_id):
    if user_id == session.get("user_id"):
        flash("Cannot delete your own account.", "error")
        return redirect(url_for("user_management"))
    repository.delete_user(user_id)
    flash("User deleted.", "success")
    return redirect(url_for("user_management"))


# --- API endpoints for AJAX ---
@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    data = request.get_json()
    target = data.get("target_url", "").strip()
    if not target:
        return jsonify({"error": "target_url required"}), 400
    try:
        result = run_scan(target, initiated_by=session.get("username", ""))
        return jsonify({
            "scan_id": result.id,
            "score": result.score,
            "grade": result.grade,
            "findings_count": len(result.findings),
            "is_wordpress": result.is_wordpress,
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
        "started_at": s.started_at,
    } for s in scans])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
