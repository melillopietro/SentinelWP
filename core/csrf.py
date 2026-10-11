"""
Centralized CSRF Protection Module for SentinelWP.
Provides global, enterprise-grade CSRF protection for HTML forms and browser-originated requests.
Compatible with Flask-WTF / CSRFProtect patterns.
"""
import hmac
import secrets
from functools import wraps
from typing import Optional
from flask import Flask, request, session, abort, current_app


class CSRFError(Exception):
    """Raised when CSRF validation fails."""
    pass


class CSRFProtect:
    """
    CSRF Protection extension for Flask.
    Enforces CSRF tokens on all mutating HTTP methods (POST, PUT, PATCH, DELETE)
    unless explicitly exempted via the @csrf.exempt decorator.
    """
    def __init__(self, app: Optional[Flask] = None):
        self._exempt_views = set()
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions = getattr(app, "extensions", {})
        app.extensions["csrf"] = self

        # Register template globals and context processors
        app.jinja_env.globals["csrf_token"] = self.generate_csrf

        @app.context_processor
        def csrf_context():
            return {"csrf_token": self.generate_csrf}

        @app.before_request
        def csrf_protect():
            csrf_enabled = current_app.config.get("WTF_CSRF_ENABLED")
            if csrf_enabled is None:
                csrf_enabled = current_app.config.get("CSRF_ENABLED")
            if csrf_enabled is None:
                csrf_enabled = not current_app.testing
            if not csrf_enabled:
                return

            if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
                return

            # Check if endpoint is exempt
            if request.endpoint:
                view_func = current_app.view_functions.get(request.endpoint)
                if view_func and getattr(view_func, "_csrf_exempt", False):
                    return

            token = self._get_token_from_request()
            if not token:
                abort(400, description="CSRF token missing.")

            expected_token = session.get("_csrf_token")
            if not expected_token or not hmac.compare_digest(str(token), str(expected_token)):
                abort(400, description="CSRF token invalid.")

    def generate_csrf(self) -> str:
        """Generate or retrieve the session-bound CSRF token."""
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]

    def _get_token_from_request(self) -> Optional[str]:
        """Extract CSRF token from form data or headers."""
        # Check form data
        if request.form and "csrf_token" in request.form:
            return request.form.get("csrf_token")

        # Check headers (standard for AJAX / fetch)
        for header_name in ("X-CSRFToken", "X-CSRF-Token", "X-CSRF-TOKEN"):
            if header_name in request.headers:
                return request.headers.get(header_name)

        # Check JSON body if parsed
        if request.is_json:
            try:
                json_data = request.get_json(silent=True)
                if isinstance(json_data, dict) and "csrf_token" in json_data:
                    return json_data.get("csrf_token")
            except Exception:
                pass

        return None

    def exempt(self, view):
        """Decorator to exempt a specific view function from CSRF protection."""
        view._csrf_exempt = True
        return view


csrf = CSRFProtect()
