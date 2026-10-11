"""
Canonical session role resolution for SentinelWP web authentication.
Login stores session['role']; legacy tests may set session['user_role'].
"""
from typing import Optional

from flask import session


def normalize_role_value(role: object) -> str:
    """Normalize UserRole enum or string to lowercase role slug."""
    if role is None:
        return "viewer"
    if hasattr(role, "value"):
        role = role.value
    return str(role).strip().lower()


def get_session_role(default: str = "viewer") -> str:
    """
    Return the authenticated user's role from the Flask session.
    Prefers session['role'] (canonical); falls back to legacy session['user_role'].
    """
    if "role" in session:
        return normalize_role_value(session.get("role"))
    if "user_role" in session:
        return normalize_role_value(session.get("user_role"))
    return default
