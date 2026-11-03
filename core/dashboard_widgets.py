"""
Dashboard widget catalog for SentinelWP v5.

Widgets are declared once here so the UI can enable/disable them without
redeploying. Defaults stay as the Posture Overview set from v4.2; additional
widgets ship disabled and can be toggled client-side (localStorage) for later
server-side preference persistence.
"""
from __future__ import annotations

from typing import Any


# size hints drive the responsive CSS grid (mobile stacks to full width)
WIDGET_CATALOG: list[dict[str, Any]] = [
    {
        "id": "kpi_strip",
        "title": "Posture KPIs",
        "description": "Total scans, completion, average risk, open findings.",
        "default": True,
        "size": "full",
        "group": "default",
    },
    {
        "id": "severity_donut",
        "title": "Exposure by Severity",
        "description": "Interactive donut of open findings by severity.",
        "default": True,
        "size": "md",
        "group": "default",
    },
    {
        "id": "top_risk_assets",
        "title": "Highest Risk Assets",
        "description": "Top assets by risk score with site favicons.",
        "default": True,
        "size": "lg",
        "group": "default",
    },
    {
        "id": "top_categories",
        "title": "Top Risk Categories",
        "description": "Most frequent open finding categories.",
        "default": True,
        "size": "md",
        "group": "default",
    },
    {
        "id": "monitoring_health",
        "title": "Continuous Monitoring Health",
        "description": "Operational pulse with drill-down cards and 7-day trend.",
        "default": True,
        "size": "full",
        "group": "default",
    },
    {
        "id": "recent_scans",
        "title": "Recent Scans",
        "description": "Latest scan activity with filters and favicons.",
        "default": True,
        "size": "full",
        "group": "default",
    },
    # --- Optional / add-later widgets (shipped disabled by default) ---
    {
        "id": "sla_kev",
        "title": "SLA & KEV Spotlight",
        "description": "SLA breaches, CISA KEV exposures, and P1 backlog.",
        "default": False,
        "size": "md",
        "group": "optional",
    },
    {
        "id": "grade_mix",
        "title": "Grade Distribution",
        "description": "Portfolio grade mix from completed scans (A–F).",
        "default": False,
        "size": "md",
        "group": "optional",
    },
    {
        "id": "portfolio_coverage",
        "title": "Portfolio Coverage",
        "description": "Verification, ownership, and BU assignment coverage.",
        "default": False,
        "size": "md",
        "group": "optional",
    },
    {
        "id": "auth_posture",
        "title": "Authorization Posture",
        "description": "Authorized vs expired vs unauthorized assets.",
        "default": False,
        "size": "md",
        "group": "optional",
    },
]


def default_enabled_ids() -> list[str]:
    return [w["id"] for w in WIDGET_CATALOG if w.get("default")]


def widget_catalog_for_template() -> list[dict[str, Any]]:
    """JSON-serializable catalog for the Customize Widgets panel."""
    return [
        {
            "id": w["id"],
            "title": w["title"],
            "description": w["description"],
            "default": bool(w.get("default")),
            "size": w.get("size", "md"),
            "group": w.get("group", "optional"),
        }
        for w in WIDGET_CATALOG
    ]
