"""
Finding title catalog for external translation / tooling.
Loads data/vulnerability_finding_titles.json and optionally merges distinct
titles observed in the local findings database.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "vulnerability_finding_titles.json"


def load_finding_title_catalog(include_db: bool = False, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    catalog: Dict[str, Any] = {
        "version": "1.0",
        "titles": [],
        "count": 0,
        "source_file": str(_CATALOG_PATH),
    }
    if _CATALOG_PATH.is_file():
        try:
            catalog = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load finding title catalog: %s", exc)
    titles: List[Dict[str, Any]] = list(catalog.get("titles") or [])
    known = {t.get("translation_key") or t.get("title_template") for t in titles}

    if include_db:
        try:
            from core import repository
            # Pull a bounded sample of distinct titles from findings
            findings, _ = repository.list_findings(
                tenant_id or "default-tenant",
                filters=None,
                page=1,
                page_size=500,
            )
            for f in findings:
                title = (f.title or "").strip()
                if not title or title in known:
                    continue
                known.add(title)
                titles.append({
                    "id": f"observed_{abs(hash(title)) % 10**10}",
                    "title_template": title,
                    "translation_key": title,
                    "source": "database_observed",
                })
        except Exception as exc:
            logger.debug("DB title merge skipped: %s", exc)

    catalog["titles"] = sorted(titles, key=lambda x: (x.get("translation_key") or ""))
    catalog["count"] = len(catalog["titles"])
    return catalog
