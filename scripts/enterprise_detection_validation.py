#!/usr/bin/env python3
"""
Run enterprise detection integrity checks and emit a JSON truthfulness report.

Usage:
  python scripts/enterprise_detection_validation.py [--output reports/detection_integrity.json]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from config import OSV_LIVE_ENRICHMENT_ENABLED  # noqa: E402


def _run_pytest(module: str) -> dict:
    cmd = [sys.executable, "-m", "pytest", module, "-q", "--tb=no"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    tail = (proc.stdout or proc.stderr or "").strip().splitlines()
    summary = tail[-1] if tail else ""
    return {
        "module": module,
        "exit_code": proc.returncode,
        "summary": summary,
        "passed": proc.returncode == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Enterprise detection integrity validation")
    parser.add_argument(
        "--output",
        default=os.path.join(ROOT, "reports", "detection_integrity.json"),
        help="JSON report path",
    )
    args = parser.parse_args()

    suites = [
        "tests/test_enterprise_detection_integrity.py",
        "tests/test_sprint2_detection_hardening.py",
        "tests/test_sprint7_qa_hardening.py",
        "tests/vulnerability_intelligence/test_service.py",
        "tests/test_scan_pipeline.py",
    ]

    results = [_run_pytest(m) for m in suites]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "product_version": "4.1.0",
        "policies": {
            "osv_live_enrichment_default": OSV_LIVE_ENRICHMENT_ENABLED,
            "local_intel_authoritative": True,
            "php_artifact_verification_required": True,
            "osv_requires_local_corroboration_for_high_confidence": True,
        },
        "suites": results,
        "status": "PASS" if all(r["passed"] for r in results) else "FAIL",
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
