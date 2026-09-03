"""
Batch scan runner with concurrent execution and scan mode support
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable
from core.models import ScanResult
from scanners.orchestrator import run_scan
from config import MAX_CONCURRENT_SCANS


@dataclass
class BatchJob:
    id: str = ""
    targets: list = field(default_factory=list)
    results: list = field(default_factory=list)
    scan_mode: str = "passive"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    total: int = 0
    completed: int = 0
    failed: int = 0


def run_batch(
    targets: list,
    initiated_by: str = "",
    scan_mode: str = "passive",
    max_workers: Optional[int] = None,
    progress_callback: Optional[Callable] = None,
) -> BatchJob:
    job = BatchJob(targets=targets, total=len(targets), scan_mode=scan_mode)
    workers = max_workers or min(MAX_CONCURRENT_SCANS, len(targets))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(run_scan, url, initiated_by, scan_mode): url
            for url in targets
        }
        for future in as_completed(future_map):
            try:
                result = future.result()
                job.results.append(result)
                job.completed += 1
            except Exception:
                job.failed += 1
            if progress_callback:
                progress_callback(job.completed + job.failed, job.total)

    job.completed_at = datetime.now(timezone.utc).isoformat()
    return job
