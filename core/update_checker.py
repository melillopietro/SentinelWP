"""
GitHub Repository Update Checker for SentinelWP
Checks GitHub API to verify if the local installation is running the latest available update.
"""
import subprocess
import requests
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger(__name__)

CURRENT_VERSION = "v3.6.0"
GITHUB_REPO_OWNER = "melillopietro"
GITHUB_REPO_NAME = "SentinelWP"

_cached_update_result: Dict[str, Any] = {}
_last_check_time: float = 0.0
CACHE_TTL_SECONDS = 300  # 5 minutes cache


def get_local_commit_hash() -> str:
    """Returns short hash of local git HEAD commit, or 'unknown'."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception as e:
        logger.debug(f"Could not determine local git commit: {e}")
    return "unknown"


def check_for_updates(force: bool = False) -> Dict[str, Any]:
    """
    Queries GitHub API to compare local installation commit with remote main branch commit.
    Returns dictionary with update status information.
    """
    global _cached_update_result, _last_check_time

    now = time.time()
    if not force and _cached_update_result and (now - _last_check_time) < CACHE_TTL_SECONDS:
        return _cached_update_result

    local_commit = get_local_commit_hash()
    repo_url = f"https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}"
    api_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commits/main"

    result = {
        "current_version": CURRENT_VERSION,
        "local_commit": local_commit,
        "remote_commit": "unknown",
        "is_latest": True,
        "latest_commit_message": "",
        "latest_commit_date": "",
        "repo_url": repo_url,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "error": None
    }

    try:
        headers = {"User-Agent": "SentinelWP-UpdateChecker/3.6.0"}
        resp = requests.get(api_url, headers=headers, timeout=5.0)

        if resp.status_code == 200:
            data = resp.json()
            remote_sha = data.get("sha", "")
            remote_short = remote_sha[:7] if remote_sha else "unknown"
            commit_msg = data.get("commit", {}).get("message", "").split("\n")[0]
            commit_date = data.get("commit", {}).get("committer", {}).get("date", "")

            result["remote_commit"] = remote_short
            result["latest_commit_message"] = commit_msg
            result["latest_commit_date"] = commit_date

            if local_commit != "unknown" and remote_short != "unknown":
                if local_commit.startswith(remote_short) or remote_short.startswith(local_commit):
                    result["is_latest"] = True
                else:
                    result["is_latest"] = False
            else:
                result["is_latest"] = True
        elif resp.status_code == 403:
            result["error"] = "GitHub API rate limit reached. Try again later."
        else:
            result["error"] = f"GitHub API returned HTTP {resp.status_code}."
    except requests.exceptions.RequestException as e:
        result["error"] = f"Could not connect to GitHub: {str(e)}"
    except Exception as e:
        result["error"] = f"Error checking updates: {str(e)}"

    _cached_update_result = result
    _last_check_time = now
    return result
