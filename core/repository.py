"""
SQLite repository layer - full CRUD for users, scans, findings
"""
import json
import sqlite3
from typing import Optional
from config import DATABASE_PATH
from core.models import (
    Finding, ScanResult, ScanStatus, Severity,
    User, UserRole, UserStatus, ScheduledScan
)

_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DATABASE_PATH, timeout=60.0, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


def init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT DEFAULT '',
            role TEXT DEFAULT 'viewer',
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            scan_mode TEXT DEFAULT 'passive',
            started_at TEXT NOT NULL,
            completed_at TEXT,
            score REAL,
            grade TEXT,
            notes TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            initiated_by TEXT DEFAULT '',
            wp_version TEXT,
            is_wordpress INTEGER,
            whois_info TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            category TEXT DEFAULT '',
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity TEXT DEFAULT 'info',
            confidence REAL DEFAULT 1.0,
            remediation TEXT DEFAULT '',
            reference TEXT DEFAULT '',
            raw_data TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            scan_mode TEXT DEFAULT 'passive',
            interval_hours INTEGER DEFAULT 24,
            last_run_at TEXT,
            next_run_at TEXT,
            enabled INTEGER DEFAULT 1,
            created_by TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()
    
    # Backward compatibility: try adding whois_info column if db already existed
    try:
        conn.execute("ALTER TABLE scans ADD COLUMN whois_info TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Initialize vulnerability intelligence tables
    try:
        from core.vulnerability_intelligence.repository import init_vuln_intel_db
        init_vuln_intel_db()
    except Exception:
        pass



# --- Users ---
def save_user(user: User):
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO users (id, username, password_hash, email, role, status, created_at) VALUES (?,?,?,?,?,?,?)",
        (user.id, user.username, user.password_hash, user.email, user.role.value if isinstance(user.role, UserRole) else user.role, user.status.value if isinstance(user.status, UserStatus) else user.status, user.created_at)
    )
    conn.commit()


def get_user_by_username(username: str) -> Optional[User]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return None
    return User(
        id=row["id"], username=row["username"], password_hash=row["password_hash"],
        email=row["email"], role=UserRole(row["role"]), status=UserStatus(row["status"]),
        created_at=row["created_at"]
    )


def get_user_by_id(user_id: str) -> Optional[User]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None
    return User(
        id=row["id"], username=row["username"], password_hash=row["password_hash"],
        email=row["email"], role=UserRole(row["role"]), status=UserStatus(row["status"]),
        created_at=row["created_at"]
    )


def list_users() -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [User(id=r["id"], username=r["username"], password_hash=r["password_hash"],
                 email=r["email"], role=UserRole(r["role"]), status=UserStatus(r["status"]),
                 created_at=r["created_at"]) for r in rows]


def count_users() -> int:
    conn = _get_conn()
    row = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()
    return row["cnt"] if row else 0


def update_user(user_id: str, **kwargs):
    conn = _get_conn()
    allowed = {"username", "password_hash", "email", "role", "status"}
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in allowed:
            if hasattr(v, "value"):
                v = v.value
            sets.append(f"{k} = ?")
            vals.append(v)
    if sets:
        vals.append(user_id)
        conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", vals)
        conn.commit()


def delete_user(user_id: str):
    conn = _get_conn()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


# --- Scans ---
def save_scan(scan: ScanResult):
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO scans (id, target_url, status, scan_mode, started_at, completed_at, score, grade, notes, tags, initiated_by, wp_version, is_wordpress, whois_info) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (scan.id, scan.target_url, scan.status.value if isinstance(scan.status, ScanStatus) else scan.status,
         scan.scan_mode, scan.started_at, scan.completed_at, scan.score, scan.grade, scan.notes, scan.tags,
         scan.initiated_by, scan.wp_version, 1 if scan.is_wordpress else 0 if scan.is_wordpress is not None else None,
         scan.whois_info)
    )
    conn.commit()


def get_scan(scan_id: str) -> Optional[ScanResult]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    scan = ScanResult(
        id=row["id"], target_url=row["target_url"], status=ScanStatus(row["status"]),
        scan_mode=row["scan_mode"] if "scan_mode" in row.keys() else "passive",
        started_at=row["started_at"], completed_at=row["completed_at"],
        score=row["score"], grade=row["grade"], notes=row["notes"], tags=row["tags"],
        initiated_by=row["initiated_by"], wp_version=row["wp_version"],
        is_wordpress=bool(row["is_wordpress"]) if row["is_wordpress"] is not None else None,
        whois_info=row["whois_info"] if "whois_info" in row.keys() else None
    )
    scan.findings = get_findings_for_scan(scan_id)
    return scan


def list_scans(limit: int = 100, offset: int = 0, filters: Optional[dict] = None) -> list:
    conn = _get_conn()
    query = "SELECT * FROM scans WHERE 1=1"
    params = []

    if filters:
        if filters.get("target_url"):
            query += " AND target_url LIKE ?"
            params.append(f"%{filters['target_url']}%")
        if filters.get("status"):
            query += " AND status = ?"
            params.append(filters["status"])
        if filters.get("scan_mode"):
            query += " AND scan_mode = ?"
            params.append(filters["scan_mode"])
        if filters.get("grade"):
            query += " AND grade = ?"
            params.append(filters["grade"])
        if filters.get("is_wordpress") is not None and str(filters["is_wordpress"]).strip() != "":
            val = str(filters["is_wordpress"]).lower()
            if val in ("1", "true", "yes"):
                query += " AND is_wordpress = 1"
            elif val in ("0", "false", "no"):
                query += " AND (is_wordpress = 0 OR is_wordpress IS NULL)"
        if filters.get("date_from"):
            query += " AND started_at >= ?"
            params.append(filters["date_from"])
        if filters.get("date_to"):
            query += " AND started_at <= ?"
            params.append(filters["date_to"] + "T23:59:59")

    query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    results = []
    for row in rows:
        s = ScanResult(
            id=row["id"], target_url=row["target_url"], status=ScanStatus(row["status"]),
            scan_mode=row["scan_mode"] if "scan_mode" in row.keys() else "passive",
            started_at=row["started_at"], completed_at=row["completed_at"],
            score=row["score"], grade=row["grade"], notes=row["notes"], tags=row["tags"],
            initiated_by=row["initiated_by"], wp_version=row["wp_version"],
            is_wordpress=bool(row["is_wordpress"]) if row["is_wordpress"] is not None else None,
            whois_info=row["whois_info"] if "whois_info" in row.keys() else None
        )
        results.append(s)
    return results


def delete_scan(scan_id: str):
    conn = _get_conn()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()


def update_scan(scan_id: str, **kwargs):
    conn = _get_conn()
    allowed = {"target_url", "status", "scan_mode", "completed_at", "score", "grade", "notes", "tags", "wp_version", "is_wordpress"}
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in allowed:
            if hasattr(v, "value"):
                v = v.value
            sets.append(f"{k} = ?")
            vals.append(v)
    if sets:
        vals.append(scan_id)
        conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)
        conn.commit()


# --- Findings ---
def save_finding(finding: Finding):
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO findings (id, scan_id, category, title, description, severity, confidence, remediation, reference, raw_data, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (finding.id, finding.scan_id, finding.category, finding.title, finding.description,
         finding.severity.value if isinstance(finding.severity, Severity) else finding.severity,
         finding.confidence, finding.remediation, finding.reference,
         json.dumps(finding.raw_data), finding.created_at)
    )
    conn.commit()


def save_findings_bulk(findings: list):
    conn = _get_conn()
    for f in findings:
        conn.execute(
            "INSERT OR REPLACE INTO findings (id, scan_id, category, title, description, severity, confidence, remediation, reference, raw_data, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (f.id, f.scan_id, f.category, f.title, f.description,
             f.severity.value if isinstance(f.severity, Severity) else f.severity,
             f.confidence, f.remediation, f.reference, json.dumps(f.raw_data), f.created_at)
        )
    conn.commit()


def get_findings_for_scan(scan_id: str) -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, created_at", (scan_id,)).fetchall()
    results = []
    for r in rows:
        f = Finding(
            id=r["id"], scan_id=r["scan_id"], category=r["category"], title=r["title"],
            description=r["description"], severity=Severity(r["severity"]),
            confidence=r["confidence"], remediation=r["remediation"], reference=r["reference"],
            raw_data=json.loads(r["raw_data"]) if r["raw_data"] else {},
            created_at=r["created_at"]
        )
        results.append(f)
    return results


def delete_finding(finding_id: str):
    conn = _get_conn()
    conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
    conn.commit()


def update_finding(finding_id: str, **kwargs):
    conn = _get_conn()
    allowed = {"category", "title", "description", "severity", "confidence", "remediation", "reference"}
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in allowed:
            if hasattr(v, "value"):
                v = v.value
            sets.append(f"{k} = ?")
            vals.append(v)
    if sets:
        vals.append(finding_id)
        conn.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id = ?", vals)
        conn.commit()


# --- Scheduled Scans ---
def save_scheduled_scan(sched: ScheduledScan):
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO scheduled_scans (id, target_url, scan_mode, interval_hours, last_run_at, next_run_at, enabled, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (sched.id, sched.target_url, sched.scan_mode, sched.interval_hours, sched.last_run_at, sched.next_run_at, 1 if sched.enabled else 0, sched.created_by, sched.created_at)
    )
    conn.commit()


def list_scheduled_scans() -> list:
    conn = _get_conn()
    from core.models import ScheduledScan
    rows = conn.execute("SELECT * FROM scheduled_scans ORDER BY created_at DESC").fetchall()
    return [ScheduledScan(
        id=r["id"], target_url=r["target_url"], scan_mode=r["scan_mode"],
        interval_hours=r["interval_hours"], last_run_at=r["last_run_at"],
        next_run_at=r["next_run_at"], enabled=bool(r["enabled"]),
        created_by=r["created_by"], created_at=r["created_at"]
    ) for r in rows]


def delete_scheduled_scan(sched_id: str):
    conn = _get_conn()
    conn.execute("DELETE FROM scheduled_scans WHERE id = ?", (sched_id,))
    conn.commit()

