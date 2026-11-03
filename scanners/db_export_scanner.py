"""
Database Export / Backup File Detection Scanner
Probes for exposed SQL dumps and backup files
"""
from scanners.base import BaseScanner
from core.models import Severity
from scanners.soft404 import response_is_soft_404


DB_BACKUP_PATHS = [
    "dump.sql", "database.sql", "db.sql", "backup.sql",
    "wordpress.sql", "wp.sql", "site.sql", "data.sql",
    "dump.sql.gz", "database.sql.gz", "backup.sql.gz",
    "db-backup.sql", "db_backup.sql", "mysql.sql",
    "backup.tar.gz", "backup.zip", "site-backup.zip",
    "wp-content/backup-db/", "wp-content/backups/",
    "wp-content/uploads/backups/",
    "backups/", "backup/", "sql/", "db/",
]


class DBExportScanner(BaseScanner):
    def scan(self) -> list:
        self._check_db_exports()
        return self.findings

    def _looks_like_backup(self, path: str, sample: bytes) -> bool:
        if not sample:
            return False
        lower = sample.lower()
        if path.endswith(".sql") or path.endswith(".sql.gz") or "sql" in path:
            if (
                b"-- mysql dump" in lower
                or b"create table" in lower
                or b"insert into" in lower
                or b"/*m!" in lower
                or b"mysqldump" in lower
            ):
                return True
            # .sql.gz may still be gzip-wrapped
            if sample.startswith(b"\x1f\x8b"):
                return True
            if path.endswith((".sql",)):
                return False
        if path.endswith(".zip") or path.endswith(".tar.gz") or path.endswith(".gz"):
            if sample.startswith(b"PK\x03\x04"):
                return True
            if sample.startswith(b"\x1f\x8b"):
                return True
            if sample[:5] == b"ustar" or b"ustar" in sample[:265]:
                return True
            return False
        # Generic path without extension: accept SQL / zip / gzip magic only
        return (
            b"-- mysql dump" in lower
            or b"create table" in lower
            or b"insert into" in lower
            or sample.startswith(b"PK\x03\x04")
            or sample.startswith(b"\x1f\x8b")
        )

    def _check_db_exports(self):
        for path in DB_BACKUP_PATHS:
            url = f"{self.target_url}/{path}"
            head = self._head(url)
            if not head or head.status_code != 200:
                continue
            content_type = head.headers.get("content-type", "").lower()
            content_length = head.headers.get("content-length", "0")
            try:
                cl_int = int(content_length)
            except (TypeError, ValueError):
                cl_int = -1

            if path.endswith("/"):
                dir_resp = self._get(url)
                if dir_resp and ("Index of" in dir_resp.text or "Parent Directory" in dir_resp.text):
                    self._add_finding(
                        category="exposure",
                        title=f"Backup Directory Listing: /{path}",
                        description=f"Directory listing enabled at /{path}. May contain database backups.",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        remediation="Block public access to backup directories. Move backups off the web root.",
                        raw_data={"url": url, "type": "directory"}
                    )
                continue

            # Skip obvious HTML error pages on HEAD
            if "text/html" in content_type:
                continue
            if 0 <= cl_int < 100:
                continue

            # Bounded GET with Range to validate magic bytes / SQL markers
            sample_resp = self._get(url, headers={"Range": "bytes=0-511"})
            if not sample_resp or sample_resp.status_code not in (200, 206):
                continue
            if response_is_soft_404(sample_resp):
                continue
            sample = sample_resp.content or b""
            if len(sample) < 8:
                continue
            sample_ct = (sample_resp.headers.get("content-type") or "").lower()
            if "text/html" in sample_ct and not self._looks_like_backup(path, sample):
                continue
            if not self._looks_like_backup(path, sample):
                continue

            self._add_finding(
                category="exposure",
                title=f"Database Backup Exposed: {path}",
                description=f"A database backup file is publicly accessible at /{path}. "
                            f"Content-Length: {content_length} bytes. "
                            f"Content signature confirmed (SQL dump / archive magic bytes). "
                            f"This may contain all site data including credentials.",
                severity=Severity.CRITICAL,
                confidence=0.95,
                remediation="Remove backup files from the web root immediately. "
                            "Store backups in a non-public location. "
                            "Block access to .sql files via server configuration.",
                raw_data={"url": url, "path": path, "content_length": content_length}
            )
