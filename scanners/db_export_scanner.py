"""
Database Export / Backup File Detection Scanner
Probes for exposed SQL dumps and backup files
"""
from scanners.base import BaseScanner
from core.models import Severity


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

    def _check_db_exports(self):
        for path in DB_BACKUP_PATHS:
            url = f"{self.target_url}/{path}"
            resp = self._head(url)
            if not resp:
                continue
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "").lower()
                content_length = resp.headers.get("content-length", "0")
                # Skip HTML error pages for any backup file
                if "text/html" in content_type and not path.endswith("/"):
                    continue
                severity = Severity.CRITICAL
                if path.endswith("/"):
                    # Directory listing
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
                self._add_finding(
                    category="exposure",
                    title=f"Database Backup Exposed: {path}",
                    description=f"A potential database backup file is publicly accessible at /{path}. "
                                f"Content-Length: {content_length} bytes. "
                                f"This may contain all site data including credentials.",
                    severity=severity,
                    confidence=0.9,
                    remediation="Remove backup files from the web root immediately. "
                                "Store backups in a non-public location. "
                                "Block access to .sql files via server configuration.",
                    raw_data={"url": url, "path": path, "content_length": content_length}
                )
