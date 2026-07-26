"""
Domain models for WSA Pro
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    PENDING = "pending"


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    category: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 1.0
    remediation: str = ""
    reference: str = ""
    raw_data: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    status: ScanStatus = ScanStatus.PENDING
    scan_mode: str = "passive"
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    findings: list = field(default_factory=list)
    score: Optional[float] = None
    grade: Optional[str] = None
    notes: str = ""
    tags: str = ""
    initiated_by: str = ""
    wp_version: Optional[str] = None
    is_wordpress: Optional[bool] = None



@dataclass
class User:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    password_hash: str = ""
    email: str = ""
    role: UserRole = UserRole.VIEWER
    status: UserStatus = UserStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
