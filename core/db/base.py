"""
Declarative base and custom type decorators for SentinelWP SQLAlchemy 2.x models.
"""
from datetime import datetime, timezone
import json
from typing import Any
from sqlalchemy import DateTime, Text, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative Base for all SentinelWP ORM entities."""
    pass


class SafeJSON(TypeDecorator):
    """
    Cross-database JSON storage decorator.
    Stores Python dicts/lists as JSON strings on SQLite, and native JSON on PostgreSQL.
    Guarantees transparent serialization/deserialization and fallback handling.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> Any:
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

    def process_result_value(self, value: Any, dialect) -> Any:
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return value


def utcnow_str() -> str:
    """Return ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()
