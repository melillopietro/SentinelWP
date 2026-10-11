"""
Enterprise Structured JSON Logging Configuration for SentinelWP.
Provides JSON formatting with request_id, tenant_id, and user_id context correlation.
Includes automatic secret redaction for Bearer tokens, passwords, API keys, and secrets.
"""
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Optional

# Secret redaction patterns — applied to all log messages before emission
_SECRET_PATTERNS = [
    # Bearer tokens
    (re.compile(r'(Bearer\s+)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    # API key values (key=..., api_key=..., apikey=...)
    (re.compile(r'(api[_-]?key\s*[=:]\s*)["\']?\S+["\']?', re.IGNORECASE), r'\1[REDACTED]'),
    # Password values
    (re.compile(r'(password\s*[=:]\s*)["\']?\S+["\']?', re.IGNORECASE), r'\1[REDACTED]'),
    # Secret values
    (re.compile(r'(secret\s*[=:]\s*)["\']?\S+["\']?', re.IGNORECASE), r'\1[REDACTED]'),
    # Token values
    (re.compile(r'(token\s*[=:]\s*)["\']?\S+["\']?', re.IGNORECASE), r'\1[REDACTED]'),
    # Authorization header
    (re.compile(r'(Authorization\s*[=:]\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
]

# Thread-local / Context storage for request correlation
try:
    from flask import has_request_context, request, g
except ImportError:
    has_request_context = lambda: False
    request = None
    g = None


class JSONFormatter(logging.Formatter):
    """
    Format log records as structured single-line JSON objects.
    Enriches records with correlation context: request_id, tenant_id, user_id.
    """

    def __init__(self, service_name: str = "sentinelwp", **kwargs):
        super().__init__(**kwargs)
        self.service_name = service_name
        self.environment = os.getenv("ENVIRONMENT", "development")

    @staticmethod
    def _redact_message(message: str) -> str:
        """Scrub sensitive values from log messages."""
        for pattern, replacement in _SECRET_PATTERNS:
            message = pattern.sub(replacement, message)
        return message

    def format(self, record: logging.LogRecord) -> str:
        # Standard ISO timestamp in UTC
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        iso_time = dt.isoformat()

        # Redact secrets from the message
        message = self._redact_message(record.getMessage())

        log_data = {
            "timestamp": iso_time,
            "level": record.levelname,
            "service": self.service_name,
            "environment": self.environment,
            "logger": record.name,
            "module": record.module,
            "line": record.lineno,
            "message": message,
        }

        # Context correlation from Flask g or request
        request_id = getattr(record, "request_id", None)
        tenant_id = getattr(record, "tenant_id", None)
        user_id = getattr(record, "user_id", None)

        if has_request_context():
            if not request_id and hasattr(g, "request_id"):
                request_id = g.request_id
            if not tenant_id and hasattr(g, "tenant_id"):
                tenant_id = g.tenant_id
            if not user_id and hasattr(g, "user_id"):
                user_id = g.user_id
            if request:
                log_data["http"] = {
                    "method": request.method,
                    "path": request.path,
                    "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
                }

        if request_id:
            log_data["request_id"] = str(request_id)
        if tenant_id:
            log_data["tenant_id"] = str(tenant_id)
        if user_id:
            log_data["user_id"] = str(user_id)

        # Exception information
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        elif record.exc_text:
            log_data["exception"] = record.exc_text

        # Extra attributes attached to record
        extra_fields = {}
        standard_attrs = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
            "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "created", "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process", "message", "request_id", "tenant_id", "user_id"
        }
        for k, v in record.__dict__.items():
            if k not in standard_attrs and not k.startswith("_"):
                try:
                    json.dumps(v)
                    extra_fields[k] = v
                except (TypeError, OverflowError):
                    extra_fields[k] = str(v)

        if extra_fields:
            log_data["extra"] = extra_fields

        return json.dumps(log_data)


def configure_logging(
    service_name: str = "sentinelwp",
    level: str = None,
    log_format: Optional[str] = None
) -> None:
    """
    Configures root logger and stdout handler.
    log_format can be 'json' or 'text'. Defaults to 'json' in production or if LOG_FORMAT=json.
    """
    if level is None:
        level = os.getenv("LOG_LEVEL", "INFO").upper()

    if log_format is None:
        log_format = os.getenv("LOG_FORMAT", "").lower()
        if not log_format:
            env = os.getenv("ENVIRONMENT", "development").lower()
            log_format = "json" if env in ("production", "staging", "prod") else "text"

    numeric_level = getattr(logging, level, logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    if log_format == "json":
        formatter = JSONFormatter(service_name=service_name)
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
