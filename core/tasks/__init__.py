"""
Celery Tasks package for SentinelWP
"""
from core.tasks.celery_app import celery_app

__all__ = ["celery_app"]
