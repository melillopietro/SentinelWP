"""
WordPress Security Auditor Pro - Configuration
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = os.getenv("WSA_DATABASE_PATH", str(DATA_DIR / "wsa.db"))
SECRET_KEY = os.getenv("WSA_SECRET_KEY", "CHANGE-ME-IN-PRODUCTION-USE-RANDOM-32-BYTES")
ADMIN_USERNAME = os.getenv("WSA_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("WSA_ADMIN_PASSWORD", "admin")
REQUEST_TIMEOUT = int(os.getenv("WSA_REQUEST_TIMEOUT", "15"))
MAX_CONCURRENT_SCANS = int(os.getenv("WSA_MAX_CONCURRENT_SCANS", "5"))
USER_AGENT = os.getenv(
    "WSA_USER_AGENT",
    "Mozilla/5.0 (compatible; SentinelWP-Auditor/2.0; +https://github.com/wuerth-it/sentinel-wp)"
)
CONFIDENCE_THRESHOLD = float(os.getenv("WSA_CONFIDENCE_THRESHOLD", "0.3"))
NORMALIZATION_FACTOR = float(os.getenv("WSA_NORMALIZATION_FACTOR", "150.0"))
SESSION_EXPIRY_HOURS = int(os.getenv("WSA_SESSION_EXPIRY_HOURS", "8"))
