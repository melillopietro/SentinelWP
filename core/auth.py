"""
Authentication and password handling
"""
import hashlib
import os
from core.models import User, UserRole, UserStatus

try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False


def hash_password(password: str) -> str:
    if USE_BCRYPT:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 310000)
    return f"pbkdf2:{salt}:{h.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    if USE_BCRYPT and password_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    if password_hash.startswith("pbkdf2:"):
        _, salt, stored_hash = password_hash.split(":")
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 310000)
        return h.hex() == stored_hash
    return False


def create_user(
    username: str,
    password: str,
    email: str = "",
    role: UserRole = UserRole.VIEWER,
    status: UserStatus = UserStatus.PENDING,
) -> User:
    return User(
        username=username,
        password_hash=hash_password(password),
        email=email,
        role=role,
        status=status,
    )
