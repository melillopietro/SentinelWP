"""
CLI utility to reset SentinelWP user passwords.

Usage:
  python3 scripts/reset_password.py --list
  python3 scripts/reset_password.py <username> <new_password>
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, ".env"))
except ImportError:
    pass

from config import DATABASE_PATH
from core import repository
from core.auth import hash_password, verify_password


def list_users() -> None:
    repository.init_db()
    users = repository.list_users()
    print(f"Database: {DATABASE_PATH}")
    if not users:
        print("No users found. Open the app and complete /setup first.")
        return
    print("Users:")
    for u in users:
        role = u.role.value if hasattr(u.role, "value") else u.role
        status = u.status.value if hasattr(u.status, "value") else u.status
        print(f"  - {u.username!r}  role={role}  status={status}")


def _find_user(username: str):
    user = repository.get_user_by_username(username)
    if user:
        return user
    target = username.strip().lower()
    for u in repository.list_users():
        if u.username.lower() == target:
            return u
    return None


def reset_password(username: str, new_pass: str) -> None:
    if len(new_pass) < 6:
        print("Error: Password must be at least 6 characters.")
        sys.exit(1)

    repository.init_db()
    print(f"Database: {DATABASE_PATH}")

    user = _find_user(username)
    if not user:
        print(f"Error: User {username!r} not found.")
        list_users()
        sys.exit(1)

    if user.status.value if hasattr(user.status, "value") else user.status != "active":
        print(f"Warning: user {user.username!r} status is not 'active' — login may still fail.")

    new_hash = hash_password(new_pass)
    repository.update_user(user.id, password_hash=new_hash)

    if not verify_password(new_pass, new_hash):
        print("Error: Password hash verification failed after update.")
        sys.exit(1)

    print(f"Success: Password updated for user {user.username!r}.")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ("--list", "-l", "list"):
        list_users()
        sys.exit(0)

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 scripts/reset_password.py --list")
        print("  python3 scripts/reset_password.py <username> <new_password>")
        print("\nDo not type angle brackets — use your real username and password.")
        sys.exit(1)

    reset_password(sys.argv[1], sys.argv[2])
