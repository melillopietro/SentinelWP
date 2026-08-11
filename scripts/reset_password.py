"""
CLI Utility to Reset User Passwords in SentinelWP
Usage: python scripts/reset_password.py <username> <new_password>
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import repository
from core.auth import hash_password


def reset_password(username: str, new_pass: str):
    repository.init_db()
    user = repository.get_user_by_username(username)
    if not user:
        print(f"Error: User '{username}' not found in database.")
        sys.exit(1)

    new_hash = hash_password(new_pass)
    repository.update_user(user.id, password_hash=new_hash)
    print(f"Success: Password for user '{username}' has been successfully updated.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scripts/reset_password.py <username> <new_password>")
        sys.exit(1)

    username_arg = sys.argv[1]
    password_arg = sys.argv[2]
    reset_password(username_arg, password_arg)
