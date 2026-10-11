"""
Multi-tenant login resolution without cross-tenant account enumeration.
"""
from typing import Optional

from core.models import User
from core.auth.passwords import verify_password


def authenticate_login_user(
    username: str,
    password: str,
    tenant_slug: Optional[str] = None,
) -> Optional[User]:
    """
    Resolve a user for password login.

    - With tenant_slug: lookup tenant by slug, then username within that tenant.
    - Without tenant_slug: unique username match, or unique password match among
      users sharing the same username across tenants.
    - Returns None on any failure (caller should use generic invalid-credentials messaging).
    """
    from core import repository

    uname = (username or "").strip()
    if not uname or not password:
        return None

    if tenant_slug and tenant_slug.strip():
        tenant = repository.get_tenant_by_slug(tenant_slug.strip())
        if not tenant:
            return None
        user = repository.get_user_by_username(uname, tenant_id=tenant.id)
        if user and verify_password(password, user.password_hash):
            return user
        return None

    candidates = repository.list_users_by_username(uname)
    if not candidates:
        return None
    if len(candidates) == 1:
        user = candidates[0]
        if verify_password(password, user.password_hash):
            return user
        return None

    verified = [u for u in candidates if verify_password(password, u.password_hash)]
    if len(verified) == 1:
        return verified[0]
    return None
