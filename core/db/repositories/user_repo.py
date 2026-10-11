"""
User Repository using SQLAlchemy 2.x
"""
from typing import Optional, List
from sqlalchemy import select, and_, func
from sqlalchemy.orm import Session
from core.models import User, UserRole, UserStatus
from core.db.models import UserModel


class UserRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(m: UserModel) -> User:
        role_val = UserRole.VIEWER
        try:
            role_val = UserRole(m.role)
        except Exception:
            pass
        status_val = UserStatus.PENDING
        try:
            status_val = UserStatus(m.status)
        except Exception:
            pass
        return User(
            id=m.id,
            tenant_id=m.tenant_id,
            username=m.username,
            password_hash=m.password_hash,
            email=m.email,
            role=role_val,
            status=status_val,
            created_at=m.created_at,
        )

    def get_by_id(self, user_id: str, tenant_id: Optional[str] = None) -> Optional[User]:
        stmt = select(UserModel).where(UserModel.id == user_id)
        if tenant_id:
            stmt = stmt.where(UserModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def get_by_username(self, username: str, tenant_id: Optional[str] = None) -> Optional[User]:
        stmt = select(UserModel).where(UserModel.username == username)
        if tenant_id:
            stmt = stmt.where(UserModel.tenant_id == tenant_id)
        res = self.session.execute(stmt).scalar_one_or_none()
        return self._to_domain(res) if res else None

    def list_by_username(self, username: str) -> List[User]:
        stmt = select(UserModel).where(UserModel.username == username)
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def list_users(self, tenant_id: Optional[str] = None) -> List[User]:
        stmt = select(UserModel)
        if tenant_id:
            stmt = stmt.where(UserModel.tenant_id == tenant_id)
        stmt = stmt.order_by(UserModel.created_at.asc())
        return [self._to_domain(m) for m in self.session.execute(stmt).scalars().all()]

    def count_users(self, tenant_id: Optional[str] = None) -> int:
        stmt = select(func.count(UserModel.id))
        if tenant_id:
            stmt = stmt.where(UserModel.tenant_id == tenant_id)
        return self.session.execute(stmt).scalar_one() or 0

    def create(self, user: User) -> User:
        role_str = user.role.value if isinstance(user.role, UserRole) else str(user.role)
        status_str = user.status.value if isinstance(user.status, UserStatus) else str(user.status)
        model = UserModel(
            id=user.id,
            tenant_id=user.tenant_id or "default-tenant",
            username=user.username,
            password_hash=user.password_hash,
            email=user.email,
            role=role_str,
            status=status_str,
            created_at=user.created_at,
        )
        self.session.add(model)
        self.session.flush()
        return user

    def save(self, user: User) -> User:
        stmt = select(UserModel).where(UserModel.id == user.id)
        model = self.session.execute(stmt).scalar_one_or_none()
        role_str = user.role.value if isinstance(user.role, UserRole) else str(user.role)
        status_str = user.status.value if isinstance(user.status, UserStatus) else str(user.status)
        if model:
            model.username = user.username
            model.password_hash = user.password_hash
            model.email = user.email
            model.role = role_str
            model.status = status_str
            model.tenant_id = user.tenant_id or model.tenant_id
            self.session.flush()
            return self._to_domain(model)
        return self.create(user)

    def update(self, user: User) -> User:
        return self.save(user)

    def update_fields(self, user_id: str, tenant_id: Optional[str] = None, **kwargs) -> bool:
        stmt = select(UserModel).where(UserModel.id == user_id)
        if tenant_id:
            stmt = stmt.where(UserModel.tenant_id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        allowed = {"username", "password_hash", "email", "role", "status", "tenant_id"}
        for k, v in kwargs.items():
            if k in allowed:
                val = v.value if hasattr(v, "value") else str(v)
                setattr(model, k, val)
        self.session.flush()
        return True

    def delete(self, user_id: str, tenant_id: Optional[str] = None) -> bool:
        stmt = select(UserModel).where(UserModel.id == user_id)
        if tenant_id:
            stmt = stmt.where(UserModel.tenant_id == tenant_id)
        model = self.session.execute(stmt).scalar_one_or_none()
        if not model:
            return False
        self.session.delete(model)
        self.session.flush()
        return True
