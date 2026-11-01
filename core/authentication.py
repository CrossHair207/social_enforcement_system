"""Authentication: registration, login, lockout, session helpers."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from config import settings
from core.security import hash_password, password_problems, verify_password
from database.models import AuditLog, User, utcnow

logger = logging.getLogger(__name__)

SESSION_USER_KEY = "uid"


class AuthError(Exception):
    """Authentication failure with a message safe to show to the user."""


def normalise_email(email: str) -> str:
    return (email or "").strip().lower()


def create_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str = "",
    role: str = "analyst",
    must_change_password: bool = False,
    actor: Optional[User] = None,
) -> User:
    email = normalise_email(email)
    if "@" not in email or len(email) > 255:
        raise AuthError("a valid e-mail address is required")
    if role not in {"admin", "manager", "analyst", "viewer"}:
        raise AuthError("unknown role")
    problems = password_problems(password)
    if problems:
        raise AuthError("password " + ", ".join(problems))
    if db.scalar(select(User).where(User.email == email)):
        raise AuthError("an account with that e-mail already exists")

    user = User(
        email=email,
        full_name=full_name.strip()[:120],
        password_hash=hash_password(password),
        role=role,
        must_change_password=must_change_password,
    )
    db.add(user)
    db.flush()
    audit(db, actor, "user.create", "user", str(user.id), detail=f"role={role}")
    return user


def authenticate(db: Session, email: str, password: str, ip: str = "") -> User:
    """Verify credentials, honouring the lockout counter."""
    email = normalise_email(email)
    user = db.scalar(select(User).where(User.email == email))
    now = utcnow()

    if user is None:
        # Perform a dummy verification so timing does not disclose account
        # existence.
        verify_password(password or "x", hash_password("dummy-value"))
        raise AuthError("invalid e-mail or password")

    if user.locked_until and user.locked_until > now:
        raise AuthError("too many failed attempts; this account is temporarily locked")

    if not user.is_active:
        raise AuthError("this account is disabled")

    if not verify_password(password or "", user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= settings.login_max_attempts:
            user.locked_until = now + timedelta(seconds=settings.login_lockout_seconds)
            user.failed_logins = 0
            audit(db, None, "auth.lockout", "user", str(user.id), detail=f"ip={ip}")
        audit(db, None, "auth.failed", "user", str(user.id), detail=f"ip={ip}")
        db.commit()
        raise AuthError("invalid e-mail or password")

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    audit(db, user, "auth.login", "user", str(user.id), detail=f"ip={ip}")
    db.commit()
    return user


def change_password(db: Session, user: User, current: str, new: str) -> None:
    if not verify_password(current, user.password_hash):
        raise AuthError("current password is incorrect")
    problems = password_problems(new)
    if problems:
        raise AuthError("password " + ", ".join(problems))
    user.password_hash = hash_password(new)
    user.must_change_password = False
    audit(db, user, "auth.password_change", "user", str(user.id))
    db.commit()


def login_session(request, user: User) -> None:
    request.session.clear()
    request.session[SESSION_USER_KEY] = user.id
    request.session["role"] = user.role


def logout_session(request) -> None:
    request.session.clear()


def get_user(db: Session, user_id: int) -> Optional[User]:
    return db.get(User, user_id)


def audit(
    db: Session,
    actor: Optional[User],
    action: str,
    object_type: str = "",
    object_id: str = "",
    detail: str = "",
    ip: str = "",
) -> None:
    db.add(
        AuditLog(
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else "",
            action=action,
            object_type=object_type,
            object_id=object_id,
            detail=detail[:4000],
            ip_address=ip[:60],
        )
    )
