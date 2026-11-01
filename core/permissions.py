"""Role-based access control.

Four roles, least privilege by default:

``viewer``   read-only access to cases and analytics.
``analyst``  creates targets/cases, uploads evidence, records submissions.
``manager``  everything an analyst can do, plus decisions, appeals, settings.
``admin``    user management and destructive operations.
"""

from __future__ import annotations

from typing import Iterable

from database.models import User

ROLE_RANK = {"viewer": 10, "analyst": 20, "manager": 30, "admin": 40}

PERMISSIONS: dict[str, set[str]] = {
    "viewer": {
        "dashboard.view",
        "case.view",
        "evidence.view",
        "analytics.view",
        "target.view",
    },
    "analyst": {
        "dashboard.view",
        "case.view",
        "case.create",
        "case.edit",
        "case.comment",
        "case.analyze",
        "case.submit",
        "case.export",
        "evidence.view",
        "evidence.upload",
        "evidence.export",
        "target.view",
        "target.create",
        "target.edit",
        "analytics.view",
        "notification.view",
    },
    "manager": {
        "dashboard.view",
        "case.view",
        "case.create",
        "case.edit",
        "case.delete",
        "case.comment",
        "case.analyze",
        "case.submit",
        "case.decide",
        "case.transition",
        "case.export",
        "appeal.manage",
        "evidence.view",
        "evidence.upload",
        "evidence.delete",
        "evidence.export",
        "target.view",
        "target.create",
        "target.edit",
        "target.delete",
        "analytics.view",
        "notification.view",
        "settings.view",
    },
    "admin": {"*"},
}


class PermissionDenied(Exception):
    """Raised when a user lacks the permission an action requires."""


def role_permissions(role: str) -> set[str]:
    return PERMISSIONS.get(role, set())


def can(user: User | None, action: str) -> bool:
    if user is None or not user.is_active:
        return False
    granted = role_permissions(user.role)
    return "*" in granted or action in granted


def require(user: User | None, action: str) -> User:
    if user is None:
        raise PermissionDenied("authentication required")
    if not can(user, action):
        raise PermissionDenied(f"role '{user.role}' cannot perform '{action}'")
    return user


def allowed_roles() -> Iterable[str]:
    return ROLE_RANK.keys()
