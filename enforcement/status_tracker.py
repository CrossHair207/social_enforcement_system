"""Case status machine.

Only two kinds of status change are accepted:

* **internal** - driven by work the operator performed (evidence filed, review
  completed, package ready). Checked against the case contents.
* **platform** - driven by a platform response the operator quotes, with a
  reference. Confirmed outcomes additionally require a recorded submission.

Anything else raises :class:`StatusError`, so a case can never drift into
"permanently disabled" because someone clicked a button.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from sqlalchemy.orm import Session

from config import settings
from database.models import (
    CONFIRMED_OUTCOMES,
    STATUS_LABELS,
    STATUSES,
    EnforcementCase,
    StatusEvent,
    User,
    utcnow,
)

INTERNAL_STATUSES = (
    "new_case",
    "under_investigation",
    "evidence_required",
    "evidence_verified",
    "ready_for_submission",
    "submitted_to_platform",
    "appealed",
    "closed",
)

PLATFORM_STATUSES = (
    "under_platform_review",
    "additional_info_requested",
    "temporarily_restricted",
    "permanently_disabled",
    "page_removed",
    "content_removed",
    "rejected",
)

PLATFORM_SOURCES = ("platform_confirmation", "platform_message")

ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "new_case": ("under_investigation", "evidence_required", "closed"),
    "under_investigation": (
        "evidence_required", "evidence_verified", "ready_for_submission", "closed"
    ),
    "evidence_required": (
        "under_investigation", "evidence_verified", "ready_for_submission", "closed"
    ),
    "evidence_verified": (
        "under_investigation", "evidence_required", "ready_for_submission", "closed"
    ),
    "ready_for_submission": (
        "under_investigation", "evidence_required", "submitted_to_platform", "closed"
    ),
    "submitted_to_platform": (
        "under_platform_review",
        "additional_info_requested",
        "temporarily_restricted",
        "permanently_disabled",
        "page_removed",
        "content_removed",
        "rejected",
        "closed",
    ),
    "under_platform_review": (
        "additional_info_requested",
        "temporarily_restricted",
        "permanently_disabled",
        "page_removed",
        "content_removed",
        "rejected",
        "closed",
    ),
    "additional_info_requested": (
        "under_platform_review",
        "temporarily_restricted",
        "permanently_disabled",
        "page_removed",
        "content_removed",
        "rejected",
        "closed",
    ),
    "temporarily_restricted": (
        "under_platform_review",
        "permanently_disabled",
        "page_removed",
        "content_removed",
        "rejected",
        "appealed",
        "closed",
    ),
    "permanently_disabled": ("appealed", "closed"),
    "page_removed": ("appealed", "closed"),
    "content_removed": ("appealed", "closed"),
    "rejected": ("appealed", "closed"),
    "appealed": ("under_platform_review", "closed"),
    "closed": (),
}


class StatusError(Exception):
    """A status change was rejected by the workflow rules."""


def available_transitions(case: EnforcementCase) -> list[str]:
    return list(ALLOWED_TRANSITIONS.get(case.status, ()))


def can_set_directly(status: str) -> bool:
    """Whether an operator may pick this status without a platform response."""
    return status in INTERNAL_STATUSES


def _check_internal_requirements(case: EnforcementCase, to_status: str) -> None:
    if to_status == "evidence_verified" and not case.evidence:
        raise StatusError("no evidence is filed, so it cannot be marked verified")
    if to_status == "ready_for_submission":
        if not case.evidence:
            raise StatusError("a case needs at least one evidence item before it can be ready")
        if case.evidence_confidence in {"unassessed", "insufficient"}:
            raise StatusError(
                "run the violation analysis first; evidence support is "
                f"'{case.evidence_confidence}'"
            )
        if not case.manual_review_confirmed:
            raise StatusError("manual review must be confirmed before the case is ready")
    if to_status == "submitted_to_platform":
        if not case.manual_review_confirmed:
            raise StatusError("manual review must be confirmed before submission is recorded")
        if not case.submissions:
            raise StatusError("record the submission (channel and reference) before this status")


def transition(
    db: Session,
    case: EnforcementCase,
    to_status: str,
    *,
    actor: Optional[User] = None,
    note: str = "",
    source: str = "internal_review",
    reference: str = "",
) -> StatusEvent:
    if to_status not in STATUSES:
        raise StatusError(f"unknown status '{to_status}'")
    if to_status == case.status:
        raise StatusError("the case already has that status")
    if to_status not in ALLOWED_TRANSITIONS.get(case.status, ()):
        raise StatusError(
            f"cannot move from '{STATUS_LABELS.get(case.status, case.status)}' to "
            f"'{STATUS_LABELS.get(to_status, to_status)}'"
        )

    if to_status in PLATFORM_STATUSES:
        if source not in PLATFORM_SOURCES:
            raise StatusError(
                "platform-result statuses require a platform-sourced update "
                "(record the platform response with its reference)"
            )
        if not reference.strip():
            raise StatusError("a platform reference or quoted response is required")
        if not case.submissions and to_status not in {"under_platform_review"}:
            raise StatusError("no submission is recorded for this case")

    if to_status in INTERNAL_STATUSES and source in PLATFORM_SOURCES:
        raise StatusError("internal statuses cannot be set from a platform response")
    if to_status in INTERNAL_STATUSES:
        _check_internal_requirements(case, to_status)

    if to_status in CONFIRMED_OUTCOMES and not reference.strip():
        raise StatusError("confirmed outcomes need the platform's confirmation reference")

    previous = case.status
    case.status = to_status
    case.status_source = source
    if to_status in PLATFORM_STATUSES:
        case.decision_reference = reference.strip()[:200]
        case.decision_at = utcnow()
        case.decision_source = source
        case.decision_summary = note.strip()[:4000] or f"Platform reported: {to_status}"
    if to_status == "submitted_to_platform" and not case.submitted_at:
        case.submitted_at = utcnow()
        case.follow_up_at = case.submitted_at + timedelta(days=settings.follow_up_days)
    if to_status in ("rejected", "temporarily_restricted"):
        case.appeal_deadline_at = utcnow() + timedelta(days=settings.appeal_deadline_days)

    event = StatusEvent(
        case_id=case.id,
        from_status=previous,
        to_status=to_status,
        note=note.strip()[:4000],
        source=source,
        actor_id=actor.id if actor else None,
    )
    db.add(event)
    db.commit()
    return event


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status.replace("_", " ").title())
