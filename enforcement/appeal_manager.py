"""Appeal drafting and outcome tracking."""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from config import settings
from database.models import Appeal, EnforcementCase, User, utcnow

APPEAL_STATUSES = (
    "drafted",
    "submitted",
    "under_review",
    "granted",
    "denied",
    "withdrawn",
)


class AppealError(Exception):
    """An appeal operation was rejected."""


def create_appeal(
    db: Session,
    case: EnforcementCase,
    *,
    reason: str,
    actor: Optional[User] = None,
) -> Appeal:
    if not case.decision_reference:
        raise AppealError(
            "an appeal needs a recorded platform decision and its reference on this case"
        )
    reason = (reason or "").strip()
    if len(reason) < 30:
        raise AppealError("state the grounds for the appeal (at least 30 characters)")

    appeal = Appeal(
        case_id=case.id,
        reason=reason[:4000],
        status="drafted",
        deadline_at=case.appeal_deadline_at
        or (case.decision_at or utcnow())
        + timedelta(days=settings.appeal_deadline_days),
        submitted_by_id=actor.id if actor else None,
    )
    db.add(appeal)
    db.commit()
    return appeal


def record_appeal_submission(
    db: Session,
    appeal: Appeal,
    *,
    reference: str,
    actor: Optional[User] = None,
) -> Appeal:
    if not (reference or "").strip():
        raise AppealError("record the reference the platform returned for the appeal")
    appeal.reference = reference.strip()[:200]
    appeal.status = "submitted"
    appeal.submitted_at = utcnow()
    db.commit()
    return appeal


def record_appeal_outcome(
    db: Session,
    appeal: Appeal,
    *,
    status: str,
    outcome: str,
) -> Appeal:
    if status not in ("granted", "denied", "withdrawn", "under_review"):
        raise AppealError("invalid appeal outcome")
    if status != "under_review" and not (outcome or "").strip():
        raise AppealError("quote the platform's appeal outcome before recording it")
    appeal.status = status
    appeal.outcome = (outcome or "").strip()[:4000]
    db.commit()
    return appeal


def pending_appeals(db: Session) -> list[Appeal]:
    return list(
        db.scalars(
            select(Appeal).where(
                Appeal.status.in_(("drafted", "submitted", "under_review"))
            )
        )
    )