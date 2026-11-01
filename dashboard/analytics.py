"""Aggregate statistics for the dashboard.

Confirmed enforcement outcomes are counted separately from unverified or
pending cases, so the headline numbers cannot overstate what the platforms have
actually decided.
"""

from __future__ import annotations

from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session

from database.models import (
    CONFIRMED_OUTCOMES,
    PLATFORM_LABELS,
    STATUS_LABELS,
    Appeal,
    EnforcementCase,
    Evidence,
    Submission,
    Target,
)
from platforms import VIOLATION_CATEGORIES

PENDING_STATUSES = (
    "new_case",
    "under_investigation",
    "evidence_required",
    "evidence_verified",
    "ready_for_submission",
    "submitted_to_platform",
    "under_platform_review",
    "additional_info_requested",
    "temporarily_restricted",
)


def _count(db: Session, statement) -> int:
    return int(db.scalar(statement) or 0)


def overview(db: Session) -> dict:
    total_cases = _count(db, select(func.count(EnforcementCase.id)))
    submitted = _count(
        db, select(func.count(EnforcementCase.id)).where(EnforcementCase.submitted_at.is_not(None))
    )
    confirmed_rows = db.execute(
        select(EnforcementCase.status, func.count(EnforcementCase.id))
        .where(
            EnforcementCase.status.in_(CONFIRMED_OUTCOMES),
            EnforcementCase.decision_source == "platform_confirmation",
        )
        .group_by(EnforcementCase.status)
    ).all()
    confirmed = {status: int(count) for status, count in confirmed_rows}
    confirmed_total = sum(confirmed.values())

    pending = _count(
        db, select(func.count(EnforcementCase.id)).where(EnforcementCase.status.in_(PENDING_STATUSES))
    )
    rejected = _count(
        db, select(func.count(EnforcementCase.id)).where(EnforcementCase.status == "rejected")
    )
    appeals_open = _count(
        db,
        select(func.count(Appeal.id)).where(
            Appeal.status.in_(("drafted", "submitted", "under_review"))
        ),
    )
    evidence_total = _count(db, select(func.count(Evidence.id)))
    submission_total = _count(db, select(func.count(Submission.id)))
    targets_total = _count(db, select(func.count(Target.id)))

    unverified_outcomes = _count(
        db,
        select(func.count(EnforcementCase.id)).where(
            EnforcementCase.status.in_(CONFIRMED_OUTCOMES),
            EnforcementCase.decision_source != "platform_confirmation",
        ),
    )

    return {
        "total_cases": total_cases,
        "submitted_cases": submitted,
        "confirmed_total": confirmed_total,
        "permanently_disabled": confirmed.get("permanently_disabled", 0),
        "pages_removed": confirmed.get("page_removed", 0),
        "content_removed": confirmed.get("content_removed", 0),
        "pending_cases": pending,
        "rejected_cases": rejected,
        "open_appeals": appeals_open,
        "evidence_items": evidence_total,
        "submissions": submission_total,
        "targets": targets_total,
        "unverified_outcomes": unverified_outcomes,
        "confirmation_rate": round(confirmed_total / submitted * 100, 1) if submitted else 0.0,
    }


def by_status(db: Session) -> list[dict]:
    rows = db.execute(
        select(EnforcementCase.status, func.count(EnforcementCase.id)).group_by(
            EnforcementCase.status
        )
    ).all()
    counts = {status: int(count) for status, count in rows}
    return [
        {"status": status, "label": label, "count": counts.get(status, 0)}
        for status, label in STATUS_LABELS.items()
    ]


def by_platform(db: Session) -> list[dict]:
    confirmed_expr = func.sum(
        case(
            (
                and_(
                    EnforcementCase.status.in_(CONFIRMED_OUTCOMES),
                    EnforcementCase.decision_source == "platform_confirmation",
                ),
                1,
            ),
            else_=0,
        )
    )
    rows = db.execute(
        select(
            Target.platform,
            func.count(EnforcementCase.id),
            confirmed_expr,
        )
        .join(EnforcementCase, EnforcementCase.target_id == Target.id)
        .group_by(Target.platform)
    ).all()
    result = []
    for platform, total, confirmed in rows:
        result.append(
            {
                "platform": platform,
                "label": PLATFORM_LABELS.get(platform, platform),
                "cases": int(total or 0),
                "confirmed": int(confirmed or 0),
            }
        )
    return sorted(result, key=lambda item: item["cases"], reverse=True)


def by_category(db: Session) -> list[dict]:
    rows = db.execute(
        select(EnforcementCase.violation_category, func.count(EnforcementCase.id)).group_by(
            EnforcementCase.violation_category
        )
    ).all()
    return [
        {
            "category": category,
            "label": str(VIOLATION_CATEGORIES.get(category, {}).get("label", category)),
            "count": int(count),
        }
        for category, count in sorted(rows, key=lambda row: row[1], reverse=True)
    ]


def recent_cases(db: Session, limit: int = 8) -> list[EnforcementCase]:
    return list(
        db.scalars(
            select(EnforcementCase)
            .order_by(EnforcementCase.created_at.desc())
            .limit(limit)
        )
    )


def confirmed_outcomes(db: Session, limit: int = 10) -> list[EnforcementCase]:
    return list(
        db.scalars(
            select(EnforcementCase)
            .where(
                EnforcementCase.status.in_(CONFIRMED_OUTCOMES),
                EnforcementCase.decision_source == "platform_confirmation",
            )
            .order_by(EnforcementCase.decision_at.desc())
            .limit(limit)
        )
    )


def chart_payload(db: Session) -> dict:
    return {
        "status": by_status(db),
        "platform": by_platform(db),
        "category": by_category(db),
        "overview": overview(db),
    }
