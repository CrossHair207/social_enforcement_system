"""Target and case lifecycle management."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from core.security import encrypt_sensitive
from database.models import (
    PLATFORM_LABELS,
    PRIORITIES,
    EnforcementCase,
    Target,
    User,
    utcnow,
)
from platforms import VIOLATION_CATEGORIES, registry
from platforms.base_platform import ParsedTarget, PlatformError
from utils.validators import ValidationError, validate_email, validate_text

REQUESTED_ACTIONS = (
    "content_removal",
    "account_suspension",
    "account_disabling",
    "page_removal",
    "account_deletion",
    "temporary_restriction",
)


class CaseError(Exception):
    """A case or target operation was rejected."""


def next_case_ref(db: Session) -> str:
    year = datetime.now().year
    prefix = f"SE-{year}-"
    count = db.scalar(
        select(func.count(EnforcementCase.id)).where(
            EnforcementCase.case_ref.like(prefix + "%")
        )
    )
    sequence = int(count or 0) + 1
    while db.scalar(
        select(EnforcementCase.id).where(
            EnforcementCase.case_ref == f"{prefix}{sequence:04d}"
        )
    ):
        sequence += 1
    return f"{prefix}{sequence:04d}"


def create_target(
    db: Session,
    *,
    platform_key: str,
    url: str,
    actor: Optional[User] = None,
    display_name: str = "",
    category: str = "",
    notes: str = "",
    kind_override: str = "",
) -> Target:
    try:
        platform = registry.get(platform_key)
        parsed = platform.parse(url)
    except PlatformError as exc:
        raise CaseError(str(exc)) from exc

    signature = parsed.url.lower().rstrip("/")
    if db.scalar(select(Target.id).where(Target.url_signature == signature)):
        raise CaseError(f"target '{parsed.url}' is already recorded")

    target = Target(
        platform=platform.key,
        url=parsed.url,
        url_signature=signature,
        public_identifier=parsed.identifier,
        display_name=validate_text(display_name, field="display name", max_length=200),
        target_kind=kind_override or parsed.kind,
        category=validate_text(category, field="category", max_length=80),
        notes=validate_text(notes, field="notes", max_length=4000),
        created_by_id=actor.id if actor else None,
    )
    db.add(target)
    db.commit()
    return target


def detect_platform(url: str) -> Optional[ParsedTarget]:
    return registry.detect(url)


def create_case(
    db: Session,
    *,
    target: Target,
    violation_category: str,
    title: str,
    description: str,
    actor: Optional[User] = None,
    priority: str = "normal",
    requested_action: str = "account_disabling",
    reporter_name: str = "",
    reporter_email: str = "",
    reporter_org: str = "",
) -> EnforcementCase:
    if violation_category not in VIOLATION_CATEGORIES:
        raise CaseError(f"unknown violation category '{violation_category}'")
    if priority not in PRIORITIES:
        raise CaseError(f"priority must be one of {', '.join(PRIORITIES)}")
    if requested_action not in REQUESTED_ACTIONS:
        raise CaseError(f"requested action must be one of {', '.join(REQUESTED_ACTIONS)}")

    case = EnforcementCase(
        case_ref=next_case_ref(db),
        title=validate_text(title, field="title", required=True, max_length=250),
        target_id=target.id,
        owner_id=actor.id if actor else None,
        violation_category=violation_category,
        priority=priority,
        description=validate_text(description, field="description", max_length=8000),
        requested_action=requested_action,
        reporter_name=validate_text(reporter_name, field="reporter name", max_length=150),
        reporter_org=validate_text(reporter_org, field="organisation", max_length=150),
        reporter_email_enc=encrypt_sensitive(
            validate_email(reporter_email, required=False)
        ),
    )
    db.add(case)
    db.commit()
    return case


def get_case(db: Session, case_id: int) -> Optional[EnforcementCase]:
    return db.get(EnforcementCase, case_id)


def search_cases(
    db: Session,
    *,
    query: str = "",
    status: str = "",
    platform: str = "",
    category: str = "",
    priority: str = "",
    owner_id: Optional[int] = None,
) -> list[EnforcementCase]:
    statement = select(EnforcementCase).join(Target)
    if query:
        like = f"%{query.strip()}%"
        statement = statement.where(
            or_(
                EnforcementCase.case_ref.ilike(like),
                EnforcementCase.title.ilike(like),
                Target.url.ilike(like),
                Target.public_identifier.ilike(like),
            )
        )
    if status:
        statement = statement.where(EnforcementCase.status == status)
    if platform:
        statement = statement.where(Target.platform == platform)
    if category:
        statement = statement.where(EnforcementCase.violation_category == category)
    if priority:
        statement = statement.where(EnforcementCase.priority == priority)
    if owner_id:
        statement = statement.where(EnforcementCase.owner_id == owner_id)
    return list(db.scalars(statement.order_by(EnforcementCase.created_at.desc())))


def update_case(db: Session, case: EnforcementCase, **fields) -> EnforcementCase:
    allowed = {
        "title",
        "description",
        "priority",
        "requested_action",
        "violation_category",
        "reporter_name",
        "reporter_org",
        "manual_review_confirmed",
    }
    unknown = set(fields) - allowed - {"reporter_email"}
    if unknown:
        raise CaseError(f"cannot update fields: {', '.join(sorted(unknown))}")
    if (
        "violation_category" in fields
        and fields["violation_category"] not in VIOLATION_CATEGORIES
    ):
        raise CaseError("unknown violation category")
    if "priority" in fields and fields["priority"] not in PRIORITIES:
        raise CaseError("invalid priority")
    if (
        "requested_action" in fields
        and fields["requested_action"] not in REQUESTED_ACTIONS
    ):
        raise CaseError("invalid requested action")
    for key, value in fields.items():
        if key == "reporter_email":
            case.reporter_email_enc = encrypt_sensitive(
                validate_email(value, required=False)
            )
        elif key == "title":
            case.title = validate_text(value, field="title", required=True, max_length=250)
        elif key == "description":
            case.description = validate_text(value, field="description", max_length=8000)
        else:
            setattr(case, key, value)
    db.commit()
    return case


def delete_case(db: Session, case: EnforcementCase) -> None:
    db.delete(case)
    db.commit()


def import_targets(db: Session, rows: Iterable[dict], *, actor: Optional[User] = None) -> dict:
    """Import targets from parsed CSV/JSON rows; never aborts on one bad row."""
    created, skipped, errors = 0, 0, []
    for index, row in enumerate(rows, start=2):
        url = str(row.get("url") or row.get("target_url") or "").strip()
        platform_key = str(row.get("platform") or "").strip().lower()
        if not url:
            errors.append({"row": index, "error": "missing url"})
            continue
        if not platform_key:
            detected = registry.detect(url)
            if not detected:
                errors.append({"row": index, "error": "could not detect platform", "url": url})
                continue
            platform_key = detected.platform
        try:
            create_target(
                db,
                platform_key=platform_key,
                url=url,
                actor=actor,
                display_name=str(row.get("display_name") or ""),
                category=str(row.get("category") or ""),
                notes=str(row.get("notes") or ""),
            )
            created += 1
        except (CaseError, ValidationError) as exc:
            message = str(exc)
            if "already recorded" in message:
                skipped += 1
            else:
                errors.append({"row": index, "error": message, "url": url})
    return {"created": created, "skipped": skipped, "errors": errors}


def platform_label(key: str) -> str:
    return PLATFORM_LABELS.get(key, key.replace("_", " ").title())


def overdue_cases(db: Session) -> list[EnforcementCase]:
    return list(
        db.scalars(
            select(EnforcementCase).where(
                EnforcementCase.follow_up_at.is_not(None),
                EnforcementCase.follow_up_at <= utcnow(),
                EnforcementCase.status.in_(
                    (
                        "submitted_to_platform",
                        "under_platform_review",
                        "additional_info_requested",
                    )
                ),
            )
        )
    )
