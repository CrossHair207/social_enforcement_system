"""Generic input validation helpers used by forms and services."""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Optional

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class ValidationError(ValueError):
    """Raised when user input fails a documented rule."""


def validate_email(value: str, *, required: bool = True) -> str:
    value = (value or "").strip()
    if not value:
        if required:
            raise ValidationError("e-mail address is required")
        return ""
    if not EMAIL_RE.match(value) or len(value) > 255:
        raise ValidationError("e-mail address is not valid")
    return value.lower()


def validate_text(
    value: str,
    *,
    field: str,
    required: bool = False,
    min_length: int = 0,
    max_length: int = 5000,
) -> str:
    value = (value or "").strip()
    if required and not value:
        raise ValidationError(f"{field} is required")
    if len(value) < min_length and value:
        raise ValidationError(f"{field} must be at least {min_length} characters")
    if len(value) > max_length:
        raise ValidationError(f"{field} must be at most {max_length} characters")
    return value


def validate_choice(value: str, allowed: tuple[str, ...] | list[str], *, field: str) -> str:
    value = (value or "").strip()
    if value not in allowed:
        raise ValidationError(f"{field} must be one of: {', '.join(allowed)}")
    return value


def parse_datetime(value: str) -> Optional[datetime]:
    """Parse ``YYYY-MM-DD`` or an ISO-8601 timestamp into an aware UTC value."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        if len(value) == 10:
            parsed = datetime.fromisoformat(value)
            return parsed.replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise ValidationError("date must be YYYY-MM-DD or an ISO-8601 timestamp") from exc


def parse_priority(value: str) -> str:
    return validate_choice(value or "normal", ("low", "normal", "high", "urgent"), field="priority")


def humanise(value: str) -> str:
    return (value or "").replace("_", " ").strip().capitalize()


def fmt_dt(value: Optional[datetime]) -> str:
    if not value:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def fmt_date(value: Optional[date | datetime]) -> str:
    if not value:
        return "—"
    return value.strftime("%Y-%m-%d")
