"""Notification creation and delivery.

In-app notifications are always stored. E-mail is attempted only when SMTP is
configured, and the recorded delivery status reflects what actually happened -
the application never reports an e-mail as sent when no transport exists.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from config import settings
from database.models import Notification, User

logger = logging.getLogger(__name__)


def _send_email(to_address: str, subject: str, body: str) -> tuple[str, str]:
    if not settings.smtp_host or not settings.smtp_from:
        return "smtp_not_configured", "SMTP_HOST and SMTP_FROM are not configured"
    try:
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = to_address
        message["Subject"] = subject
        message.set_content(body)

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as client:
            if settings.smtp_starttls:
                client.starttls()
            if settings.smtp_user:
                client.login(settings.smtp_user, settings.smtp_password)
            client.send_message(message)
        return "email_sent", ""
    except Exception as exc:  # pragma: no cover - network dependent
        logger.warning("e-mail delivery failed: %s", exc)
        return "email_failed", str(exc)[:300]


def notify(
    db: Session,
    *,
    title: str,
    body: str = "",
    level: str = "info",
    user_id: Optional[int] = None,
    case_id: Optional[int] = None,
    email_to: str = "",
) -> Notification:
    notification = Notification(
        user_id=user_id,
        case_id=case_id,
        level=level,
        title=title[:250],
        body=body[:4000],
        channel="in_app",
        delivery_status="stored",
    )
    db.add(notification)
    db.commit()

    if email_to:
        status, detail = _send_email(email_to, f"[SEMS] {title}", body)
        notification.channel = "in_app+email"
        notification.delivery_status = status if not detail else f"{status}: {detail}"
        db.commit()
    return notification


def notify_case_event(
    db: Session,
    *,
    case,
    title: str,
    body: str,
    level: str = "info",
) -> Notification:
    owner = db.get(User, case.owner_id) if case.owner_id else None
    return notify(
        db,
        title=title,
        body=body,
        level=level,
        user_id=owner.id if owner else None,
        case_id=case.id,
    )


def for_user(db: Session, user: User, limit: int = 50, unread_only: bool = False):
    statement = select(Notification).where(
        (Notification.user_id == user.id) | (Notification.user_id.is_(None))
    )
    if unread_only:
        statement = statement.where(Notification.is_read.is_(False))
    return list(db.scalars(statement.order_by(Notification.created_at.desc()).limit(limit)))


def unread_count(db: Session, user_id: int) -> int:
    return int(
        db.scalar(
            select(func.count(Notification.id)).where(
                Notification.is_read.is_(False),
                (Notification.user_id == user_id) | (Notification.user_id.is_(None)),
            )
        )
        or 0
    )


def mark_all_read(db: Session, user_id: int) -> int:
    result = db.execute(
        update(Notification)
        .where(
            Notification.is_read.is_(False),
            (Notification.user_id == user_id) | (Notification.user_id.is_(None)),
        )
        .values(is_read=True)
    )
    db.commit()
    return int(result.rowcount or 0)