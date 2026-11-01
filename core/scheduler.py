"""Lightweight in-process reminder scheduler.

No external broker is required: a daemon thread wakes on an interval and runs
the reminder job. Jobs are idempotent and only ever create notifications from
stored case data (never from assumed platform behaviour).
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta
from typing import Callable, Optional

from sqlalchemy import select

from core.database import session_scope
from database.models import EnforcementCase, Notification, utcnow

logger = logging.getLogger(__name__)


def run_reminder_cycle(db) -> dict[str, int]:
    """Create due reminders for follow-ups and appeal deadlines."""
    now = utcnow()
    created = {"follow_up": 0, "appeal_deadline": 0, "stale_case": 0}

    due_followups = db.scalars(
        select(EnforcementCase).where(
            EnforcementCase.follow_up_at.is_not(None),
            EnforcementCase.follow_up_at <= now,
            EnforcementCase.status.in_(
                ("submitted_to_platform", "under_platform_review", "additional_info_requested")
            ),
        )
    ).all()
    for case in due_followups:
        exists = db.scalar(
            select(Notification.id).where(
                Notification.case_id == case.id,
                Notification.title.like("Follow-up due%"),
                Notification.created_at >= now - timedelta(days=3),
            )
        )
        if exists:
            continue
        db.add(
            Notification(
                user_id=case.owner_id,
                case_id=case.id,
                level="warning",
                title=f"Follow-up due for {case.case_ref}",
                body=(
                    "The scheduled follow-up date for this case has passed and the "
                    "platform has not recorded a decision. Review the case and record "
                    "the current platform response."
                ),
            )
        )
        created["follow_up"] += 1

    appeals = db.scalars(
        select(EnforcementCase).where(
            EnforcementCase.appeal_deadline_at.is_not(None),
            EnforcementCase.appeal_deadline_at <= now + timedelta(days=3),
            EnforcementCase.appeal_deadline_at >= now,
        )
    ).all()
    for case in appeals:
        exists = db.scalar(
            select(Notification.id).where(
                Notification.case_id == case.id,
                Notification.title.like("Appeal window%"),
                Notification.created_at >= now - timedelta(days=2),
            )
        )
        if exists:
            continue
        db.add(
            Notification(
                user_id=case.owner_id,
                case_id=case.id,
                level="warning",
                title=f"Appeal window closing for {case.case_ref}",
                body="The appeal deadline recorded for this case is within three days.",
            )
        )
        created["appeal_deadline"] += 1

    stale_cutoff = now - timedelta(days=30)
    stale = db.scalars(
        select(EnforcementCase).where(
            EnforcementCase.status.in_(("new_case", "evidence_required")),
            EnforcementCase.updated_at <= stale_cutoff,
        )
    ).all()
    for case in stale:
        exists = db.scalar(
            select(Notification.id).where(
                Notification.case_id == case.id,
                Notification.title.like("Case stalled%"),
                Notification.created_at >= now - timedelta(days=7),
            )
        )
        if exists:
            continue
        db.add(
            Notification(
                user_id=case.owner_id,
                case_id=case.id,
                level="info",
                title=f"Case stalled: {case.case_ref}",
                body="No status change has been recorded for 30 days.",
            )
        )
        created["stale_case"] += 1

    db.commit()
    return created


class ReminderScheduler:
    def __init__(self, interval_seconds: int = 900) -> None:
        self.interval = max(60, int(interval_seconds))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sems-reminders", daemon=True)
        self._thread.start()
        logger.info("reminder scheduler started (interval=%ss)", self.interval)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                with session_scope() as db:
                    result = run_reminder_cycle(db)
                logger.debug("reminder cycle: %s", result)
            except Exception:  # pragma: no cover - defensive
                logger.exception("reminder cycle failed")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None


scheduler = ReminderScheduler()