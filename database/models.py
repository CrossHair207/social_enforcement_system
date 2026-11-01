"""SQLAlchemy ORM models.

Design notes
------------
* Every enforcement case is tied to exactly one public target and one owning
  staff user, so multi-case work never mixes evidence between cases.
* Nothing in the schema stores credentials for a third-party social account.
  The only secret material held is the *reporter's* contact address, which is
  encrypted at rest (see ``core/security.py``).
* Enforcement outcomes are never free text only: decisions carry a
  ``decision_source`` so an unverified claim can never be reported as a
  platform-confirmed removal.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import DateTime as _DateTime
from sqlalchemy import TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC timestamps on every backend.

    SQLite discards the offset, returning naive datetimes. Without this
    decorator a naive value compared against an aware ``utcnow()`` raises
    ``TypeError`` at runtime, so every datetime column uses this type.
    """

    impl = _DateTime
    cache_ok = True

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("timezone", True)
        super().__init__(*args, **kwargs)

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


# Every model below refers to ``DateTime``; binding the name to the UTC-aware
# decorator keeps all columns consistent.
DateTime = UTCDateTime


ROLES = ("admin", "manager", "analyst", "viewer")

PRIORITIES = ("low", "normal", "high", "urgent")

STATUSES = (
    "new_case",
    "under_investigation",
    "evidence_required",
    "evidence_verified",
    "ready_for_submission",
    "submitted_to_platform",
    "under_platform_review",
    "additional_info_requested",
    "temporarily_restricted",
    "permanently_disabled",
    "page_removed",
    "content_removed",
    "rejected",
    "appealed",
    "closed",
)

STATUS_LABELS = {
    "new_case": "New Case",
    "under_investigation": "Under Investigation",
    "evidence_required": "Evidence Required",
    "evidence_verified": "Evidence Verified",
    "ready_for_submission": "Ready for Submission",
    "submitted_to_platform": "Submitted to Platform",
    "under_platform_review": "Under Platform Review",
    "additional_info_requested": "Additional Information Requested",
    "temporarily_restricted": "Temporarily Restricted",
    "permanently_disabled": "Permanently Disabled",
    "page_removed": "Page Removed",
    "content_removed": "Content Removed",
    "rejected": "Rejected",
    "appealed": "Appealed",
    "closed": "Closed",
}

#: Statuses that represent a real, platform-confirmed enforcement result.
CONFIRMED_OUTCOMES = ("permanently_disabled", "page_removed", "content_removed")

TERMINAL_STATUSES = ("permanently_disabled", "page_removed", "content_removed", "rejected", "closed")

PLATFORMS = ("facebook_personal", "facebook_pages", "instagram", "tiktok")

PLATFORM_LABELS = {
    "facebook_personal": "Facebook Personal Account",
    "facebook_pages": "Facebook Page",
    "instagram": "Instagram Account",
    "tiktok": "TikTok Account",
}


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)

    cases: Mapped[list["EnforcementCase"]] = relationship(back_populates="owner")

    def has_role(self, *roles: str) -> bool:
        return self.role in roles


class Target(TimestampMixin, Base):
    """A public social media account or Page that a case is about."""

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("url_signature", name="uq_target_signature"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    platform: Mapped[str] = mapped_column(String(40), index=True)
    url: Mapped[str] = mapped_column(String(700))
    url_signature: Mapped[str] = mapped_column(String(700), index=True)
    public_identifier: Mapped[str] = mapped_column(String(200), default="")
    display_name: Mapped[str] = mapped_column(String(200), default="")
    target_kind: Mapped[str] = mapped_column(String(30), default="account")
    category: Mapped[str] = mapped_column(String(80), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)

    cases: Mapped[list["EnforcementCase"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class EnforcementCase(TimestampMixin, Base):
    __tablename__ = "enforcement_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_ref: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(250))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    owner_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)

    violation_category: Mapped[str] = mapped_column(String(60))
    priority: Mapped[str] = mapped_column(String(20), default="normal")
    status: Mapped[str] = mapped_column(String(40), default="new_case", index=True)
    status_source: Mapped[str] = mapped_column(String(40), default="internal_review")

    description: Mapped[str] = mapped_column(Text, default="")
    requested_action: Mapped[str] = mapped_column(String(60), default="account_disabling")

    confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    evidence_confidence: Mapped[str] = mapped_column(String(30), default="unassessed")
    recommended_channel: Mapped[str] = mapped_column(String(120), default="")
    policy_matches_json: Mapped[str] = mapped_column(Text, default="[]")
    analysis_json: Mapped[str] = mapped_column(Text, default="{}")
    manual_review_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)

    reporter_name: Mapped[str] = mapped_column(String(150), default="")
    reporter_org: Mapped[str] = mapped_column(String(150), default="")
    reporter_email_enc: Mapped[str] = mapped_column(Text, default="")

    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    follow_up_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    appeal_deadline_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)

    decision_summary: Mapped[str] = mapped_column(Text, default="")
    decision_source: Mapped[str] = mapped_column(String(40), default="none")
    decision_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    decision_reference: Mapped[str] = mapped_column(String(200), default="")

    target: Mapped[Target] = relationship(back_populates="cases")
    owner: Mapped[Optional[User]] = relationship(back_populates="cases")
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="Evidence.id"
    )
    status_events: Mapped[list["StatusEvent"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="StatusEvent.id"
    )
    notes: Mapped[list["CaseNote"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.id"
    )
    submissions: Mapped[list["Submission"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="Submission.id"
    )
    appeals: Mapped[list["Appeal"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="Appeal.id"
    )

    @property
    def is_confirmed_outcome(self) -> bool:
        return bool(
            self.status in CONFIRMED_OUTCOMES and self.decision_source == "platform_confirmation"
        )


class Evidence(TimestampMixin, Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("enforcement_cases.id"), index=True)
    original_name: Mapped[str] = mapped_column(String(400))
    stored_name: Mapped[str] = mapped_column(String(200))
    rel_path: Mapped[str] = mapped_column(String(700))
    media_type: Mapped[str] = mapped_column(String(150), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(40), default="screenshot")
    description: Mapped[str] = mapped_column(Text, default="")
    source_url: Mapped[str] = mapped_column(String(700), default="")
    captured_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    uploaded_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)

    case: Mapped[EnforcementCase] = relationship(back_populates="evidence")
    events: Mapped[list["EvidenceEvent"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan", order_by="EvidenceEvent.id"
    )


class EvidenceEvent(Base):
    __tablename__ = "evidence_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), index=True)
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(Text, default="")
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    evidence: Mapped[Evidence] = relationship(back_populates="events")


class StatusEvent(Base):
    __tablename__ = "status_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("enforcement_cases.id"), index=True)
    from_status: Mapped[str] = mapped_column(String(40), default="")
    to_status: Mapped[str] = mapped_column(String(40))
    note: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(40), default="internal_review")
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[EnforcementCase] = relationship(back_populates="status_events")


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("enforcement_cases.id"), index=True)
    author_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[EnforcementCase] = relationship(back_populates="notes")


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("enforcement_cases.id"), index=True)
    platform: Mapped[str] = mapped_column(String(40))
    channel: Mapped[str] = mapped_column(String(120))
    method: Mapped[str] = mapped_column(String(20), default="manual")  # manual | official_api
    reference: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(40), default="recorded")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    notes: Mapped[str] = mapped_column(Text, default="")
    submitted_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[EnforcementCase] = relationship(back_populates="submissions")


class Appeal(TimestampMixin, Base):
    __tablename__ = "appeals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("enforcement_cases.id"), index=True)
    reference: Mapped[str] = mapped_column(String(200), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(40), default="drafted")
    outcome: Mapped[str] = mapped_column(Text, default="")
    deadline_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    submitted_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)

    case: Mapped[EnforcementCase] = relationship(back_populates="appeals")


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)
    case_id: Mapped[Optional[int]] = mapped_column(ForeignKey("enforcement_cases.id"), default=None)
    level: Mapped[str] = mapped_column(String(20), default="info")
    title: Mapped[str] = mapped_column(String(250))
    body: Mapped[str] = mapped_column(Text, default="")
    channel: Mapped[str] = mapped_column(String(20), default="in_app")
    delivery_status: Mapped[str] = mapped_column(String(40), default="stored")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), default=None)
    actor_email: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(80), index=True)
    object_type: Mapped[str] = mapped_column(String(60), default="")
    object_id: Mapped[str] = mapped_column(String(60), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip_address: Mapped[str] = mapped_column(String(60), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)