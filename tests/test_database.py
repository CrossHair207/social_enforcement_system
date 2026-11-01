"""Database, target and case persistence tests."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from core.authentication import audit, create_user
from database.models import AuditLog, EnforcementCase, Evidence, Target
from enforcement.case_manager import CaseError, next_case_ref
from evidence.evidence_manager import store_evidence
from tests.conftest import create_case, create_target


def test_case_reference_sequence(db):
    target = create_target(db, platform_key="instagram", url="https://www.instagram.com/alpha")
    first = create_case(db, target=target)
    second = create_case(db, target=target, title="Second case")
    assert first.case_ref.endswith("0001")
    assert second.case_ref.endswith("0002")
    assert next_case_ref(db).endswith("0003")


def test_duplicate_target_is_rejected(db):
    create_target(db, platform_key="tiktok", url="https://www.tiktok.com/@dupe")
    with pytest.raises(CaseError):
        create_target(db, platform_key="tiktok", url="https://www.tiktok.com/@dupe/")


def test_target_url_is_normalised(db):
    target = create_target(
        db, platform_key="facebook_personal", url="http://facebook.com/Some.User"
    )
    assert target.url == "https://www.facebook.com/some.user"
    assert target.public_identifier == "some.user"


def test_deleting_case_removes_dependent_rows(db):
    target = create_target(db, platform_key="instagram", url="https://www.instagram.com/cascade")
    case = create_case(db, target=target)
    item = store_evidence(
        db,
        case,
        filename="shot.png",
        data=b"\x89PNG\r\n\x1a\n" + b"payload" * 10,
        kind="screenshot",
    )
    evidence_id = item.id
    db.delete(case)
    db.commit()

    assert db.get(Evidence, evidence_id) is None
    assert db.scalar(select(func.count(EnforcementCase.id))) == 0
    assert db.get(Target, target.id) is not None


def test_audit_log_records_actor(db):
    user = create_user(
        db, email="manager@example.com", password="ManagerPassw0rd!2", role="manager"
    )
    audit(db, user, "case.export", "case", "42", detail="pdf")
    db.commit()
    row = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()))
    assert row.action == "case.export"
    assert row.actor_email == "manager@example.com"
    assert row.object_id == "42"


def test_duplicate_email_rejected(db):
    from core.authentication import AuthError

    create_user(db, email="dup@example.com", password="ManagerPassw0rd!2", role="analyst")
    with pytest.raises(AuthError):
        create_user(db, email="DUP@example.com", password="ManagerPassw0rd!2", role="analyst")