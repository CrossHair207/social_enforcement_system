"""Violation analysis and enforcement workflow rules."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from database.models import utcnow
from enforcement import appeal_manager, status_tracker, submission_manager
from enforcement.violation_analyzer import analyze, analyze_case, apply_analysis
from evidence.evidence_manager import store_evidence
from tests.conftest import create_case, create_target

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PDF = b"%PDF-1.4\n" + b"licence" * 20

LONG_DESCRIPTION = (
    "Between 2024-05-01 and 2024-05-05 the Page published three posts that copy our "
    "registered logo and our product photography, and the account sent messages to "
    "customers asking them to pay an invoice through a link that copies our login page. "
    "Customers reported the messages to our support inbox. We hold the trademark "
    "registration and the copyright in the photographs, and we have never licensed "
    "this Page to use either. The posts were captured on 2024-05-02 and the messages "
    "on 2024-05-04, each with a screenshot and the direct URL recorded in this case."
)


def _new_case(db, platform="instagram", **kwargs):
    target = create_target(
        db,
        platform_key=platform,
        url=f"https://www.{'instagram.com' if platform == 'instagram' else 'tiktok.com/@x' if platform == 'tiktok' else 'facebook.com'}/{abs(hash(kwargs.get('title', 't')))}",
    )
    return create_case(
        db,
        target=target,
        violation_category=kwargs.pop("violation_category", "copyright"),
        description=kwargs.pop("description", LONG_DESCRIPTION),
        **kwargs,
    )


def _strong_evidence(db, case):
    store_evidence(
        db, case, filename="one.png", data=PNG, kind="screenshot",
        captured_at=datetime(2024, 5, 2, tzinfo=timezone.utc),
    )
    store_evidence(
        db, case, filename="two.png", data=PNG + b"2", kind="screenshot",
        captured_at=datetime(2024, 5, 4, tzinfo=timezone.utc),
    )
    store_evidence(
        db, case, filename="licence.pdf", data=PDF, kind="ownership_document",
        description="Trademark registration certificate",
    )
    store_evidence(
        db, case, filename="post-url.txt", data=b"https://example.test/post/1",
        kind="post_url", source_url="https://example.test/post/1",
    )


def test_empty_case_scores_insufficient(db):
    case = _new_case(db, description="")
    result = analyze_case(case)
    assert result.confidence == "insufficient"
    assert result.score < 25
    assert result.missing_evidence
    assert result.verdict == "support_level_only"


def test_opinion_only_description_is_penalised(db):
    case = _new_case(db, description="I hate this account, it is annoying and stupid and everyone knows it.")
    result = analyze_case(case)
    assert any("opinion" in warning.lower() for warning in result.warnings)
    assert result.confidence == "insufficient"


def test_strong_evidence_raises_support_level(db):
    case = _new_case(db)
    _strong_evidence(db, case)
    result = analyze_case(case)
    assert result.score >= 70
    assert result.confidence == "strong"
    assert any("ownership" in item.lower() for item in result.missing_evidence) is False


def test_ip_category_requires_ownership_document(db):
    case = _new_case(db)
    store_evidence(
        db, case, filename="one.png", data=PNG, kind="screenshot",
        captured_at=utcnow(),
    )
    result = analyze_case(case)
    assert any("ownership" in item.lower() for item in result.missing_evidence)


def test_analyzer_ignores_target_popularity(db):
    target = create_target(db, platform_key="instagram", url="https://www.instagram.com/famous")
    target.display_name = "Very Famous Brand"
    case = create_case(
        db, target=target, violation_category="impersonation",
        title="popular account", description="",
    )
    assert analyze_case(case).confidence == "insufficient"


def test_ready_for_submission_needs_review_and_analysis(db):
    case = _new_case(db)
    _strong_evidence(db, case)
    status_tracker.transition(db, case, "under_investigation")

    with pytest.raises(status_tracker.StatusError):
        status_tracker.transition(db, case, "ready_for_submission")

    apply_analysis(case, analyze_case(case))
    case.manual_review_confirmed = True
    db.commit()
    status_tracker.transition(db, case, "ready_for_submission")
    assert case.status == "ready_for_submission"


def test_platform_status_requires_platform_source(db):
    case = _new_case(db)
    _strong_evidence(db, case)
    apply_analysis(case, analyze_case(case))
    case.manual_review_confirmed = True
    db.commit()
    status_tracker.transition(db, case, "under_investigation")
    status_tracker.transition(db, case, "ready_for_submission")
    submission_manager.record_submission(
        db, case, channel_label="In-app report", reference="REF-12345"
    )
    assert case.status == "submitted_to_platform"

    with pytest.raises(status_tracker.StatusError):
        status_tracker.transition(db, case, "permanently_disabled", note="looks removed")

    submission_manager.record_platform_response(
        db,
        case,
        status="permanently_disabled",
        reference="FB-998877",
        note="Platform message: the account has been permanently disabled.",
    )
    assert case.status == "permanently_disabled"
    assert case.is_confirmed_outcome is True
    assert case.decision_source == "platform_confirmation"


def test_submission_requires_evidence_and_review(db):
    case = _new_case(db)
    with pytest.raises(submission_manager.SubmissionError):
        submission_manager.record_submission(
            db, case, channel_label="In-app", reference="X-1"
        )


def test_submission_rejects_unofficial_api_method(db):
    case = _new_case(db)
    _strong_evidence(db, case)
    apply_analysis(case, analyze_case(case))
    case.manual_review_confirmed = True
    db.commit()
    with pytest.raises(submission_manager.SubmissionError):
        submission_manager.record_submission(
            db, case, channel_label="API", reference="X-1", method="official_api"
        )


def test_appeal_requires_recorded_decision(db):
    case = _new_case(db)
    with pytest.raises(appeal_manager.AppealError):
        appeal_manager.create_appeal(db, case, reason="The decision was based on a mistake of fact.")


def test_appeal_lifecycle(db):
    case = _new_case(db)
    _strong_evidence(db, case)
    apply_analysis(case, analyze_case(case))
    case.manual_review_confirmed = True
    db.commit()
    status_tracker.transition(db, case, "under_investigation")
    status_tracker.transition(db, case, "ready_for_submission")
    submission_manager.record_submission(db, case, channel_label="In-app", reference="R-1")
    submission_manager.record_platform_response(
        db, case, status="rejected", reference="R-2", note="Rejected: no violation found."
    )

    appeal = appeal_manager.create_appeal(
        db, case, reason="The platform misread the ownership document that was attached."
    )
    assert appeal.status == "drafted"
    appeal_manager.record_appeal_submission(db, appeal, reference="AP-1")
    assert appeal.status == "submitted"
    appeal_manager.record_appeal_outcome(db, appeal, status="granted", outcome="Content removed.")
    assert appeal.status == "granted"


def test_invalid_transition_blocked(db):
    case = _new_case(db)
    with pytest.raises(status_tracker.StatusError):
        status_tracker.transition(db, case, "permanently_disabled", source="platform_confirmation", reference="x")


def test_analyze_function_direct():
    result = analyze(
        platform_key="tiktok",
        category="harassment",
        description=LONG_DESCRIPTION,
        evidence_items=[],
    )
    assert result.recommended_action == "account_disabling"
    assert result.policy_match["platform"] == "tiktok"


def test_official_api_submission_path_with_mock_platform(db):
    """A platform that *did* offer a takedown API would unlock the API path."""
    from platforms import registry
    from platforms.base_platform import ApiCapability
    from platforms.instagram import InstagramPlatform

    class MockApiPlatform(InstagramPlatform):
        key = "mock_api"
        label = "Mock platform with enforcement API"

        def api_capability(self) -> ApiCapability:
            return ApiCapability(
                takedown_submission=True,
                status_retrieval=True,
                notes="Mock: a public enforcement API exists for this test.",
            )

    registry.register(MockApiPlatform())
    try:
        target = create_target(
            db, platform_key="mock_api", url="https://www.instagram.com/mock_target"
        )
        case = create_case(
            db,
            target=target,
            violation_category="copyright",
            title="Mock API submission",
            description=LONG_DESCRIPTION,
        )
        _strong_evidence(db, case)
        apply_analysis(case, analyze_case(case))
        case.manual_review_confirmed = True
        db.commit()

        submission = submission_manager.record_submission(
            db,
            case,
            channel_label="Mock enforcement API",
            reference="API-REF-1",
            method="official_api",
        )
        assert submission.method == "official_api"
        assert case.status == "submitted_to_platform"
    finally:
        registry._platforms.pop("mock_api", None)