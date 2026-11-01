"""Record and prepare official enforcement submissions."""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from database.models import EnforcementCase, Submission, User
from enforcement import status_tracker
from enforcement.policy_matcher import match
from enforcement.violation_analyzer import load_analysis
from platforms import registry


class SubmissionError(Exception):
    """A submission cannot be prepared or recorded yet."""


def build_submission_package(case: EnforcementCase) -> dict:
    """Everything the operator needs to file the report through the official channel."""
    platform = registry.get(case.target.platform)
    policy = match(case.violation_category, case.target.platform)
    analysis = load_analysis(case)

    blockers: list[str] = []
    if not case.evidence:
        blockers.append("No evidence is filed.")
    if not case.manual_review_confirmed:
        blockers.append("Manual review has not been confirmed.")
    if case.evidence_confidence in {"unassessed", "insufficient"}:
        blockers.append("Violation analysis has not reached a usable support level.")
    if not case.description.strip():
        blockers.append("The case has no conduct description.")

    return {
        "case_reference": case.case_ref,
        "platform": platform.key,
        "platform_label": platform.label,
        "target_url": case.target.url,
        "target_identifier": case.target.public_identifier,
        "category": policy.category,
        "category_label": policy.category_label,
        "policies": policy.policies,
        "channel": policy.channel,
        "evidence_count": len(case.evidence),
        "evidence_confidence": case.evidence_confidence,
        "confidence_score": case.confidence_score,
        "requested_action": case.requested_action,
        "manual_review_confirmed": case.manual_review_confirmed,
        "api_capability": platform.api_capability().__dict__,
        "instructions": platform.submission_instructions(case.violation_category),
        "analysis_summary": analysis.get("summary", ""),
        "blockers": blockers,
        "ready": not blockers,
    }


def record_submission(
    db: Session,
    case: EnforcementCase,
    *,
    channel_label: str,
    reference: str,
    method: str = "manual",
    notes: str = "",
    actor: Optional[User] = None,
) -> Submission:
    """Persist a submission the operator actually made, then advance the case."""
    package = build_submission_package(case)
    if package["blockers"]:
        raise SubmissionError("; ".join(package["blockers"]))
    if method not in {"manual", "official_api"}:
        raise SubmissionError("method must be 'manual' or 'official_api'")
    if method == "official_api" and not package["api_capability"]["takedown_submission"]:
        raise SubmissionError(
            "this platform has no public takedown API; record the submission as 'manual'"
        )
    channel_label = (channel_label or package["channel"]["label"]).strip()[:120]
    reference = (reference or "").strip()[:200]
    if not reference:
        raise SubmissionError(
            "record the reference, case number or confirmation text the platform returned"
        )

    submission = Submission(
        case_id=case.id,
        platform=case.target.platform,
        channel=channel_label,
        method=method,
        reference=reference,
        status="recorded",
        payload_json=json.dumps(package, default=str),
        notes=(notes or "").strip()[:4000],
        submitted_by_id=actor.id if actor else None,
    )
    db.add(submission)
    db.flush()

    # A submission can only be recorded from a ready case. If the operator has
    # already filed the report before clicking through the internal stages, walk
    # the case forward so the history reflects the checks that just ran. Each
    # step re-validates the evidence, analysis and manual-review requirements.
    if case.status == "new_case":
        status_tracker.transition(
            db,
            case,
            "under_investigation",
            actor=actor,
            note="Advanced automatically when the submission was recorded.",
        )
    if case.status in ("under_investigation", "evidence_required", "evidence_verified"):
        status_tracker.transition(
            db,
            case,
            "ready_for_submission",
            actor=actor,
            note="Readiness checks passed when the submission was recorded.",
        )

    if case.status not in (
        "submitted_to_platform",
        "under_platform_review",
        "additional_info_requested",
    ):
        status_tracker.transition(
            db,
            case,
            "submitted_to_platform",
            actor=actor,
            note=f"Submitted via {channel_label} (ref: {reference})",
            source="internal_review",
        )
    db.commit()
    return submission


def record_platform_response(
    db: Session,
    case: EnforcementCase,
    *,
    status: str,
    reference: str,
    note: str,
    actor: Optional[User] = None,
) -> None:
    """Apply a platform-reported outcome, quoted from the platform's message."""
    status_tracker.transition(
        db,
        case,
        status,
        actor=actor,
        note=note,
        source="platform_confirmation",
        reference=reference,
    )
