"""Canonical case document model shared by every export format.

The generator only ever renders values that exist on the case. Missing fields
are rendered as ``not recorded`` rather than invented, and the platform's
decision is labelled with its source so a draft can never read as a confirmed
removal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.security import decrypt_sensitive
from database.models import (
    CONFIRMED_OUTCOMES,
    PLATFORM_LABELS,
    STATUS_LABELS,
    EnforcementCase,
)
from enforcement.violation_analyzer import load_analysis, load_policies
from evidence.evidence_manager import inventory

NOT_RECORDED = "not recorded"

DISCLAIMER = (
    "This document was prepared from the case file. It does not assert that the "
    "target has violated any policy; the platform makes that determination. "
    "Statements about the platform's decision are included only where the "
    "platform's own confirmation is recorded on the case."
)


def _fmt(value: Optional[datetime]) -> str:
    if not value:
        return NOT_RECORDED
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass
class CasePackage:
    case_reference: str
    generated_at: str
    platform: str
    platform_label: str
    target_url: str
    target_identifier: str
    target_display_name: str
    violation_category: str
    violation_label: str
    status: str
    status_label: str
    requested_action: str
    description: str
    evidence_confidence: str
    confidence_score: int
    manual_review_confirmed: bool
    policies: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    submissions: list[dict] = field(default_factory=list)
    decision: dict = field(default_factory=dict)
    appeals: list[dict] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    reporter: dict = field(default_factory=dict)
    channel: dict = field(default_factory=dict)
    analysis_summary: str = ""
    disclaimer: str = DISCLAIMER

    def as_dict(self) -> dict:
        return {
            "case_reference": self.case_reference,
            "generated_at": self.generated_at,
            "platform": self.platform,
            "platform_label": self.platform_label,
            "target": {
                "url": self.target_url,
                "identifier": self.target_identifier,
                "display_name": self.target_display_name,
            },
            "violation": {
                "category": self.violation_category,
                "label": self.violation_label,
                "description": self.description,
                "policies": self.policies,
            },
            "assessment": {
                "evidence_confidence": self.evidence_confidence,
                "confidence_score": self.confidence_score,
                "manual_review_confirmed": self.manual_review_confirmed,
                "summary": self.analysis_summary,
                "missing_evidence": self.missing_evidence,
            },
            "requested_action": self.requested_action,
            "status": {"code": self.status, "label": self.status_label},
            "evidence": self.evidence,
            "timeline": self.timeline,
            "submissions": self.submissions,
            "decision": self.decision,
            "appeals": self.appeals,
            "reporter": self.reporter,
            "official_channel": self.channel,
            "disclaimer": self.disclaimer,
        }


def build_package(
    case: EnforcementCase,
    *,
    include_contact: bool = True,
    include_analysis: bool = True,
) -> CasePackage:
    target = case.target
    analysis = load_analysis(case) if include_analysis else {}

    reporter: dict = {}
    if include_contact:
        reporter = {
            "name": case.reporter_name or NOT_RECORDED,
            "organisation": case.reporter_org or NOT_RECORDED,
            "email": decrypt_sensitive(case.reporter_email_enc) or NOT_RECORDED,
        }

    timeline = [
        {
            "at": _fmt(event.created_at),
            "event": f"{STATUS_LABELS.get(event.from_status, event.from_status or 'start')} "
            f"-> {STATUS_LABELS.get(event.to_status, event.to_status)}",
            "source": event.source,
            "note": event.note,
        }
        for event in case.status_events
    ]

    decision = {
        "summary": case.decision_summary or NOT_RECORDED,
        "reference": case.decision_reference or NOT_RECORDED,
        "source": case.decision_source,
        "recorded_at": _fmt(case.decision_at),
        "confirmed_by_platform": bool(case.is_confirmed_outcome),
        "label": (
            "Platform-confirmed outcome"
            if case.is_confirmed_outcome
            else "No platform-confirmed outcome recorded"
        ),
    }
    if case.status in CONFIRMED_OUTCOMES and not case.is_confirmed_outcome:
        decision["label"] = (
            "Status recorded without platform confirmation - treat as unverified"
        )

    package = CasePackage(
        case_reference=case.case_ref,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        platform=target.platform,
        platform_label=PLATFORM_LABELS.get(target.platform, target.platform),
        target_url=target.url,
        target_identifier=target.public_identifier,
        target_display_name=target.display_name or NOT_RECORDED,
        violation_category=case.violation_category,
        violation_label=str(
            (analysis.get("policy_match") or {}).get("category_label")
            or case.violation_category.replace("_", " ").title()
        ),
        status=case.status,
        status_label=STATUS_LABELS.get(case.status, case.status),
        requested_action=case.requested_action.replace("_", " "),
        description=case.description or NOT_RECORDED,
        evidence_confidence=case.evidence_confidence,
        confidence_score=case.confidence_score,
        manual_review_confirmed=case.manual_review_confirmed,
        policies=load_policies(case),
        evidence=inventory(case),
        timeline=timeline,
        submissions=[
            {
                "at": _fmt(item.submitted_at),
                "channel": item.channel,
                "method": item.method,
                "reference": item.reference or NOT_RECORDED,
                "notes": item.notes,
            }
            for item in case.submissions
        ],
        decision=decision,
        appeals=[
            {
                "status": appeal.status,
                "reference": appeal.reference or NOT_RECORDED,
                "reason": appeal.reason,
                "outcome": appeal.outcome or NOT_RECORDED,
                "deadline": _fmt(appeal.deadline_at),
            }
            for appeal in case.appeals
        ],
        missing_evidence=list(analysis.get("missing_evidence") or []),
        reporter=reporter,
        channel=(analysis.get("recommended_channel") or {}),
        analysis_summary=analysis.get("summary", ""),
    )
    return package


def render_text(package: CasePackage) -> str:
    lines = [
        "ENFORCEMENT REQUEST PACKAGE",
        "=" * 60,
        f"Case reference : {package.case_reference}",
        f"Generated      : {package.generated_at}",
        f"Platform       : {package.platform_label}",
        f"Target URL     : {package.target_url}",
        f"Target handle  : {package.target_identifier}",
        f"Display name   : {package.target_display_name}",
        f"Status         : {package.status_label}",
        "",
        "ALLEGED VIOLATION",
        "-" * 60,
        f"Category       : {package.violation_label}",
        f"Requested      : {package.requested_action}",
        "",
        "Documented conduct:",
        package.description,
        "",
        "POLICIES CITED",
        "-" * 60,
    ]
    if package.policies:
        for policy in package.policies:
            lines.append(f"* {policy.get('title')}")
            lines.append(f"  {policy.get('url')}")
            lines.append(f"  {policy.get('summary')}")
    else:
        lines.append("No policy reference recorded.")

    lines.extend(["", "EVIDENCE INVENTORY", "-" * 60])
    if package.evidence:
        for item in package.evidence:
            lines.append(
                f"#{item['id']} {item['file']} ({item['kind']}, {item['size_bytes']} bytes)"
            )
            lines.append(f"    captured: {item['captured_at'] or 'not recorded'}")
            lines.append(f"    sha256  : {item['sha256']}")
            if item["source_url"]:
                lines.append(f"    source  : {item['source_url']}")
            if item["description"]:
                lines.append(f"    note    : {item['description']}")
    else:
        lines.append("No evidence filed.")

    lines.extend(
        [
            "",
            "ASSESSMENT",
            "-" * 60,
            f"Evidence support : {package.evidence_confidence} "
            f"({package.confidence_score}/100)",
            f"Manual review    : {'confirmed' if package.manual_review_confirmed else 'not confirmed'}",
        ]
    )
    if package.missing_evidence:
        lines.append("Still needed:")
        lines.extend(f"* {item}" for item in package.missing_evidence)

    lines.extend(["", "TIMELINE", "-" * 60])
    if package.timeline:
        for entry in package.timeline:
            lines.append(f"{entry['at']}  {entry['event']} [{entry['source']}]")
            if entry["note"]:
                lines.append(f"    {entry['note']}")
    else:
        lines.append("No status history recorded.")

    lines.extend(["", "SUBMISSIONS", "-" * 60])
    if package.submissions:
        for item in package.submissions:
            lines.append(
                f"{item['at']}  {item['channel']} ({item['method']}) ref={item['reference']}"
            )
    else:
        lines.append("No submission recorded.")

    lines.extend(
        [
            "",
            "PLATFORM DECISION",
            "-" * 60,
            f"{package.decision.get('label')}",
            f"Reference : {package.decision.get('reference')}",
            f"Recorded  : {package.decision.get('recorded_at')}",
            f"Summary   : {package.decision.get('summary')}",
        ]
    )

    if package.reporter:
        lines.extend(
            [
                "",
                "REPORTER CONTACT",
                "-" * 60,
                f"Name         : {package.reporter.get('name')}",
                f"Organisation : {package.reporter.get('organisation')}",
                f"E-mail       : {package.reporter.get('email')}",
            ]
        )

    if package.channel:
        lines.extend(
            [
                "",
                "OFFICIAL REPORTING CHANNEL",
                "-" * 60,
                f"{package.channel.get('label')} - {package.channel.get('url')}",
            ]
        )

    lines.extend(["", "DISCLAIMER", "-" * 60, package.disclaimer, ""])
    return "\n".join(lines)


def render_json(package: CasePackage) -> str:
    return json.dumps(package.as_dict(), indent=2, default=str)
