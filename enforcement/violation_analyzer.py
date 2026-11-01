"""Evidence-weighted violation assessment.

The analyzer never decides that an account *is* violating a policy. It scores
how well the case file supports a specific allegation, lists what is missing,
and produces a neutral draft the operator must review before anything is
submitted. Identity, popularity or personal disagreement never contribute to
the score: only the documented conduct, the cited policy and the filed
evidence do.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable

from database.models import Evidence, EnforcementCase
from enforcement.policy_matcher import PolicyMatch, match

OPINION_MARKERS = (
    "i hate", "i don't like", "i do not like", "annoying", "stupid", "ugly",
    "i disagree", "should be banned", "everyone knows", "obviously fake",
)

FACT_MARKERS = (
    "posted", "sent", "message", "payment", "invoice", "link", "impersonat",
    "used my", "copyright", "trademark", "threat", "harass", "scam", "phish",
    "screenshot", "published", "uploaded", "account", "page",
)

#: Words that name the subject but describe no conduct; they must not count as
#: factual content on their own.
GENERIC_FACT_MARKERS = {"account", "page"}

CONFIDENCE_BANDS = (
    (70, "strong"),
    (45, "moderate"),
    (25, "low"),
    (0, "insufficient"),
)


@dataclass
class AnalysisResult:
    score: int
    confidence: str
    verdict: str
    summary: str
    explanation: str
    missing_evidence: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommended_channel: dict[str, object] = field(default_factory=dict)
    recommended_action: str = "account_disabling"
    policy_match: dict[str, object] = field(default_factory=dict)
    components: list[dict[str, object]] = field(default_factory=list)
    manual_review_required: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "summary": self.summary,
            "explanation": self.explanation,
            "missing_evidence": self.missing_evidence,
            "warnings": self.warnings,
            "recommended_channel": self.recommended_channel,
            "recommended_action": self.recommended_action,
            "policy_match": self.policy_match,
            "components": self.components,
            "manual_review_required": self.manual_review_required,
        }


def _band(score: int) -> str:
    for threshold, label in CONFIDENCE_BANDS:
        if score >= threshold:
            return label
    return "insufficient"


def _evidence_urls(items: Iterable[Evidence]) -> list[Evidence]:
    return [item for item in items if item.kind in {"profile_url", "post_url"}]


def _has_evidence_kind(items: Iterable[Evidence], kind: str) -> bool:
    return any(item.kind == kind for item in items)


def _covered_by(items: Iterable[Evidence], expectation: str) -> bool:
    """Loose, explainable mapping from policy expectations to filed evidence."""
    text = expectation.lower()
    items = list(items)
    if "screenshot" in text or "screen" in text:
        return any(
            item.kind in {"screenshot", "image", "screen_recording", "video"}
            for item in items
        )
    if "url" in text:
        return bool(_evidence_urls(items))
    if (
        "ownership" in text
        or "registration" in text
        or "identity document" in text
    ):
        return any(item.kind == "ownership_document" for item in items)
    if (
        "transaction" in text
        or "payment" in text
        or "message" in text
        or "correspondence" in text
    ):
        return any(
            item.kind in {"correspondence", "screenshot", "text_description"}
            for item in items
        )
    if "timestamp" in text or "date" in text:
        return any(item.captured_at for item in items)
    if "description" in text:
        return True
    return any(
        item.kind in {"screenshot", "image", "text_description", "correspondence"}
        for item in items
    )


def _recommended_action(category: str, platform_key: str) -> str:
    if platform_key == "facebook_pages":
        return "page_removal"
    if category in {"copyright", "trademark", "prohibited_content"}:
        return "content_removal"
    return "account_disabling"


def analyze(
    *,
    platform_key: str,
    category: str,
    description: str,
    evidence_items: list[Evidence],
    requested_action: str = "",
) -> AnalysisResult:
    policy: PolicyMatch = match(category, platform_key)
    description = (description or "").strip()
    components: list[dict[str, object]] = []
    warnings: list[str] = []
    missing: list[str] = []
    score = 5  # baseline: a case exists, but nothing is proven yet
    components.append({"item": "case opened", "points": 5, "reason": "baseline"})

    lowered = description.lower()
    opinion_hits = [marker for marker in OPINION_MARKERS if marker in lowered]
    fact_hits = [marker for marker in FACT_MARKERS if marker in lowered]
    substantive_facts = [m for m in fact_hits if m not in GENERIC_FACT_MARKERS]

    if not description:
        missing.append(
            "A factual description of the conduct (what was posted, sent or offered, and when)"
        )
        warnings.append("No conduct description was supplied; the case cannot be assessed.")
    elif len(description) < 60:
        score += 5
        missing.append(
            "A fuller description: the current text is too short to show a policy breach"
        )
        components.append({"item": "description", "points": 5, "reason": "short description"})
    else:
        points = 15 if len(description) < 300 else 25
        if opinion_hits and not substantive_facts:
            warnings.append(
                "The description reads as opinion rather than documented conduct. "
                "Rewrite it around observable actions before submitting."
            )
            points = 5
        components.append(
            {
                "item": "description",
                "points": points,
                "reason": f"{len(description)} characters",
            }
        )
        score += points

    if substantive_facts:
        score += 5
        components.append(
            {
                "item": "observable facts",
                "points": 5,
                "reason": ", ".join(substantive_facts[:4]),
            }
        )
    else:
        missing.append("Observable facts (what the account published, to whom, and when)")

    kinds = {item.kind for item in evidence_items}
    visual = [item for item in evidence_items if item.kind in ("screenshot", "image")]
    if visual:
        score += 15
        components.append(
            {"item": "visual evidence", "points": 15, "reason": "screenshot/image filed"}
        )
    else:
        missing.append("At least one dated screenshot of the conduct")

    if len(visual) >= 2:
        score += 5
        components.append(
            {"item": "multiple captures", "points": 5, "reason": "two or more visual items"}
        )

    if _evidence_urls(evidence_items):
        score += 10
        components.append(
            {"item": "source URLs", "points": 10, "reason": "profile or post URL recorded"}
        )
    else:
        missing.append("Direct URL(s) to the offending profile, Page or post")

    if any(item.captured_at for item in evidence_items):
        score += 5
        components.append(
            {"item": "collection dates", "points": 5, "reason": "capture timestamps recorded"}
        )
    else:
        missing.append("The date each capture was taken")

    if policy.requires_ownership_document:
        if _has_evidence_kind(evidence_items, "ownership_document"):
            score += 20
            components.append(
                {"item": "ownership proof", "points": 20, "reason": "rights document filed"}
            )
        else:
            missing.append(
                "Proof of ownership or licence for the work or mark (required for this category)"
            )

    if _has_evidence_kind(evidence_items, "correspondence"):
        score += 5
        components.append(
            {"item": "correspondence", "points": 5, "reason": "messages or notices filed"}
        )

    if kinds & {"video", "screen_recording"}:
        score += 5
        components.append(
            {"item": "recorded proof", "points": 5, "reason": "video/screen recording filed"}
        )

    for expectation in policy.expected_evidence:
        if not _covered_by(evidence_items, expectation) and expectation not in missing:
            missing.append(f"Policy expects: {expectation}")

    if not evidence_items:
        warnings.append("No evidence is filed on this case yet.")

    score = max(0, min(100, score))
    confidence = _band(score)
    action = requested_action or _recommended_action(category, platform_key)

    summary = (
        f"{policy.category_label} alleged against {policy.platform_label}: "
        f"evidence support is {confidence} ({score}/100)."
    )
    explanation_lines = [
        f"Category: {policy.category_label}.",
        "Policies cited: " + "; ".join(p["title"] for p in policy.policies) + ".",
        f"Filed evidence: {len(evidence_items)} item(s)"
        + (f" ({', '.join(sorted(kinds))})." if kinds else "."),
        f"Requested action: {action.replace('_', ' ')}.",
        "",
        "This assessment ranks how well the file supports the allegation. It is not a "
        "finding that the target violated policy; the platform decides that independently.",
    ]
    if missing:
        explanation_lines.append("")
        explanation_lines.append("Before submission, supply:")
        explanation_lines.extend(f"- {item}" for item in missing)

    return AnalysisResult(
        score=score,
        confidence=confidence,
        verdict="support_level_only",
        summary=summary,
        explanation="\n".join(explanation_lines),
        missing_evidence=missing,
        warnings=warnings,
        recommended_channel=policy.channel,
        recommended_action=action,
        policy_match=policy.as_dict(),
        components=components,
    )


def analyze_case(case: EnforcementCase) -> AnalysisResult:
    return analyze(
        platform_key=case.target.platform,
        category=case.violation_category,
        description=case.description,
        evidence_items=list(case.evidence),
        requested_action=case.requested_action,
    )


def apply_analysis(case: EnforcementCase, result: AnalysisResult) -> None:
    """Persist analysis output on the case (no status change on its own)."""
    case.confidence_score = result.score
    case.evidence_confidence = result.confidence
    case.recommended_channel = str(result.recommended_channel.get("label", ""))
    case.analysis_json = json.dumps(result.as_dict(), default=str)
    case.policy_matches_json = json.dumps(
        result.policy_match.get("policies", []), default=str
    )


def load_analysis(case: EnforcementCase) -> dict:
    try:
        return json.loads(case.analysis_json or "{}")
    except json.JSONDecodeError:
        return {}


def load_policies(case: EnforcementCase) -> list[dict]:
    try:
        return json.loads(case.policy_matches_json or "[]")
    except json.JSONDecodeError:
        return []