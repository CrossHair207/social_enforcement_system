"""Map a documented conduct description onto official platform policies."""

from __future__ import annotations

from dataclasses import dataclass, field

from platforms import VIOLATION_CATEGORIES, registry
from platforms.base_platform import BasePlatform, PlatformError


class PolicyMatchError(Exception):
    """Raised when a category or platform cannot be matched to a policy."""


@dataclass(frozen=True)
class PolicyMatch:
    category: str
    category_label: str
    platform: str
    platform_label: str
    policies: list[dict[str, object]] = field(default_factory=list)
    channel: dict[str, object] = field(default_factory=dict)
    requires_ownership_document: bool = False
    expected_evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "category_label": self.category_label,
            "platform": self.platform,
            "platform_label": self.platform_label,
            "policies": self.policies,
            "channel": self.channel,
            "requires_ownership_document": self.requires_ownership_document,
            "expected_evidence": self.expected_evidence,
        }


def platform_for(key: str) -> BasePlatform:
    try:
        return registry.get(key)
    except PlatformError as exc:
        raise PolicyMatchError(str(exc)) from exc


def match(category: str, platform_key: str) -> PolicyMatch:
    """Return the policy references and reporting channel for one category."""
    if category not in VIOLATION_CATEGORIES:
        raise PolicyMatchError(
            f"unknown violation category '{category}' "
            f"(choose one of: {', '.join(VIOLATION_CATEGORIES)})"
        )
    platform = platform_for(platform_key)
    policies = platform.policies_for(category)
    if not policies:
        raise PolicyMatchError(
            f"{platform.label} has no policy reference for '{category}'"
        )
    channel = platform.channel_for(category)
    expected: list[str] = []
    for policy in policies:
        for item in policy.evidence_expectations:
            if item not in expected:
                expected.append(item)
    return PolicyMatch(
        category=category,
        category_label=str(VIOLATION_CATEGORIES[category]["label"]),
        platform=platform.key,
        platform_label=platform.label,
        policies=[
            {
                "key": policy.key,
                "title": policy.title,
                "url": policy.url,
                "summary": policy.summary,
                "evidence_expectations": list(policy.evidence_expectations),
            }
            for policy in policies
        ],
        channel={
            "key": channel.key,
            "label": channel.label,
            "url": channel.url,
            "method": channel.method,
            "requires_login": channel.requires_login,
            "notes": channel.notes,
        },
        requires_ownership_document=bool(
            VIOLATION_CATEGORIES[category]["requires_ownership_document"]
        ),
        expected_evidence=expected,
    )


def categories_for_platform(platform_key: str) -> list[dict[str, str]]:
    platform = platform_for(platform_key)
    return [
        {"key": category, "label": str(VIOLATION_CATEGORIES[category]["label"])}
        for category in platform.categories()
        if category in VIOLATION_CATEGORIES
    ]


def reporting_instructions(category: str, platform_key: str) -> list[str]:
    return platform_for(platform_key).submission_instructions(category)
