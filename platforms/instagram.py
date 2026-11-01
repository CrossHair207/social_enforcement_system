"""Instagram account module."""

from __future__ import annotations

import re

from platforms.base_platform import (
    ApiCapability,
    BasePlatform,
    InvalidTargetUrl,
    PolicyReference,
    ReportingChannel,
)
from platforms.facebook_personal import FacebookPersonalPlatform, META

IG_GUIDELINES = "https://help.instagram.com/477434105621119"


class InstagramPlatform(BasePlatform):
    key = "instagram"
    label = "Instagram account"
    hosts = ("instagram.com", "www.instagram.com")
    target_kind = "account"
    default_channel_key = "in_app_report"
    reserved_segments = frozenset(
        {
            "p", "reel", "reels", "tv", "stories", "explore", "accounts", "direct",
            "about", "legal", "developer", "directory", "emaillogin", "challenge",
            "web", "api", "graphql", "oauth", "privacy", "terms", "session",
            "emails", "lite", "invites", "s", "static", "ar", "nametag",
        }
    )

    def extract(self, segments, query):
        if not segments:
            raise InvalidTargetUrl("an Instagram profile URL is required")
        first = segments[0]
        if first in self.reserved_segments:
            raise InvalidTargetUrl(f"'/{first}' is an Instagram app route, not a profile")
        if len(segments) > 1 and segments[1] not in {"tagged", "reels", "channel"}:
            raise InvalidTargetUrl("only profile URLs are accepted (instagram.com/<username>)")
        if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", first):
            raise InvalidTargetUrl("Instagram usernames are 1-30 characters of letters, digits, '.' or '_'")
        return first, "account", "", False, ""

    def build_url(self, identifier: str, kind: str) -> str:
        return f"https://www.instagram.com/{identifier}"

    def policies(self):
        meta_impersonation = f"{META}/impersonation/"
        return {
            "fake_account": (
                PolicyReference(
                    "ig-authenticity",
                    "Instagram Community Guidelines - Authentic identity",
                    IG_GUIDELINES,
                    "Instagram requires accounts to represent a real person, business or entity.",
                    ("profile screenshot", "evidence the identity is fictitious"),
                ),
            ),
            "impersonation": (
                PolicyReference(
                    "ig-impersonation",
                    "Instagram Community Guidelines - Impersonation",
                    IG_GUIDELINES,
                    "Accounts may not pretend to be someone else.",
                    ("side-by-side screenshots", "proof of the reporter's identity"),
                ),
            ),
            "fraud_scam": (
                PolicyReference(
                    "ig-fraud",
                    "Instagram Community Guidelines - Fraud and deception",
                    IG_GUIDELINES,
                    "Deceptive practices, including scam giveaways and payment fraud, are prohibited.",
                    ("screenshots of the offer", "records of the transaction"),
                ),
            ),
            "phishing": (
                PolicyReference(
                    "ig-phishing",
                    "Instagram Community Guidelines - Fraud and deception",
                    IG_GUIDELINES,
                    "Phishing links impersonating login pages are prohibited.",
                    ("screenshot", "full destination URL"),
                ),
            ),
            "identity_theft": (
                PolicyReference(
                    "ig-impersonation",
                    "Meta Community Standards - Impersonation",
                    meta_impersonation,
                    "Using another person's identity or images requires permission.",
                    ("identity document of the reporter", "screenshots"),
                ),
            ),
            "copyright": (
                PolicyReference(
                    "ig-copyright",
                    "Instagram Copyright Reporting",
                    "https://www.facebook.com/help/ip",
                    "Rights holders can report unauthorised reproduction of their work.",
                    ("proof of ownership", "URLs of the infringing posts"),
                ),
            ),
            "trademark": (
                PolicyReference(
                    "ig-trademark",
                    "Instagram Trademark Reporting",
                    "https://www.facebook.com/help/ip",
                    "Reports of confusing trademark use are handled by the rights-holder form.",
                    ("registration certificate", "screenshots of the use"),
                ),
            ),
            "harassment": (
                PolicyReference(
                    "ig-harassment",
                    "Instagram Community Guidelines - Respect others",
                    IG_GUIDELINES,
                    "Harassment, bullying and unwanted contact are prohibited.",
                    ("dated screenshots of each incident",),
                ),
            ),
            "threats": (
                PolicyReference(
                    "ig-threats",
                    "Instagram Community Guidelines - Threats",
                    IG_GUIDELINES,
                    "Threats of violence are prohibited.",
                    ("screenshot of the threat", "timestamp"),
                ),
            ),
            "prohibited_content": (
                PolicyReference(
                    "ig-prohibited",
                    "Instagram Community Guidelines - Restricted content",
                    IG_GUIDELINES,
                    "Certain content categories are prohibited outright.",
                    ("screenshots", "post URLs"),
                ),
            ),
            "fraudulent_business_page": (
                PolicyReference(
                    "ig-business-fraud",
                    "Instagram Community Guidelines - Fraud and deception",
                    IG_GUIDELINES,
                    "Business accounts may not deceive customers.",
                    ("screenshots of the account and offers", "transaction records"),
                ),
            ),
            "other": (
                PolicyReference(
                    "ig-guidelines",
                    "Instagram Community Guidelines",
                    IG_GUIDELINES,
                    "Cite the specific guideline clause that the conduct breaches.",
                ),
            ),
        }

    def channels(self):
        report = ReportingChannel(
            "in_app_report",
            "Instagram in-app report flow",
            "https://help.instagram.com/",
            "in_app",
            notes=(
                "Open the profile, tap '...' -> 'Report' -> 'Something about this account'. "
                "Instagram does not provide a public web form for account takedowns."
            ),
        )
        ip = ReportingChannel(
            "ip",
            "Meta intellectual-property reporting",
            "https://www.facebook.com/help/ip",
            "web_form",
            notes="Copyright and trademark reports for Instagram content.",
        )
        return {
            "default": report,
            "in_app_report": report,
            "copyright": ip,
            "trademark": ip,
        }

    def api_capability(self) -> ApiCapability:
        return ApiCapability(
            takedown_submission=False,
            status_retrieval=False,
            notes=(
                "The Instagram Graph API covers content publishing and insights for "
                "accounts you manage; it has no endpoint for reporting or removing "
                "another account. Enforcement therefore runs through the in-app flow."
            ),
        )

    def submission_instructions(self, category: str) -> list[str]:
        steps = super().submission_instructions(category)
        steps.insert(
            1,
            "Open the target profile, tap the '...' menu, choose 'Report', then "
            "'Something about this account'.",
        )
        return steps
