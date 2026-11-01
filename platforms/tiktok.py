"""TikTok account module."""

from __future__ import annotations

import re

from platforms.base_platform import (
    ApiCapability,
    BasePlatform,
    InvalidTargetUrl,
    PolicyReference,
    ReportingChannel,
)

TT_GUIDELINES = "https://www.tiktok.com/community-guidelines/en/"
TT_REPORT = "https://www.tiktok.com/community-guidelines/en/report/"
TT_IP = "https://www.tiktok.com/legal/report/Copyright"


class TikTokPlatform(BasePlatform):
    key = "tiktok"
    label = "TikTok account"
    hosts = ("tiktok.com", "www.tiktok.com", "m.tiktok.com")
    target_kind = "account"
    default_channel_key = "in_app_report"
    reserved_segments = frozenset(
        {
            "video", "tag", "music", "discover", "foryou", "live", "upload", "search",
            "about", "legal", "transparency", "business", "creator", "download",
            "embed", "share", "trending", "explore", "login", "signup", "feedback",
            "community-guidelines", "t", "o", "api",
        }
    )

    def extract(self, segments, query):
        if not segments:
            raise InvalidTargetUrl("a TikTok profile URL is required")
        first = segments[0]
        if first.startswith("@"):
            username = first[1:]
            if not re.fullmatch(r"[A-Za-z0-9._]{2,24}", username):
                raise InvalidTargetUrl("TikTok usernames are 2-24 characters")
            return username, "account", "", False, ""
        if first in self.reserved_segments:
            raise InvalidTargetUrl(f"'/{first}' is a TikTok section, not a profile")
        if re.fullmatch(r"[A-Za-z0-9._]{2,24}", first):
            return first, "account", "", True, (
                "URL without the '@' prefix; confirm it resolves to the intended profile."
            )
        raise InvalidTargetUrl("TikTok profile URLs look like tiktok.com/@username")

    def build_url(self, identifier: str, kind: str) -> str:
        return f"https://www.tiktok.com/@{identifier}"

    def policies(self):
        return {
            "fake_account": (
                PolicyReference(
                    "tt-authenticity",
                    "TikTok Community Guidelines - Account integrity",
                    TT_GUIDELINES,
                    "Accounts must not misrepresent who operates them or create fictitious identities at scale.",
                    ("profile screenshot", "evidence the identity is fictitious"),
                ),
            ),
            "impersonation": (
                PolicyReference(
                    "tt-impersonation",
                    "TikTok Community Guidelines - Impersonation",
                    TT_GUIDELINES,
                    "Accounts may not impersonate another person or brand.",
                    ("side-by-side screenshots", "proof of the reporter's identity or brand"),
                ),
            ),
            "fraud_scam": (
                PolicyReference(
                    "tt-fraud",
                    "TikTok Community Guidelines - Fraud and scams",
                    TT_GUIDELINES,
                    "Scams and deceptive financial schemes are prohibited.",
                    ("screenshots of the solicitation", "transaction or message records"),
                ),
            ),
            "phishing": (
                PolicyReference(
                    "tt-phishing",
                    "TikTok Community Guidelines - Fraud and scams (phishing)",
                    TT_GUIDELINES,
                    "Links designed to steal credentials or payment data are prohibited.",
                    ("screenshot", "full destination URL"),
                ),
            ),
            "identity_theft": (
                PolicyReference(
                    "tt-impersonation",
                    "TikTok Community Guidelines - Impersonation",
                    TT_GUIDELINES,
                    "Using another person's identity or likeness requires authorisation.",
                    ("identity document of the reporter", "screenshots"),
                ),
            ),
            "copyright": (
                PolicyReference(
                    "tt-copyright",
                    "TikTok Copyright Policy and reporting form",
                    TT_IP,
                    "Rights holders may report content that reproduces their work.",
                    ("proof of ownership", "video URLs", "description of the original work"),
                ),
            ),
            "trademark": (
                PolicyReference(
                    "tt-trademark",
                    "TikTok Intellectual Property Policy",
                    "https://www.tiktok.com/legal/intellectual-property-policy",
                    "Confusing use of a registered mark may be reported by the rights holder.",
                    ("registration certificate", "screenshots of the use"),
                ),
            ),
            "harassment": (
                PolicyReference(
                    "tt-harassment",
                    "TikTok Community Guidelines - Harassment and bullying",
                    TT_GUIDELINES,
                    "Targeted abuse and unwanted contact are prohibited.",
                    ("dated screenshots of each incident",),
                ),
            ),
            "threats": (
                PolicyReference(
                    "tt-violence",
                    "TikTok Community Guidelines - Violent content and threats",
                    TT_GUIDELINES,
                    "Threats of physical harm are prohibited.",
                    ("screenshot of the threat", "timestamp", "report filed with law enforcement if applicable"),
                ),
            ),
            "prohibited_content": (
                PolicyReference(
                    "tt-prohibited",
                    "TikTok Community Guidelines - Prohibited content",
                    TT_GUIDELINES,
                    "Prohibited categories include sexual exploitation of minors and regulated goods.",
                    ("screenshots", "video URLs"),
                ),
            ),
            "fraudulent_business_page": (
                PolicyReference(
                    "tt-business-fraud",
                    "TikTok Community Guidelines - Fraud and scams",
                    TT_GUIDELINES,
                    "Business accounts may not take payment without delivering.",
                    ("screenshots of the offers", "transaction records"),
                ),
            ),
            "other": (
                PolicyReference(
                    "tt-guidelines",
                    "TikTok Community Guidelines",
                    TT_GUIDELINES,
                    "Cite the specific guideline clause that the conduct breaches.",
                ),
            ),
        }

    def channels(self):
        report = ReportingChannel(
            "in_app_report",
            "TikTok in-app report flow",
            TT_REPORT,
            "in_app",
            notes=(
                "Open the profile, tap '...' -> 'Report' -> choose the category. TikTok "
                "documents the reporting routes on its community guidelines site."
            ),
        )
        ip = ReportingChannel(
            "ip",
            "TikTok intellectual-property report form",
            TT_IP,
            "web_form",
            notes="Copyright form; the trademark form is linked from TikTok's IP policy page.",
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
                "The TikTok Display/Content Posting APIs cover your own content and "
                "analytics only. There is no public endpoint for reporting another "
                "account, so this module generates the package for the official form."
            ),
        )

    def submission_instructions(self, category: str) -> list[str]:
        steps = super().submission_instructions(category)
        steps.insert(
            1,
            "Open the target profile, tap the '...' menu, choose 'Report', then the "
            "category matching the documented violation.",
        )
        return steps