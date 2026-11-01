"""Facebook personal-account module."""

from __future__ import annotations

import re

from platforms.base_platform import (
    ApiCapability,
    BasePlatform,
    InvalidTargetUrl,
    PolicyReference,
    ReportingChannel,
)

META = "https://transparency.meta.com/policies/community-standards"


class FacebookPersonalPlatform(BasePlatform):
    key = "facebook_personal"
    label = "Facebook personal account"
    hosts = ("facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com")
    target_kind = "account"
    default_channel_key = "report_links"
    reserved_segments = frozenset(
        {
            "about", "ads", "business", "careers", "events", "friends", "gaming", "groups",
            "help", "home.php", "legal", "login", "login.php", "marketplace", "messages",
            "messenger", "music", "notifications", "pages", "policies", "privacy", "reel",
            "reels", "settings", "share", "sharer", "stories", "story.php", "watch",
            "photo.php", "permalink.php", "photo", "plugins", "dialog", "hashtag",
            "profile.php", "p", "people", "donate", "fundraisers", "livenow", "recover",
            "checkpoint", "two_step_verification", "business", "ads", "campaign",
        }
    )

    def extract(self, segments, query):
        if not segments or segments[0] == "profile.php":
            ids = query.get("id") or []
            if ids and re.fullmatch(r"\d{3,25}", ids[0]):
                return ids[0], "account", "", False, "numeric profile id"
            raise InvalidTargetUrl("profile.php links must include a numeric id parameter")

        if segments[0] == "people" and len(segments) >= 2:
            identifier = segments[-1]
            if re.fullmatch(r"\d{3,25}", identifier):
                return identifier, "account", segments[1] if len(segments) > 2 else "", False, ""
            raise InvalidTargetUrl("people URLs must end with a numeric id")

        first = segments[0]
        if first in self.reserved_segments:
            raise InvalidTargetUrl(
                f"'/{first}' is a Facebook section, not a personal profile URL"
            )
        if "/" in "".join(segments[1:]):
            pass
        if len(segments) > 1 and segments[1] not in {"about", "about_contact_and_basic_info", "photos", "friends"}:
            raise InvalidTargetUrl(
                "only profile URLs are accepted (e.g. facebook.com/<username>)"
            )
        return first, "account", "", False, ""

    def build_url(self, identifier: str, kind: str) -> str:
        if re.fullmatch(r"\d+", identifier):
            return f"https://www.facebook.com/profile.php?id={identifier}"
        return f"https://www.facebook.com/{identifier}"

    # ------------------------------------------------------------------
    def policies(self):
        return {
            "fake_account": (
                PolicyReference(
                    "meta-authenticity",
                    "Meta Community Standards - Authenticity",
                    f"{META}/account-integrity/",
                    "Accounts must represent a real person or entity and must not be "
                    "created with a false identity.",
                    ("profile screenshot", "evidence the identity does not exist"),
                ),
            ),
            "impersonation": (
                PolicyReference(
                    "meta-impersonation",
                    "Meta Community Standards - Impersonation",
                    f"{META}/impersonation/",
                    "Accounts may not pretend to be another person or entity.",
                    ("side-by-side screenshots of both profiles", "proof of the reporter's association"),
                ),
            ),
            "fraud_scam": (
                PolicyReference(
                    "meta-fraud",
                    "Meta Community Standards - Fraud, Deception and Scams",
                    f"{META}/fraud-deception-and-scams/",
                    "Accounts may not use deception to obtain money, property or personal information.",
                    ("screenshots of the solicitation", "payment or message records"),
                ),
            ),
            "phishing": (
                PolicyReference(
                    "meta-phishing",
                    "Meta Community Standards - Fraud, Deception and Scams (phishing)",
                    f"{META}/fraud-deception-and-scams/",
                    "Sharing links that impersonate a login page to steal credentials violates the standards.",
                    ("screenshot of the post/message", "full destination URL"),
                ),
            ),
            "identity_theft": (
                PolicyReference(
                    "meta-impersonation",
                    "Meta Community Standards - Impersonation",
                    f"{META}/impersonation/",
                    "Using another person's identity, images or documents requires their permission.",
                    ("government identity document of the reporter", "screenshots of the copied material"),
                ),
            ),
            "copyright": (
                PolicyReference(
                    "meta-copyright",
                    "Meta Copyright Reporting",
                    "https://www.facebook.com/help/ip",
                    "Rights holders may report content that reproduces their work without authorisation.",
                    ("proof of ownership or licence", "URLs of the infringing posts", "description of the original work"),
                ),
            ),
            "trademark": (
                PolicyReference(
                    "meta-trademark",
                    "Meta Trademark Reporting",
                    "https://www.facebook.com/help/ip",
                    "Use of a mark that confuses people about affiliation may be reported by the rights holder.",
                    ("trademark registration certificate", "screenshots of the infringing use"),
                ),
            ),
            "harassment": (
                PolicyReference(
                    "meta-harassment",
                    "Meta Community Standards - Bullying and Harassment",
                    f"{META}/bullying-harassment/",
                    "Repeated targeted abuse and unwanted contact are prohibited.",
                    ("dated screenshots of each incident", "context showing the pattern"),
                ),
            ),
            "threats": (
                PolicyReference(
                    "meta-violence",
                    "Meta Community Standards - Violence and Incitement",
                    f"{META}/violence-incitement/",
                    "Credible threats of physical harm are prohibited.",
                    ("screenshot of the threat", "timestamp", "any report filed with law enforcement"),
                ),
            ),
            "prohibited_content": (
                PolicyReference(
                    "meta-regulated",
                    "Meta Community Standards - Regulated Goods and Prohibited Content",
                    f"{META}/regulated-goods/",
                    "Sale or promotion of regulated goods and certain sexual content are prohibited.",
                    ("screenshots of the content", "URLs of the posts"),
                ),
            ),
            "fraudulent_business_page": (
                PolicyReference(
                    "meta-fraud",
                    "Meta Community Standards - Fraud, Deception and Scams",
                    f"{META}/fraud-deception-and-scams/",
                    "Pages may not deceive people about the business they represent.",
                    ("screenshots of the Page and its offers", "records of the transaction"),
                ),
            ),
            "other": (
                PolicyReference(
                    "meta-standards",
                    "Meta Community Standards (index)",
                    "https://transparency.meta.com/policies/community-standards/",
                    "Locate and cite the specific clause violated before submitting.",
                ),
            ),
        }

    def channels(self):
        report = ReportingChannel(
            "report_links",
            "Facebook reporting centre",
            "https://www.facebook.com/help/reportlinks",
            "in_app",
            notes=(
                "Facebook handles account and profile reports through the in-app or "
                "web report flow; the reporting centre page lists the current routes."
            ),
        )
        ip = ReportingChannel(
            "ip",
            "Meta intellectual-property reporting",
            "https://www.facebook.com/help/ip",
            "web_form",
            notes="Rights-holder forms for copyright and trademark reports.",
        )
        return {
            "default": report,
            "report_links": report,
            "copyright": ip,
            "trademark": ip,
        }

    def api_capability(self) -> ApiCapability:
        return ApiCapability(
            takedown_submission=False,
            status_retrieval=False,
            notes=(
                "Meta does not expose a public API for reporting personal accounts or "
                "for reading the outcome of an account report. Rights holders enrolled "
                "in Meta's IP partner programmes submit through separate, contract-gated "
                "channels; this module therefore generates the evidence package and "
                "guides the operator through the official flow."
            ),
        )

    def submission_instructions(self, category: str) -> list[str]:
        steps = super().submission_instructions(category)
        steps.insert(
            1,
            "Open the target profile, use the '...' menu, choose 'Report', then "
            "'Something about this account'.",
        )
        return steps
