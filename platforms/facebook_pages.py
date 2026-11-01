"""Facebook Page module (Page removal rather than profile removal)."""

from __future__ import annotations

import re

from platforms.base_platform import ApiCapability, BasePlatform, InvalidTargetUrl
from platforms.facebook_personal import FacebookPersonalPlatform, META


class FacebookPagesPlatform(BasePlatform):
    key = "facebook_pages"
    label = "Facebook Page"
    hosts = ("facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com")
    target_kind = "page"
    default_channel_key = "report_links"

    def claims(self, url: str) -> bool:
        match = re.search(r"facebook\.com/(pages/|p/)", (url or "").lower())
        if match:
            return True
        return bool(re.search(r"facebook\.com/[A-Za-z0-9_.\-]+-\d{8,}/?$", (url or "").lower()))

    def extract(self, segments, query):
        if not segments:
            raise InvalidTargetUrl("a Page URL is required")

        if segments[0] == "pages":
            identifiers = [segment for segment in segments[1:] if segment]
            if not identifiers:
                raise InvalidTargetUrl("Page URLs look like facebook.com/pages/<name>/<id>")
            identifier = identifiers[-1]
            if not re.fullmatch(r"\d{5,25}", identifier):
                return identifier, "page", identifiers[0] if len(identifiers) > 1 else "", True, (
                    "vanity Page URL without a numeric id"
                )
            display = identifiers[0] if len(identifiers) > 1 else ""
            return identifier, "page", display, False, "numeric Page id"

        if segments[0] == "p":
            identifier = segments[-1]
            match = re.search(r"-(\d{8,25})$", identifier)
            if match:
                return match.group(1), "page", identifier[: match.start()], False, ""
            raise InvalidTargetUrl("Page URLs look like facebook.com/p/<name>-<id>")

        if segments[0] in FacebookPersonalPlatform.reserved_segments:
            raise InvalidTargetUrl(f"'/{segments[0]}' is not a Page URL")

        first = segments[0]
        match = re.search(r"-(\d{8,25})$", first)
        if match:
            return match.group(1), "page", first[: match.start()], False, "numeric Page id"
        return first, "page", "", True, (
            "vanity URL: Facebook serves both profiles and Pages from the same path, so "
            "confirm the target is a Page before submitting."
        )

    def build_url(self, identifier: str, kind: str) -> str:
        if re.fullmatch(r"\d+", identifier):
            return f"https://www.facebook.com/pages/{identifier}"
        return f"https://www.facebook.com/{identifier}"

    def policies(self):
        base = FacebookPersonalPlatform()
        # Pages are held to the same community standards as profiles.
        return dict(base.policies())

    def channels(self):
        from platforms.base_platform import ReportingChannel

        page_report = ReportingChannel(
            "page_report",
            "Facebook Page reporting",
            "https://www.facebook.com/help/reportlinks",
            "in_app",
            notes=(
                "Page-level reports are filed from the Page itself: '...' menu -> "
                "'Report Page' -> choose the closest category."
            ),
        )
        channels = dict(FacebookPersonalPlatform().channels())
        channels["default"] = page_report
        channels["report_links"] = page_report
        channels["fake_account"] = page_report
        channels["fraudulent_business_page"] = page_report
        return channels

    def api_capability(self) -> ApiCapability:
        return ApiCapability(
            takedown_submission=False,
            status_retrieval=False,
            notes=(
                "Meta provides no public API for Page removal requests. Page reports are "
                "filed through the in-app flow; the Graph API is not an enforcement "
                "channel, so this module never attempts automated submission."
            ),
        )

    def submission_instructions(self, category: str) -> list[str]:
        steps = super().submission_instructions(category)
        steps.insert(
            1,
            "Open the target Page, use the '...' menu under the cover photo, choose "
            "'Report Page', then select the category that matches the documented violation.",
        )
        return steps
