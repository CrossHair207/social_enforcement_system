"""Platform abstraction, policy catalogue and URL grammar.

Every platform module subclasses :class:`BasePlatform` and declares:

* which hosts and URL shapes it owns (``hosts``, ``extract``),
* the policy references that apply to each violation category (``policies``),
* the official reporting channel for each category (``channel_for``),
* what automation the platform actually permits (``api_capability``).

The last point matters for honesty: none of the four platforms expose a public
API for submitting account/page takedowns or reading enforcement decisions, so
every module reports ``supported=False`` with the reason and the application
routes the operator through the official manual workflow instead of pretending
to automate it.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar, Iterable, Optional
from urllib.parse import parse_qs, urlsplit


class PlatformError(Exception):
    """Base class for platform-level failures."""


class InvalidTargetUrl(PlatformError):
    """The supplied URL is not a valid target for this platform."""


@dataclass(frozen=True)
class ParsedTarget:
    platform: str
    url: str
    identifier: str
    kind: str
    display_name: str = ""
    ambiguous: bool = False
    notes: str = ""


@dataclass(frozen=True)
class PolicyReference:
    """One official policy document that a violation category maps to."""

    key: str
    title: str
    url: str
    summary: str
    evidence_expectations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReportingChannel:
    """An official reporting/enforcement route."""

    key: str
    label: str
    url: str
    method: str  # "web_form" | "in_app" | "official_api" | "email"
    requires_login: bool = True
    notes: str = ""


@dataclass(frozen=True)
class ApiCapability:
    """What the platform officially automates for enforcement."""

    takedown_submission: bool = False
    status_retrieval: bool = False
    notes: str = ""


#: Violation taxonomy shared by all platforms. ``requires_ownership_document``
#: marks categories where the platform asks the reporter to prove rights.
VIOLATION_CATEGORIES: dict[str, dict[str, object]] = {
    "fake_account": {
        "label": "Fake account",
        "summary": "Account represents a person or entity that does not exist, or is operated under a fictitious identity.",
        "requires_ownership_document": False,
    },
    "impersonation": {
        "label": "Impersonation",
        "summary": "Account or Page pretends to be a real person, brand or organisation it is not affiliated with.",
        "requires_ownership_document": False,
    },
    "fraud_scam": {
        "label": "Fraud or scam",
        "summary": "Account or Page is used to deceive people out of money, goods or account credentials.",
        "requires_ownership_document": False,
    },
    "phishing": {
        "label": "Phishing",
        "summary": "Account distributes links or messages designed to steal credentials or payment data.",
        "requires_ownership_document": False,
    },
    "identity_theft": {
        "label": "Unauthorised identity usage",
        "summary": "Account uses another person's name, images or documents without permission.",
        "requires_ownership_document": True,
    },
    "copyright": {
        "label": "Copyright infringement",
        "summary": "Account or Page republishes protected works without a licence or exception.",
        "requires_ownership_document": True,
    },
    "trademark": {
        "label": "Trademark infringement",
        "summary": "Account or Page uses a registered mark in a way that confuses as to source or endorsement.",
        "requires_ownership_document": True,
    },
    "harassment": {
        "label": "Harassment and bullying",
        "summary": "Sustained targeted abuse, intimidation or unwanted contact directed at a person.",
        "requires_ownership_document": False,
    },
    "threats": {
        "label": "Threats of violence",
        "summary": "Account issues credible threats of physical harm against a person or group.",
        "requires_ownership_document": False,
    },
    "prohibited_content": {
        "label": "Prohibited content distribution",
        "summary": "Account distributes content the platform prohibits outright (e.g. sexual exploitation of minors, sale of regulated goods).",
        "requires_ownership_document": False,
    },
    "fraudulent_business_page": {
        "label": "Fraudulent business Page",
        "summary": "Page trades under false pretences, impersonates a legitimate business, or takes payment without delivering.",
        "requires_ownership_document": False,
    },
    "other": {
        "label": "Other documented violation",
        "summary": "A violation that does not fit the categories above; the operator must cite the exact policy clause.",
        "requires_ownership_document": False,
    },
}

CATEGORY_LABELS = {key: str(value["label"]) for key, value in VIOLATION_CATEGORIES.items()}


def category_label(key: str) -> str:
    return CATEGORY_LABELS.get(key, key.replace("_", " ").capitalize())


POLICY_SOURCE_NOTE = (
    "Policy links point at the platforms' public policy documentation. Confirm the "
    "current wording in the platform's help centre before citing it in a submission, "
    "because platforms revise policy pages without notice."
)


class BasePlatform(ABC):
    """Interface every platform module implements."""

    key: ClassVar[str] = "base"
    label: ClassVar[str] = "Base platform"
    hosts: ClassVar[tuple[str, ...]] = ()
    default_channel_key: ClassVar[str] = "default"
    reserved_segments: ClassVar[frozenset[str]] = frozenset()
    target_kind: ClassVar[str] = "account"

    # ------------------------------------------------------------------
    # URL handling
    # ------------------------------------------------------------------
    def host_matches(self, hostname: str) -> bool:
        hostname = (hostname or "").lower().rstrip(".")
        return any(hostname == host or hostname.endswith("." + host) for host in self.hosts)

    def claims(self, url: str) -> bool:
        """Whether this module should handle the URL (used for auto-detection)."""
        try:
            self.parse(url)
            return True
        except PlatformError:
            return False

    def parse(self, url: str, *, allow_ambiguous: bool = True) -> ParsedTarget:
        raw = (url or "").strip()
        if not raw:
            raise InvalidTargetUrl("target URL is required")
        if "://" not in raw:
            raw = "https://" + raw
        parts = urlsplit(raw)
        if parts.scheme not in {"http", "https"}:
            raise InvalidTargetUrl("only http(s) URLs can be recorded")
        if parts.username or parts.password:
            raise InvalidTargetUrl("URLs containing credentials are rejected")
        host = (parts.hostname or "").lower()
        if not self.host_matches(host):
            raise InvalidTargetUrl(
                f"host '{host}' does not belong to {self.label} "
                f"(expected one of: {', '.join(self.hosts)})"
            )

        path = re.sub(r"/{2,}", "/", parts.path or "/")
        segments = [segment for segment in path.split("/") if segment]
        query = parse_qs(parts.query)

        identifier, kind, display_name, ambiguous, notes = self.extract(segments, query)
        identifier = (identifier or "").strip()
        if not identifier:
            raise InvalidTargetUrl("could not determine a public identifier from this URL")
        if not re.fullmatch(r"[A-Za-z0-9._@\-]{1,120}", identifier):
            raise InvalidTargetUrl("public identifier contains unsupported characters")
        if ambiguous and not allow_ambiguous:
            raise InvalidTargetUrl("URL shape is ambiguous for this platform")

        # Handles are case-insensitive on every supported platform, so the
        # canonical URL and identifier are lower-cased for reliable de-duplication.
        identifier = identifier.lower()
        normalised = self.build_url(identifier, kind)
        return ParsedTarget(
            platform=self.key,
            url=normalised,
            identifier=identifier,
            kind=kind,
            display_name=display_name,
            ambiguous=ambiguous,
            notes=notes,
        )

    def build_url(self, identifier: str, kind: str) -> str:
        return f"https://{self.hosts[0]}/{identifier}"

    @abstractmethod
    def extract(
        self, segments: list[str], query: dict[str, list[str]]
    ) -> tuple[str, str, str, bool, str]:
        """Return ``(identifier, kind, display_name, ambiguous, notes)``."""

    # ------------------------------------------------------------------
    # Policy and channel catalogue
    # ------------------------------------------------------------------
    def policies(self) -> dict[str, tuple[PolicyReference, ...]]:
        raise NotImplementedError

    def channels(self) -> dict[str, ReportingChannel]:
        raise NotImplementedError

    def policies_for(self, category: str) -> tuple[PolicyReference, ...]:
        catalogue = self.policies()
        return catalogue.get(category) or catalogue.get("other") or ()

    def channel_for(self, category: str) -> ReportingChannel:
        catalogue = self.channels()
        return catalogue.get(category) or catalogue[self.default_channel_key]

    def api_capability(self) -> ApiCapability:
        return ApiCapability(
            takedown_submission=False,
            status_retrieval=False,
            notes=(
                f"{self.label} does not publish an API for submitting account or Page "
                "takedown requests or for reading enforcement decisions, so this "
                "module prepares the request package and walks the operator through "
                "the official reporting channel."
            ),
        )

    def categories(self) -> Iterable[str]:
        return VIOLATION_CATEGORIES.keys()

    def described_categories(self) -> list[dict[str, object]]:
        result = []
        for key in self.categories():
            meta = VIOLATION_CATEGORIES[key]
            result.append(
                {
                    "key": key,
                    "label": meta["label"],
                    "summary": meta["summary"],
                    "requires_ownership_document": meta["requires_ownership_document"],
                    "policies": [policy.__dict__ for policy in self.policies_for(key)],
                    "channel": self.channel_for(key).__dict__,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Submission text
    # ------------------------------------------------------------------
    def submission_instructions(self, category: str) -> list[str]:
        channel = self.channel_for(category)
        steps = [
            f"Sign in to the account that will own the report (staff account, not the target).",
            f"Open the official {self.label} reporting channel: {channel.url}",
        ]
        if channel.method == "in_app":
            steps.append(
                "Use the in-app flow: open the target profile or Page, choose "
                "'Report', then select the category that matches the documented "
                "violation."
            )
        else:
            steps.append("Complete every required field of the official form.")
        steps.extend(
            [
                "Attach the evidence package exported from this case, in the "
                "platform's supported formats.",
                "Record the confirmation screen or reference number in this case as "
                "soon as the platform provides it.",
                "Do not submit the same case repeatedly; wait for the platform's "
                "decision and use the appeal route if it is rejected.",
            ]
        )
        return steps


class PlatformRegistry:
    """Holds every registered platform module."""

    def __init__(self) -> None:
        self._platforms: dict[str, BasePlatform] = {}

    def register(self, platform: BasePlatform) -> None:
        self._platforms[platform.key] = platform

    def get(self, key: str) -> BasePlatform:
        try:
            return self._platforms[key]
        except KeyError as exc:
            raise PlatformError(f"unknown platform '{key}'") from exc

    def all(self) -> list[BasePlatform]:
        return list(self._platforms.values())

    def keys(self) -> list[str]:
        return list(self._platforms.keys())

    def detect(self, url: str) -> Optional[ParsedTarget]:
        """Return the first platform that claims the URL, preferring specific ones."""
        for platform in self._platforms.values():
            try:
                return platform.parse(url)
            except PlatformError:
                continue
        return None


registry = PlatformRegistry()
