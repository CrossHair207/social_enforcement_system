"""Platform integration modules.

Each platform module is self-contained: URL grammar, policy catalogue,
official reporting channels and an honest statement of API capability. The
registry lets the rest of the application stay platform-agnostic, so a new
platform is a new module plus one ``register`` call.
"""

from platforms.base_platform import (  # noqa: F401
    BasePlatform,
    InvalidTargetUrl,
    ParsedTarget,
    PlatformError,
    PolicyReference,
    ReportingChannel,
    VIOLATION_CATEGORIES,
    category_label,
    registry,
)
from platforms.facebook_pages import FacebookPagesPlatform
from platforms.facebook_personal import FacebookPersonalPlatform
from platforms.instagram import InstagramPlatform
from platforms.tiktok import TikTokPlatform

for _platform in (
    FacebookPersonalPlatform(),
    FacebookPagesPlatform(),
    InstagramPlatform(),
    TikTokPlatform(),
):
    registry.register(_platform)

__all__ = [
    "BasePlatform",
    "InvalidTargetUrl",
    "ParsedTarget",
    "PlatformError",
    "PolicyReference",
    "ReportingChannel",
    "VIOLATION_CATEGORIES",
    "category_label",
    "registry",
]