"""Platform URL grammar and policy catalogue tests."""

from __future__ import annotations

import pytest

from platforms import VIOLATION_CATEGORIES, registry
from platforms.base_platform import InvalidTargetUrl


def test_all_platforms_registered():
    assert set(registry.keys()) == {
        "facebook_personal",
        "facebook_pages",
        "instagram",
        "tiktok",
    }


@pytest.mark.parametrize(
    "url,platform,identifier",
    [
        ("https://www.facebook.com/jane.doe", "facebook_personal", "jane.doe"),
        ("https://facebook.com/profile.php?id=100012345", "facebook_personal", "100012345"),
        (
            "https://www.facebook.com/pages/Acme-Help/123456789012345",
            "facebook_pages",
            "123456789012345",
        ),
        ("https://www.instagram.com/some_user.name/", "instagram", "some_user.name"),
        ("https://www.tiktok.com/@scam_account", "tiktok", "scam_account"),
    ],
)
def test_parsing(url, platform, identifier):
    parsed = registry.detect(url) or registry.get(platform).parse(url)
    assert parsed is not None
    assert parsed.platform == platform
    assert parsed.identifier == identifier


def test_lookalike_host_rejected():
    with pytest.raises(InvalidTargetUrl):
        registry.get("instagram").parse("https://instagram.com.evil.example/user")


def test_credentials_in_url_rejected():
    with pytest.raises(InvalidTargetUrl):
        registry.get("facebook_personal").parse("https://user:pass@facebook.com/x")


def test_facebook_section_is_not_a_profile():
    with pytest.raises(InvalidTargetUrl):
        registry.get("facebook_personal").parse("https://www.facebook.com/groups/12345")


def test_tiktok_without_at_is_flagged_ambiguous():
    parsed = registry.get("tiktok").parse("https://www.tiktok.com/example")
    assert parsed.ambiguous is True


@pytest.mark.parametrize("platform", [p.key for p in registry.all()])
def test_every_category_has_policy_and_channel(platform):
    module = registry.get(platform)
    for category in VIOLATION_CATEGORIES:
        policies = module.policies_for(category)
        assert policies, f"{platform} has no policy for {category}"
        assert policies[0].url.startswith("https://")
        channel = module.channel_for(category)
        assert channel.url.startswith("https://")


@pytest.mark.parametrize("platform", [p.key for p in registry.all()])
def test_no_platform_claims_a_takedown_api(platform):
    capability = registry.get(platform).api_capability()
    assert capability.takedown_submission is False
    assert capability.status_retrieval is False
    assert capability.notes


def test_page_urls_route_to_page_module():
    parsed = registry.detect("https://www.facebook.com/pages/Shop/1234567890")
    assert parsed is not None and parsed.platform == "facebook_pages"