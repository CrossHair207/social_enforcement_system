"""End-to-end integration test through the real HTTP surface."""

from __future__ import annotations

import re

from tests.conftest import csrf, login

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 128

DESCRIPTION = (
    "On 2024-05-01 the account published three posts copying our logo and sent "
    "customers a message asking them to pay an invoice through a link that copies "
    "our login page. Screenshots of each post and the message were captured on "
    "2024-05-02 and the direct post URL is recorded in this case."
)


def _post(client, url, data, **kwargs):
    token = kwargs.pop("token", None) or csrf(client.get("/dashboard").text)
    payload = dict(data)
    payload["csrf_token"] = token
    return client.post(url, data=payload, follow_redirects=False, **kwargs)


def test_full_case_lifecycle(client):
    login(client)

    response = _post(
        client,
        "/targets",
        {
            "platform": "instagram",
            "url": "https://www.instagram.com/impersonator",
            "display_name": "Impersonator",
            "category": "brand",
            "notes": "reported by customer support",
        },
    )
    assert response.status_code == 303

    response = _post(
        client,
        "/cases",
        {
            "target_id": "1",
            "title": "Brand impersonation on Instagram",
            "violation_category": "impersonation",
            "description": DESCRIPTION,
            "priority": "high",
            "requested_action": "account_disabling",
            "reporter_name": "Support Analyst",
            "reporter_email": "support@example.com",
            "reporter_org": "Example Ltd",
        },
    )
    assert response.status_code == 303
    assert "/cases/1" in response.headers["location"]

    token = csrf(client.get("/cases/1").text)
    response = client.post(
        "/cases/1/evidence",
        data={
            "kind": "screenshot",
            "description": "Profile and post capture",
            "captured_at": "2024-05-02",
            "csrf_token": token,
        },
        files=[("files", ("capture.png", PNG, "image/png"))],
        follow_redirects=False,
    )
    assert response.status_code == 303

    response = _post(
        client,
        "/cases/1/evidence-link",
        {
            "source_url": "https://www.instagram.com/p/XYZ123/",
            "kind": "post_url",
            "description": "Offending post",
        },
    )
    assert response.status_code == 303

    response = _post(client, "/cases/1/analyze", {})
    assert response.status_code == 303
    page = client.get("/cases/1").text
    assert "Evidence support" in page
    assert "moderate" in page or "strong" in page

    response = _post(
        client,
        "/cases/1/review",
        {"confirmed_note": "Verified the policy match, the target identity and each capture."},
    )
    assert response.status_code == 303

    response = _post(client, "/cases/1/status", {"to_status": "under_investigation", "note": "started"})
    assert response.status_code == 303
    response = _post(client, "/cases/1/status", {"to_status": "ready_for_submission", "note": "ready"})
    assert response.status_code == 303

    response = _post(
        client,
        "/cases/1/submit",
        {
            "channel_label": "Instagram in-app report",
            "reference": "IG-REF-778899",
            "method": "manual",
            "notes": "Reported through the profile menu.",
        },
    )
    assert response.status_code == 303
    page = client.get("/cases/1").text
    assert "submitted" in page.lower()

    response = _post(
        client,
        "/cases/1/platform-response",
        {
            "platform_status": "permanently_disabled",
            "reference": "IG-DECISION-4455",
            "note": "Platform message: this account has been permanently disabled.",
        },
    )
    assert response.status_code == 303
    page = client.get("/cases/1").text
    assert "Platform-confirmed" in page

    stats = client.get("/api/stats").json()
    assert stats["overview"]["confirmed_total"] == 1
    assert stats["overview"]["permanently_disabled"] == 1
    assert stats["overview"]["total_cases"] == 1

    for fmt in ("txt", "json", "pdf", "docx", "zip"):
        export = client.get(f"/cases/1/export/{fmt}")
        assert export.status_code == 200, fmt
        assert len(export.content) > 200

    assert client.get("/analytics").status_code == 200
    assert client.get("/notifications").status_code == 200
    assert client.get("/healthz").json()["status"] == "ok"


def test_platform_status_cannot_be_set_through_status_form(client):
    login(client)
    _post(
        client,
        "/targets",
        {"platform": "tiktok", "url": "https://www.tiktok.com/@bad_actor", "display_name": "", "category": "", "notes": ""},
    )
    _post(
        client,
        "/cases",
        {
            "target_id": "1",
            "title": "Scam",
            "violation_category": "fraud_scam",
            "description": DESCRIPTION,
            "priority": "normal",
            "requested_action": "account_disabling",
        },
    )
    response = _post(
        client,
        "/cases/1/status",
        {"to_status": "permanently_disabled", "note": "looks gone"},
    )
    # The form action is rejected and the operator is redirected with an error.
    assert response.status_code == 303
    assert "err=" in response.headers["location"]
    page = client.get("/cases/1").text
    assert "Permanently Disabled" not in page.split("Status history")[0].split("badge status-")[1][:40]


def test_evidence_upload_rejects_executable(client):
    login(client)
    _post(
        client,
        "/targets",
        {"platform": "instagram", "url": "https://www.instagram.com/x", "display_name": "", "category": "", "notes": ""},
    )
    _post(
        client,
        "/cases",
        {
            "target_id": "1",
            "title": "Case",
            "violation_category": "harassment",
            "description": DESCRIPTION,
            "priority": "normal",
            "requested_action": "content_removal",
        },
    )
    token = csrf(client.get("/cases/1").text)
    response = client.post(
        "/cases/1/evidence",
        data={"kind": "other", "csrf_token": token},
        files=[("files", ("tool.exe", b"MZ\x90\x00payload", "application/octet-stream"))],
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "err=" in response.headers["location"]
    assert "evidence #" not in client.get("/cases/1").text


def test_import_endpoint_skips_duplicates(client):
    login(client)
    csv_body = (
        "url,platform,display_name\n"
        "https://www.instagram.com/imported_one,,Imported One\n"
        "https://www.instagram.com/imported_one,,Duplicate\n"
        "https://not-a-social-host.example/x,,\n"
    ).encode()
    token = csrf(client.get("/targets").text)
    response = client.post(
        "/targets/import",
        data={"csrf_token": token},
        files=[("file", ("targets.csv", csv_body, "text/csv"))],
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "Imported%201" in response.headers["location"] or "Imported 1" in response.headers["location"]
    page = client.get("/targets").text
    assert page.count("imported_one") >= 1
    match = re.search(r"Imported (\d+) target", page) if "Imported" in page else None