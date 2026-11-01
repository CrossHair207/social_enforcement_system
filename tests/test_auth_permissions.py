"""Authentication, CSRF, session and role-permission tests."""

from __future__ import annotations

import pytest

from config import settings
from core.authentication import AuthError, create_user
from core.permissions import PermissionDenied, can, require
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, csrf, login, make_user


def test_unauthenticated_redirects_to_login(client):
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_login_success_and_dashboard(client):
    login(client)
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "Overview" in response.text


def test_wrong_password_rejected(client):
    token = csrf(client.get("/login").text)
    response = client.post(
        "/login",
        data={"email": ADMIN_EMAIL, "password": "wrong-password", "csrf_token": token},
    )
    assert response.status_code == 401
    assert "invalid" in response.text.lower()


def test_login_requires_csrf(client):
    response = client.post(
        "/login", data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 400


def test_state_changing_post_without_csrf_rejected(client):
    login(client)
    response = client.post(
        "/targets", data={"platform": "instagram", "url": "https://www.instagram.com/x"}
    )
    assert response.status_code == 400


def test_account_lockout_after_failures(client, monkeypatch):
    monkeypatch.setattr(settings, "login_max_attempts", 3)
    for _ in range(3):
        token = csrf(client.get("/login").text)
        client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": "nope", "csrf_token": token},
        )
    token = csrf(client.get("/login").text)
    response = client.post(
        "/login",
        data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "csrf_token": token},
    )
    assert response.status_code == 401
    assert "locked" in response.text.lower()


def test_viewer_cannot_create_cases(client):
    make_user("viewer@example.com", "viewer")
    login(client, "viewer@example.com", "AnalystPassw0rd!23")
    assert client.get("/dashboard").status_code == 200
    assert client.get("/cases/new").status_code == 403


def test_analyst_cannot_delete_or_decide(client):
    make_user("analyst@example.com", "analyst")
    login(client, "analyst@example.com", "AnalystPassw0rd!23")
    token = csrf(client.get("/cases").text)
    assert client.post("/cases/1/delete", data={"csrf_token": token}).status_code == 403
    assert (
        client.post(
            "/cases/1/platform-response",
            data={
                "platform_status": "permanently_disabled",
                "reference": "X",
                "note": "n",
                "csrf_token": token,
            },
        ).status_code
        == 403
    )


def test_analyst_can_open_a_case(client):
    make_user("analyst2@example.com", "analyst")
    login(client, "analyst2@example.com", "AnalystPassw0rd!23")
    token = csrf(client.get("/targets").text)
    client.post(
        "/targets",
        data={
            "platform": "tiktok",
            "url": "https://www.tiktok.com/@analyst_case",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    token = csrf(client.get("/cases/new").text)
    response = client.post(
        "/cases",
        data={
            "target_id": "1",
            "title": "Scam account",
            "violation_category": "fraud_scam",
            "description": "The account requested payment for goods that were never delivered.",
            "priority": "normal",
            "requested_action": "account_disabling",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "/cases/1" in response.headers["location"]


def test_password_policy_enforced(client):
    from core.database import session_scope

    with session_scope() as db:
        with pytest.raises(AuthError):
            create_user(db, email="weak@example.com", password="short", role="analyst")


def test_permission_helper_matrix():
    class U:
        def __init__(self, role):
            self.role = role
            self.is_active = True

    assert can(U("manager"), "case.decide") is True
    assert can(U("analyst"), "case.decide") is False
    assert can(U("viewer"), "case.create") is False
    assert can(U("admin"), "anything.at.all") is True
    assert can(None, "case.view") is False
    with pytest.raises(PermissionDenied):
        require(U("viewer"), "case.create")


def test_logout_clears_session(client):
    login(client)
    token = csrf(client.get("/dashboard").text)
    response = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_api_requires_login(client):
    response = client.get("/api/stats", follow_redirects=False)
    assert response.status_code == 303
