"""Pytest fixtures: every test runs against a fresh SQLite database."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_BASE_TMP = Path(tempfile.mkdtemp(prefix="sems-tests-"))
os.environ.setdefault("DATA_DIR", str(_BASE_TMP))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_BASE_TMP / 'bootstrap.db'}")
os.environ.setdefault("ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("ADMIN_PASSWORD", "AdminPassw0rd!2024")
os.environ.setdefault("SCHEDULER_ENABLED", "false")
os.environ.setdefault("APP_ENV", "development")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app as app_module  # noqa: E402
from config import settings  # noqa: E402
from core.database import configure, session_scope  # noqa: E402
from core.authentication import create_user  # noqa: E402

ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh database, fresh evidence directory, app lifespan executed."""
    configure(f"sqlite:///{tmp_path / 'sems.db'}")
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(settings, "admin_email", ADMIN_EMAIL)
    monkeypatch.setattr(settings, "admin_password", ADMIN_PASSWORD)
    monkeypatch.setattr(settings, "scheduler_enabled", False)
    settings.ensure_directories()
    with TestClient(app_module.app) as test_client:
        yield test_client


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """Service-layer session against an isolated database and data directory."""
    from core.database import init_db

    configure(f"sqlite:///{tmp_path / 'service.db'}")
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    settings.ensure_directories()
    init_db()
    with session_scope() as session:
        yield session


def csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token missing from page"
    return match.group(1)


def page_csrf(client: TestClient, path: str = "/dashboard") -> str:
    response = client.get(path)
    assert response.status_code == 200, response.text[:300]
    return csrf(response.text)


def login(client: TestClient, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD):
    token = csrf(client.get("/login").text)
    response = client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text[:300]
    return response


def make_user(email: str, role: str, password: str = "AnalystPassw0rd!23"):
    with session_scope() as db:
        user = create_user(db, email=email, password=password, role=role)
        db.commit()
        return user.id


def create_target(
    db,
    platform_key="instagram",
    url="https://www.instagram.com/test_target",
    **kwargs,
):
    from enforcement.case_manager import create_target as _create

    return _create(db, platform_key=platform_key, url=url, **kwargs)


def create_case(db, target, **kwargs):
    from enforcement.case_manager import create_case as _create

    defaults = dict(
        target=target,
        violation_category="impersonation",
        title="Impersonation of a real account",
        description=(
            "Between 2024-05-01 and 2024-05-03 the account sent messages to our "
            "support inbox pretending to be our brand and asked customers to pay "
            "an invoice through a link that copies our login page."
        ),
    )
    defaults.update(kwargs)
    return _create(db, **defaults)