"""Central configuration for the Social Media Enforcement Management System.

Configuration is layered, in this order of precedence:

1. Real environment variables.
2. Variables from a ``.env`` file in the project root (see ``.env.example``).
3. Safe defaults declared below.

Secrets are never hard-coded: ``SECRET_KEY`` and ``ENCRYPTION_KEY`` must be
supplied in production or generated once and persisted by the operator.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Minimal ``.env`` reader (no external dependency)."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(BASE_DIR / ".env")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_list(name: str, default: Iterable[str]) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if not raw:
        return tuple(default)
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


@dataclass(slots=True)
class Settings:
    """Runtime settings shared by every module."""

    app_name: str = "Social Enforcement Management System"
    version: str = "1.0.0"
    environment: str = field(default_factory=lambda: os.environ.get("APP_ENV", "development"))

    # ---- security -----------------------------------------------------
    secret_key: str = field(default_factory=lambda: os.environ.get("SECRET_KEY", ""))
    encryption_key: str = field(default_factory=lambda: os.environ.get("ENCRYPTION_KEY", ""))
    session_cookie: str = "sems_session"
    session_max_age: int = field(default_factory=lambda: _env_int("SESSION_MAX_AGE", 60 * 60 * 8))
    cookie_secure: bool = field(default_factory=lambda: _env_bool("COOKIE_SECURE", False))
    cookie_samesite: str = field(default_factory=lambda: os.environ.get("COOKIE_SAMESITE", "lax"))
    password_min_length: int = field(default_factory=lambda: _env_int("PASSWORD_MIN_LENGTH", 12))
    login_max_attempts: int = field(default_factory=lambda: _env_int("LOGIN_MAX_ATTEMPTS", 8))
    login_lockout_seconds: int = field(default_factory=lambda: _env_int("LOGIN_LOCKOUT_SECONDS", 900))

    # ---- persistence --------------------------------------------------
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'data' / 'sems.db').as_posix()}"
        )
    )
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
    )

    # ---- uploads ------------------------------------------------------
    max_upload_mb: int = field(default_factory=lambda: _env_int("MAX_UPLOAD_MB", 25))
    allowed_extensions: tuple[str, ...] = field(
        default_factory=lambda: _env_list(
            "ALLOWED_EXTENSIONS",
            # .txt / .json are accepted so plain-text exports of a post or a
            # message thread can be filed, but never executable types.
            (".png", ".jpg", ".jpeg", ".webp", ".gif", ".pdf", ".mp4", ".mov",
             ".mp3", ".m4a", ".txt", ".json", ".eml", ".html"),
        )
    )

    # ---- workflow -----------------------------------------------------
    follow_up_days: int = field(default_factory=lambda: _env_int("FOLLOW_UP_DAYS", 14))
    appeal_deadline_days: int = field(default_factory=lambda: _env_int("APPEAL_DEADLINE_DAYS", 30))
    scheduler_enabled: bool = field(default_factory=lambda: _env_bool("SCHEDULER_ENABLED", True))
    scheduler_interval_seconds: int = field(
        default_factory=lambda: _env_int("SCHEDULER_INTERVAL_SECONDS", 900)
    )

    # ---- notifications ------------------------------------------------
    smtp_host: str = field(default_factory=lambda: os.environ.get("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _env_int("SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: os.environ.get("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: os.environ.get("SMTP_FROM", ""))
    smtp_starttls: bool = field(default_factory=lambda: _env_bool("SMTP_STARTTLS", True))

    # ---- bootstrap ----------------------------------------------------
    admin_email: str = field(default_factory=lambda: os.environ.get("ADMIN_EMAIL", ""))
    admin_password: str = field(default_factory=lambda: os.environ.get("ADMIN_PASSWORD", ""))
    default_platform: str = "facebook_personal"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def export_dir(self) -> Path:
        return self.data_dir / "exports"

    def ensure_directories(self) -> None:
        for directory in (self.data_dir, self.evidence_dir, self.export_dir):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o700)
            except OSError:  # pragma: no cover - e.g. Windows
                pass

    def resolve_secrets(self) -> None:
        """Guarantee usable secrets.

        In development a random key is generated for the process lifetime. In
        production a missing ``SECRET_KEY`` is a configuration error, because
        rotating it silently would invalidate every session and make encrypted
        reporter contact details unreadable.
        """
        if not self.secret_key:
            if self.environment.lower() == "production":
                raise RuntimeError(
                    "SECRET_KEY must be set when APP_ENV=production "
                    "(see .env.example)."
                )
            self.secret_key = secrets.token_urlsafe(48)
        if not self.encryption_key:
            if self.environment.lower() == "production":
                raise RuntimeError(
                    "ENCRYPTION_KEY must be set when APP_ENV=production "
                    "(see .env.example)."
                )
            self.encryption_key = self.secret_key


settings = Settings()
settings.resolve_secrets()
