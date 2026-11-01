"""Password hashing, CSRF protection and field-level encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from config import settings

PBKDF2_ITERATIONS = 210_000
_HASH_PREFIX = "pbkdf2_sha256"


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 and a per-user salt."""
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "$".join(
        (
            _HASH_PREFIX,
            str(PBKDF2_ITERATIONS),
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )
    )


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of a PBKDF2 hash."""
    try:
        prefix, iterations, salt_b64, digest_b64 = stored.split("$")
        if prefix != _HASH_PREFIX:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


def password_problems(password: str) -> list[str]:
    """Return human-readable policy violations for a candidate password."""
    problems: list[str] = []
    if len(password) < settings.password_min_length:
        problems.append(f"must be at least {settings.password_min_length} characters")
    if not re.search(r"[A-Za-z]", password):
        problems.append("must contain a letter")
    if not re.search(r"\d", password):
        problems.append("must contain a digit")
    if password.lower() in {"password", "changeme", "letmein", "admin123456"}:
        problems.append("is a commonly used password")
    return problems


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
CSRF_SESSION_KEY = "csrf_token"


def csrf_token(session: dict) -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def verify_csrf(session: dict, submitted: Optional[str]) -> bool:
    expected = session.get(CSRF_SESSION_KEY)
    if not expected or not submitted:
        return False
    return hmac.compare_digest(str(expected), str(submitted))


class CsrfError(Exception):
    """Raised when a state-changing request carries an invalid CSRF token."""


# ---------------------------------------------------------------------------
# Field-level encryption (reporter contact details only)
# ---------------------------------------------------------------------------
def _fernet() -> Fernet:
    raw = settings.encryption_key or settings.secret_key
    if len(raw) == 44 and raw.endswith("="):
        key = raw.encode()
    else:
        key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(key)


def encrypt_sensitive(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode()


def decrypt_sensitive(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def mask_email(value: str) -> str:
    """Mask an address for list views: ``jo•••@example.com``."""
    if not value or "@" not in value:
        return ""
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        masked = local[:1] + "•"
    else:
        masked = local[:2] + "•" * min(len(local) - 2, 6)
    return f"{masked}@{domain}"


def safe_filename(name: str) -> str:
    """Reduce an uploaded filename to a harmless stem (no path components)."""
    stem = name.replace("\\", "/").split("/")[-1]
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem).strip("._") or "file"
    return stem[:120]
