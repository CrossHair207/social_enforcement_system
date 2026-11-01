"""Application entrypoint.

Run with::

    uvicorn app:app --host 127.0.0.1 --port 8000

or ``python app.py`` for the bundled development server.
"""

from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from starlette.middleware.sessions import SessionMiddleware

from config import settings
from core.authentication import create_user
from core.database import init_db, session_scope
from core.scheduler import ReminderScheduler
from dashboard.routes import router, templates
from database.models import User
from utils.logging import configure_logging

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "dashboard" / "static"


def seed_administrator() -> None:
    """Create the first administrator exactly once."""
    with session_scope() as db:
        if db.scalar(select(func.count(User.id))):
            return
        email = settings.admin_email or "admin@localhost"
        generated = False
        password = settings.admin_password
        if not password:
            password = secrets.token_urlsafe(15)
            generated = True
        create_user(
            db,
            email=email,
            password=password,
            full_name="Initial administrator",
            role="admin",
            must_change_password=generated,
        )
        banner = "=" * 72
        print(banner)
        print(" Initial administrator created")
        print(f"   e-mail   : {email}")
        if generated:
            print(f"   password : {password}")
            print("   Shown once. Change it immediately after signing in.")
        else:
            print("   password : taken from ADMIN_PASSWORD")
        print(banner)


def create_app() -> FastAPI:
    settings.ensure_directories()
    configure_logging(settings.data_dir)
    reminder = ReminderScheduler(settings.scheduler_interval_seconds)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        init_db()
        seed_administrator()
        if settings.scheduler_enabled:
            reminder.start()
        logger.info(
            "%s %s ready (env=%s, db=%s)",
            settings.app_name,
            settings.version,
            settings.environment,
            settings.database_url.split("://")[0],
        )
        try:
            yield
        finally:
            reminder.stop()

    application = FastAPI(
        title=settings.app_name,
        version=settings.version,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    application.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie=settings.session_cookie,
        max_age=settings.session_max_age,
        same_site=settings.cookie_samesite,
        https_only=settings.cookie_secure,
    )

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; object-src 'none'",
        )
        if request.session.get("uid"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @application.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        location = (exc.headers or {}).get("Location")
        if location:
            from starlette.responses import RedirectResponse

            return RedirectResponse(location, status_code=exc.status_code)
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        try:
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "request": request,
                    "status_code": exc.status_code,
                    "detail": exc.detail,
                    "app_name": settings.app_name,
                    "app_version": settings.version,
                },
                status_code=exc.status_code,
            )
        except Exception:  # pragma: no cover - template fallback
            return HTMLResponse(
                f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>",
                status_code=exc.status_code,
            )

    application.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    application.include_router(router)
    return application


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
