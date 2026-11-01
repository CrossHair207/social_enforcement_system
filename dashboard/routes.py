"""HTTP routes for the dashboard (server-rendered pages plus a small JSON API)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from config import settings
from core import authentication, permissions
from core.authentication import audit
from core.database import get_db
from core.scheduler import run_reminder_cycle
from core.security import csrf_token, decrypt_sensitive, mask_email, verify_csrf
from dashboard import analytics, notifications
from database.models import (
    CONFIRMED_OUTCOMES,
    PLATFORM_LABELS,
    PRIORITIES,
    STATUSES,
    STATUS_LABELS,
    Appeal,
    EnforcementCase,
    Evidence,
    Notification,
    Target,
    User,
)
from documents import docx_generator, pdf_generator, report_generator
from enforcement import appeal_manager, case_manager, status_tracker, submission_manager
from enforcement.case_manager import CaseError, REQUESTED_ACTIONS
from enforcement.policy_matcher import PolicyMatchError, categories_for_platform, match
from enforcement.submission_manager import SubmissionError
from enforcement.violation_analyzer import analyze_case, apply_analysis, load_analysis, load_policies
from evidence import evidence_exporter, evidence_manager
from evidence.evidence_manager import EVIDENCE_KINDS
from platforms import VIOLATION_CATEGORIES, registry
from platforms.base_platform import POLICY_SOURCE_NOTE
from platforms.base_platform import PlatformError
from utils.validators import (
    ValidationError,
    fmt_dt,
    parse_datetime,
    validate_email,
)

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _format_dt(value):
    return fmt_dt(value)


def _status_label(value: str) -> str:
    return STATUS_LABELS.get(value, (value or "").replace("_", " ").title())


def _platform_label(value: str) -> str:
    return PLATFORM_LABELS.get(value, (value or "").replace("_", " ").title())


def _category_label(value: str) -> str:
    return str(VIOLATION_CATEGORIES.get(value, {}).get("label", (value or "").replace("_", " ").title()))


templates.env.filters["dt"] = _format_dt
templates.env.filters["status_label"] = _status_label
templates.env.filters["platform_label"] = _platform_label
templates.env.filters["category_label"] = _category_label
templates.env.globals.update(
    app_name=settings.app_name,
    app_version=settings.version,
    policy_source_note=POLICY_SOURCE_NOTE,
    statuses=STATUSES,
    status_labels=STATUS_LABELS,
    platforms=PLATFORM_LABELS,
    categories={key: str(meta["label"]) for key, meta in VIOLATION_CATEGORIES.items()},
    priorities=PRIORITIES,
    requested_actions=REQUESTED_ACTIONS,
    evidence_kinds=EVIDENCE_KINDS,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    user_id = request.session.get(authentication.SESSION_USER_KEY)
    if not user_id:
        return None
    user = db.get(User, int(user_id))
    if user is None or not user.is_active:
        request.session.clear()
        return None
    return user


def require_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    user = current_user(request, db)
    if user is None:
        raise HTTPException(
            status_code=303, headers={"Location": f"/login?next={request.url.path}"}
        )
    return user


def require_action(user: User, action: str) -> None:
    if not permissions.can(user, action):
        raise HTTPException(
            status_code=403,
            detail=f"Your role ({user.role}) is not permitted to perform this action.",
        )


def check_csrf(request: Request, token: str) -> None:
    if not verify_csrf(request.session, token):
        raise HTTPException(status_code=400, detail="Invalid or missing CSRF token.")


def page(
    request: Request,
    user: User,
    db: Session,
    template: str,
    **context,
) -> HTMLResponse:
    base = {
        "request": request,
        "user": user,
        "can": permissions.can,
        "csrf_token": csrf_token(request.session),
        "unread": notifications.unread_count(db, user.id),
        "message": request.query_params.get("msg", ""),
        "error": request.query_params.get("err", ""),
        "level": request.query_params.get("level", "success"),
    }
    base.update(context)
    return templates.TemplateResponse(request, template, base)


def back(url: str, message: str = "", error: str = "") -> RedirectResponse:
    from urllib.parse import quote

    separator = "&" if "?" in url else "?"
    if error:
        return RedirectResponse(
            f"{url}{separator}err={quote(error[:400])}&level=danger", status_code=303
        )
    if message:
        return RedirectResponse(
            f"{url}{separator}msg={quote(message[:400])}", status_code=303
        )
    return RedirectResponse(url, status_code=303)


def _case_or_404(db: Session, case_id: int, user: User) -> EnforcementCase:
    case = db.get(EnforcementCase, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if user.role == "analyst" and case.owner_id not in (None, user.id):
        # Analysts work their own caseload; managers and admins see everything.
        raise HTTPException(status_code=403, detail="This case belongs to another analyst.")
    return case


def _parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)):
    if current_user(request, db):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "csrf_token": csrf_token(request.session), "error": ""},
    )


@router.post("/login")
def login_submit(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    db: Session = Depends(get_db),
):
    check_csrf(request, csrf_token_field)
    try:
        user = authentication.authenticate(
            db, email, password, ip=request.client.host if request.client else ""
        )
    except authentication.AuthError as exc:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "csrf_token": csrf_token(request.session),
                "error": str(exc),
                "email": email,
            },
            status_code=401,
        )
    authentication.login_session(request, user)
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token_field: str = Form("", alias="csrf_token")):
    check_csrf(request, csrf_token_field)
    authentication.logout_session(request)
    return RedirectResponse("/login", status_code=303)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@router.get("/", include_in_schema=False)
def root(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    return RedirectResponse("/dashboard" if user else "/login", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    require_action(user, "dashboard.view")
    return page(
        request,
        user,
        db,
        "dashboard.html",
        overview=analytics.overview(db),
        by_status=analytics.by_status(db),
        by_platform=analytics.by_platform(db),
        recent=analytics.recent_cases(db),
        confirmed=analytics.confirmed_outcomes(db),
        overdue=case_manager.overdue_cases(db),
    )


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
@router.get("/targets", response_class=HTMLResponse)
def targets_list(
    request: Request,
    platform: str = "",
    q: str = "",
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "target.view")
    statement = select(Target)
    if platform:
        statement = statement.where(Target.platform == platform)
    if q:
        statement = statement.where(Target.url.ilike(f"%{q}%"))
    rows = list(db.scalars(statement.order_by(Target.created_at.desc()).limit(500)))
    return page(
        request,
        user,
        db,
        "targets.html",
        targets=rows,
        filter_platform=platform,
        query=q,
    )


@router.post("/targets")
def target_create(
    request: Request,
    platform: str = Form(""),
    url: str = Form(""),
    display_name: str = Form(""),
    category: str = Form(""),
    notes: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "target.create")
    check_csrf(request, csrf_token_field)
    platform_key = platform
    if not platform_key and url:
        detected = case_manager.detect_platform(url)
        if detected is None:
            return back("/targets", error="Could not identify the platform from that URL; select it explicitly.")
        platform_key = detected.platform
    if not platform_key:
        return back("/targets", error="Choose a platform or supply a recognisable profile URL.")
    try:
        target = case_manager.create_target(
            db,
            platform_key=platform_key,
            url=url,
            actor=user,
            display_name=display_name,
            category=category,
            notes=notes,
        )
    except (CaseError, ValidationError, PlatformError) as exc:
        return back("/targets", error=str(exc))
    audit(db, user, "target.create", "target", str(target.id), detail=target.url)
    db.commit()
    return back("/targets", message=f"Target {target.public_identifier} added.")


@router.post("/targets/import")
async def targets_import(
    request: Request,
    file: UploadFile = File(...),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "target.create")
    check_csrf(request, csrf_token_field)
    raw = (await file.read()).decode("utf-8", errors="replace")
    try:
        from utils.exporters import parse_csv, parse_json_records

        if (file.filename or "").lower().endswith(".json"):
            rows = parse_json_records(raw)
        else:
            rows = parse_csv(raw)
    except Exception as exc:
        return back("/targets", error=f"Import file could not be read: {exc}")
    result = case_manager.import_targets(db, rows, actor=user)
    audit(db, user, "target.import", "target", "", detail=json.dumps(result))
    db.commit()
    summary = f"Imported {result['created']} target(s), skipped {result['skipped']} duplicate(s)"
    if result["errors"]:
        summary += f", {len(result['errors'])} row(s) failed"
    return back("/targets", message=summary)


@router.get("/targets/export.csv")
def targets_export(user: User = Depends(require_user), db: Session = Depends(get_db)):
    require_action(user, "target.view")
    from utils.exporters import to_csv

    rows = [
        {
            "id": item.id,
            "platform": item.platform,
            "url": item.url,
            "identifier": item.public_identifier,
            "display_name": item.display_name,
            "category": item.category,
            "created_at": item.created_at.isoformat() if item.created_at else "",
        }
        for item in db.scalars(select(Target).order_by(Target.id))
    ]
    body = to_csv(
        rows,
        ["id", "platform", "url", "identifier", "display_name", "category", "created_at"],
    )
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="targets.csv"'},
    )


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
@router.get("/cases", response_class=HTMLResponse)
def cases_list(
    request: Request,
    status: str = "",
    platform: str = "",
    category: str = "",
    priority: str = "",
    q: str = "",
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.view")
    rows = case_manager.search_cases(
        db,
        query=q,
        status=status,
        platform=platform,
        category=category,
        priority=priority,
        owner_id=user.id if user.role == "analyst" else None,
    )
    return page(
        request,
        user,
        db,
        "cases.html",
        cases=rows,
        filters={
            "status": status,
            "platform": platform,
            "category": category,
            "priority": priority,
            "q": q,
        },
    )


@router.get("/cases/new", response_class=HTMLResponse)
def case_new_form(
    request: Request,
    target_id: str = "",
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.create")
    targets = list(db.scalars(select(Target).order_by(Target.created_at.desc()).limit(500)))
    selected = db.get(Target, _parse_int(target_id)) if target_id else None
    return page(
        request,
        user,
        db,
        "case_new.html",
        targets=targets,
        selected_target=selected,
        policies_note="",
    )


@router.post("/cases")
def case_create(
    request: Request,
    target_id: str = Form(...),
    title: str = Form(""),
    violation_category: str = Form(""),
    description: str = Form(""),
    priority: str = Form("normal"),
    requested_action: str = Form("account_disabling"),
    reporter_name: str = Form(""),
    reporter_email: str = Form(""),
    reporter_org: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.create")
    check_csrf(request, csrf_token_field)
    target = db.get(Target, _parse_int(target_id))
    if target is None:
        return back("/cases/new", error="Select a target that exists.")
    try:
        case = case_manager.create_case(
            db,
            target=target,
            violation_category=violation_category,
            title=title,
            description=description,
            actor=user,
            priority=priority,
            requested_action=requested_action,
            reporter_name=reporter_name,
            reporter_email=reporter_email,
            reporter_org=reporter_org,
        )
    except (CaseError, ValidationError) as exc:
        return back("/cases/new", error=str(exc))
    audit(db, user, "case.create", "case", str(case.id), detail=case.case_ref)
    notifications.notify_case_event(
        db,
        case=case,
        title=f"Case {case.case_ref} created",
        body="Collect evidence and run the violation analysis before submission.",
    )
    db.commit()
    return back(f"/cases/{case.id}", message=f"Case {case.case_ref} created.")


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(
    request: Request,
    case_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.view")
    case = _case_or_404(db, case_id, user)
    analysis = load_analysis(case)
    package = None
    if permissions.can(user, "case.submit"):
        try:
            package = submission_manager.build_submission_package(case)
        except PlatformError:
            package = None
    return page(
        request,
        user,
        db,
        "case_detail.html",
        case=case,
        analysis=analysis,
        policies=load_policies(case),
        policy_catalog=list(
            match(case.violation_category, case.target.platform).policies
        ),
        available=status_tracker.available_transitions(case),
        stage_options=[
            option
            for option in status_tracker.available_transitions(case)
            if status_tracker.can_set_directly(option) and option != "submitted_to_platform"
        ],
        platform_options=[
            option
            for option in status_tracker.available_transitions(case)
            if option in status_tracker.PLATFORM_STATUSES
        ],
        package=package,
        integrity=[
            {"evidence_id": item.id, "ok": evidence_manager.absolute_path(item).is_file()}
            for item in case.evidence
        ],
        reporter_email_masked=mask_email(decrypt_sensitive(case.reporter_email_enc)),
    )


@router.post("/cases/{case_id}/update")
def case_update(
    request: Request,
    case_id: int,
    title: str = Form(""),
    description: str = Form(""),
    violation_category: str = Form(""),
    priority: str = Form("normal"),
    requested_action: str = Form("account_disabling"),
    reporter_name: str = Form(""),
    reporter_email: str = Form(""),
    reporter_org: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.edit")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    try:
        case_manager.update_case(
            db,
            case,
            title=title,
            description=description,
            violation_category=violation_category,
            priority=priority,
            requested_action=requested_action,
            reporter_name=reporter_name,
            reporter_org=reporter_org,
            reporter_email=reporter_email,
        )
    except (CaseError, ValidationError) as exc:
        return back(f"/cases/{case_id}", error=str(exc))
    audit(db, user, "case.update", "case", str(case.id))
    db.commit()
    return back(f"/cases/{case_id}", message="Case details updated.")


@router.post("/cases/{case_id}/analyze")
def case_analyze(
    request: Request,
    case_id: int,
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.analyze")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    try:
        result = analyze_case(case)
    except (PolicyMatchError, PlatformError) as exc:
        return back(f"/cases/{case_id}", error=str(exc))
    apply_analysis(case, result)
    db.commit()
    audit(db, user, "case.analyze", "case", str(case.id), detail=f"score={result.score}")
    return back(
        f"/cases/{case_id}",
        message=f"Analysis complete: evidence support {result.confidence} ({result.score}/100).",
    )


@router.post("/cases/{case_id}/review")
def case_confirm_review(
    request: Request,
    case_id: int,
    confirmed_note: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.edit")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    if len((confirmed_note or "").strip()) < 10:
        return back(
            f"/cases/{case_id}",
            error="Record the reviewer's note (at least 10 characters) before confirming manual review.",
        )
    case.manual_review_confirmed = True
    audit(db, user, "case.manual_review", "case", str(case.id), detail=confirmed_note[:1000])
    notifications.notify_case_event(
        db,
        case=case,
        title=f"Manual review confirmed for {case.case_ref}",
        body=confirmed_note[:1000],
    )
    db.commit()
    return back(f"/cases/{case_id}", message="Manual review recorded.")


@router.post("/cases/{case_id}/status")
def case_status(
    request: Request,
    case_id: int,
    to_status: str = Form(""),
    note: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.transition")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    try:
        status_tracker.transition(db, case, to_status, actor=user, note=note)
    except status_tracker.StatusError as exc:
        return back(f"/cases/{case_id}", error=str(exc))
    audit(db, user, "case.status", "case", str(case.id), detail=f"-> {to_status}")
    notifications.notify_case_event(
        db,
        case=case,
        title=f"{case.case_ref} moved to {STATUS_LABELS.get(to_status, to_status)}",
        body=note[:1000],
    )
    db.commit()
    return back(f"/cases/{case_id}", message="Status updated.")


@router.post("/cases/{case_id}/platform-response")
def case_platform_response(
    request: Request,
    case_id: int,
    platform_status: str = Form(""),
    reference: str = Form(""),
    note: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.decide")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    try:
        submission_manager.record_platform_response(
            db,
            case,
            status=platform_status,
            reference=reference,
            note=note,
            actor=user,
        )
    except status_tracker.StatusError as exc:
        return back(f"/cases/{case_id}", error=str(exc))
    audit(
        db,
        user,
        "case.platform_response",
        "case",
        str(case.id),
        detail=f"{platform_status} ref={reference}",
    )
    notifications.notify_case_event(
        db,
        case=case,
        title=f"Platform response recorded for {case.case_ref}",
        body=f"{STATUS_LABELS.get(platform_status, platform_status)} (ref {reference})",
    )
    db.commit()
    return back(f"/cases/{case_id}", message="Platform response recorded.")


@router.post("/cases/{case_id}/notes")
def case_note(
    request: Request,
    case_id: int,
    body: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.comment")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    body = (body or "").strip()
    if not body:
        return back(f"/cases/{case_id}", error="Note cannot be empty.")
    from database.models import CaseNote

    db.add(CaseNote(case_id=case.id, author_id=user.id, body=body[:4000]))
    audit(db, user, "case.note", "case", str(case.id))
    db.commit()
    return back(f"/cases/{case_id}", message="Note added.")


@router.post("/cases/{case_id}/delete")
def case_delete(
    request: Request,
    case_id: int,
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.delete")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    reference = case.case_ref
    for item in list(case.evidence):
        path = evidence_manager.absolute_path(item)
        if path.is_file():
            path.unlink()
    case_manager.delete_case(db, case)
    audit(db, user, "case.delete", "case", str(case_id), detail=reference)
    db.commit()
    return back("/cases", message=f"Case {reference} deleted.")


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
@router.post("/cases/{case_id}/evidence")
async def evidence_upload(
    request: Request,
    case_id: int,
    files: Optional[list[UploadFile]] = File(None),
    kind: str = Form("screenshot"),
    description: str = Form(""),
    source_url: str = Form(""),
    captured_at: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "evidence.upload")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    if not files:
        return back(f"/cases/{case_id}#evidence", error="Choose at least one file to upload.")
    try:
        captured = parse_datetime(captured_at)
    except ValidationError as exc:
        return back(f"/cases/{case_id}#evidence", error=str(exc))

    stored, failures = 0, []
    for upload in files:
        if not upload.filename:
            continue
        data = await upload.read()
        try:
            evidence_manager.store_evidence(
                db,
                case,
                filename=upload.filename,
                data=data,
                kind=kind,
                description=description,
                source_url=source_url,
                captured_at=captured,
                actor=user,
            )
            stored += 1
        except ValidationError as exc:
            failures.append(f"{upload.filename}: {exc}")
    if stored:
        audit(db, user, "evidence.upload", "case", str(case.id), detail=f"{stored} file(s)")
        db.commit()
    if failures:
        return back(
            f"/cases/{case_id}#evidence",
            error="; ".join(failures[:3]),
        )
    return back(f"/cases/{case_id}#evidence", message=f"{stored} evidence file(s) stored.")


@router.post("/cases/{case_id}/evidence-link")
def evidence_link(
    request: Request,
    case_id: int,
    source_url: str = Form(""),
    kind: str = Form("profile_url"),
    description: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "evidence.upload")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    url = (source_url or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        return back(f"/cases/{case_id}#evidence", error="Enter a full http(s) URL.")
    if kind not in ("profile_url", "post_url"):
        return back(f"/cases/{case_id}#evidence", error="Link evidence must be a profile or post URL.")
    body = (
        f"Source URL: {url}\nKind: {kind}\n"
        f"Captured by: {user.email}\nRecorded at: {datetime.now(timezone.utc).isoformat()}\n"
        f"Note: {description}\n"
    ).encode()
    filename = f"url-{kind}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.txt"
    try:
        evidence_manager.store_evidence(
            db,
            case,
            filename=filename,
            data=body,
            kind=kind,
            description=description,
            source_url=url,
            captured_at=datetime.now(timezone.utc),
            actor=user,
        )
    except ValidationError as exc:
        return back(f"/cases/{case_id}#evidence", error=str(exc))
    audit(db, user, "evidence.link", "case", str(case.id), detail=url)
    db.commit()
    return back(f"/cases/{case_id}#evidence", message="Source URL recorded as evidence.")


@router.post("/evidence/{evidence_id}/verify")
def evidence_verify(
    request: Request,
    evidence_id: int,
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "evidence.view")
    check_csrf(request, csrf_token_field)
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    case = _case_or_404(db, evidence.case_id, user)
    result = evidence_manager.verify_integrity(db, evidence)
    audit(
        db,
        user,
        "evidence.verify",
        "evidence",
        str(evidence.id),
        detail="ok" if result["ok"] else str(result["reason"]),
    )
    db.commit()
    if result["ok"]:
        return back(f"/cases/{case.id}#evidence", message="Integrity verified: digest matches.")
    return back(f"/cases/{case.id}#evidence", error=f"Integrity problem: {result['reason']}")


@router.post("/evidence/{evidence_id}/delete")
def evidence_delete(
    request: Request,
    evidence_id: int,
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "evidence.delete")
    check_csrf(request, csrf_token_field)
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    case_id = evidence.case_id
    evidence_manager.delete_evidence(db, evidence, actor=user)
    audit(db, user, "evidence.delete", "evidence", str(evidence_id))
    return back(f"/cases/{case_id}#evidence", message="Evidence removed.")


@router.get("/evidence/{evidence_id}/download")
def evidence_download(
    evidence_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "evidence.view")
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    _case_or_404(db, evidence.case_id, user)
    path = evidence_manager.absolute_path(evidence)
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Evidence file is missing from storage")
    return FileResponse(path, media_type=evidence.media_type, filename=evidence.original_name)


# ---------------------------------------------------------------------------
# Submission, appeals, export
# ---------------------------------------------------------------------------
@router.post("/cases/{case_id}/submit")
def case_submit(
    request: Request,
    case_id: int,
    channel_label: str = Form(""),
    reference: str = Form(""),
    method: str = Form("manual"),
    notes: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.submit")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    try:
        submission_manager.record_submission(
            db,
            case,
            channel_label=channel_label,
            reference=reference,
            method=method,
            notes=notes,
            actor=user,
        )
    except (SubmissionError, status_tracker.StatusError, PlatformError) as exc:
        return back(f"/cases/{case_id}#submission", error=str(exc))
    audit(db, user, "case.submit", "case", str(case.id), detail=reference)
    notifications.notify_case_event(
        db,
        case=case,
        title=f"{case.case_ref} submitted",
        body=f"Recorded submission via {channel_label or 'official channel'} (ref {reference}).",
    )
    db.commit()
    return back(f"/cases/{case_id}#submission", message="Submission recorded.")


@router.post("/cases/{case_id}/appeal")
def case_appeal(
    request: Request,
    case_id: int,
    reason: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "appeal.manage")
    check_csrf(request, csrf_token_field)
    case = _case_or_404(db, case_id, user)
    try:
        appeal_manager.create_appeal(db, case, reason=reason, actor=user)
    except appeal_manager.AppealError as exc:
        return back(f"/cases/{case_id}#appeals", error=str(exc))
    audit(db, user, "appeal.create", "case", str(case.id))
    db.commit()
    return back(f"/cases/{case_id}#appeals", message="Appeal drafted.")


@router.post("/appeals/{appeal_id}/submit")
def appeal_submit(
    request: Request,
    appeal_id: int,
    reference: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "appeal.manage")
    check_csrf(request, csrf_token_field)
    appeal = db.get(Appeal, appeal_id)
    if appeal is None:
        raise HTTPException(status_code=404, detail="Appeal not found")
    case = _case_or_404(db, appeal.case_id, user)
    try:
        appeal_manager.record_appeal_submission(db, appeal, reference=reference, actor=user)
    except appeal_manager.AppealError as exc:
        return back(f"/cases/{case.id}#appeals", error=str(exc))
    if case.status in ("rejected", "temporarily_restricted", *CONFIRMED_OUTCOMES):
        try:
            status_tracker.transition(
                db, case, "appealed", actor=user, note="Appeal submitted to platform."
            )
        except status_tracker.StatusError:
            pass
    audit(db, user, "appeal.submit", "appeal", str(appeal.id), detail=reference)
    db.commit()
    return back(f"/cases/{case.id}#appeals", message="Appeal submission recorded.")


@router.get("/cases/{case_id}/export/{fmt}")
def case_export(
    case_id: int,
    fmt: str,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.export")
    case = _case_or_404(db, case_id, user)
    if fmt not in ("txt", "json", "pdf", "docx", "zip"):
        raise HTTPException(status_code=400, detail="Unsupported export format")
    package = report_generator.build_package(case)
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    stem = case.case_ref.replace("/", "-")

    if fmt == "zip":
        path = evidence_exporter.write_package(case, settings.export_dir / f"{stem}-evidence.zip")
        return FileResponse(path, media_type="application/zip", filename=path.name)
    if fmt == "pdf":
        path = pdf_generator.build_pdf(package, settings.export_dir / f"{stem}.pdf")
        return FileResponse(path, media_type="application/pdf", filename=path.name)
    if fmt == "docx":
        path = docx_generator.build_docx(package, settings.export_dir / f"{stem}.docx")
        return FileResponse(
            path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=path.name,
        )
    if fmt == "json":
        body = report_generator.render_json(package)
        media = "application/json"
    else:
        body = report_generator.render_text(package)
        media = "text/plain; charset=utf-8"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{stem}.{fmt}"'},
    )


# ---------------------------------------------------------------------------
# Analytics, notifications, settings, users
# ---------------------------------------------------------------------------
@router.get("/analytics", response_class=HTMLResponse)
def analytics_page(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    require_action(user, "analytics.view")
    return page(
        request,
        user,
        db,
        "analytics.html",
        overview=analytics.overview(db),
        by_status=analytics.by_status(db),
        by_platform=analytics.by_platform(db),
        by_category=analytics.by_category(db),
        chart=analytics.chart_payload(db),
    )


@router.get("/api/stats")
def api_stats(user: User = Depends(require_user), db: Session = Depends(get_db)):
    require_action(user, "analytics.view")
    return JSONResponse(analytics.chart_payload(db))


@router.get("/api/cases")
def api_cases(
    status: str = "",
    platform: str = "",
    q: str = "",
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "case.view")
    rows = case_manager.search_cases(
        db,
        query=q,
        status=status,
        platform=platform,
        owner_id=user.id if user.role == "analyst" else None,
    )
    return JSONResponse(
        [
            {
                "case_ref": item.case_ref,
                "title": item.title,
                "platform": item.target.platform,
                "target_url": item.target.url,
                "status": item.status,
                "category": item.violation_category,
                "confidence": item.evidence_confidence,
                "submitted_at": item.submitted_at.isoformat() if item.submitted_at else None,
                "confirmed_outcome": item.is_confirmed_outcome,
            }
            for item in rows
        ]
    )


@router.get("/notifications", response_class=HTMLResponse)
def notifications_page(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    require_action(user, "notification.view")
    return page(
        request,
        user,
        db,
        "notifications.html",
        items=notifications.for_user(db, user),
    )


@router.post("/notifications/read")
def notifications_read(
    request: Request,
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    require_action(user, "notification.view")
    check_csrf(request, csrf_token_field)
    notifications.mark_all_read(db, user.id)
    return back("/notifications", message="Notifications marked as read.")


@router.post("/notifications/run-reminders")
def notifications_run(
    request: Request,
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if user.role not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Only managers can run the reminder job.")
    check_csrf(request, csrf_token_field)
    result = run_reminder_cycle(db)
    return back(
        "/notifications",
        message=f"Reminder cycle complete: {sum(result.values())} notification(s) created.",
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    require_action(user, "settings.view")
    capabilities = [
        {
            "key": platform.key,
            "label": platform.label,
            "capability": platform.api_capability().__dict__,
        }
        for platform in registry.all()
    ]
    return page(
        request,
        user,
        db,
        "settings.html",
        configuration={
            "environment": settings.environment,
            "database": settings.database_url.split("://")[0],
            "data_dir": str(settings.data_dir),
            "max_upload_mb": settings.max_upload_mb,
            "session_max_age": settings.session_max_age,
            "smtp_configured": bool(settings.smtp_host and settings.smtp_from),
            "scheduler_enabled": settings.scheduler_enabled,
            "follow_up_days": settings.follow_up_days,
            "appeal_deadline_days": settings.appeal_deadline_days,
        },
        capabilities=capabilities,
    )


@router.post("/settings/password")
def settings_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    check_csrf(request, csrf_token_field)
    if new_password != confirm_password:
        return back("/settings", error="New passwords do not match.")
    try:
        authentication.change_password(db, user, current_password, new_password)
    except authentication.AuthError as exc:
        return back("/settings", error=str(exc))
    return back("/settings", message="Password changed.")


@router.get("/users", response_class=HTMLResponse)
def users_page(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    require_action(user, "settings.view")
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only administrators manage users.")
    return page(
        request,
        user,
        db,
        "users.html",
        users=list(db.scalars(select(User).order_by(User.id))),
    )


@router.post("/users")
def users_create(
    request: Request,
    email: str = Form(""),
    full_name: str = Form(""),
    role: str = Form("analyst"),
    password: str = Form(""),
    csrf_token_field: str = Form("", alias="csrf_token"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only administrators manage users.")
    check_csrf(request, csrf_token_field)
    try:
        created = authentication.create_user(
            db, email=email, password=password, full_name=full_name, role=role, actor=user
        )
    except authentication.AuthError as exc:
        return back("/users", error=str(exc))
    db.commit()
    return back("/users", message=f"User {created.email} created.")


@router.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
        database_ok = True
    except Exception:  # pragma: no cover - defensive
        database_ok = False
    return JSONResponse(
        {"status": "ok" if database_ok else "degraded", "database": database_ok},
        status_code=200 if database_ok else 503,
    )