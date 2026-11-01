# Social Enforcement Management System (SEMS)

A self-hosted Python application for running **legitimate, evidence-based
enforcement cases** against social media accounts and Pages that violate
platform policy: Facebook personal accounts, Facebook Pages, Instagram accounts
and TikTok accounts.

SEMS is a case-management system, not a report cannon. It helps an authorised
team record what was observed, attach tamper-evident evidence, cite the exact
policy, generate a professional request package, file the report through the
platform's **official** channel, and record what the platform actually decided.

## What this system deliberately does not do

* No fake or coordinated mass reporting, and no bulk submission feature.
* No CAPTCHA bypass, rate-limit circumvention, scraping behind login, or any
  unauthorised access to a target account.
* No storage of passwords, tokens or sessions belonging to any third-party
  social media account.
* No invented facts: documents render "not recorded" rather than guessing, and
  a removal is only counted as confirmed when the platform's own reference is
  stored against the case.
* No claim of automation that the platforms do not offer. None of the four
  platforms publishes an API for submitting account/Page takedowns or reading
  enforcement decisions; each module says so explicitly and drives the operator
  through the documented manual flow instead.

## Features

| Area | What you get |
|---|---|
| Targets | URL validation and platform detection, canonical handles, duplicate detection, CSV/JSON import, CSV export |
| Cases | Year-based case references, priorities, categories, requested action, per-case evidence, notes, status history |
| Analysis | Evidence-weighted support score, missing-evidence checklist, policy mapping, recommended channel — never an automatic "guilty" verdict |
| Evidence | SHA-256 hashing, duplicate detection, magic-byte validation, integrity re-checks, ZIP evidence packages |
| Submission | Preparation checklist with hard blockers, official channel instructions, submission reference tracking, platform-response recording |
| Appeals | Drafting, submission reference, deadline tracking, outcome recording |
| Documents | PDF, DOCX, TXT and JSON enforcement packages |
| Dashboard | Overview, cases, targets, analytics, notifications, settings, user management; light/dark theme |
| Notifications | In-app notifications from real events, plus scheduled follow-up, appeal-deadline and stalled-case reminders; optional SMTP e-mail |
| Security | PBKDF2 password hashing, session cookies, CSRF tokens on every state change, RBAC, encrypted reporter contact, audit log |

## Architecture

```
Browser (server-rendered Jinja2 + progressive CSS)
        │  HTTPS
        ▼
FastAPI application (app.py)
  ├─ SessionMiddleware  ── signed, HttpOnly session cookie
  ├─ security headers   ── CSP, nosniff, frame-deny, no-store
  └─ dashboard/routes.py ── pages + small JSON API
        │
        ├── core/          auth, RBAC, crypto, DB sessions, reminder scheduler
        ├── platforms/     one module per platform (URL grammar + policy + channel)
        ├── enforcement/   policy matching, analysis, status machine, submissions, appeals
        ├── evidence/      validation, hashing, storage, integrity, ZIP packaging
        ├── documents/     canonical case model → PDF / DOCX / TXT / JSON
        └── dashboard/     routes, analytics, notifications, templates, static
        │
        ▼
SQLAlchemy 2.x  ──►  SQLite (default)  |  PostgreSQL (production)
Filesystem      ──►  DATA_DIR/evidence/<case>/…  (0600, hashed)
```

### Project layout

```
social_enforcement_system/
├── app.py                     # FastAPI factory, lifespan, security headers, admin bootstrap
├── config.py                  # layered configuration (.env → env → defaults)
├── requirements.txt
├── start.bat / start.sh       # one-command launch (Windows / POSIX)
├── .env.example
├── core/
│   ├── authentication.py      # login, lockout, password change, audit helper
│   ├── security.py            # PBKDF2, CSRF, field encryption, filename safety
│   ├── database.py            # engine/session management, init_db
│   ├── permissions.py         # role → permission matrix
│   └── scheduler.py           # in-process reminder thread
├── platforms/
│   ├── base_platform.py       # abstraction, URL grammar, policy/channel types, registry
│   ├── facebook_personal.py
│   ├── facebook_pages.py
│   ├── instagram.py
│   └── tiktok.py
├── enforcement/
│   ├── case_manager.py        # targets, cases, search, import
│   ├── violation_analyzer.py  # evidence-weighted support scoring
│   ├── policy_matcher.py      # category → policy references + channel
│   ├── submission_manager.py  # readiness checks, submission + platform response records
│   ├── status_tracker.py      # state machine with corroboration rules
│   └── appeal_manager.py
├── evidence/
│   ├── evidence_manager.py    # storage, integrity, inventory
│   ├── file_validator.py      # allow-list, size, magic bytes, script rejection
│   ├── hash_manager.py        # SHA-256 helpers
│   └── evidence_exporter.py   # ZIP package + manifest verification
├── documents/
│   ├── report_generator.py    # canonical case package (single source of truth)
│   ├── pdf_generator.py       # ReportLab
│   └── docx_generator.py      # python-docx
├── dashboard/
│   ├── routes.py              # all HTTP routes
│   ├── analytics.py           # aggregates; confirmed vs unverified outcomes
│   ├── notifications.py       # in-app + optional SMTP delivery with honest status
│   ├── templates/             # base, login, dashboard, targets, cases, case detail, …
│   └── static/style.css
├── database/
│   ├── models.py              # ORM models + status/category constants
│   └── migrations/            # schema notes + PostgreSQL initialiser
├── utils/                     # validators, logging, CSV/JSON exporters
├── examples/                  # importable target lists
└── tests/                     # 69 pytest tests (unit + integration)
```

### Data model

`User` owns `EnforcementCase`; a case refers to exactly one `Target` (platform,
canonical URL, public identifier). Each case owns its `Evidence`, `StatusEvent`,
`CaseNote`, `Submission` and `Appeal` rows, so evidence can never leak between
cases. `Notification`, `EvidenceEvent` and `AuditLog` record what happened and
who did it. Timestamps are stored as timezone-aware UTC on every backend.

### Case lifecycle

Internal stages (operator-driven, checked against case contents):

```
new_case → under_investigation → evidence_required → evidence_verified
        → ready_for_submission → submitted_to_platform
```

Platform stages (require a quoted platform response **and** a reference;
confirmed removals additionally require a recorded submission):

```
under_platform_review → additional_info_requested → temporarily_restricted
                      → permanently_disabled | page_removed | content_removed
                      → rejected  → appealed → …
```

`ready_for_submission` refuses to advance unless evidence exists, the analysis
has produced at least "low" support, and manual review is confirmed.
`permanently_disabled`, `page_removed` and `content_removed` are the only
statuses counted as confirmed outcomes in analytics, and only when
`decision_source == platform_confirmation`.

### Platform integration reality

| Platform | Takedown submission API | Status API | Route used |
|---|---|---|---|
| Facebook personal account | none | none | in-app report flow (`facebook.com/help/reportlinks`) |
| Facebook Page | none | none | "Report Page" flow |
| Instagram | none (Graph API is for accounts you own) | none | "Report → Something about this account" |
| TikTok | none (Display/Posting APIs are for your own content) | none | in-app report + IP forms |

Rights-holder IP programmes (copyright/trademark) are contract-gated and out of
scope for automation; the modules link to the official forms and mark the case
as `manual`. `platform.api_capability()` is the single source of truth and is
shown in Settings so operators can see what is and is not automated.

### Evidence integrity

* Extension allow-list + size limit + magic-byte agreement; executables,
  shebang scripts, double extensions, and HTML containing script are rejected.
* SHA-256 recorded at upload; re-checking recomputes the digest from disk and
  writes an `evidence_events` row (`verified` / `MISMATCH`).
* Identical files are refused per case (duplicate detection) unless the operator
  explicitly allows it.
* Exported ZIPs carry `manifest.json`, `inventory.csv` and a README explaining
  how to verify each hash; `verify_package()` re-hashes every file.

### Documents

`documents/report_generator.py` builds one `CasePackage` used by all exporters,
so PDF/DOCX/TXT/JSON cannot drift apart. It contains: case reference, platform,
target URL and handle, category, cited policies, the operator's factual
description, evidence inventory with hashes, timeline, submissions, assessment,
requested action, reporter contact (optional) and an explicit disclaimer that
the document does not assert a violation — the platform decides.

## Quick start (Linux / macOS)

```bash
cd social_enforcement_system
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # optional for a local trial
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. On first start the application creates the data
directories, the schema, and one administrator. If `ADMIN_PASSWORD` is unset, a
random password is printed **once** to the console and the account is flagged to
change it.

Or simply run `./start.sh` (POSIX) / `start.bat` (Windows), which does the same
steps and opens the browser.

## Windows installation

1. **Install Python 3.10 or newer** from python.org. On the first installer
   screen tick *Add python.exe to PATH*, then choose *Install Now*.
2. Verify in PowerShell: `python --version`.
3. **Copy the project** to a folder you can write to, for example
   `C:\sems`, and open a terminal there.
4. **Create the virtual environment**:

   ```bat
   python -m venv .venv
   .venv\Scripts\activate
   ```

5. **Install dependencies**:

   ```bat
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

6. **Configure**: `copy .env.example .env`, then edit `.env` and set at least

   ```
   SECRET_KEY=<48+ random characters>
   ENCRYPTION_KEY=<Fernet key>
   ADMIN_EMAIL=you@yourdomain.example
   ADMIN_PASSWORD=<a strong password>
   ```

   Generate both values with:

   ```bat
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

7. **Initialise and start** (the schema is created automatically on first run):

   ```bat
   python -m uvicorn app:app --host 127.0.0.1 --port 8000
   ```

8. **Open the dashboard**: http://127.0.0.1:8000 and sign in with
   `ADMIN_EMAIL` / `ADMIN_PASSWORD`.
9. Afterwards, just double-click `start.bat`.

### Windows troubleshooting

| Symptom | Cause and fix |
|---|---|
| `python` opens the Microsoft Store | Python is not installed with PATH; reinstall and tick "Add python.exe to PATH", or use `py -3` |
| `'uvicorn' is not recognized` | The virtual environment is not active: run `.venv\Scripts\activate` first |
| `Activate.ps1 cannot be loaded ... execution policies` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that PowerShell window |
| `[Errno 10048] address already in use` | Port 8000 is taken: start with `--port 8010` |
| Browser shows "connection refused" | The server console was closed; the app runs only while it is open |
| `SECRET_KEY must be set when APP_ENV=production` | Set `SECRET_KEY` in `.env` or leave `APP_ENV=development` for local use |
| Evidence upload rejected | Check `ALLOWED_EXTENSIONS` and `MAX_UPLOAD_MB`; PNG/JPG/PDF/MP4 are enabled by default |
| Time shows in the wrong zone | Times are stored and displayed in UTC by design |

## Configuration

All settings come from `.env` or the environment (environment wins).

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `production` requires explicit secrets |
| `SECRET_KEY` | random (dev) | Session signing; must be stable in production |
| `ENCRYPTION_KEY` | derived from `SECRET_KEY` (dev) | Fernet key for reporter contact |
| `DATABASE_URL` | `sqlite:///./data/sems.db` | SQLAlchemy URL; PostgreSQL supported |
| `DATA_DIR` | `./data` | Evidence, exports and logs |
| `MAX_UPLOAD_MB` | `25` | Per-file upload limit |
| `ALLOWED_EXTENSIONS` | images, PDF, video, audio, txt/json/eml/html | Evidence allow-list |
| `SESSION_MAX_AGE` | `28800` | Session lifetime in seconds |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `COOKIE_SAMESITE` | `lax` | Cookie SameSite policy |
| `PASSWORD_MIN_LENGTH` | `12` | Minimum password length |
| `LOGIN_MAX_ATTEMPTS` | `8` | Failures before lockout |
| `LOGIN_LOCKOUT_SECONDS` | `900` | Lockout duration |
| `FOLLOW_UP_DAYS` | `14` | Follow-up reminder offset after submission |
| `APPEAL_DEADLINE_DAYS` | `30` | Appeal window tracked per decision |
| `SCHEDULER_ENABLED` | `true` | In-process reminder thread |
| `SCHEDULER_INTERVAL_SECONDS` | `900` | Reminder cycle interval |
| `SMTP_*` | empty | Optional outbound e-mail; blank keeps notifications in-app |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | empty | First-run administrator |

## Roles

| Capability | Viewer | Analyst | Manager | Admin |
|---|---|---|---|---|
| View dashboard, targets, cases, analytics | ✓ | ✓ | ✓ | ✓ |
| Create targets and cases, upload evidence, record submissions | | ✓ | ✓ | ✓ |
| Run analysis, export documents | | ✓ | ✓ | ✓ |
| Record platform responses, appeals, move cases to decisions | | | ✓ | ✓ |
| Delete cases/evidence, open settings | | | ✓ | ✓ |
| Manage users | | | | ✓ |

Analysts see their own caseload; managers and administrators see every case.

## Operating a case

1. **Add the target** from *Target accounts* (URL is validated and normalised).
2. **Open a case**, choose the category, and write only observable conduct.
3. **Upload evidence** — screenshots, recordings, documents, or record the
   public profile/post URLs.
4. **Run the analysis** to see the support level and the missing-evidence list.
5. **Close the gaps**, then **confirm manual review** with a reviewer note.
6. Move the case to **Ready for submission** (blocked until the above is done).
7. Use the official link and the generated package to **file the report**, then
   **record the submission** with the reference the platform returned.
8. When the platform answers, **record the platform response** (manager only).
   Only that path can produce a confirmed outcome.
9. Export the PDF/DOCX package and the evidence ZIP for your own records.

## HTTP surface

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/login`, `/logout` | Authentication |
| GET | `/dashboard` | Overview |
| GET/POST | `/targets`, `/targets/import`, `/targets/export.csv` | Target management |
| GET/POST | `/cases`, `/cases/new`, `/cases/{id}` | Case management |
| POST | `/cases/{id}/update`, `/analyze`, `/review`, `/status`, `/notes` | Case work |
| POST | `/cases/{id}/evidence`, `/evidence-link` | Evidence capture |
| POST | `/evidence/{id}/verify`, `/delete`; GET `/evidence/{id}/download` | Integrity |
| POST | `/cases/{id}/submit`, `/platform-response`, `/appeal` | Submission & appeals |
| GET | `/cases/{id}/export/{txt,json,pdf,docx,zip}` | Documents |
| GET | `/analytics`, `/notifications`, `/settings`, `/users` | Admin views |
| GET | `/api/stats`, `/api/cases` | JSON API (session authenticated) |
| GET | `/healthz` | Liveness + database check |

Interactive API docs are disabled deliberately; the JSON endpoints above are the
supported machine interface.

## Tests

```bash
python -m pytest tests -q
```

69 tests cover: schema and cascades, target normalisation, platform URL grammar
and policy catalogues, evidence validation/integrity/packaging, analysis
scoring, the status machine's corroboration rules, submission and appeal rules,
authentication, lockout, CSRF, RBAC, document generation ("never invent facts"),
and a full HTTP case lifecycle including all five export formats.

## Production deployment

1. `APP_ENV=production`, `SECRET_KEY` and `ENCRYPTION_KEY` set and backed up
   (losing `ENCRYPTION_KEY` makes stored reporter contacts unreadable).
2. PostgreSQL (`DATABASE_URL=postgresql+psycopg://…`) initialised with
   `python database/migrations/init_postgres.py`.
3. Terminate TLS at a reverse proxy (nginx/Caddy) and set `COOKIE_SECURE=true`.
   Bind uvicorn to `127.0.0.1` behind that proxy.
4. Multiple uvicorn workers are safe (no in-process shared state except the
   reminder thread; run the reminder cycle from one process only, or leave
   `SCHEDULER_ENABLED=true` on a single worker).
5. Back up `DATABASE_URL` **and** `DATA_DIR/evidence` together; test a restore.
6. Ship logs (`DATA_DIR/logs/sems.log`, rotated) to your SIEM and review
   `audit_logs` periodically.
7. Restrict network access to the dashboard; it is an internal case-management
   tool, not a public site.

## Limitations

* Enforcement decisions are made by the platforms; SEMS can only record them.
* Policy URLs and report flows change; the Settings page and the policy panel
  remind operators to confirm current wording before submission.
* Vanity Facebook URLs cannot be classified as profile vs Page from the URL
  alone; the Page module flags this and the operator confirms.
* No public API exists for any of the four platforms' account takedowns, so the
  submission step is always a human action with a recorded reference.
* Evidence authenticity is a human judgement; hashes prove integrity, not truth.

## Adding a platform

1. Create `platforms/newplatform.py` subclassing `BasePlatform` and implement
   `extract()`, `build_url()`, `policies()`, `channels()` and `api_capability()`.
2. Register it in `platforms/__init__.py`.
3. Nothing else changes: routes, analysis, documents, evidence and analytics all
   iterate the registry.
4. Add parsing tests to `tests/test_platforms.py`.

## Licence and use

Operate this system only for accounts and Pages you are legitimately reporting
and only through the platforms' official channels. Misuse (fake reports,
coordinated mass reporting, harassment) violates platform terms and may be
unlawful; the application is built to make that misuse visible and hard.
