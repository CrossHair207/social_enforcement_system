<!-- last updated: 2026-11-01 -->
# Security documentation

## Scope and data classification

SEMS holds three classes of sensitive data:

| Class | Examples | Where it lives |
|---|---|---|
| Case material | target URLs, conduct descriptions, evidence files | database + `DATA_DIR/evidence` |
| Reporter identity | reporter name, organisation, e-mail | database (e-mail encrypted) |
| Staff credentials | password hashes, sessions, audit trail | database + signed cookies |

No social media credentials, tokens or session cookies for any target account
are collected, stored or transmitted by design.

## Trust boundaries

1. **Browser ↔ application.** All input is untrusted: forms, uploads, query
   strings, headers. Protected by session auth, CSRF tokens, server-side
   validation and Jinja auto-escaping.
2. **Application ↔ filesystem.** Uploaded filenames are attacker-controlled; the
   app never uses them as a path. Files are stored under a generated UUID name
   inside `DATA_DIR/evidence/case-<id>/`, written `0600`.
3. **Application ↔ platform.** No automated calls to social platforms are made.
   Operators file reports in their own browser session. The application therefore
   cannot leak credentials to a platform, and cannot be used to mass-submit.
4. **Application ↔ operator.** Roles are enforced server-side on every route;
   the UI hides what a role cannot do, but the check does not rely on the UI.

## Controls implemented

**Authentication**

* PBKDF2-HMAC-SHA256, 210 000 iterations, 16-byte random per-user salt,
  constant-time comparison.
* Password policy (length + character class + common-password rejection) on
  creation and change; first-run admin is flagged for change when auto-generated.
* Account lockout after `LOGIN_MAX_ATTEMPTS` failures for
  `LOGIN_LOCKOUT_SECONDS`; failed attempts are audited with source IP.
* Dummy hash verification on unknown e-mails to reduce timing disclosure.
* No self-registration: accounts are created by an administrator only.

**Session management**

* Signed session cookie (`itsdangerous` via Starlette `SessionMiddleware`),
  HttpOnly, `SameSite=lax` by default, `Secure` when `COOKIE_SECURE=true`.
* Session cleared on login and logout; `Cache-Control: no-store` on authenticated
  responses.
* Session lifetime bounded by `SESSION_MAX_AGE`.

**CSRF**

* A random token per session is embedded in every form and verified on every
  state-changing POST, including login and logout. Missing or mismatched tokens
  return HTTP 400 before any state changes.

**Authorisation**

* Explicit permission matrix (`core/permissions.py`) with `viewer / analyst /
  manager / admin`; every mutating route calls `require_action(...)`.
* Analysts are additionally scoped to their own caseload.
* Confirmed enforcement outcomes, appeals and destructive operations require
  manager or admin.

**Input handling**

* All SQL goes through SQLAlchemy Core/ORM with bound parameters.
* Targets must parse against a platform's URL grammar: scheme check, host and
  subdomain allow-list (blocks lookalike domains), no URL credentials, character
  whitelist for identifiers, canonical lower-cased handle.
* Length and allow-list validation for every text and enumerated field
  (`utils/validators.py`), with typed errors surfaced as user messages.
* Jinja2 auto-escaping is on for every template; no template calls `|safe`.

**Uploads**

* Extension allow-list, `MAX_UPLOAD_MB` limit, magic-byte agreement with the
  extension, rejection of PE/ELF/Mach-O/shebang content, rejection of double
  extensions with executable suffixes, rejection of HTML containing script.
* Server-generated storage names; original names sanitised for display.
* SHA-256 recorded and re-verifiable; duplicate content per case refused.

**Cryptography**

* Reporter e-mail encrypted at rest with Fernet (AES-128-CBC + HMAC) using
  `ENCRYPTION_KEY`; only a masked form is rendered in list/detail views.
* Session signing key and encryption key come from the environment; the app
  refuses to start in production without them.

**Audit and monitoring**

* `audit_logs` records actor, action, object, detail, IP and timestamp for logins,
  failures, lockouts, case/target/evidence changes, submissions, decisions and
  exports of sensitive scope.
* Rotating application log at `DATA_DIR/logs/sems.log` (5 × 5 MB).

**Browser hardening**

* `Content-Security-Policy: default-src 'self'; img-src 'self' data:;
  style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';
  form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'`
* `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`.
* Interactive API docs/OpenAPI disabled.

**Availability**

* Upload size cap protects disk; file writes are per-case directories.
* The reminder scheduler is a single daemon thread with an idempotent cycle and
  exception isolation so a failure cannot take the web process down.

## Residual risks and operator responsibilities

1. **Evidence truthfulness.** Hashes prove a file has not changed since upload;
   they cannot prove the capture is authentic. Manual review is mandatory and is
   recorded on the case.
2. **Phishing of staff.** A compromised operator account could file a bad report.
   Mitigations: least privilege, audit trail, manager approval before any
   platform-response outcome, and a strong password policy. Add SSO in front of
   the app if your environment requires it.
3. **Policy drift.** Platform policy URLs and reporting flows change. Confirm the
   current wording before submitting; the UI links to the current pages rather
   than copying text.
4. **Email delivery.** If SMTP is unconfigured, reminders stay in-app; the stored
   `delivery_status` reflects that rather than pretending an e-mail was sent.
5. **Local SQLite.** Fine for a single-team deployment. Use PostgreSQL and a
   proper backup regime for multi-user or regulated use.
6. **No database-level row security.** Object scoping is enforced in the service
   layer. If you expose the database to other applications, add row-level
   security or separate credentials.

## Hardening checklist for deployment

- [ ] `APP_ENV=production`, strong `SECRET_KEY` and `ENCRYPTION_KEY`, both backed up
- [ ] HTTPS termination with `COOKIE_SECURE=true`
- [ ] `ADMIN_PASSWORD` set before first start; rotate after hand-over
- [ ] One account per person, correct role, no shared logins
- [ ] Dashboard reachable only from your network / VPN
- [ ] `DATA_DIR` on an encrypted volume with restrictive filesystem permissions
- [ ] Database and evidence backups tested by restoring into a staging instance
- [ ] Log shipping and a periodic review of `audit_logs`
- [ ] Dependency updates reviewed monthly (`pip list --outdated`)

## Data retention

Define a retention period for closed cases (for example 24 months), then delete
the case and its evidence together; `POST /cases/{id}/delete` removes both. Keep
`audit_logs` longer if your policy requires an immutable trail, and export case
packages you must retain before deletion.

## Reporting a security issue

Security issues in this application should be reported privately to the team that
operates the deployment, with reproduction steps and the affected version shown in
the dashboard footer. Do not open a public issue containing live case data.