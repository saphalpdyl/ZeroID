# ZeroID — Aadarsha Tiwari's Module

**CSC 327 • ZeroT • Forms, input validation, CSP, SMTP**

This starter module implements Aadarsha's responsibilities described in the proposal and slide 11. **The authentication core, persistence, TOTP verification, token issuance, lockout, and sessions must be connected to Saphal/Samip's Go backend.** No fabricated authentication or fake successful login is included.

## Features
- Registration, password login, TOTP code entry, and email verification pages
- Shared field validation (browser UX and a Go server-side validation package)
- Strong per-request nonce-based Content Security Policy through Next.js middleware
- A same-origin API bridge with an exact allowlist and Origin checks
- Go SMTP email sender with local MailHog support; production TLS is required
- Go tests for input validation

## Start the forms
Start the database and MailHog first (needs Docker; see [db/README.md](db/README.md)):
```bash
cp .env.example .env    # then set real random passwords
docker compose up -d
```
Then the web app:
```bash
cd web
cp .env.example .env.local
npm install
npm run dev
```
Visit http://localhost:3000/register, /login, /totp, /verify-email, /portal.

`ZEROID_API_URL` points at the Go identity service. Without that running, the forms show a meaningful connection error and do **not** pretend registration/login succeeded.

## Connect to teammates' API
The frontend's server-side API bridge expects:

| POST endpoint | JSON request | Expected successful response |
|---|---|---|
| `/api/register` | `{email,password}` | 200/201; user instructed to verify email |
| `/api/login` | `{email,password}` | 200; proceed to TOTP (backend can issue short-lived login ticket via secure cookie) |
| `/api/totp/verify` | `{code}` | 200; backend sets authenticated session cookie |
| `/api/email/verify` | `{token}` | 200; verification complete |
| `/api/email/resend` | `{email}` | 200; generic confirmation |
| `/api/logout` | `{}` | 200; backend revokes the server-side session and clears the cookie |

The portal also calls one **GET** endpoint server-side (not through the proxy), forwarding the browser's cookie:

| GET endpoint | Expected response |
|---|---|
| `/api/me` | 200 with the JSON below, or 401 if there is no valid session |

```json
{
  "email": "alice@zeroid.test",
  "emailVerified": true,
  "session": { "startedAt": "2026-11-22T18:44:00Z", "expiresAt": "2026-11-22T19:44:00Z" },
  "recentEvents": [ { "type": "login_totp", "success": true, "ip": "127.0.0.1", "at": "2026-11-22T18:44:00Z" } ]
}
```
`type` values match `auth_events.event_type` in `db/migrations/001_init.sql`. If the shape changes, update `web/lib/session.ts` only.

**These are suggested integration contracts, not claimed existing endpoints.** Agree on names and fields with the Go backend owner; update `web/app/api/[...path]/route.ts` and the form components if necessary. Never return TOTP secrets, password hashes, session tokens or verification tokens to the page. The proxy forwards backend Set-Cookie headers for the same origin; ensure cookie attributes/domain and CSRF mechanisms match deployment. Never allow users to select a proxy target.

## Run Go tests
```bash
cd service
go test ./...
```
Database tests in `service/store` are skipped unless `TEST_DATABASE_URL` points at a Postgres with the migrations applied (see [security-tests/README.md](security-tests/README.md)).

## Database & client portal (Samip)
| Piece | Where | Notes |
|---|---|---|
| Schema + least-privilege role | `db/migrations/` | Applied automatically by `docker compose up`. Table/column contract in [db/README.md](db/README.md). |
| Database layer (pgx) | `service/store/` | One function per operation, parameterized queries only. Create one `store.New(ctx, os.Getenv("DATABASE_URL"))` at startup and call it from the handlers. |
| Client portal | `web/app/portal/`, `web/lib/session.ts` | Server-rendered; redirects to `/login` unless `GET /api/me` confirms the session. |
| Test accounts | `service/cmd/seed/` | `go run ./cmd/seed` with `DATABASE_URL` and `SEED_PASSWORD` creates fictional `alice`/`bob`/`carol@zeroid.test`. |
| Attack scripts | `security-tests/` | Brute-force and SQL-injection demos; settings in `common.py`. |

**Integration notes for the core service (Saphal):**
- Login: on a wrong password call `store.RecordFailedLogin(ctx, id, 5, lockFor)`; on success `ResetFailedLogins`. Refuse while `user.IsLocked(now)`.
- TOTP: after checking a code is valid for time step `s`, call `UseTOTPStep(ctx, id, s)`; `false` means a replayed code.
- Tokens / sessions: store only `sha256(raw)`; use `CreateToken`/`ConsumeToken` and `CreateSession`/`ValidateSession`/`RevokeSession`.
- Log every attempt with `LogEvent` (never passwords, codes or tokens).
- If you have your own Argon2id helper, swap it into `hashPassword` in `service/cmd/seed/main.go`.
- The Go module is still named `zeroid/aadarsha` (from the first commit); rename it in `go.mod` and the imports if you restructure.

## MailHog development SMTP
MailHog listens on `localhost:1025` for SMTP and exposes mail at `http://localhost:8025` when installed and running. Sample configuration is in `service/.env.example`. Configure MailHog externally or via Docker:
```bash
docker run --rm -p 1025:1025 -p 8025:8025 mailhog/mailhog
```
MailHog catches messages for testing; it does not deliver real email. Use `smtp.NewSenderFromEnv()` from the Go identity backend and `SendVerification()` / `SendPasswordReset()` after the backend creates single-use hashed-at-rest tokens. Keep token creation and verification inside the core service.

## CSP and validation boundaries
CSP uses a fresh nonce for each incoming web request (pages are rendered per request via `dynamic = 'force-dynamic'` in `web/app/layout.tsx`, otherwise pre-rendered pages would have no nonce and the browser would block their scripts; `'unsafe-eval'` is added only in `npm run dev`); styles and scripts are limited to the application's origin and nonce, with additional restrictions. Test under deployment: third-party analytics/fonts or Next.js dev tooling may need tightly scoped exceptions. A CSP protects browsers; it does **not** replace output escaping or server-side validation. The Go validator package provides a simple reusable baseline, but integrate validation at **every backend entry point**.

## Security acceptance checklist
- Registration rejects malformed emails and bad passwords on the server.
- Email verification uses a short-lived, single-use, hashed-at-rest token (proposal: 15 minutes).
- TOTP is checked by the backend with replay protection; 5 failures trigger temporary lockout.
- Authenticated cookies are HttpOnly, Secure in HTTPS, and SameSite; rotate ID on login.
- Origin/CSRF protection is enforced by the backend, not only the web proxy.
- Credentials and tokens never appear in application logs.
- OWASP ZAP and Semgrep must be run on the integrated app; **zero findings is a target, not a verified result**.

## Ownership and scope
**Aadarsha:** UI forms, validation, CSP, SMTP integration. **Saphal:** Go identity core/cryptography, login and TOTP verification, token security. **Samip:** database and portal. Proposed APIs may be adapted to teammates' concrete implementations.
