# Aadarsha — Integration handoff

## What I implemented
- Four interactive identity forms (register, login, TOTP, verify email)
- Browser-side validation and Go-side reusable validation functions
- Nonce-based Content Security Policy and additional browser security headers
- Go SMTP sender for verification/reset emails (MailHog development mode)
- Same-origin POST bridge with endpoint allowlist, Origin check, body size limit, cookie forwarding

## Teammates need to provide
1. Saphal: five Go POST handlers with agreed JSON request/response contracts (see README), replay-protected TOTP, session handling, single-use token verification, lockouts, and CSRF checks.
2. Samip: persistence for account verification, encrypted 2FA secret, hashed verification tokens, sessions; deployment and portal redirect.
3. Saphal/Samip: generation and secure storage of registration verification/reset tokens before calling the SMTP helper.

## Acceptance/demo sequence
1. Register an account with a 12+ character password; show bad email and short password errors.
2. Check MailHog at http://localhost:8025 for a verification email.
3. Verify a token (15-minute, single-use rule enforced by backend).
4. Login with password; show a separate TOTP step; attempt a wrong code.
5. Show CSP header in browser developer tools > Network > Response Headers.
6. Show CSRF and rate-limit/lockout behavior from integrated backend.
7. Run `go test ./...`, then integrated Semgrep and OWASP ZAP scans.

## Important limitation
The sample is a client and helper library, **not** a complete IdP. It cannot securely authenticate users by itself and should not be presented as a completed, tested full ZeroID implementation.
