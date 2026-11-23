# Security tests (Samip)

Attack scripts for the live security demos. **Only run them against your own
local ZeroID** (course rule). They need only Python 3, no installs.

| Script | Demo | OWASP | Defense it proves |
|---|---|---|---|
| `brute_force.py` | Brute-force protection | A07 | Lockout after 5 failures (`service/store/users.go` → `RecordFailedLogin`) |
| `sql_injection.py` | SQL injection | A05 | Validation + parameterized queries (`service/store/*.go`) |

## Before running

1. Start everything (Postgres/MailHog, Go service, web).
2. Create test accounts: `cd service && go run ./cmd/seed` (needs `DATABASE_URL` and `SEED_PASSWORD`).
3. If the backend uses different paths or lockout status codes, edit
   `common.py` only.

```bash
python security-tests/brute_force.py
python security-tests/sql_injection.py
```

Both print `PASS`/`FAIL` per check and exit non-zero on failure, so the output
can go straight into the report as test evidence.

`brute_force.py` locks the test account. Use `--email bob@zeroid.test` to keep
`alice` free for the main demo, or wait out the lockout.

## Database-level evidence (no running app needed)

```bash
cd service
TEST_DATABASE_URL=postgres://zeroid_app:<password>@localhost:5432/zeroid go test ./store -v
```

Covers SQL injection, lockout after 5, TOTP replay, single-use and expiring
tokens (including 10 parallel attempts), idle/revoked sessions and the
append-only audit log.

## Static analysis (Semgrep)

The proposal targets zero high/critical Semgrep findings. Semgrep runs best
in Docker (its Windows support is limited):

```bash
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan --config auto --error /src
```

Save the output for the report. Run it once the backend code is merged so the
scan covers the whole app.
