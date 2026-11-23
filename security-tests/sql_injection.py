"""SQL injection demo (OWASP A05): classic payloads against login and register.

    python security-tests/sql_injection.py

Every payload must be refused (never HTTP 200 on login) and no response may
contain a database error. Two layers stop it:
  1. Input validation rejects malformed emails before they reach the DB
     (service/validation, web/lib/validation.ts).
  2. Even if a payload got through, every query uses pgx placeholders, so the
     payload is treated as plain data (service/store; see
     TestSQLInjectionIsJustData in service/store/store_test.go).
"""
import sys

from common import DB_ERROR_MARKERS, LOGIN_PATH, REGISTER_PATH, post

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin@zeroid.test' --",
    "alice@zeroid.test'; DROP TABLE users; --",
    "x' UNION SELECT id, email, password_hash FROM users --",
    "\" OR \"\"=\"",
    "alice@zeroid.test' AND pg_sleep(5) --",
]

failures = 0


def check(label, path, payload, must_not_succeed=True):
    global failures
    status, message, raw = post(path, payload)
    leaked = [m for m in DB_ERROR_MARKERS if m in raw.lower()]
    ok = not leaked and not (must_not_succeed and status == 200)
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  HTTP {status}  {label:<52} {message[:60]}")
    if leaked:
        print(f"        database error text leaked: {leaked}")


print("Login - payload in email field")
for p in PAYLOADS:
    check(repr(p), LOGIN_PATH, {"email": p, "password": "any-password-123"})

print("\nLogin - payload in password field")
for p in PAYLOADS:
    check(repr(p), LOGIN_PATH, {"email": "alice@zeroid.test", "password": p})

print("\nRegister - payload in email field")
for p in PAYLOADS:
    check(repr(p), REGISTER_PATH, {"email": p, "password": "a-long-enough-password"})

print()
if failures:
    sys.exit(f"FAIL: {failures} check(s) failed")
print("PASS: no payload logged in and no database errors leaked")
