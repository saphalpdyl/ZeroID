"""Brute-force demo: lockout after 5 failed logins (OWASP A07).

    python security-tests/brute_force.py
    python security-tests/brute_force.py --email bob@zeroid.test --attempts 8

Sends wrong passwords to the login endpoint and shows the account getting
locked. If SEED_PASSWORD is set, it then tries the CORRECT password to show
that it is refused too while the account is locked.

Note: this locks the test account for the lockout period. Use a seeded,
fictional account (see service/cmd/seed).
"""
import argparse
import os
import sys

from common import LOCKOUT_STATUSES, LOGIN_PATH, post

parser = argparse.ArgumentParser()
parser.add_argument("--email", default="alice@zeroid.test")
parser.add_argument("--attempts", type=int, default=7)
args = parser.parse_args()

print(f"Brute-forcing {args.email} with {args.attempts} wrong passwords\n")
locked_at = None
for i in range(1, args.attempts + 1):
    status, message, _ = post(LOGIN_PATH, {"email": args.email, "password": f"wrong-guess-{i:04d}"})
    locked = status in LOCKOUT_STATUSES
    if locked and locked_at is None:
        locked_at = i
    print(f"  attempt {i}: HTTP {status}  {'LOCKED ' if locked else ''}{message}")
    if status == 200:
        sys.exit("FAIL: a wrong password was accepted!")

correct = os.environ.get("SEED_PASSWORD")
if correct and locked_at:
    status, message, _ = post(LOGIN_PATH, {"email": args.email, "password": correct})
    print(f"\n  correct password while locked: HTTP {status}  {message}")
    if status == 200:
        sys.exit("FAIL: correct password was accepted during lockout")

print()
if locked_at is None:
    sys.exit(f"FAIL: no lockout after {args.attempts} attempts (expected status in {sorted(LOCKOUT_STATUSES)})")
if locked_at > 6:
    sys.exit(f"FAIL: lockout only started at attempt {locked_at} (expected after 5 failures)")
print(f"PASS: account locked at attempt {locked_at} (after {locked_at - 1} failures)")
