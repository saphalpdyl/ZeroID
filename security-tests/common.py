"""Shared settings for the ZeroID attack scripts (Samip).

Only run these against your OWN local ZeroID (course rule). Standard library
only - no installs needed.

FOR SAPHAL: if the backend's API differs from the README contract, adjust the
values in this file only.
"""
import json
import os
import urllib.error
import urllib.request

# Through the Next.js proxy (same path a browser uses). The proxy requires a
# same-origin Origin header, which we send below.
BASE_URL = os.environ.get("ZEROID_URL", "http://localhost:3000")

LOGIN_PATH = "/api/login"
REGISTER_PATH = "/api/register"

# HTTP statuses that mean "you are locked out / rate limited".
# Agree these with the backend (423 Locked and 429 Too Many Requests are usual).
LOCKOUT_STATUSES = {423, 429}

# Text that must NEVER appear in a response: it would mean a raw database
# error leaked to the user (information disclosure, OWASP A10/A05).
DB_ERROR_MARKERS = ["syntax error", "sqlstate", "pgx", "pq:", "postgres", "relation \"", "column \""]


def post(path, payload):
    """POST JSON, return (status, message, raw_text). Never raises on HTTP errors."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE_URL + path,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Origin": BASE_URL, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, text = resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors="replace")
    except urllib.error.URLError as e:
        raise SystemExit(f"Cannot reach {BASE_URL} ({e.reason}). Is ZeroID running?")
    try:
        message = json.loads(text).get("message", "")
    except (ValueError, AttributeError):
        message = text[:120]
    return status, message, text
