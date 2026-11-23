# ZeroID database (Samip)

PostgreSQL 17 schema for ZeroID. Plain SQL, no migration tool required — the
numbered files in `migrations/` run in order and work with goose /
golang-migrate later if we want one.

## Run it locally

```bash
cp .env.example .env          # then put real random passwords in .env
docker compose up -d          # starts Postgres + MailHog
docker compose exec postgres psql -U zeroid_owner -d zeroid -c '\dt'
```

The schema is applied automatically the **first** time the container starts.
To rebuild from scratch after changing a migration:

```bash
docker compose down -v && docker compose up -d
```

## Tables

| Table | Holds | How secrets are stored |
|---|---|---|
| `users` | email, password, verification, lockout counters | `password_hash` must be an Argon2id PHC string (DB rejects anything else) |
| `totp_credentials` | authenticator secret, replay counter | AES-256-GCM ciphertext + 12-byte nonce; key is **not** in the DB |
| `recovery_codes` | backup codes | Argon2id hashes, `used_at` makes them single-use |
| `one_time_tokens` | email verify, password reset, login ticket | SHA-256 of the token; `expires_at` + `used_at` = short-lived, single-use |
| `sessions` | server-side sessions | SHA-256 of the session ID; idle/absolute expiry, `revoked_at` |
| `auth_events` | audit log of every auth event | app role can only INSERT/SELECT (append-only) |

## Contract for the Go service (Saphal)

What the backend is expected to do with each column — the schema enforces
the shape, the code enforces the timing:

- **Lockout:** on a failed password, `failed_login_count += 1`; at 5 set
  `locked_until = now() + <lock period>` and log a `lockout` event. Reset to 0
  on success. Refuse logins while `locked_until > now()`.
- **TOTP replay:** accept a code only if its time step `> last_used_step`, then
  store the step.
- **Tokens:** generate 32 random bytes, email/cookie the raw value, store
  `sha256(raw)`. Look up by hash, require `used_at IS NULL AND expires_at > now()`,
  then set `used_at` in the same statement. Expiry: email verify / reset 15 min,
  login ticket 60 s.
- **Sessions:** cookie holds a random ID, DB holds `sha256(id)`. Valid only if
  `revoked_at IS NULL`, `expires_at > now()` (1 h) and
  `last_seen_at > now() - interval '10 minutes'`. Create a new row on every
  login (session ID rotation).
- **Logging:** insert an `auth_events` row for every attempt, success or
  failure. Never log passwords, codes or tokens.
- **Queries:** parameterized only (`$1, $2` with pgx). No string-built SQL.

## Database roles (least privilege)

| Role | Used by | Can do |
|---|---|---|
| `zeroid_owner` | migrations, admin | everything |
| `zeroid_app` | the Go service (`DATABASE_URL`) | read/write data, **append-only** on `auth_events`, no schema changes |

Both passwords come from `.env`; nothing is hard-coded.

## Test accounts

Demo accounts are created through the real registration flow (or a small Go
seed command once the Argon2id helper exists), so their hashes are produced by
the same code the app uses. Use fictional emails such as `alice@zeroid.test`.
