-- ZeroID database schema (Samip — database design)
--
-- Rule for this whole file: the database never stores a secret in a form an
-- attacker could use. Passwords are Argon2id hashes, TOTP secrets are
-- AES-256-GCM ciphertext (the key lives outside the DB), and every token,
-- recovery code and session ID is stored only as a hash.
-- CHECK constraints enforce this at the database level, so even buggy
-- application code cannot write a plaintext password or a raw token.
--
-- Requires PostgreSQL 13+ (gen_random_uuid() is built in).

BEGIN;

-- ---------------------------------------------------------------------------
-- users: one row per account
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email              text        NOT NULL
                                   CHECK (char_length(email) BETWEEN 3 AND 254),
    -- PHC string produced by Argon2id, e.g. "$argon2id$v=19$m=...". Anything
    -- else (plaintext, bcrypt, md5...) is rejected by the database.
    password_hash      text        NOT NULL
                                   CHECK (password_hash LIKE '$argon2id$%'),
    email_verified_at  timestamptz,
    -- Brute-force protection (lockout after 5 consecutive failures).
    failed_login_count integer     NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until       timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- Emails are unique regardless of case (Alice@x.com == alice@x.com).
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

-- ---------------------------------------------------------------------------
-- totp_credentials: the user's authenticator secret, encrypted at rest
-- ---------------------------------------------------------------------------
CREATE TABLE totp_credentials (
    user_id           uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- AES-256-GCM output (ciphertext + 16-byte auth tag) and its 12-byte nonce.
    secret_ciphertext bytea       NOT NULL CHECK (octet_length(secret_ciphertext) > 16),
    secret_nonce      bytea       NOT NULL CHECK (octet_length(secret_nonce) = 12),
    -- Which encryption key was used, so keys can be rotated later.
    key_version       smallint    NOT NULL DEFAULT 1,
    -- Replay protection: the last accepted 30-second time step. A code for
    -- this step or an earlier one must be rejected.
    last_used_step    bigint,
    -- NULL until the user proves enrollment by entering a first valid code.
    confirmed_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- recovery_codes: one-time backup codes, stored hashed
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_codes (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  text        NOT NULL CHECK (code_hash LIKE '$argon2id$%'),
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- one_time_tokens: email verification, password reset, login tickets
-- ---------------------------------------------------------------------------
-- Tokens are long random values, so a SHA-256 hash is enough (no need for a
-- slow hash). The raw token only ever exists in the email / cookie.
CREATE TABLE one_time_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    text        NOT NULL
                           CHECK (purpose IN ('email_verify', 'password_reset', 'login_ticket')),
    token_hash bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,             -- single use: set once, never cleared
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);

CREATE INDEX one_time_tokens_user_purpose_idx ON one_time_tokens (user_id, purpose);

-- ---------------------------------------------------------------------------
-- sessions: server-side sessions (the cookie only holds a random ID)
-- ---------------------------------------------------------------------------
-- We store SHA-256(session ID), so a stolen database cannot be used to
-- hijack live sessions.
CREATE TABLE sessions (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_hash bytea       NOT NULL UNIQUE CHECK (octet_length(session_hash) = 32),
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(), -- for the 10-min idle timeout
    expires_at   timestamptz NOT NULL,               -- absolute limit (1-hour re-login)
    -- When the user last passed TOTP; sensitive actions need this <= 5 min old.
    mfa_at       timestamptz,
    revoked_at   timestamptz,                        -- immediate revocation
    ip           inet,
    user_agent   text CHECK (char_length(user_agent) <= 512),
    CHECK (expires_at > created_at)
);

CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- auth_events: append-only audit log of every authentication event
-- ---------------------------------------------------------------------------
-- The app role can INSERT and SELECT here but never UPDATE or DELETE (see
-- 002_app_role.sql), so an attacker using the app's connection cannot erase
-- their tracks. Never put passwords, codes or tokens in `detail`.
CREATE TABLE auth_events (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    uuid        REFERENCES users (id) ON DELETE SET NULL,
    -- Email as typed, so failed logins for unknown accounts are still logged.
    email      text        CHECK (char_length(email) <= 254),
    event_type text        NOT NULL CHECK (event_type IN (
                               'register',
                               'email_verify',
                               'login_password',
                               'login_totp',
                               'login_recovery_code',
                               'lockout',
                               'logout',
                               'session_revoked',
                               'totp_enroll',
                               'password_reset_request',
                               'password_reset'
                           )),
    success    boolean     NOT NULL,
    ip         inet,
    user_agent text        CHECK (char_length(user_agent) <= 512),
    detail     jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_events_user_time_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX auth_events_time_idx      ON auth_events (created_at DESC);

COMMIT;
