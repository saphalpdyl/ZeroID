-- Least-privilege permissions for the application's database role.
--
-- The Go service connects as `zeroid_app`, never as the database owner. It
-- can read and write data, but it cannot change the schema, and it can only
-- append to the audit log. The role itself (and its password, from the
-- environment) is created by db/docker-init.sh before this file runs.

BEGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO zeroid_app;

GRANT SELECT, INSERT, UPDATE, DELETE
    ON users, totp_credentials, recovery_codes, one_time_tokens, sessions
    TO zeroid_app;

-- Audit log is append-only for the app.
GRANT SELECT, INSERT ON auth_events TO zeroid_app;

COMMIT;
