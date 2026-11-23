package store

import (
	"context"
	"time"
)

// Session is a server-side login session. The browser cookie holds a random
// session ID; the database only holds SHA-256(ID).
type Session struct {
	ID         string
	UserID     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	MFAAt      *time.Time // last time the user passed TOTP
}

// CreateSession starts a new session (call on every successful login, which
// also gives session-ID rotation). maxAge is the absolute lifetime (1 hour).
func (s *Store) CreateSession(ctx context.Context, userID string, sessionHash []byte, maxAge time.Duration, ip, userAgent string) (Session, error) {
	var sess Session
	err := s.db.QueryRow(ctx,
		`INSERT INTO sessions (session_hash, user_id, expires_at, mfa_at, ip, user_agent)
		 VALUES ($1, $2, now() + make_interval(secs => $3), now(), NULLIF($4, '')::inet, NULLIF(left($5, 512), ''))
		 RETURNING id, user_id, created_at, last_seen_at, expires_at, mfa_at`,
		sessionHash, userID, maxAge.Seconds(), ip, userAgent).
		Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.MFAAt)
	if err != nil {
		return Session{}, notFound("create session", err)
	}
	return sess, nil
}

// ValidateSession is the check for every authenticated request. In one
// statement it finds the session, requires it to be unrevoked, before its
// absolute expiry and active within idleTimeout (10 minutes), and refreshes
// last_seen_at. Returns ErrNotFound if the session is not valid.
func (s *Store) ValidateSession(ctx context.Context, sessionHash []byte, idleTimeout time.Duration) (Session, error) {
	var sess Session
	err := s.db.QueryRow(ctx,
		`UPDATE sessions SET last_seen_at = now()
		 WHERE session_hash = $1
		   AND revoked_at IS NULL
		   AND expires_at > now()
		   AND last_seen_at > now() - make_interval(secs => $2)
		 RETURNING id, user_id, created_at, last_seen_at, expires_at, mfa_at`,
		sessionHash, idleTimeout.Seconds()).
		Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.MFAAt)
	if err != nil {
		return Session{}, notFound("validate session", err)
	}
	sess.MFAAt = ptrTime(sess.MFAAt)
	return sess, nil
}

// MarkSessionMFA records a fresh TOTP check (for "TOTP within 5 minutes"
// before sensitive actions).
func (s *Store) MarkSessionMFA(ctx context.Context, sessionID string) error {
	_, err := s.db.Exec(ctx, `UPDATE sessions SET mfa_at = now() WHERE id = $1`, sessionID)
	if err != nil {
		return notFound("mark session mfa", err)
	}
	return nil
}

// RevokeSession ends one session immediately (logout).
func (s *Store) RevokeSession(ctx context.Context, sessionHash []byte) error {
	_, err := s.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE session_hash = $1 AND revoked_at IS NULL`, sessionHash)
	if err != nil {
		return notFound("revoke session", err)
	}
	return nil
}

// RevokeAllSessions ends every session for a user (password reset, lockout,
// "sign out everywhere"). Returns how many were revoked.
func (s *Store) RevokeAllSessions(ctx context.Context, userID string) (int64, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, notFound("revoke all sessions", err)
	}
	return tag.RowsAffected(), nil
}
