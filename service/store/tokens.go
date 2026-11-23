package store

import (
	"context"
	"time"
)

// TokenPurpose matches the CHECK constraint on one_time_tokens.purpose.
type TokenPurpose string

const (
	PurposeEmailVerify   TokenPurpose = "email_verify"   // proposal: 15 min
	PurposePasswordReset TokenPurpose = "password_reset" // proposal: 15 min
	PurposeLoginTicket   TokenPurpose = "login_ticket"   // proposal: 60 s
)

// CreateToken stores the SHA-256 hash of a freshly generated random token.
// The raw token goes only in the email or cookie, never in the database.
func (s *Store) CreateToken(ctx context.Context, userID string, purpose TokenPurpose, tokenHash []byte, ttl time.Duration) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO one_time_tokens (user_id, purpose, token_hash, expires_at)
		 VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
		userID, string(purpose), tokenHash, ttl.Seconds())
	if err != nil {
		return notFound("create token", err)
	}
	return nil
}

// ConsumeToken checks and burns a token in ONE statement: it must exist, have
// the right purpose, be unexpired and unused. Returns the owner's user id, or
// ErrNotFound for any invalid token (the caller should not reveal which rule
// failed). A token can never be consumed twice, even by parallel requests.
func (s *Store) ConsumeToken(ctx context.Context, purpose TokenPurpose, tokenHash []byte) (string, error) {
	var userID string
	err := s.db.QueryRow(ctx,
		`UPDATE one_time_tokens SET used_at = now()
		 WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
		 RETURNING user_id`,
		tokenHash, string(purpose)).Scan(&userID)
	if err != nil {
		return "", notFound("consume token", err)
	}
	return userID, nil
}

// DeleteExpiredTokens removes old tokens (optional housekeeping).
func (s *Store) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM one_time_tokens WHERE expires_at < now() - interval '1 day'`)
	if err != nil {
		return 0, notFound("delete expired tokens", err)
	}
	return tag.RowsAffected(), nil
}
