package store

import (
	"context"
	"time"
)

// TOTPCredential holds a user's encrypted authenticator secret. The store
// never sees the plaintext secret or the AES key.
type TOTPCredential struct {
	UserID           string
	SecretCiphertext []byte // AES-256-GCM output (ciphertext + tag)
	SecretNonce      []byte // 12-byte GCM nonce
	KeyVersion       int16
	LastUsedStep     *int64
	ConfirmedAt      *time.Time
}

// SaveTOTP stores (or replaces) a user's encrypted TOTP secret. A replaced
// secret starts unconfirmed with no used steps.
func (s *Store) SaveTOTP(ctx context.Context, userID string, ciphertext, nonce []byte, keyVersion int16) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO totp_credentials (user_id, secret_ciphertext, secret_nonce, key_version)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (user_id) DO UPDATE SET
		     secret_ciphertext = EXCLUDED.secret_ciphertext,
		     secret_nonce      = EXCLUDED.secret_nonce,
		     key_version       = EXCLUDED.key_version,
		     last_used_step    = NULL,
		     confirmed_at      = NULL,
		     created_at        = now()`,
		userID, ciphertext, nonce, keyVersion)
	if err != nil {
		return notFound("save totp", err)
	}
	return nil
}

// GetTOTP returns the user's encrypted secret, or ErrNotFound if not enrolled.
func (s *Store) GetTOTP(ctx context.Context, userID string) (TOTPCredential, error) {
	var c TOTPCredential
	err := s.db.QueryRow(ctx,
		`SELECT user_id, secret_ciphertext, secret_nonce, key_version, last_used_step, confirmed_at
		 FROM totp_credentials WHERE user_id = $1`, userID).
		Scan(&c.UserID, &c.SecretCiphertext, &c.SecretNonce, &c.KeyVersion, &c.LastUsedStep, &c.ConfirmedAt)
	if err != nil {
		return TOTPCredential{}, notFound("get totp", err)
	}
	c.ConfirmedAt = ptrTime(c.ConfirmedAt)
	return c, nil
}

// UseTOTPStep is the replay protection. After the caller has checked that a
// code is mathematically valid for time step `step`, call this: it returns
// true only if that step is newer than every step used before, and records
// it in the same statement. A replayed (or older) code returns false.
//
// It also confirms enrollment the first time a code is accepted.
func (s *Store) UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE totp_credentials
		 SET last_used_step = $2, confirmed_at = coalesce(confirmed_at, now())
		 WHERE user_id = $1 AND (last_used_step IS NULL OR last_used_step < $2)`,
		userID, step)
	if err != nil {
		return false, notFound("use totp step", err)
	}
	return tag.RowsAffected() == 1, nil
}
