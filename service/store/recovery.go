package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RecoveryCode is one unused backup code (hash only).
type RecoveryCode struct {
	ID       string
	CodeHash string // Argon2id PHC string
}

// ReplaceRecoveryCodes deletes the user's old codes and stores new hashes, in
// one transaction (all or nothing).
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		for _, h := range codeHashes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListUnusedRecoveryCodes returns the hashes the caller should compare a
// typed code against (Argon2id verification happens in the caller).
func (s *Store) ListUnusedRecoveryCodes(ctx context.Context, userID string) ([]RecoveryCode, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, code_hash FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list recovery codes: %w", err)
	}
	codes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (RecoveryCode, error) {
		var c RecoveryCode
		return c, r.Scan(&c.ID, &c.CodeHash)
	})
	if err != nil {
		return nil, fmt.Errorf("store: list recovery codes: %w", err)
	}
	return codes, nil
}

// UseRecoveryCode marks a code as used. Returns false if it was already used
// (e.g. two requests raced), so each code works exactly once.
func (s *Store) UseRecoveryCode(ctx context.Context, codeID string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE recovery_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL`, codeID)
	if err != nil {
		return false, notFound("use recovery code", err)
	}
	return tag.RowsAffected() == 1, nil
}
