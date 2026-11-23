// Package store is ZeroID's database layer (Samip — database connectors).
//
// Rules for everything in this package:
//   - Every query uses pgx placeholders ($1, $2, ...). No SQL is ever built
//     from user input, so SQL injection is not possible here (OWASP A05).
//   - The store only moves data. It never hashes, encrypts or decides policy;
//     callers pass in hashes/ciphertext and choose limits like "5 attempts".
//   - Checks that must not race (single-use tokens, TOTP replay, lockout
//     counters) are done in ONE SQL statement so two parallel requests can't
//     both succeed.
//
// The schema lives in db/migrations; see db/README.md for the column contract.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound: no matching row (or token/session invalid, expired or used).
	ErrNotFound = errors.New("store: not found")
	// ErrEmailTaken: an account with this email already exists.
	ErrEmailTaken = errors.New("store: email already registered")
)

// Store wraps a connection pool. Create one at startup and share it.
type Store struct {
	db *pgxpool.Pool
}

// New connects using a URL such as DATABASE_URL from .env. It connects as the
// least-privilege zeroid_app role, never the database owner.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{db: pool}, nil
}

// NewFromPool wraps an existing pool (useful for tests or custom config).
func NewFromPool(pool *pgxpool.Pool) *Store { return &Store{db: pool} }

// Close releases all connections.
func (s *Store) Close() { s.db.Close() }

// notFound turns pgx's "no rows" into ErrNotFound and wraps other errors.
func notFound(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("store: %s: %w", op, err)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// nullableTime converts a NULL timestamp into a nil pointer.
func ptrTime(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	return t
}
