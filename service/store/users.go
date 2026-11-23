package store

import (
	"context"
	"time"
)

// User is one row of the users table.
type User struct {
	ID               string
	Email            string
	PasswordHash     string // Argon2id PHC string; the DB rejects anything else
	EmailVerifiedAt  *time.Time
	FailedLoginCount int
	LockedUntil      *time.Time
	CreatedAt        time.Time
}

// IsLocked reports whether the account is in a temporary lockout right now.
func (u User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

const userColumns = `id, email, password_hash, email_verified_at, failed_login_count, locked_until, created_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerifiedAt, &u.FailedLoginCount, &u.LockedUntil, &u.CreatedAt)
	u.EmailVerifiedAt, u.LockedUntil = ptrTime(u.EmailVerifiedAt), ptrTime(u.LockedUntil)
	return u, err
}

// CreateUser inserts a new, unverified account. passwordHash must already be
// an Argon2id hash. Returns ErrEmailTaken if the email exists (any case).
func (s *Store) CreateUser(ctx context.Context, email, passwordHash string) (User, error) {
	row := s.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING `+userColumns,
		email, passwordHash)
	u, err := scanUser(row)
	if isUniqueViolation(err) {
		return User{}, ErrEmailTaken
	}
	if err != nil {
		return User{}, notFound("create user", err)
	}
	return u, nil
}

// GetUserByEmail looks up an account, ignoring email case.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	u, err := scanUser(s.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, email))
	if err != nil {
		return User{}, notFound("get user by email", err)
	}
	return u, nil
}

// GetUserByID looks up an account by its id.
func (s *Store) GetUserByID(ctx context.Context, id string) (User, error) {
	u, err := scanUser(s.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id))
	if err != nil {
		return User{}, notFound("get user by id", err)
	}
	return u, nil
}

// MarkEmailVerified records that the user proved they own their email.
func (s *Store) MarkEmailVerified(ctx context.Context, userID string) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE users SET email_verified_at = coalesce(email_verified_at, now()), updated_at = now()
		 WHERE id = $1`, userID)
	if err != nil {
		return notFound("mark email verified", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdatePasswordHash replaces the password (after a reset). Also clears any
// lockout, since the user just proved control of their email.
func (s *Store) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE users SET password_hash = $2, failed_login_count = 0, locked_until = NULL, updated_at = now()
		 WHERE id = $1`, userID, passwordHash)
	if err != nil {
		return notFound("update password", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordFailedLogin counts one failed attempt in a single atomic statement.
// When the count reaches maxAttempts the account is locked for lockFor and
// the counter starts again from 0. Returns the lock expiry if the account is
// now locked (nil otherwise).
//
// Example: RecordFailedLogin(ctx, id, 5, 15*time.Minute)
func (s *Store) RecordFailedLogin(ctx context.Context, userID string, maxAttempts int, lockFor time.Duration) (*time.Time, error) {
	var lockedUntil *time.Time
	err := s.db.QueryRow(ctx,
		`UPDATE users SET
		     locked_until = CASE WHEN failed_login_count + 1 >= $2
		                         THEN now() + make_interval(secs => $3) ELSE locked_until END,
		     failed_login_count = CASE WHEN failed_login_count + 1 >= $2
		                               THEN 0 ELSE failed_login_count + 1 END,
		     updated_at = now()
		 WHERE id = $1
		 RETURNING CASE WHEN locked_until > now() THEN locked_until END`,
		userID, maxAttempts, lockFor.Seconds()).Scan(&lockedUntil)
	if err != nil {
		return nil, notFound("record failed login", err)
	}
	return ptrTime(lockedUntil), nil
}

// ResetFailedLogins clears the counter after a successful password check.
func (s *Store) ResetFailedLogins(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE users SET failed_login_count = 0, updated_at = now() WHERE id = $1`, userID)
	if err != nil {
		return notFound("reset failed logins", err)
	}
	return nil
}
