package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventType matches the CHECK constraint on auth_events.event_type.
type EventType string

const (
	EventRegister             EventType = "register"
	EventEmailVerify          EventType = "email_verify"
	EventLoginPassword        EventType = "login_password"
	EventLoginTOTP            EventType = "login_totp"
	EventLoginRecoveryCode    EventType = "login_recovery_code"
	EventLockout              EventType = "lockout"
	EventLogout               EventType = "logout"
	EventSessionRevoked       EventType = "session_revoked"
	EventTOTPEnroll           EventType = "totp_enroll"
	EventPasswordResetRequest EventType = "password_reset_request"
	EventPasswordReset        EventType = "password_reset"
)

// Event is one audit-log entry. Log EVERY attempt, success or failure.
// Never put passwords, TOTP codes, tokens or session IDs in Detail.
type Event struct {
	UserID    string // empty if the account is unknown (e.g. bad email)
	Email     string // as typed by the user
	Type      EventType
	Success   bool
	IP        string
	UserAgent string
	Detail    map[string]any // optional, e.g. {"reason": "bad_password"}
	CreatedAt time.Time      // filled in when reading
}

// LogEvent appends to the audit log. The app role cannot update or delete
// these rows, so the log can't be erased through the app.
func (s *Store) LogEvent(ctx context.Context, e Event) error {
	var detail *string
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("store: log event detail: %w", err)
		}
		d := string(b)
		detail = &d
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO auth_events (user_id, email, event_type, success, ip, user_agent, detail)
		 VALUES (NULLIF($1, '')::uuid, NULLIF(left($2, 254), ''), $3, $4,
		         NULLIF($5, '')::inet, NULLIF(left($6, 512), ''), $7::jsonb)`,
		e.UserID, e.Email, string(e.Type), e.Success, e.IP, e.UserAgent, detail)
	if err != nil {
		return fmt.Errorf("store: log event: %w", err)
	}
	return nil
}

// RecentEvents returns a user's latest events, newest first (for the portal).
func (s *Store) RecentEvents(ctx context.Context, userID string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(ctx,
		`SELECT coalesce(user_id::text, ''), coalesce(email, ''), event_type, success,
		        coalesce(host(ip), ''), coalesce(user_agent, ''), created_at
		 FROM auth_events WHERE user_id = $1
		 ORDER BY created_at DESC, id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent events: %w", err)
	}
	events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
		var e Event
		var t string
		err := r.Scan(&e.UserID, &e.Email, &t, &e.Success, &e.IP, &e.UserAgent, &e.CreatedAt)
		e.Type = EventType(t)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: recent events: %w", err)
	}
	return events, nil
}
