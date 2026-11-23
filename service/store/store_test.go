package store

// Integration tests: they run against a real PostgreSQL with the migrations
// applied, connected as the least-privilege zeroid_app role.
//
//   TEST_DATABASE_URL=postgres://zeroid_app:...@localhost:5432/zeroid go test ./store
//
// Without TEST_DATABASE_URL the tests are skipped, so `go test ./...` still
// passes on machines without a database.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const fakeHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"

func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database tests")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	// Optional: when connecting as the owner, drop to the app role so the
	// tests prove the code works with least privilege.
	if role := os.Getenv("TEST_DATABASE_ROLE"); role != "" {
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
			return err
		}
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return NewFromPool(pool)
}

func uniqueEmail(t *testing.T) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%x@zeroid.test", strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")), b)
}

func randomHash() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	h := sha256.Sum256(b)
	return h[:]
}

func newUser(t *testing.T, s *Store) User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), uniqueEmail(t), fakeHash)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUsers(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)

	if _, err := s.CreateUser(ctx, strings.ToUpper(u.Email), fakeHash); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("duplicate email (other case): got %v, want ErrEmailTaken", err)
	}
	if _, err := s.CreateUser(ctx, uniqueEmail(t), "plaintext-password"); err == nil {
		t.Fatal("plaintext password was accepted")
	}
	got, err := s.GetUserByEmail(ctx, strings.ToUpper(u.Email))
	if err != nil || got.ID != u.ID {
		t.Fatalf("GetUserByEmail: %v %v", got, err)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatal("new user should be unverified")
	}
	if err := s.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetUserByID(ctx, u.ID); got.EmailVerifiedAt == nil {
		t.Fatal("email not marked verified")
	}
	if _, err := s.GetUserByEmail(ctx, "nobody@zeroid.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown email: got %v, want ErrNotFound", err)
	}
}

func TestSQLInjectionIsJustData(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	newUser(t, s)
	for _, evil := range []string{
		"' OR '1'='1",
		"admin@zeroid.test'; DROP TABLE users; --",
		"x' UNION SELECT id, email, password_hash, null, 0, null, now() FROM users --",
	} {
		if _, err := s.GetUserByEmail(ctx, evil); !errors.Is(err, ErrNotFound) {
			t.Fatalf("injection %q: got %v, want ErrNotFound", evil, err)
		}
	}
	// users table still exists and works
	newUser(t, s)
}

func TestLockoutAfterFiveFailures(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)
	for i := 1; i <= 4; i++ {
		locked, err := s.RecordFailedLogin(ctx, u.ID, 5, 15*time.Minute)
		if err != nil || locked != nil {
			t.Fatalf("attempt %d: locked=%v err=%v", i, locked, err)
		}
	}
	locked, err := s.RecordFailedLogin(ctx, u.ID, 5, 15*time.Minute)
	if err != nil || locked == nil {
		t.Fatalf("5th failure should lock: locked=%v err=%v", locked, err)
	}
	got, _ := s.GetUserByID(ctx, u.ID)
	if !got.IsLocked(time.Now()) {
		t.Fatal("user should be locked")
	}
	if d := time.Until(*got.LockedUntil); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("lock duration %v, want ~15m", d)
	}
	if err := s.UpdatePasswordHash(ctx, u.ID, fakeHash); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetUserByID(ctx, u.ID); got.IsLocked(time.Now()) || got.FailedLoginCount != 0 {
		t.Fatal("password reset should clear lockout")
	}
}

func TestTOTPReplayProtection(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)
	if _, err := s.GetTOTP(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not enrolled: got %v", err)
	}
	ct, nonce := make([]byte, 36), make([]byte, 12)
	if err := s.SaveTOTP(ctx, u.ID, ct, nonce, 1); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 1000); !ok {
		t.Fatal("first code should be accepted")
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 1000); ok {
		t.Fatal("REPLAY of same code was accepted")
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 999); ok {
		t.Fatal("older code was accepted")
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 1001); !ok {
		t.Fatal("next code should be accepted")
	}
	c, err := s.GetTOTP(ctx, u.ID)
	if err != nil || c.ConfirmedAt == nil || *c.LastUsedStep != 1001 {
		t.Fatalf("GetTOTP: %+v %v", c, err)
	}
	if err := s.SaveTOTP(ctx, u.ID, ct, []byte("short"), 1); err == nil {
		t.Fatal("bad nonce length accepted")
	}
}

func TestTokensAreSingleUseAndExpire(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)
	h := randomHash()
	if err := s.CreateToken(ctx, u.ID, PurposeEmailVerify, h, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeToken(ctx, PurposePasswordReset, h); !errors.Is(err, ErrNotFound) {
		t.Fatal("token used for the wrong purpose")
	}
	id, err := s.ConsumeToken(ctx, PurposeEmailVerify, h)
	if err != nil || id != u.ID {
		t.Fatalf("consume: %v %v", id, err)
	}
	if _, err := s.ConsumeToken(ctx, PurposeEmailVerify, h); !errors.Is(err, ErrNotFound) {
		t.Fatal("token was used TWICE")
	}

	short := randomHash()
	if err := s.CreateToken(ctx, u.ID, PurposeLoginTicket, short, time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := s.ConsumeToken(ctx, PurposeLoginTicket, short); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired token was accepted")
	}
	if err := s.CreateToken(ctx, u.ID, PurposeEmailVerify, []byte("raw-token"), time.Minute); err == nil {
		t.Fatal("unhashed token accepted")
	}
}

func TestTokenRace(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)
	h := randomHash()
	_ = s.CreateToken(ctx, u.ID, PurposePasswordReset, h, time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeToken(ctx, PurposePasswordReset, h); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("token consumed %d times in parallel, want exactly 1", wins)
	}
}

func TestRecoveryCodes(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)
	if err := s.ReplaceRecoveryCodes(ctx, u.ID, []string{fakeHash, fakeHash, fakeHash}); err != nil {
		t.Fatal(err)
	}
	codes, err := s.ListUnusedRecoveryCodes(ctx, u.ID)
	if err != nil || len(codes) != 3 {
		t.Fatalf("list: %d %v", len(codes), err)
	}
	if ok, _ := s.UseRecoveryCode(ctx, codes[0].ID); !ok {
		t.Fatal("first use should succeed")
	}
	if ok, _ := s.UseRecoveryCode(ctx, codes[0].ID); ok {
		t.Fatal("recovery code used twice")
	}
	if codes, _ = s.ListUnusedRecoveryCodes(ctx, u.ID); len(codes) != 2 {
		t.Fatalf("want 2 unused codes, got %d", len(codes))
	}
	if err := s.ReplaceRecoveryCodes(ctx, u.ID, []string{"not-a-hash"}); err == nil {
		t.Fatal("unhashed recovery code accepted")
	}
	if codes, _ = s.ListUnusedRecoveryCodes(ctx, u.ID); len(codes) != 2 {
		t.Fatal("failed replace should roll back (transaction)")
	}
}

func TestSessions(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)
	h := randomHash()
	sess, err := s.CreateSession(ctx, u.ID, h, time.Hour, "203.0.113.7", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if d := sess.ExpiresAt.Sub(sess.CreatedAt); d != time.Hour {
		t.Fatalf("absolute expiry %v, want 1h", d)
	}
	got, err := s.ValidateSession(ctx, h, 10*time.Minute)
	if err != nil || got.UserID != u.ID || got.MFAAt == nil {
		t.Fatalf("validate: %+v %v", got, err)
	}
	if _, err := s.ValidateSession(ctx, randomHash(), 10*time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown session accepted")
	}
	// idle timeout: a session unused longer than the limit is rejected
	time.Sleep(1100 * time.Millisecond)
	if _, err := s.ValidateSession(ctx, h, time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatal("idle session accepted")
	}
	if err := s.RevokeSession(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(ctx, h, 10*time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked session accepted")
	}
	h2, h3 := randomHash(), randomHash()
	_, _ = s.CreateSession(ctx, u.ID, h2, time.Hour, "", "")
	_, _ = s.CreateSession(ctx, u.ID, h3, time.Hour, "", "")
	if n, err := s.RevokeAllSessions(ctx, u.ID); err != nil || n != 2 {
		t.Fatalf("revoke all: %d %v", n, err)
	}
}

func TestAuditLog(t *testing.T) {
	s, ctx := testStore(t), context.Background()
	u := newUser(t, s)
	for i, ok := range []bool{false, false, true} {
		err := s.LogEvent(ctx, Event{UserID: u.ID, Email: u.Email, Type: EventLoginPassword, Success: ok,
			IP: "198.51.100.1", UserAgent: "agent", Detail: map[string]any{"attempt": i + 1}})
		if err != nil {
			t.Fatal(err)
		}
	}
	// unknown account: still logged, with no user id
	if err := s.LogEvent(ctx, Event{Email: "ghost@zeroid.test", Type: EventLoginPassword}); err != nil {
		t.Fatal(err)
	}
	events, err := s.RecentEvents(ctx, u.ID, 10)
	if err != nil || len(events) != 3 {
		t.Fatalf("recent: %d %v", len(events), err)
	}
	if !events[0].Success || events[0].IP != "198.51.100.1" {
		t.Fatalf("newest first expected: %+v", events[0])
	}
	if err := s.LogEvent(ctx, Event{Type: "made_up"}); err == nil {
		t.Fatal("unknown event type accepted")
	}
}
