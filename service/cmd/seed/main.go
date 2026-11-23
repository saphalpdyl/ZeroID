// Command seed creates fictional test accounts for demos (Samip).
//
//	DATABASE_URL=... SEED_PASSWORD=... go run ./cmd/seed
//
// Accounts (all fictional):
//
//	alice@zeroid.test  verified    – main demo user
//	bob@zeroid.test    verified    – second user, for access-control demos
//	carol@zeroid.test  unverified  – shows the "verify your email" path
//
// The password comes from SEED_PASSWORD so nothing is hard-coded. Running it
// twice is safe: existing accounts are skipped.
//
// TOTP is NOT seeded: the secret must be encrypted with the AES key owned by
// the core service, so users enroll their authenticator through the app.
//
// FOR SAPHAL: hashPassword below writes a standard Argon2id PHC string, which
// any Argon2id verifier can check. If the core service has its own hashing
// helper, swap it in here so seed and app always use the same code.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/argon2"

	"zeroid/aadarsha/store"
	"zeroid/aadarsha/validation"
)

// Argon2id parameters (above the OWASP minimum of m=19 MiB, t=2, p=1).
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 2
	argonKeyLen    = 32
	argonSaltLen   = 16
)

func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var accounts = []struct {
	email    string
	verified bool
}{
	{"alice@zeroid.test", true},
	{"bob@zeroid.test", true},
	{"carol@zeroid.test", false},
}

func main() {
	dbURL, password := os.Getenv("DATABASE_URL"), os.Getenv("SEED_PASSWORD")
	if dbURL == "" || password == "" {
		log.Fatal("set DATABASE_URL and SEED_PASSWORD (see .env.example)")
	}
	if err := validation.Password(password); err != nil {
		log.Fatalf("SEED_PASSWORD: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := store.New(ctx, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	for _, a := range accounts {
		hash, err := hashPassword(password)
		if err != nil {
			log.Fatal(err)
		}
		u, err := s.CreateUser(ctx, a.email, hash)
		if errors.Is(err, store.ErrEmailTaken) {
			fmt.Printf("exists   %s\n", a.email)
			continue
		}
		if err != nil {
			log.Fatalf("%s: %v", a.email, err)
		}
		if a.verified {
			if err := s.MarkEmailVerified(ctx, u.ID); err != nil {
				log.Fatalf("%s: %v", a.email, err)
			}
		}
		_ = s.LogEvent(ctx, store.Event{UserID: u.ID, Email: a.email, Type: store.EventRegister, Success: true,
			Detail: map[string]any{"source": "seed"}})
		fmt.Printf("created  %s (verified=%v)\n", a.email, a.verified)
	}
}
