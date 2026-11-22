package validation

import (
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"
)

func Email(email string) error {
	if email != strings.TrimSpace(email) || len(email) == 0 || len(email) > 254 || strings.ContainsAny(email, "\r\n\t ") {
		return errors.New("invalid email")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || strings.ContainsAny(email, "<>(),;\"") {
		return errors.New("invalid email")
	}
	return nil
}
func Password(password string) error {
	n := utf8.RuneCountInString(password)
	if !utf8.ValidString(password) || n < 12 || n > 128 {
		return errors.New("password must be 12–128 characters")
	}
	return nil
}
func TOTP(code string) error {
	if len(code) != 6 {
		return errors.New("TOTP code must be 6 digits")
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return errors.New("TOTP code must be digits")
		}
	}
	return nil
}
func Token(token string) error {
	if len(token) < 16 || len(token) > 512 {
		return errors.New("invalid token")
	}
	for _, c := range token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return errors.New("invalid token")
		}
	}
	return nil
}
