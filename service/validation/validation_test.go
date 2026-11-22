package validation

import "testing"

func TestEmail(t *testing.T) {
	for _, v := range []string{"a@example.com", "person+tag@example.org"} {
		if err := Email(v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"", "a@", "a@example.com\r\nBcc: bad@x.com", "A Name <a@example.com>"} {
		if Email(v) == nil {
			t.Errorf("accepted bad email %q", v)
		}
	}
}
func TestPassword(t *testing.T) {
	if Password("good password 123") == nil && Password("short") != nil {
		return
	}
	t.Fatal("password validation wrong")
}
func TestTOTP(t *testing.T) {
	if TOTP("123456") != nil || TOTP("12345a") == nil || TOTP("12345") == nil {
		t.Fatal("TOTP validation wrong")
	}
}
func TestToken(t *testing.T) {
	if Token("abcdefghijklmnop") != nil || Token("x") == nil || Token("abcdefghijklmnop!") == nil {
		t.Fatal("token validation wrong")
	}
}
