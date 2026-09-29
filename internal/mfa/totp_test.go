package mfa

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B SHA-1 vector: secret "12345678901234567890"
// (ASCII), T=59s → 94287082 (8-digit) → 287082 truncated to 6 digits.
func TestRFC6238Vector(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(59, 0).UTC()
	if !Verify(secret, "287082", at) {
		t.Fatal("RFC 6238 vector must verify")
	}
	if Verify(secret, "287083", at) {
		t.Fatal("wrong code must not verify")
	}
}

func TestWindowSkew(t *testing.T) {
	secret := []byte("12345678901234567890")
	base := time.Unix(120, 0).UTC() // counter 4
	code := hotp(secret, counter(base))
	if !Verify(secret, code, base.Add(-Period*time.Second)) {
		t.Fatal("must verify one step early")
	}
	if !Verify(secret, code, base.Add(Period*time.Second)) {
		t.Fatal("must verify one step late")
	}
	if Verify(secret, code, base.Add(2*Period*time.Second)) {
		t.Fatal("must not verify two steps away")
	}
}

func TestProvisioningURL(t *testing.T) {
	secret := []byte("12345678901234567890")
	u := ProvisioningURL("payments-api", "a@b.c", secret)
	if !strings.HasPrefix(u, "otpauth://totp/") {
		t.Fatalf("bad scheme: %s", u)
	}
	if !strings.Contains(u, "secret=") || !strings.Contains(u, "issuer=") {
		t.Fatalf("missing params: %s", u)
	}
}
