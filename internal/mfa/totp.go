package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Period is the TOTP time step. Digits is the code length.
	// SHA-1 is used per RFC 6238 default (interoperable with every
	// authenticator app); the 20-byte secret keeps its full strength.
	Period = 30
	Digits = 6
)

// GenerateSecret returns 20 cryptographically random bytes for use as
// the TOTP shared secret.
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("mfa: entropy: %w", err)
	}
	return secret, nil
}

// ProvisioningURL builds the otpauth:// URL authenticator apps consume
// (QR code content). The secret is base32 without padding per the
// de-facto standard.
func ProvisioningURL(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("digits", strconv.Itoa(Digits))
	q.Set("period", strconv.Itoa(Period))
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

func counter(at time.Time) int64 {
	return at.Unix() / Period
}

func hotp(secret []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	code %= 1000000
	s := strconv.FormatUint(uint64(code), 10)
	return strings.Repeat("0", Digits-len(s)) + s
}

// Verify checks code against the current and adjacent time steps
// (±1 period clock-skew window). Comparison is constant-time.
func Verify(secret []byte, code string, at time.Time) bool {
	if len(code) != Digits {
		return false
	}
	c := counter(at.UTC())
	for _, delta := range []int64{-1, 0, 1} {
		candidate := hotp(secret, c+delta)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
