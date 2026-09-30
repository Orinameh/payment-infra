package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSignMatchesStdlib(t *testing.T) {
	secret, body := []byte("whsec_test"), []byte(`{"event":"x"}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if got := sign(secret, body); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSignKeySensitivity(t *testing.T) {
	if sign([]byte("a"), []byte("b")) == sign([]byte("c"), []byte("b")) {
		t.Fatal("different secrets must produce different signatures")
	}
}
