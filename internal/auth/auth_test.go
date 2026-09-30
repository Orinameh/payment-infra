package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testKeys(t *testing.T) (priv *rsa.PrivateKey, pubPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pubPEM
}

func signed(t *testing.T, priv *rsa.PrivateKey, claims Claims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func validClaims() Claims {
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "payments-api",
			Audience:  jwt.ClaimStrings{"payments"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role: "user",
		AMR:  []string{"pwd", "otp"},
	}
}

func TestParseValid(t *testing.T) {
	priv, pub := testKeys(t)
	a, err := NewAuthenticator(pub, "payments-api", "payments")
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Parse("Bearer " + signed(t, priv, validClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "user-1" || !got.HasMFA() {
		t.Fatalf("unexpected claims: %+v", got)
	}
}

func TestRejectsWrongAlgorithm(t *testing.T) {
	_, pub := testKeys(t)
	a, _ := NewAuthenticator(pub, "payments-api", "payments")
	// HS256 with any secret: must be rejected (algorithm confusion).
	evil, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims()).SignedString([]byte("secret"))
	if _, err := a.Parse(evil); err == nil {
		t.Fatal("non-RSA signing method must be rejected")
	}
}

func TestRejectsNoneAlgorithm(t *testing.T) {
	_, pub := testKeys(t)
	a, _ := NewAuthenticator(pub, "payments-api", "payments")
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := a.Parse(none); err == nil {
		t.Fatal("alg:none must be rejected")
	}
}

func TestRejectsExpired(t *testing.T) {
	priv, pub := testKeys(t)
	a, _ := NewAuthenticator(pub, "payments-api", "payments")
	c := validClaims()
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	if _, err := a.Parse(signed(t, priv, c)); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestRejectsWrongIssuer(t *testing.T) {
	priv, pub := testKeys(t)
	a, _ := NewAuthenticator(pub, "payments-api", "payments")
	c := validClaims()
	c.Issuer = "evil-issuer"
	if _, err := a.Parse(signed(t, priv, c)); err == nil {
		t.Fatal("wrong issuer must be rejected")
	}
}

func TestRejectsMissingToken(t *testing.T) {
	_, pub := testKeys(t)
	a, _ := NewAuthenticator(pub, "payments-api", "payments")
	if _, err := a.Parse(""); err == nil {
		t.Fatal("missing token must be rejected")
	}
}

func TestHasScopeAndMFA(t *testing.T) {
	c := &Claims{Scopes: []string{"transfer:write"}, AMR: []string{"pwd"}}
	if !c.HasScope("transfer:write") || c.HasScope("admin") {
		t.Fatal("scope check wrong")
	}
	if c.HasMFA() {
		t.Fatal("pwd-only must not count as MFA")
	}
	c.AMR = []string{"pwd", "webauthn"}
	if !c.HasMFA() {
		t.Fatal("webauthn must count as MFA")
	}
}
