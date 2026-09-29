package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingToken = errors.New("auth: missing token")
	ErrInvalidToken = errors.New("auth: invalid token")
	ErrExpiredToken = errors.New("auth: token expired")
)

// Claims carries the authenticated principal's identity and permissions.
// Subject is the user UUID. Role and Scopes drive authorization decisions.
type Claims struct {
	jwt.RegisteredClaims
	Role       string   `json:"role"`
	MerchantID string   `json:"merchant_id,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	KYCTier    int      `json:"kyc_tier,omitempty"`
	AMR        []string `json:"amr,omitempty"` // authentication methods: ["pwd","otp","mfa"]
}

// HasScope reports whether the principal holds a scope.
func (c *Claims) HasScope(s string) bool {
	for _, sc := range c.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

// HasMFA reports whether the token was issued after multi-factor auth.
// PCI DSS 4.0 requires MFA for all access to the cardholder data
// environment. Money-movement endpoints require MFA in production.
func (c *Claims) HasMFA() bool {
	for _, m := range c.AMR {
		if m == "mfa" || m == "otp" || m == "webauthn" {
			return true
		}
	}
	return false
}

// Authenticator parses and validates JWT RS256 tokens.
//
// RS256 (asymmetric) is required over HS256 (symmetric): with HS256,
// any service that can verify a token can also mint one, which means
// a single compromised verifier compromises the entire system. RS256
// keeps the signing key exclusively at the issuer.
type Authenticator struct {
	publicKey any
	issuer    string
	audience  string
	clockSkew time.Duration
}

// NewAuthenticator parses an RSA public key in PEM format. The key
// should be loaded from a secrets manager or Kubernetes Secret —
// never baked into the binary or committed to source control.
func NewAuthenticator(publicKeyPEM []byte, issuer, audience string) (*Authenticator, error) {
	pub, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("auth: parse public key: %w", err)
	}
	return &Authenticator{
		publicKey: pub,
		issuer:    issuer,
		audience:  audience,
		clockSkew: 30 * time.Second,
	}, nil
}

// Parse validates signature, algorithm, issuer, audience, and expiry.
// It rejects `alg: none` and any non-RSA signing method — this blocks
// the algorithm-confusion attack class.
func (a *Authenticator) Parse(tokenStr string) (*Claims, error) {
	if tokenStr == "" {
		return nil, ErrMissingToken
	}
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (any, error) {
			// Strict algorithm check. Reject anything that isn't RSA.
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("auth: unexpected signing method: %v", t.Header["alg"])
			}
			return a.publicKey, nil
		},
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(a.clockSkew),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !tok.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// MTLSConfig returns a TLS config that REQUIRES and verifies client
// certificates. TLS 1.3 minimum. Use this on the server side for any
// service-to-service endpoint handling money movement.
func MTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("auth: failed to parse CA cert")
	}
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("auth: keypair: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// NewRefreshToken returns a random opaque token and its SHA-256 hash.
// Only the hash is persisted; the plaintext goes to the client.
func NewRefreshToken() (token string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type ctxKey int

const claimsKey ctxKey = iota

func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok
}

// MustClaims panics if no claims are present. Only call from handlers
// that are guaranteed to sit behind AuthRequired middleware.
func MustClaims(ctx context.Context) *Claims {
	c, ok := ClaimsFrom(ctx)
	if !ok {
		panic("auth: MustClaims called without AuthRequired middleware")
	}
	return c
}
