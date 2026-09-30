package httpapi

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"payment-infra/internal/auth"
	"payment-infra/internal/user"

	"github.com/google/uuid"
)

func TestWriteErrShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeErr(w, 422, CodeTransferInsufficient, "insufficient funds")
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != "TRANSFER_INSUFFICIENT_FUNDS" || body["error"] != "insufficient funds" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestMintAccessTokenNilGuard(t *testing.T) {
	h := &Handler{}
	u := &user.User{ID: uuid.New()}
	if _, err := h.mintAccessToken(u, nil); err == nil {
		t.Fatal("nil SignToken must error, not panic")
	}
}

func TestMintAccessTokenClaims(t *testing.T) {
	var got auth.Claims
	h := &Handler{
		Issuer:         "payments-api",
		Audience:       "payments",
		AccessTokenTTL: 900,
		SignToken: func(c auth.Claims) (string, error) {
			got = c
			return "signed", nil
		},
	}
	u := &user.User{ID: uuid.New(), KYCTier: 2}
	tok, err := h.mintAccessToken(u, nil)
	if err != nil || tok != "signed" {
		t.Fatalf("got %q, %v", tok, err)
	}
	if got.Subject != u.ID.String() || got.KYCTier != 2 {
		t.Fatalf("claims not propagated: %+v", got)
	}
	if len(got.AMR) != 1 || got.AMR[0] != "pwd" {
		t.Fatalf("default AMR must be [pwd], got %v", got.AMR)
	}
	if _, err := h.mintAccessToken(u, []string{"pwd", "otp"}); err != nil {
		t.Fatal(err)
	}
	if len(got.AMR) != 2 {
		t.Fatalf("custom AMR must be kept, got %v", got.AMR)
	}
}

func TestErrForbiddenDistinct(t *testing.T) {
	if errors.Is(errForbidden, nil) {
		t.Fatal("sanity")
	}
}
