package ledger

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestValidateBalanced(t *testing.T) {
	w1, w2 := uuid.New(), uuid.New()
	req := PostRequest{
		Type: "wallet_transfer",
		Entries: []Entry{
			{WalletID: w1, Amount: -500050, Currency: "NGN"},
			{WalletID: w2, Amount: 500050, Currency: "NGN"},
		},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("balanced request must validate: %v", err)
	}
}

func TestValidateTooFew(t *testing.T) {
	req := PostRequest{Entries: []Entry{{WalletID: uuid.New(), Amount: 1, Currency: "NGN"}}}
	if err := req.Validate(); !errors.Is(err, ErrTooFewEntries) {
		t.Fatalf("expected ErrTooFewEntries, got %v", err)
	}
}

func TestValidateUnbalanced(t *testing.T) {
	req := PostRequest{Entries: []Entry{
		{WalletID: uuid.New(), Amount: -100, Currency: "NGN"},
		{WalletID: uuid.New(), Amount: 99, Currency: "NGN"},
	}}
	if err := req.Validate(); !errors.Is(err, ErrUnbalanced) {
		t.Fatalf("expected ErrUnbalanced, got %v", err)
	}
}

func TestValidateMixedCurrency(t *testing.T) {
	req := PostRequest{Entries: []Entry{
		{WalletID: uuid.New(), Amount: -100, Currency: "NGN"},
		{WalletID: uuid.New(), Amount: 100, Currency: "USD"},
	}}
	if err := req.Validate(); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("expected ErrCurrencyMismatch, got %v", err)
	}
}

func TestValidateZeroAmount(t *testing.T) {
	req := PostRequest{Entries: []Entry{
		{WalletID: uuid.New(), Amount: 0, Currency: "NGN"},
		{WalletID: uuid.New(), Amount: 0, Currency: "NGN"},
	}}
	if err := req.Validate(); !errors.Is(err, ErrEmptyAmount) {
		t.Fatalf("expected ErrEmptyAmount, got %v", err)
	}
}
