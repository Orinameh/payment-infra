package nibss

import (
	"context"
	"payment-infra/internal/money"
)

// Provider is the outbound bank-transfer seam. The payment service
// depends on this interface, not on any concrete implementation.
//
// Both the real NIP client and the dummy client satisfy it, so the
// wiring is a single config switch in cmd/api/main.go.
type Provider interface {
	// Transfer sends funds from an internal wallet to an external
	// bank account via NIP.
	//
	// The Amount is money.Money in the source wallet's currency.
	// For NGN, Amount.Minor is already in kobo — the wire format
	// NIP expects. There is no conversion here.
	Transfer(ctx context.Context, req TransferRequest) (*TransferResponse, error)

	// NameEnquiry resolves a NUBAN account number to an account name.
	// NIP requires this before a transfer to prevent misdirected funds.
	NameEnquiry(ctx context.Context, req NameEnquiryRequest) (*NameEnquiryResponse, error)

	// Mode returns "dummy" or "real" so callers can log or gate
	// behaviour. Health checks use it to warn if the dummy is wired
	// up in a non-development environment.
	Mode() string
}

// TransferRequest is the domain-level request. It deliberately does
// not mirror NIP's XML envelope — that conversion happens inside the
// real client.
type TransferRequest struct {
	FromAccount string      // our internal wallet's settlement account (NUBAN)
	ToAccount   string      // recipient's NUBAN
	ToBankCode  string      // CBN bank code
	Amount      money.Money // source currency; .Minor is the wire value
	Narration   string
	Reference   string // idempotency key on the NIP side
}

type TransferResponse struct {
	SessionID    string // NIP session ID
	Reference    string // our reference, echoed back
	ResponseCode string // NIP response code ("00" = success)
	Message      string
	Amount       money.Money // echoed back for verification
}

type NameEnquiryRequest struct {
	AccountNumber string
	BankCode      string
}

type NameEnquiryResponse struct {
	AccountName   string
	AccountNumber string
	BankCode      string
	SessionID     string
}
