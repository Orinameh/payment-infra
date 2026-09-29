package nibss

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
)

// DummyClient is a deterministic fake NIP provider. It never talks to
// the network. Every transfer succeeds with a fabricated session ID.
//
// Purpose: let the outbound-transfer flow be built and tested end to
// end before NIBSS onboarding completes.
type DummyClient struct {
	env         string
	failureRate float64
	counter     atomic.Uint64
}

type DummyConfig struct {
	// Environment is compared against "production" and "prod".
	// Construction fails if a dummy is requested in production.
	Environment string
	// FailureRate injects deterministic failures for testing the
	// retry path. 0 = always succeed. 0.5 = half fail.
	FailureRate float64
}

func NewDummyClient(cfg DummyConfig) (*DummyClient, error) {
	env := strings.ToLower(strings.TrimSpace(cfg.Environment))
	if env == "production" || env == "prod" {
		return nil, ErrDummyInProduction
	}
	if cfg.FailureRate < 0 || cfg.FailureRate > 1 {
		return nil, fmt.Errorf("nibss: failure rate must be between 0 and 1")
	}
	slog.Warn("nibss: DUMMY CLIENT ACTIVE — no real NIP traffic will be sent",
		"environment", env, "failure_rate", cfg.FailureRate)
	return &DummyClient{env: env, failureRate: cfg.FailureRate}, nil
}

func (c *DummyClient) Mode() string { return "dummy" }

func (c *DummyClient) Transfer(ctx context.Context,
	req TransferRequest) (*TransferResponse, error) {

	if req.FromAccount == "" || req.ToAccount == "" {
		return nil, fmt.Errorf("nibss: from and to accounts required")
	}
	if err := req.Amount.RequirePositive(); err != nil {
		return nil, err
	}
	if req.ToBankCode == "" {
		return nil, fmt.Errorf("nibss: target bank code required")
	}

	n := c.counter.Add(1)
	if c.failureRate > 0 && float64(n%100)/100.0 < c.failureRate {
		slog.Warn("nibss: dummy transfer failing (injected)",
			"reference", req.Reference, "attempt", n)
		return nil, fmt.Errorf("nibss: dummy injected failure for %s", req.Reference)
	}

	sessionID := deterministicID("nibss-session", req.Reference, n)

	slog.Info("nibss: dummy transfer succeeded",
		"reference", req.Reference,
		"from", req.FromAccount,
		"to", req.ToAccount,
		"bank", req.ToBankCode,
		"amount_minor", req.Amount.Minor,
		"currency", req.Amount.Currency,
		"session_id", sessionID)

	return &TransferResponse{
		SessionID:    sessionID,
		Reference:    req.Reference,
		ResponseCode: "00",
		Message:      "Approved (dummy)",
		Amount:       req.Amount,
	}, nil
}

func (c *DummyClient) NameEnquiry(ctx context.Context,
	req NameEnquiryRequest) (*NameEnquiryResponse, error) {

	if req.AccountNumber == "" || req.BankCode == "" {
		return nil, fmt.Errorf("nibss: account number and bank code required")
	}
	return &NameEnquiryResponse{
		AccountName:   "DUMMY ACCOUNT NAME",
		AccountNumber: req.AccountNumber,
		BankCode:      req.BankCode,
		SessionID:     deterministicID("nibss-ne-session", req.AccountNumber, 0),
	}, nil
}

func deterministicID(prefix, key string, counter uint64) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%d", prefix, key, counter))
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return uuid.Must(uuid.FromBytes(b[:])).String()
}
