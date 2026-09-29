package fraud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"payment-infra/internal/money"
	"payment-infra/internal/platform/db"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrBlocked = errors.New("fraud: transaction blocked")
	ErrReview  = errors.New("fraud: transaction requires review")
)

type Service struct{ pool *pgxpool.Pool }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

type CheckRequest struct {
	UserID   uuid.UUID
	WalletID uuid.UUID
	Amount   money.Money
}

type Result struct {
	RiskScore      int
	Decision       string
	RulesTriggered []string
}

// Check evaluates risk and returns a decision. It performs ONLY reads.
// All writes happen in RecordAlert, which the caller invokes outside
// the payment transaction so alerts survive rollbacks.
//
// q should be the payment transaction (tx), not the pool: the velocity
// query must see the same snapshot as the balance lock, otherwise two
// concurrent transfers can both pass the check.
func (s *Service) Check(ctx context.Context, q db.Querier, req CheckRequest) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()

	result := &Result{Decision: "allow"}

	// velocity_1min: burst pattern (mule / bot behaviour).
	var count int
	if err := q.QueryRow(ctx, `
		SELECT COUNT(*) FROM ledger_entries
		WHERE wallet_id = $1 AND created_at > now() - interval '1 minute'`,
		req.WalletID).Scan(&count); err != nil {
		// Fail open with a log: fraud-signal downtime must not halt
		// all payments, but it must be visible.
		slog.Warn("fraud velocity check failed, failing open", "err", err)
	} else if count > 10 {
		result.RiskScore += 300
		result.RulesTriggered = append(result.RulesTriggered, "velocity_1min")
	}

	// velocity_24h: sustained abnormal throughput on one wallet.
	var dayCount int
	if err := q.QueryRow(ctx, `
		SELECT COUNT(*) FROM ledger_entries
		WHERE wallet_id = $1 AND created_at > now() - interval '24 hours'`,
		req.WalletID).Scan(&dayCount); err != nil {
		slog.Warn("fraud daily velocity check failed, failing open", "err", err)
	} else if dayCount > 100 {
		result.RiskScore += 150
		result.RulesTriggered = append(result.RulesTriggered, "velocity_24h")
	}

	if req.Amount.Currency == money.NGN && req.Amount.Minor > 500000 {
		result.RiskScore += 200
		result.RulesTriggered = append(result.RulesTriggered, "high_value_ngn")
	}

	// new_account_high_value: accounts under 24h old moving more than
	// ₦2,000 in one transfer get extra scrutiny (first-party mule
	// pattern). Uses the actor's created_at on the tx snapshot.
	var createdAt time.Time
	if err := q.QueryRow(ctx,
		`SELECT created_at FROM users WHERE id = $1`,
		req.UserID).Scan(&createdAt); err == nil {
		if time.Since(createdAt) < 24*time.Hour && req.Amount.Minor > 200000 {
			result.RiskScore += 250
			result.RulesTriggered = append(result.RulesTriggered, "new_account_high_value")
		}
	} else {
		slog.Warn("fraud account-age check failed, failing open", "err", err)
	}

	switch {
	case result.RiskScore >= 700:
		result.Decision = "block"
	case result.RiskScore >= 400:
		result.Decision = "review"
	}
	return result, nil
}

// RecordAlert persists the fraud check result. Call this OUTSIDE the
// payment transaction. The txID is the transaction that resulted from
// the check, or nil if the payment failed or was blocked.
//
// This is called on every attempt — successful, blocked, or rolled
// back — because AML rules care about attempted transactions, not
// just completed ones.
func (s *Service) RecordAlert(ctx context.Context, req CheckRequest,
	result *Result, txID *uuid.UUID) {

	writeCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := s.pool.Exec(writeCtx, `
		INSERT INTO aml_alerts (user_id, wallet_id, transaction_id, rule_code,
		                        severity, description, amount_minor, currency)
		VALUES ($1, $2, $3, 'fraud_check', $4, $5, $6, $7)`,
		req.UserID, req.WalletID, txID, severityOf(result.RiskScore),
		fmt.Sprintf("risk=%d rules=%v decision=%s",
			result.RiskScore, result.RulesTriggered, result.Decision),
		req.Amount.Minor, string(req.Amount.Currency))

	if err != nil {
		// Do not fail the payment because AML persistence is down.
		// Log and move on; a separate reconciliation can backfill.
		slog.Error("failed to persist AML alert",
			"err", err, "wallet_id", req.WalletID)
	}
}

func severityOf(score int) string {
	switch {
	case score >= 700:
		return "critical"
	case score >= 400:
		return "high"
	case score >= 200:
		return "medium"
	}
	return "low"
}
