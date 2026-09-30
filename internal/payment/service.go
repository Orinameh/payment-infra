package payment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"payment-infra/internal/audit"
	"payment-infra/internal/fraud"
	"payment-infra/internal/httpx"
	"payment-infra/internal/ledger"
	"payment-infra/internal/money"
	"payment-infra/internal/nibss"
	"payment-infra/internal/outbox"
	"payment-infra/internal/platform/db"
	"payment-infra/internal/wallet"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInsufficientFunds = wallet.ErrInsufficientFunds
	ErrLimitExceeded     = errors.New("payment: transaction limit exceeded")
)

type TransferRequest struct {
	FromWalletID uuid.UUID
	ToWalletID   uuid.UUID
	Amount       money.Money
	Reference    string
	EndToEndID   string
	IdemKey      string
	Metadata     map[string]any
}

type TransferResult struct {
	TransactionID uuid.UUID `json:"transaction_id"`
	Status        string    `json:"status"`
	NewBalance    int64     `json:"new_balance_minor"`
	Currency      string    `json:"currency"`
}

type Service struct {
	pool    *pgxpool.Pool
	wallets *wallet.Service
	ledger  *ledger.Service
	fraud   *fraud.Service
	audit   *audit.Recorder
	nibss   nibss.Provider
	outbox  outbox.Writer
}

type Config struct {
	nibss nibss.Provider
}

type Option func(*Config)

func WithNIBSS(p nibss.Provider) Option {
	return func(c *Config) { c.nibss = p }
}

func NewService(pool *pgxpool.Pool, w *wallet.Service, l *ledger.Service,
	f *fraud.Service, a *audit.Recorder, opts ...Option) *Service {
	cfg := &Config{}
	for _, opt := range opts {
		opt(cfg)
	}
	return &Service{
		pool:    pool,
		wallets: w,
		ledger:  l,
		fraud:   f,
		audit:   a,
		nibss:   cfg.nibss,
	}
}

func (s *Service) Transfer(ctx context.Context, actorID uuid.UUID,
	req TransferRequest) (*TransferResult, error) {

	if req.FromWalletID == req.ToWalletID {
		return nil, errors.New("payment: from and to must differ")
	}
	if err := req.Amount.RequirePositive(); err != nil {
		return nil, err
	}
	if req.IdemKey == "" {
		return nil, errors.New("payment: idempotency key required")
	}

	// Hash the request WITHOUT the idempotency key itself. The key is
	// the dedup identity; the hash is the payload fingerprint. Including
	// the key in the hash is harmless but conceptually wrong and makes
	// the "key reused with different payload" check harder to reason.
	fingerprint, _ := json.Marshal(struct {
		From uuid.UUID      `json:"from"`
		To   uuid.UUID      `json:"to"`
		Amt  int64          `json:"amount_minor"`
		Ccy  money.Currency `json:"currency"`
		Ref  string         `json:"reference"`
		E2E  string         `json:"end_to_end_id"`
		Meta map[string]any `json:"metadata"`
	}{
		From: req.FromWalletID, To: req.ToWalletID,
		Amt: req.Amount.Minor, Ccy: req.Amount.Currency,
		Ref: req.Reference, E2E: req.EndToEndID, Meta: req.Metadata,
	})
	reqHash := hashBody(fingerprint)

	fraudReq := fraud.CheckRequest{
		UserID:   actorID,
		WalletID: req.FromWalletID,
		Amount:   req.Amount,
	}

	var (
		out         *TransferResult
		fraudResult *fraud.Result
	)

	err := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		rec, err := reserveIdem(ctx, tx, req.IdemKey, reqHash)
		if err != nil {
			return err
		}
		if rec != nil {
			return json.Unmarshal(rec.body, &out)
		}

		// Fraud check runs on the tx snapshot (same view as the wallet
		// locks below), not on a separate pool connection.
		fraudResult, err = s.fraud.Check(ctx, tx, fraudReq)
		if err != nil {
			return err
		}
		if fraudResult.Decision == "block" {
			return fraud.ErrBlocked
		}

		// Tier limit check runs inside the wallet lock (Fix 2).
		precheck := func(ctx context.Context, tx pgx.Tx,
			sourceWalletID uuid.UUID, amount money.Money) error {
			return s.checkTierLimit(ctx, tx, actorID, amount)
		}

		if err := s.wallets.Transfer(ctx, tx,
			req.FromWalletID, req.ToWalletID, req.Amount,
			req.Reference, actorID,
			wallet.WithPrecheck(precheck)); err != nil {
			return err
		}

		txID, err := s.ledger.Post(ctx, tx, ledger.PostRequest{
			Type:       "wallet_transfer",
			Reference:  req.Reference,
			EndToEndID: req.EndToEndID,
			Metadata:   req.Metadata,
			Entries: []ledger.Entry{
				{WalletID: req.FromWalletID, Amount: -req.Amount.Minor, Currency: string(req.Amount.Currency)},
				{WalletID: req.ToWalletID, Amount: req.Amount.Minor, Currency: string(req.Amount.Currency)},
			},
		})
		if err != nil {
			return err
		}

		from, err := s.wallets.Get(ctx, tx, req.FromWalletID)
		if err != nil {
			return err
		}
		out = &TransferResult{
			TransactionID: txID,
			Status:        "posted",
			NewBalance:    from.Balance,
			Currency:      from.Currency,
		}
		if err := s.outbox.Emit(ctx, tx, "transaction", txID,
			"payments.transfer_posted", map[string]any{
				"transaction_id": txID.String(),
				"from_wallet_id": req.FromWalletID.String(),
				"to_wallet_id":   req.ToWalletID.String(),
				"amount_minor":   req.Amount.Minor,
				"currency":       string(req.Amount.Currency),
				"reference":      req.Reference,
				"end_to_end_id":  req.EndToEndID,
				"new_balance":    from.Balance,
				// Correlation: lets the consumer, webhook deliveries,
				// and audit trail all join back to the HTTP request.
				"request_id": httpx.RequestIDFrom(ctx),
			}); err != nil {
			return err
		}
		return storeIdem(ctx, tx, req.IdemKey, 201, out)
	})

	// Persist the AML alert regardless of tx outcome. This is the fix:
	// the write happens on a separate connection, after commit or
	// rollback, so it always lands.
	if fraudResult != nil {
		var txID *uuid.UUID
		if out != nil {
			id := out.TransactionID
			txID = &id
		}
		s.fraud.RecordAlert(ctx, fraudReq, fraudResult, txID)
	}

	if err != nil {
		return nil, fmt.Errorf("payment: transfer: %w", err)
	}
	return out, nil
}

// checkTierLimit enforces CBN tiered limits. Called from within
// wallet.Transfer's precheck, so it runs with the source wallet
// locked. Two concurrent transfers on the same wallet cannot both
// pass a daily limit check.
//
// Reads:
//
//	users.kyc_tier                         — the user's current tier
//	transaction_limits                     — per-tier single/daily/new-account caps
//	SUM of debits in the last 24 hours     — the user's usage so far
func (s *Service) checkTierLimit(ctx context.Context, tx pgx.Tx,
	userID uuid.UUID, amount money.Money) error {

	var (
		kycTier       int
		userCreatedAt time.Time
	)
	err := tx.QueryRow(ctx, `
		SELECT kyc_tier, created_at FROM users WHERE id = $1`,
		userID).Scan(&kycTier, &userCreatedAt)
	if err != nil {
		return fmt.Errorf("payment: read kyc tier: %w", err)
	}

	var (
		singleTxLimit int64
		dailyLimit    int64
		newCap        *int64
		newHours      int
	)
	err = tx.QueryRow(ctx, `
		SELECT single_tx_limit, daily_limit, new_account_cap, new_account_hours
		FROM transaction_limits
		WHERE kyc_tier = $1 AND currency = $2`,
		kycTier, string(amount.Currency),
	).Scan(&singleTxLimit, &dailyLimit, &newCap, &newHours)
	if err != nil {
		return fmt.Errorf("%w: no limit configured for tier %d currency %s",
			ErrLimitExceeded, kycTier, amount.Currency)
	}

	// 1. Single-transaction limit.
	if amount.Minor > singleTxLimit {
		return fmt.Errorf("%w: single-transaction limit of %d %s (attempted %d)",
			ErrLimitExceeded, singleTxLimit, amount.Currency, amount.Minor)
	}

	// 2. Daily limit: sum of debits in the last 24 hours across all
	//    of the user's wallets in this currency.
	var dailySum int64
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(SUM(-e.amount), 0)
		FROM ledger_entries e
		JOIN wallets w ON w.id = e.wallet_id
		WHERE w.user_id = $1
		  AND w.currency = $2
		  AND e.amount < 0
		  AND e.created_at > now() - interval '24 hours'`,
		userID, string(amount.Currency),
	).Scan(&dailySum)
	if err != nil {
		return fmt.Errorf("payment: read daily usage: %w", err)
	}
	if dailySum+amount.Minor > dailyLimit {
		return fmt.Errorf("%w: daily limit of %d %s exceeded (used %d, attempted %d)",
			ErrLimitExceeded, dailyLimit, amount.Currency, dailySum, amount.Minor)
	}

	// 3. New-account cap. CBN requires a per-transaction cap on
	//    newly activated accounts. We use user.created_at as the
	//    activation timestamp; adding a dedicated activated_at column
	//    would be more precise.
	if newCap != nil && time.Since(userCreatedAt) < time.Duration(newHours)*time.Hour {
		if dailySum+amount.Minor > *newCap {
			return fmt.Errorf("%w: new-account cap of %d %s exceeded within %d hours",
				ErrLimitExceeded, *newCap, amount.Currency, newHours)
		}
	}
	return nil
}

// idempotency helpers

type idemRecord struct {
	body []byte
}

func hashBody(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func reserveIdem(ctx context.Context, q db.Querier, key, hash string) (*idemRecord, error) {
	// Atomic reserve: INSERT first. On conflict (concurrent duplicate),
	// fall through to the SELECT below instead of letting both callers
	// proceed. The old SELECT-then-INSERT allowed two concurrent
	// requests with the same key to both insert and both execute.
	var inserted bool
	err := q.QueryRow(ctx, `
		INSERT INTO idempotency_keys (key, request_hash, expires_at)
		VALUES ($1, $2, now() + interval '24 hours')
		ON CONFLICT (key) DO NOTHING
		RETURNING true`, key, hash).Scan(&inserted)
	if err == nil && inserted {
		return nil, nil // we won the race; caller executes
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	var (
		storedHash string
		status     int
		body       []byte
	)
	err = q.QueryRow(ctx, `
		SELECT request_hash, COALESCE(response_status,0), COALESCE(response_body,'null'::jsonb)
		FROM idempotency_keys WHERE key = $1`, key,
	).Scan(&storedHash, &status, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		// Lost a race with an expirer/deleter; retry once via insert.
		_, err = q.Exec(ctx, `
			INSERT INTO idempotency_keys (key, request_hash, expires_at)
			VALUES ($1, $2, now() + interval '24 hours')
			ON CONFLICT (key) DO NOTHING`, key, hash)
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if storedHash != hash {
		return nil, errors.New("idempotency: key reused with different payload")
	}
	if status == 0 {
		return nil, errors.New("idempotency: request in flight")
	}
	return &idemRecord{body: body}, nil
}

func storeIdem(ctx context.Context, q db.Querier, key string, status int, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `
		UPDATE idempotency_keys SET response_status = $1, response_body = $2
		WHERE key = $3`, status, raw, key)
	return err
}
