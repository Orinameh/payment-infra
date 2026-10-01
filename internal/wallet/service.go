package wallet

import (
	"context"
	"errors"
	"fmt"
	"payment-infra/internal/audit"
	"payment-infra/internal/cache"
	"payment-infra/internal/httpx"
	"payment-infra/internal/money"
	"payment-infra/internal/nuban"
	"payment-infra/internal/platform/db"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNotFound          = errors.New("wallet: not found")
	ErrInsufficientFunds = errors.New("wallet: insufficient funds")
	ErrFrozen            = errors.New("wallet: frozen")
	ErrCurrencyMismatch  = errors.New("wallet: currency mismatch")
	ErrStaleVersion      = errors.New("wallet: stale version")
)

type Wallet struct {
	ID       uuid.UUID `json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	Currency string    `json:"currency"`
	Balance  int64     `json:"balance_minor"`
	Version  int64     `json:"version"`
	Status   string    `json:"status"`
	// AccountNumber is the wallet's virtual NUBAN (nullable for rows
	// created before numbering; the backfill closes that gap).
	AccountNumber *string   `json:"account_number,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Service struct {
	audit *audit.Recorder
	cache *cache.WalletCache
	// bankCode roots generated NUBANs (our CBN institution code).
	// Empty disables numbering (tests, numbering-free deploys).
	bankCode string
}

func NewService(a *audit.Recorder) *Service { return &Service{audit: a} }

// SetBankCode enables virtual-NUBAN assignment on Create and backfill.
func (s *Service) SetBankCode(code string) { s.bankCode = code }

// SetCache enables the Redis cache-aside read path. Nil (default)
// means every read hits PostgreSQL. The cache is best-effort:
// invalidation failures self-heal at TTL expiry, and PostgreSQL
// remains the source of truth.
func (s *Service) SetCache(c *cache.WalletCache) { s.cache = c }

func (s *Service) invalidate(ctx context.Context, ids ...uuid.UUID) {
	if s.cache != nil {
		s.cache.DelWallets(ctx, ids...)
	}
}

// EnsureAccountNumber returns the wallet's NUBAN, assigning one if
// numbering is enabled and the row predates it. Used on rails (bank
// transfer) that must present a source account number.
func (s *Service) EnsureAccountNumber(ctx context.Context, q db.Querier, id uuid.UUID) (string, error) {
	var acct *string
	if err := q.QueryRow(ctx,
		`SELECT account_number FROM wallets WHERE id = $1`, id,
	).Scan(&acct); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	if acct != nil {
		return *acct, nil
	}
	if s.bankCode == "" {
		return "", fmt.Errorf("wallet: numbering disabled, no account number")
	}
	for attempt := 0; attempt < 5; attempt++ {
		n, err := nuban.Generate(s.bankCode)
		if err != nil {
			return "", err
		}
		tag, err := q.Exec(ctx, `
			UPDATE wallets SET account_number = $1, updated_at = now()
			WHERE id = $2 AND account_number IS NULL`, n, id)
		if err != nil {
			if db.IsUniqueViolation(err) {
				continue
			}
			return "", err
		}
		if tag.RowsAffected() == 1 {
			s.invalidate(ctx, id)
			return n, nil
		}
		// Someone else numbered it concurrently; read back.
		if err := q.QueryRow(ctx,
			`SELECT account_number FROM wallets WHERE id = $1`, id,
		).Scan(&acct); err != nil {
			return "", err
		}
		if acct != nil {
			return *acct, nil
		}
	}
	return "", fmt.Errorf("wallet: account number collisions")
}

// GetByAccountNumber resolves a virtual NUBAN to its wallet. Used by
// name enquiry and inbound matching.
func (s *Service) GetByAccountNumber(ctx context.Context, q db.Querier, accountNumber string) (*Wallet, error) {
	var w Wallet
	err := q.QueryRow(ctx, `
		SELECT id, user_id, currency, balance, version, status, account_number, created_at, updated_at
		FROM wallets WHERE account_number = $1`, accountNumber,
	).Scan(&w.ID, &w.UserID, &w.Currency, &w.Balance, &w.Version, &w.Status,
		&w.AccountNumber, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &w, err
}

// GetCached serves balance reads from Redis when possible, falling
// back to PostgreSQL on a miss. Use for display/read endpoints only —
// transactional code (Debit/Credit/Transfer) must use lock + Get so it
// never acts on a stale balance.
func (s *Service) GetCached(ctx context.Context, q db.Querier, id uuid.UUID) (*Wallet, error) {
	if s.cache != nil {
		if cw, ok := s.cache.GetWallet(ctx, id); ok {
			return &Wallet{
				ID: cw.ID, UserID: cw.UserID, Currency: cw.Currency,
				Balance: cw.Balance, Version: cw.Version, Status: cw.Status,
				AccountNumber: cw.AccountNumber,
			}, nil
		}
	}
	w, err := s.Get(ctx, q, id)
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		s.cache.SetWallet(ctx, &cache.CachedWallet{
			ID: w.ID, UserID: w.UserID, Currency: w.Currency,
			Balance: w.Balance, Version: w.Version, Status: w.Status,
			AccountNumber: w.AccountNumber,
		})
	}
	return w, nil
}

func (s *Service) Create(ctx context.Context, q db.Querier, userID uuid.UUID, currency string) (*Wallet, error) {
	// Numbered wallets retry generation on the (negligible but
	// possible) account_number collision. The (user_id, currency)
	// conflict is absorbed by ON CONFLICT and returns the existing row.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		var acct *string
		if s.bankCode != "" {
			n, err := nuban.Generate(s.bankCode)
			if err != nil {
				return nil, err
			}
			acct = &n
		}
		var w Wallet
		err := q.QueryRow(ctx, `
			INSERT INTO wallets (user_id, currency, account_number)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, currency) DO UPDATE SET updated_at = wallets.updated_at
			RETURNING id, user_id, currency, balance, version, status, account_number, created_at, updated_at`,
			userID, currency, acct,
		).Scan(&w.ID, &w.UserID, &w.Currency, &w.Balance, &w.Version, &w.Status,
			&w.AccountNumber, &w.CreatedAt, &w.UpdatedAt)
		if err == nil {
			return &w, nil
		}
		// Only an account_number collision is retryable here; the
		// currency conflict never errors (ON CONFLICT absorbs it).
		if acct != nil && db.IsUniqueViolation(err) {
			lastErr = err
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("wallet: account number collisions: %w", lastErr)
}

// BackfillAccountNumbers assigns NUBANs to pre-numbering wallets in
// small batches. Idempotent and safe to run hourly; returns the count
// assigned this call (0 when caught up). No-op without a bank code.
func (s *Service) BackfillAccountNumbers(ctx context.Context, q db.Querier, batch int) (int, error) {
	if s.bankCode == "" {
		return 0, nil
	}
	if batch <= 0 || batch > 100 {
		batch = 20
	}
	rows, err := q.Query(ctx, `
		SELECT id FROM wallets
		WHERE account_number IS NULL
		ORDER BY created_at LIMIT $1`, batch)
	if err != nil {
		return 0, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	assigned := 0
	for _, id := range ids {
		for attempt := 0; attempt < 5; attempt++ {
			n, err := nuban.Generate(s.bankCode)
			if err != nil {
				return assigned, err
			}
			tag, err := q.Exec(ctx, `
				UPDATE wallets SET account_number = $1, updated_at = now()
				WHERE id = $2 AND account_number IS NULL`, n, id)
			if err != nil {
				if db.IsUniqueViolation(err) {
					continue
				}
				return assigned, err
			}
			if tag.RowsAffected() == 1 {
				assigned++
				s.invalidate(ctx, id)
			}
			break
		}
	}
	return assigned, nil
}

func (s *Service) Get(ctx context.Context, q db.Querier, id uuid.UUID) (*Wallet, error) {
	var w Wallet
	err := q.QueryRow(ctx, `
		SELECT id, user_id, currency, balance, version, status, account_number, created_at, updated_at
		FROM wallets WHERE id = $1`, id,
	).Scan(&w.ID, &w.UserID, &w.Currency, &w.Balance, &w.Version, &w.Status,
		&w.AccountNumber, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &w, err
}

func (s *Service) ListByUser(ctx context.Context, q db.Querier, userID uuid.UUID) ([]Wallet, error) {
	rows, err := q.Query(ctx, `
		SELECT id, user_id, currency, balance, version, status, account_number, created_at, updated_at
		FROM wallets WHERE user_id = $1 ORDER BY currency`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Wallet
	for rows.Next() {
		var w Wallet
		if err := rows.Scan(&w.ID, &w.UserID, &w.Currency, &w.Balance, &w.Version,
			&w.Status, &w.AccountNumber, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// lock acquires a row lock. Any concurrent transaction attempting
// Debit, Credit, or Transfer on the same wallet blocks here until this
// transaction commits. This is the primary defense against the
// double-withdrawal race.
func (s *Service) lock(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*Wallet, error) {
	var w Wallet
	err := tx.QueryRow(ctx, `
		SELECT id, user_id, currency, balance, version, status, account_number, created_at, updated_at
		FROM wallets WHERE id = $1 FOR UPDATE`, id,
	).Scan(&w.ID, &w.UserID, &w.Currency, &w.Balance, &w.Version, &w.Status,
		&w.AccountNumber, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &w, err
}

func (s *Service) lockMany(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID]*Wallet, error) {
	sorted := append([]uuid.UUID(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })

	rows, err := tx.Query(ctx, `
		SELECT id, user_id, currency, balance, version, status, account_number, created_at, updated_at
		FROM wallets WHERE id = ANY($1) ORDER BY id FOR UPDATE`, sorted)
	if err != nil {
		return nil, fmt.Errorf("wallet: lock many: %w", err)
	}
	defer rows.Close()

	out := make(map[uuid.UUID]*Wallet, len(sorted))
	for rows.Next() {
		var w Wallet
		if err := rows.Scan(&w.ID, &w.UserID, &w.Currency, &w.Balance, &w.Version,
			&w.Status, &w.AccountNumber, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, err
		}
		out[w.ID] = &w
	}
	return out, rows.Err()
}

// applyDelta performs the write with an OCC version guard. The WHERE
// clause on version ensures a writer that somehow bypassed the lock
// still cannot apply a stale update.
func (s *Service) applyDelta(ctx context.Context, q db.Querier,
	id uuid.UUID, delta int64, expectedVersion int64) error {

	tag, err := q.Exec(ctx, `
		UPDATE wallets
		SET balance = balance + $1, version = version + 1, updated_at = now()
		WHERE id = $2 AND version = $3`,
		delta, id, expectedVersion)
	if err != nil {
		// CHECK (balance >= 0) fires here as SQLSTATE 23514.
		if db.IsCheckViolation(err) {
			return ErrInsufficientFunds
		}
		return fmt.Errorf("wallet: apply delta: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleVersion
	}
	return nil
}

// Debit withdraws from a wallet. Must be called inside a transaction.
func (s *Service) Debit(ctx context.Context, tx pgx.Tx,
	id uuid.UUID, amount money.Money, reason string, actorID uuid.UUID) (*Wallet, error) {

	if err := amount.RequirePositive(); err != nil {
		return nil, err
	}

	w, err := s.lock(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if w.Status != "active" {
		return nil, ErrFrozen
	}
	if w.Currency != string(amount.Currency) {
		return nil, ErrCurrencyMismatch
	}
	if w.Balance < amount.Minor {
		return nil, ErrInsufficientFunds
	}

	if err := s.applyDelta(ctx, tx, id, -amount.Minor, w.Version); err != nil {
		return nil, err
	}
	s.invalidate(ctx, id)

	w.Balance -= amount.Minor
	w.Version++

	if s.audit != nil {
		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorID: actorID, ActorType: "user",
			Action: "wallet.debit", EntityType: "wallet", EntityID: id,
			RequestID: httpx.RequestIDFrom(ctx),
			Metadata: map[string]any{
				"amount_minor":  amount.Minor,
				"currency":      w.Currency,
				"reason":        reason,
				"balance_after": w.Balance,
			},
		}); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func (s *Service) Credit(ctx context.Context, tx pgx.Tx,
	id uuid.UUID, amount money.Money, reason string, actorID uuid.UUID) (*Wallet, error) {

	if err := amount.RequirePositive(); err != nil {
		return nil, err
	}

	w, err := s.lock(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if w.Status != "active" {
		return nil, ErrFrozen
	}
	if w.Currency != string(amount.Currency) {
		return nil, ErrCurrencyMismatch
	}

	if err := s.applyDelta(ctx, tx, id, amount.Minor, w.Version); err != nil {
		return nil, err
	}
	s.invalidate(ctx, id)

	w.Balance += amount.Minor
	w.Version++

	if s.audit != nil {
		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorID: actorID, ActorType: "user",
			Action: "wallet.credit", EntityType: "wallet", EntityID: id,
			RequestID: httpx.RequestIDFrom(ctx),
			Metadata: map[string]any{
				"amount_minor":  amount.Minor,
				"currency":      w.Currency,
				"reason":        reason,
				"balance_after": w.Balance,
			},
		}); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// TransferPrecheck runs after wallet locks are acquired but before
// deltas are applied. It receives the transaction, the source wallet
// ID, and the amount. Return a non-nil error to abort the transfer.
//
// This is the correct place to enforce limits that depend on the
// source wallet's locked state (e.g., daily transaction totals).
type TransferPrecheck func(ctx context.Context, tx pgx.Tx,
	sourceWalletID uuid.UUID, amount money.Money) error

type transferConfig struct {
	precheck TransferPrecheck
}

type TransferOption func(*transferConfig)

func WithPrecheck(p TransferPrecheck) TransferOption {
	return func(c *transferConfig) { c.precheck = p }
}

// Transfer moves funds between two wallets atomically. Locks both in
// ascending id order to prevent deadlock when A→B and B→A arrive
// concurrently.
func (s *Service) Transfer(ctx context.Context, tx pgx.Tx,
	fromID, toID uuid.UUID, amount money.Money, reason string, actorID uuid.UUID,
	opts ...TransferOption) error {

	if fromID == toID {
		return errors.New("wallet: from and to must differ")
	}
	if err := amount.RequirePositive(); err != nil {
		return err
	}

	cfg := &transferConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Acquire locks in deterministic (ascending id) order.
	wallets, err := s.lockMany(ctx, tx, []uuid.UUID{fromID, toID})
	if err != nil {
		return err
	}
	from, ok := wallets[fromID]
	if !ok {
		return ErrNotFound
	}
	to, ok := wallets[toID]
	if !ok {
		return ErrNotFound
	}

	// Precheck runs while the source wallet is locked. Two concurrent
	// transfers on the same source cannot both pass a limit check.
	if cfg.precheck != nil {
		if err := cfg.precheck(ctx, tx, fromID, amount); err != nil {
			return err
		}
	}

	if from.Status != "active" || to.Status != "active" {
		return ErrFrozen
	}
	if from.Currency != to.Currency {
		return ErrCurrencyMismatch
	}
	if from.Currency != string(amount.Currency) {
		return ErrCurrencyMismatch
	}
	if from.Balance < amount.Minor {
		return ErrInsufficientFunds
	}

	if err := s.applyDelta(ctx, tx, fromID, -amount.Minor, from.Version); err != nil {
		return err
	}
	if err := s.applyDelta(ctx, tx, toID, amount.Minor, to.Version); err != nil {
		return err
	}
	s.invalidate(ctx, fromID, toID)

	if s.audit != nil {
		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorID: actorID, ActorType: "user",
			Action: "wallet.transfer", EntityType: "wallet", EntityID: fromID,
			RequestID: httpx.RequestIDFrom(ctx),
			Metadata: map[string]any{
				"from":          fromID.String(),
				"to":            toID.String(),
				"amount_minor":  amount.Minor,
				"currency":      from.Currency,
				"reason":        reason,
				"balance_after": from.Balance - amount.Minor,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}
