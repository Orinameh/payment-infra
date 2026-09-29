package ledger

import (
	"context"
	"errors"
	"fmt"
	"payment-infra/internal/platform/db"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrUnbalanced       = errors.New("ledger: entries do not balance to zero")
	ErrTooFewEntries    = errors.New("ledger: at least two entries required")
	ErrCurrencyMismatch = errors.New("ledger: mixed currencies in one transaction")
	ErrEmptyAmount      = errors.New("ledger: entry amount is zero")
)

type Entry struct {
	WalletID uuid.UUID
	Amount   int64 // signed, minor units
	Currency string
}

type PostRequest struct {
	Type       string
	Reference  string
	EndToEndID string
	Metadata   map[string]any
	Entries    []Entry
}

func (r PostRequest) Validate() error {
	if len(r.Entries) < 2 {
		return ErrTooFewEntries
	}
	currency := r.Entries[0].Currency
	var sum int64
	for _, e := range r.Entries {
		if e.Currency != currency {
			return ErrCurrencyMismatch
		}
		if e.Amount == 0 {
			return ErrEmptyAmount
		}
		sum += e.Amount
	}
	if sum != 0 {
		return ErrUnbalanced
	}
	return nil
}

type Service struct{}

func NewService() *Service { return &Service{} }

func (s *Service) Post(ctx context.Context, tx pgx.Tx, req PostRequest) (uuid.UUID, error) {
	if err := req.Validate(); err != nil {
		return uuid.Nil, err
	}

	meta := req.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	currency := req.Entries[0].Currency

	var txID uuid.UUID
	err := tx.QueryRow(ctx, `
		INSERT INTO transactions (type, status, reference, end_to_end_id,
		                          total_minor, currency, metadata, posted_at)
		VALUES ($1, 'posted', $2, $3, $4, $5, $6, now())
		RETURNING id`,
		req.Type, req.Reference, req.EndToEndID,
		absSum(req.Entries)/2,
		currency, meta,
	).Scan(&txID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("ledger: insert transaction: %w", err)
	}

	// Batch insert entries.
	walletIDs := make([]uuid.UUID, len(req.Entries))
	amounts := make([]int64, len(req.Entries))
	currencies := make([]string, len(req.Entries))
	for i, e := range req.Entries {
		walletIDs[i] = e.WalletID
		amounts[i] = e.Amount
		currencies[i] = e.Currency
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO ledger_entries (transaction_id, wallet_id, amount, currency)
		SELECT $1, w, a, c
		FROM unnest($2::uuid[], $3::bigint[], $4::char(3)[]) AS t(w, a, c)`,
		txID, walletIDs, amounts, currencies)
	if err != nil {
		return uuid.Nil, fmt.Errorf("ledger: insert entries: %w", err)
	}
	return txID, nil
}

func absSum(entries []Entry) int64 {
	var s int64
	for _, e := range entries {
		if e.Amount > 0 {
			s += e.Amount
		}
	}
	return s
}

type HistoryEntry struct {
	TransactionID uuid.UUID `json:"transaction_id"`
	Type          string    `json:"type"`
	Reference     string    `json:"reference,omitempty"`
	AmountMinor   int64     `json:"amount_minor"`
	Currency      string    `json:"currency"`
	CreatedAt     time.Time `json:"created_at"`
}

func (s *Service) History(ctx context.Context, q db.Querier,
	walletID uuid.UUID, limit, offset int) ([]HistoryEntry, error) {

	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := q.Query(ctx, `
		SELECT t.id, t.type, COALESCE(t.reference,''), e.amount, e.currency, e.created_at
		FROM ledger_entries e
		JOIN transactions t ON t.id = e.transaction_id
		WHERE e.wallet_id = $1
		ORDER BY e.id DESC
		LIMIT $2 OFFSET $3`, walletID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HistoryEntry
	for rows.Next() {
		var h HistoryEntry
		if err := rows.Scan(&h.TransactionID, &h.Type, &h.Reference,
			&h.AmountMinor, &h.Currency, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RebuildBalance recomputes a wallet balance from the ledger. It replays
// only entries after the latest snapshot (see internal/snapshot), so the
// cost is O(entries since snapshot) instead of O(all entries). With no
// snapshot yet it falls back to a full sum.
func (s *Service) RebuildBalance(ctx context.Context, q db.Querier, walletID uuid.UUID) (int64, error) {
	var (
		snapBalance int64
		upto        int64
		hasSnap     bool
	)
	err := q.QueryRow(ctx, `
		SELECT balance, entry_id_upto FROM ledger_snapshots
		WHERE wallet_id = $1 ORDER BY snapshot_at DESC LIMIT 1`,
		walletID).Scan(&snapBalance, &upto)
	switch {
	case err == nil:
		hasSnap = true
	case err == pgx.ErrNoRows:
		// No snapshot: full replay below.
	default:
		return 0, err
	}
	var tail int64
	if hasSnap {
		err = q.QueryRow(ctx, `
			SELECT COALESCE(SUM(amount), 0) FROM ledger_entries
			WHERE wallet_id = $1 AND id > $2`, walletID, upto).Scan(&tail)
	} else {
		err = q.QueryRow(ctx, `
			SELECT COALESCE(SUM(amount), 0) FROM ledger_entries WHERE wallet_id = $1`,
			walletID).Scan(&tail)
	}
	if err != nil {
		return 0, err
	}
	return snapBalance + tail, nil
}
