package reconciliation

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct{ pool *pgxpool.Pool }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

type Discrepancy struct {
	WalletID      string `json:"wallet_id"`
	CachedBalance int64  `json:"cached_balance_minor"`
	LedgerSum     int64  `json:"ledger_sum_minor"`
	Drift         int64  `json:"drift_minor"`
}

func (s *Service) Run(ctx context.Context) error {
	start := time.Now()
	var runID int64
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO reconciliation_runs (status) VALUES ('running') RETURNING id`,
	).Scan(&runID); err != nil {
		return err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT w.id,
		       w.balance,
		       COALESCE(SUM(e.amount), 0)::bigint,
		       (w.balance - COALESCE(SUM(e.amount), 0))::bigint
		FROM wallets w
		LEFT JOIN ledger_entries e ON e.wallet_id = w.id
		GROUP BY w.id, w.balance
		HAVING w.balance <> COALESCE(SUM(e.amount), 0)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var discrepancies []Discrepancy
	for rows.Next() {
		var d Discrepancy
		if err := rows.Scan(&d.WalletID, &d.CachedBalance, &d.LedgerSum, &d.Drift); err != nil {
			return err
		}
		discrepancies = append(discrepancies, d)
		slog.Error("BALANCE DRIFT",
			"wallet_id", d.WalletID,
			"cached_minor", d.CachedBalance,
			"ledger_sum_minor", d.LedgerSum,
			"drift_minor", d.Drift)
	}

	details, _ := json.Marshal(discrepancies)
	_, err = s.pool.Exec(ctx, `
		UPDATE reconciliation_runs
		SET status = 'completed',
		    wallets_checked = (SELECT COUNT(*) FROM wallets),
		    discrepancies = $1, drift_details = $2, completed_at = now()
		WHERE id = $3`, len(discrepancies), details, runID)
	if err != nil {
		return err
	}
	slog.Info("reconciliation complete",
		"duration", time.Since(start),
		"discrepancies", len(discrepancies))
	return nil
}
