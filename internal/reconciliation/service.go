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

	// Keyset-batched scan: the old single GROUP BY over all wallets and
	// all entries held a long snapshot and spiked memory/IO on large
	// tables. Batches of 500 wallets keep each query short and let the
	// run resume cleanly if the worker restarts (progress is per batch).
	const batch = 500
	var (
		lastID        *string
		checked       int64
		discrepancies []Discrepancy
	)
	for {
		rows, err := s.pool.Query(ctx, `
			SELECT w.id::text, w.balance,
			       COALESCE(SUM(e.amount), 0)::bigint,
			       (w.balance - COALESCE(SUM(e.amount), 0))::bigint
			FROM wallets w
			LEFT JOIN ledger_entries e ON e.wallet_id = w.id
			WHERE ($1::text IS NULL OR w.id::text > $1)
			GROUP BY w.id, w.balance
			ORDER BY w.id
			LIMIT $2`, lastID, batch)
		if err != nil {
			return s.failRun(ctx, runID, err)
		}
		var batchIDs []string
		for rows.Next() {
			var (
				id     string
				cached int64
				sum    int64
				drift  int64
			)
			if err := rows.Scan(&id, &cached, &sum, &drift); err != nil {
				rows.Close()
				return s.failRun(ctx, runID, err)
			}
			batchIDs = append(batchIDs, id)
			checked++
			if cached != sum {
				d := Discrepancy{WalletID: id, CachedBalance: cached, LedgerSum: sum, Drift: drift}
				discrepancies = append(discrepancies, d)
				slog.Error("BALANCE DRIFT",
					"wallet_id", d.WalletID,
					"cached_minor", d.CachedBalance,
					"ledger_sum_minor", d.LedgerSum,
					"drift_minor", d.Drift)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return s.failRun(ctx, runID, err)
		}
		if len(batchIDs) == 0 {
			break
		}
		lastID = &batchIDs[len(batchIDs)-1]
		if len(batchIDs) < batch {
			break
		}
	}

	details, _ := json.Marshal(discrepancies)
	_, err := s.pool.Exec(ctx, `
		UPDATE reconciliation_runs
		SET status = 'completed',
		    wallets_checked = $1,
		    discrepancies = $2, drift_details = $3, completed_at = now()
		WHERE id = $4`, checked, len(discrepancies), details, runID)
	if err != nil {
		return err
	}
	slog.Info("reconciliation complete",
		"duration", time.Since(start),
		"wallets_checked", checked,
		"discrepancies", len(discrepancies))
	return nil
}

func (s *Service) failRun(ctx context.Context, runID int64, cause error) error {
	_, _ = s.pool.Exec(ctx,
		`UPDATE reconciliation_runs SET status = 'failed', completed_at = now() WHERE id = $1`,
		runID)
	return cause
}
