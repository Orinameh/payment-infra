package snapshot

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service writes periodic per-wallet balance snapshots. Snapshots bound
// the cost of RebuildBalance (and reconciliation): instead of scanning
// every ledger entry since account creation, verification replays only
// entries after the latest snapshot's entry_id_upto.
type Service struct {
	pool  *pgxpool.Pool
	batch int
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, batch: 200}
}

func (s *Service) Run(ctx context.Context) error {
	start := time.Now()
	var (
		n        int
		lastID   uuid.UUID
		firstRun = true
	)
	for {
		rows, err := s.pool.Query(ctx, `
			SELECT id FROM wallets
			WHERE ($1 OR id > $2)
			ORDER BY id LIMIT $3`, firstRun, lastID, s.batch)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			break
		}
		firstRun = false
		for _, id := range ids {
			var sum, upto int64
			err := s.pool.QueryRow(ctx, `
				SELECT COALESCE(SUM(amount),0), COALESCE(MAX(id),0)
				FROM ledger_entries WHERE wallet_id = $1`, id,
			).Scan(&sum, &upto)
			if err != nil {
				return err
			}
			if _, err := s.pool.Exec(ctx, `
				INSERT INTO ledger_snapshots (wallet_id, snapshot_at, balance, entry_id_upto)
				VALUES ($1, now(), $2, $3)`, id, sum, upto); err != nil {
				return err
			}
			n++
			lastID = id
		}
	}
	slog.Info("snapshots complete", "wallets", n, "duration", time.Since(start))
	return nil
}
