package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Service prunes operational tables whose growth is otherwise
// unbounded. Windows are chosen so pruning can never resurrect work:
//
//   - processed_messages (30d): dedup duplicates arrive within minutes
//     of first delivery (AckWait/MaxDeliver), never weeks later.
//   - outbox published rows (30d): already on NATS (180d stream
//     retention); the table is a buffer, not an archive.
//   - webhook deliveries terminal rows (90d).
//   - expired idempotency keys, spent verification tokens (7d),
//     dead refresh tokens (60d), old reconciliation runs (180d).
//
// Ledger, transactions, AML alerts, and audit rows are NEVER pruned
// (5-year AML retention).
type Service struct{ pool *pgxpool.Pool }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Run(ctx context.Context) error {
	jobs := []struct {
		name string
		sql  string
	}{
		{"outbox", `DELETE FROM outbox WHERE published_at IS NOT NULL AND published_at < now() - interval '30 days'`},
		{"processed_messages", `DELETE FROM processed_messages WHERE processed_at < now() - interval '30 days'`},
		{"webhook_deliveries", `DELETE FROM webhook_deliveries WHERE status IN ('delivered','dead_letter') AND created_at < now() - interval '90 days'`},
		{"idempotency_keys", `DELETE FROM idempotency_keys WHERE expires_at < now()`},
		{"verification_tokens", `DELETE FROM verification_tokens WHERE (consumed_at IS NOT NULL OR expires_at < now()) AND created_at < now() - interval '7 days'`},
		{"refresh_tokens", `DELETE FROM refresh_tokens WHERE (revoked_at IS NOT NULL OR expires_at < now()) AND created_at < now() - interval '60 days'`},
		{"reconciliation_runs", `DELETE FROM reconciliation_runs WHERE completed_at IS NOT NULL AND completed_at < now() - interval '180 days'`},
	}
	for _, j := range jobs {
		tag, err := s.pool.Exec(ctx, j.sql)
		if err != nil {
			return err
		}
		if n := tag.RowsAffected(); n > 0 {
			slog.Info("retention pruned", "table", j.name, "rows", n)
		}
	}
	return nil
}

// RunLoop ticks hourly until ctx is cancelled. Run it in the worker.
func (s *Service) RunLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Run(ctx); err != nil {
				slog.Error("retention", "err", err)
			}
		}
	}
}
