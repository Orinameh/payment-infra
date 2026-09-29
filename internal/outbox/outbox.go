package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"payment-infra/internal/platform/db"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Writer struct{}

func (Writer) Emit(ctx context.Context, q db.Querier, aggType string,
	aggID uuid.UUID, eventType string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `
		INSERT INTO outbox (aggregate_type, aggregate_id, event_type, payload)
		VALUES ($1, $2, $3, $4)`,
		aggType, aggID, eventType, raw)
	return err
}

type Publisher interface {
	Publish(ctx context.Context, subject, key string, payload []byte) error
}

type Worker struct {
	pool      *pgxpool.Pool
	publisher Publisher
	batch     int
	interval  time.Duration
}

func NewWorker(pool *pgxpool.Pool, pub Publisher) *Worker {
	return &Worker{pool: pool, publisher: pub, batch: 100, interval: 500 * time.Millisecond}
}

func (w *Worker) Run(ctx context.Context) error {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := w.drain(ctx); err != nil {
				slog.Error("outbox drain", "err", err)
			}
		}
	}
}

func (w *Worker) drain(ctx context.Context) error {
	return db.WithTx(ctx, w.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, event_type, payload FROM outbox
			WHERE published_at IS NULL
			ORDER BY id LIMIT $1
			FOR UPDATE SKIP LOCKED`, w.batch)
		if err != nil {
			return err
		}
		type ev struct {
			ID        int64
			EventType string
			Payload   []byte
		}
		var events []ev
		for rows.Next() {
			var e ev
			if err := rows.Scan(&e.ID, &e.EventType, &e.Payload); err != nil {
				rows.Close()
				return err
			}
			events = append(events, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}

		ids := make([]int64, 0, len(events))
		for _, e := range events {
			if err := w.publisher.Publish(ctx, e.EventType,
				fmt.Sprintf("outbox-%d", e.ID), e.Payload); err != nil {
				return fmt.Errorf("publish %d: %w", e.ID, err)
			}
			ids = append(ids, e.ID)
		}
		_, err = tx.Exec(ctx,
			`UPDATE outbox SET published_at = now() WHERE id = ANY($1)`, ids)
		return err
	})
}
