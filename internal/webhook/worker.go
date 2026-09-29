package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"payment-infra/internal/crypto"
	"payment-infra/internal/platform/db"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnqueueForEvent fans a consumed event out to every active endpoint
// subscribed to it. Called from the queue consumer (at-least-once by
// design — the UNIQUE on (endpoint_id, event dedup) is not enforced,
// so identical redeliveries can enqueue duplicates; the delivery worker
// signs each attempt with its delivery id so receivers can dedup).
func EnqueueForEvent(ctx context.Context, q db.Querier, eventType string, payload []byte) error {
	rows, err := q.Query(ctx, `
		SELECT id FROM webhook_endpoints
		WHERE status = 'active'
		  AND (event_types = '{}' OR $1 = ANY(event_types))
		  AND (circuit_state = 'closed'
		       OR (circuit_state = 'half_open')
		       OR (circuit_state = 'open' AND circuit_opened_at < now() - interval '5 minutes'))`,
		eventType)
	if err != nil {
		return fmt.Errorf("webhook: list endpoints: %w", err)
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
	for _, id := range ids {
		if _, err := q.Exec(ctx, `
			INSERT INTO webhook_deliveries (endpoint_id, event_type, payload)
			VALUES ($1, $2, $3)`, id, eventType, payload); err != nil {
			return fmt.Errorf("webhook: enqueue: %w", err)
		}
	}
	return nil
}

// Backoff returns the delay before attempt n (1-based). Exponential
// with a 24h cap: 1m, 5m, 15m, 1h, 4h, 12h, 24h, 24h...
func Backoff(attempt int) time.Duration {
	steps := []time.Duration{
		time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour,
		4 * time.Hour, 12 * time.Hour, 24 * time.Hour,
	}
	if attempt <= 1 {
		return steps[0]
	}
	if attempt > len(steps) {
		return 24 * time.Hour
	}
	return steps[attempt-1]
}

type Worker struct {
	pool     *pgxpool.Pool
	enc      *crypto.Encryptor
	client   *http.Client
	batch    int
	interval time.Duration
	failOpen int // consecutive failures before opening an endpoint circuit
}

func NewWorker(pool *pgxpool.Pool, enc *crypto.Encryptor) *Worker {
	return &Worker{
		pool: pool, enc: enc,
		client:   &http.Client{Timeout: 10 * time.Second},
		batch:    20,
		interval: 5 * time.Second,
		failOpen: 5,
	}
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
				slog.Error("webhook drain", "err", err)
			}
		}
	}
}

type delivery struct {
	id         int64
	endpointID uuid.UUID
	url        string
	secret     []byte
	eventType  string
	payload    []byte
	attempts   int
	maxAttempt int
}

func (w *Worker) drain(ctx context.Context) error {
	var due []delivery
	err := db.WithTx(ctx, w.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT d.id, d.endpoint_id, e.url, e.secret_encrypted,
			       d.event_type, d.payload, d.attempts, d.max_attempts
			FROM webhook_deliveries d
			JOIN webhook_endpoints e ON e.id = d.endpoint_id
			WHERE d.status = 'pending'
			  AND d.next_attempt_at <= now()
			  AND d.locked_until IS NULL
			  AND e.status = 'active'
			  AND (e.circuit_state IN ('closed','half_open')
			       OR e.circuit_opened_at < now() - interval '5 minutes')
			ORDER BY d.next_attempt_at
			LIMIT $1
			FOR UPDATE OF d SKIP LOCKED`, w.batch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				d  delivery
				ct []byte
			)
			if err := rows.Scan(&d.id, &d.endpointID, &d.url, &ct,
				&d.eventType, &d.payload, &d.attempts, &d.maxAttempt); err != nil {
				return err
			}
			secret, err := w.enc.Decrypt(ct)
			if err != nil {
				return fmt.Errorf("webhook: decrypt secret for %s: %w", d.endpointID, err)
			}
			d.secret = secret
			due = append(due, d)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// Hold the claim while we deliver outside the tx.
		for _, d := range due {
			if _, err := tx.Exec(ctx,
				`UPDATE webhook_deliveries SET locked_until = now() + interval '2 minutes' WHERE id = $1`,
				d.id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, d := range due {
		w.deliver(ctx, d)
	}
	return nil
}

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (w *Worker) deliver(ctx context.Context, d delivery) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(d.payload))
	if err != nil {
		w.fail(ctx, d, 0, "bad request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Event", d.eventType)
	req.Header.Set("X-Webhook-Delivery", fmt.Sprintf("%d", d.id))
	req.Header.Set("X-Webhook-Signature", sign(d.secret, d.payload))

	resp, err := w.client.Do(req)
	if err != nil {
		w.fail(ctx, d, 0, "transport: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, err := w.pool.Exec(ctx, `
			UPDATE webhook_deliveries
			SET status = 'delivered', delivered_at = now(), locked_until = NULL,
			    attempts = attempts + 1, response_status = $1
			WHERE id = $2`, resp.StatusCode, d.id)
		if err != nil {
			slog.Error("webhook mark delivered", "err", err, "id", d.id)
		}
		// Success closes a half-open circuit.
		_, _ = w.pool.Exec(ctx,
			`UPDATE webhook_endpoints SET circuit_state = 'closed', circuit_opened_at = NULL
			 WHERE id = $1 AND circuit_state <> 'closed'`, d.endpointID)
		return
	}
	w.fail(ctx, d, resp.StatusCode, "unexpected status")
}

func (w *Worker) fail(ctx context.Context, d delivery, status int, body string) {
	attempts := d.attempts + 1
	if attempts >= d.maxAttempt {
		_, err := w.pool.Exec(ctx, `
			UPDATE webhook_deliveries
			SET status = 'dead_letter', locked_until = NULL,
			    attempts = $1, response_status = $2, response_body = $3
			WHERE id = $4`, attempts, status, body, d.id)
		if err != nil {
			slog.Error("webhook dead letter", "err", err, "id", d.id)
		}
		_, _ = w.pool.Exec(ctx,
			`UPDATE webhook_endpoints SET circuit_state = 'open', circuit_opened_at = now()
			 WHERE id = $1`, d.endpointID)
		return
	}
	next := time.Now().Add(Backoff(attempts))
	_, err := w.pool.Exec(ctx, `
		UPDATE webhook_deliveries
		SET attempts = $1, next_attempt_at = $2, locked_until = NULL,
		    response_status = $3, response_body = $4
		WHERE id = $5`, attempts, next, status, body, d.id)
	if err != nil {
		slog.Error("webhook reschedule", "err", err, "id", d.id)
	}
	// Track consecutive failures toward the circuit breaker.
	var consecutive int
	_ = w.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_deliveries
		  WHERE endpoint_id = $1 AND status = 'pending' AND attempts > 0`,
		d.endpointID).Scan(&consecutive)
	if consecutive >= w.failOpen {
		_, _ = w.pool.Exec(ctx,
			`UPDATE webhook_endpoints SET circuit_state = 'half_open', circuit_opened_at = now()
			 WHERE id = $1 AND circuit_state = 'closed'`, d.endpointID)
	}
}
