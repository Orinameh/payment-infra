package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"payment-infra/internal/audit"
	"payment-infra/internal/crypto"
	"payment-infra/internal/outbox"
	"payment-infra/internal/platform/db"
	"payment-infra/internal/queue"
	"payment-infra/internal/reconciliation"
	"payment-infra/internal/retention"
	"payment-infra/internal/snapshot"
	"payment-infra/internal/wallet"
	"payment-infra/internal/webhook"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, os.Getenv("DATABASE_URL"), 10)
	if err != nil {
		logger.Error("db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	pub, err := queue.NewPublisher(ctx, queue.NATSConfig{
		URL:        envOr("NATS_URL", "nats://localhost:4222"),
		StreamName: "PAYMENTS",
		Subjects:   []string{"payments.>"},
		MaxAge:     180 * 24 * time.Hour, // CBN retention
		MaxBytes:   10 * 1024 * 1024 * 1024,
		Replicas:   1,
	})
	if err != nil {
		logger.Error("nats", "err", err)
		os.Exit(1)
	}
	defer pub.Close()

	go func() {
		if err := outbox.NewWorker(pool, pub).Run(ctx); err != nil {
			logger.Error("outbox", "err", err)
		}
	}()

	consumer, err := queue.NewConsumer(pool, queue.ConsumerConfig{
		URL:      envOr("NATS_URL", "nats://localhost:4222"),
		Stream:   "PAYMENTS",
		Durable:  "payments-worker",
		Subjects: []string{"payments.>"},
	}, func(ctx context.Context, subject string, payload []byte) error {
		return dispatchEvent(ctx, pool, subject, payload)
	})
	if err != nil {
		logger.Error("consumer", "err", err)
		os.Exit(1)
	}
	defer consumer.Close()

	go func() {
		if err := consumer.Run(ctx); err != nil {
			logger.Error("consumer", "err", err)
		}
	}()

	// Webhook delivery needs the keyring to decrypt endpoint HMAC
	// secrets (any generation, via envelope key ids).
	enc, err := crypto.NewKeyRingFromEnv()
	if err != nil {
		logger.Error("encryption keyring", "err", err)
		os.Exit(1)
	}
	logger.Info("encryption keyring ready", "active", enc.ActiveID())
	go func() {
		if err := webhook.NewWorker(pool, enc).Run(ctx); err != nil {
			logger.Error("webhook", "err", err)
		}
	}()

	reconSvc := reconciliation.NewService(pool)

	// NUBAN backfill shares the wallet service (bank code from env).
	walletSvc := wallet.NewService(&audit.Recorder{})
	if code := os.Getenv("BANK_CODE"); code != "" {
		walletSvc.SetBankCode(code)
	}

	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := reconSvc.Run(ctx); err != nil {
					logger.Error("reconciliation", "err", err)
				}
			}
		}
	}()

	snapSvc := snapshot.NewService(pool)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := snapSvc.Run(ctx); err != nil {
					logger.Error("snapshots", "err", err)
				}
			}
		}
	}()

	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if broken, err := audit.VerifyChain(ctx, pool); err != nil {
					logger.Error("audit verify", "err", err)
				} else if broken != nil {
					logger.Error("AUDIT CHAIN BROKEN",
						"id", broken.ID, "reason", broken.Reason)
				}
			}
		}
	}()

	// Retention never touches money tables — only operational buffers.
	go retention.NewService(pool).RunLoop(ctx, time.Hour)

	// NUBAN backfill for pre-numbering wallets. Self-terminating:
	// each run assigns a batch until none remain, then no-ops.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := walletSvc.BackfillAccountNumbers(ctx, pool, 50); err != nil {
					logger.Error("nuban backfill", "err", err)
				} else if n > 0 {
					logger.Info("nuban backfill", "assigned", n)
				}
			}
		}
	}()

	logger.Info("worker running: outbox, consumer, webhooks, snapshots, retention, reconciliation, audit")
	<-ctx.Done()
}

// dispatchEvent routes consumed events to their side-effect handlers.
// transfer_posted fans out to registered webhook endpoints; unknown
// subjects log and ack so they never block the consumer.
func dispatchEvent(ctx context.Context, q db.Querier, subject string, payload []byte) error {
	switch subject {
	case "payments.transfer_posted", "payments.bank_transfer_posted":
		if err := webhook.EnqueueForEvent(ctx, q, subject, payload); err != nil {
			return err
		}
		slog.Info("transfer fanned out to webhooks",
			"subject", subject, "request_id", requestIDOf(payload))
		return nil
	default:
		slog.Info("event consumed (no handler)",
			"subject", subject, "bytes", len(payload),
			"request_id", requestIDOf(payload))
		return nil
	}
}

// requestIDOf extracts the correlating request id from an event payload.
// Best-effort: events predating propagation simply log empty.
func requestIDOf(payload []byte) string {
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return ""
	}
	id, _ := doc["request_id"].(string)
	return id
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
