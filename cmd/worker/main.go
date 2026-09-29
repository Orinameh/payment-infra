package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"payment-infra/internal/audit"
	"payment-infra/internal/outbox"
	"payment-infra/internal/platform/db"
	"payment-infra/internal/queue"
	"payment-infra/internal/reconciliation"
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

	reconSvc := reconciliation.NewService(pool)
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

	logger.Info("worker running: outbox, reconciliation, audit")
	<-ctx.Done()
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
