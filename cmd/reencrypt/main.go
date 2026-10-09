package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"payment-infra/internal/crypto"
	"payment-infra/internal/platform/db"
	"strconv"
)

// Rotation step 3: re-encrypt rows written under retired keys.
//
//	plan: read-only census per column per key id. Retirable when every
//	      non-null row is already under the active key.
//	run:  decrypt-with-ring + encrypt-with-active + compare-and-swap
//	      writeback. Idempotent; safe beside live traffic.
//
// Both commands need DATABASE_URL and ENCRYPTION_KEYS (full ring: new
// first/active, old retained for reads). Run fails closed on the
// first undecryptable row — a missing key id means ENCRYPTION_KEYS
// is incomplete, and silently skipping would fake a clean report.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cmd := "plan"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd != "plan" && cmd != "run" {
		logger.Error("usage: reencrypt [plan|run]", "cmd", cmd)
		os.Exit(2)
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("DATABASE_URL required")
		os.Exit(1)
	}
	ring, err := crypto.NewKeyRingFromEnv()
	if err != nil {
		logger.Error("encryption keyring", "err", err)
		os.Exit(1)
	}

	batch := 500
	if s := os.Getenv("REENCRYPT_BATCH"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			batch = n
		}
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn, 5)
	if err != nil {
		logger.Error("db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	switch cmd {
	case "plan":
		rep, err := crypto.Plan(ctx, pool, ring, nil, batch)
		if err != nil {
			logger.Error("plan", "err", err)
			os.Exit(1)
		}
		printReport(logger, rep, false)
		if !rep.Retirable() {
			logger.Info("verdict: NOT retirable — run reencrypt run, then plan again")
			os.Exit(3)
		}
		logger.Info("verdict: retirable — old keys can be dropped")
	case "run":
		rep, err := crypto.Run(ctx, pool, ring, nil, batch)
		if err != nil {
			logger.Error("run", "err", err)
			os.Exit(1)
		}
		printReport(logger, rep, true)
		if !rep.Retirable() {
			logger.Info("verdict: NOT retirable — rerun (concurrent writes skipped) then plan")
			os.Exit(3)
		}
		logger.Info("verdict: retirable — old keys can be dropped")
	}
}

func printReport(logger *slog.Logger, rep *crypto.Report, withWrites bool) {
	for _, c := range rep.Columns {
		attrs := []any{
			"table", c.Table, "column", c.Column,
			"scanned", c.Scanned, "active", c.Active,
			"needs_work", c.NeedsWork, "by_key", fmt.Sprintf("%v", c.ByKey),
		}
		if withWrites {
			attrs = append(attrs,
				"reencrypted", c.Reencrypted, "skipped", c.Skipped)
		}
		logger.Info("column", attrs...)
	}
}
