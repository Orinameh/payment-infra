package wallet

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"payment-infra/internal/audit"
	"payment-infra/internal/money"
	"payment-infra/internal/platform/db"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestConcurrentDebitsSingleWinner is the double-withdrawal proof: N
// concurrent debits of the full balance must leave exactly one winner
// and a zero (never negative) balance. Requires a real Postgres with
// migrations applied:
//
//	TEST_DATABASE_URL=postgres://payments:secret@localhost:5432/payments?sslmode=disable go test -race -run TestConcurrentDebits ./internal/wallet/
func TestConcurrentDebitsSingleWinner(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL unset; skipping postgres-backed concurrency test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, dsn, 20)
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	defer pool.Close()

	svc := NewService(&audit.Recorder{})

	var userID uuid.UUID
	err = pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name, status,
		                   email_verified_at, phone_verified_at)
		VALUES ('concurrency-'+gen_random_uuid()::text+'@example.com', '!', 'Race Test', 'active', now(), now())
		RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	w, err := svc.Create(ctx, pool, userID, "NGN")
	if err != nil {
		t.Fatalf("create wallet: %v", err)
	}

	const balance = int64(10_000) // 100.00 NGN in kobo
	if err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := svc.Credit(ctx, tx, w.ID, money.New(balance, money.NGN), "seed", userID)
		return err
	}); err != nil {
		t.Fatalf("seed credit: %v", err)
	}

	const racers = 50
	var (
		wins  atomic.Int64
		fails atomic.Int64
		wg    sync.WaitGroup
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
				_, err := svc.Debit(ctx, tx, w.ID, money.New(balance, money.NGN), "race", userID)
				return err
			})
			if err == nil {
				wins.Add(1)
			} else if errors.Is(err, ErrInsufficientFunds) {
				fails.Add(1)
			} else {
				t.Errorf("unexpected debit error: %v", err)
			}
		}()
	}
	wg.Wait()

	if wins.Load() != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", wins.Load())
	}
	if fails.Load() != racers-1 {
		t.Fatalf("expected %d insufficient-funds failures, got %d", racers-1, fails.Load())
	}

	final, err := svc.Get(ctx, pool, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Balance != 0 {
		t.Fatalf("final balance = %d, want 0", final.Balance)
	}
	if final.Balance < 0 {
		t.Fatal("balance went negative")
	}
}
