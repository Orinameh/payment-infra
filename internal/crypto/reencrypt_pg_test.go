package crypto

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"payment-infra/internal/platform/db"
)

// TestReencryptPlanRun exercises the rotation step 3 against a real
// Postgres with migrations applied:
//
//	TEST_DATABASE_URL=postgres://postgres@/db?host=/tmp&sslmode=disable \
//	  go test -race -run TestReencrypt ./internal/crypto/
func TestReencryptPlanRun(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL unset; skipping postgres-backed reencrypt test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, dsn, 5)
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	// Close via Cleanup (registered first, so it runs last): deferred
	// pool.Close() would run before t.Cleanup row deletes, leaking rows.
	t.Cleanup(func() { pool.Close() })

	k1 := bytes.Repeat([]byte{1}, 32)
	k2 := bytes.Repeat([]byte{2}, 32)
	oldRing, err := NewKeyRing(map[string][]byte{"k1": k1, "k2": k2}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	newRing, err := NewKeyRing(map[string][]byte{"k1": k1, "k2": k2}, "k2")
	if err != nil {
		t.Fatal(err)
	}

	phoneCT, err := oldRing.EncryptString("+2348012345678")
	if err != nil {
		t.Fatal(err)
	}
	totpCT, err := oldRing.Encrypt([]byte("totp-secret"))
	if err != nil {
		t.Fatal(err)
	}
	secretCT, err := oldRing.Encrypt([]byte("whsec_123"))
	if err != nil {
		t.Fatal(err)
	}

	var userID string
	err = pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name, status,
		                   email_verified_at, phone_verified_at,
		                   phone_encrypted, totp_secret_encrypted)
		VALUES ('reenc-' || gen_random_uuid()::text || '@example.com', '!', 'Reencrypt Test',
		        'active', now(), now(), $1, $2)
		RETURNING id::text`, phoneCT, totpCT).Scan(&userID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1::uuid`, userID)
	})
	var epID string
	err = pool.QueryRow(ctx, `
		INSERT INTO webhook_endpoints (user_id, url, secret_encrypted, event_types)
		VALUES ($1::uuid, 'https://example.com/hook', $2, '{payments.transfer_posted}')
		RETURNING id::text`, userID, secretCT).Scan(&epID)
	if err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_endpoints WHERE id = $1::uuid`, epID)
	})

	targets := []ColumnTarget{
		{Table: "users", IDColumn: "id", Column: "phone_encrypted"},
		{Table: "users", IDColumn: "id", Column: "totp_secret_encrypted"},
		{Table: "webhook_endpoints", IDColumn: "id", Column: "secret_encrypted"},
	}

	before, err := Plan(ctx, pool, newRing, targets, 100)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if before.Retirable() {
		t.Fatal("rows under retired k1 must not be retirable")
	}

	rep, err := Run(ctx, pool, newRing, targets, 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, c := range rep.Columns {
		if c.Reencrypted == 0 {
			t.Fatalf("%s.%s: expected ≥1 reencrypted row", c.Table, c.Column)
		}
	}
	if !rep.Retirable() {
		t.Fatalf("run report must be retirable when nothing was skipped: %+v", rep.Columns)
	}

	after, err := Plan(ctx, pool, newRing, targets, 100)
	if err != nil {
		t.Fatalf("plan after: %v", err)
	}
	if !after.Retirable() {
		t.Fatalf("expected retirable after run: %+v", after.Columns)
	}

	var gotPhone []byte
	if err := pool.QueryRow(ctx, `SELECT phone_encrypted FROM users WHERE id = $1::uuid`,
		userID).Scan(&gotPhone); err != nil {
		t.Fatal(err)
	}
	id, ok, err := EnvelopeKeyID(gotPhone)
	if err != nil || !ok || id != "k2" {
		t.Fatalf("phone must be under k2 after run: id=%q ok=%v err=%v", id, ok, err)
	}
	pt, err := newRing.Decrypt(gotPhone)
	if err != nil || string(pt) != "+2348012345678" {
		t.Fatalf("decrypt after run: %q %v", pt, err)
	}
}
