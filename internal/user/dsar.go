package user

import (
	"context"
	"fmt"
	"time"

	"payment-infra/internal/audit"
	"payment-infra/internal/platform/db"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Export is a bounded data-subject access bundle: identity, wallets,
// consent history, and the actor's own audit trail. Ledger entries are
// reachable per-wallet via the transactions API; financial records are
// never deleted, only PII is (see Erase).
type Export struct {
	User     *User           `json:"user"`
	Wallets  []WalletSummary `json:"wallets"`
	Consents []ConsentRecord `json:"consents"`
	Audit    []AuditRecord   `json:"audit_trail"`
}

type WalletSummary struct {
	ID        uuid.UUID `json:"id"`
	Currency  string    `json:"currency"`
	Balance   int64     `json:"balance_minor"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type ConsentRecord struct {
	Purpose   string    `json:"purpose"`
	Granted   bool      `json:"granted"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditRecord struct {
	Action    string    `json:"action"`
	Entity    string    `json:"entity_type"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) ExportUser(ctx context.Context, userID uuid.UUID) (*Export, error) {
	u, err := s.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := &Export{User: u}

	rows, err := s.pool.Query(ctx, `
		SELECT id, currency, balance, status, created_at
		FROM wallets WHERE user_id = $1 ORDER BY currency`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var w WalletSummary
		if err := rows.Scan(&w.ID, &w.Currency, &w.Balance, &w.Status, &w.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Wallets = append(out.Wallets, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT purpose, granted, created_at FROM user_consents
		WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c ConsentRecord
		if err := rows.Scan(&c.Purpose, &c.Granted, &c.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Consents = append(out.Consents, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT action, entity_type, created_at FROM audit_log
		WHERE actor_id = $1 ORDER BY id DESC LIMIT 200`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a AuditRecord
		if err := rows.Scan(&a.Action, &a.Entity, &a.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Audit = append(out.Audit, a)
	}
	rows.Close()
	return out, rows.Err()
}

// Erase executes the right-to-erasure: PII is nulled/redacted, the
// password is burned, sessions revoked, the account closed. Ledger
// entries, transactions, AML alerts, and audit rows are RETAINED
// (AML/CFT 5-year retention overrides erasure). Idempotent-guarded:
// an already-erased account returns ErrAlreadyErased.
func (s *Service) Erase(ctx context.Context, userID uuid.UUID) error {
	err := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var erasure *time.Time
		if err := tx.QueryRow(ctx,
			`SELECT erasure_at FROM users WHERE id = $1`, userID,
		).Scan(&erasure); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if erasure != nil {
			return ErrAlreadyErased
		}

		tag, err := tx.Exec(ctx, `
			UPDATE users
			SET full_name = '[redacted]',
			    phone = NULL,
			    phone_encrypted = NULL,
			    bvn_encrypted = NULL,
			    nin_encrypted = NULL,
			    email = ('redacted_' || $1::text || '@deleted.local')::citext,
			    password_hash = '!',
			    status = 'closed',
			    failed_login_count = 0,
			    locked_until = NULL,
			    erasure_at = now(),
			    updated_at = now()
			WHERE id = $1 AND erasure_at IS NULL`, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAlreadyErased
		}

		if _, err := tx.Exec(ctx,
			`UPDATE refresh_tokens SET revoked_at = now()
			  WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO dsar_requests (user_id, type, status, completed_at)
			VALUES ($1, 'erasure', 'completed', now())`, userID); err != nil {
			return err
		}

		return s.audit.Record(ctx, tx, audit.Event{
			ActorID:    userID,
			ActorType:  "user",
			Action:     "user.erased",
			EntityType: "user",
			EntityID:   userID,
			Metadata:   map[string]any{"retained": []string{"ledger", "transactions", "aml_alerts", "audit_log"}},
		})
	})
	if err != nil {
		return fmt.Errorf("user: erase: %w", err)
	}
	return nil
}
