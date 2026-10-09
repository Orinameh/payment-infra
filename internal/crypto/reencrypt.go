package crypto

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ColumnTarget is one encrypted column to inspect or re-encrypt.
// IDColumn is the table's UUID primary key used for stable paging.
type ColumnTarget struct {
	Table    string
	IDColumn string
	Column   string
}

// DefaultTargets covers every application-encrypted column. Keep in
// sync with the schema: users PII/TOTP + webhook HMAC secrets.
var DefaultTargets = []ColumnTarget{
	{Table: "users", IDColumn: "id", Column: "phone_encrypted"},
	{Table: "users", IDColumn: "id", Column: "bvn_encrypted"},
	{Table: "users", IDColumn: "id", Column: "nin_encrypted"},
	{Table: "users", IDColumn: "id", Column: "totp_secret_encrypted"},
	{Table: "webhook_endpoints", IDColumn: "id", Column: "secret_encrypted"},
}

// ColumnStats describes one column's rotation state. ByKey is the
// scan-time key distribution; in Run reports it reflects pre-rewrite
// ids (rows counted under their old key even after being re-encrypted).
type ColumnStats struct {
	Table       string         `json:"table"`
	Column      string         `json:"column"`
	Scanned     int            `json:"scanned_non_null"`
	Active      int            `json:"already_active"`
	NeedsWork   int            `json:"needs_reencrypt"`
	Reencrypted int            `json:"reencrypted,omitempty"`
	Skipped     int            `json:"skipped_concurrent_write,omitempty"`
	ByKey       map[string]int `json:"by_key_id"`
}

// Report is the per-column rollup for Plan and Run.
type Report struct {
	ActiveID string        `json:"active_key_id"`
	Columns  []ColumnStats `json:"columns"`
}

// Retirable reports whether every non-null row is already under the
// active key — i.e. the old key ids can be dropped from
// ENCRYPTION_KEYS. Empty tables are trivially retirable.
func (rep *Report) Retirable() bool {
	for _, c := range rep.Columns {
		if c.NeedsWork > 0 {
			return false
		}
	}
	return true
}

func classify(ct []byte, activeID string) (key string, needsWork bool) {
	if len(ct) == 0 {
		return "empty", false
	}
	id, ok, err := EnvelopeKeyID(ct)
	if err != nil {
		return "malformed", true
	}
	if !ok {
		return "legacy", true
	}
	return id, id != activeID
}

// scanColumn pages over non-null ciphertexts oldest-first. fn sees
// each row's id (as text) and raw ciphertext. Paging by PK keeps each
// batch bounded and safe beside live writers; ids travel as text so
// the uuid round-trip never depends on driver scan types.
func scanColumn(ctx context.Context, pool *pgxpool.Pool, t ColumnTarget, batch int,
	fn func(id string, ct []byte) error) error {
	var lastSeen *string
	for {
		rows, err := pool.Query(ctx, fmt.Sprintf(
			`SELECT %s::text, %s FROM %s
			  WHERE %s IS NOT NULL AND (%s > $1::uuid OR $1 IS NULL)
			  ORDER BY %s LIMIT $2`,
			t.IDColumn, t.Column, t.Table, t.Column, t.IDColumn, t.IDColumn),
			lastSeen, batch)
		if err != nil {
			return fmt.Errorf("crypto: reencrypt scan %s.%s: %w", t.Table, t.Column, err)
		}
		n := 0
		var last string
		var scanErr error
		for rows.Next() {
			var id string
			var ct []byte
			if err := rows.Scan(&id, &ct); err != nil {
				scanErr = err
				break
			}
			n++
			last = id
			if err := fn(id, ct); err != nil {
				scanErr = err
				break
			}
		}
		rows.Close()
		if scanErr != nil {
			return scanErr
		}
		if rows.Err() != nil {
			return rows.Err()
		}
		if n < batch {
			return nil
		}
		lastSeen = &last
	}
}

// Plan counts rows per key id without writing. Safe to run anytime;
// it takes no locks beyond SKIP LOCKED reads. A Retirable report
// means step 3 of rotation is done and the old key can be dropped.
func Plan(ctx context.Context, pool *pgxpool.Pool, ring *KeyRing, targets []ColumnTarget, batch int) (*Report, error) {
	if batch <= 0 {
		batch = 500
	}
	if len(targets) == 0 {
		targets = DefaultTargets
	}
	rep := &Report{ActiveID: ring.ActiveID()}
	for _, t := range targets {
		st := ColumnStats{Table: t.Table, Column: t.Column, ByKey: map[string]int{}}
		err := scanColumn(ctx, pool, t, batch, func(_ string, ct []byte) error {
			key, need := classify(ct, ring.ActiveID())
			st.Scanned++
			st.ByKey[key]++
			if need {
				st.NeedsWork++
			} else {
				st.Active++
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		rep.Columns = append(rep.Columns, st)
	}
	return rep, nil
}

// Run rewrites every stale row under the active key. Each row is
// decrypted with the full ring and re-encrypted with active, then
// written back with a compare-and-swap on the old ciphertext:
//
//	UPDATE ... SET col = $new WHERE id = $id AND col = $old
//
// The CAS guards a concurrent application write between our read and
// write: 0 rows affected means someone else changed the value first,
// so we skip instead of clobbering their plaintext. Re-running Run
// converges (idempotent); live traffic is unaffected.
func Run(ctx context.Context, pool *pgxpool.Pool, ring *KeyRing, targets []ColumnTarget, batch int) (*Report, error) {
	if batch <= 0 {
		batch = 500
	}
	if len(targets) == 0 {
		targets = DefaultTargets
	}
	rep := &Report{ActiveID: ring.ActiveID()}
	for _, t := range targets {
		st := ColumnStats{Table: t.Table, Column: t.Column, ByKey: map[string]int{}}
		updateSQL := fmt.Sprintf(
			`UPDATE %s SET %s = $1 WHERE %s = $2 AND %s = $3`,
			t.Table, t.Column, t.IDColumn, t.Column)
		err := scanColumn(ctx, pool, t, batch, func(id string, ct []byte) error {
			key, need := classify(ct, ring.ActiveID())
			st.Scanned++
			st.ByKey[key]++
			if !need {
				st.Active++
				return nil
			}
			st.NeedsWork++
			pt, err := ring.Decrypt(ct)
			if err != nil {
				return fmt.Errorf("crypto: reencrypt %s.%s id %v: decrypt: %w", t.Table, t.Column, id, err)
			}
			fresh, err := ring.Encrypt(pt)
			if err != nil {
				return fmt.Errorf("crypto: reencrypt %s.%s id %v: encrypt: %w", t.Table, t.Column, id, err)
			}
			tag, err := pool.Exec(ctx, updateSQL, fresh, id, ct)
			if err != nil {
				return fmt.Errorf("crypto: reencrypt %s.%s id %v: update: %w", t.Table, t.Column, id, err)
			}
			if tag.RowsAffected() == 0 {
				st.Skipped++ // concurrent write won; next run picks it up
				return nil
			}
			st.Reencrypted++
			return nil
		})
		if err != nil {
			return nil, err
		}
		// NeedsWork was counted at scan time; rows we rewrote are no
		// longer stale. What remains (skipped concurrent writes) needs
		// another run — Retirable() stays honest for both Plan and Run.
		st.NeedsWork -= st.Reencrypted
		rep.Columns = append(rep.Columns, st)
	}
	return rep, nil
}
