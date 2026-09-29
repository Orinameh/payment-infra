package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const chainLockID int64 = 0x6175646974 // "audit"

// Event is one immutable audit record. The hash chain makes tampering
// detectable: any modification to a historical row breaks verification
// of every subsequent row.
type Event struct {
	ActorID    uuid.UUID
	ActorType  string // "user", "system", "admin"
	Action     string
	EntityType string
	EntityID   uuid.UUID
	Metadata   map[string]any
	IP         net.IP
	UserAgent  string
	RequestID  string
}

// Recorder writes hash-chained audit entries. Every financial state
// change must call Record inside the same DB transaction as the change,
// so the audit trail can never diverge from the ledger.
type Recorder struct{}

// canonical returns the deterministic byte representation hashed into
// the chain. Field order is fixed and JSON is sorted by encoding/json.
func ipString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func canonical(e Event, prevHash string, at time.Time) ([]byte, error) {
	payload := map[string]any{
		"actor_id":    e.ActorID.String(),
		"actor_type":  e.ActorType,
		"action":      e.Action,
		"entity_type": e.EntityType,
		"entity_id":   e.EntityID.String(),
		"metadata":    e.Metadata,
		"ip":          ipString(e.IP),
		"user_agent":  e.UserAgent,
		"request_id":  e.RequestID,
		"at":          at.UTC().Format(time.RFC3339Nano),
		"prev_hash":   prevHash,
	}
	return json.Marshal(payload)
}

// Record inserts a new audit entry. It MUST be called inside the same
// transaction as the state change it describes.
//
// Serialization uses a transaction-scoped advisory lock (chainLockID),
// not SELECT ... FOR UPDATE on the head row: the head row is a hot spot
// and FOR UPDATE on an empty table locks nothing, while the advisory
// lock serializes appends regardless of table contents and releases
// automatically at commit/rollback.
func (Recorder) Record(ctx context.Context, tx pgx.Tx, e Event) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, chainLockID); err != nil {
		return fmt.Errorf("audit: acquire chain lock: %w", err)
	}
	var prevHash string
	err := tx.QueryRow(ctx, `
		SELECT entry_hash FROM audit_log
		ORDER BY id DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("audit: read chain head: %w", err)
	}
	if prevHash == "" {
		prevHash = "genesis"
	}

	at := time.Now().UTC()
	body, err := canonical(e, prevHash, at)
	if err != nil {
		return fmt.Errorf("audit: canonicalize: %w", err)
	}
	sum := sha256.Sum256(body)
	entryHash := hex.EncodeToString(sum[:])

	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return fmt.Errorf("audit: marshal metadata: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_log (
			actor_id, actor_type, action, entity_type, entity_id,
			metadata, ip_address, user_agent, request_id,
			previous_hash, entry_hash, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.ActorID, e.ActorType, e.Action, e.EntityType, e.EntityID,
		meta, e.IP, e.UserAgent, e.RequestID,
		prevHash, entryHash, at,
	)
	return err
}

// VerifyChain re-computes the hash chain for all rows and returns the
// first broken entry, if any. Run this periodically and alert on
// non-nil results. A broken chain means the audit trail has been
// tampered with — a serious incident.
func VerifyChain(ctx context.Context, pool *pgxpool.Pool) (*BrokenEntry, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, actor_id, actor_type, action, entity_type, entity_id,
		       metadata, ip_address, COALESCE(user_agent,''), COALESCE(request_id,''),
		       previous_hash, entry_hash, created_at
		FROM audit_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	expectedPrev := "genesis"
	for rows.Next() {
		var (
			id           int64
			actorID      uuid.UUID
			actorType    string
			action       string
			entityType   string
			entityID     uuid.UUID
			metaRaw      []byte
			ip           net.IP
			userAgent    string
			requestID    string
			previousHash string
			entryHash    string
			createdAt    time.Time
		)
		if err := rows.Scan(&id, &actorID, &actorType, &action, &entityType,
			&entityID, &metaRaw, &ip, &userAgent, &requestID,
			&previousHash, &entryHash, &createdAt); err != nil {
			return nil, err
		}
		if previousHash != expectedPrev {
			return &BrokenEntry{ID: id, Reason: "previous_hash mismatch"}, nil
		}
		var meta map[string]any
		_ = json.Unmarshal(metaRaw, &meta)
		e := Event{
			ActorID: actorID, ActorType: actorType, Action: action,
			EntityType: entityType, EntityID: entityID, Metadata: meta,
			IP: ip, UserAgent: userAgent, RequestID: requestID,
		}
		body, err := canonical(e, previousHash, createdAt)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != entryHash {
			// Backward compat: rows written before the nil-IP fix
			// hashed net.IP(nil).String() == "<nil>" instead of "".
			// Accept either encoding for rows with NULL ip so the
			// fix doesn't falsely report a broken chain.
			if ip == nil {
				if legacyOK(e, previousHash, createdAt, entryHash) {
					expectedPrev = entryHash
					continue
				}
			}
			return &BrokenEntry{ID: id, Reason: "entry_hash mismatch"}, nil
		}
		expectedPrev = entryHash
	}
	return nil, rows.Err()
}

type BrokenEntry struct {
	ID     int64
	Reason string
}

// legacyOK recomputes the hash with the pre-fix nil encoding ("<nil>")
// for rows whose ip is NULL.
func legacyOK(e Event, prevHash string, at time.Time, want string) bool {
	payload := map[string]any{
		"actor_id":    e.ActorID.String(),
		"actor_type":  e.ActorType,
		"action":      e.Action,
		"entity_type": e.EntityType,
		"entity_id":   e.EntityID.String(),
		"metadata":    e.Metadata,
		"ip":          "<nil>",
		"user_agent":  e.UserAgent,
		"request_id":  e.RequestID,
		"at":          at.UTC().Format(time.RFC3339Nano),
		"prev_hash":   prevHash,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]) == want
}

func (b *BrokenEntry) Error() string {
	return fmt.Sprintf("audit: chain broken at id=%d: %s", b.ID, b.Reason)
}
