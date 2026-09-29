package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCanonicalDeterministic(t *testing.T) {
	at := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	e := Event{
		ActorID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ActorType: "user", Action: "wallet.debit",
		EntityType: "wallet",
		EntityID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Metadata:   map[string]any{"amount_minor": 100},
	}
	a, err := canonical(e, "genesis", at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonical(e, "genesis", at)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("canonical form not deterministic")
	}
}

func TestNilIPEncodesEmpty(t *testing.T) {
	if got := ipString(nil); got != "" {
		t.Fatalf("nil IP must encode as empty, got %q", got)
	}
}

func TestLegacyNilCompat(t *testing.T) {
	at := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	e := Event{
		ActorID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ActorType: "user", Action: "user.registered",
		EntityType: "user",
		EntityID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
	}
	// Simulate a pre-fix row: hash the "<nil>" encoding manually.
	payload := map[string]any{
		"actor_id": e.ActorID.String(), "actor_type": e.ActorType,
		"action": e.Action, "entity_type": e.EntityType,
		"entity_id": e.EntityID.String(), "metadata": e.Metadata,
		"ip": "<nil>", "user_agent": "", "request_id": "",
		"at": at.UTC().Format(time.RFC3339Nano), "prev_hash": "genesis",
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if !legacyOK(e, "genesis", at, hex.EncodeToString(sum[:])) {
		t.Fatal("legacy <nil> row must verify")
	}
	if legacyOK(e, "genesis", at, "deadbeef") {
		t.Fatal("wrong hash must not verify")
	}
}
