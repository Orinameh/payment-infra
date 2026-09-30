package payment

import "testing"

func TestHashBodyDeterministic(t *testing.T) {
	a := hashBody([]byte(`{"a":1}`))
	b := hashBody([]byte(`{"a":1}`))
	if a != b {
		t.Fatal("same input must hash identically")
	}
	if len(a) != 64 {
		t.Fatalf("sha256 hex must be 64 chars, got %d", len(a))
	}
	if c := hashBody([]byte(`{"a":2}`)); c == a {
		t.Fatal("different input must hash differently")
	}
}
