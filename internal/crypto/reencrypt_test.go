package crypto

import (
	"bytes"
	"testing"
)

func TestEnvelopeKeyIDRoundTrip(t *testing.T) {
	ring, _ := testRing(t)
	ct, err := ring.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	id, ok, err := EnvelopeKeyID(ct)
	if err != nil || !ok {
		t.Fatalf("versioned envelope must parse: id=%q ok=%v err=%v", id, ok, err)
	}
	if id != ring.ActiveID() {
		t.Fatalf("got %q want %q", id, ring.ActiveID())
	}
}

func TestEnvelopeKeyIDLegacy(t *testing.T) {
	_, keys := testRing(t)
	legacy, _ := NewEncryptor(keys["k1"])
	raw, _ := legacy.Encrypt([]byte("old"))
	if id, ok, err := EnvelopeKeyID(raw); err != nil || ok || id != "" {
		t.Fatalf("legacy row must report ok=false: id=%q ok=%v err=%v", id, ok, err)
	}
}

func TestEnvelopeKeyIDMalformed(t *testing.T) {
	truncatedID := append(append(append([]byte{}, envelopeMagic...), 0x02, 'k', '1'), 0x00, 0x01, 0x02, 0x03, 0x04)
	for _, ct := range [][]byte{
		append([]byte{}, envelopeMagic...),
		append(append([]byte{}, envelopeMagic...), 0x05, 'a'),
		truncatedID, // id present but nonce truncated: must not parse as healthy
	} {
		if _, ok, err := EnvelopeKeyID(ct); !ok || err == nil {
			t.Fatalf("truncated envelope must be malformed: %x", ct)
		}
	}
	if !NeedsReencrypt(truncatedID, "k1") {
		t.Fatal("truncated envelope under the active id must still need work")
	}
}

func TestNeedsReencrypt(t *testing.T) {
	ring, keys := testRing(t)
	if NeedsReencrypt(nil, "k1") {
		t.Fatal("empty must never need work")
	}
	fresh, _ := ring.Encrypt([]byte("x"))
	if NeedsReencrypt(fresh, "k1") {
		t.Fatal("active row must not need work")
	}
	rotated, _ := NewKeyRing(keys, "k2")
	if !NeedsReencrypt(fresh, rotated.ActiveID()) {
		t.Fatal("row under retired key must need work")
	}
	legacy, _ := NewEncryptor(keys["k1"])
	raw, _ := legacy.Encrypt([]byte("old"))
	if !NeedsReencrypt(raw, "k1") {
		t.Fatal("legacy row must always need work")
	}
}

func TestEncryptFailsClosedWithoutActive(t *testing.T) {
	ring, _ := testRing(t)
	ring.active = "ghost"
	if _, err := ring.Encrypt([]byte("x")); err == nil {
		t.Fatal("missing active key must error, not panic")
	}
}

func TestClassifyCounts(t *testing.T) {
	ring, keys := testRing(t)
	rotated, _ := NewKeyRing(keys, "k2")
	oldCT, _ := ring.Encrypt([]byte("a"))    // k1 envelope
	legacyEnc, _ := NewEncryptor(keys["k1"]) // raw
	legacyCT, _ := legacyEnc.Encrypt([]byte("b"))

	cases := []struct {
		ct   []byte
		ring *KeyRing
		key  string
		need bool
	}{
		{oldCT, rotated, "k1", true},
		{legacyCT, rotated, "legacy", true},
	}
	for _, c := range cases {
		key, need := classify(c.ct, c.ring.ActiveID())
		if key != c.key || need != c.need {
			t.Fatalf("classify=%q,%v want %q,%v", key, need, c.key, c.need)
		}
	}
	if !bytes.HasPrefix(oldCT, envelopeMagic) {
		t.Fatal("test setup broken: expected envelope")
	}
}
