package crypto

import (
	"bytes"
	"testing"
)

func testRing(t *testing.T) (*KeyRing, map[string][]byte) {
	t.Helper()
	k1 := bytes.Repeat([]byte{1}, 32)
	k2 := bytes.Repeat([]byte{2}, 32)
	ring, err := NewKeyRing(map[string][]byte{"k1": k1, "k2": k2}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	return ring, map[string][]byte{"k1": k1, "k2": k2}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	ring, _ := testRing(t)
	ct, err := ring.Encrypt([]byte("+2348012345678"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ct, envelopeMagic) {
		t.Fatal("new writes must carry the envelope")
	}
	pt, err := ring.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "+2348012345678" {
		t.Fatalf("got %q", pt)
	}
}

func TestLegacyRowStillDecrypts(t *testing.T) {
	ring, keys := testRing(t)
	legacy, err := NewEncryptor(keys["k1"])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := legacy.Encrypt([]byte("old-row"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ring.Decrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "old-row" {
		t.Fatalf("got %q", pt)
	}
}

func TestRetiredKeyReads(t *testing.T) {
	ring, keys := testRing(t)
	ct, err := ring.Encrypt([]byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	// Rotate: k2 becomes active, k1 stays for reads.
	rotated, err := NewKeyRing(keys, "k2")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := rotated.Decrypt(ct)
	if err != nil {
		t.Fatalf("retired key must still decrypt: %v", err)
	}
	if string(pt) != "v" {
		t.Fatalf("got %q", pt)
	}
	// New writes now carry k2.
	ct2, _ := rotated.Encrypt([]byte("v2"))
	if !bytes.Contains(ct2, []byte("k2")) {
		t.Fatal("post-rotation writes must reference the new key id")
	}
}

func TestUnknownKeyIDFails(t *testing.T) {
	ring, _ := testRing(t)
	other, _ := NewKeyRing(map[string][]byte{"zz": bytes.Repeat([]byte{9}, 32)}, "zz")
	ct, _ := other.Encrypt([]byte("x"))
	if _, err := ring.Decrypt(ct); err == nil {
		t.Fatal("unknown key id must fail loudly, not return garbage")
	}
}
