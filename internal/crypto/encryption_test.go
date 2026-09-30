package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, err := NewEncryptor(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enc.Encrypt([]byte("+2348012345678"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, []byte("+2348012345678")) {
		t.Fatal("ciphertext must differ from plaintext")
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "+2348012345678" {
		t.Fatalf("got %q", pt)
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	enc, _ := NewEncryptor(bytes.Repeat([]byte{7}, 32))
	ct, _ := enc.Encrypt([]byte("secret"))
	ct[len(ct)-1] ^= 0xff // flip a tag bit
	if _, err := enc.Decrypt(ct); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	a, _ := NewEncryptor(bytes.Repeat([]byte{7}, 32))
	b, _ := NewEncryptor(bytes.Repeat([]byte{8}, 32))
	ct, _ := a.Encrypt([]byte("secret"))
	if _, err := b.Decrypt(ct); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
}

func TestBadKeyLength(t *testing.T) {
	if _, err := NewEncryptor([]byte("short")); err == nil {
		t.Fatal("non-32-byte key must be rejected")
	}
}

func TestCiphertextTooShort(t *testing.T) {
	enc, _ := NewEncryptor(bytes.Repeat([]byte{7}, 32))
	if _, err := enc.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("truncated ciphertext must be rejected")
	}
}

func TestStringHelpers(t *testing.T) {
	enc, _ := NewEncryptor(bytes.Repeat([]byte{7}, 32))
	ct, err := enc.EncryptString("hello")
	if err != nil {
		t.Fatal(err)
	}
	s, err := enc.DecryptString(ct)
	if err != nil || s != "hello" {
		t.Fatalf("got %q, %v", s, err)
	}
}
