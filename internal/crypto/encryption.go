package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKeyLength = errors.New("crypto: key must be exactly 32 bytes for AES-256")
	ErrCiphertextShort  = errors.New("crypto: ciphertext too short")
)

// Encryptor provides AES-256-GCM authenticated encryption for PII
// and secrets stored in the database.
//
// AES-256-GCM is the correct choice: it is an AEAD cipher, meaning it
// provides both confidentiality and integrity. If a single bit of
// ciphertext is tampered with, Decrypt fails rather than returning
// corrupted plaintext. Avoid CBC + HMAC manual constructions —
// GCM is the standard library's default recommendation.
//
// The 32-byte key must come from a secrets manager (AWS KMS,
// HashiCorp Vault, or Kubernetes Secret). Never hardcode it.

type Encryptor struct {
	aead cipher.AEAD
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return &Encryptor{aead: aead}, nil
}

// Encrypt produces a nonce-prefixed ciphertext. The returned bytes
// have the format: nonce || ciphertext || tag.
//
// A fresh random 12-byte nonce is generated for every call. Reusing
// a nonce with the same key would catastrophically break GCM — Go's
// crypto/rand provides the entropy needed to make collisions
// negligible.

func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. Returns an error if the ciphertext has
// been tampered with — GCM authenticates before decrypting.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrCiphertextShort
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := e.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}

// EncryptString is a convenience for string fields.
func (e *Encryptor) EncryptString(s string) ([]byte, error) {
	return e.Encrypt([]byte(s))
}

func (e *Encryptor) DecryptString(ct []byte) (string, error) {
	p, err := e.Decrypt(ct)
	if err != nil {
		return "", err
	}
	return string(p), nil
}

// MaskBVN returns the BVN masked for display: first 3 and last 2 digits.
// PCI DSS and NDPR both require masking of sensitive identifiers when
// displayed. This is used in API responses and audit logs.
func MaskBVN(bvn string) string {
	if len(bvn) < 11 {
		return "***"
	}
	return bvn[:3] + "******" + bvn[9:]
}

// MaskNIN returns the NIN masked for display.
func MaskNIN(nin string) string {
	if len(nin) < 11 {
		return "***"
	}
	return nin[:3] + "******" + nin[9:]
}

// MaskPhone returns the phone masked, showing country code and last 2.
func MaskPhone(phone string) string {
	if len(phone) < 6 {
		return "***"
	}
	return phone[:4] + "****" + phone[len(phone)-2:]
}

// MaskPAN returns a card PAN masked per PCI DSS: first 6 and last 4.
// Never store a full PAN without PCI DSS certification.
func MaskPAN(pan string) string {
	if len(pan) < 13 {
		return "****"
	}
	return pan[:6] + "******" + pan[len(pan)-4:]
}

// GenerateRandomKey produces a 32-byte key for AES-256. Use this only
// for tests or initial key generation — production keys come from KMS.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// KeyFromBase64 decodes a base64-encoded key from an environment
// variable or secret manager.
func KeyFromBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
