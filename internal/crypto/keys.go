package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrUnknownKeyID = errors.New("crypto: unknown key id")
	ErrBadEnvelope  = errors.New("crypto: malformed envelope")
)

// envelopeMagic prefixes every versioned ciphertext. 8 bytes of fixed
// magic make accidental collision with legacy (raw nonce||ct) rows
// negligible (2^-64), and detection is exact, not heuristic.
var envelopeMagic = []byte("PAYENC1:")

// KeyRing holds the active encryption key plus retired keys for
// decryption. Rotation without a ring orphans every existing row the
// moment the env var changes — the ring is what makes rotation safe.
//
// Safe rollout order (all instances must hold both keys before the
// flip, because the ring is loaded once at boot and rotation needs a
// restart — a pod without the new key fails closed with
// ErrUnknownKeyID on rows written by the new active key):
//
//  1. Deploy ENCRYPTION_KEYS="old:<b64>,new:<b64>" everywhere
//     (old stays first = active; new is present for reads).
//  2. Deploy ENCRYPTION_KEYS="new:<b64>,old:<b64>" everywhere
//     (new writes begin; old rows still decrypt via envelope key id).
//  3. Re-encrypt old rows (cmd/reencrypt run), confirm with
//     cmd/reencrypt plan, then deploy ENCRYPTION_KEYS="new:<b64>".
//
// Envelope layout: magic + keyID length (1 byte) + keyID + nonce +
// ciphertext+tag. Rows written before versioning (raw GCM output) are
// decrypted by trying each known key.
type KeyRing struct {
	active string
	keys   map[string]*Encryptor
}

func NewKeyRing(keys map[string][]byte, active string) (*KeyRing, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("crypto: keyring needs at least one key")
	}
	if _, ok := keys[active]; !ok {
		return nil, fmt.Errorf("crypto: active key %q not in ring", active)
	}
	ring := &KeyRing{active: active, keys: map[string]*Encryptor{}}
	for id, raw := range keys {
		if len(id) == 0 || len(id) > 32 || strings.Contains(id, ":") {
			return nil, fmt.Errorf("crypto: bad key id %q", id)
		}
		enc, err := NewEncryptor(raw)
		if err != nil {
			return nil, fmt.Errorf("crypto: key %q: %w", id, err)
		}
		ring.keys[id] = enc
	}
	return ring, nil
}

// NewKeyRingFromEnv reads ENCRYPTION_KEYS as "id1:base64,id2:base64"
// (first entry is active). It is the only supported variable — there
// is deliberately no fallback, so a missing or malformed value fails
// fast at boot instead of silently running unencrypted or miskeyed.
func NewKeyRingFromEnv() (*KeyRing, error) {
	if spec := strings.TrimSpace(os.Getenv("ENCRYPTION_KEYS")); spec != "" {
		keys := map[string][]byte{}
		var order []string
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			id, b64, ok := strings.Cut(part, ":")
			if !ok || id == "" || b64 == "" {
				return nil, fmt.Errorf("crypto: bad ENCRYPTION_KEYS entry %q", part)
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
			if err != nil {
				return nil, fmt.Errorf("crypto: key %q: %w", id, err)
			}
			if _, dup := keys[id]; dup {
				return nil, fmt.Errorf("crypto: duplicate key id %q", id)
			}
			keys[id] = raw
			order = append(order, id)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("crypto: ENCRYPTION_KEYS is empty")
		}
		return NewKeyRing(keys, order[0])
	}
	return nil, fmt.Errorf("crypto: ENCRYPTION_KEYS is required (format \"id1:<base64>,id2:<base64>\", first is active)")
}

func (r *KeyRing) ActiveID() string { return r.active }

// Encrypt seals with the active key inside a versioned envelope.
func (r *KeyRing) Encrypt(plaintext []byte) ([]byte, error) {
	enc, ok := r.keys[r.active]
	if !ok || enc == nil {
		return nil, fmt.Errorf("crypto: active key %q not in ring", r.active)
	}
	raw, err := enc.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(envelopeMagic)+1+len(r.active)+len(raw))
	out = append(out, envelopeMagic...)
	out = append(out, byte(len(r.active)))
	out = append(out, r.active...)
	out = append(out, raw...)
	return out, nil
}

// EncryptString mirrors Encryptor for string fields.
func (r *KeyRing) EncryptString(s string) ([]byte, error) {
	return r.Encrypt([]byte(s))
}

// Decrypt opens versioned envelopes via their key id, and legacy raw
// rows by trying each known key.
func (r *KeyRing) Decrypt(ciphertext []byte) ([]byte, error) {
	if bytes.HasPrefix(ciphertext, envelopeMagic) {
		rest := ciphertext[len(envelopeMagic):]
		if len(rest) < 1 {
			return nil, ErrBadEnvelope
		}
		n := int(rest[0])
		if len(rest) < 1+n+12 {
			return nil, ErrBadEnvelope
		}
		id := string(rest[1 : 1+n])
		enc, ok := r.keys[id]
		if !ok {
			return nil, fmt.Errorf("%w: %q (key retired or never deployed here)",
				ErrUnknownKeyID, id)
		}
		return enc.Decrypt(rest[1+n:])
	}
	for _, enc := range r.keys {
		if pt, err := enc.Decrypt(ciphertext); err == nil {
			return pt, nil
		}
	}
	return nil, fmt.Errorf("crypto: decrypt: no key opened the row")
}

// EnvelopeKeyID returns the key id carried by a versioned envelope.
// ok=false means a legacy pre-envelope row (raw nonce||ciphertext).
// A malformed envelope returns ErrBadEnvelope. The minimum-length
// check mirrors Decrypt (id + 12-byte nonce must be present), so a
// truncated envelope can never classify as a healthy active-key row.
func EnvelopeKeyID(ciphertext []byte) (id string, ok bool, err error) {
	if !bytes.HasPrefix(ciphertext, envelopeMagic) {
		return "", false, nil
	}
	rest := ciphertext[len(envelopeMagic):]
	if len(rest) < 1 {
		return "", true, ErrBadEnvelope
	}
	n := int(rest[0])
	if n == 0 || n > 32 || len(rest) < 1+n+12 {
		return "", true, ErrBadEnvelope
	}
	return string(rest[1 : 1+n]), true, nil
}

// NeedsReencrypt reports whether ct should be rewritten under the
// active key: legacy rows always, versioned rows whose key id differs
// from active. Empty/NULL ciphertexts (nil) never need work.
func NeedsReencrypt(ct []byte, activeID string) bool {
	if len(ct) == 0 {
		return false
	}
	id, ok, err := EnvelopeKeyID(ct)
	if err != nil {
		return true // malformed: try a decrypt-and-rewrite; failures surface at Run
	}
	if !ok {
		return true // legacy pre-envelope row
	}
	return id != activeID
}

// DecryptString mirrors Encryptor for string fields.
func (r *KeyRing) DecryptString(ct []byte) (string, error) {
	p, err := r.Decrypt(ct)
	if err != nil {
		return "", err
	}
	return string(p), nil
}
