package user

import (
	"context"
	"encoding/base32"
	"fmt"
	"time"

	"payment-infra/internal/crypto"
	"payment-infra/internal/mfa"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetEncryptor wires the PII/TOTP encryptor. MFA enrollment and phone
// encryption fail closed when it is nil.
func (s *Service) SetEncryptor(enc *crypto.Encryptor) { s.enc = enc }

// BeginMFA generates a TOTP secret, stores it encrypted (resetting any
// prior verification), and returns the plaintext secret plus the
// otpauth URL for QR display. The secret is shown exactly once.
func (s *Service) BeginMFA(ctx context.Context, userID uuid.UUID, issuer string) (secret, otpauthURL string, err error) {
	if s.enc == nil {
		return "", "", ErrMFAUnavailable
	}
	raw, err := mfa.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	ct, err := s.enc.Encrypt(raw)
	if err != nil {
		return "", "", fmt.Errorf("user: encrypt totp secret: %w", err)
	}
	var email string
	err = s.pool.QueryRow(ctx, `
		UPDATE users SET totp_secret_encrypted = $1, totp_verified_at = NULL, updated_at = now()
		WHERE id = $2 RETURNING email`, ct, userID).Scan(&email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", "", ErrNotFound
		}
		return "", "", err
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return b32, mfa.ProvisioningURL(issuer, email, raw), nil
}

// ConfirmMFA verifies the code against the stored secret and marks MFA
// enrolled. Until confirmed, the secret grants nothing.
func (s *Service) ConfirmMFA(ctx context.Context, userID uuid.UUID, code string) error {
	if s.enc == nil {
		return ErrMFAUnavailable
	}
	var ct []byte
	if err := s.pool.QueryRow(ctx,
		`SELECT totp_secret_encrypted FROM users WHERE id = $1`, userID,
	).Scan(&ct); err != nil {
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	if len(ct) == 0 {
		return fmt.Errorf("user: no MFA setup in progress: %w", ErrMFAInvalid)
	}
	raw, err := s.enc.Decrypt(ct)
	if err != nil {
		return fmt.Errorf("user: decrypt totp secret: %w", err)
	}
	if !mfa.Verify(raw, code, time.Now()) {
		return ErrMFAInvalid
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE users SET totp_verified_at = now(), updated_at = now() WHERE id = $1`,
		userID)
	return err
}

// MFAEnrolled reports whether the user completed TOTP enrollment.
func (s *Service) MFAEnrolled(ctx context.Context, userID uuid.UUID) (bool, error) {
	var verified *time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT totp_verified_at FROM users WHERE id = $1`, userID,
	).Scan(&verified); err != nil {
		if err == pgx.ErrNoRows {
			return false, ErrNotFound
		}
		return false, err
	}
	return verified != nil, nil
}

// VerifyMFACode enforces step-up auth: unenrolled users pass through
// (MFA is opt-in until policy mandates it); enrolled users must present
// a valid code. Missing code and wrong code are distinct errors so the
// handler can message them correctly.
func (s *Service) VerifyMFACode(ctx context.Context, userID uuid.UUID, code string) error {
	var (
		ct       []byte
		verified *time.Time
	)
	if err := s.pool.QueryRow(ctx,
		`SELECT totp_secret_encrypted, totp_verified_at FROM users WHERE id = $1`,
		userID).Scan(&ct, &verified); err != nil {
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	if verified == nil {
		return nil // not enrolled
	}
	if code == "" {
		return ErrMFARequired
	}
	if s.enc == nil {
		return ErrMFAUnavailable
	}
	raw, err := s.enc.Decrypt(ct)
	if err != nil {
		return fmt.Errorf("user: decrypt totp secret: %w", err)
	}
	if !mfa.Verify(raw, code, time.Now()) {
		return ErrMFAInvalid
	}
	return nil
}
