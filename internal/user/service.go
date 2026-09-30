package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"payment-infra/internal/audit"
	"payment-infra/internal/auth"
	"payment-infra/internal/crypto"
	"payment-infra/internal/httpx"
	"payment-infra/internal/platform/db"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrEmailTaken         = errors.New("user: email already registered")
	ErrNotFound           = errors.New("user: not found")
	ErrInvalidCredentials = errors.New("user: invalid credentials")
	ErrAccountLocked      = errors.New("user: account temporarily locked")
	ErrAccountNotActive   = errors.New("user: account is not active")
	ErrTokenInvalid       = errors.New("user: token invalid or expired")
	ErrConsentRequired    = errors.New("user: NDPR consent required")
	ErrSanctioned         = errors.New("user: registration blocked by sanctions screening")
	ErrAlreadyErased      = errors.New("user: account already erased")
	ErrMFARequired        = errors.New("user: MFA code required")
	ErrMFAInvalid         = errors.New("user: MFA code invalid")
	ErrMFAUnavailable     = errors.New("user: MFA unavailable")
)

type Status string

const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusClosed    Status = "closed"
)

type User struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	// Phone is the masked display form (+234****78). The full number
	// lives only as AES-256-GCM ciphertext in phone_encrypted and is
	// never returned by the API.
	Phone           string     `json:"phone,omitempty"`
	PhoneVerifiedAt *time.Time `json:"phone_verified_at,omitempty"`
	FullName        string     `json:"full_name"`
	Status          Status     `json:"status"`
	KYCTier         int        `json:"kyc_tier"`
	CreatedAt       time.Time  `json:"created_at"`
}

type Service struct {
	pool       *pgxpool.Pool
	audit      *audit.Recorder
	bcryptCost int
	// enc encrypts TOTP secrets (and PII) at rest. Wired via
	// SetEncryptor; MFA enrollment fails closed when nil.
	enc *crypto.KeyRing
	// dummyHash is a real bcrypt hash (60 chars, valid salt, valid
	// digest). Comparing a password against it takes the same ~250ms
	// as a real comparison, so login response time does not reveal
	// whether an email is registered.
	dummyHash []byte
}

func NewService(pool *pgxpool.Pool, a *audit.Recorder) *Service {
	dummy, err := bcrypt.GenerateFromPassword(
		[]byte("timing-attack-mitigation-dummy-password"), 12)
	if err != nil {
		// This only fails if bcrypt itself is broken. Fail fast.
		panic(fmt.Sprintf("user: cannot precompute dummy hash: %v", err))
	}
	return &Service{pool: pool, audit: a, bcryptCost: 12, dummyHash: dummy}
}

type RegisterInput struct {
	Email, Phone, Password, FullName string
	ConsentGiven                     bool
	IP, UserAgent                    string
}

func (s *Service) Register(ctx context.Context, in RegisterInput) (*User, error) {
	if !in.ConsentGiven {
		return nil, ErrConsentRequired
	}
	// bcrypt silently truncates at 72 bytes; reject longer passwords
	// rather than storing a weaker hash than the user intended.
	if len(in.Password) > 72 {
		return nil, fmt.Errorf("user: password exceeds 72 bytes")
	}

	// Sanctions screening BEFORE any row is created. Exact CITEXT match
	// against the consolidated feed table; the feed job owns fuzzy
	// alias expansion. A hit blocks registration and is audited.
	var sanctionSource string
	err := s.pool.QueryRow(ctx,
		`SELECT source FROM sanctioned_names WHERE name = $1 LIMIT 1`,
		in.FullName).Scan(&sanctionSource)
	if err == nil {
		s.auditDenied(ctx, in.Email, "user.registration_blocked",
			"sanctions_hit:"+sanctionSource, in.IP, in.UserAgent)
		return nil, ErrSanctioned
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		// Screening store down: fail CLOSED. Onboarding can retry;
		// admitting an unscreened user cannot be undone.
		return nil, fmt.Errorf("user: sanctions screening unavailable: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("user: hash password: %w", err)
	}

	// Phone at rest: the full number is AES-256-GCM ciphertext in
	// phone_encrypted; the phone column carries only the masked display
	// form (+234****78), never the full number. A full phone in the
	// database is a breach-report event — fail closed when the
	// encryptor is unavailable.
	var phoneMasked *string
	var phoneCT []byte
	if in.Phone != "" {
		if s.enc == nil {
			return nil, fmt.Errorf("user: phone encryption unavailable: %w", ErrMFAUnavailable)
		}
		m := crypto.MaskPhone(in.Phone)
		phoneMasked = &m
		phoneCT, err = s.enc.EncryptString(in.Phone)
		if err != nil {
			return nil, fmt.Errorf("user: encrypt phone: %w", err)
		}
	}

	var u User
	err = db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO users (email, phone, phone_encrypted, password_hash, full_name, consent_given_at)
			VALUES ($1, $2, $3, $4, $5, now())
			RETURNING id, email, COALESCE(phone,''), full_name, status, kyc_tier, created_at`,
			strings.ToLower(in.Email), phoneMasked, phoneCT, string(hash), in.FullName,
		).Scan(&u.ID, &u.Email, &u.Phone, &u.FullName, &u.Status, &u.KYCTier, &u.CreatedAt)
		if err != nil {
			if db.IsUniqueViolation(err) {
				return ErrEmailTaken
			}
			return err
		}
		return s.audit.Record(ctx, tx, audit.Event{
			ActorID:    u.ID,
			ActorType:  "user",
			Action:     "user.registered",
			EntityType: "user",
			EntityID:   u.ID,
			Metadata:   map[string]any{"email": u.Email, "status": string(u.Status)},
			UserAgent:  in.UserAgent,
			RequestID:  httpx.RequestIDFrom(ctx),
		})
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) IssueVerificationToken(ctx context.Context,
	userID uuid.UUID, purpose string) (string, error) {

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b)
	hash := auth.HashToken(plaintext)

	ttl := "24 hours"
	if purpose == "password_reset" {
		ttl = "1 hour"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO verification_tokens (user_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)`,
		userID, purpose, hash, ttl)
	return plaintext, err
}

func (s *Service) VerifyToken(ctx context.Context,
	plaintext, purpose string, ip string, userAgent string) (*User, error) {

	hash := auth.HashToken(plaintext)

	var (
		u            User
		becameActive bool
	)

	err := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var userID uuid.UUID
		err := tx.QueryRow(ctx, `
			UPDATE verification_tokens
			SET consumed_at = now()
			WHERE token_hash = $1 AND purpose = $2
			  AND consumed_at IS NULL AND expires_at > now()
			RETURNING user_id`, hash, purpose).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}

		switch purpose {
		case "email_verify":
			_, err = tx.Exec(ctx,
				`UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1`,
				userID)
		case "phone_verify":
			_, err = tx.Exec(ctx,
				`UPDATE users SET phone_verified_at = now(), updated_at = now() WHERE id = $1`,
				userID)
		}
		if err != nil {
			return err
		}

		// Attempt the pending → active transition. RETURNING tells us
		// whether the transition actually happened; a no-op means the
		// user was already active or the other verification is still
		// missing.
		err = tx.QueryRow(ctx, `
			UPDATE users SET status = 'active', updated_at = now()
			WHERE id = $1 AND status = 'pending'
			  AND email_verified_at IS NOT NULL
			  AND phone_verified_at IS NOT NULL
			RETURNING id`, userID).Scan(&userID)
		switch {
		case err == nil:
			becameActive = true
		case errors.Is(err, pgx.ErrNoRows):
			// No transition; not an error.
		default:
			return err
		}

		err = tx.QueryRow(ctx, `
			SELECT id, email, email_verified_at, COALESCE(phone,''), phone_verified_at,
			       full_name, status, kyc_tier, created_at
			FROM users WHERE id = $1`, userID,
		).Scan(&u.ID, &u.Email, &u.EmailVerifiedAt, &u.Phone, &u.PhoneVerifiedAt,
			&u.FullName, &u.Status, &u.KYCTier, &u.CreatedAt)
		if err != nil {
			return err
		}

		// Audit the verification event.
		action := "user.email_verified"
		if purpose == "phone_verify" {
			action = "user.phone_verified"
		}
		if err := s.audit.Record(ctx, tx, audit.Event{
			ActorID:    u.ID,
			ActorType:  "user",
			Action:     action,
			EntityType: "user",
			EntityID:   u.ID,
			Metadata: map[string]any{
				"purpose": purpose,
				"status":  string(u.Status),
			},
			IP:        parseIP(ip),
			UserAgent: userAgent,
			RequestID: httpx.RequestIDFrom(ctx),
		}); err != nil {
			return err
		}

		// If this verification was the one that activated the account,
		// emit a separate event. This gives compliance a single search
		// key for "when did this account become active."
		if becameActive {
			return s.audit.Record(ctx, tx, audit.Event{
				ActorID:    u.ID,
				ActorType:  "system",
				Action:     "user.activated",
				EntityType: "user",
				EntityID:   u.ID,
				Metadata: map[string]any{
					"email_verified": u.EmailVerifiedAt != nil,
					"phone_verified": u.PhoneVerifiedAt != nil,
				},
				IP:        parseIP(ip),
				UserAgent: userAgent,
				RequestID: httpx.RequestIDFrom(ctx),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// parseIP converts a string IP to net.IP. Returns nil on failure so
// the audit record is still written; a malformed IP should not block
// verification.
func parseIP(s string) net.IP {
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

func (s *Service) Authenticate(ctx context.Context,
	email, password, ip, userAgent string) (*User, error) {

	var (
		u            User
		passwordHash string
		failedCount  int
		lockedUntil  *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, COALESCE(phone,''), full_name, status, kyc_tier, created_at,
		       password_hash, failed_login_count, locked_until
		FROM users WHERE email = $1`, strings.ToLower(email),
	).Scan(&u.ID, &u.Email, &u.Phone, &u.FullName, &u.Status, &u.KYCTier,
		&u.CreatedAt, &passwordHash, &failedCount, &lockedUntil)

	if errors.Is(err, pgx.ErrNoRows) {
		// Run bcrypt against the precomputed dummy hash so the
		// response time does not reveal whether the email exists.
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))

		s.auditLoginFailure(ctx, uuid.Nil, email, "user_not_found", ip, userAgent)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		s.auditLoginFailure(ctx, u.ID, email, "account_locked", ip, userAgent)
		return nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		newCount := failedCount + 1
		var lock *time.Time
		if newCount >= 5 {
			t := time.Now().Add(15 * time.Minute)
			lock = &t
		}
		_, _ = s.pool.Exec(ctx, `
			UPDATE users SET failed_login_count = $1, locked_until = $2
			WHERE id = $3`, newCount, lock, u.ID)

		s.auditLoginFailure(ctx, u.ID, email, "invalid_password", ip, userAgent)
		return nil, ErrInvalidCredentials
	}

	if u.Status != StatusActive {
		s.auditLoginFailure(ctx, u.ID, email,
			"account_not_active:"+string(u.Status), ip, userAgent)
		return nil, ErrAccountNotActive
	}

	_, _ = s.pool.Exec(ctx, `
		UPDATE users SET failed_login_count = 0, locked_until = NULL,
		                 last_login_at = now()
		WHERE id = $1`, u.ID)

	return &u, nil
}

// auditDenied writes an audit row for a rejected pre-auth action
// (blocked registration, etc.) on a fresh transaction. Never fails the
// caller's rejection.
func (s *Service) auditDenied(ctx context.Context,
	attemptedEmail, action, reason, ip, userAgent string) {

	err := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		return s.audit.Record(ctx, tx, audit.Event{
			ActorID:    uuid.Nil,
			ActorType:  "anonymous",
			Action:     action,
			EntityType: "user",
			EntityID:   uuid.Nil,
			Metadata: map[string]any{
				"email":  attemptedEmail,
				"reason": reason,
			},
			IP:        parseIP(ip),
			UserAgent: userAgent,
			RequestID: httpx.RequestIDFrom(ctx),
		})
	})
	if err != nil {
		slog.Error("failed to write denial audit",
			"err", err, "action", action, "reason", reason)
	}
}

// auditLoginFailure writes an audit row for a rejected login attempt.
// Runs on a fresh transaction so it does not depend on the caller's
// state, and logs but does not fail on error.
//
// We record the ATTEMPTED email in metadata, not the user's stored
// email, because for user_not_found there is no user row. Passwords
// are never recorded.
func (s *Service) auditLoginFailure(ctx context.Context,
	userID uuid.UUID, attemptedEmail, reason, ip, userAgent string) {

	actorType := "user"
	action := "auth.login_failed"
	if userID == uuid.Nil {
		actorType = "anonymous"
	}

	// Wrap in a small transaction because audit.Record uses an
	// advisory lock that only works inside a tx.
	err := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		return s.audit.Record(ctx, tx, audit.Event{
			ActorID:    userID,
			ActorType:  actorType,
			Action:     action,
			EntityType: "user",
			EntityID:   userID,
			Metadata: map[string]any{
				"email":  attemptedEmail,
				"reason": reason,
			},
			IP:        parseIP(ip),
			UserAgent: userAgent,
			RequestID: httpx.RequestIDFrom(ctx),
		})
	})
	if err != nil {
		// Audit failure must never block login rejection. Log and
		// move on; a broken audit pipeline is detected by monitoring.
		slog.Error("failed to write login failure audit",
			"err", err, "actor_type", actorType, "reason", reason)
	}
}

func (s *Service) IssueRefreshToken(ctx context.Context,
	userID uuid.UUID, ip, ua string) (string, error) {

	token, hash, err := auth.NewRefreshToken()
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
		VALUES ($1, $2, now() + interval '30 days', NULLIF($3,'')::inet, $4)`,
		userID, hash, ip, ua)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) RotateRefreshToken(ctx context.Context,
	token string) (userID uuid.UUID, newToken string, err error) {

	hash := auth.HashToken(token)
	err = db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Atomically revoke the old token and return the user it
		// belonged to. A revoked/expired token matches 0 rows.
		err := tx.QueryRow(ctx, `
			UPDATE refresh_tokens
			SET revoked_at = now()
			WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
			RETURNING user_id`, hash).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}
		var h string
		newToken, h, err = auth.NewRefreshToken()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
			VALUES ($1, $2, now() + interval '30 days')`, userID, h)
		return err
	})
	return
}

func (s *Service) RevokeRefreshToken(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL`,
		auth.HashToken(token))
	return err
}

func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, email_verified_at, phone, phone_verified_at,
		       full_name, status, kyc_tier, created_at
		FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.EmailVerifiedAt, &u.Phone, &u.PhoneVerifiedAt,
		&u.FullName, &u.Status, &u.KYCTier, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}
