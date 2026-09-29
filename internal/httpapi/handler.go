package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"payment-infra/internal/auth"
	"payment-infra/internal/fraud"
	"payment-infra/internal/httpx"
	"payment-infra/internal/ledger"
	"payment-infra/internal/money"
	"payment-infra/internal/payment"
	"payment-infra/internal/user"
	"payment-infra/internal/wallet"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Handler struct {
	Pool     *pgxpool.Pool
	ReadPool *pgxpool.Pool // optional replica; nil means read from Pool
	Users    *user.Service
	Wallets  *wallet.Service
	Payments *payment.Service
	Ledger   *ledger.Service
	Logger   *slog.Logger

	AccessTokenTTL int
	Issuer         string
	Audience       string
	SignToken      func(claims auth.Claims) (string, error)
}

// read returns the replica for replica-safe queries (lists, history).
// Balance reads stay on the primary (or cache) so a client never sees
// a stale balance immediately after its own transfer.
func (h *Handler) read() *pgxpool.Pool {
	if h.ReadPool != nil {
		return h.ReadPool
	}
	return h.Pool
}

func NewRouter(h *Handler, authn *auth.Authenticator, rl *httpx.RateLimiter) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /v1/readyz", h.Readyz)

	// Auth (public — must NOT sit behind AuthRequired)
	mux.HandleFunc("POST /v1/auth/register", h.Register)
	mux.HandleFunc("POST /v1/auth/verify", h.Verify)
	mux.HandleFunc("POST /v1/auth/login", h.Login)
	mux.HandleFunc("POST /v1/auth/refresh", h.Refresh)
	mux.HandleFunc("POST /v1/auth/logout", h.Logout)

	// Protected helpers: auth first (so claims exist), then per-user
	// rate limiting, then the handler. Auth outer → RateLimit inner is
	// required so RateLimit sees the JWT subject instead of just IP.
	protected := func(next http.HandlerFunc) http.Handler {
		return httpx.Chain(next,
			httpx.AuthRequired(authn),
			httpx.RateLimit(rl),
		)
	}

	// Users
	mux.Handle("GET /v1/users/me", protected(h.GetMe))

	// Wallets
	mux.Handle("POST /v1/wallets", protected(h.CreateWallet))
	mux.Handle("GET /v1/wallets", protected(h.ListWallets))
	mux.Handle("GET /v1/wallets/{id}", protected(h.GetWallet))
	mux.Handle("GET /v1/wallets/{id}/transactions", protected(h.GetWalletHistory))

	// Transfers
	mux.Handle("POST /v1/transfers", protected(h.Transfer))

	mux.Handle("GET /metrics", promhttp.Handler())

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

// ownerCheck enforces object-level ownership. Every wallet access goes
// through this. OWASP API1:2025 (BOLA) is the #1 fintech API risk.
//
// Returns wallet.ErrNotFound when the wallet does not exist and a
// distinct forbidden error otherwise, so callers can map 404 vs 403
// correctly (collapsing both to 403 creates a user-enumeration oracle
// in reverse — clients can't tell a bad UUID from someone else's).
var errForbidden = errors.New("forbidden")

func (h *Handler) ownerCheck(ctx context.Context, walletID uuid.UUID) (*wallet.Wallet, error) {
	claims := auth.MustClaims(ctx)
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, errors.New("invalid subject")
	}
	w, err := h.Wallets.Get(ctx, h.Pool, walletID)
	if err != nil {
		return nil, err
	}
	if w.UserID != userID && claims.Role != "admin" {
		return nil, errForbidden
	}
	return w, nil
}

// ownerCheckCached is the read-path variant: balance display served
// from Redis when warm. Ownership (user_id) is immutable, so the cached
// copy authorizes as well as the row. Mutating paths keep using
// ownerCheck (authoritative) since the tx re-locks regardless.
func (h *Handler) ownerCheckCached(ctx context.Context, walletID uuid.UUID) (*wallet.Wallet, error) {
	claims := auth.MustClaims(ctx)
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, errors.New("invalid subject")
	}
	w, err := h.Wallets.GetCached(ctx, h.Pool, walletID)
	if err != nil {
		return nil, err
	}
	if w.UserID != userID && claims.Role != "admin" {
		return nil, errForbidden
	}
	return w, nil
}

// Readyz is a dependency-aware readiness probe. /v1/healthz only proves
// the process is alive; readyz proves it can serve traffic.
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.Pool.Ping(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, CodeServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ---- auth handlers ----

type registerBody struct {
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Password     string `json:"password"`
	FullName     string `json:"full_name"`
	ConsentGiven bool   `json:"consent_given"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var body registerBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, "invalid json")
		return
	}
	if len(body.Password) < 12 {
		writeErr(w, http.StatusBadRequest, CodeAuthWeakPassword, "password must be at least 12 characters")
		return
	}
	if !body.ConsentGiven {
		writeErr(w, http.StatusBadRequest, CodeAuthConsentRequired, "NDPR consent is required")
		return
	}

	u, err := h.Users.Register(r.Context(), user.RegisterInput{
		Email: body.Email, Phone: body.Phone, Password: body.Password,
		FullName: body.FullName, ConsentGiven: true,
		IP: httpx.RealIPFrom(r.Context()), UserAgent: r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, user.ErrEmailTaken):
			writeErr(w, http.StatusConflict, CodeUserEmailTaken, "email already registered")
		case errors.Is(err, user.ErrSanctioned):
			writeErr(w, http.StatusForbidden, CodeUserSanctioned, "registration blocked")
		case errors.Is(err, user.ErrConsentRequired):
			writeErr(w, http.StatusBadRequest, CodeAuthConsentRequired, "consent is required")
		default:
			h.Logger.Error("register", "err", err)
			writeErr(w, http.StatusInternalServerError, CodeInternalError, "registration failed")
		}
		return
	}

	emailToken, _ := h.Users.IssueVerificationToken(r.Context(), u.ID, "email_verify")
	phoneToken, _ := h.Users.IssueVerificationToken(r.Context(), u.ID, "phone_verify")

	writeJSON(w, http.StatusCreated, map[string]any{
		"user":    u,
		"message": "Check your email and phone to activate your account.",
		// Dev-only. Remove in production; tokens go via email/SMS.
		"_dev_email_token": emailToken,
		"_dev_phone_token": phoneToken,
	})
}

type verifyBody struct {
	Token   string `json:"token"`
	Purpose string `json:"purpose"`
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	var body verifyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, "invalid json")
		return
	}
	if body.Purpose != "email_verify" && body.Purpose != "phone_verify" {
		writeErr(w, http.StatusBadRequest, CodeVerifyInvalidPurpose, "invalid purpose")
		return
	}

	u, err := h.Users.VerifyToken(r.Context(), body.Token, body.Purpose, httpx.RealIPFrom(r.Context()), r.UserAgent())
	if err != nil {
		if errors.Is(err, user.ErrTokenInvalid) {
			writeErr(w, http.StatusBadRequest, CodeVerifyTokenInvalid, "token invalid or expired")
			return
		}
		h.Logger.Error("verify", "err", err)
		writeErr(w, http.StatusInternalServerError, CodeInternalError, "verification failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":    u,
		"message": "Verification complete.",
	})
}

type loginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body loginBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, "invalid json")
		return
	}

	u, err := h.Users.Authenticate(r.Context(), body.Email, body.Password, httpx.RealIPFrom(r.Context()), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, user.ErrAccountLocked):
			writeErr(w, http.StatusTooManyRequests, CodeAuthAccountLocked, "account temporarily locked")
		case errors.Is(err, user.ErrAccountNotActive):
			writeErr(w, http.StatusForbidden, CodeAuthNotActive, "verify your email and phone before logging in")
		default:
			writeErr(w, http.StatusUnauthorized, CodeAuthInvalidCredentials, "invalid credentials")
		}
		return
	}

	access, err := h.SignToken(auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID.String(),
			Issuer:    h.Issuer,
			Audience:  jwt.ClaimStrings{h.Audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(h.AccessTokenTTL) * time.Second)),
		},
		Role:    "user",
		KYCTier: u.KYCTier,
		AMR:     []string{"pwd"},
	})
	if err != nil {
		h.Logger.Error("sign token", "err", err)
		writeErr(w, http.StatusInternalServerError, CodeInternalError, "login failed")
		return
	}

	refresh, err := h.Users.IssueRefreshToken(r.Context(), u.ID,
		httpx.RealIPFrom(r.Context()), r.UserAgent())
	if err != nil {
		h.Logger.Error("issue refresh", "err", err)
		writeErr(w, http.StatusInternalServerError, CodeInternalError, "login failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":          u,
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    h.AccessTokenTTL,
	})
}

type refreshBody struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var body refreshBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, "invalid json")
		return
	}

	userID, newRefresh, err := h.Users.RotateRefreshToken(r.Context(), body.RefreshToken)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, CodeAuthRefreshInvalid, "invalid refresh token")
		return
	}

	u, err := h.Users.GetByID(r.Context(), userID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, CodeUserNotFound, "user not found")
		return
	}

	access, err := h.SignToken(auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID.String(),
			Issuer:    h.Issuer,
			Audience:  jwt.ClaimStrings{h.Audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(h.AccessTokenTTL) * time.Second)),
		},
		Role:    "user",
		KYCTier: u.KYCTier,
		AMR:     []string{"pwd"},
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, CodeInternalError, "token issuance failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": newRefresh,
		"token_type":    "Bearer",
		"expires_in":    h.AccessTokenTTL,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var body refreshBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, "invalid json")
		return
	}
	_ = h.Users.RevokeRefreshToken(r.Context(), body.RefreshToken)
	w.WriteHeader(http.StatusNoContent)
}

// ---- user handlers ----

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.MustClaims(r.Context())
	userID, _ := uuid.Parse(claims.Subject)
	u, err := h.Users.GetByID(r.Context(), userID)
	if err != nil {
		writeErr(w, http.StatusNotFound, CodeUserNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// ---- wallet handlers ----

type createWalletBody struct {
	Currency string `json:"currency"`
}

func (h *Handler) CreateWallet(w http.ResponseWriter, r *http.Request) {
	claims := auth.MustClaims(r.Context())
	userID, _ := uuid.Parse(claims.Subject)

	var body createWalletBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, "invalid json")
		return
	}
	if _, ok := money.Decimals(money.Currency(body.Currency)); !ok {
		writeErr(w, http.StatusBadRequest, CodeWalletCurrencyInvalid, "unsupported currency")
		return
	}

	wlt, err := h.Wallets.Create(r.Context(), h.Pool, userID, body.Currency)
	if err != nil {
		h.Logger.Error("create wallet", "err", err)
		writeErr(w, http.StatusInternalServerError, CodeInternalError, "could not create wallet")
		return
	}
	writeJSON(w, http.StatusCreated, wlt)
}

func (h *Handler) ListWallets(w http.ResponseWriter, r *http.Request) {
	claims := auth.MustClaims(r.Context())
	userID, _ := uuid.Parse(claims.Subject)
	ws, err := h.Wallets.ListByUser(r.Context(), h.read(), userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, CodeInternalError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

func (h *Handler) GetWallet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, CodeWalletInvalidID, "invalid wallet id")
		return
	}
	wlt, err := h.ownerCheckCached(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, wallet.ErrNotFound):
			writeErr(w, http.StatusNotFound, CodeWalletNotFound, "wallet not found")
		case errors.Is(err, errForbidden):
			writeErr(w, http.StatusForbidden, CodeForbidden, "forbidden")
		default:
			writeErr(w, http.StatusForbidden, CodeForbidden, "forbidden")
		}
		return
	}
	writeJSON(w, http.StatusOK, wlt)
}

func (h *Handler) GetWalletHistory(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, CodeWalletInvalidID, "invalid wallet id")
		return
	}
	if _, err := h.ownerCheckCached(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, wallet.ErrNotFound):
			writeErr(w, http.StatusNotFound, CodeWalletNotFound, "wallet not found")
		default:
			writeErr(w, http.StatusForbidden, CodeForbidden, "forbidden")
		}
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	entries, err := h.Ledger.History(r.Context(), h.read(), id, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, CodeInternalError, "history failed")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// ---- transfer handler ----

type transferBody struct {
	FromWalletID string `json:"from_wallet_id"`
	ToWalletID   string `json:"to_wallet_id"`
	Amount       string `json:"amount"`   // major units: "5000.50"
	Currency     string `json:"currency"` // "NGN"
	Reference    string `json:"reference"`
	EndToEndID   string `json:"end_to_end_id"`
}

func (h *Handler) Transfer(w http.ResponseWriter, r *http.Request) {
	claims := auth.MustClaims(r.Context())
	actorID, _ := uuid.Parse(claims.Subject)

	idemKey := r.Header.Get("Idempotency-Key")
	if idemKey == "" {
		writeErr(w, http.StatusBadRequest, CodePaymentIdempotencyKey, "Idempotency-Key header required")
		return
	}

	var body transferBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, "invalid json")
		return
	}
	fromID, err := uuid.Parse(body.FromWalletID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, CodeWalletInvalidID, "invalid from_wallet_id")
		return
	}
	toID, err := uuid.Parse(body.ToWalletID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, CodeWalletInvalidID, "invalid to_wallet_id")
		return
	}
	amount, err := money.ParseMajor(body.Amount, money.Currency(body.Currency))
	if err != nil {
		writeErr(w, http.StatusBadRequest, CodeRequestInvalidJSON, err.Error())
		return
	}

	if _, err := h.ownerCheck(r.Context(), fromID); err != nil {
		switch {
		case errors.Is(err, wallet.ErrNotFound):
			writeErr(w, http.StatusNotFound, CodeWalletNotFound, "source wallet not found")
		default:
			writeErr(w, http.StatusForbidden, CodeForbidden, "forbidden")
		}
		return
	}

	res, err := h.Payments.Transfer(r.Context(), actorID, payment.TransferRequest{
		FromWalletID: fromID,
		ToWalletID:   toID,
		Amount:       amount,
		Reference:    body.Reference,
		EndToEndID:   body.EndToEndID,
		IdemKey:      idemKey,
	})
	if err != nil {
		switch {
		case errors.Is(err, wallet.ErrInsufficientFunds):
			writeErr(w, http.StatusUnprocessableEntity, CodeTransferInsufficient, "insufficient funds")
		case errors.Is(err, wallet.ErrFrozen):
			writeErr(w, http.StatusUnprocessableEntity, CodeTransferWalletFrozen, "wallet frozen")
		case errors.Is(err, wallet.ErrCurrencyMismatch):
			writeErr(w, http.StatusUnprocessableEntity, CodeTransferCurrencyMismatch, "currency mismatch")
		case errors.Is(err, wallet.ErrNotFound):
			writeErr(w, http.StatusNotFound, CodeWalletNotFound, "wallet not found")
		case errors.Is(err, wallet.ErrStaleVersion):
			writeErr(w, http.StatusConflict, CodeTransferConflict, "concurrent modification, retry")
		case errors.Is(err, payment.ErrLimitExceeded):
			writeErr(w, http.StatusUnprocessableEntity, CodeTransferLimitExceeded, err.Error())
		case errors.Is(err, fraud.ErrBlocked):
			writeErr(w, http.StatusUnprocessableEntity, CodeTransferBlocked, "transaction blocked by fraud checks")
		case errors.Is(err, fraud.ErrReview):
			writeErr(w, http.StatusAccepted, CodeTransferReview, "transaction under review")

		default:
			h.Logger.Error("transfer", "err", err,
				"request_id", httpx.RequestIDFrom(r.Context()))
			writeErr(w, http.StatusInternalServerError, CodeInternalError, "transfer failed")
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"transaction_id":      res.TransactionID,
		"status":              res.Status,
		"new_balance_minor":   res.NewBalance,
		"new_balance_display": money.New(res.NewBalance, money.Currency(res.Currency)).Format(),
		"currency":            res.Currency,
	})
}
