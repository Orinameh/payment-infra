package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"payment-infra/internal/audit"
	"payment-infra/internal/auth"
	"payment-infra/internal/crypto"
	"payment-infra/internal/fraud"
	"payment-infra/internal/httpapi"
	"payment-infra/internal/httpx"
	"payment-infra/internal/ledger"
	"payment-infra/internal/nibss"
	"payment-infra/internal/payment"
	"payment-infra/internal/platform/db"
	"payment-infra/internal/user"
	"payment-infra/internal/wallet"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── Database ──────────────────────────────────────────────────
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("DATABASE_URL required")
		os.Exit(1)
	}
	pool, err := db.Connect(ctx, dsn, 20)
	if err != nil {
		logger.Error("db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// ── JWT keys ──────────────────────────────────────────────────
	pubKey, err := os.ReadFile(envOr("JWT_PUBLIC_KEY_PATH", "/run/secrets/jwt_public.pem"))
	if err != nil {
		logger.Error("jwt public key", "err", err)
		os.Exit(1)
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(
		mustRead(envOr("JWT_PRIVATE_KEY_PATH", "/run/secrets/jwt_private.pem")))
	if err != nil {
		logger.Error("jwt private key", "err", err)
		os.Exit(1)
	}

	authenticator, err := auth.NewAuthenticator(pubKey,
		envOr("JWT_ISSUER", "payments-api"),
		envOr("JWT_AUDIENCE", "payments"))
	if err != nil {
		logger.Error("auth", "err", err)
		os.Exit(1)
	}

	// ── Encryption key (PII at rest) ──────────────────────────────
	encKey, err := crypto.KeyFromBase64(os.Getenv("ENCRYPTION_KEY_B64"))
	if err != nil {
		logger.Error("encryption key", "err", err)
		os.Exit(1)
	}
	if _, err := crypto.NewEncryptor(encKey); err != nil {
		logger.Error("encryption key", "err", err)
		os.Exit(1)
	}

	// ── Services ──────────────────────────────────────────────────
	auditRec := &audit.Recorder{}
	walletSvc := wallet.NewService(auditRec)
	ledgerSvc := ledger.NewService()
	fraudSvc := fraud.NewService(pool)
	userSvc := user.NewService(pool, auditRec)

	// NIBSS provider is optional. If NIBSS_MODE is unset, this
	// returns (nil, nil) and the payment service runs without
	// outbound bank transfers.
	nibssProvider, err := nibss.NewFromEnv()
	if err != nil {
		logger.Error("nibss init", "err", err)
		os.Exit(1)
	}

	var paymentOpts []payment.Option
	if nibssProvider != nil {
		paymentOpts = append(paymentOpts, payment.WithNIBSS(nibssProvider))
		logger.Info("nibss provider enabled", "mode", nibssProvider.Mode())
	}

	// Single construction of the payment service, with all options
	// applied. Do NOT create it twice.
	paymentSvc := payment.NewService(pool, walletSvc, ledgerSvc, fraudSvc, auditRec,
		paymentOpts...)

	// ── JWT signing ───────────────────────────────────────────────
	signToken := func(claims auth.Claims) (string, error) {
		t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		return t.SignedString(privKey)
	}

	// ── HTTP handler ──────────────────────────────────────────────
	h := &httpapi.Handler{
		Pool:           pool,
		Users:          userSvc,
		Wallets:        walletSvc,
		Payments:       paymentSvc,
		Ledger:         ledgerSvc,
		Logger:         logger,
		AccessTokenTTL: 900,
		Issuer:         envOr("JWT_ISSUER", "payments-api"),
		Audience:       envOr("JWT_AUDIENCE", "payments"),
		SignToken:      signToken,
	}

	mux := httpapi.NewRouter(h, authenticator, httpx.NewRateLimiter(10, 20))

	// ── Middleware chain (global only) ──────────────────────────
	// Auth and per-user rate limiting are applied per-route inside
	// NewRouter: public routes (register/login/healthz) must NOT require
	// a token, and RateLimit must run AFTER AuthRequired so it can key
	// on the JWT subject instead of just client IP.
	handler := httpx.Chain(mux,
		httpx.RequestID,
		httpx.RealIP,
		httpx.CORS(parseOrigins(os.Getenv("ALLOWED_ORIGINS"))),
		httpx.Metrics,
		httpx.Logging(logger),
		httpx.Recovery(logger),
	)

	// ── Server ────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:              ":" + envOr("PORT", "8443"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("api listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http", "err", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "err", err)
	}
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func parseOrigins(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, o := range strings.Split(s, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return b
}
