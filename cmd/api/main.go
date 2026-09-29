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
	"payment-infra/internal/cache"
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

	// ── Redis (optional balance cache) ──────────────────────────
	// If REDIS_ADDR is unset or unreachable, the API runs without a
	// cache — every balance read hits PostgreSQL. Cache absence must
	// never fail startup.
	var walletCache *cache.WalletCache
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb, err := cache.Connect(ctx, cache.Config{
			Addr:         addr,
			Password:     os.Getenv("REDIS_PASSWORD"),
			DialTimeout:  2 * time.Second,
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		})
		if err != nil {
			logger.Warn("redis unavailable, running without balance cache", "err", err)
		} else {
			defer func() { _ = rdb.Close() }()
			logger.Info("redis balance cache enabled", "addr", addr)
			walletCache = cache.NewWalletCache(rdb)
		}
	}

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

	// ── Encryption keyring (PII at rest) ──────────────────────────
	// Versioned: ENCRYPTION_KEYS="id:b64,..." (first is active) with
	// fallback to legacy ENCRYPTION_KEY_B64. Rotation never orphans
	// rows — envelopes carry their key id.
	enc, err := crypto.NewKeyRingFromEnv()
	if err != nil {
		logger.Error("encryption keyring", "err", err)
		os.Exit(1)
	}
	logger.Info("encryption keyring ready", "active", enc.ActiveID())

	// ── Services ──────────────────────────────────────────────────
	auditRec := &audit.Recorder{}
	walletSvc := wallet.NewService(auditRec)
	if walletCache != nil {
		walletSvc.SetCache(walletCache)
	}
	ledgerSvc := ledger.NewService()
	fraudSvc := fraud.NewService(pool)
	userSvc := user.NewService(pool, auditRec)
	userSvc.SetEncryptor(enc)

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
		DPOName:        os.Getenv("DPO_NAME"),
		DPOEmail:       os.Getenv("DPO_EMAIL"),
	}

	// Optional read replica. History and wallet lists go here; balance
	// reads stay on the primary (or cache) to avoid stale-read anomalies
	// after a client's own transfer.
	if readDSN := os.Getenv("READ_DATABASE_URL"); readDSN != "" {
		readPool, err := db.Connect(ctx, readDSN, 10)
		if err != nil {
			logger.Warn("read replica unavailable, reading from primary", "err", err)
		} else {
			defer readPool.Close()
			h.ReadPool = readPool
			logger.Info("read replica enabled")
		}
	}

	mux := httpapi.NewRouter(h, authenticator,
		httpx.NewRateLimiter(10, 20),
		// Public auth endpoints: strict per-IP budget (2 rps sustained,
		// burst 10). Login lockout is per-account; this is per-IP and
		// covers register/verify spam that lockout cannot see.
		httpx.NewRateLimiter(2, 10),
	)

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
