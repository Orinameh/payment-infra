package httpx

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"payment-infra/internal/auth"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	realIPKey
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "payments_http_requests_total",
	}, []string{"method", "path", "status"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "payments_http_duration_seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func RealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				host = strings.TrimSpace(strings.Split(xff, ",")[0])
			}
		}
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), realIPKey, host)))
	})
}

func RealIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(realIPKey).(string)
	return ip
}

func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFrom(r.Context()),
				"ip", RealIPFrom(r.Context()),
			}
			if claims, ok := auth.ClaimsFrom(r.Context()); ok {
				attrs = append(attrs, "user_id", claims.Subject)
			}
			logger.Info("http_request", attrs...)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(c int) {
	if !w.wrote {
		w.status = c
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(c)
}

func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic", "request_id", RequestIDFrom(r.Context()), "panic", rec)
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		// Use the route pattern (e.g. "GET /v1/wallets/{id}") as the
		// label, not the raw URL. Raw paths contain UUIDs — one series
		// per wallet would explode Prometheus cardinality.
		route := r.Pattern
		if route == "" {
			route = r.Method + " " + r.URL.Path
		}
		status := strconv.Itoa(sw.status)
		httpRequests.WithLabelValues(r.Method, route, status).Inc()
		httpDuration.WithLabelValues(r.Method, route).
			Observe(time.Since(start).Seconds())
	})
}

// CORS is a minimal allowlist-based CORS middleware. Browsers block
// cross-origin calls without these headers. AllowedOrigins should come
// from config (e.g. ALLOWED_ORIGINS=https://app.example.com). Empty
// means same-origin only: no Access-Control-Allow-Origin is set.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := map[string]struct{}{}
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o != "" {
			allowed[o] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := allowed[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-Request-ID")
					w.Header().Set("Access-Control-Max-Age", "600")
				}
				if r.Method == http.MethodOptions {
					if _, ok := allowed[origin]; ok {
						w.WriteHeader(http.StatusNoContent)
					} else {
						w.WriteHeader(http.StatusForbidden)
					}
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter is a per-key token bucket.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func NewRateLimiter(rate, burst float64) *RateLimiter {
	rl := &RateLimiter{buckets: map[string]*bucket{}, rate: rate, burst: burst}
	go rl.gc()
	return rl
}

func (rl *RateLimiter) gc() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.burst, lastSeen: now}
		rl.buckets[key] = b
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func RateLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := RealIPFrom(r.Context())
			if claims, ok := auth.ClaimsFrom(r.Context()); ok {
				key = claims.Subject
			}
			if !rl.Allow(key) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func AuthRequired(a *auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := a.Parse(r.Header.Get("Authorization"))
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithClaims(r.Context(), claims)))
		})
	}
}

func RequireMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := auth.ClaimsFrom(r.Context())
		if !ok || !c.HasMFA() {
			http.Error(w, `{"error":"MFA required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
