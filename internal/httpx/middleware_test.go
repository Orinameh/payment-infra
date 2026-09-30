package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterBurstAndIsolation(t *testing.T) {
	rl := NewRateLimiter(0.001, 2) // ~never refills within the test
	if !rl.Allow("a") {
		t.Fatal("burst of 2 must allow two")
	}
	if rl.Allow("a") {
		t.Fatal("third immediate request must be denied")
	}
	if !rl.Allow("b") {
		t.Fatal("buckets must be per-key")
	}
}

func TestRequestIDPassthroughAndGeneration(t *testing.T) {
	echo := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(RequestIDFrom(r.Context())))
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", "fixed-id")
	w := httptest.NewRecorder()
	echo.ServeHTTP(w, r)
	if w.Body.String() != "fixed-id" || w.Header().Get("X-Request-ID") != "fixed-id" {
		t.Fatalf("must echo caller request id, got %q", w.Body.String())
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	echo.ServeHTTP(w2, r2)
	if w2.Body.String() == "" || w2.Header().Get("X-Request-ID") == "" {
		t.Fatal("must generate a request id when absent")
	}
}
