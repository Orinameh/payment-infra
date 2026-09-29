package nibss

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// NewFromEnv builds the NIBSS provider from environment variables.
//
//	NIBSS_MODE unset   → returns (nil, nil); outbound transfers disabled
//	NIBSS_MODE=dummy   → DummyClient; refused in production
//	NIBSS_MODE=real    → Client; requires credentials to be set
//
// A nil Provider with nil error means the feature is intentionally
// off. Callers must nil-check before use.
//
// The real mode performs only structural validation — the returned
// Client will refuse to send real traffic until Client.Transfer is
// implemented after NIBSS onboarding. This is by design: the wiring
// is in place, the implementation is not.
func NewFromEnv() (Provider, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("NIBSS_MODE")))
	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))

	switch mode {
	case "":
		slog.Info("nibss: disabled (NIBSS_MODE unset)")
		return nil, nil

	case "dummy":
		if env == "production" || env == "prod" {
			return nil, ErrDummyInProduction
		}
		p, err := NewDummyClient(DummyConfig{
			Environment: env,
			FailureRate: 0,
		})
		if err != nil {
			return nil, fmt.Errorf("nibss: dummy init: %w", err)
		}
		slog.Info("nibss: provider configured", "mode", p.Mode(), "environment", env)
		return p, nil

	case "real":
		p, err := NewClient(ClientConfig{
			BaseURL:         os.Getenv("NIBSS_BASE_URL"),
			InstitutionCode: os.Getenv("NIBSS_INSTITUTION_CODE"),
			SigningKeyPEM:   []byte(os.Getenv("NIBSS_SIGNING_KEY_PEM")),
			DESKeyB64:       os.Getenv("NIBSS_DES_KEY_B64"),
			Timeout:         15 * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("nibss: real init: %w", err)
		}
		slog.Info("nibss: provider configured",
			"mode", p.Mode(),
			"base_url", os.Getenv("NIBSS_BASE_URL"),
			"institution_code", os.Getenv("NIBSS_INSTITUTION_CODE"))
		return p, nil

	default:
		return nil, fmt.Errorf("nibss: unknown NIBSS_MODE %q (expected dummy|real or unset)", mode)
	}
}
