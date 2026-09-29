package nibss

import "errors"

var (
	// ErrNotImplemented is returned by the real Client until NIBSS
	// onboarding completes. Callers should treat it as a
	// configuration error, not a runtime failure.
	ErrNotImplemented = errors.New("nibss: real client not implemented — requires NIBSS onboarding and credentials")

	// ErrNotConfigured is returned when NIBSS is disabled (no
	// NIBSS_MODE set). Callers that require outbound transfers
	// should surface this as a user-facing "not available" error.
	ErrNotConfigured = errors.New("nibss: provider not configured")

	// ErrDummyInProduction is returned when NewFromEnv detects a
	// dummy provider being requested in a production environment.
	ErrDummyInProduction = errors.New("nibss: refusing to construct dummy client in production")
)
