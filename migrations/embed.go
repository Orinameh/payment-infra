package migrations

import "embed"

// FS embeds the *.sql files in this directory so the migrate binary
// carries them without needing a filesystem checkout (distroless
// runtime has no source tree).
//
//go:embed *.sql
var FS embed.FS
