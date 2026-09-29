package main

import (
	"database/sql"
	"log/slog"
	"os"
	"payment-infra/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("DATABASE_URL required")
		os.Exit(1)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		logger.Error("open", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	goose.SetDialect("postgres")
	goose.SetSequential(true)

	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if err := goose.Run(cmd, db, "."); err != nil {
		logger.Error("migrate", "cmd", cmd, "err", err)
		os.Exit(1)
	}
	logger.Info("migration complete", "cmd", cmd)
}
