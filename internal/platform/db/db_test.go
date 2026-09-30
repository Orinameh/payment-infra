package db

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsCheckViolation(t *testing.T) {
	if !IsCheckViolation(&pgconn.PgError{Code: "23514"}) {
		t.Fatal("23514 must be a check violation")
	}
	if IsCheckViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("23505 must not be a check violation")
	}
	if IsCheckViolation(errors.New("boom")) {
		t.Fatal("generic error must not match")
	}
	if IsCheckViolation(nil) {
		t.Fatal("nil must not match")
	}
}

func TestIsUniqueViolation(t *testing.T) {
	if !IsUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("23505 must be a unique violation")
	}
	if IsUniqueViolation(&pgconn.PgError{Code: "23514"}) {
		t.Fatal("23514 must not be a unique violation")
	}
}
