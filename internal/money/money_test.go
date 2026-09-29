package money

import (
	"errors"
	"math"
	"testing"
)

func TestParseMajorNGN(t *testing.T) {
	m, err := ParseMajor("5000.50", NGN)
	if err != nil {
		t.Fatal(err)
	}
	if m.Minor != 500050 || m.Currency != NGN {
		t.Fatalf("got %v", m)
	}
}

func TestParseMajorRejectsExcessPrecision(t *testing.T) {
	if _, err := ParseMajor("5000.555", NGN); !errors.Is(err, ErrPrecision) {
		t.Fatalf("expected ErrPrecision, got %v", err)
	}
}

func TestParseMajorJPYNoSubunit(t *testing.T) {
	m, err := ParseMajor("5000", JPY)
	if err != nil {
		t.Fatal(err)
	}
	if m.Minor != 5000 {
		t.Fatalf("got %d", m.Minor)
	}
	if _, err := ParseMajor("5000.5", JPY); !errors.Is(err, ErrPrecision) {
		t.Fatalf("expected ErrPrecision for JPY decimals, got %v", err)
	}
}

func TestParseMajorUnknownCurrency(t *testing.T) {
	if _, err := ParseMajor("1.00", "XXX"); !errors.Is(err, ErrUnknownCurrency) {
		t.Fatalf("expected ErrUnknownCurrency, got %v", err)
	}
}

func TestAddOverflow(t *testing.T) {
	a := New(math.MaxInt64, NGN)
	if _, err := a.Add(New(1, NGN)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("expected ErrOverflow, got %v", err)
	}
}

func TestSubOverflow(t *testing.T) {
	a := New(math.MinInt64, NGN)
	if _, err := a.Sub(New(1, NGN)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("expected ErrOverflow, got %v", err)
	}
}

func TestAddCurrencyMismatch(t *testing.T) {
	if _, err := New(1, NGN).Add(New(1, USD)); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("expected ErrCurrencyMismatch, got %v", err)
	}
}

func TestFormat(t *testing.T) {
	if got := New(500050, NGN).Format(); got != "NGN 5000.50" {
		t.Fatalf("got %q", got)
	}
}

func TestRequirePositive(t *testing.T) {
	if err := New(0, NGN).RequirePositive(); !errors.Is(err, ErrNegative) {
		t.Fatalf("expected ErrNegative for zero, got %v", err)
	}
	if err := New(-1, NGN).RequirePositive(); !errors.Is(err, ErrNegative) {
		t.Fatalf("expected ErrNegative for negative, got %v", err)
	}
	if err := New(1, NGN).RequirePositive(); err != nil {
		t.Fatalf("unexpected %v", err)
	}
}
