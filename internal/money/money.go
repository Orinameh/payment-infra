package money

import (
	"errors"
	"fmt"

	"github.com/shopspring/decimal"
)

type Currency string

const (
	NGN Currency = "NGN"
	USD Currency = "USD"
	EUR Currency = "EUR"
	GBP Currency = "GBP"
	JPY Currency = "JPY"
)

// decimals is the single source of truth for how many minor units make
// one major unit. NGN: 100 kobo = 1 naira. USD: 100 cents = 1 dollar.
// JPY: 1 yen (no subunit). KWD would be 1000 fils.
var decimals = map[Currency]int32{
	NGN: 2,
	USD: 2,
	EUR: 2,
	GBP: 2,
	JPY: 0,
}

var (
	ErrCurrencyMismatch = errors.New("money: currency mismatch")
	ErrUnknownCurrency  = errors.New("money: unknown currency")
	ErrPrecision        = errors.New("money: too many decimal places")
	ErrOverflow         = errors.New("money: amount overflows int64")
	ErrNegative         = errors.New("money: amount must be positive")
)

// Money is an exact integer amount in the currency's smallest unit
// (kobo, cents, pence). Never uses float64. Never rounds. The value is
// what it is — there is no representation error.
//
// Int64 range: ~9.2 quintillion minor units. In kobo that is
// ~92 quadrillion naira, roughly 1000× Nigeria's annual GDP. Sufficient.
type Money struct {
	Minor int64

	Currency Currency
}

func New(minor int64, c Currency) Money {
	return Money{Minor: minor, Currency: c}
}

// Decimals returns the number of decimal places for a currency.
func Decimals(c Currency) (int32, bool) {
	d, ok := decimals[c]
	return d, ok
}

// ParseMajor converts a major-unit string ("5000.50") into minor units
// (500050 kobo). Use this ONLY at API boundaries. Internal code never
// sees major units.
//
// Rejects inputs with more precision than the currency allows: parsing
// "5000.555" as NGN fails, because NGN has only 2 decimal places and
// silently rounding a client's input would be a correctness bug.
func ParseMajor(s string, c Currency) (Money, error) {
	_, ok := decimals[c]
	if !ok {
		return Money{}, ErrUnknownCurrency
	}
	d, err := decimal.NewFromString(s)
	if err != nil {
		return Money{}, fmt.Errorf("money: parse %q: %w", s, err)
	}
	return FromMajor(d, c)
}

func FromMajor(d decimal.Decimal, c Currency) (Money, error) {
	dec, ok := decimals[c]
	if !ok {
		return Money{}, ErrUnknownCurrency
	}
	shifted := d.Shift(dec)
	rounded := shifted.Round(0)
	if !rounded.Equal(shifted) {
		return Money{}, fmt.Errorf("%w: %s has more than %d decimal places",
			ErrPrecision, d, dec)
	}
	big := rounded.BigInt()
	if !big.IsInt64() {
		return Money{}, ErrOverflow
	}
	minor := big.Int64()
	return Money{Minor: minor, Currency: c}, nil
}

// ToMajor returns the major-unit decimal for display or ISO 20022
// message construction.
func (m Money) ToMajor() decimal.Decimal {
	dec := decimals[m.Currency]
	return decimal.New(m.Minor, 0).Shift(-dec)
}

// Format returns a human-readable string. Never parse this back.
func (m Money) Format() string {
	dec := decimals[m.Currency]
	return fmt.Sprintf("%s %s", m.Currency, m.ToMajor().StringFixed(dec))
}

func (m Money) IsZero() bool     { return m.Minor == 0 }
func (m Money) IsNegative() bool { return m.Minor < 0 }
func (m Money) IsPositive() bool { return m.Minor > 0 }
func (m Money) Neg() Money       { return Money{Minor: -m.Minor, Currency: m.Currency} }

func (m Money) Add(o Money) (Money, error) {
	if m.Currency != o.Currency {
		return Money{}, fmt.Errorf("%w: %s vs %s", ErrCurrencyMismatch, m.Currency, o.Currency)
	}
	sum := m.Minor + o.Minor
	// Overflow: same-sign operands producing an opposite-sign result.
	if ((m.Minor ^ sum) & (o.Minor ^ sum)) < 0 {
		return Money{}, fmt.Errorf("%w: %d + %d", ErrOverflow, m.Minor, o.Minor)
	}
	return Money{Minor: sum, Currency: m.Currency}, nil
}

func (m Money) Sub(o Money) (Money, error) {
	if m.Currency != o.Currency {
		return Money{}, fmt.Errorf("%w: %s vs %s", ErrCurrencyMismatch, m.Currency, o.Currency)
	}
	diff := m.Minor - o.Minor
	if ((m.Minor ^ o.Minor) & (m.Minor ^ diff)) < 0 {
		return Money{}, fmt.Errorf("%w: %d - %d", ErrOverflow, m.Minor, o.Minor)
	}
	return Money{Minor: diff, Currency: m.Currency}, nil
}

func (m Money) Cmp(o Money) (int, error) {
	if m.Currency != o.Currency {
		return 0, fmt.Errorf("%w: %s vs %s", ErrCurrencyMismatch, m.Currency, o.Currency)
	}
	switch {
	case m.Minor < o.Minor:
		return -1, nil
	case m.Minor > o.Minor:
		return 1, nil
	}
	return 0, nil
}

// RequirePositive returns an error if the amount is zero or negative.
// Use in every debit, credit, and transfer entry point.
func (m Money) RequirePositive() error {
	if m.Minor <= 0 {
		return fmt.Errorf("%w: got %d", ErrNegative, m.Minor)
	}
	return nil
}

func (m Money) String() string { return fmt.Sprintf("%d %s", m.Minor, m.Currency) }
