package money

import (
	"errors"
	"testing"
)

func TestMajorMinorRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		major string
		cur   Currency
		minor int64
	}{
		{"5000.50", NGN, 500050},
		{"0.01", USD, 1},
		{"5000", JPY, 5000},
	} {
		m, err := ParseMajor(tc.major, tc.cur)
		if err != nil {
			t.Fatal(err)
		}
		if m.Minor != tc.minor {
			t.Fatalf("%s: got %d want %d", tc.major, m.Minor, tc.minor)
		}
		back, err := ParseMajor(m.ToMajor().String(), tc.cur)
		if err != nil || back.Minor != tc.minor {
			t.Fatalf("round trip failed for %s: %v %v", tc.major, back, err)
		}
	}
}

func TestParseMajorOverflow(t *testing.T) {
	if _, err := ParseMajor("99999999999999999999999.00", NGN); !errors.Is(err, ErrOverflow) {
		t.Fatalf("expected ErrOverflow, got %v", err)
	}
}

func TestParseMajorGarbage(t *testing.T) {
	if _, err := ParseMajor("not-a-number", NGN); err == nil {
		t.Fatal("garbage input must fail")
	}
	if _, err := ParseMajor("", NGN); err == nil {
		t.Fatal("empty input must fail")
	}
}
