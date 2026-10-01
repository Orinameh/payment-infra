package nuban

import "testing"

// Vectors from the CBN NUBAN circular (First Bank, code 011).
func TestCBNVectors(t *testing.T) {
	if got, _ := CheckDigit("011", "000001457"); got != '9' {
		t.Fatalf("vector 1: got %c want 9", got)
	}
	if err := Validate("0000014579", "011"); err != nil {
		t.Fatalf("vector 1 must validate: %v", err)
	}
	if got, _ := CheckDigit("011", "000000022"); got != '0' {
		t.Fatalf("vector 2: got %c want 0", got)
	}
	if err := Validate("0000000220", "011"); err != nil {
		t.Fatalf("vector 2 must validate: %v", err)
	}
}

func TestTamperedDigitFails(t *testing.T) {
	if err := Validate("0000014578", "011"); err == nil {
		t.Fatal("wrong check digit must fail")
	}
	if err := Validate("0000014579", "058"); err == nil {
		t.Fatal("right number under wrong bank must fail")
	}
}

func TestGenerateRoundTrip(t *testing.T) {
	for i := 0; i < 50; i++ {
		acct, err := Generate("999")
		if err != nil {
			t.Fatal(err)
		}
		if len(acct) != 10 {
			t.Fatalf("must be 10 digits, got %q", acct)
		}
		if err := Validate(acct, "999"); err != nil {
			t.Fatalf("generated number must validate: %v", err)
		}
	}
}

func TestValidateBankCode(t *testing.T) {
	if err := ValidateBankCode("011"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "01", "0111", "ABC", "01X"} {
		if err := ValidateBankCode(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

func TestBadInputs(t *testing.T) {
	if err := Validate("123", "011"); err == nil {
		t.Fatal("short number must fail")
	}
	if err := Validate("000001457X", "011"); err == nil {
		t.Fatal("non-numeric must fail")
	}
	if _, err := Generate("01"); err == nil {
		t.Fatal("short bank code must fail")
	}
}
