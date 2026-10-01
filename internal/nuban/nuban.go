package nuban

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

var (
	ErrBadLength     = errors.New("nuban: account number must be 10 digits")
	ErrNotNumeric    = errors.New("nuban: account number must be numeric")
	ErrBadBankCode   = errors.New("nuban: bank code must be 3 digits")
	ErrBadCheckDigit = errors.New("nuban: invalid check digit")
)

// weights is the CBN-approved NUBAN weight vector, applied to the
// 3-digit bank code followed by the 9-digit serial:
// https://www.cbn.gov.ng/OUT/2011/CIRCULARS/BSPD/NUBAN%20PROPOSALS%20V%200%204-%2003%2009%202010.PDF
var weights = [12]int{3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3}

func digits(s string) ([]int, error) {
	out := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return nil, ErrNotNumeric
		}
		out[i] = int(s[i] - '0')
	}
	return out, nil
}

// ValidateBankCode checks a CBN 3-digit institution code. Fail fast at
// startup: a bad code would otherwise fail every Generate at runtime.
func ValidateBankCode(code string) error {
	if len(code) != 3 {
		return ErrBadBankCode
	}
	_, err := digits(code)
	return err
}

// CheckDigit computes the NUBAN check digit for a 9-digit serial under
// a 3-digit bank code: weighted sum mod 10, subtracted from 10
// (10 maps to 0).
func CheckDigit(bankCode, serial string) (byte, error) {
	if len(bankCode) != 3 {
		return 0, ErrBadBankCode
	}
	if len(serial) != 9 {
		return 0, fmt.Errorf("nuban: serial must be 9 digits: %w", ErrBadLength)
	}
	ds, err := digits(bankCode + serial)
	if err != nil {
		return 0, err
	}
	sum := 0
	for i, d := range ds {
		sum += d * weights[i]
	}
	check := 10 - (sum % 10)
	if check == 10 {
		check = 0
	}
	return byte('0' + check), nil
}

// Validate reports whether account is a well-formed 10-digit NUBAN
// whose check digit matches bankCode. This is a format check only —
// it proves the number *can* exist, not that it does. Existence is
// proven by name enquiry.
func Validate(account, bankCode string) error {
	if len(account) != 10 {
		return ErrBadLength
	}
	want, err := CheckDigit(bankCode, account[:9])
	if err != nil {
		return err
	}
	if account[9] != want {
		return fmt.Errorf("%w: got %c want %c", ErrBadCheckDigit, account[9], want)
	}
	return nil
}

// Generate mints a random valid NUBAN under bankCode: random 9-digit
// serial (zero-padded) plus the computed check digit. Callers enforce
// global uniqueness (UNIQUE constraint + retry); the 10^9 serial space
// makes collisions negligible but not impossible.
func Generate(bankCode string) (string, error) {
	if len(bankCode) != 3 {
		return "", ErrBadBankCode
	}
	if _, err := digits(bankCode); err != nil {
		return "", err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
	if err != nil {
		return "", fmt.Errorf("nuban: entropy: %w", err)
	}
	serial := fmt.Sprintf("%09d", n.Int64())
	check, err := CheckDigit(bankCode, serial)
	if err != nil {
		return "", err
	}
	return serial + string(check), nil
}
