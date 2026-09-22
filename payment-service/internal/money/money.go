// Package money is the exactly-representable decimal the payment path uses for
// money.
//
// Why not float64: 0.1 + 0.2 != 0.3, and a ledger whose arithmetic depends on
// binary rounding is a ledger that disagrees with the bank. Why not a decimal
// library: the amounts here have at most two fraction digits and at most eight
// integer digits — the `amount DECIMAL(10, 2)` column from docs/contacts.md —
// so a signed count of minor units (cents) is exact, cheap and dependency-free.
//
// Everything on this path is parsed strictly. A JSON number that is a string
// ("50.00"), carries an exponent (5e1), more than two decimals (50.001) or a
// sign (-50) is rejected rather than silently rounded: quietly shaving a
// fraction of a cent off a transfer is exactly the class of bug a financial
// service is not allowed to have.
package money

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrMalformed is returned for a value that is not a plain non-negative
// decimal with at most two fraction digits.
var ErrMalformed = errors.New("amount must be a plain decimal number with at most two fraction digits")

// maxIntDigits is the number of integer digits DECIMAL(10, 2) can hold (10
// total - 2 for the fraction).
const maxIntDigits = 8

// Amount is a non-negative monetary value in minor units (cents).
type Amount struct {
	cents int64
}

// Zero is the additive identity.
var Zero = Amount{}

// FromCents builds an Amount from minor units. Negative values are clamped to
// zero because no path in this service is allowed to move money backwards.
func FromCents(cents int64) Amount {
	if cents < 0 {
		return Zero
	}
	return Amount{cents: cents}
}

// Cents returns the value in minor units.
func (a Amount) Cents() int64 { return a.cents }

// IsZero reports whether the amount is zero (and therefore invalid as a
// transfer, which must move a positive sum).
func (a Amount) IsZero() bool { return a.cents == 0 }

// String renders the amount with exactly two fraction digits — the canonical
// form for both the SQL parameter and the JSON response, so a reader never has
// to ask whether "50" meant 50.00 or 50.0001.
func (a Amount) String() string {
	cents := a.cents
	if cents < 0 {
		cents = -cents
	}
	return strconv.FormatInt(cents/100, 10) + "." + fmt.Sprintf("%02d", cents%100)
}

// MarshalJSON emits the amount as a JSON number, not a string: the Policy
// Request Contract in docs/policymaker.md shows `"amount": 50.00`, and the Rego
// rules compare it numerically (`input.context.amount <= 50000`). A quoted
// string would make the engine compare a string to a number and deny by
// default.
func (a Amount) MarshalJSON() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalJSON parses an amount from a JSON number. Exponent and string forms
// are rejected (see Parse).
func (a *Amount) UnmarshalJSON(raw []byte) error {
	parsed, err := Parse(string(raw))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// Parse reads a plain decimal (the JSON number token form) into an Amount.
//
// Accepted: 50, 50.0, 50.00, 0.01, 99999999.99
// Rejected: "50" (a string), 5e1, 50.001, -50, .5, 50., 1,000
func Parse(raw string) (Amount, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return Zero, ErrMalformed
	}
	// json.Number preserves the literal the client sent; anything that is not a
	// JSON number token is rejected before we look at its digits.
	if _, err := strconv.ParseFloat(text, 64); err != nil {
		return Zero, fmt.Errorf("%w: %q is not a number", ErrMalformed, text)
	}
	if strings.ContainsAny(text, "eE+") {
		return Zero, fmt.Errorf("%w: %q uses exponent or sign notation", ErrMalformed, text)
	}

	whole, fraction, hasFraction := strings.Cut(text, ".")
	if whole == "" {
		return Zero, fmt.Errorf("%w: %q has no integer part", ErrMalformed, text)
	}
	if len(whole) > maxIntDigits {
		return Zero, fmt.Errorf("%w: %q exceeds the DECIMAL(10,2) range", ErrMalformed, text)
	}
	for _, r := range whole {
		if r < '0' || r > '9' {
			return Zero, fmt.Errorf("%w: %q is not a non-negative decimal", ErrMalformed, text)
		}
	}
	fractionDigits := 0
	if hasFraction {
		if fraction == "" {
			return Zero, fmt.Errorf("%w: %q has a decimal point with no fraction", ErrMalformed, text)
		}
		for _, r := range fraction {
			if r < '0' || r > '9' {
				return Zero, fmt.Errorf("%w: %q is not a decimal number", ErrMalformed, text)
			}
		}
		fractionDigits = len(fraction)
		if fractionDigits > 2 {
			// Rounding here would silently alter the amount the caller asked
			// for. Fractional cents have no representation in the ledger, so
			// the request is refused instead.
			return Zero, fmt.Errorf("%w: %q has more than two fraction digits", ErrMalformed, text)
		}
	}

	units, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return Zero, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	minor := int64(0)
	if fractionDigits > 0 {
		// "5" is 50 cents, "05" is 5 cents: normalise before scaling.
		minor, err = strconv.ParseInt(fraction+strings.Repeat("0", 2-fractionDigits), 10, 64)
		if err != nil {
			return Zero, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
	}
	return Amount{cents: units*100 + minor}, nil
}
