package money

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestParseAcceptsContractAmounts(t *testing.T) {
	cases := map[string]int64{
		"50":          5000,
		"50.0":        5000,
		"50.00":       5000,
		"0.01":        1,
		"0":           0,
		"99999999.99": 9999999999,
		"50000":       5000000,
	}
	for input, want := range cases {
		got, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q) returned error: %v", input, err)
		}
		if got.Cents() != want {
			t.Errorf("Parse(%q) = %d cents, want %d", input, got.Cents(), want)
		}
	}
}

func TestParseRejectsAnythingThatWouldNeedRounding(t *testing.T) {
	for _, input := range []string{
		"",             // empty
		`"50.00"`,      // a JSON string, not a number
		"5e1",          // exponent notation
		"50.001",       // sub-cent precision
		"-50",          // backwards money movement
		"+50",          // sign
		".5",           // no integer part
		"50.",          // bare decimal point
		"1,000",        // thousands separator
		"999999999.99", // exceeds DECIMAL(10,2)
		"0x10",         // not decimal
		"abc",
	} {
		if _, err := Parse(input); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q) error = %v, want ErrMalformed", input, err)
		}
	}
}

func TestStringIsCanonicalTwoDecimals(t *testing.T) {
	cases := map[int64]string{0: "0.00", 1: "0.01", 10: "0.10", 5000: "50.00", 9999999999: "99999999.99"}
	for cents, want := range cases {
		if got := FromCents(cents).String(); got != want {
			t.Errorf("FromCents(%d).String() = %q, want %q", cents, got, want)
		}
	}
	if got := FromCents(-5); !got.IsZero() {
		t.Errorf("FromCents(-5) = %v, want zero", got)
	}
}

// The Policy Request Contract compares the amount numerically, so it must be
// marshalled as a JSON number — a quoted string would be compared to 50000 as a
// string and denied by the engine's default-deny rule.
func TestMarshalJSONIsANumber(t *testing.T) {
	amount, err := Parse("50.00")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	encoded, err := json.Marshal(struct {
		Amount Amount `json:"amount"`
	}{Amount: amount})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(encoded) != `{"amount":50.00}` {
		t.Fatalf("encoded = %s, want {\"amount\":50.00}", encoded)
	}

	var decoded struct {
		Amount Amount `json:"amount"`
	}
	if err := json.Unmarshal([]byte(`{"amount":60000}`), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Amount.Cents() != 6000000 {
		t.Fatalf("decoded = %d cents, want 6000000", decoded.Amount.Cents())
	}

	if err := json.Unmarshal([]byte(`{"amount":"50.00"}`), &decoded); err == nil {
		t.Fatal("a quoted amount must be rejected")
	}
}
