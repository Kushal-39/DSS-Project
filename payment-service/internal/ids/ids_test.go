package ids

import (
	"strings"
	"testing"
)

func TestNewUUIDv4IsACanonicalVersion4Identifier(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := NewUUIDv4()
		if err != nil {
			t.Fatalf("NewUUIDv4: %v", err)
		}
		if !IsUUID(id) {
			t.Fatalf("%q is not a canonical UUID", id)
		}
		// Version 4 and variant 10 are what make the id a random identifier
		// rather than a predictable one, which matters for a ledger key.
		if id[14] != '4' {
			t.Fatalf("%q is not version 4", id)
		}
		if !strings.ContainsRune("89ab", rune(id[19])) {
			t.Fatalf("%q has the wrong variant nibble", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q — the generator is not random", id)
		}
		seen[id] = true
	}
}

func TestIsUUIDRejectsAnythingElse(t *testing.T) {
	valid := []string{
		"6f9619ff-8b86-d011-b42d-00c04fc964ff",
		"6F9619FF-8B86-D011-B42D-00C04FC964FF",
	}
	for _, value := range valid {
		if !IsUUID(value) {
			t.Errorf("IsUUID(%q) = false", value)
		}
	}

	invalid := []string{
		"",
		"nope",
		"6f9619ff8b86d011b42d00c04fc964ff",    // no separators
		"6f9619ff-8b86-d011-b42d-00c04fc964f", // too short
		"6f9619ff-8b86-d011-b42d-00c04fc964fff",
		"6f9619ff_8b86_d011_b42d_00c04fc964ff",
		"zz9619ff-8b86-d011-b42d-00c04fc964ff",
	}
	for _, value := range invalid {
		if IsUUID(value) {
			t.Errorf("IsUUID(%q) = true", value)
		}
	}

	if err := Validate("sender_id", "nope"); err == nil {
		t.Error("Validate must reject a non-UUID")
	} else if !strings.Contains(err.Error(), "sender_id") {
		t.Errorf("the error must name the field, got %v", err)
	}
	if err := Validate("sender_id", valid[0]); err != nil {
		t.Errorf("Validate rejected a valid UUID: %v", err)
	}
}
