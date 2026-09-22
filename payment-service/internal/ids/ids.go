// Package ids holds the two identifier operations this service needs: minting a
// transaction id, and validating the UUIDs a caller sends.
//
// It is deliberately dependency-free (crypto/rand plus hex formatting, the same
// choice the IdP made) because a UUID library would be the service's only extra
// dependency for fifteen lines of code. The transaction id has to come from
// crypto/rand rather than math/rand: it is the primary key of a financial
// ledger row, and a predictable key is a forgeable one.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidUUID is returned for an identifier that is not a canonical UUID.
var ErrInvalidUUID = errors.New("not a valid UUID")

// NewUUIDv4 returns a random UUID v4 in canonical lowercase form.
func NewUUIDv4() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("ids: could not read randomness: %w", err)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10
	return format(buf), nil
}

// MustNewUUIDv4 is NewUUIDv4 for call sites that can only fail on a broken
// kernel entropy source. Panicking there is correct: without randomness this
// service cannot mint a safe identifier, and continuing would produce a ledger
// with guessable keys.
func MustNewUUIDv4() string {
	id, err := NewUUIDv4()
	if err != nil {
		panic(err)
	}
	return id
}

// IsUUID reports whether value is a canonical UUID (8-4-4-4-12 hex, with or
// without the version/variant nibbles set).
//
// The request contract (docs/contacts.md) types sender_id and receiver_id as
// UUIDs. Validating the shape before the policy check keeps malformed input out
// of the policy engine's decision log and out of the Account Service's SQL, and
// gives the caller a precise reason instead of a generic refusal.
func IsUUID(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) != 36 {
		return false
	}
	for index, r := range trimmed {
		switch index {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexDigit(r) {
				return false
			}
		}
	}
	return true
}

// Validate returns an error naming the field when the UUID is unusable.
func Validate(field, value string) error {
	if !IsUUID(value) {
		return fmt.Errorf("%w: %s must be a UUID", ErrInvalidUUID, field)
	}
	return nil
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func format(buf [16]byte) string {
	encoded := hex.EncodeToString(buf[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}
