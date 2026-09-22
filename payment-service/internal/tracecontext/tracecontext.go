// Package tracecontext implements the W3C Trace Context header
// (`traceparent`) that docs/flow.md §3 has the API Gateway inject and every
// later hop propagate.
//
// It exists so this service can do the three things Person 6's trace join
// needs: read the trace id it was called with, keep the same trace id when it
// calls the Policy Engine and the Account Service, and produce a *child* span
// id per outgoing call. Doing it with the standard library instead of an
// OpenTelemetry SDK keeps the money path free of a dependency whose exporter
// would sit inside the request path.
package tracecontext

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// Trace mirrors the four fields of the traceparent header.
//
// version(2) "-" trace-id(32) "-" parent-id(16) "-" flags(2)
type Trace struct {
	// Version is the traceparent version, "00" for the current spec.
	Version string
	// TraceID is the 32 lowercase hex character trace identifier.
	TraceID string
	// SpanID is the 16 lowercase hex character id of the span this header
	// belongs to.
	SpanID string
	// Flags carries the sampled bit in its low bit.
	Flags string
}

// Sampled reports whether the trace flags request that the trace be recorded.
func (t Trace) Sampled() bool {
	if len(t.Flags) != 2 {
		return false
	}
	value, err := hex.DecodeString(t.Flags)
	if err != nil {
		return false
	}
	return value[0]&0x01 == 0x01
}

// Header renders the canonical header value.
func (t Trace) Header() string {
	return t.Version + "-" + t.TraceID + "-" + t.SpanID + "-" + t.Flags
}

// Parse reads a traceparent header.
//
// It is deliberately strict about the parts the spec makes unambiguous
// (field count, lengths, lowercase hex, and the two all-zero ids that the spec
// forbids) because a malformed header that is accepted silently produces spans
// that never join to anything — the failure mode is invisible, which is worse
// than a rejected header that shows up in the logs.
func Parse(header string) (Trace, bool) {
	raw := strings.TrimSpace(header)
	// An empty header, or the all-zero value the spec defines as "not
	// sampled and no trace" (used by tracestate-only producers), is not a
	// usable context.
	if raw == "" {
		return Trace{}, false
	}

	parts := strings.Split(raw, "-")
	if len(parts) != 4 {
		return Trace{}, false
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]

	if version == "ff" || len(version) != 2 || !isLowerHex(version) {
		return Trace{}, false
	}
	if len(traceID) != 32 || !isLowerHex(traceID) || traceID == strings.Repeat("0", 32) {
		return Trace{}, false
	}
	if len(spanID) != 16 || !isLowerHex(spanID) || spanID == strings.Repeat("0", 16) {
		return Trace{}, false
	}
	if len(flags) != 2 || !isLowerHex(flags) {
		return Trace{}, false
	}
	return Trace{Version: version, TraceID: traceID, SpanID: spanID, Flags: flags}, true
}

// OrNew returns the parsed header, or a freshly generated trace when there is
// nothing usable to continue.
//
// The gateway is the first hop and normally supplies the header. Generating one
// anyway means a request that somehow arrives without it still produces
// correlatable evidence instead of untraceable logs.
//
// The caller's sampling decision is preserved (W3C TC §3.2.2.5): this service
// does not get to overrule it. It always emits its audit decisions either way,
// because the audit trail is a security record rather than telemetry sampling.
func OrNew(header string) Trace {
	if parsed, ok := Parse(header); ok {
		return parsed
	}
	return New()
}

// New generates a new trace rooted at a fresh span id, sampled.
func New() Trace {
	return Trace{
		Version: "00",
		TraceID: randomHex(16),
		SpanID:  randomHex(8),
		Flags:   "01",
	}
}

// Child returns a copy of the trace with a new span id, for an outgoing call.
// The trace id — the join key — is preserved; only the span identity changes,
// which is what makes a distributed flow a tree rather than a flat list.
func (t Trace) Child() Trace {
	return Trace{Version: t.Version, TraceID: t.TraceID, SpanID: randomHex(8), Flags: t.Flags}
}

// HeaderWithSpan renders the header for a specific span id.
func (t Trace) HeaderWithSpan(spanID string) string {
	return t.Version + "-" + t.TraceID + "-" + spanID + "-" + t.Flags
}

// NewSpanID returns a fresh 16 hex character span id.
func NewSpanID() string { return randomHex(8) }

// randomHex returns n random bytes as lowercase hex. crypto/rand (not math/rand)
// because a predictable trace id would let a caller forge a trace that joins to
// another flow's decisions.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is unrecoverable; an empty id makes the span
		// unusable, which is visible, rather than silently reused.
		return ""
	}
	return hex.EncodeToString(buf)
}

func isLowerHex(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return value != ""
}
