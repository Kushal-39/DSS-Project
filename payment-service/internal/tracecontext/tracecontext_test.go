package tracecontext

import (
	"strings"
	"testing"
)

const validHeader = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestParseAcceptsTheSpecExample(t *testing.T) {
	trace, ok := Parse(validHeader)
	if !ok {
		t.Fatal("the example header from docs/flow.md §3 must parse")
	}
	if trace.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace id = %q", trace.TraceID)
	}
	if trace.SpanID != "00f067aa0ba902b7" {
		t.Errorf("span id = %q", trace.SpanID)
	}
	if !trace.Sampled() {
		t.Error("the sampled flag must be read")
	}
	if trace.Header() != validHeader {
		t.Errorf("Header() = %q, want the original", trace.Header())
	}
}

func TestParseRejectsMalformedHeaders(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"too few fields":     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
		"too many fields":    validHeader + "-extra",
		"short trace id":     "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
		"all-zero trace id":  "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"all-zero span id":   "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"uppercase hex":      "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"invalid version ff": "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"non-hex":            "00-4bf92f3577b34da6a3ce929d0e0e473z-00f067aa0ba902b7-01",
		"bad flags":          "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
	}
	for name, header := range cases {
		if _, ok := Parse(header); ok {
			t.Errorf("%s: %q must be rejected", name, header)
		}
	}
}

func TestOrNewKeepsTheTraceAndGeneratesWhenAbsent(t *testing.T) {
	continuing := OrNew(validHeader)
	if continuing.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("OrNew must preserve the incoming trace id, got %q", continuing.TraceID)
	}

	generated := OrNew("")
	if len(generated.TraceID) != 32 || len(generated.SpanID) != 16 {
		t.Fatalf("generated trace is not 32/16 hex characters: %+v", generated)
	}
	if generated.TraceID == continuing.TraceID {
		t.Error("a generated trace must not reuse the incoming trace id")
	}
	if _, ok := Parse(generated.Header()); !ok {
		t.Error("a generated header must parse back")
	}
}

// A child span keeps the join key and changes only the span identity — that is
// what makes a distributed flow a tree instead of a flat list.
func TestChildKeepsTheTraceIDAndChangesTheSpanID(t *testing.T) {
	parent, _ := Parse(validHeader)
	child := parent.Child()

	if child.TraceID != parent.TraceID {
		t.Errorf("child trace id = %q, want %q", child.TraceID, parent.TraceID)
	}
	if child.SpanID == parent.SpanID {
		t.Error("child span id must differ from the parent's")
	}
	if len(child.SpanID) != 16 {
		t.Errorf("child span id %q is not 16 hex characters", child.SpanID)
	}
	if !strings.HasPrefix(child.Header(), "00-"+parent.TraceID+"-") {
		t.Errorf("child header %q does not carry the parent trace id", child.Header())
	}
}

func TestNewSpanIDIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewSpanID()
		if len(id) != 16 {
			t.Fatalf("span id %q is not 16 hex characters", id)
		}
		if seen[id] {
			t.Fatalf("duplicate span id %q: the generator is not random", id)
		}
		seen[id] = true
	}
}
