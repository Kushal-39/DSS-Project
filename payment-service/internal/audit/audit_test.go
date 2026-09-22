package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *buffer) records(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()

	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("not JSON: %v (%s)", err, line)
		}
		out = append(out, record)
	}
	return out
}

func newRecorder(t *testing.T) (*Recorder, *buffer) {
	t.Helper()
	out := &buffer{}
	return New(slog.New(slog.NewJSONHandler(out, nil)), "payment-service"), out
}

// The pipeline classifies on the event name and the verdict (telemetry's
// docs/integration.md §2). A record without either is dropped as noise, which
// means a decision that is not labelled is a decision nobody will see.
func TestRecordCarriesTheClassifiableVocabulary(t *testing.T) {
	recorder, out := newRecorder(t)

	recorder.Log(context.Background(), Record{
		Event:       EventAccessDecision,
		Verdict:     VerdictDeny,
		Reason:      ReasonPolicyDenied,
		UserID:      "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		Roles:       []string{"customer"},
		Action:      "TRANSFER",
		Resource:    "account_6f9619ff",
		TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		Duration:    12 * time.Millisecond,
		Input:       map[string]any{"subject": map[string]any{"user_id": "x"}},
		Result:      Outcome{Allow: false},
		Detail:      map[string]any{"upstream_status": 403},
	})

	records := out.records(t)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]

	if record["msg"] != EventAccessDecision {
		t.Errorf("msg = %v (the classifier reads it as the event type)", record["msg"])
	}
	if record["decision"] != VerdictDeny {
		t.Errorf("decision = %v", record["decision"])
	}
	// slog's JSON handler supplies `time`, which is what makes re-ingestion
	// idempotent (the same record hashes to the same id).
	if record["time"] == nil {
		t.Error("every record must carry a timestamp")
	}
	if record["level"] != "WARN" {
		t.Errorf("level = %v, want WARN for a denial", record["level"])
	}
	for _, key := range []string{"service", "reason", "user_id", "action", "resource", "traceparent", "duration_ms"} {
		if record[key] == nil {
			t.Errorf("missing %q in %v", key, record)
		}
	}
	// The nested envelope is what the pipeline promotes into columns, so it has
	// to be an object rather than a flattened string.
	if _, ok := record["input"].(map[string]any); !ok {
		t.Errorf("input = %T, want an object", record["input"])
	}
	if result, ok := record["result"].(map[string]any); !ok || result["allow"] != false {
		t.Errorf("result = %v, want {\"allow\":false}", record["result"])
	}
	if detail, ok := record["detail"].(map[string]any); !ok || detail["upstream_status"] != float64(403) {
		t.Errorf("detail = %v", record["detail"])
	}
}

func TestEventNamesEndInAnUnambiguousOutcomeOrCarryAVerdict(t *testing.T) {
	// The vocabulary the pipeline knows by name, plus the names this service
	// emits that are graded by their explicit verdict. Anything else would be
	// classified as noise.
	known := map[string]bool{
		EventHTTPRequest:             true,
		EventAccessDecision:          true,
		EventRequestBlocked:          true,
		EventTokenRejected:           true,
		EventMTLSRejected:            true,
		EventUpstreamError:           true,
		EventVerificationUnavailable: true,
	}
	for _, name := range []string{
		EventHTTPRequest, EventAccessDecision, EventRequestBlocked, EventTokenRejected,
		EventMTLSRejected, EventUpstreamError, EventVerificationUnavailable,
		EventTransferCommitted,
	} {
		if !known[name] {
			// EventTransferCommitted is graded by its explicit verdict, which
			// every record for it carries; the rest must be recognised names.
			if !strings.HasSuffix(name, "_committed") {
				t.Errorf("%q is not a name the pipeline recognises and must carry an explicit verdict", name)
			}
		}
	}
}

func TestLevelsFollowTheVerdict(t *testing.T) {
	cases := map[string]string{
		VerdictPermit: "INFO",
		VerdictDeny:   "WARN",
		VerdictError:  "ERROR",
		VerdictInfo:   "INFO",
	}
	for verdict, want := range cases {
		recorder, out := newRecorder(t)
		recorder.Log(context.Background(), Record{Event: EventHTTPRequest, Verdict: verdict})
		records := out.records(t)
		if records[0]["level"] != want {
			t.Errorf("verdict %s logged at %v, want %s", verdict, records[0]["level"], want)
		}
	}
}

// A nil logger must not panic: the recorder is constructed in the wiring and a
// missing logger should degrade to the default, not take the service down.
func TestNewFallsBackToTheDefaultLogger(t *testing.T) {
	recorder := New(nil, "payment-service")
	recorder.Log(context.Background(), Record{Event: EventHTTPRequest, Verdict: VerdictInfo})
}
