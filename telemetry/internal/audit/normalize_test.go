package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// The fixtures below are the real shapes the components in this monorepo emit.
// Classification that only works on invented payloads is worthless, so these
// strings are copied from the IdP's handlers (idp/internal/httpapi/server.go)
// and from the contract in docs/division.md.
const (
	// traceLine is the IdP's access log, with a traceparent the gateway injects.
	traceLine = `{"time":"2026-09-21T07:20:00.123456789Z","level":"INFO","msg":"http_request",` +
		`"method":"POST","path":"/login","status":401,"duration_ms":3,` +
		`"remote_addr":"172.20.0.1:5555","user_agent":"curl/8.6.0",` +
		`"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}`
	traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	spanID  = "00f067aa0ba902b7"
)

func TestFromLogLineClassifiesRealProducerShapes(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		wantOK       bool
		wantCategory Category
		wantDecision Decision
		wantReason   string
		wantSubject  string
		wantRoles    []string
		wantStatus   int
	}{
		{
			name:         "idp access log, rejected credentials",
			line:         traceLine,
			wantOK:       true,
			wantCategory: CategoryAccess,
			wantDecision: DecisionDeny,
			wantReason:   "unauthorized",
			wantStatus:   401,
		},
		{
			name:         "idp access log, healthy request",
			line:         `{"level":"INFO","msg":"http_request","method":"GET","path":"/.well-known/jwks.json","status":200}`,
			wantOK:       true,
			wantCategory: CategoryAccess,
			wantDecision: DecisionPermit,
			wantReason:   "ok",
			wantStatus:   200,
		},
		{
			name:         "idp access log, throttled at the perimeter",
			line:         `{"level":"INFO","msg":"http_request","method":"POST","path":"/login","status":429}`,
			wantOK:       true,
			wantCategory: CategoryAccess,
			wantDecision: DecisionDeny,
			wantReason:   "rate_limited",
			wantStatus:   429,
		},
		{
			name:         "idp failed login",
			line:         `{"level":"INFO","msg":"login_attempt","outcome":"denied","username":"admin"}`,
			wantOK:       true,
			wantCategory: CategoryAuth,
			wantDecision: DecisionDeny,
			wantReason:   "invalid_credentials",
			wantSubject:  "admin",
		},
		{
			name:         "idp successful login carries the subject and role",
			line:         `{"level":"INFO","msg":"login_attempt","outcome":"permit","user_id":"11111111-1111-4111-8111-111111111111","role":"admin"}`,
			wantOK:       true,
			wantCategory: CategoryAuth,
			wantDecision: DecisionPermit,
			wantReason:   "authenticated",
			wantSubject:  "11111111-1111-4111-8111-111111111111",
			wantRoles:    []string{"admin"},
		},
		{
			name:         "policy engine decision (the ABAC contract)",
			line:         `{"level":"INFO","msg":"access_decision","service":"policy-engine","allow":false,"reason":"threat_level_high","user_id":"customer","resource":"account_987"}`,
			wantOK:       true,
			wantCategory: CategoryAuthz,
			wantDecision: DecisionDeny,
			wantReason:   "threat_level_high",
			wantSubject:  "customer",
		},
		{
			name:         "policy engine permit",
			line:         `{"msg":"access_decision","service":"policy-engine","allow":true,"user_id":"customer"}`,
			wantOK:       true,
			wantCategory: CategoryAuthz,
			wantDecision: DecisionPermit,
			wantReason:   "policy_allowed",
			wantSubject:  "customer",
		},
		{
			name:         "gateway rate limiting",
			line:         `{"msg":"rate_limited","service":"api-gateway","user_id":"customer","remote_addr":"203.0.113.7"}`,
			wantOK:       true,
			wantCategory: CategoryRateLimit,
			wantDecision: DecisionDeny,
			wantReason:   "rate_limited",
		},
		{
			name:         "gateway token rejection",
			line:         `{"msg":"token_rejected","service":"api-gateway","reason":"signature_mismatch"}`,
			wantOK:       true,
			wantCategory: CategoryAuth,
			wantDecision: DecisionDeny,
			wantReason:   "signature_mismatch",
		},
		{
			name:         "readiness failure",
			line:         `{"level":"WARN","msg":"readiness_check_failed","error":"dial tcp: connection refused"}`,
			wantOK:       true,
			wantCategory: CategoryError,
			wantDecision: DecisionError,
			wantReason:   "readiness_check_failed",
		},
		{
			name:         "panic",
			line:         `{"level":"ERROR","msg":"http_panic","panic":"runtime error","path":"/x"}`,
			wantOK:       true,
			wantCategory: CategoryError,
			wantDecision: DecisionError,
		},
		{
			name:         "explicit deny verdict on an unknown event name",
			line:         `{"msg":"mystery_event","decision":"DENY","reason":"revoked","method":"DELETE","path":"/accounts/1"}`,
			wantOK:       true,
			wantDecision: DecisionDeny,
			wantReason:   "revoked",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, ok := FromLogLine([]byte(test.line), "producer")
			if ok != test.wantOK {
				t.Fatalf("ok = %v, want %v", ok, test.wantOK)
			}
			if !test.wantOK {
				return
			}
			if test.wantCategory != "" && event.Category != test.wantCategory {
				t.Errorf("category = %q, want %q", event.Category, test.wantCategory)
			}
			if event.Decision != test.wantDecision {
				t.Errorf("decision = %q, want %q", event.Decision, test.wantDecision)
			}
			if test.wantReason != "" && event.Reason != test.wantReason {
				t.Errorf("reason = %q, want %q", event.Reason, test.wantReason)
			}
			if test.wantSubject != "" && event.Subject != test.wantSubject {
				t.Errorf("subject = %q, want %q", event.Subject, test.wantSubject)
			}
			if test.wantRoles != nil && strings.Join(event.Roles, ",") != strings.Join(test.wantRoles, ",") {
				t.Errorf("roles = %v, want %v", event.Roles, test.wantRoles)
			}
			if test.wantStatus != 0 && event.Status != test.wantStatus {
				t.Errorf("status = %d, want %d", event.Status, test.wantStatus)
			}
			if event.ID == "" {
				t.Error("event has no id")
			}
			if event.OccurredAt.IsZero() {
				t.Error("event has no timestamp")
			}
			if event.Service == "" {
				t.Error("event has no service")
			}
		})
	}
}

func TestFromLogLineSkipsOperationalNoise(t *testing.T) {
	// These are real IdP log lines that carry no security signal. Copying the
	// log stream into the audit trail would bury the decisions, and Loki
	// already has them.
	noise := []string{
		`{"msg":"migrate: starting"}`,
		`{"msg":"seed: complete"}`,
		`{"msg":"db: connected","attempt":1}`,
		`{"msg":"db: ping failed, retrying","attempt":2,"error":"dial tcp: timeout"}`,
		`{"msg":"serve: listening","addr":":8080"}`,
		`not json at all`,
		``,
		`{"level":"INFO"}`,
	}
	for _, line := range noise {
		if event, ok := FromLogLine([]byte(line), "idp"); ok {
			t.Errorf("line %q was classified as %s/%s, want skipped", line, event.Category, event.Decision)
		}
	}
}

func TestFromLogLineExtractsTraceContext(t *testing.T) {
	event, ok := FromLogLine([]byte(traceLine), "idp")
	if !ok {
		t.Fatal("access log was not classified")
	}
	if event.TraceID != traceID {
		t.Errorf("trace_id = %q, want %q", event.TraceID, traceID)
	}
	if event.SpanID != spanID {
		t.Errorf("span_id = %q, want %q", event.SpanID, spanID)
	}
	if event.RemoteAddr != "172.20.0.1:5555" {
		t.Errorf("remote_addr = %q", event.RemoteAddr)
	}
	if event.DurationMS != 3 {
		t.Errorf("duration_ms = %d, want 3", event.DurationMS)
	}
}

func TestFromLogLineRejectsMalformedTraceparent(t *testing.T) {
	// A traceparent with an unusable trace id must not invent one; the event is
	// still recorded, it just cannot be joined to a trace.
	for _, value := range []string{"", "garbage", "00-short-00f067aa0ba902b7-01", "00-xyz-abc-01"} {
		line := `{"msg":"http_request","method":"GET","path":"/","status":200,"traceparent":"` + value + `"}`
		event, ok := FromLogLine([]byte(line), "idp")
		if !ok {
			t.Fatalf("line with traceparent %q was not classified", value)
		}
		if event.TraceID != "" {
			t.Errorf("traceparent %q produced trace_id %q, want empty", value, event.TraceID)
		}
	}
}

func TestFingerprintIsStableAndContentDerived(t *testing.T) {
	first, ok := FromLogLine([]byte(traceLine), "idp")
	if !ok {
		t.Fatal("not classified")
	}

	// The same record re-ingested (collector retry, container restart) must
	// produce the same id, or the audit trail double-counts every event.
	second, ok := FromLogLine([]byte(traceLine), "idp")
	if !ok {
		t.Fatal("not classified")
	}
	if first.ID != second.ID {
		t.Errorf("ids differ for identical records: %s vs %s", first.ID, second.ID)
	}

	different, ok := FromLogLine([]byte(strings.Replace(traceLine, "/login", "/token", 1)), "idp")
	if !ok {
		t.Fatal("not classified")
	}
	if first.ID == different.ID {
		t.Error("distinct records produced the same id")
	}
}

func TestFingerprintDistinguishesRecordsThatDifferOnlyInVerdict(t *testing.T) {
	// Two log lines can be byte-identical apart from the decision they record
	// (a permit and a denial of the same request, when the producer logs no
	// timestamp). Deduplicating them would silently drop a decision.
	denied, ok := FromMap(map[string]any{
		"msg": "access_decision", "service": "policy-engine", "method": "POST",
		"path": "/api/v1/payment", "status": 403, "decision": "deny",
	}, "policy-engine")
	if !ok {
		t.Fatal("not classified")
	}
	allowed, ok := FromMap(map[string]any{
		"msg": "access_decision", "service": "policy-engine", "method": "POST",
		"path": "/api/v1/payment", "status": 403, "decision": "permit",
	}, "policy-engine")
	if !ok {
		t.Fatal("not classified")
	}
	if denied.ID == allowed.ID {
		t.Errorf("a denial and a permit share the id %s", denied.ID)
	}

	// An oversized payload is truncated to a placeholder, so the fields that
	// survive truncation have to carry the identity.
	big := strings.Repeat("x", maxRawBytes+1024)
	one, _ := FromLogLine([]byte(`{"msg":"http_request","path":"/a","status":401,"blob":"`+big+`"}`), "idp")
	two, _ := FromLogLine([]byte(`{"msg":"http_request","path":"/b","status":403,"blob":"`+big+`"}`), "idp")
	if one.ID == two.ID {
		t.Errorf("two truncated records with different decisions share the id %s", one.ID)
	}
}

func TestBoundedRawTruncatesOversizedPayloads(t *testing.T) {
	// A producer must not be able to use the ingest API to push unbounded data
	// into the audit store.
	big := `{"msg":"http_request","path":"/","status":200,"blob":"` + strings.Repeat("x", maxRawBytes+1024) + `"}`
	event, ok := FromLogLine([]byte(big), "idp")
	if !ok {
		t.Fatal("not classified")
	}
	if truncated, _ := event.Raw["_truncated"].(bool); !truncated {
		t.Errorf("oversized raw payload was not truncated: %d keys", len(event.Raw))
	}
	encoded, err := json.Marshal(event.Raw)
	if err != nil {
		t.Fatalf("raw is not encodable: %v", err)
	}
	if len(encoded) > 256 {
		t.Errorf("stored raw payload is %d bytes, want a small placeholder", len(encoded))
	}
}

func TestParseEventsAcceptsObjectArrayAndEnvelope(t *testing.T) {
	record := `{"msg":"http_request","method":"POST","path":"/login","status":401}`

	tests := []struct {
		name  string
		body  string
		count int
	}{
		{"single object", record, 1},
		{"array", "[" + record + "," + record + "]", 2},
		{"events envelope", `{"events":[` + record + `,` + record + `]}`, 2},
		{"logs envelope", `{"logs":[` + record + `]}`, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events, _, err := ParseEvents([]byte(test.body), "producer")
			if err != nil {
				t.Fatalf("ParseEvents: %v", err)
			}
			if len(events) != test.count {
				t.Fatalf("got %d events, want %d", len(events), test.count)
			}
		})
	}
}

func TestParseEventsRejectsNonJSON(t *testing.T) {
	if _, _, err := ParseEvents([]byte("hello"), "producer"); err == nil {
		t.Error("plain text was accepted as an event payload")
	}
	if _, _, err := ParseEvents([]byte("   "), "producer"); err == nil {
		t.Error("empty payload was accepted")
	}
}

// TestParseLogsHandlesNewlineDelimitedBatches is the regression test for the
// bug the first end-to-end run found: a collector ships whatever a container
// printed, so a batch is a mixture of structured records and plain text. The
// whole batch used to be rejected with 400, which threw away the decisions
// sitting in the same batch.
func TestParseLogsHandlesNewlineDelimitedBatches(t *testing.T) {
	body := strings.Join([]string{
		traceLine,
		`{"msg":"db: ping failed, retrying","attempt":3,"error":"dial tcp: timeout"}`,
		`Starting the container...`, // not JSON at all
		`{"msg":"login_attempt","outcome":"denied","username":"admin"}`,
	}, "\n")

	events, skipped, err := ParseLogs([]byte(body), "idp")
	if err != nil {
		t.Fatalf("ParseLogs returned an error for a mixed batch: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (the access log and the failed login)", len(events))
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2 (one operational line, one plain text line)", skipped)
	}
}

func TestParseLogsAcceptsABatchWithNoSecuritySignal(t *testing.T) {
	// A batch of pure chatter is a successful delivery of nothing, not a
	// malformed request: the collector did its job.
	events, skipped, err := ParseLogs([]byte(
		"{\"msg\":\"serve: listening\"}\nplain text\n{\"msg\":\"migrate: complete\"}"), "idp")
	if err != nil {
		t.Fatalf("ParseLogs: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0", len(events))
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3", skipped)
	}
}

func TestParseLogsAcceptsPrettyPrintedEnvelope(t *testing.T) {
	pretty := "{\n  \"events\": [\n    {\"msg\":\"http_request\",\"method\":\"GET\",\"path\":\"/\",\"status\":200}\n  ]\n}"
	events, _, err := ParseLogs([]byte(pretty), "producer")
	if err != nil {
		t.Fatalf("ParseLogs: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
}

func TestParseLogsAcceptsASingleObjectAndNDJSONOfArrays(t *testing.T) {
	record := `{"msg":"http_request","method":"GET","path":"/","status":200}`

	events, _, err := ParseLogs([]byte(record), "producer")
	if err != nil || len(events) != 1 {
		t.Fatalf("single object: %d events, err %v", len(events), err)
	}

	events, _, err = ParseLogs([]byte("["+record+"]\n["+record+","+record+"]"), "producer")
	if err != nil {
		t.Fatalf("NDJSON of arrays: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("NDJSON of arrays: got %d events, want 3", len(events))
	}
}

func TestParseLogsRejectsEmptyAndUnparseable(t *testing.T) {
	if _, _, err := ParseLogs([]byte("  \n "), "producer"); err == nil {
		t.Error("an empty payload was accepted")
	}
	if _, _, err := ParseLogs([]byte("just some text"), "producer"); err == nil {
		t.Error("plain text was accepted")
	}
}

func TestFieldHelpersAreTolerant(t *testing.T) {
	// Five different producers feed this pipeline; the helpers must cope with
	// every reasonable way of writing the same thing.
	now := 1758440000.5
	event, ok := FromMap(map[string]any{
		"msg":         "http_request",
		"method":      "post",
		"path":        "/login",
		"status":      "401", // string status
		"duration_ms": 12.0,  // float duration
		"remote_addr": "203.0.113.7",
		"roles":       "admin, auditor", // comma-separated roles
		"time":        now,              // unix seconds as a float
	}, "producer")
	if !ok {
		t.Fatal("record was not classified")
	}
	if event.Method != "POST" {
		t.Errorf("method = %q, want POST", event.Method)
	}
	if event.Status != 401 {
		t.Errorf("status = %d, want 401", event.Status)
	}
	if event.DurationMS != 12 {
		t.Errorf("duration_ms = %d, want 12", event.DurationMS)
	}
	if len(event.Roles) != 2 || event.Roles[0] != "admin" || event.Roles[1] != "auditor" {
		t.Errorf("roles = %v, want [admin auditor]", event.Roles)
	}
	if got := event.OccurredAt.Unix(); got != int64(now) {
		t.Errorf("occurred_at = %d, want %d", got, int64(now))
	}
}

func TestFromMapPrefersTheProducersOwnServiceName(t *testing.T) {
	event, ok := FromMap(map[string]any{"msg": "http_request", "path": "/", "status": 200, "service": "api-gateway"}, "idp")
	if !ok {
		t.Fatal("not classified")
	}
	if event.Service != "api-gateway" {
		t.Errorf("service = %q, want the producer's own name", event.Service)
	}

	// The collector supplies a default when the producer stays anonymous,
	// which is exactly what the IdP's own logs require.
	event, ok = FromMap(map[string]any{"msg": "http_request", "path": "/", "status": 200}, "idp")
	if !ok {
		t.Fatal("not classified")
	}
	if event.Service != "idp" {
		t.Errorf("service = %q, want the collector's default", event.Service)
	}
}

func TestDeterministicIDIsUUIDShaped(t *testing.T) {
	id := DeterministicID("a", "b")
	if len(id) != 36 {
		t.Fatalf("id %q is not UUID shaped", id)
	}
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Errorf("id %q is missing its dashes", id)
	}
	if DeterministicID("a", "b") == DeterministicID("b", "a") {
		t.Error("id ignores field order, so distinct inputs collide")
	}
	if len(NewID()) != 36 {
		t.Error("NewID is not UUID shaped")
	}
}
