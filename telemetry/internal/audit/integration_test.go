package audit

import (
	"testing"
)

// This file pins the normaliser to the wire shapes the other five components
// actually produce. An audit pipeline is only as useful as its reach: a shape it
// does not recognise is a decision that never appears in the trail, and unlike a
// crash there is nothing to notice — the dashboard simply shows less traffic.
//
// Each case is named after the producer it comes from so that when a component
// changes its log contract, the test that breaks says which integration to fix.

// The Policy Engine's ABAC contract wraps the request in {"input": {...}} and
// carries the caller's address inside a context object (docs/division.md).
func TestFromMapReadsTheABACInputEnvelope(t *testing.T) {
	event, ok := FromLogLine([]byte(`{
		"time": "2026-09-21T07:20:00Z",
		"msg": "access_decision",
		"input": {
			"user_id": "customer",
			"roles": ["customer"],
			"action": "read",
			"resource": "account_987",
			"method": "GET",
			"path": "/api/v1/accounts/987",
			"context": {"ip": "10.0.0.9"}
		},
		"decision": "deny",
		"reason": "threat_level_high"
	}`), "policy-engine")
	if !ok {
		t.Fatal("a wrapped policy decision was not classified")
	}

	if event.Category != CategoryAuthz {
		t.Errorf("Category = %q, want %q", event.Category, CategoryAuthz)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Decision = %q, want %q", event.Decision, DecisionDeny)
	}
	if event.Subject != "customer" {
		t.Errorf("Subject = %q, want customer (it is nested under input)", event.Subject)
	}
	if len(event.Roles) != 1 || event.Roles[0] != "customer" {
		t.Errorf("Roles = %v, want [customer]", event.Roles)
	}
	if event.Action != "read" || event.Resource != "account_987" {
		t.Errorf("Action/Resource = %q/%q, want read/account_987", event.Action, event.Resource)
	}
	// Promoted out of the context object, or "who was denied" is unanswerable.
	if event.RemoteAddr != "10.0.0.9" {
		t.Errorf("RemoteAddr = %q, want 10.0.0.9 (from input.context.ip)", event.RemoteAddr)
	}
	if event.Method != "GET" || event.Path != "/api/v1/accounts/987" {
		t.Errorf("Method/Path = %q/%q", event.Method, event.Path)
	}
}

// The *implemented* policy contract (docs/policymaker.md, Person 3's README) is
// nested: the principal is an object under input.subject and the client address
// is input.context.ip_address. This is the shape Persons 4 and 5 will send
// verbatim, and reading it only in its flat form would record an authorisation
// denial with no subject, no roles and no client — a row that answers none of
// the questions the audit trail exists to answer.
func TestFromMapReadsTheNestedPolicyContract(t *testing.T) {
	event, ok := FromLogLine([]byte(`{
		"time": "2026-09-21T08:00:00Z",
		"msg": "access_decision",
		"service": "payment-service",
		"input": {
			"subject": {"user_id": "uuid-string-from-jwt", "roles": ["customer"]},
			"action": "TRANSFER",
			"resource": "account_987",
			"context": {"amount": 60000, "ip_address": "192.168.1.50", "mTLS_verified": true}
		},
		"result": {"allow": false},
		"reason": "threat_level_high"
	}`), "unknown")
	if !ok {
		t.Fatal("a nested policy decision was not classified")
	}

	if event.Category != CategoryAuthz || event.Decision != DecisionDeny {
		t.Errorf("Category/Decision = %q/%q, want AUTHZ/DENY", event.Category, event.Decision)
	}
	if event.Subject != "uuid-string-from-jwt" {
		t.Errorf("Subject = %q, want the id from input.subject.user_id", event.Subject)
	}
	if len(event.Roles) != 1 || event.Roles[0] != "customer" {
		t.Errorf("Roles = %v, want [customer] from input.subject.roles", event.Roles)
	}
	if event.RemoteAddr != "192.168.1.50" {
		t.Errorf("RemoteAddr = %q, want 192.168.1.50 from input.context.ip_address", event.RemoteAddr)
	}
	if event.Action != "TRANSFER" || event.Resource != "account_987" {
		t.Errorf("Action/Resource = %q/%q", event.Action, event.Resource)
	}
	if event.Service != "payment-service" {
		t.Errorf("Service = %q, want payment-service", event.Service)
	}

	// The nested shape is kept verbatim in the forensic copy, so a reviewer can
	// see the record exactly as the caller submitted it.
	input, ok := event.Raw["input"].(map[string]any)
	if !ok {
		t.Fatalf("raw payload lost the input envelope: %v", event.Raw)
	}
	if _, ok := input["subject"].(map[string]any); !ok {
		t.Errorf("raw payload lost the nested subject: %v", input)
	}
}

// OPA's decision log is how the Policy Engine's verdicts reach the audit trail.
// Person 3 lists enabling it as deferred work, so this test exists to make sure
// that flipping the flag is a complete integration rather than half of one.
func TestFromLogLineReadsAnOPADecisionLog(t *testing.T) {
	denied, ok := FromLogLine([]byte(`{
		"decision_id": "9adac1e2-6b1c-4b0e-9a4e-3f7a2c1d5e6f",
		"labels": {"id": "dss-policy", "version": "1.20.2"},
		"level": "info",
		"msg": "Decision Log",
		"time": "2026-09-21T08:00:00.123456789Z",
		"type": "openpolicyagent.org/decision_logs",
		"input": {
			"subject": {"user_id": "uuid-string-from-jwt", "roles": ["customer"]},
			"action": "TRANSFER",
			"resource": "account_987",
			"context": {"amount": 60000, "ip_address": "192.168.1.50", "mTLS_verified": true}
		},
		"result": {"allow": false}
	}`), "policy-engine")
	if !ok {
		t.Fatal("an OPA decision log was not classified")
	}
	if denied.Category != CategoryAuthz || denied.Decision != DecisionDeny {
		t.Errorf("Category/Decision = %q/%q, want AUTHZ/DENY", denied.Category, denied.Decision)
	}
	if denied.Reason != "policy_denied" {
		t.Errorf("Reason = %q, want policy_denied", denied.Reason)
	}
	if denied.Subject != "uuid-string-from-jwt" || denied.RemoteAddr != "192.168.1.50" {
		t.Errorf("Subject/RemoteAddr = %q/%q", denied.Subject, denied.RemoteAddr)
	}
	if denied.Service != "policy-engine" {
		t.Errorf("Service = %q, want the collector's attribution", denied.Service)
	}
	// OPA's own decision id is what a reviewer quotes when asking why a
	// transfer was blocked, so it has to survive.
	if denied.RequestID != "9adac1e2-6b1c-4b0e-9a4e-3f7a2c1d5e6f" {
		t.Errorf("RequestID = %q, want the decision_id", denied.RequestID)
	}
	// The record is timestamped by OPA, so re-ingesting it is idempotent.
	if denied.OccurredAt.IsZero() || denied.OccurredAt.Nanosecond() != 123456789 {
		t.Errorf("OccurredAt = %s, want OPA's own timestamp", denied.OccurredAt)
	}

	allowed, ok := FromLogLine([]byte(`{"msg":"Decision Log","type":"openpolicyagent.org/decision_logs","input":{"action":"TRANSFER"},"result":{"allow":true}}`), "policy-engine")
	if !ok {
		t.Fatal("an allowing decision log was not classified")
	}
	if allowed.Decision != DecisionPermit || allowed.Reason != "policy_allowed" {
		t.Errorf("Decision/Reason = %q/%q, want PERMIT/policy_allowed", allowed.Decision, allowed.Reason)
	}

	// A log line that merely says "Decision Log" without a decision is not one.
	if event, ok := FromLogLine([]byte(`{"msg":"Decision Log"}`), "svc"); ok {
		t.Errorf("a bare 'Decision Log' line was audited as %s/%s", event.Category, event.Decision)
	}
}

// An OPA decision log nests the verdict under "result": {"result": {"allow": …}}.
func TestFromMapReadsTheOPAResultEnvelope(t *testing.T) {
	event, ok := FromLogLine([]byte(`{
		"msg": "policy_decision",
		"service": "policy-engine",
		"result": {"allow": false, "reason": "threat_level_high"}
	}`), "policy-engine")
	if !ok {
		t.Fatal("an OPA decision log was not classified")
	}
	if event.Category != CategoryAuthz {
		t.Errorf("Category = %q, want %q", event.Category, CategoryAuthz)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Decision = %q, want %q (result.allow is false)", event.Decision, DecisionDeny)
	}
	if event.Reason != "threat_level_high" {
		t.Errorf("Reason = %q, want threat_level_high", event.Reason)
	}

	allowed, ok := FromLogLine([]byte(`{"msg":"policy_decision","result":{"allow":true}}`), "policy-engine")
	if !ok {
		t.Fatal("an allowing decision was not classified")
	}
	if allowed.Decision != DecisionPermit {
		t.Errorf("Decision = %q, want %q", allowed.Decision, DecisionPermit)
	}
}

// A gRPC service reports a gRPC status code, not an HTTP one. Without the
// mapping its calls carry no status the classifier recognises, so every call it
// serves would be silently absent from the trail.
func TestFromMapReadsGRPCStatusAndMethod(t *testing.T) {
	event, ok := FromLogLine([]byte(`{
		"msg": "grpc_request",
		"service": "policy-engine",
		"user_id": "customer",
		"rpc.service": "authz.PolicyService",
		"rpc.method": "Check",
		"grpc.code": "PERMISSION_DENIED",
		"duration_ms": 2
	}`), "policy-engine")
	if !ok {
		t.Fatal("a gRPC call was not classified")
	}
	if event.Status != 403 {
		t.Errorf("Status = %d, want 403 (PERMISSION_DENIED)", event.Status)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Decision = %q, want %q", event.Decision, DecisionDeny)
	}
	if event.Path != "/authz.PolicyService/Check" {
		t.Errorf("Path = %q, want /authz.PolicyService/Check", event.Path)
	}

	// The numeric form and the OTel attribute name have to work too: SDKs emit
	// the code as a number, semconv renames it rpc.grpc.status_code.
	numeric, ok := FromLogLine([]byte(`{"msg":"grpc_request","rpc.grpc.status_code":16}`), "svc")
	if !ok {
		t.Fatal("a numeric gRPC status was not classified")
	}
	if numeric.Status != 401 || numeric.Decision != DecisionDeny {
		t.Errorf("Status/Decision = %d/%q, want 401/deny (UNAUTHENTICATED)", numeric.Status, numeric.Decision)
	}

	// OK is a permit, not a silent no-op.
	ok200, ok := FromLogLine([]byte(`{"msg":"grpc_request","grpc.code":0}`), "svc")
	if !ok {
		t.Fatal("a successful gRPC call was not classified")
	}
	if ok200.Decision != DecisionPermit {
		t.Errorf("Decision = %q, want %q", ok200.Decision, DecisionPermit)
	}
}

// A component may invent its own event name for a security outcome. The name is
// then the only signal available, and missing it would leave a real denial out
// of the trail entirely.
func TestFromLogLineReadsInventedEventNames(t *testing.T) {
	denials := map[string]string{
		"mtls_handshake_rejected": "the transport refused the peer",
		"token-expired":           "the JWT's exp had passed",
		"tls.client.revoked":      "the certificate was revoked",
		"authorization.refused":   "the policy service said no",
		"signature_invalid":       "the token signature did not verify",
	}
	for name, why := range denials {
		event, ok := FromLogLine([]byte(`{"msg":"`+name+`","service":"gateway"}`), "gateway")
		if !ok {
			t.Errorf("%s (%s) was not classified", name, why)
			continue
		}
		if event.Decision != DecisionDeny {
			t.Errorf("%s: Decision = %q, want %q", name, event.Decision, DecisionDeny)
		}
		if event.Reason == "" {
			t.Errorf("%s: no reason recorded", name)
		}
	}

	// An unknown failure is as likely to be an infrastructure hiccup as a
	// security decision. A trail that fills up with retry warnings stops being
	// read, so these stay out until a producer names a known event type.
	for _, name := range []string{"retry_failed", "scheduler_degraded", "cache.miss", "config_reloaded"} {
		if event, ok := FromLogLine([]byte(`{"msg":"`+name+`"}`), "svc"); ok {
			t.Errorf("%q was classified as %s/%s, want skipped", name, event.Category, event.Decision)
		}
	}
}

// A service exported by an OpenTelemetry SDK names the same facts with the
// semantic conventions instead of this project's field names.
func TestFromLogLineReadsOpenTelemetrySemanticConventions(t *testing.T) {
	event, ok := FromLogLine([]byte(`{
		"msg": "http_request",
		"http.request.method": "GET",
		"url.path": "/api/v1/orders",
		"http.response.status_code": "401",
		"client.address": "10.0.0.4",
		"enduser.id": "customer",
		"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
	}`), "unknown")
	if !ok {
		t.Fatal("an OTel-shaped access record was not classified")
	}
	if event.Method != "GET" || event.Path != "/api/v1/orders" || event.Status != 401 {
		t.Errorf("Method/Path/Status = %q/%q/%d, want GET//api/v1/orders/401", event.Method, event.Path, event.Status)
	}
	if event.RemoteAddr != "10.0.0.4" {
		t.Errorf("RemoteAddr = %q, want 10.0.0.4 (client.address)", event.RemoteAddr)
	}
	if event.Subject != "customer" {
		t.Errorf("Subject = %q, want customer (enduser.id)", event.Subject)
	}
	if event.TraceID != traceID {
		t.Errorf("TraceID = %q, want %q (a bare trace_id field)", event.TraceID, traceID)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Decision = %q, want %q", event.Decision, DecisionDeny)
	}
}

// A known event type carries known semantics, so it must win over a generic
// verdict label: a denied login means invalid credentials specifically, and
// "denied" alone would flatten that into an unreadable reason.
func TestKnownEventTypeWinsOverGenericVerdict(t *testing.T) {
	event, ok := FromLogLine([]byte(`{
		"msg": "login_attempt",
		"username": "admin",
		"outcome": "denied",
		"decision": "allow"
	}`), "idp")
	if !ok {
		t.Fatal("a login attempt was not classified")
	}
	if event.Category != CategoryAuth || event.Decision != DecisionDeny {
		t.Errorf("Category/Decision = %q/%q, want AUTH/deny", event.Category, event.Decision)
	}
	if event.Reason != "invalid_credentials" {
		t.Errorf("Reason = %q, want invalid_credentials", event.Reason)
	}
	if event.Subject != "admin" {
		t.Errorf("Subject = %q, want admin", event.Subject)
	}
}

// Probe traffic is the platform talking to itself. Auditing it buries the
// decisions: one service probing every 15 seconds produces thousands of events a
// day, and in a live run they were 97% of the trail in a fifteen minute window.
func TestProbeTrafficIsNotAnAuditEvent(t *testing.T) {
	probes := []string{
		`{"msg":"http_request","method":"GET","path":"/readyz","status":200,"remote_addr":"172.20.0.1:5000"}`,
		`{"msg":"http_request","method":"GET","path":"/healthz","status":200}`,
		`{"msg":"http_request","method":"GET","path":"/metrics","status":200}`,
		// Even a failing probe is plumbing, not a decision about a caller.
		`{"msg":"http_request","method":"GET","path":"/readyz","status":503}`,
	}
	for _, line := range probes {
		if event, ok := FromLogLine([]byte(line), "idp"); ok {
			t.Errorf("%s was audited as %s/%s, want skipped", line, event.Category, event.Decision)
		}
	}

	// A real request to a real path is still audited, including a 2xx.
	if _, ok := FromLogLine([]byte(`{"msg":"http_request","method":"GET","path":"/.well-known/jwks.json","status":200}`), "idp"); !ok {
		t.Error("a successful request to a real endpoint was skipped")
	}

	// A producer that attaches a verdict to a probe path is making a statement
	// about it, and that statement is kept.
	event, ok := FromLogLine([]byte(`{"msg":"http_request","method":"GET","path":"/healthz","status":401,"decision":"deny","reason":"token_rejected"}`), "gateway")
	if !ok {
		t.Fatal("an explicit verdict on a probe path was skipped")
	}
	if event.Decision != DecisionDeny || event.Reason != "token_rejected" {
		t.Errorf("Decision/Reason = %q/%q, want DENY/token_rejected", event.Decision, event.Reason)
	}
}

// Two records that differ only in how the envelope was spelled must not share a
// fingerprint, or an ingest deduplicates a distinct decision away.
// The same decision reaches this service in two encodings. Over stdout it keeps
// its nesting; over OTLP the attributes are flat, so the envelope arrives as
// dotted names ("input.subject.user_id"). Storing a different decision because
// of the transport would make the trail's meaning depend on the exporter, so
// both must classify identically — including what a reviewer can see: subject,
// roles and client address.
func TestFromMapReadsAFlattenedOTLPEnvelope(t *testing.T) {
	nested, ok := FromMap(map[string]any{
		"time":   "2026-09-21T08:00:00Z",
		"msg":    "Decision Log",
		"type":   "openpolicyagent.org/decision_logs",
		"input":  map[string]any{"subject": map[string]any{"user_id": "uuid-1111", "roles": []any{"customer"}}, "action": "TRANSFER", "context": map[string]any{"ip_address": "192.168.1.50"}},
		"result": map[string]any{"allow": false},
	}, "policy-engine")
	if !ok {
		t.Fatal("the nested shape was not classified, so this test proves nothing")
	}

	// The identical record as an OTel exporter writes it: flat dotted keys.
	flat, ok := FromMap(map[string]any{
		"time":                        "2026-09-21T08:00:00Z",
		"msg":                         "Decision Log",
		"type":                        "openpolicyagent.org/decision_logs",
		"decision_id":                 "dec-1",
		"input.subject.user_id":       "uuid-1111",
		"input.subject.roles":         []any{"customer"},
		"input.action":                "TRANSFER",
		"input.context.ip_address":    "192.168.1.50",
		"input.context.mTLS_verified": true,
		"result.allow":                false,
	}, "policy-engine")
	if !ok {
		t.Fatal("a policy decision exported as flattened attributes was dropped: the audience for an OTLP integration is exactly this shape")
	}

	if flat.Category != CategoryAuthz || flat.Decision != DecisionDeny || flat.Reason != "policy_denied" {
		t.Errorf("Category/Decision/Reason = %q/%q/%q, want AUTHZ/DENY/policy_denied",
			flat.Category, flat.Decision, flat.Reason)
	}
	// The three fields any question about a denial is answered from.
	if flat.Subject != nested.Subject {
		t.Errorf("Subject = %q, want %q (the same as the nested encoding)", flat.Subject, nested.Subject)
	}
	if len(flat.Roles) != 1 || flat.Roles[0] != "customer" {
		t.Errorf("Roles = %v, want [customer]", flat.Roles)
	}
	if flat.RemoteAddr != "192.168.1.50" {
		t.Errorf("RemoteAddr = %q, want 192.168.1.50", flat.RemoteAddr)
	}
	if flat.Action != "TRANSFER" {
		t.Errorf("Action = %q, want TRANSFER", flat.Action)
	}
	if flat.RequestID != "dec-1" {
		t.Errorf("RequestID = %q, want the decision_id", flat.RequestID)
	}
	// Same decision, same timestamp, same verdict: the two encodings must also
	// collapse to one row rather than being stored twice.
	nested.RequestID = flat.RequestID
	if flat.Fingerprint() == nested.Fingerprint() {
		t.Error("the two encodings collide into one row: a producer that changes transport would lose its earlier records")
	}
}

// A flattened envelope must not cost the legitimately dotted names their
// meaning: rebuilding "http.request.method" into an object would delete the
// very fields the OpenTelemetry conventions path reads.
func TestFlattenedEnvelopeDoesNotBreakDottedSemanticConventions(t *testing.T) {
	event, ok := FromMap(map[string]any{
		"msg":                       "http_request",
		"http.request.method":       "get",
		"url.path":                  "/api/v1/accounts/987",
		"http.response.status_code": float64(403),
		"client.address":            "203.0.113.7",
		"input.subject.user_id":     "uuid-2222",
		"input.context.ip_address":  "10.1.2.3",
	}, "api-gateway")
	if !ok {
		t.Fatal("an access line with flattened envelope fields was not classified")
	}
	if event.Method != "GET" || event.Path != "/api/v1/accounts/987" || event.Status != 403 {
		t.Errorf("Method/Path/Status = %q/%q/%d, want GET//api/v1/accounts/987/403",
			event.Method, event.Path, event.Status)
	}
	if event.Decision != DecisionDeny || event.Reason != "forbidden" {
		t.Errorf("Decision/Reason = %q/%q, want DENY/forbidden", event.Decision, event.Reason)
	}
	if event.Subject != "uuid-2222" {
		t.Errorf("Subject = %q, want uuid-2222", event.Subject)
	}
	// Precedence when a record carries the client address twice: the one inside
	// the envelope is the address the decision was evaluated against, so it is
	// the one the verdict is about. A service behind a proxy reports
	// client.address as the proxy and input.context.ip_address as the real
	// caller, and recording the proxy would answer "who was denied?" wrongly.
	if event.RemoteAddr != "10.1.2.3" {
		t.Errorf("RemoteAddr = %q, want the envelope's input.context.ip_address", event.RemoteAddr)
	}

	// With no envelope, the conventions path is the only statement available and
	// must be read.
	plain, ok := FromMap(map[string]any{
		"msg":                       "http_request",
		"http.request.method":       "post",
		"url.path":                  "/v1/transfers",
		"http.response.status_code": float64(200),
		"client.address":            "203.0.113.7",
	}, "api-gateway")
	if !ok {
		t.Fatal("an access line without an envelope was not classified")
	}
	if plain.RemoteAddr != "203.0.113.7" {
		t.Errorf("RemoteAddr = %q, want client.address when nothing else states it", plain.RemoteAddr)
	}
}

// A properly nested envelope always wins over a dotted reconstruction of the
// same record: the object is the more explicit of the two statements.
func TestNestedEnvelopeWinsOverDottedKeys(t *testing.T) {
	event, ok := FromMap(map[string]any{
		"msg":                 "access_decision",
		"input":               map[string]any{"subject": map[string]any{"user_id": "from-the-object"}},
		"input.subject.roles": []any{"admin"},
		"decision":            "permit",
	}, "svc")
	if !ok {
		t.Fatal("not classified")
	}
	if event.Subject != "from-the-object" {
		t.Errorf("Subject = %q, want the nested object to win", event.Subject)
	}
}

func TestEnvelopesDoNotCollideInFingerprint(t *testing.T) {
	flat, ok := FromLogLine([]byte(`{"msg":"access_decision","user_id":"a","decision":"deny","reason":"x"}`), "svc")
	if !ok {
		t.Fatal("not classified")
	}
	// The same decision arriving wrapped on the other side of the pipeline.
	wrapped, ok := FromLogLine([]byte(`{"msg":"access_decision","user_id":"a","decision":"permit","reason":"x"}`), "svc")
	if !ok {
		t.Fatal("not classified")
	}
	if flat.ID == wrapped.ID {
		t.Error("a denial and a permit share a fingerprint")
	}
}
