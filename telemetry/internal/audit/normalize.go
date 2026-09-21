package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// maxRawBytes caps the forensic copy of a producer's payload. The pipeline
// must not be a way to push unbounded data into the audit store.
const maxRawBytes = 8 << 10

// FromLogLine classifies one structured JSON log line emitted by any
// component on stdout.
//
// It returns ok=false for lines that carry no security signal (startup
// banners, migration progress, health probes) so the audit trail stays a
// record of decisions rather than a copy of the log stream — raw log
// aggregation is Loki's job in this design.
func FromLogLine(line []byte, defaultService string) (Event, bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || trimmed[0] != '{' {
		return Event{}, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return Event{}, false
	}
	return FromMap(raw, defaultService)
}

// FromMap classifies an already-decoded structured record. Producers that push
// directly to the ingest API go through this too, so push and pull ingestion
// behave identically.
func FromMap(raw map[string]any, defaultService string) (Event, bool) {
	// Producers rarely send a flat record, and the envelope does not always
	// arrive as an object. The project's ABAC contract wraps the request in
	// {"input": {...}} (docs/division.md) and an OPA decision log nests the
	// verdict under "result"; a record exported through an OTel SDK carries the
	// same facts as dotted attribute names ("input.subject.user_id"), because
	// OTLP attributes are flat. Rebuilding the nesting first means the stored
	// decision does not depend on which of the two the producer chose.
	record := nestDottedKeys(raw)
	// Classification reads a flattened view; the original payload is kept for
	// forensics exactly as the producer wrote it.
	fields := flattenEnvelope(record)

	// OPA's own decision log is a security decision that happens to arrive in
	// OPA's house style: the verdict is an object under "result", the request is
	// under "input", and the event calls itself "Decision Log". Recognising it is
	// what makes `--set decision_logs.console=true` a complete integration for
	// the Policy Engine instead of one that needs a shim.
	if isOPADecisionLog(record) {
		fields["msg"] = "policy_decision"
		if _, exists := fields["request_id"]; !exists {
			fields["request_id"] = stringField(fields, "decision_id")
		}
	}

	event := Event{Raw: boundedRaw(raw)}

	event.EventType = stringField(fields, "msg", "event", "event_type", "event_name", "event.name", "name")
	event.Service = firstNonEmpty(
		stringField(fields, "service", "component", "service_name", "app"),
		defaultService,
		"unknown",
	)

	// Identity, trace context and request context are common to every shape.
	event.Subject = firstNonEmpty(
		stringField(fields, "user_id", "sub", "subject", "user", "username", "enduser.id"),
	)
	event.Roles = rolesField(fields)
	// Each lookup accepts both this project's field names and the OpenTelemetry
	// semantic conventions. A service exported by an OTel SDK names the same
	// facts http.request.method / url.path / http.response.status_code, and a
	// record that cannot be understood is a decision missing from the trail.
	event.Method = strings.ToUpper(stringField(fields,
		"method", "http_method", "http.request.method", "http.method"))
	event.Path = stringField(fields,
		"path", "url", "route", "request_path", "url.path", "http.target", "http.route")
	event.Status = intField(fields,
		"status", "status_code", "http_status", "http.response.status_code", "http.status_code")
	event.RemoteAddr = stringField(fields,
		"remote_addr", "ip", "client_ip", "remote_ip", "client.address", "net.peer.ip")
	event.TraceID, event.SpanID = parseTraceparent(stringField(fields, "traceparent", "trace_parent"))
	// An OpenTelemetry resource log carries its trace context as separate ids
	// rather than as a traceparent header.
	if event.TraceID == "" {
		event.TraceID = parseTraceID(stringField(fields, "trace_id", "traceId", "trace.id"))
	}
	event.RequestID = stringField(fields, "request_id", "trace_id_request", "x_request_id")
	event.DurationMS = int64Field(fields, "duration_ms", "latency_ms")
	event.Action = stringField(fields, "action", "operation")
	event.Resource = stringField(fields, "resource", "resource_id")
	event.OccurredAt = timeField(fields, "time", "ts", "timestamp", "occurred_at")

	// A gRPC service reports a gRPC status code, not an HTTP one. Without this
	// mapping its access logs carry no status the classifier recognises, and
	// every call it serves would be silently absent from the audit trail.
	if event.Status == 0 {
		event.Status = statusFromGRPC(fields)
	}
	// The RPC identity is filled in whenever the producer did not already give
	// an HTTP path: a gRPC service logs rpc.service/rpc.method, and dropping
	// them would leave the decision attributed to nobody.
	if event.Path == "" {
		if rpc := grpcMethod(fields); rpc != "" {
			event.Path = rpc
			if event.Method == "" {
				event.Method = "GRPC"
			}
		}
	}

	// Known event types carry known semantics. A login_attempt whose outcome is
	// "denied" means invalid credentials specifically, not merely "denied", so
	// classification wins for them and an explicit verdict only decides the
	// events we do not recognise.
	classified, ok := classify(event, fields)
	if !ok {
		return Event{}, false
	}
	event = classified

	if event.Reason == "" {
		event.Reason = firstNonEmpty(
			stringField(fields, "reason", "deny_reason", "error_code"),
			defaultReason(event.Decision),
		)
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.Message == "" {
		event.Message = summarise(event, fields)
	}
	if event.Category == "" {
		event.Category = CategoryAccess
	}
	if event.Decision == "" {
		event.Decision = DecisionInfo
	}
	event.ID = event.Fingerprint()
	return event, true
}

// classify maps a known event type onto a category and a verdict.
func classify(event Event, raw map[string]any) (Event, bool) {
	switch strings.ToLower(event.EventType) {
	case "http_request", "access", "request":
		if isProbe(raw, event.Path) {
			return Event{}, false
		}
		event.Category = CategoryAccess
		event.Decision, event.Reason = decisionForStatus(event.Status)
		// A specific reason from the component beats the generic status one.
		if explicit := stringField(raw, "reason", "deny_reason"); explicit != "" {
			event.Reason = explicit
		}

	case "login_attempt", "login", "authenticate":
		event.Category = CategoryAuth
		if isNegativeToken(stringField(raw, "outcome", "result")) {
			event.Decision, event.Reason = DecisionDeny, "invalid_credentials"
		} else {
			event.Decision, event.Reason = DecisionPermit, "authenticated"
		}

	case "access_decision", "authz_decision", "policy_decision", "authorize", "authz":
		event.Category = CategoryAuthz
		if isNegativeToken(stringField(raw, "decision", "allow", "result", "outcome", "permit")) {
			event.Decision, event.Reason = DecisionDeny, firstNonEmpty(
				stringField(raw, "reason"), "policy_denied")
		} else {
			event.Decision, event.Reason = DecisionPermit, "policy_allowed"
		}

	case "rate_limited", "rate_limit":
		event.Category = CategoryRateLimit
		event.Decision, event.Reason = DecisionDeny, "rate_limited"

	case "token_rejected":
		event.Category = CategoryAuth
		event.Decision = DecisionDeny
		event.Reason = firstNonEmpty(stringField(raw, "reason"), "invalid_token")

	case "upstream_error", "http_panic", "panic", "verification_unavailable",
		"readiness_check_failed", "token_issue_failed", "internal_error", "fatal":
		event.Category = CategoryError
		event.Decision = DecisionError
		event.Reason = firstNonEmpty(stringField(raw, "reason"), strings.ToLower(event.EventType))

	case "request_blocked", "access_denied", "forbidden", "unauthorized":
		event.Category = CategoryAccess
		event.Decision = DecisionDeny
		event.Reason = firstNonEmpty(stringField(raw, "reason"), strings.ToLower(event.EventType))

	default:
		// Unknown event name: an explicit verdict is the next best signal, then
		// the request shape.
		switch {
		case decisionField(raw) != "":
			event.Decision = decisionField(raw)
			event.Reason = stringField(raw, "reason", "deny_reason", "error_code")
			event.Category = categoryField(raw, event)
		case event.Status != 0:
			if isProbe(raw, event.Path) {
				return Event{}, false
			}
			event.Category = CategoryAccess
			event.Decision, event.Reason = decisionForStatus(event.Status)
		case verdictFromEventName(event.EventType) != "":
			// A component invented its own event name for a security outcome
			// ("mtls_handshake_rejected", "token_expired"). The name is the
			// only signal available, and missing it would leave a real denial
			// out of the audit trail entirely.
			event.Decision = verdictFromEventName(event.EventType)
			event.Category = categoryField(raw, event)
			event.Reason = firstNonEmpty(
				stringField(raw, "reason", "deny_reason", "error_code"),
				strings.ToLower(event.EventType),
			)
		case event.Action != "":
			event.Category = CategoryAuthz
			event.Decision, event.Reason = DecisionInfo, "unclassified_action"
		default:
			return Event{}, false
		}
	}

	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	return event, true
}

// probePaths are the operational endpoints every service exposes to its own
// platform.
//
// A health probe is not a security decision: it has no subject, no resource and
// no adversary, and at a 15 second interval one service produces thousands of
// them a day. Counting them would dilute the denial rate the dashboard exists to
// show and bury the decisions underneath — in a live run of this stack, 60 of 62
// events in a fifteen minute window were the IdP's own readiness probe. They are
// still in Loki; they are just not audit events.
var probePaths = map[string]bool{
	"/healthz": true, "/readyz": true, "/livez": true, "/health": true,
	"/health/live": true, "/health/ready": true, "/healthcheck": true,
	"/metrics": true, "/favicon.ico": true, "/robots.txt": true,
}

// isProbe reports whether a record is a bare probe line.
//
// Only the bare "GET /healthz 200" access line is dropped. A producer that
// attaches an explicit verdict, reason or action to the request is making a
// statement about it, and that statement is kept: a probe endpoint that starts
// refusing callers is a real signal.
func isProbe(raw map[string]any, path string) bool {
	if path == "" || !probePaths[strings.ToLower(strings.TrimSpace(path))] {
		return false
	}
	for _, key := range []string{"decision", "verdict", "outcome", "result", "allow", "reason", "deny_reason", "error_code", "action"} {
		if value, exists := raw[key]; exists && value != nil && strings.TrimSpace(fmt.Sprint(value)) != "" {
			return false
		}
	}
	return true
}

// defaultReason gives a verdict a non-empty label so the dashboard's
// "denials by reason" panel never has a blank row.
func defaultReason(decision Decision) string {
	switch decision {
	case DecisionPermit:
		return "allowed"
	case DecisionDeny:
		return "denied"
	case DecisionError:
		return "error"
	default:
		return ""
	}
}

// decisionForStatus maps an HTTP status onto a verdict.
func decisionForStatus(status int) (Decision, string) {
	switch {
	case status == 0:
		return DecisionInfo, ""
	case status == 401:
		return DecisionDeny, "unauthorized"
	case status == 403:
		return DecisionDeny, "forbidden"
	case status == 429:
		return DecisionDeny, "rate_limited"
	case status >= 500:
		return DecisionError, "server_error"
	case status >= 400:
		return DecisionDeny, "request_rejected"
	default:
		return DecisionPermit, "ok"
	}
}

// categoryField resolves an explicit category, defaulting sensibly.
func categoryField(raw map[string]any, event Event) Category {
	if category := strings.ToUpper(stringField(raw, "category")); category != "" {
		return Category(category)
	}
	if strings.EqualFold(event.EventType, "login_attempt") {
		return CategoryAuth
	}
	if event.Method != "" || event.Path != "" {
		return CategoryAccess
	}
	return CategoryAuthz
}

// decisionField normalises an explicit verdict from any of the spellings the
// components might use for it.
func decisionField(raw map[string]any) Decision {
	value := strings.ToLower(stringField(raw, "decision", "verdict", "outcome", "result"))
	switch value {
	case "permit", "permitted", "allow", "allowed", "true", "success", "ok":
		return DecisionPermit
	case "deny", "denied", "false", "blocked", "reject", "rejected", "failure", "refused":
		return DecisionDeny
	case "error", "failed":
		return DecisionError
	case "info":
		return DecisionInfo
	}
	// A boolean `allow` field (the Policy Engine's contract) lands here.
	if allowed, ok := raw["allow"].(bool); ok {
		if allowed {
			return DecisionPermit
		}
		return DecisionDeny
	}
	return ""
}

// isOPADecisionLog reports whether a record is one of OPA's decision logs.
//
// OPA names them with its own msg ("Decision Log") and, in the newer format,
// with a type of "openpolicyagent.org/decision_logs". Both are required to be
// accompanied by an input or a result, so a component that coincidentally logs
// the same phrase is not mistaken for the policy engine.
func isOPADecisionLog(raw map[string]any) bool {
	if typed := strings.ToLower(stringField(raw, "type")); strings.HasPrefix(typed, "openpolicyagent.org/decision_logs") {
		return true
	}
	if !strings.EqualFold(stringField(raw, "msg"), "Decision Log") {
		return false
	}
	_, hasInput := raw["input"]
	_, hasResult := raw["result"]
	return hasInput || hasResult
}

// nestedRoots are the field names whose nested objects are rebuilt from their
// dotted form.
//
// The list is closed on purpose. A record is full of legitimately dotted names
// ("http.request.method", "rpc.service", "http.response.status_code") and
// rebuilding those would destroy the very fields the classifier reads. Only the
// security envelope is reconstructed, and only when it did not arrive as an
// object.
var nestedRoots = map[string]bool{
	"input":   true,
	"result":  true,
	"subject": true,
	"context": true,
}

// nestDottedKeys turns "input.subject.user_id": "x" back into
// {"input": {"subject": {"user_id": "x"}}}, so a flattened record classifies
// exactly like a nested one.
//
// Without this, the same policy decision sent by an OTel exporter is stored
// with no subject, no role and no client address — or, when the flat form has
// no verdict field the classifier recognises, dropped altogether. That is the
// worst shape of bug this pipeline has: everything looks healthy and the trail
// is quietly missing what it exists to record.
func nestDottedKeys(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return raw
	}
	var nested map[string]any
	for key, value := range raw {
		root, rest, found := strings.Cut(key, ".")
		if !found || rest == "" || !nestedRoots[root] {
			continue
		}
		// A properly nested envelope always wins: a producer that sends both is
		// sending a contradiction, and the object is the more explicit of the two.
		if _, isObject := raw[root].(map[string]any); isObject {
			continue
		}
		if nested == nil {
			nested = make(map[string]any, len(raw))
			for field, original := range raw {
				nested[field] = original
			}
		}
		insertPath(nested, strings.Split(key, "."), value)
	}
	if nested == nil {
		return raw
	}
	return nested
}

// insertPath writes a value at a dotted path, creating the objects along it and
// leaving anything already there alone (the most specific key written wins).
func insertPath(target map[string]any, path []string, value any) {
	for _, part := range path[:len(path)-1] {
		if part == "" {
			return
		}
		child, ok := target[part].(map[string]any)
		if !ok {
			child = make(map[string]any)
			target[part] = child
		}
		target = child
	}
	if last := path[len(path)-1]; last != "" {
		if _, exists := target[last]; !exists {
			target[last] = value
		}
	}
}

// flattenEnvelope resolves the wrapper shapes the security components send.
//
// The Policy Engine's implemented contract is the nested one from
// docs/policymaker.md — {"input": {"subject": {"user_id", "roles"}, "context":
// {"ip_address", ...}}} — and OPA's decision log puts the verdict under
// "result". Merging those objects up (top-level fields win) means a policy
// decision is classified, attributed and joined to a trace exactly like a flat
// log line. Without the nested merge the trail records an authorisation denial
// with no subject, no role and no client address: a row that answers none of
// the questions it exists to answer.
func flattenEnvelope(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return raw
	}

	var merged map[string]any
	for _, key := range []string{"input", "result"} {
		envelope, ok := raw[key].(map[string]any)
		if !ok {
			continue
		}
		if merged == nil {
			merged = make(map[string]any, len(raw)+len(envelope))
			for field, value := range raw {
				merged[field] = value
			}
		}
		for field, value := range envelope {
			if _, exists := merged[field]; !exists {
				merged[field] = value
			}
		}
	}
	if merged == nil {
		return raw
	}

	// The ABAC contract carries the caller's address inside the context object
	// and the principal inside a subject object (docs/policymaker.md). The audit
	// trail wants both as first-class fields, or "which role was denied, from
	// where?" is unanswerable.
	promoteObject(merged, "subject", "user_id", "sub", "username", "roles", "role")
	if context, ok := merged["context"].(map[string]any); ok {
		for _, field := range []string{"ip_address", "ip", "remote_addr", "client_ip"} {
			if value, found := context[field]; found {
				if _, exists := merged["ip"]; !exists {
					merged["ip"] = value
				}
				break
			}
		}
	}
	return merged
}

// promoteObject copies selected fields out of a nested object into the flat
// view, without overwriting anything the producer already sent at the top
// level. The nested object itself is left in place, so `raw` still shows the
// record in the shape its producer wrote.
func promoteObject(merged map[string]any, object string, keys ...string) {
	nested, ok := merged[object].(map[string]any)
	if !ok {
		return
	}
	for _, key := range keys {
		value, found := nested[key]
		if !found {
			continue
		}
		if _, exists := merged[key]; !exists {
			merged[key] = value
		}
	}
}

// grpcStatusCodes maps the canonical gRPC status onto the HTTP status whose
// meaning the audit trail already uses, so one set of verdict rules covers both
// transports.
var grpcStatusCodes = map[int]int{
	0:  200, // OK
	1:  499, // CANCELLED
	2:  500, // UNKNOWN
	3:  400, // INVALID_ARGUMENT
	4:  504, // DEADLINE_EXCEEDED
	5:  404, // NOT_FOUND
	6:  409, // ALREADY_EXISTS
	7:  403, // PERMISSION_DENIED
	8:  429, // RESOURCE_EXHAUSTED
	9:  412, // FAILED_PRECONDITION
	10: 409, // ABORTED
	11: 400, // OUT_OF_RANGE
	12: 501, // UNIMPLEMENTED
	13: 500, // INTERNAL
	14: 503, // UNAVAILABLE
	15: 500, // DATA_LOSS
	16: 401, // UNAUTHENTICATED
}

// grpcStatusNames accepts the textual form of a gRPC status, which is what
// "grpc.code": "PERMISSION_DENIED" looks like in structured logs.
var grpcStatusNames = map[string]int{
	"OK": 0, "CANCELLED": 1, "UNKNOWN": 2, "INVALID_ARGUMENT": 3,
	"DEADLINE_EXCEEDED": 4, "NOT_FOUND": 5, "ALREADY_EXISTS": 6,
	"PERMISSION_DENIED": 7, "RESOURCE_EXHAUSTED": 8, "FAILED_PRECONDITION": 9,
	"ABORTED": 10, "OUT_OF_RANGE": 11, "UNIMPLEMENTED": 12, "INTERNAL": 13,
	"UNAVAILABLE": 14, "DATA_LOSS": 15, "UNAUTHENTICATED": 16,
}

// statusFromGRPC derives an HTTP-equivalent status from a gRPC status code.
//
// Only the namespaced keys are read: a bare "status" or "code" field belongs to
// whichever transport the producer already documented, and guessing there would
// misclassify an HTTP service.
func statusFromGRPC(raw map[string]any) int {
	code, ok := grpcStatusCode(raw)
	if !ok {
		return 0
	}
	return grpcStatusCodes[code]
}

func grpcStatusCode(raw map[string]any) (int, bool) {
	for _, key := range []string{"rpc.grpc.status_code", "grpc.status_code", "grpc.code", "rpc.status_code"} {
		if _, found := raw[key]; !found {
			continue
		}
		text := strings.TrimSpace(stringField(raw, key))
		if code, known := grpcStatusNames[strings.ToUpper(text)]; known {
			return code, true
		}
		code := intField(raw, key)
		if _, known := grpcStatusCodes[code]; known {
			return code, true
		}
	}
	return 0, false
}

// grpcMethod builds the canonical "/package.Service/Method" form from the
// attributes a gRPC server logs.
func grpcMethod(raw map[string]any) string {
	service := firstNonEmpty(
		stringField(raw, "rpc.service", "grpc.service"),
	)
	method := firstNonEmpty(
		stringField(raw, "rpc.method", "grpc.method"),
	)
	switch {
	case service == "" && method == "":
		return ""
	case service == "":
		return "/" + method
	case method == "":
		return "/" + service
	}
	return "/" + service + "/" + method
}

// verdictFromEventName infers a verdict from an event name a component coined
// itself.
//
// The rule is deliberately narrow: only the last underscore/dash/dot-separated
// word counts, and only words that are unambiguously about access are accepted.
// "..._failed" and "..._error" are excluded on purpose — an unknown failure is
// as likely to be an infrastructure hiccup as a security decision, and a
// security trail that fills up with retry warnings stops being read. A service
// that wants its own failure name audited adds it to the known event list.
func verdictFromEventName(name string) Decision {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ':' || r == ' '
	})
	if len(words) == 0 {
		return ""
	}

	switch words[len(words)-1] {
	case "denied", "deny", "rejected", "reject", "blocked", "block",
		"forbidden", "refused", "unauthorized", "unauthenticated",
		"invalid", "expired", "revoked":
		return DecisionDeny
	case "allowed", "allow", "granted", "permitted", "permit":
		return DecisionPermit
	}
	return ""
}

// summarise builds the one readable line the dashboard feed shows.
func summarise(event Event, raw map[string]any) string {
	switch {
	case event.Method != "" && event.Path != "" && event.Status != 0:
		return fmt.Sprintf("%d %s %s", event.Status, event.Method, event.Path)
	case event.Method != "" && event.Path != "":
		return fmt.Sprintf("%s %s", event.Method, event.Path)
	}
	if detail := stringField(raw, "error", "message", "detail"); detail != "" {
		return detail
	}
	return event.EventType
}

// Fingerprint derives the stable identity of an event. Ingesting the same
// record twice (a container restart re-reading its log file, a collector
// retrying a batch) must not double-count it in the audit trail.
//
// The raw payload carries most of the distinguishing detail, but the verdict
// fields are hashed too: a payload large enough to have been truncated to a
// placeholder would otherwise make two different decisions look identical, and
// silently dropping a decision is the worst failure this pipeline has.
func (e Event) Fingerprint() string {
	raw := ""
	if len(e.Raw) > 0 {
		if encoded, err := json.Marshal(e.Raw); err == nil {
			raw = string(encoded)
		}
	}
	return DeterministicID(
		e.Service,
		e.EventType,
		e.OccurredAt.UTC().Format(time.RFC3339Nano),
		string(e.Category),
		string(e.Decision),
		e.Reason,
		e.TraceID,
		e.SpanID,
		e.Method,
		e.Path,
		strconv.Itoa(e.Status),
		e.Subject,
		e.Message,
		raw,
	)
}

// DeterministicID hashes its inputs into a UUID-shaped identifier.
func DeterministicID(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	var id [16]byte
	copy(id[:], hash.Sum(nil)[:16])
	id[6] = (id[6] & 0x0f) | 0x40 // version 4
	id[8] = (id[8] & 0x3f) | 0x80 // variant 10
	return formatUUID(id)
}

// NewID returns a random UUID v4.
func NewID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return DeterministicID(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return formatUUID(id)
}

func formatUUID(b [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// parseTraceparent extracts trace and span ids from a W3C traceparent header
// value ("00-<32 hex>-<16 hex>-<01"), which is what ties an audit decision to
// the distributed trace it happened inside.
func parseTraceparent(value string) (traceID, spanID string) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) < 3 {
		return "", ""
	}
	if len(parts[1]) == 32 && isHex(parts[1]) {
		traceID = strings.ToLower(parts[1])
	}
	if len(parts[2]) == 16 && isHex(parts[2]) {
		spanID = strings.ToLower(parts[2])
	}
	return traceID, spanID
}

// parseTraceID accepts a bare 32-hex-character W3C trace id.
func parseTraceID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 32 && isHex(value) {
		return strings.ToLower(value)
	}
	return ""
}

func isHex(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// boundedRaw keeps a forensic copy of the payload without letting a producer
// push an unbounded blob into the store.
func boundedRaw(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	if len(encoded) > maxRawBytes {
		return map[string]any{"_truncated": true, "_bytes": len(encoded)}
	}
	return raw
}

// --- field helpers (tolerant, because five different producers feed this) ---

func stringField(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case json.Number:
			return typed.String()
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(typed)
		}
	}
	return ""
}

func intField(raw map[string]any, keys ...string) int {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return int(typed)
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				return int(parsed)
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
				return parsed
			}
		}
	}
	return 0
}

// int64Field is intField for the fields that hold millisecond durations; a
// duration that overflows an int32 would silently truncate on 32-bit builds.
func int64Field(raw map[string]any, keys ...string) int64 {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return int64(typed)
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				return parsed
			}
		case string:
			if parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func rolesField(raw map[string]any) []string {
	value, ok := raw["roles"]
	if !ok {
		if role := stringField(raw, "role"); role != "" {
			return []string{role}
		}
		return nil
	}
	switch typed := value.(type) {
	case []any:
		roles := make([]string, 0, len(typed))
		for _, item := range typed {
			if role, ok := item.(string); ok && strings.TrimSpace(role) != "" {
				roles = append(roles, strings.TrimSpace(role))
			}
		}
		return roles
	case []string:
		return typed
	case string:
		if typed == "" {
			return nil
		}
		parts := strings.Split(typed, ",")
		roles := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				roles = append(roles, part)
			}
		}
		return roles
	}
	return nil
}

// timeField accepts RFC3339 strings (what log/slog writes) as well as unix
// seconds/milliseconds, because not every producer uses slog.
func timeField(raw map[string]any, keys ...string) time.Time {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if parsed, err := time.Parse(time.RFC3339Nano, typed); err == nil {
				return parsed.UTC()
			}
			if parsed, err := time.Parse(time.RFC3339, typed); err == nil {
				return parsed.UTC()
			}
			if seconds, err := strconv.ParseFloat(typed, 64); err == nil {
				return fromUnix(seconds)
			}
		case float64:
			return fromUnix(typed)
		case json.Number:
			if seconds, err := typed.Float64(); err == nil {
				return fromUnix(seconds)
			}
		}
	}
	return time.Time{}
}

// fromUnix interprets a number as seconds or milliseconds depending on
// magnitude — 1e9-ish is seconds (2001+), 1e12-ish is milliseconds.
func fromUnix(value float64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	if value > 1e11 {
		return time.UnixMilli(int64(value)).UTC()
	}
	return time.Unix(int64(value), int64((value-float64(int64(value)))*1e9)).UTC()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// isNegativeToken recognises the many ways a producer writes "no".
func isNegativeToken(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "denied", "deny", "false", "fail", "failed", "failure", "reject", "rejected",
		"blocked", "no", "0", "unauthorized", "forbidden":
		return true
	}
	return false
}
