package payments

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"paymentservice/internal/account"
	"paymentservice/internal/audit"
	"paymentservice/internal/config"
	"paymentservice/internal/metrics"
	"paymentservice/internal/money"
	"paymentservice/internal/policy"
	"paymentservice/internal/store"
	"paymentservice/internal/tracecontext"
	"paymentservice/internal/tracing"
)

const (
	senderID   = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
	receiverID = "8f9619ff-8b86-d011-b42d-00c04fc964fa"
	adminID    = "1f9619ff-8b86-d011-b42d-00c04fc964f1"
)

// lockedBuffer collects the audit trail the service writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) lines(t *testing.T) []map[string]any {
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
			t.Fatalf("audit line is not JSON: %v (%s)", err, line)
		}
		out = append(out, record)
	}
	return out
}

// find returns the first audit record with the given event type.
func find(t *testing.T, records []map[string]any, event string) map[string]any {
	t.Helper()
	for _, record := range records {
		if record["msg"] == event {
			return record
		}
	}
	t.Fatalf("no %q record in %v", event, eventTypes(records))
	return nil
}

func eventTypes(records []map[string]any) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, strings.TrimSpace(record["msg"].(string)))
	}
	return out
}

// stubEngine is a stand-in for Person 3's Policy Engine.
type stubEngine struct {
	server  *httptest.Server
	allow   bool
	status  int
	inputs  []policy.Input
	mu      sync.Mutex
	timeout time.Duration
}

func newEngine(t *testing.T, allow bool) *stubEngine {
	t.Helper()
	stub := &stubEngine{allow: allow, status: http.StatusOK}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Input policy.Input `json:"input"`
		}
		body, _ := json.Marshal(struct {
			Input policy.Input `json:"input"`
		}{Input: policy.Input{}})
		_ = body
		raw, _ := readAll(r)
		_ = json.Unmarshal(raw, &request)
		stub.mu.Lock()
		stub.inputs = append(stub.inputs, request.Input)
		stub.mu.Unlock()

		w.WriteHeader(stub.status)
		_, _ = w.Write([]byte(`{"result":{"allow":` + boolString(stub.allow) + `}}`))
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}

func (e *stubEngine) input(t *testing.T) policy.Input {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.inputs) == 0 {
		t.Fatal("the policy engine was never asked")
	}
	return e.inputs[len(e.inputs)-1]
}

func (e *stubEngine) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.inputs)
}

// stubAccount is a stand-in for Person 4's Account Service.
type stubAccount struct {
	server *httptest.Server
	status int
	calls  int
	mu     sync.Mutex
}

func newAccountService(t *testing.T, status int) *stubAccount {
	t.Helper()
	stub := &stubAccount{status: status}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.calls++
		stub.mu.Unlock()
		w.WriteHeader(stub.status)
		_, _ = w.Write([]byte(`{"status":"answered"}`))
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

func (a *stubAccount) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// failingStore is a ledger that cannot write, for the reconciliation case.
type failingStore struct{ store.Store }

func (failingStore) RecordTransaction(context.Context, store.Transaction) (store.Transaction, error) {
	return store.Transaction{}, errors.New("the ledger is on fire")
}
func (failingStore) Ping(context.Context) error { return nil }
func (failingStore) Kind() string               { return "failing" }
func (failingStore) Close()                     {}

type harness struct {
	service  *Service
	engine   *stubEngine
	accounts *stubAccount
	ledger   store.Store
	audit    *lockedBuffer
	cfg      *config.Config
}

func newHarness(t *testing.T, options harnessOptions) *harness {
	t.Helper()

	engine := newEngine(t, options.allow)
	if options.engineStatus != 0 {
		engine.status = options.engineStatus
	}
	accounts := newAccountService(t, options.deductStatus)

	policyClient, err := policy.New(policy.Options{URL: engine.server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	accountClient, err := account.New(account.Options{
		BaseURL: accounts.server.URL, Timeout: time.Second, AllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("account.New: %v", err)
	}

	cfg := &config.Config{
		ServiceName:          "payment-service",
		EnforceSenderBinding: options.enforceBinding,
		MaxTransfer:          mustAmount(t, "99999999.99"),
	}
	if options.noMaxTransfer {
		cfg.MaxTransfer = mustAmount(t, "100.00")
	}

	buffer := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(buffer, nil))

	ledger := store.Store(store.NewMemory())
	if options.ledgerFails {
		ledger = failingStore{}
	}

	tracer := tracing.New(tracing.Options{})
	if options.otlpURL != "" {
		tracer = tracing.New(tracing.Options{Endpoint: options.otlpURL, Timeout: time.Second})
	}

	service := New(Options{
		Config:   cfg,
		Store:    ledger,
		Policy:   policyClient,
		Accounts: accountClient,
		Audit:    audit.New(logger, cfg.ServiceName),
		Metrics:  metrics.New(),
		Tracer:   tracer,
		Logger:   logger,
		NewTxnID: func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
	})

	return &harness{
		service:  service,
		engine:   engine,
		accounts: accounts,
		ledger:   ledger,
		audit:    buffer,
		cfg:      cfg,
	}
}

type harnessOptions struct {
	allow          bool
	engineStatus   int
	deductStatus   int
	enforceBinding bool
	ledgerFails    bool
	noMaxTransfer  bool
	otlpURL        string
}

func mustAmount(t *testing.T, value string) money.Amount {
	t.Helper()
	parsed, err := money.Parse(value)
	if err != nil {
		t.Fatalf("Parse(%q): %v", value, err)
	}
	return parsed
}

func sampleTransfer(t *testing.T, value string) Transfer {
	t.Helper()
	return Transfer{SenderID: senderID, ReceiverID: receiverID, Amount: mustAmount(t, value)}
}

func customerContext() (Principal, Envelope) {
	return Principal{UserID: senderID, Roles: []string{"customer"}, DeviceID: "laptop"},
		Envelope{
			TraceParent:  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			Span:         tracecontext.Trace{Version: "00", TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7", Flags: "01"},
			RemoteAddr:   "192.168.1.50",
			RequestID:    "request-1",
			Bearer:       "Bearer the.jwt.token",
			MTLSVerified: true,
			MTLSIdentity: "gateway",
		}
}

func TestTransferCommitsWhenEverythingAllows(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: true, deductStatus: http.StatusOK, enforceBinding: true})
	principal, envelope := customerContext()

	result, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), principal, envelope)
	if failure != nil {
		t.Fatalf("Transfer refused: %v", failure)
	}
	if result.Transaction.TxnID != "11111111-2222-4333-8444-555555555555" {
		t.Errorf("txn_id = %q", result.Transaction.TxnID)
	}
	if result.Transaction.Amount.String() != "50.00" {
		t.Errorf("amount = %q", result.Transaction.Amount.String())
	}

	// The policy engine saw the contract input, with the mTLS state taken from
	// the connection rather than from anything the caller could set.
	input := h.engine.input(t)
	if input.Action != policy.ActionTransfer {
		t.Errorf("action = %q", input.Action)
	}
	if input.Resource != "account_"+senderID {
		t.Errorf("resource = %q", input.Resource)
	}
	if !input.Context.MTLSVerified {
		t.Error("context.mTLS_verified must reflect the verified connection")
	}
	if input.Context.IPAddress != "192.168.1.50" {
		t.Errorf("context.ip_address = %q", input.Context.IPAddress)
	}

	// Person 4 was asked exactly once, and the ledger holds exactly one row.
	if h.accounts.callCount() != 1 {
		t.Errorf("the account service was called %d times, want 1", h.accounts.callCount())
	}
	memory, ok := h.ledger.(*store.Memory)
	if !ok {
		t.Fatal("the harness must use the memory ledger")
	}
	if entries := memory.Entries(); len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}

	records := h.audit.lines(t)
	decision := find(t, records, audit.EventAccessDecision)
	if decision["decision"] != audit.VerdictPermit {
		t.Errorf("policy decision = %v, want PERMIT", decision["decision"])
	}
	if decision["action"] != policy.ActionTransfer {
		t.Errorf("the audit record must name the high-risk action explicitly, got %v", decision["action"])
	}
	committed := find(t, records, audit.EventTransferCommitted)
	if committed["decision"] != audit.VerdictPermit {
		t.Errorf("transfer verdict = %v, want PERMIT", committed["decision"])
	}
	if committed["txn_id"] == nil {
		if detail, ok := committed["detail"].(map[string]any); !ok || detail["txn_id"] == nil {
			t.Error("the committed record must identify the ledger row")
		}
	}
}

// A refusal must leave no side effect at all: no debit, no ledger row.
func TestTransferStopsBeforeTheDebitWhenPolicyDenies(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: false, deductStatus: http.StatusOK, enforceBinding: true})
	principal, envelope := customerContext()

	_, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "60000.00"), principal, envelope)
	if failure == nil {
		t.Fatal("a denied transfer must not be committed")
	}
	if failure.Status != statusForbidden {
		t.Errorf("status = %d, want 403 (docs/policymaker.md)", failure.Status)
	}
	if failure.Reason != audit.ReasonPolicyDenied {
		t.Errorf("reason = %q, want %q", failure.Reason, audit.ReasonPolicyDenied)
	}
	if h.accounts.callCount() != 0 {
		t.Fatal("no money may move when the policy engine refuses")
	}
	if memory := h.ledger.(*store.Memory); len(memory.Entries()) != 0 {
		t.Fatal("no ledger row may be written when the policy engine refuses")
	}

	decision := find(t, h.audit.lines(t), audit.EventAccessDecision)
	if decision["decision"] != audit.VerdictDeny {
		t.Errorf("decision = %v, want DENY", decision["decision"])
	}
	// The nested envelope is what Person 6's pipeline promotes into columns, so
	// the audit record has to carry it.
	input, ok := decision["input"].(map[string]any)
	if !ok {
		t.Fatalf("the audit record must carry the policy input, got %T", decision["input"])
	}
	subject, ok := input["subject"].(map[string]any)
	if !ok {
		t.Fatalf("the subject must be nested, got %T", input["subject"])
	}
	if subject["user_id"] != senderID {
		t.Errorf("input.subject.user_id = %v", subject["user_id"])
	}
	result, ok := decision["result"].(map[string]any)
	if !ok || result["allow"] != false {
		t.Errorf("the audit record must carry the engine's answer, got %v", decision["result"])
	}
}

// "The engine said no" and "the guard was down" are different incidents. The
// status code and the audit category must both keep them apart.
func TestTransferFailsClosedWhenThePolicyEngineIsDown(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: true, deductStatus: http.StatusOK, enforceBinding: true})
	principal, envelope := customerContext()
	h.engine.server.Close()

	_, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), principal, envelope)
	if failure == nil {
		t.Fatal("an unreachable policy engine must fail closed")
	}
	if failure.Status != statusForbidden {
		t.Errorf("status = %d, want 403 (Person 3's README: fail closed)", failure.Status)
	}
	if failure.Code != "policy_unavailable" {
		t.Errorf("code = %q, want policy_unavailable so the outage is distinguishable from a denial", failure.Code)
	}
	if h.accounts.callCount() != 0 {
		t.Fatal("no money may move when the guard is down")
	}

	record := find(t, h.audit.lines(t), audit.EventVerificationUnavailable)
	if record["decision"] != audit.VerdictError {
		t.Errorf("an unavailable guard must be an ERROR, not a denial, got %v", record["decision"])
	}
	if record["reason"] != audit.ReasonPolicyDown {
		t.Errorf("reason = %q", record["reason"])
	}
}

func TestTransferAbortsWhenTheAccountServiceRefuses(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: true, deductStatus: http.StatusForbidden, enforceBinding: true})
	principal, envelope := customerContext()

	_, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), principal, envelope)
	if failure == nil {
		t.Fatal("a refused deduction must abort the transfer")
	}
	// docs/contacts.md §Person 5: "If Person 4 returns an error, immediately
	// abort the process and return 400 Bad Request to the client."
	if failure.Status != statusBadRequest {
		t.Errorf("status = %d, want 400", failure.Status)
	}
	if failure.Code != "deduction_failed" {
		t.Errorf("code = %q", failure.Code)
	}
	if memory := h.ledger.(*store.Memory); len(memory.Entries()) != 0 {
		t.Fatal("a refused deduction must not produce a ledger row")
	}

	records := h.audit.lines(t)
	// The policy engine allowed it; the Account Service refused it. Both facts
	// are in the trail, under different event types.
	if decision := find(t, records, audit.EventAccessDecision); decision["decision"] != audit.VerdictPermit {
		t.Errorf("policy decision = %v, want PERMIT", decision["decision"])
	}
	blocked := find(t, records, audit.EventRequestBlocked)
	if blocked["decision"] != audit.VerdictDeny {
		t.Errorf("decision = %v, want DENY", blocked["decision"])
	}
	if blocked["reason"] != audit.ReasonDeductDenied {
		t.Errorf("reason = %q", blocked["reason"])
	}
	if blocked["action"] != policy.ActionTransfer {
		t.Errorf("the refusal must name the action it refused, got %v", blocked["action"])
	}
}

func TestTransferReportsAnUnavailableAccountServiceAsAnError(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: true, deductStatus: http.StatusInternalServerError, enforceBinding: true})
	principal, envelope := customerContext()

	_, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), principal, envelope)
	if failure == nil {
		t.Fatal("a 5xx from the account service must abort the transfer")
	}
	if failure.Status != statusBadRequest {
		t.Errorf("status = %d, want 400 (the contract's answer for an upstream error)", failure.Status)
	}

	record := find(t, h.audit.lines(t), audit.EventUpstreamError)
	if record["decision"] != audit.VerdictError {
		t.Errorf("decision = %v, want ERROR: the deduction's outcome is unknown", record["decision"])
	}
	if record["reason"] != audit.ReasonDeductUnavail {
		t.Errorf("reason = %q", record["reason"])
	}
}

// The worst case: the debit succeeded and the ledger row did not.
func TestTransferReportsALedgerFailureWithEvidenceForReconciliation(t *testing.T) {
	h := newHarness(t, harnessOptions{
		allow: true, deductStatus: http.StatusOK, enforceBinding: true, ledgerFails: true,
	})
	principal, envelope := customerContext()

	_, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), principal, envelope)
	if failure == nil {
		t.Fatal("a ledger failure must be reported, never swallowed")
	}
	if failure.Status != statusInternalServerError {
		t.Errorf("status = %d, want 500", failure.Status)
	}
	if failure.Code != "ledger_write_failed" {
		t.Errorf("code = %q", failure.Code)
	}

	record := find(t, h.audit.lines(t), audit.EventUpstreamError)
	if record["reason"] != audit.ReasonLedgerFailed {
		t.Errorf("reason = %q", record["reason"])
	}
	detail, ok := record["detail"].(map[string]any)
	if !ok {
		t.Fatalf("detail must be present, got %T", record["detail"])
	}
	for _, key := range []string{"sender_id", "receiver_id", "amount", "txn_id", "note"} {
		if detail[key] == nil {
			t.Errorf("the reconciliation record is missing %q: %v", key, detail)
		}
	}
	if !strings.Contains(strings.ToLower(detail["note"].(string)), "debit") {
		t.Errorf("the note must say the account was debited: %v", detail["note"])
	}
}

func TestTransferValidatesBeforeAskingAnyone(t *testing.T) {
	cases := map[string]struct {
		transfer Transfer
		failure  string
		options  harnessOptions
	}{
		"sender is not a uuid": {
			transfer: Transfer{ReceiverID: receiverID, Amount: money.FromCents(5000)},
			failure:  "invalid_sender_id",
		},
		"receiver is not a uuid": {
			transfer: Transfer{SenderID: senderID, Amount: money.FromCents(5000)},
			failure:  "invalid_receiver_id",
		},
		"zero amount": {
			transfer: Transfer{SenderID: senderID, ReceiverID: receiverID},
			failure:  "invalid_amount",
		},
		"self transfer": {
			transfer: Transfer{SenderID: senderID, ReceiverID: senderID, Amount: money.FromCents(5000)},
			failure:  "self_transfer_refused",
		},
		"above the configured maximum": {
			transfer: Transfer{SenderID: senderID, ReceiverID: receiverID, Amount: money.FromCents(20000)},
			failure:  "amount_too_large",
			options:  harnessOptions{noMaxTransfer: true},
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			options := testCase.options
			options.allow = true
			options.deductStatus = http.StatusOK
			options.enforceBinding = true
			h := newHarness(t, options)
			principal, envelope := customerContext()

			_, failure := h.service.Transfer(context.Background(), testCase.transfer, principal, envelope)
			if failure == nil {
				t.Fatal("the transfer must be refused")
			}
			if failure.Code != testCase.failure {
				t.Fatalf("code = %q, want %q", failure.Code, testCase.failure)
			}
			if failure.Status != statusBadRequest && failure.Status != statusForbidden {
				t.Errorf("status = %d, want a 4xx", failure.Status)
			}
			// Malformed input must never reach another service.
			if h.engine.callCount() != 0 {
				t.Error("the policy engine must not be asked about malformed input")
			}
			if h.accounts.callCount() != 0 {
				t.Error("the account service must not be called for malformed input")
			}
			record := find(t, h.audit.lines(t), audit.EventRequestBlocked)
			if record["decision"] != audit.VerdictDeny {
				t.Errorf("decision = %v, want DENY", record["decision"])
			}
		})
	}
}

func TestTransferBindsTheTokenToTheSenderAccount(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: true, deductStatus: http.StatusOK, enforceBinding: true})

	// A customer naming somebody else's account is the attack this control
	// exists for: the policy engine cannot catch it, because its rules are about
	// the action and the amount, not about who owns the named account.
	other := Principal{UserID: "99999999-8888-4777-8666-555555555555", Roles: []string{"customer"}}
	_, envelope := customerContext()

	_, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), other, envelope)
	if failure == nil {
		t.Fatal("a customer must not be able to debit an account that is not theirs")
	}
	if failure.Status != statusForbidden || failure.Code != "sender_mismatch" {
		t.Fatalf("failure = %+v, want 403 sender_mismatch", failure)
	}
	if h.engine.callCount() != 0 || h.accounts.callCount() != 0 {
		t.Fatal("nothing may be asked or debited for a mismatched sender")
	}

	// An admin may act on behalf of a customer: the Rego baseline grants admins
	// an override, and this mirrors it.
	admin := Principal{UserID: adminID, Roles: []string{"admin"}}
	if _, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), admin, envelope); failure != nil {
		t.Fatalf("an admin override must be honoured: %v", failure)
	}
}

func TestTransferCanBeConfiguredWithoutTheSenderBinding(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: true, deductStatus: http.StatusOK, enforceBinding: false})
	other := Principal{UserID: "99999999-8888-4777-8666-555555555555", Roles: []string{"customer"}}
	_, envelope := customerContext()

	if _, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), other, envelope); failure != nil {
		t.Fatalf("the binding is configurable and must be honoured when off: %v", failure)
	}
}

// The policy engine's Rego rule requires mTLS_verified, so this value decides
// whether a transfer is allowed at all. It must come from the connection.
func TestTransferPassesTheConnectionsMTLSState(t *testing.T) {
	h := newHarness(t, harnessOptions{allow: true, deductStatus: http.StatusOK, enforceBinding: true})
	principal, envelope := customerContext()
	envelope.MTLSVerified = false

	if _, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), principal, envelope); failure != nil {
		t.Fatalf("Transfer: %v", failure)
	}
	if input := h.engine.input(t); input.Context.MTLSVerified {
		t.Error("an unverified connection must be reported to the engine as such")
	}
}

func TestTransferExportsChildSpansForEachDependency(t *testing.T) {
	spans := make(chan map[string]any, 16)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []map[string]any `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		body, _ := readAll(r)
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("span payload is not OTLP/JSON: %v", err)
			return
		}
		for _, group := range payload.ResourceSpans {
			for _, scope := range group.ScopeSpans {
				for _, span := range scope.Spans {
					spans <- span
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	h := newHarness(t, harnessOptions{
		allow: true, deductStatus: http.StatusOK, enforceBinding: true, otlpURL: receiver.URL,
	})
	principal, envelope := customerContext()

	if _, failure := h.service.Transfer(context.Background(), sampleTransfer(t, "50.00"), principal, envelope); failure != nil {
		t.Fatalf("Transfer: %v", failure)
	}

	seen := map[string]bool{}
	deadline := time.After(3 * time.Second)
	for len(seen) < 3 {
		select {
		case span := <-spans:
			name, _ := span["name"].(string)
			seen[name] = true
			if span["traceId"] != envelope.Span.TraceID {
				t.Errorf("span %q exported under trace %v, want the request's trace %s",
					name, span["traceId"], envelope.Span.TraceID)
			}
			if span["parentSpanId"] != envelope.Span.SpanID {
				t.Errorf("span %q parent = %v, want this service's span %s",
					name, span["parentSpanId"], envelope.Span.SpanID)
			}
		case <-deadline:
			t.Fatalf("only %v were exported; a trace needs the dependency calls too", seen)
		}
	}
	for _, expected := range []string{"policy.authorize", "account.deduct", "ledger.insert"} {
		if !seen[expected] {
			t.Errorf("span %q was not exported", expected)
		}
	}
}

func TestNewDefaultsToAUUIDGenerator(t *testing.T) {
	service := New(Options{Config: &config.Config{MaxTransfer: money.FromCents(1000)}, Store: store.NewMemory()})
	id, err := service.newTxnID()
	if err != nil {
		t.Fatalf("newTxnID: %v", err)
	}
	if len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Errorf("generated id %q is not a UUID", id)
	}
}
