package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"paymentservice/internal/account"
	"paymentservice/internal/audit"
	"paymentservice/internal/certgen"
	"paymentservice/internal/config"
	"paymentservice/internal/jwtauth"
	"paymentservice/internal/metrics"
	"paymentservice/internal/money"
	"paymentservice/internal/mtls"
	"paymentservice/internal/payments"
	"paymentservice/internal/policy"
	"paymentservice/internal/store"
	"paymentservice/internal/tracecontext"
	"paymentservice/internal/tracing"
)

const (
	senderID    = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
	receiverID  = "8f9619ff-8b86-d011-b42d-00c04fc964fa"
	traceParent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
)

// ---------------------------------------------------------------------------
// Audit capture
// ---------------------------------------------------------------------------

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) records(t *testing.T) []map[string]any {
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

func findRecord(t *testing.T, records []map[string]any, event string) map[string]any {
	t.Helper()
	for _, record := range records {
		if record["msg"] == event {
			return record
		}
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, fmt.Sprint(record["msg"]))
	}
	t.Fatalf("no %q record among %v", event, names)
	return nil
}

func hasRecord(records []map[string]any, event string) bool {
	for _, record := range records {
		if record["msg"] == event {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The stack under test
// ---------------------------------------------------------------------------

type stack struct {
	url        string
	caFile     string
	certsDir   string
	engine     *engineStub
	accounts   *accountStub
	ledger     *store.Memory
	audit      *lockedBuffer
	registry   *metrics.Registry
	rejections chan mtls.Rejection
	// token signs a token the way Person 1's IdP would.
	token func(roles []string, subject string, expired bool) string
}

type engineStub struct {
	mu     sync.Mutex
	inputs []policy.Input
	// denyAbove refuses any transfer above this amount, mirroring the Rego
	// baseline's 50 000 fraud threshold.
	denyAbove int64
	down      bool
	server    *httptest.Server
}

func (e *engineStub) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Input policy.Input `json:"input"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("the engine received a payload it could not parse: %v", err)
		}
		e.mu.Lock()
		e.inputs = append(e.inputs, request.Input)
		down := e.down
		denyAbove := e.denyAbove
		e.mu.Unlock()

		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		allow := request.Input.Context.Amount.Cents() <= denyAbove
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"result":{"allow":%t}}`, allow)))
	}
}

func (e *engineStub) input(t *testing.T) policy.Input {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.inputs) == 0 {
		t.Fatal("the policy engine was never asked")
	}
	return e.inputs[len(e.inputs)-1]
}

func (e *engineStub) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.inputs)
}

type accountStub struct {
	mu     sync.Mutex
	status int
	calls  int
	server *httptest.Server
}

func (a *accountStub) setStatus(status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = status
}

func (a *accountStub) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func newStack(t *testing.T, mutate func(*config.Config)) *stack {
	t.Helper()

	// --- certificates -----------------------------------------------------
	certsDir := t.TempDir()
	if _, err := certgen.WriteBundle(certsDir, certgen.DefaultHosts, false); err != nil {
		t.Fatalf("certgen.WriteBundle: %v", err)
	}
	caFile := certsDir + "/" + certgen.CAFile

	// --- IdP: keys and tokens --------------------------------------------
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "test-key-1"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)

	token := func(roles []string, subject string, expired bool) string {
		expiry := time.Now().Add(15 * time.Minute)
		if expired {
			expiry = time.Now().Add(-time.Hour)
		}
		claims := jwt.MapClaims{
			"iss":       "http://idp:8080",
			"aud":       []string{"zerotrust-api-gateway"},
			"sub":       subject,
			"roles":     roles,
			"device_id": "test-device",
			"iat":       time.Now().Add(-time.Minute).Unix(),
			"exp":       expiry.Unix(),
		}
		signed := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed.Header["kid"] = kid
		value, err := signed.SignedString(key)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return value
	}

	// --- Policy Engine and Account Service -------------------------------
	engine := &engineStub{denyAbove: 5000000}
	engine.server = httptest.NewServer(engine.handler(t))
	t.Cleanup(engine.server.Close)

	accounts := &accountStub{status: http.StatusOK}
	accounts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accounts.mu.Lock()
		accounts.calls++
		status := accounts.status
		accounts.mu.Unlock()
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"answered"}`))
	}))
	t.Cleanup(accounts.server.Close)

	// --- configuration ----------------------------------------------------
	cfg := &config.Config{
		Addr:                   "127.0.0.1:0",
		ServiceName:            "payment-service",
		Store:                  config.StoreMemory,
		MaxBodyBytes:           4096,
		JWKSURL:                jwks.URL,
		JWTAudience:            "zerotrust-api-gateway",
		JWTClockSkew:           30 * time.Second,
		JWKSRefreshInterval:    5 * time.Minute,
		JWKSUnknownKidInterval: 10 * time.Second,
		PolicyURL:              engine.server.URL,
		PolicyTimeout:          2 * time.Second,
		AccountServiceURL:      accounts.server.URL,
		AccountServiceTimeout:  2 * time.Second,
		AllowInsecureUpstream:  true,
		MaxTransfer:            mustAmount(t, "99999999.99"),
		EnforceSenderBinding:   true,
		AllowedClientIDs:       []string{"gateway", "account-service"},
	}
	if mutate != nil {
		mutate(cfg)
	}

	// --- collaborators ----------------------------------------------------
	buffer := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(buffer, nil))

	verifier, err := jwtauth.New(jwtauth.Options{
		JWKSURL: cfg.JWKSURL, Audience: cfg.JWTAudience, ClockSkew: cfg.JWTClockSkew,
		CacheTTL: cfg.JWKSRefreshInterval, KidThrottle: cfg.JWKSUnknownKidInterval,
	})
	if err != nil {
		t.Fatalf("jwtauth.New: %v", err)
	}
	policyClient, err := policy.New(policy.Options{URL: cfg.PolicyURL, Timeout: cfg.PolicyTimeout})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	accountClient, err := account.New(account.Options{
		BaseURL: cfg.AccountServiceURL, Timeout: cfg.AccountServiceTimeout, AllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("account.New: %v", err)
	}

	registry := metrics.New()
	recorder := audit.New(logger, cfg.ServiceName)
	ledger := store.NewMemory()

	transferService := payments.New(payments.Options{
		Config: cfg, Store: ledger, Policy: policyClient, Accounts: accountClient,
		Audit: recorder, Metrics: registry, Logger: logger,
	})
	handler := New(Deps{
		Config: cfg, Logger: logger, Verifier: verifier, Payments: transferService,
		Store: ledger, Audit: recorder, Metrics: registry, Tracer: tracing.New(tracing.Options{}),
	})

	// --- listener ---------------------------------------------------------
	serverConfig, err := mtls.ServerSettings{
		CertFile:          certsDir + "/" + certgen.ServerFile,
		KeyFile:           certsDir + "/" + certgen.ServerKeyFile,
		CAFile:            caFile,
		RequireClientCert: true,
	}.ServerConfig()
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rejections := make(chan mtls.Rejection, 16)
	listener := mtls.NewListener(raw, serverConfig, 2*time.Second, func(rejection mtls.Rejection) {
		RecordHandshakeRejection(recorder, registry, rejection)
		rejections <- rejection
	})

	server := &http.Server{Handler: handler}
	server.ErrorLog = log.New(io.Discard, "", 0)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return &stack{
		url:        "https://" + raw.Addr().String(),
		caFile:     caFile,
		certsDir:   certsDir,
		engine:     engine,
		accounts:   accounts,
		ledger:     ledger,
		audit:      buffer,
		registry:   registry,
		rejections: rejections,
		token:      token,
	}
}

func mustAmount(t *testing.T, value string) money.Amount {
	t.Helper()
	parsed, err := money.Parse(value)
	if err != nil {
		t.Fatalf("Parse(%q): %v", value, err)
	}
	return parsed
}

// client builds an HTTPS client that presents the named certificate.
func (s *stack) client(t *testing.T, certName string) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(readFile(t, s.caFile))

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if certName != "" {
		// The caller names a file (certgen.ProbeFile); the pair lives beside it.
		prefix := strings.TrimSuffix(certName, ".crt")
		certificate, err := tls.LoadX509KeyPair(
			s.certsDir+"/"+prefix+".crt", s.certsDir+"/"+prefix+".key")
		if err != nil {
			t.Fatalf("load %s: %v", certName, err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
}

func (s *stack) do(t *testing.T, client *http.Client, method, path, token, body string) (int, map[string]any, http.Header) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, s.url+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("traceparent", traceParent)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)

	var decoded map[string]any
	if len(bytes.TrimSpace(payload)) > 0 {
		_ = json.Unmarshal(payload, &decoded)
	}
	return response.StatusCode, decoded, response.Header
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestEveryRouteRequiresAClientCertificate(t *testing.T) {
	s := newStack(t, nil)

	// No client certificate at all: the handshake itself must fail, so no
	// handler, no route and no policy call happens. The request is issued by
	// hand because a transport error is the expected outcome.
	response, err := s.client(t, "").Get(s.url + healthzPath)
	if err == nil {
		response.Body.Close()
		t.Fatal("a client without a certificate must not be served")
	}

	select {
	case rejection := <-s.rejections:
		if rejection.Reason != mtls.ReasonNoCertificate {
			t.Errorf("reason = %q, want %q", rejection.Reason, mtls.ReasonNoCertificate)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the refusal must be reported")
	}

	// The refusal is in the audit trail: without the listener hook it would be
	// invisible, because nothing in the application ever ran.
	record := findRecord(t, s.audit.records(t), audit.EventMTLSRejected)
	if record["decision"] != audit.VerdictDeny {
		t.Errorf("decision = %v, want DENY", record["decision"])
	}
	if record["service"] != "payment-service" {
		t.Errorf("service = %v", record["service"])
	}
}

func TestProbeCertificateCannotCallTheBusinessAPI(t *testing.T) {
	s := newStack(t, nil)
	token := s.token([]string{"customer"}, senderID, false)

	// The probe certificate is a valid, CA-signed credential — and it is not in
	// the caller allowlist, because diagnosing a service is not the same as
	// being allowed to move money through it.
	status, body, _ := s.do(t, s.client(t, certgen.ProbeFile), http.MethodGet, healthzPath, "", "")
	if status != http.StatusOK {
		t.Fatalf("the probe certificate must be able to read the probe: %d %v", status, body)
	}

	status, body, _ = s.do(t, s.client(t, certgen.ProbeFile), http.MethodPost, TransferPath, token,
		`{"sender_id":"`+senderID+`","receiver_id":"`+receiverID+`","amount":50.00}`)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 %v", status, body)
	}
	if code := errorCode(t, body); code != "client_not_authorized" {
		t.Errorf("code = %q, want client_not_authorized", code)
	}
	if s.engine.calls() != 0 || s.accounts.callCount() != 0 {
		t.Fatal("a client outside the allowlist must not reach the policy engine or the ledger")
	}

	record := findRecord(t, s.audit.records(t), audit.EventRequestBlocked)
	if record["reason"] != audit.ReasonMTLSIdentity {
		t.Errorf("reason = %v, want %v", record["reason"], audit.ReasonMTLSIdentity)
	}
	if detail, ok := record["detail"].(map[string]any); !ok || detail["mtls_identity"] != "probe" {
		t.Errorf("the refusal must name the certificate it refused, got %v", record["detail"])
	}
}

func TestTransferRequiresAValidBearerToken(t *testing.T) {
	s := newStack(t, nil)
	body := `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `","amount":50.00}`

	cases := map[string]struct {
		token  string
		status int
		code   string
		reason string
	}{
		"missing": {token: "", status: http.StatusUnauthorized, code: "token_missing", reason: audit.ReasonTokenMissing},
		"garbage": {token: "not-a-token", status: http.StatusUnauthorized, code: "token_invalid", reason: audit.ReasonTokenInvalid},
		"expired": {
			token:  s.token([]string{"customer"}, senderID, true),
			status: http.StatusUnauthorized, code: "token_expired", reason: audit.ReasonTokenExpired,
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			status, payload, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodPost, TransferPath, testCase.token, body)
			if status != testCase.status {
				t.Fatalf("status = %d, want %d (%v)", status, testCase.status, payload)
			}
			if code := errorCode(t, payload); code != testCase.code {
				t.Errorf("code = %q, want %q", code, testCase.code)
			}
			if s.accounts.callCount() != 0 || s.engine.calls() != 0 {
				t.Fatal("an unauthenticated request must not reach any dependency")
			}
		})
	}

	// Every refusal is in the trail with a reason the dashboard can group on.
	reasons := map[string]bool{}
	for _, record := range s.audit.records(t) {
		if record["msg"] == audit.EventRequestBlocked {
			reasons[fmt.Sprint(record["reason"])] = true
		}
	}
	for _, expected := range []string{audit.ReasonTokenMissing, audit.ReasonTokenInvalid, audit.ReasonTokenExpired} {
		if !reasons[expected] {
			t.Errorf("no audit record with reason %q (got %v)", expected, reasons)
		}
	}
}

func TestTransferValidatesTheBodyBeforeAnythingElse(t *testing.T) {
	s := newStack(t, nil)
	token := s.token([]string{"customer"}, senderID, false)
	client := s.client(t, certgen.GatewayFile)

	cases := map[string]struct {
		body   string
		status int
		code   string
	}{
		"not json":           {body: `{`, status: http.StatusBadRequest, code: "invalid_request_body"},
		"empty":              {body: "", status: http.StatusBadRequest, code: "invalid_request_body"},
		"unknown field":      {body: `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `","amount":50,"memo":"x"}`, status: http.StatusBadRequest, code: "invalid_request_body"},
		"amount as a string": {body: `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `","amount":"50.00"}`, status: http.StatusBadRequest, code: "invalid_amount"},
		"sub-cent amount":    {body: `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `","amount":50.001}`, status: http.StatusBadRequest, code: "invalid_amount"},
		"negative amount":    {body: `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `","amount":-50}`, status: http.StatusBadRequest, code: "invalid_amount"},
		"missing amount":     {body: `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `"}`, status: http.StatusBadRequest, code: "invalid_amount"},
		"sender not a uuid":  {body: `{"sender_id":"nope","receiver_id":"` + receiverID + `","amount":50}`, status: http.StatusBadRequest, code: "invalid_sender_id"},
		"self transfer":      {body: `{"sender_id":"` + senderID + `","receiver_id":"` + senderID + `","amount":50}`, status: http.StatusBadRequest, code: "self_transfer_refused"},
		"trailing json":      {body: `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `","amount":50}{}`, status: http.StatusBadRequest, code: "invalid_request_body"},
		"oversized body": {
			body:   `{"sender_id":"` + senderID + `","receiver_id":"` + receiverID + `","amount":50,"pad":"` + strings.Repeat("x", 5000) + `"}`,
			status: http.StatusRequestEntityTooLarge, code: "request_too_large",
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			status, payload, _ := s.do(t, client, http.MethodPost, TransferPath, token, testCase.body)
			if status != testCase.status {
				t.Fatalf("status = %d, want %d (%v)", status, testCase.status, payload)
			}
			if code := errorCode(t, payload); code != testCase.code {
				t.Errorf("code = %q, want %q", code, testCase.code)
			}
		})
	}

	if s.engine.calls() != 0 || s.accounts.callCount() != 0 {
		t.Fatal("malformed bodies must not reach the policy engine or the account service")
	}
}

func TestTransferEndToEnd(t *testing.T) {
	s := newStack(t, nil)
	token := s.token([]string{"customer"}, senderID, false)

	status, payload, headers := s.do(t, s.client(t, certgen.GatewayFile), http.MethodPost, TransferPath, token,
		`{"sender_id":"`+senderID+`","receiver_id":"`+receiverID+`","amount":50.00}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, payload)
	}

	// The response carries the ledger row's identity and the trace context.
	for _, field := range []string{"txn_id", "sender_id", "receiver_id", "amount", "created_at"} {
		if payload[field] == nil {
			t.Errorf("the response is missing %q: %v", field, payload)
		}
	}
	if payload["amount"] != float64(50) {
		t.Errorf("amount = %v, want 50", payload["amount"])
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(payload["created_at"])); err != nil {
		t.Errorf("created_at %v is not RFC3339: %v", payload["created_at"], err)
	}
	if got := headers.Get("traceparent"); !strings.HasPrefix(got, "00-4bf92f3577b34da6a3ce929d0e0e4736-") {
		t.Errorf("the response traceparent %q must continue the caller's trace", got)
	}
	if headers.Get("X-Request-ID") == "" {
		t.Error("the response must carry a request id")
	}

	// The ledger holds exactly one row, and Person 4 was asked exactly once.
	if entries := s.ledger.Entries(); len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	} else if entries[0].Amount.String() != "50.00" {
		t.Errorf("ledger amount = %q", entries[0].Amount.String())
	}
	if s.accounts.callCount() != 1 {
		t.Errorf("the account service was called %d times, want 1", s.accounts.callCount())
	}

	// The policy engine received the exact contract input, including the mTLS
	// state of this very connection.
	input := s.engine.input(t)
	if input.Subject.UserID != senderID || len(input.Subject.Roles) != 1 || input.Subject.Roles[0] != "customer" {
		t.Errorf("subject = %+v", input.Subject)
	}
	if input.Action != "TRANSFER" || input.Resource != "account_"+senderID {
		t.Errorf("action/resource = %q/%q", input.Action, input.Resource)
	}
	if !input.Context.MTLSVerified {
		t.Error("the engine must be told the connection was mutually authenticated")
	}
	// The engine is handed *this service's* span, not the caller's: the trace id
	// (the join key) is preserved and the span id advances, which is what makes
	// the flow a tree rather than a flat list.
	trace, ok := tracecontext.Parse(input.Context.TraceParent)
	if !ok {
		t.Fatalf("the engine received a malformed traceparent %q", input.Context.TraceParent)
	}
	incoming, _ := tracecontext.Parse(traceParent)
	if trace.TraceID != incoming.TraceID {
		t.Errorf("trace id = %q, want the caller's %q", trace.TraceID, incoming.TraceID)
	}
	if trace.SpanID == incoming.SpanID {
		t.Error("the outgoing span id must be this service's, not the caller's")
	}
	if header := headers.Get("traceparent"); header != trace.Header() {
		t.Errorf("the response traceparent %q must be the same span this service used", header)
	}

	// The audit trail carries both halves: the authorization decision with the
	// engine's own answer, and the committed transfer.
	records := s.audit.records(t)
	decision := findRecord(t, records, audit.EventAccessDecision)
	if decision["decision"] != audit.VerdictPermit || decision["reason"] != audit.ReasonAllowed {
		t.Errorf("decision record = %v/%v", decision["decision"], decision["reason"])
	}
	if decision["action"] != "TRANSFER" {
		t.Errorf("the decision must name the action, got %v", decision["action"])
	}
	committed := findRecord(t, records, audit.EventTransferCommitted)
	if committed["decision"] != audit.VerdictPermit {
		t.Errorf("committed record = %v", committed["decision"])
	}
	detail, ok := committed["detail"].(map[string]any)
	if !ok {
		t.Fatalf("the committed record must carry the ledger row as evidence, got %v", committed["detail"])
	}
	if detail["txn_id"] != payload["txn_id"] {
		t.Errorf("the audit record's txn_id %v must match the response %v", detail["txn_id"], payload["txn_id"])
	}
	if detail["amount"] != "50.00" {
		t.Errorf("the committed record must state the exact amount, got %v", detail["amount"])
	}

	// And the access line for the request itself.
	access := findRecord(t, records, audit.EventHTTPRequest)
	if access["status"] != float64(http.StatusOK) {
		t.Errorf("access status = %v", access["status"])
	}
	if detail, ok := access["detail"].(map[string]any); !ok || detail["mtls_verified"] != true {
		t.Errorf("the access line must record the verified connection, got %v", access["detail"])
	}
}

func TestTransferIsRefusedWhenThePolicyDenies(t *testing.T) {
	s := newStack(t, nil)
	token := s.token([]string{"customer"}, senderID, false)

	// 60 000 is above the Rego baseline's threshold, so the engine refuses.
	status, payload, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodPost, TransferPath, token,
		`{"sender_id":"`+senderID+`","receiver_id":"`+receiverID+`","amount":60000.00}`)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%v)", status, payload)
	}
	if code := errorCode(t, payload); code != "policy_denied" {
		t.Errorf("code = %q, want policy_denied", code)
	}
	if s.accounts.callCount() != 0 {
		t.Fatal("no money may move when the authorization is denied")
	}
	if entries := s.ledger.Entries(); len(entries) != 0 {
		t.Fatal("a denied transfer must not reach the ledger")
	}

	decision := findRecord(t, s.audit.records(t), audit.EventAccessDecision)
	if decision["decision"] != audit.VerdictDeny {
		t.Errorf("decision = %v, want DENY", decision["decision"])
	}
}

func TestTransferIsRefusedWhenTheSenderDoesNotOwnTheAccount(t *testing.T) {
	s := newStack(t, nil)
	// A customer token for a different user.
	token := s.token([]string{"customer"}, "99999999-8888-4777-8666-555555555555", false)

	status, payload, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodPost, TransferPath, token,
		`{"sender_id":"`+senderID+`","receiver_id":"`+receiverID+`","amount":50.00}`)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%v)", status, payload)
	}
	if code := errorCode(t, payload); code != "sender_mismatch" {
		t.Errorf("code = %q, want sender_mismatch", code)
	}
	if s.engine.calls() != 0 {
		t.Error("a mismatched sender must not even reach the policy engine")
	}
}

func TestTransferIsRefusedWhenTheAccountServiceRefuses(t *testing.T) {
	s := newStack(t, nil)
	s.accounts.setStatus(http.StatusForbidden)
	token := s.token([]string{"customer"}, senderID, false)

	status, payload, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodPost, TransferPath, token,
		`{"sender_id":"`+senderID+`","receiver_id":"`+receiverID+`","amount":50.00}`)
	// docs/contacts.md §Person 5: an error from Person 4 means 400 Bad Request.
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%v)", status, payload)
	}
	if code := errorCode(t, payload); code != "deduction_failed" {
		t.Errorf("code = %q, want deduction_failed", code)
	}
	if entries := s.ledger.Entries(); len(entries) != 0 {
		t.Fatal("a refused deduction must not produce a ledger row")
	}
}

func TestTransferIsRefusedWhenThePolicyEngineIsDown(t *testing.T) {
	s := newStack(t, nil)
	token := s.token([]string{"customer"}, senderID, false)
	s.engine.server.Close() // the guard is gone

	status, payload, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodPost, TransferPath, token,
		`{"sender_id":"`+senderID+`","receiver_id":"`+receiverID+`","amount":50.00}`)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want a refusal (%v)", status, payload)
	}
	if code := errorCode(t, payload); code != "policy_unavailable" {
		t.Errorf("code = %q, want policy_unavailable so the outage is distinguishable", code)
	}
	if s.accounts.callCount() != 0 {
		t.Fatal("a transfer must not be attempted when the guard is down")
	}

	record := findRecord(t, s.audit.records(t), audit.EventVerificationUnavailable)
	if record["decision"] != audit.VerdictError {
		t.Errorf("an unavailable guard must be audited as an ERROR, got %v", record["decision"])
	}
}

func TestAnAdminTokenMayTransferFromAnyAccount(t *testing.T) {
	s := newStack(t, nil)
	token := s.token([]string{"admin"}, "99999999-8888-4777-8666-555555555555", false)

	status, payload, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodPost, TransferPath, token,
		`{"sender_id":"`+senderID+`","receiver_id":"`+receiverID+`","amount":50.00}`)
	if status != http.StatusOK {
		t.Fatalf("an admin must be able to act on behalf of a customer: %d %v", status, payload)
	}
}

func TestProbesAndMetrics(t *testing.T) {
	s := newStack(t, nil)
	client := s.client(t, certgen.ProbeFile)

	status, payload, _ := s.do(t, client, http.MethodGet, healthzPath, "", "")
	if status != http.StatusOK || payload["status"] != "ok" {
		t.Fatalf("healthz = %d %v", status, payload)
	}

	status, payload, _ = s.do(t, client, http.MethodGet, readyzPath, "", "")
	if status != http.StatusOK {
		t.Fatalf("readyz = %d %v", status, payload)
	}
	detail, ok := payload["detail"].(map[string]any)
	if !ok || detail["ledger"] != "ok" {
		t.Errorf("readyz detail = %v, want the ledger's state", payload["detail"])
	}

	response, err := client.Get(s.url + metricsPath)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), metrics.RequestsTotal) {
		t.Errorf("the metrics endpoint must expose the request counter, got:\n%s", body)
	}
	if !strings.Contains(string(body), `route="healthz"`) {
		t.Errorf("the request counter must be labelled by route, got:\n%s", body)
	}
}

// Readiness has to reflect whether the service can actually serve a transfer.
// With no key material and an unreachable IdP it cannot, and reporting that as
// healthy would take the service out of an operator's view exactly when they
// need it.
func TestReadyzReportsAnUnkeyedGuard(t *testing.T) {
	s := newStack(t, func(cfg *config.Config) {
		cfg.JWKSURL = "http://127.0.0.1:1/.well-known/jwks.json"
	})

	status, payload, _ := s.do(t, s.client(t, certgen.ProbeFile), http.MethodGet, readyzPath, "", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503 (%v)", status, payload)
	}
	detail, ok := payload["detail"].(map[string]any)
	if !ok || detail["jwks"] != "unreachable" {
		t.Errorf("the detail must name the dependency that is down, got %v", payload["detail"])
	}
	if detail["ledger"] != "ok" {
		t.Errorf("the ledger is reachable and must be reported as such, got %v", detail["ledger"])
	}
}

func TestWrongMethodIsNotRoutedToTheTransferHandler(t *testing.T) {
	s := newStack(t, nil)
	token := s.token([]string{"customer"}, senderID, false)

	status, _, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodGet, TransferPath, token, "")
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", status)
	}
}

func TestUnknownRouteIsNotFound(t *testing.T) {
	s := newStack(t, nil)
	status, _, _ := s.do(t, s.client(t, certgen.GatewayFile), http.MethodGet, "/api/v1/payments/other", "", "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func errorCode(t *testing.T, payload map[string]any) string {
	t.Helper()
	envelope, ok := payload["error"].(map[string]any)
	if !ok {
		return ""
	}
	code, _ := envelope["code"].(string)
	return code
}
