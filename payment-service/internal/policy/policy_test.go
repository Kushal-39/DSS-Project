package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"paymentservice/internal/money"
)

func engine(t *testing.T, status int, body string, capture *[]byte) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read the request body: %v", err)
			}
			*capture = body
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{URL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func sampleRequest(t *testing.T) Request {
	t.Helper()
	amount, err := money.Parse("50.00")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return Request{Input: Input{
		Subject:  Subject{UserID: "6f9619ff-8b86-d011-b42d-00c04fc964ff", Roles: []string{"customer"}},
		Action:   ActionTransfer,
		Resource: "account_6f9619ff-8b86-d011-b42d-00c04fc964ff",
		Context: Context{
			Amount:       amount,
			IPAddress:    "192.168.1.50",
			MTLSVerified: true,
			ReceiverID:   "8f9619ff-8b86-d011-b42d-00c04fc964fa",
			DeviceID:     "laptop",
			TraceParent:  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		},
	}}
}

// The contract is the point of this test. docs/policymaker.md shows the payload
// nested under `input` with the subject as an object; docs/division.md shows a
// flat shape that the engine denies by default. This asserts that the shape sent
// is the nested one, field for field, because a silently flat payload looks
// exactly like a legitimate refusal.
func TestAuthorizeSendsTheNestedContractPayload(t *testing.T) {
	var captured []byte
	client := engine(t, http.StatusOK, `{"result":{"allow":true}}`, &captured)

	decision, err := client.Authorize(context.Background(), sampleRequest(t))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !decision.Allow {
		t.Fatal("the engine allowed the request; the client must report it as allowed")
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(captured, &decoded); err != nil {
		t.Fatalf("the sent payload is not valid JSON: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("the payload must have exactly one top-level key (input), got %v", keys(decoded))
	}
	if _, ok := decoded["input"]; !ok {
		t.Fatalf("the payload is not wrapped in `input`: %s", captured)
	}
	if _, flat := decoded["roles"]; flat {
		t.Fatalf("the flat division.md shape was sent: %s", captured)
	}

	var input struct {
		Subject  map[string]json.RawMessage `json:"subject"`
		Action   string                     `json:"action"`
		Resource string                     `json:"resource"`
		Context  map[string]json.RawMessage `json:"context"`
	}
	if err := json.Unmarshal(decoded["input"], &input); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	if input.Action != "TRANSFER" {
		t.Errorf("action = %q, want TRANSFER", input.Action)
	}
	if input.Resource != "account_6f9619ff-8b86-d011-b42d-00c04fc964ff" {
		t.Errorf("resource = %q", input.Resource)
	}
	if _, ok := input.Subject["user_id"]; !ok {
		t.Error("subject.user_id is missing")
	}
	if _, ok := input.Subject["roles"]; !ok {
		t.Error("subject.roles is missing")
	}
	// The Rego rule compares the amount numerically, so it must be a number.
	if raw := string(input.Context["amount"]); raw != "50.00" {
		t.Errorf("context.amount = %s, want the JSON number 50.00", raw)
	}
	if raw := string(input.Context["mTLS_verified"]); raw != "true" {
		t.Errorf("context.mTLS_verified = %s, want true", raw)
	}
	if _, ok := input.Context["ip_address"]; !ok {
		t.Error("context.ip_address is missing")
	}
	if _, ok := input.Context["traceparent"]; !ok {
		t.Error("context.traceparent is missing (the engine's own decision log needs it to join a flow)")
	}
}

func TestAuthorizeOnlyAllowsAnExplicitTrue(t *testing.T) {
	cases := map[string]struct {
		body        string
		allow       bool
		expectError error
	}{
		"allowed":            {body: `{"result":{"allow":true}}`, allow: true},
		"denied":             {body: `{"result":{"allow":false}}`, allow: false},
		"denied with reason": {body: `{"result":{"allow":false,"reason":"threat_level_high"}}`, allow: false},
		"missing allow":      {body: `{"result":{}}`, expectError: ErrMalformedResponse},
		"flat allow":         {body: `{"allow":true}`, expectError: ErrMalformedResponse},
		"not JSON":           {body: `{"result":`, expectError: ErrMalformedResponse},
		"empty object":       {body: `{}`, expectError: ErrMalformedResponse},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			client := engine(t, http.StatusOK, testCase.body, nil)
			decision, err := client.Authorize(context.Background(), sampleRequest(t))
			if !errors.Is(err, testCase.expectError) {
				t.Fatalf("error = %v, want %v", err, testCase.expectError)
			}
			if testCase.expectError == nil && decision.Allow != testCase.allow {
				t.Fatalf("allow = %v, want %v", decision.Allow, testCase.allow)
			}
			if testCase.expectError != nil && decision.Allow {
				t.Fatal("a malformed document must never be read as an allow")
			}
		})
	}
}

func TestAuthorizeReportsTheEnginesOwnReason(t *testing.T) {
	client := engine(t, http.StatusOK, `{"result":{"allow":false,"deny_reason":"amount_above_threshold"}}`, nil)
	decision, err := client.Authorize(context.Background(), sampleRequest(t))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Reason != "amount_above_threshold" {
		t.Errorf("reason = %q", decision.Reason)
	}
	if len(decision.Raw) == 0 {
		t.Error("the raw decision must be kept for the audit record")
	}
}

// A guard that cannot get an answer must not answer "yes".
func TestAuthorizeFailsClosedWhenTheEngineIsUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()

	client, err := New(Options{URL: server.URL, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Authorize(context.Background(), sampleRequest(t)); !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("error = %v, want ErrEngineUnavailable", err)
	}
}

func TestAuthorizeTreatsANonOKResponseAsUnavailable(t *testing.T) {
	client := engine(t, http.StatusInternalServerError, `{"error":"boom"}`, nil)
	if _, err := client.Authorize(context.Background(), sampleRequest(t)); !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("error = %v, want ErrEngineUnavailable", err)
	}
}

func TestAuthorizeFailsClosedWhenTheEngineDoesNotAnswerInTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	t.Cleanup(server.Close)

	// The check is synchronous and in the request path: a slow engine is an
	// unavailable engine, not a reason to hold a transfer open.
	client, err := New(Options{URL: server.URL, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Authorize(context.Background(), sampleRequest(t)); !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("error = %v, want ErrEngineUnavailable", err)
	}
}

func TestAuthorizeDoesNotFollowARedirect(t *testing.T) {
	var redirected int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	t.Cleanup(target.Close)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{URL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Authorize(context.Background(), sampleRequest(t)); err == nil {
		t.Fatal("a redirect must not be followed")
	}
	if redirected != 0 {
		t.Fatal("the redirect target must never be contacted")
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
