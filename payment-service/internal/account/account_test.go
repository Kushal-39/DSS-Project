package account

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

type capturedRequest struct {
	Path          string
	Authorization string
	TraceParent   string
	RequestID     string
	Body          Request
	RawBody       string
}

func upstream(t *testing.T, status int, body string, capture *capturedRequest) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if capture != nil {
			captured := capturedRequest{
				Path:          r.URL.Path,
				Authorization: r.Header.Get("Authorization"),
				TraceParent:   r.Header.Get("traceparent"),
				RequestID:     r.Header.Get("X-Request-ID"),
				RawBody:       string(raw),
			}
			_ = json.Unmarshal(raw, &captured.Body)
			*capture = captured
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{BaseURL: server.URL, Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func amount(t *testing.T, value string) money.Amount {
	t.Helper()
	parsed, err := money.Parse(value)
	if err != nil {
		t.Fatalf("Parse(%q): %v", value, err)
	}
	return parsed
}

func TestDeductSendsTheAccountServiceContract(t *testing.T) {
	var captured capturedRequest
	client := upstream(t, http.StatusOK, `{"status":"ok"}`, &captured)

	result, err := client.Deduct(context.Background(), Request{
		UserID: "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		Amount: amount(t, "50.00"),
	}, Credentials{
		Bearer:      "Bearer the.jwt.token",
		TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		RequestID:   "abc123",
	})
	if err != nil {
		t.Fatalf("Deduct: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("a 200 must be a success, got %d", result.StatusCode)
	}

	// docs/contacts.md: POST /api/v1/accounts/deduct with {"user_id","amount"}.
	if captured.Path != DeductPath {
		t.Errorf("path = %q, want %q", captured.Path, DeductPath)
	}
	if captured.Body.UserID != "6f9619ff-8b86-d011-b42d-00c04fc964ff" {
		t.Errorf("user_id = %q", captured.Body.UserID)
	}
	if captured.Body.Amount.String() != "50.00" {
		t.Errorf("amount = %q, want 50.00", captured.Body.Amount.String())
	}
	if captured.RawBody != `{"user_id":"6f9619ff-8b86-d011-b42d-00c04fc964ff","amount":50.00}` {
		t.Errorf("body = %s", captured.RawBody)
	}
	// The caller's identity and trace context travel with the call: Person 4
	// re-authorizes the same principal (docs/flow.md §5) and the flow stays
	// joinable across the hop.
	if captured.Authorization != "Bearer the.jwt.token" {
		t.Errorf("Authorization = %q", captured.Authorization)
	}
	if captured.TraceParent == "" {
		t.Error("traceparent must be forwarded")
	}
	if captured.RequestID != "abc123" {
		t.Errorf("X-Request-ID = %q", captured.RequestID)
	}
}

func TestDeductTreatsARefusalAsAnAnswer(t *testing.T) {
	client := upstream(t, http.StatusForbidden, `{"error":{"code":"insufficient_funds"}}`, nil)

	result, err := client.Deduct(context.Background(), Request{
		UserID: "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		Amount: amount(t, "50.00"),
	}, Credentials{})
	if err != nil {
		t.Fatalf("a 403 is an answer, not a transport failure: %v", err)
	}
	if result.Succeeded() {
		t.Fatal("a 403 must not be a success")
	}
	if result.RateLimited() {
		t.Fatal("a 403 is not rate limiting")
	}
	if result.Snippet() == "" {
		t.Error("the upstream body is the evidence for the refusal and must be kept")
	}
}

// A 5xx means the deduction's outcome is unknown, which is a different incident
// from a refusal — and the difference decides whether a retry is safe.
func TestDeductTreatsAServerErrorAsUnavailable(t *testing.T) {
	client := upstream(t, http.StatusInternalServerError, `{"error":"boom"}`, nil)

	result, err := client.Deduct(context.Background(), Request{
		UserID: "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		Amount: amount(t, "50.00"),
	}, Credentials{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if result.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", result.StatusCode)
	}
}

func TestDeductReportsAnUnreachableUpstream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()

	client, err := New(Options{BaseURL: server.URL, Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Deduct(context.Background(), Request{
		UserID: "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		Amount: amount(t, "50.00"),
	}, Credentials{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

// The request carries the caller's bearer token, so a redirect would hand that
// credential to whatever host the upstream names.
func TestDeductDoesNotFollowARedirect(t *testing.T) {
	var redirectTarget int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectTarget++ }))
	t.Cleanup(target.Close)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{BaseURL: server.URL, Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := client.Deduct(context.Background(), Request{
		UserID: "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		Amount: amount(t, "50.00"),
	}, Credentials{Bearer: "Bearer secret"})
	if err != nil {
		t.Fatalf("Deduct: %v", err)
	}
	if result.Succeeded() {
		t.Fatal("a redirect must not be read as a completed deduction")
	}
	if redirectTarget != 0 {
		t.Fatal("the redirect target must never receive the bearer token")
	}
}

func TestNewRefusesToMoveMoneyOverCleartextByDefault(t *testing.T) {
	if _, err := New(Options{BaseURL: "http://account-service:8082"}); err == nil {
		t.Fatal("an http:// upstream must be refused unless it is explicitly allowed")
	}
	if _, err := New(Options{BaseURL: "http://account-service:8082", AllowInsecure: true}); err != nil {
		t.Fatalf("the explicit override must be honoured: %v", err)
	}
	if _, err := New(Options{BaseURL: ""}); err == nil {
		t.Fatal("a base URL is required")
	}
}

func TestDeductValidatesItsOwnRequest(t *testing.T) {
	client := upstream(t, http.StatusOK, `{}`, nil)

	if _, err := client.Deduct(context.Background(), Request{
		Amount: amount(t, "50.00"),
	}, Credentials{}); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("an empty user_id must be refused locally: %v", err)
	}
	if _, err := client.Deduct(context.Background(), Request{
		UserID: "6f9619ff-8b86-d011-b42d-00c04fc964ff",
	}, Credentials{}); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("a zero amount must be refused locally: %v", err)
	}
}
