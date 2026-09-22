// Package account is the client for Person 4's Account Service (Microservice
// A) — the only component that owns the balances.
//
// docs/contacts.md is explicit about why this client exists at all:
//
//	"DO NOT try to deduct money yourself. You do not have access to the
//	 accounts table. You MUST send a synchronous HTTP request to Person 4's
//	 /api/v1/accounts/deduct endpoint."
//
// So this package is a thin, deliberately narrow pipe:
//
//   - One endpoint, one request shape: `{"user_id","amount"}`. No query, no
//     balance read, no SQL. The `transactions` table is this service's; the
//     `accounts` table is not (docs/database.md §2).
//   - **No retries.** A deduction is not idempotent and Person 4's contract
//     exposes no idempotency key, so a retry after a timeout could debit the
//     account twice. A timeout is reported as an unavailable upstream and the
//     caller refuses the transfer; a human or a future reconciliation job
//     resolves the ambiguity. "Lost money" and "double-charged customer" are
//     both bad, and only one of them is recoverable by the ledger.
//   - **No redirects.** The request carries the caller's bearer token; following
//     a redirect would hand that credential to whatever host the upstream names.
//   - The caller's JWT and the W3C traceparent are forwarded, so Person 4
//     re-authorizes the *original* principal (docs/flow.md §5) and the flow
//     stays joinable across the hop.
package account

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"paymentservice/internal/money"
)

// Sentinel errors.
var (
	// ErrUnavailable means no answer arrived: connection failure, TLS
	// rejection, timeout, or a 5xx. The deduction's outcome is *unknown*, which
	// is why the caller must not retry it.
	ErrUnavailable = errors.New("account service unavailable")
	// ErrMalformedRequest means this service built a request Person 4 cannot
	// accept. It is a bug here, not an upstream failure.
	ErrMalformedRequest = errors.New("account service request could not be built")
)

// DeductPath is Person 4's contract endpoint (docs/contacts.md).
const DeductPath = "/api/v1/accounts/deduct"

// Request is the documented body of a deduction.
type Request struct {
	UserID string       `json:"user_id"`
	Amount money.Amount `json:"amount"`
}

// Credentials are the caller's identity, forwarded unchanged.
type Credentials struct {
	// Bearer is the Authorization header value ("Bearer <jwt>"). Person 4
	// verifies the same token independently — this service is not a trust
	// boundary for the caller's identity, it only passes it on.
	Bearer string
	// TraceParent keeps the distributed flow joinable across the hop
	// (docs/flow.md §3).
	TraceParent string
	// RequestID is this service's own correlation id, so an upstream log line
	// can be matched to the transfer that caused it.
	RequestID string
}

// Result is the upstream outcome.
type Result struct {
	// StatusCode is the HTTP status the Account Service answered with.
	StatusCode int
	// Body is the response body, bounded and used for the audit record.
	Body []byte
	// Duration is how long the call took.
	Duration time.Duration
}

// Succeeded reports whether the deduction was applied. Any 2xx counts:
// a 2xx from the deduct endpoint means the account was debited, and refusing to
// record a ledger row after a successful debit would orphan the money.
func (r Result) Succeeded() bool { return r.StatusCode >= 200 && r.StatusCode < 300 }

// RateLimited reports upstream throttling, which the audit trail counts
// separately from a refusal (telemetry/docs/integration.md §2).
func (r Result) RateLimited() bool { return r.StatusCode == http.StatusTooManyRequests }

// Client calls the Account Service.
type Client struct {
	url     string
	http    *http.Client
	timeout time.Duration
}

// Options configure a Client.
type Options struct {
	// BaseURL is the Account Service root, e.g. https://account-service:8082.
	BaseURL string
	// Timeout bounds the whole exchange. It is longer than the policy check
	// because a deduction touches a database, and shorter than any human
	// patience for a synchronous transfer.
	Timeout time.Duration
	// TLS is this service's client identity: its certificate (when the
	// Transport Contract is in force) and the CA that signed the Account
	// Service's certificate.
	TLS *tls.Config
	// AllowInsecure permits a plain http:// base URL. Startup warns when it is
	// set; it exists only so the service can be demoed against an Account
	// Service that has not adopted mTLS yet.
	AllowInsecure bool
}

// New builds a Client.
func New(options Options) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(options.BaseURL), "/")
	if base == "" {
		return nil, errors.New("account: a base URL is required")
	}
	if strings.HasPrefix(base, "http://") && !options.AllowInsecure {
		return nil, fmt.Errorf(
			"account: refusing to call %s over plain http — internal traffic must satisfy the Transport "+
				"Contract (docs/division.md §2)", base)
	}
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}

	transport := &http.Transport{
		MaxIdleConns:        8,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig:     options.TLS,
	}

	return &Client{
		url:     base + DeductPath,
		timeout: options.Timeout,
		http: &http.Client{
			Transport: transport,
			Timeout:   options.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Never follow: the redirect target would receive the caller's
				// bearer token.
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Deduct performs the synchronous deduction.
//
// The returned error is ErrUnavailable when no answer was received, and nil
// whenever the upstream answered — a refusal is an answer, and the caller
// distinguishes it by Result.StatusCode.
func (c *Client) Deduct(ctx context.Context, request Request, credentials Credentials) (Result, error) {
	if strings.TrimSpace(request.UserID) == "" || request.Amount.IsZero() {
		return Result{}, fmt.Errorf("%w: user_id and amount are required", ErrMalformedRequest)
	}

	body, err := json.Marshal(request)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrMalformedRequest, err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrMalformedRequest, err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	if credentials.Bearer != "" {
		httpRequest.Header.Set("Authorization", credentials.Bearer)
	}
	if credentials.TraceParent != "" {
		httpRequest.Header.Set("traceparent", credentials.TraceParent)
	}
	if credentials.RequestID != "" {
		httpRequest.Header.Set("X-Request-ID", credentials.RequestID)
	}

	start := time.Now()
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return Result{Duration: time.Since(start)}, fmt.Errorf(
			"%w: %v", ErrUnavailable, classifyTransportError(err))
	}
	defer response.Body.Close()
	duration := time.Since(start)

	// Bounded: the audit record only needs enough of the body to name the
	// failure, and an upstream must not be able to make this service allocate
	// without limit.
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	if err != nil {
		return Result{StatusCode: response.StatusCode, Duration: duration}, fmt.Errorf(
			"%w: reading the response: %v", ErrUnavailable, err)
	}

	// A 5xx is not a refusal: it is the Account Service failing to answer, and
	// the deduction may or may not have been applied. It is reported as an
	// unavailable upstream so the audit trail does not call it a denial.
	if response.StatusCode >= 500 {
		return Result{StatusCode: response.StatusCode, Body: responseBody, Duration: duration}, fmt.Errorf(
			"%w: the account service answered %s", ErrUnavailable, response.Status)
	}

	return Result{StatusCode: response.StatusCode, Body: responseBody, Duration: duration}, nil
}

// Snippet returns a short, single-line excerpt of the upstream body for a log
// line. Operator-facing detail belongs in the audit trail; a multi-kilobyte
// dump does not.
func (r Result) Snippet() string {
	const limit = 256
	text := strings.Join(strings.Fields(string(r.Body)), " ")
	if len(text) > limit {
		return text[:limit] + "…"
	}
	return text
}

func classifyTransportError(err error) error {
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return fmt.Errorf("the account service certificate was rejected (is the shared CA configured?): %w", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("no answer before the deadline: %w", err)
	}
	return err
}
