// Package policy is the client for Person 3's Policy Engine (OPA).
//
// The contract is docs/policymaker.md and it is followed literally, because the
// engine's Rego policy is written against it and a single misplaced field
// silently evaluates to `false` (default deny), which looks exactly like a
// legitimate refusal:
//
//	POST http://policy-engine:8181/v1/data/authz/allow
//	{"input":{"subject":{"user_id":"…","roles":["customer"]},
//	          "action":"TRANSFER","resource":"account_987",
//	          "context":{"amount":50.00,"ip_address":"192.168.1.50","mTLS_verified":true}}}
//	→ {"result":{"allow":true}}
//
// Three rules this client enforces on itself:
//
//  1. The payload is wrapped in `input` and the subject is nested. There is no
//     code path here that can send the flat shape docs/division.md shows,
//     because that shape is denied by the engine's default-deny rule.
//  2. `mTLS_verified` is passed from the connection's actual TLS state, never
//     from a header or a body field a caller controls. A client that could set
//     that flag could satisfy the Rego rule's mTLS requirement itself.
//  3. Anything other than a well-formed `{"result":{"allow":true}}` is a
//     refusal, and a call that produced no interpretable answer is reported as
//     an *unavailable* guard rather than as a policy denial, so the audit trail
//     keeps "the engine said no" and "the engine was not there" apart.
package policy

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
	"time"

	"paymentservice/internal/money"
)

// Sentinel errors. Both mean "do not allow"; they differ in what the audit
// trail says about why.
var (
	// ErrEngineUnavailable is a call that produced no answer: transport
	// failure, timeout, or a non-200 response.
	ErrEngineUnavailable = errors.New("policy engine unavailable")
	// ErrMalformedResponse is an answer that cannot be interpreted as the
	// documented decision document.
	ErrMalformedResponse = errors.New("policy engine returned a malformed decision document")
)

// Action names. The Rego baseline reads `input.action == "TRANSFER"`, so the
// spelling is part of the contract rather than a local choice.
const (
	ActionTransfer = "TRANSFER"
)

// Subject is the authenticated principal the decision is about.
type Subject struct {
	// UserID is the token's `sub` claim.
	UserID string `json:"user_id"`
	// Roles is the token's `roles` claim, as an array: the Rego rules read
	// `"customer" in input.subject.roles`.
	Roles []string `json:"roles"`
}

// Context is the request-level attribute set the rules evaluate.
//
// The four contract fields come first and are always sent. The rest are
// additive: Rego ignores keys it does not name, and they give the engine (and
// its future rules) the facts this service already knows — including the trace
// id, which is the only way the engine's own decision log can later be joined
// to the distributed flow it decided about (telemetry/docs/integration.md §3
// "Person 3").
type Context struct {
	// Amount is marshalled as a JSON number, because the Rego rule compares it
	// numerically.
	Amount money.Amount `json:"amount"`
	// IPAddress is the evaluated client address. It is the caller's network
	// address as this service observed it, not a header a proxy could forge.
	IPAddress string `json:"ip_address"`
	// MTLSVerified is derived from the TLS state of this connection.
	MTLSVerified bool `json:"mTLS_verified"`

	ReceiverID  string `json:"receiver_id,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	TraceParent string `json:"traceparent,omitempty"`
}

// Input is the envelope the engine requires.
type Input struct {
	Subject  Subject `json:"subject"`
	Action   string  `json:"action"`
	Resource string  `json:"resource"`
	Context  Context `json:"context"`
}

// Request is the request body: the input wrapped in `input`.
type Request struct {
	Input Input `json:"input"`
}

// Response is the engine's decision document.
//
// Allow is a pointer so a *missing* `result.allow` can be told apart from an
// explicit `false`: the first is a broken contract and the second is a
// decision. Both refuse the request; only one of them is evidence that the
// engine is working.
type Response struct {
	Result struct {
		Allow *bool `json:"allow"`
		// Reason and DenyReason are not part of the documented contract; they
		// are read when present so a richer policy can explain itself without
		// a caller-side change.
		Reason     string `json:"reason"`
		DenyReason string `json:"deny_reason"`
	} `json:"result"`
}

// Decision is the engine's answer, with the raw document kept for the audit
// record.
type Decision struct {
	// Allow is true only when the engine said exactly `{"allow":true}`.
	Allow bool
	// Reason is the engine's own explanation when it supplied one.
	Reason string
	// Raw is the exact response body, logged alongside the request so the
	// audit trail holds the engine's answer rather than this client's summary
	// of it.
	Raw json.RawMessage
	// Duration is how long the synchronous check took.
	Duration time.Duration
}

// Client calls the engine.
type Client struct {
	url     string
	http    *http.Client
	timeout time.Duration
}

// Options configure a Client.
type Options struct {
	URL string
	// Timeout bounds the whole exchange. The check is synchronous and in the
	// request path, so it is short (2s by default): a policy engine that cannot
	// answer quickly cannot be allowed to hold a payment request open.
	Timeout time.Duration
	// TLS is set when the engine serves https.
	TLS *tls.Config
}

// New builds a Client.
func New(options Options) (*Client, error) {
	if options.URL == "" {
		return nil, errors.New("policy: an engine URL is required")
	}
	if options.Timeout <= 0 {
		options.Timeout = 2 * time.Second
	}

	transport := &http.Transport{
		// Connections to an internal service are pooled; the engine is
		// consulted on every transfer, so a fresh handshake per call would add
		// latency to the money path for no security benefit.
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: options.Timeout,
		TLSClientConfig:       options.TLS,
	}

	return &Client{
		url:     options.URL,
		timeout: options.Timeout,
		http: &http.Client{
			Transport: transport,
			Timeout:   options.Timeout,
			// A redirect from a policy engine is not a policy decision. Not
			// following one keeps this call pinned to the configured endpoint.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Authorize asks the engine for a decision.
//
// A returned error is always a refusal: callers must treat both an error and
// Allow=false as "do not proceed".
func (c *Client) Authorize(ctx context.Context, request Request) (Decision, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: encoding the input: %v", ErrEngineUnavailable, err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	// Sent as a header as well as inside input.context: the engine ignores
	// headers, and a future proxy or log in front of it does not have to.
	if request.Input.Context.TraceParent != "" {
		httpRequest.Header.Set("traceparent", request.Input.Context.TraceParent)
	}

	start := time.Now()
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrEngineUnavailable, classifyTransportError(err))
	}
	defer response.Body.Close()
	duration := time.Since(start)

	if response.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(response.Body, 256))
		return Decision{Raw: snippet, Duration: duration}, fmt.Errorf(
			"%w: engine returned %s: %s", ErrEngineUnavailable, response.Status, bytes.TrimSpace(snippet))
	}

	// Bound the body: a decision document is a handful of bytes, and the size
	// of what a dependency can make this service allocate is not the
	// dependency's decision to make.
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return Decision{}, fmt.Errorf("%w: reading the decision: %v", ErrEngineUnavailable, err)
	}

	var document Response
	if err := json.Unmarshal(raw, &document); err != nil {
		return Decision{Raw: raw, Duration: duration}, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	if document.Result.Allow == nil {
		return Decision{Raw: raw, Duration: duration}, fmt.Errorf(
			"%w: the response has no result.allow field", ErrMalformedResponse)
	}

	return Decision{
		Allow:    *document.Result.Allow,
		Reason:   firstNonEmpty(document.Result.DenyReason, document.Result.Reason),
		Raw:      raw,
		Duration: duration,
	}, nil
}

// classifyTransportError turns a Go transport error into a sentence an operator
// can act on. "connection refused" and "certificate signed by unknown
// authority" are the two failures that actually happen against an internal
// service, and mistaking one for the other costs an afternoon.
func classifyTransportError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		var tlsErr *tls.CertificateVerificationError
		if errors.As(err, &tlsErr) {
			return fmt.Errorf("the engine's certificate was rejected: %w", err)
		}
		return fmt.Errorf("the engine did not answer before the deadline: %w", err)
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return fmt.Errorf("the engine's certificate was rejected: %w", err)
	}
	return err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
