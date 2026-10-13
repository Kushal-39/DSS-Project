package mtls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// acceptErrSlot is a concrete struct that can hold an error value inside an
// atomic.Pointer. Go's atomic pointer ops store *T, and T cannot be an
// interface here, so we box the error in a concrete wrapper.
type acceptErrSlot struct {
	v error
}

// Rejection describes a TLS handshake this service refused.
//
// It exists because the most common integration failure in this project leaves
// no trace at all otherwise: a caller without a certificate (or with one signed
// by the wrong CA) never reaches a handler, so nothing inside the application
// runs and nothing is logged. The handshake is the only place that can see it
// (telemetry/docs/integration.md §3 "Person 4" makes exactly this point).
type Rejection struct {
	// RemoteAddr is the peer that was refused. It may be a caller that never
	// authenticated, so it is evidence, not identity.
	RemoteAddr string
	// Reason is a stable, machine-readable classification.
	Reason string
	// Identity and Subject are set when a certificate *was* presented but
	// rejected — the case worth investigating, since the caller is inside the
	// network and appears to believe it has credentials.
	Identity string
	Subject  string
	// Err is the underlying handshake error.
	Err error
	// Duration is how long the handshake took before it failed.
	Duration time.Duration
	// Suppressed is the number of additional rejections from the same listener
	// that were not reported individually because of rate limiting. A port scan
	// must not be able to fill the audit store; a sustained refusal remains
	// visible either way.
	Suppressed int
}

// Rejection reasons.
const (
	// ReasonNoCertificate is a client that presented no certificate at all.
	ReasonNoCertificate = "no_client_certificate"
	// ReasonUntrustedCertificate is a certificate that does not chain to the
	// configured CA (or is expired, or not valid for client authentication).
	ReasonUntrustedCertificate = "client_certificate_untrusted"
	// ReasonNotTLS is a peer speaking something that is not TLS.
	ReasonNotTLS = "not_a_tls_client"
	// ReasonTimeout is a handshake that never completed (slow-loris on the TLS
	// handshake).
	ReasonTimeout = "handshake_timeout"
	// ReasonHandshakeFailed is anything else: protocol mismatch, aborted
	// connection, or a client that refused our certificate.
	ReasonHandshakeFailed = "handshake_failed"
)

// maxInFlightHandshakes bounds how many handshakes this listener will run at
// once. The bound is the point: without it, a client that opens connections and
// never speaks consumes a file descriptor and a goroutine each time it is
// allowed to, and "a lot of half-open connections" is a denial of service that
// costs the attacker one socket per attempt.
const maxInFlightHandshakes = 64

// Listener wraps a net.Listener and performs the TLS handshake during Accept.
//
// The handshake is idiomatic to leave to net/http, but then a refused peer is
// invisible: http.Server just closes the connection, and this project's audit
// trail would have nothing to show for the single most common integration
// failure (a caller with no, or the wrong, client certificate).
//
// Three details make doing it here correct rather than merely different:
//
//  1. **A refused handshake is absorbed, not reported as an accept error.**
//     Accept never returns an error for a bad peer, so net/http's accept loop
//     never sees one. That matters twice over: http.Server logs every accept
//     error (`http: Accept error: …`) into the same stdout stream the audit
//     collector reads — a scanner would fill the trail with noise — and it
//     applies an exponential backoff (5 ms doubling to 1 s) to the accept loop,
//     which lets a handful of bad clients slow down legitimate connections.
//
//  2. **Handshakes run concurrently and are bounded.** A handshake is
//     attacker-controlled work: a peer can open a connection and stall for the
//     whole handshake timeout. Performing it inline in Accept would mean one
//     stalled client blocks every other connection for that long, so the
//     handshake is handed to a goroutine of its own and Accept waits for the
//     next *completed* handshake. maxInFlightHandshakes caps how much of that
//     work exists at once.
//
//  3. **Only transient accept failures are absorbed.** A TCP listener's accept
//     can fail transiently (EAGAIN / temporary resource exhaustion) without the
//     listener being dead, and treating that as a permanent error would stop
//     serving. recordAcceptErr classifies the error: transient ones are
//     remembered for diagnostics without stopping Accept; permanent ones
//     (Close, bad file descriptor) are propagated.
type Listener struct {
	net.Listener
	config           *tls.Config
	handshakeTimeout time.Duration
	onReject         func(Rejection)

	// slots is the in-flight handshake semaphore.
	slots chan struct{}
	// accepted carries connections whose handshake succeeded. Its capacity
	// exceeds the semaphore's, so a handshake goroutine never blocks handing
	// over a good connection (and never holds its slot waiting to).
	accepted chan net.Conn
	// done is closed by Close to unblock Accept and any goroutine still
	// finishing a handshake.
	done             chan struct{}
	closeOnce        sync.Once
	closeErr         error
	stopped          chan struct{}
	terminalErr      atomic.Pointer[acceptErrSlot]
	handshakeCtx     context.Context
	cancelHandshakes context.CancelFunc
	handshakes       sync.WaitGroup

	// acceptErr is an atomic that remembers the first transient accept failure
	// without letting a permanent one (bad file descriptor, Close) pass through.
	acceptErr atomic.Pointer[acceptErrSlot]

	// Rate limiting for the rejection log. A scanner hitting the port produces
	// thousands of identical refusals; the audit trail needs the first few and
	// a count, not all of them.
	mu         sync.Mutex
	windowFrom time.Time
	windowHits int
	suppressed int
}

// rateWindow and rateBurst bound how many rejections are reported per window.
const (
	rateWindow = time.Second
	rateBurst  = 10
)

// NewListener wraps inner. onReject may be nil, in which case refusals are only
// counted (never audited), which is not what production wants — the audit line
// is the point.
func NewListener(inner net.Listener, config *tls.Config, handshakeTimeout time.Duration, onReject func(Rejection)) *Listener {
	if handshakeTimeout <= 0 {
		handshakeTimeout = 5 * time.Second
	}
	listener := &Listener{
		Listener:         inner,
		config:           config,
		handshakeTimeout: handshakeTimeout,
		onReject:         onReject,
		slots:            make(chan struct{}, maxInFlightHandshakes),
		accepted:         make(chan net.Conn, maxInFlightHandshakes+1),
		done:             make(chan struct{}),
		stopped:          make(chan struct{}),
	}
	listener.handshakeCtx, listener.cancelHandshakes = context.WithCancel(context.Background())
	go listener.acceptLoop()
	return listener
}

// Accept returns only connections whose handshake completed, so a handler can
// never observe an unverified peer. Every refusal is classified, rate-limited
// and reported through onReject instead of being surfaced to net/http.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.stopped:
		if slot := l.terminalErr.Load(); slot != nil {
			return nil, slot.v
		}
		return nil, net.ErrClosed
	}
}

// Accept sockets continuously; a bad or stalled peer never serializes the next
// handshake. Both unfinished handshakes and completed queued sockets are bounded.
func (l *Listener) acceptLoop() {
	defer close(l.stopped)
	for {
		select {
		case l.slots <- struct{}{}:
		case <-l.done:
			return
		}
		conn, err := l.Listener.Accept()
		if err != nil {
			<-l.slots
			if l.recordAcceptErr(err) {
				l.terminalErr.Store(&acceptErrSlot{v: err})
				return
			}
			select {
			case <-time.After(10 * time.Millisecond):
			case <-l.done:
				return
			}
			continue
		}
		l.handshakes.Add(1)
		go func() { defer l.handshakes.Done(); l.handshake(conn) }()
	}
}

// handshake completes one connection and either hands it to Accept or reports
// the refusal. It always releases its slot.
func (l *Listener) handshake(conn net.Conn) {
	defer func() { <-l.slots }()

	tlsConn := tls.Server(conn, l.config)
	start := time.Now()
	ctx, cancel := context.WithTimeout(l.handshakeCtx, l.handshakeTimeout)
	handshakeErr := tlsConn.HandshakeContext(ctx)
	cancel()

	if handshakeErr == nil {
		select {
		case <-l.done:
			// The listener closed while this handshake was finishing: nobody
			// will ever read the connection, so close it rather than leak a
			// descriptor and a peer waiting for a response.
			_ = tlsConn.Close()
		case l.accepted <- tlsConn:
		}
		return
	}

	// Classify before closing: the peer's certificate and the remote address
	// are what the audit line is built from, and the refusal the caller sees
	// otherwise leaves no evidence of *who* was refused.
	rejection := classifyRejection(tlsConn, conn, handshakeErr, time.Since(start))
	if report, suppressed := l.record(); report {
		rejection.Suppressed = suppressed
		if l.onReject != nil {
			l.onReject(rejection)
		}
	}
	_ = tlsConn.Close()
}

// ClearAcceptErr clears any transient accept error remembered by Accept, so a
// recovered listener does not return a stale error on its next call.
func (l *Listener) ClearAcceptErr() {
	l.acceptErr.Store(nil)
}

// AcceptErr returns the first transient accept error Accept recorded, or nil.
func (l *Listener) AcceptErr() error {
	if p := l.acceptErr.Load(); p != nil {
		return p.v
	}
	return nil
}

// acceptErrTimeout is an opaque marker for an accept timeout; it satisfies error
// so it can be stored in the atomic, and it surfaces as a timeout to a caller
// that asks for it.
type acceptErrTimeout struct{}

func (acceptErrTimeout) Error() string { return "accept timed out" }
func (acceptErrTimeout) Timeout() bool { return true }

// Close stops accepting and unblocks Accept. A connection whose handshake
// finished after the server left is closed rather than drained: it belongs to a
// server that is shutting down.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.cancelHandshakes()
		l.closeErr = l.Listener.Close()
		<-l.stopped
		l.handshakes.Wait()
		for {
			select {
			case conn := <-l.accepted:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	return l.closeErr
}

// recordAcceptErr classifies an accept error as transient or permanent.
// Transient errors are remembered without stopping Accept; permanent ones stop
// it. This is the difference between "a TCP stack hiccup" and "the listener is
// dead".
func (l *Listener) recordAcceptErr(err error) bool {
	if err == nil {
		return false
	}
	// A closed listener should be reported rather than absorbed.
	if errors.Is(err, net.ErrClosed) {
		l.acceptErr.Store(nil)
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// A timeout on accept is transient: the OS could not return a connection
		// in time, not a dead socket. Remember it for diagnostics but do not stop.
		timeoutErr := acceptErrTimeout{}
		slot := acceptErrSlot{v: &timeoutErr}
		if l.acceptErr.CompareAndSwap(nil, &slot) {
			return false
		}
		return false
	}
	// Anything else is assumed permanent, including EOF, file descriptor
	// problems and the like. Remember it so the next Accept also surfaces it
	// (the caller can decide how long to keep trying), and clear any transient
	// noise we had recorded.
	slot := acceptErrSlot{v: err}
	l.acceptErr.Store(&slot)
	return true
}

// record decides whether this rejection should be reported, and how many were
// skipped since the last report.
func (l *Listener) record() (report bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.windowFrom) > rateWindow {
		l.windowFrom = now
		l.windowHits = 0
	}
	l.windowHits++
	if l.windowHits > rateBurst {
		l.suppressed++
		return false, l.suppressed
	}
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed
}

// classifyRejection turns a handshake error into a reason and, when one was
// offered, the identity of the certificate that was rejected.
func classifyRejection(tlsConn *tls.Conn, conn net.Conn, err error, elapsed time.Duration) Rejection {
	rejection := Rejection{
		RemoteAddr: conn.RemoteAddr().String(),
		Err:        err,
		Duration:   elapsed,
	}

	var verification *tls.CertificateVerificationError
	switch {
	case errors.As(err, &verification):
		// Either the chain does not lead to the configured CA, or the
		// certificate is expired or not valid for client authentication. All
		// three are "this credential is not acceptable", and the underlying
		// error text is carried in the log line for the distinction.
		rejection.Reason = ReasonUntrustedCertificate
		// The offered chain is available even though verification failed, so
		// the log can name the caller instead of only saying "someone".
		if len(verification.UnverifiedCertificates) > 0 {
			leaf := verification.UnverifiedCertificates[0]
			rejection.Identity = strings.TrimSpace(leaf.Subject.CommonName)
			rejection.Subject = leaf.Subject.String()
		}
	case strings.Contains(err.Error(), "didn't provide a certificate"):
		rejection.Reason = ReasonNoCertificate
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		rejection.Reason = ReasonTimeout
	case isNotTLS(err):
		rejection.Reason = ReasonNotTLS
	default:
		rejection.Reason = ReasonHandshakeFailed
	}

	// A peer certificate can still be present on a failed handshake (for
	// example when the failure was on the caller's side of the exchange).
	if state := tlsConn.ConnectionState(); len(state.PeerCertificates) > 0 && rejection.Identity == "" {
		leaf := state.PeerCertificates[0]
		rejection.Identity = strings.TrimSpace(leaf.Subject.CommonName)
		rejection.Subject = leaf.Subject.String()
	}
	return rejection
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isNotTLS(err error) bool {
	message := err.Error()
	return strings.Contains(message, "first record does not look like a TLS handshake") ||
		strings.Contains(message, "unexpected record type")
}
