package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"telemetry/internal/certtest"
)

// The tests issue their own certificates rather than checking in fixtures: a
// checked-in key is a checked-in secret, and a fixture that expires turns a
// green suite red on a date nobody chose.

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func caFile(t *testing.T, ca *certtest.CA) string {
	t.Helper()
	path, err := ca.WriteCAFile(t.TempDir())
	if err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

// serverFiles issues a certificate for the names a test dials.
func serverFiles(t *testing.T, ca *certtest.CA) (certPath, keyPath string) {
	t.Helper()
	bundle, err := ca.Issue("telemetry", true, []string{"localhost", "telemetry"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		t.Fatalf("issue server certificate: %v", err)
	}
	certPath, keyPath, err = bundle.WriteFiles(t.TempDir(), "server")
	if err != nil {
		t.Fatalf("write server certificate: %v", err)
	}
	return certPath, keyPath
}

func clientFiles(t *testing.T, ca *certtest.CA) (certPath, keyPath string) {
	t.Helper()
	bundle, err := ca.Issue("telemetry-collector", false, nil, nil)
	if err != nil {
		t.Fatalf("issue client certificate: %v", err)
	}
	certPath, keyPath, err = bundle.WriteFiles(t.TempDir(), "client")
	if err != nil {
		t.Fatalf("write client certificate: %v", err)
	}
	return certPath, keyPath
}

// --- settings --------------------------------------------------------------

func TestNoSettingsMeansNoTLS(t *testing.T) {
	// A local `docker compose up --build` must keep working, so an unset
	// configuration has to mean "plain HTTP", not "fail to start".
	var settings Settings
	if settings.Enabled() {
		t.Error("empty settings reported TLS as enabled")
	}
	server, err := settings.Server()
	if err != nil || server != nil {
		t.Errorf("Server() = %v, %v; want nil, nil", server, err)
	}
	client, err := settings.Client()
	if err != nil || client != nil {
		t.Errorf("Client() = %v, %v; want nil, nil", client, err)
	}
}

func TestMisconfigurationIsNamed(t *testing.T) {
	// A certificate without its key, and a mutual listener with nothing to
	// verify against, are startup errors rather than handshake surprises.
	if err := (Settings{CertFile: "/tmp/a.crt"}).Validate(); err == nil {
		t.Error("a certificate without a key was accepted")
	} else if !strings.Contains(err.Error(), "together") {
		t.Errorf("error = %v, want it to explain the pair", err)
	}
	if err := (Settings{KeyFile: "/tmp/a.key"}).Validate(); err == nil {
		t.Error("a key without a certificate was accepted")
	}
	if err := (Settings{RequireClientCert: true}).Validate(); err == nil {
		t.Error("requiring a client certificate without a CA was accepted")
	}

	// A file that parses but holds no certificate is the truncated-file
	// failure mode: it must be reported here, not as every peer failing to
	// verify later.
	broken := filepath.Join(t.TempDir(), "ca.crt")
	if err := writeFile(broken, "not a certificate"); err != nil {
		t.Fatalf("write broken CA: %v", err)
	}
	if _, err := (Settings{CAFile: broken}).Server(); err == nil {
		t.Error("a CA file with no PEM certificate was accepted")
	} else if !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("error = %v, want it to name the file's problem", err)
	}
	if _, err := (Settings{CAFile: filepath.Join(t.TempDir(), "missing.crt")}).Server(); err == nil {
		t.Error("a missing CA file was accepted")
	}
}

// --- the real handshake ----------------------------------------------------

// serve starts a TLS listener with these settings and returns its address. The
// handler echoes one byte.
func serve(t *testing.T, settings Settings) string {
	t.Helper()
	config, err := settings.Server()
	if err != nil {
		t.Fatalf("Server(): %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				buffer := make([]byte, 1)
				if _, err := connection.Read(buffer); err != nil {
					return
				}
				// The reply says whether the peer was authenticated with a
				// certificate, because a successful handshake does not.
				reply := []byte("a")
				if state, ok := connection.(*tls.Conn); ok && len(state.ConnectionState().PeerCertificates) > 0 {
					reply = []byte("k")
				}
				_, _ = connection.Write(reply)
			}()
		}
	}()
	return listener.Addr().String()
}

// dial completes a full round trip and returns the server's reply: 'k' when it
// authenticated the peer with a certificate, 'a' when the peer was anonymous.
//
// A round trip is required because under TLS 1.3 the client finishes its side of
// the handshake before the server has looked at its certificate, so a successful
// Dial proves nothing about whether the peer was accepted. Only moving bytes does.
func dial(t *testing.T, address string, settings Settings) (byte, error) {
	t.Helper()
	config, err := settings.Client()
	if err != nil {
		t.Fatalf("Client(): %v", err)
	}
	connection, err := tls.Dial("tcp", address, config)
	if err != nil {
		return 0, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := connection.Write([]byte("x")); err != nil {
		return 0, err
	}
	reply := make([]byte, 1)
	if _, err := connection.Read(reply); err != nil {
		return 0, err
	}
	return reply[0], nil
}

func TestMutualTLSRequiresACertificateFromTheSharedCA(t *testing.T) {
	ca, err := certtest.NewCA("dss-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	serverCert, serverKey := serverFiles(t, ca)
	clientCert, clientKey := clientFiles(t, ca)

	address := serve(t, Settings{
		CertFile:          serverCert,
		KeyFile:           serverKey,
		CAFile:            caFile(t, ca),
		RequireClientCert: true,
	})

	// The collector that holds a certificate issued by the shared CA connects,
	// and the server can name it.
	reply, err := dial(t, address, Settings{CAFile: caFile(t, ca), CertFile: clientCert, KeyFile: clientKey})
	if err != nil {
		t.Fatalf("a client with a CA-issued certificate was refused: %v", err)
	}
	if reply != 'k' {
		t.Errorf("the server did not authenticate the collector, reply = %q", reply)
	}

	// A peer without a certificate is refused during the handshake, before it
	// can send a single byte of an audit record.
	if _, err := dial(t, address, Settings{CAFile: caFile(t, ca)}); err == nil {
		t.Error("a client with no certificate was accepted by a mutual listener")
	}

	// A certificate from a different authority is not a certificate.
	otherCA, err := certtest.NewCA("some-other-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	otherCert, otherKey := clientFiles(t, otherCA)
	if _, err := dial(t, address, Settings{CAFile: caFile(t, ca), CertFile: otherCert, KeyFile: otherKey}); err == nil {
		t.Error("a certificate from an unrelated CA was accepted by a mutual listener")
	}
}

func TestServerCertificateIsVerifiedAgainstTheCA(t *testing.T) {
	ca, err := certtest.NewCA("dss-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	serverCert, serverKey := serverFiles(t, ca)

	// Trusting a *different* CA must fail: the client pins the shared CA
	// instead of the system pool, so a certificate from a public authority is
	// not a reason to trust the audit API.
	address := serve(t, Settings{CertFile: serverCert, KeyFile: serverKey})
	otherCA, err := certtest.NewCA("some-other-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	if _, err := dial(t, address, Settings{CAFile: caFile(t, otherCA)}); err == nil {
		t.Error("a server was trusted through the wrong CA")
	}
	if _, err := dial(t, address, Settings{CAFile: caFile(t, ca)}); err != nil {
		t.Errorf("the CA that signed the server was not trusted: %v", err)
	}
}

// A client that offers a certificate is verified when it chains to the CA, but
// one without a certificate is still served: that is how mTLS is rolled out to
// a fleet without breaking every collector at once.
func TestClientCertificatesAreVerifiedWhenOffered(t *testing.T) {
	ca, err := certtest.NewCA("dss-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	serverCert, serverKey := serverFiles(t, ca)
	clientCert, clientKey := clientFiles(t, ca)

	address := serve(t, Settings{CertFile: serverCert, KeyFile: serverKey, CAFile: caFile(t, ca)})

	if reply, err := dial(t, address, Settings{CAFile: caFile(t, ca)}); err != nil {
		t.Errorf("a client with no certificate was refused before mTLS was required: %v", err)
	} else if reply != 'a' {
		t.Errorf("an anonymous client was reported as authenticated: %q", reply)
	}
	if reply, err := dial(t, address, Settings{CAFile: caFile(t, ca), CertFile: clientCert, KeyFile: clientKey}); err != nil {
		t.Errorf("a client with a valid certificate was refused: %v", err)
	} else if reply != 'k' {
		t.Errorf("a valid certificate was not verified, reply = %q", reply)
	}

	// A certificate from an unrelated authority is never *verified*, but this
	// mode does not refuse the connection either: the client sees that its
	// certificate is not in the server's acceptable-CA list and sends none, so
	// the peer is simply anonymous. That is Go's behaviour and it is the right
	// default for a staged rollout — the security guarantee this mode gives is
	// "a certificate that is presented is verified", and requiring one outright
	// is what TestMutualTLSRequiresACertificateFromTheSharedCA asserts.
	otherCA, err := certtest.NewCA("some-other-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	otherCert, otherKey := clientFiles(t, otherCA)
	if reply, err := dial(t, address, Settings{CAFile: caFile(t, ca), CertFile: otherCert, KeyFile: otherKey}); err != nil {
		t.Errorf("optional client authentication refused a connection outright: %v", err)
	} else if reply == 'k' {
		t.Error("a certificate from an unrelated CA was verified as valid")
	}
}

// The Transport Contract names TLS 1.3. A client that can only offer less must
// be refused rather than negotiated down to.
func TestTLS13IsTheFloor(t *testing.T) {
	ca, err := certtest.NewCA("dss-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	serverCert, serverKey := serverFiles(t, ca)
	address := serve(t, Settings{CertFile: serverCert, KeyFile: serverKey})

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("could not load the test CA")
	}
	connection, err := tls.Dial("tcp", address, &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: "telemetry",
	})
	if err == nil {
		connection.Close()
		t.Fatal("a TLS 1.2-only client was allowed to connect")
	}
	if !strings.Contains(err.Error(), "protocol version") {
		t.Logf("TLS 1.2 was refused with: %v", err)
	}
}
