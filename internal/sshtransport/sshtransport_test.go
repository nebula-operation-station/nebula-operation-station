// SPDX-License-Identifier: AGPL-3.0-or-later

package sshtransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func edSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ecSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rsaSigner(t *testing.T, bits int) ssh.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type mode int

const (
	modeSSH     mode = iota
	modeGarbage      // speaks something that is not SSH
	modeSilent       // accepts TCP, never sends anything
)

// server is an in-process SSH server on 127.0.0.1.
type server struct {
	t          *testing.T
	ln         net.Listener
	mode       mode
	hostKeys   []ssh.Signer
	authorized ssh.PublicKey
	noKeepRep  atomic.Bool

	conns    atomic.Int32 // TCP connections accepted
	authSeen atomic.Int32 // public-key authentication attempts
	users    sync.Map
	wg       sync.WaitGroup
	mu       sync.Mutex
	open     []net.Conn
}

func newServer(t *testing.T, m mode, authorized ssh.PublicKey, hostKeys ...ssh.Signer) *server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{t: t, ln: ln, mode: m, hostKeys: hostKeys, authorized: authorized}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		ln.Close()
		// Close server-side connections too, so a client a failed test
		// leaked cannot block the cleanup.
		s.mu.Lock()
		for _, c := range s.open {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *server) ep() Endpoint {
	a := s.ln.Addr().(*net.TCPAddr)
	return Endpoint{Host: "127.0.0.1", Port: uint16(a.Port)}
}

func (s *server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.conns.Add(1)
		s.mu.Lock()
		s.open = append(s.open, c)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *server) handle(c net.Conn) {
	defer c.Close()
	switch s.mode {
	case modeGarbage:
		fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	case modeSilent:
		buf := make([]byte, 1)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Read(buf)
		return
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.authSeen.Add(1)
			s.users.Store(md.User(), true)
			if s.authorized != nil && string(key.Marshal()) == string(s.authorized.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("denied")
		},
	}
	for _, k := range s.hostKeys {
		cfg.AddHostKey(k)
	}
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go func() {
		for r := range reqs {
			if s.noKeepRep.Load() {
				continue // swallow: no reply
			}
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for nc := range chans {
		_ = nc.Reject(ssh.Prohibited, "test server")
	}
}

// closedEndpoint is a local port nobody listens on.
func closedEndpoint(t *testing.T) Endpoint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return Endpoint{Host: "127.0.0.1", Port: uint16(p)}
}

var fast = Config{ConnectTimeout: 2 * time.Second}

func wantClass(t *testing.T, err error, c Class) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Class != c {
		t.Fatalf("want class %q, got %v", c, err)
	}
	return e
}

func TestDialFirstEndpoint(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	s := newServer(t, modeSSH, user.PublicKey(), hk)
	c, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{s.ep()}, User: "nebula", HostKey: hk.PublicKey()}, user)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Endpoint != s.ep() || len(c.Attempts) != 0 {
		t.Fatalf("endpoint %v attempts %v", c.Endpoint, c.Attempts)
	}
	if _, ok := s.users.Load("nebula"); !ok {
		t.Fatal("server did not see user nebula")
	}
}

func TestTCPFailureFallsBackToNextEndpoint(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	s := newServer(t, modeSSH, user.PublicKey(), hk)
	eps := []Endpoint{closedEndpoint(t), closedEndpoint(t), s.ep()}
	c, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: eps, User: "nebula", HostKey: hk.PublicKey()}, user)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Endpoint != s.ep() || len(c.Attempts) != 2 || c.Attempts[0].Stage != StageTCP {
		t.Fatalf("endpoint %v attempts %+v", c.Endpoint, c.Attempts)
	}
}

func TestAllEndpointsUnreachable(t *testing.T) {
	user := edSigner(t)
	_, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{closedEndpoint(t), closedEndpoint(t)},
		User: "nebula", HostKey: edSigner(t).PublicKey()}, user)
	e := wantClass(t, err, ClassUnreachable)
	if len(e.Attempts) != 2 {
		t.Fatalf("attempts %+v", e.Attempts)
	}
}

func TestHandshakeFailureTriesNextEndpointOnce(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	pin := hk.PublicKey()

	// One handshake failure, then success.
	bad := newServer(t, modeGarbage, nil)
	good := newServer(t, modeSSH, user.PublicKey(), hk)
	c, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{bad.ep(), good.ep()}, User: "nebula", HostKey: pin}, user)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	// Two handshake failures: stop, the third endpoint is not contacted.
	bad1 := newServer(t, modeGarbage, nil)
	bad2 := newServer(t, modeGarbage, nil)
	third := newServer(t, modeSSH, user.PublicKey(), hk)
	_, err = fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{bad1.ep(), bad2.ep(), third.ep()}, User: "nebula", HostKey: pin}, user)
	wantClass(t, err, ClassUnreachable)
	if third.conns.Load() != 0 {
		t.Fatal("third endpoint contacted after two handshake failures")
	}

	// A TCP failure between them does not use up the retry.
	bad3 := newServer(t, modeGarbage, nil)
	good2 := newServer(t, modeSSH, user.PublicKey(), hk)
	c, err = fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{closedEndpoint(t), bad3.ep(), good2.ep()}, User: "nebula", HostKey: pin}, user)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestSilentEndpointTimesOut(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	silent := newServer(t, modeSilent, nil)
	good := newServer(t, modeSSH, user.PublicKey(), hk)
	cfg := Config{ConnectTimeout: 300 * time.Millisecond}
	start := time.Now()
	c, err := cfg.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{silent.ep(), good.ep()}, User: "nebula", HostKey: hk.PublicKey()}, user)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if time.Since(start) > 3*time.Second || c.Attempts[0].Stage != StageHandshake {
		t.Fatalf("took %v, attempts %+v", time.Since(start), c.Attempts)
	}
}

func TestHostKeyMismatchIsHardStop(t *testing.T) {
	hk, other, user := edSigner(t), edSigner(t), edSigner(t)
	evil := newServer(t, modeSSH, user.PublicKey(), other)
	good := newServer(t, modeSSH, user.PublicKey(), hk)
	_, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{evil.ep(), good.ep()}, User: "nebula", HostKey: hk.PublicKey()}, user)
	e := wantClass(t, err, ClassHostKeyMismatch)
	if e.Presented == nil || Fingerprint(e.Presented) != Fingerprint(other.PublicKey()) {
		t.Fatalf("presented %v", e.Presented)
	}
	if evil.authSeen.Load() != 0 {
		t.Fatal("credential offered to a host with the wrong key")
	}
	if good.conns.Load() != 0 {
		t.Fatal("next endpoint tried after a host key mismatch")
	}
	if !strings.Contains(e.Error(), Fingerprint(other.PublicKey())) {
		t.Fatalf("error does not name the presented key: %v", e)
	}
}

func TestMissingPinnedKeyTypeIsMismatch(t *testing.T) {
	pinned, user := edSigner(t), edSigner(t)
	// The host now offers only an ECDSA key: no silent switch of key type.
	ecOnly := newServer(t, modeSSH, user.PublicKey(), ecSigner(t))
	good := newServer(t, modeSSH, user.PublicKey(), pinned)
	_, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{ecOnly.ep(), good.ep()}, User: "nebula", HostKey: pinned.PublicKey()}, user)
	wantClass(t, err, ClassHostKeyMismatch)
	if ecOnly.authSeen.Load() != 0 || good.conns.Load() != 0 {
		t.Fatal("authentication attempted or next endpoint tried")
	}
}

func TestOnlyThePinnedKeyTypeIsNegotiated(t *testing.T) {
	ed, ec, rs, user := edSigner(t), ecSigner(t), rsaSigner(t, 2048), edSigner(t)
	s := newServer(t, modeSSH, user.PublicKey(), ed, ec, rs)
	for _, pin := range []ssh.Signer{ed, ec, rs} {
		c, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{s.ep()}, User: "nebula", HostKey: pin.PublicKey()}, user)
		if err != nil {
			t.Fatalf("pin %s: %v", pin.PublicKey().Type(), err)
		}
		c.Close()
	}
}

func TestAuthFailureIsHardStop(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	deny := newServer(t, modeSSH, edSigner(t).PublicKey(), hk) // authorizes another key
	good := newServer(t, modeSSH, user.PublicKey(), hk)
	_, err := fast.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{deny.ep(), good.ep()}, User: "nebula", HostKey: hk.PublicKey()}, user)
	wantClass(t, err, ClassAuth)
	if good.conns.Load() != 0 {
		t.Fatal("key offered to another endpoint after an authentication failure")
	}
	if deny.authSeen.Load() == 0 {
		t.Fatal("authentication was not attempted")
	}
}

func TestDialNeedsPinAndEndpoints(t *testing.T) {
	user := edSigner(t)
	cases := []Target{
		{HostID: "h", Endpoints: []Endpoint{{Host: "127.0.0.1"}}, User: "n"},
		{HostID: "h", User: "n", HostKey: edSigner(t).PublicKey()},
		{HostID: "h", Endpoints: make([]Endpoint, MaxEndpoints+1), User: "n", HostKey: edSigner(t).PublicKey()},
		{HostID: "h", Endpoints: []Endpoint{{Host: "127.0.0.1"}}, HostKey: edSigner(t).PublicKey()},
		{HostID: "h", Endpoints: []Endpoint{{Host: "127.0.0.1"}}, User: "n", HostKey: rsaSigner(t, 1024).PublicKey()},
	}
	for i, tg := range cases {
		_, err := fast.Dial(context.Background(), tg, user)
		if ClassOf(err) != ClassInvalid {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestCanceledContext(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	s := newServer(t, modeSSH, user.PublicKey(), hk)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fast.Dial(ctx, Target{HostID: "h1", Endpoints: []Endpoint{s.ep()}, User: "nebula", HostKey: hk.PublicKey()}, user)
	wantClass(t, err, ClassCanceled)
}

func TestKeepaliveDropsDeadConnection(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	s := newServer(t, modeSSH, user.PublicKey(), hk)
	s.noKeepRep.Store(true)
	cfg := Config{ConnectTimeout: 2 * time.Second, KeepaliveInterval: 40 * time.Millisecond, KeepaliveMaxMissed: 3}
	c, err := cfg.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{s.ep()}, User: "nebula", HostKey: hk.PublicKey()}, user)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection kept although keepalives went unanswered")
	}
	c.Close()
}

func TestKeepaliveKeepsLiveConnection(t *testing.T) {
	hk, user := edSigner(t), edSigner(t)
	s := newServer(t, modeSSH, user.PublicKey(), hk)
	cfg := Config{ConnectTimeout: 2 * time.Second, KeepaliveInterval: 20 * time.Millisecond, KeepaliveMaxMissed: 2}
	c, err := cfg.Dial(context.Background(), Target{HostID: "h1", Endpoints: []Endpoint{s.ep()}, User: "nebula", HostKey: hk.PublicKey()}, user)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("live connection dropped")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestProbeSendsNoCredentialAndPrefersEd25519(t *testing.T) {
	ed, ec, rs := edSigner(t), ecSigner(t), rsaSigner(t, 2048)
	s := newServer(t, modeSSH, nil, rs, ec, ed)
	k, err := fast.Probe(context.Background(), s.ep())
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(k) != Fingerprint(ed.PublicKey()) {
		t.Fatalf("probe chose %s", k.Type())
	}
	if s.authSeen.Load() != 0 {
		t.Fatal("probe attempted authentication")
	}
	empty := true
	s.users.Range(func(_, _ any) bool { empty = false; return false })
	if !empty {
		t.Fatal("probe sent a user name")
	}

	// Without ed25519, ECDSA beats RSA.
	s2 := newServer(t, modeSSH, nil, rs, ec)
	k, err = fast.Probe(context.Background(), s2.ep())
	if err != nil || k.Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("probe chose %v, %v", k, err)
	}
}

func TestProbeRefusesWeakKeyAndNonSSH(t *testing.T) {
	weak := newServer(t, modeSSH, nil, rsaSigner(t, 1024))
	_, err := fast.Probe(context.Background(), weak.ep())
	wantClass(t, err, ClassInvalid)

	garbage := newServer(t, modeGarbage, nil)
	_, err = fast.Probe(context.Background(), garbage.ep())
	wantClass(t, err, ClassUnreachable)

	_, err = fast.Probe(context.Background(), closedEndpoint(t))
	wantClass(t, err, ClassUnreachable)
}

func TestParseEndpoint(t *testing.T) {
	ok := map[string]Endpoint{
		"host.lan":          {Host: "host.lan"},
		"Host.LAN:2222":     {Host: "host.lan", Port: 2222},
		"192.168.0.37":      {Host: "192.168.0.37"},
		"10.0.0.1:22":       {Host: "10.0.0.1", Port: 22},
		"fd00::1":           {Host: "fd00::1"},
		"[fd00::1]":         {Host: "fd00::1"},
		"[fd00::1]:2200":    {Host: "fd00::1", Port: 2200},
		"srv-01.example.de": {Host: "srv-01.example.de"},
	}
	for in, want := range ok {
		got, err := ParseEndpoint(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "host:0", "host:65536", "host:22a", "host:022", "-bad.lan", "a..b", "[10.0.0.1]",
		"fe80::1%eth0", "host name", "x:" + strings.Repeat("1", 6), strings.Repeat("a", 64) + ".lan", "ho_st"} {
		if _, err := ParseEndpoint(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if (Endpoint{Host: "fd00::1"}).Address() != "[fd00::1]:22" {
		t.Error("IPv6 address form")
	}
}

func authorizedLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestImportKnownHosts(t *testing.T) {
	ed, rs, other := edSigner(t), rsaSigner(t, 2048), edSigner(t)
	eps := []Endpoint{{Host: "srv1.lan"}, {Host: "10.8.0.5", Port: 2222}}

	data := strings.Join([]string{
		"# comment",
		"",
		"srv1.lan,192.168.0.10 " + authorizedLine(rs.PublicKey()),
		"[10.8.0.5]:2222 " + authorizedLine(ed.PublicKey()),
		knownhosts.HashHostname("srv1.lan") + " " + authorizedLine(ed.PublicKey()),
		"*.lan " + authorizedLine(other.PublicKey()),    // wildcard: ignored
		"10.8.0.5 " + authorizedLine(other.PublicKey()), // port 22: another endpoint
	}, "\n")
	m, err := ImportKnownHosts([]byte(data), eps)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(m.Key) != Fingerprint(ed.PublicKey()) || len(m.Endpoints) != 2 || m.Ignored != 1 {
		t.Fatalf("match %s endpoints %v ignored %d", Fingerprint(m.Key), m.Endpoints, m.Ignored)
	}

	// Only RSA known: RSA is chosen.
	m, err = ImportKnownHosts([]byte("srv1.lan "+authorizedLine(rs.PublicKey())), eps[:1])
	if err != nil || m.Key.Type() != ssh.KeyAlgoRSA {
		t.Fatalf("%v %v", m.Key, err)
	}

	// Revoked keys are never chosen.
	revoked := "@revoked * " + authorizedLine(ed.PublicKey()) + "\n" + "srv1.lan " + authorizedLine(ed.PublicKey())
	if _, err := ImportKnownHosts([]byte(revoked), eps[:1]); err == nil {
		t.Fatal("revoked key chosen")
	}
	revoked += "\nsrv1.lan " + authorizedLine(rs.PublicKey())
	m, err = ImportKnownHosts([]byte(revoked), eps[:1])
	if err != nil || m.Key.Type() != ssh.KeyAlgoRSA {
		t.Fatalf("expected the non-revoked RSA key: %v %v", m.Key, err)
	}

	// Two different ed25519 keys for the host: conflict.
	conflict := "srv1.lan " + authorizedLine(ed.PublicKey()) + "\n[10.8.0.5]:2222 " + authorizedLine(other.PublicKey())
	if _, err := ImportKnownHosts([]byte(conflict), eps); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict not reported: %v", err)
	}

	// Nothing for these endpoints.
	if _, err := ImportKnownHosts([]byte("other.lan "+authorizedLine(ed.PublicKey())), eps); err == nil {
		t.Fatal("no entry accepted")
	}
	// A broken line is reported with its number, not skipped.
	broken := "srv1.lan " + authorizedLine(ed.PublicKey()) + "\nsrv2.lan ssh-ed25519 AAAA-not-base64"
	if _, err := ImportKnownHosts([]byte(broken), eps); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("broken line: %v", err)
	}
	// Weak keys are not usable.
	weak := "srv1.lan " + authorizedLine(rsaSigner(t, 1024).PublicKey())
	if m, err := ImportKnownHosts([]byte(weak), eps[:1]); err == nil || m.Ignored != 1 {
		t.Fatalf("weak key: %v %v", m, err)
	}
	// @cert-authority lines are ignored.
	ca := "@cert-authority srv1.lan " + authorizedLine(ed.PublicKey())
	if _, err := ImportKnownHosts([]byte(ca), eps[:1]); err == nil {
		t.Fatal("CA key pinned as host key")
	}
}
