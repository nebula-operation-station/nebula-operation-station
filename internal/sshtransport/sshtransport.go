// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sshtransport is the executor's SSH client (spec 08). It speaks SSH
// through x/crypto/ssh only, checks the pinned host key on every endpoint
// and maps every failure to one class, so the caller can decide without
// parsing error strings:
//
//	TCP timeout or refused                  -> next endpoint
//	SSH handshake failure before the key    -> next endpoint, once per dial
//	host key differs from the pin           -> hard stop (ClassHostKeyMismatch)
//	authentication failure                  -> hard stop (ClassAuth), no other
//	                                           endpoint sees the key
//
// Host keys are pinned per host, not per address. Probe reads a host's key
// for enrollment without sending any credential.
package sshtransport

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Timeouts from spec 08.
const (
	ConnectTimeout     = 10 * time.Second
	KeepaliveInterval  = 15 * time.Second
	KeepaliveMaxMissed = 4
)

// Limits.
const (
	DefaultPort  = 22
	MaxEndpoints = 8
	MinRSABits   = 2048
	maxHostLen   = 253
)

// preferredAlgorithms is the host key negotiation order before a key is
// pinned (spec 08: ed25519, then ECDSA, then rsa-sha2-512).
var preferredAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
}

// Endpoint is one address of a host. Port 0 means DefaultPort.
type Endpoint struct {
	Host string
	Port uint16
}

func (e Endpoint) port() uint16 {
	if e.Port == 0 {
		return DefaultPort
	}
	return e.Port
}

// Address is host:port for net.Dial.
func (e Endpoint) Address() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.port())))
}

func (e Endpoint) String() string { return e.Address() }

// ParseEndpoint accepts "host", "host:port", "[v6addr]", "[v6addr]:port"
// and a bare IPv6 address. host is an IP address or a DNS name.
func ParseEndpoint(s string) (Endpoint, error) {
	host, portStr := s, ""
	switch {
	case net.ParseIP(s) != nil:
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		host = s[1 : len(s)-1]
		if ip := net.ParseIP(host); ip == nil || ip.To4() != nil {
			return Endpoint{}, fmt.Errorf("endpoint %q: brackets are only for IPv6 addresses", s)
		}
	case strings.Contains(s, ":"):
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return Endpoint{}, fmt.Errorf("endpoint %q: %w", s, err)
		}
		host, portStr = h, p
	}
	if err := checkHost(host); err != nil {
		return Endpoint{}, fmt.Errorf("endpoint %q: %w", s, err)
	}
	e := Endpoint{Host: strings.ToLower(host)}
	if portStr != "" {
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != portStr {
			return Endpoint{}, fmt.Errorf("endpoint %q: port must be 1..65535", s)
		}
		e.Port = uint16(n)
	}
	return e, nil
}

// checkHost accepts an IP address (no zone) or an RFC 1123 host name.
func checkHost(h string) error {
	if h == "" || len(h) > maxHostLen {
		return errors.New("host name empty or too long")
	}
	if ip := net.ParseIP(h); ip != nil {
		return nil
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid host name %q", h)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("invalid host name %q", h)
			}
		}
	}
	return nil
}

// CheckHostKey accepts Ed25519, ECDSA (P-256/384/521) and RSA keys of at
// least MinRSABits. Anything else cannot be pinned.
func CheckHostKey(k ssh.PublicKey) error {
	if k == nil {
		return errors.New("no host key")
	}
	switch k.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return nil
	case ssh.KeyAlgoRSA:
		ck, ok := k.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("RSA host key without public key material")
		}
		pk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || pk.N.BitLen() < MinRSABits {
			return fmt.Errorf("RSA host key shorter than %d bits", MinRSABits)
		}
		return nil
	default:
		return fmt.Errorf("host key type %q is not accepted", k.Type())
	}
}

// Fingerprint is the OpenSSH SHA256 fingerprint ("SHA256:..."), the form
// `ssh-keygen -lf` prints.
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// pinnedAlgorithms offers only the pinned key's type (spec 08), so
// negotiation cannot pick a different, unpinned key of the host.
func pinnedAlgorithms(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512}
	}
	return []string{k.Type()}
}

// Class is the outcome class of a failed Dial.
type Class string

const (
	// ClassInvalid: the target cannot be dialled (no pin, bad endpoints).
	ClassInvalid Class = "invalid"
	// ClassUnreachable: every endpoint failed at TCP, or the handshake
	// failed before the host key on the endpoints tried.
	ClassUnreachable Class = "unreachable"
	// ClassHostKeyMismatch: an endpoint presented a key other than the pin,
	// or offered no key of the pinned type. Hard stop for the host.
	ClassHostKeyMismatch Class = "host_key_mismatch"
	// ClassAuth: the host key matched, then authentication failed (or the
	// connection dropped during it). Hard stop: no other endpoint is tried
	// with the same key.
	ClassAuth Class = "auth_failed"
	// ClassCanceled: the context ended.
	ClassCanceled Class = "canceled"
)

// Stage of one attempt.
const (
	StageTCP       = "tcp"
	StageHandshake = "handshake"
	StageHostKey   = "host_key"
	StageAuth      = "auth"
)

// Attempt records what happened on one endpoint.
type Attempt struct {
	Endpoint Endpoint
	Stage    string
	Err      error
}

// Error is returned by Dial and Probe.
type Error struct {
	Class    Class
	Attempts []Attempt
	// Presented is the key a mismatching endpoint showed (nil if it
	// offered no key of the pinned type).
	Presented ssh.PublicKey
	Detail    string
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ssh %s", e.Class)
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	}
	for _, a := range e.Attempts {
		fmt.Fprintf(&b, "; %s %s: %v", a.Endpoint, a.Stage, a.Err)
	}
	return b.String()
}

// ClassOf returns the class of err, or "" if it is not an *Error.
func ClassOf(err error) Class {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}

// Config tunes the transport. The zero value uses the spec 08 defaults.
type Config struct {
	ConnectTimeout     time.Duration
	KeepaliveInterval  time.Duration
	KeepaliveMaxMissed int
	// DialContext opens the TCP connection; nil uses net.Dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (c Config) connectTimeout() time.Duration {
	if c.ConnectTimeout > 0 {
		return c.ConnectTimeout
	}
	return ConnectTimeout
}

func (c Config) keepalive() (time.Duration, int) {
	iv, n := c.KeepaliveInterval, c.KeepaliveMaxMissed
	if iv <= 0 {
		iv = KeepaliveInterval
	}
	if n <= 0 {
		n = KeepaliveMaxMissed
	}
	return iv, n
}

func (c Config) dialTCP(ctx context.Context, ep Endpoint) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, c.connectTimeout())
	defer cancel()
	if c.DialContext != nil {
		return c.DialContext(ctx, "tcp", ep.Address())
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", ep.Address())
}

// Target is a host to connect to.
type Target struct {
	HostID    string
	Endpoints []Endpoint // in the admin's order; never reordered
	User      string
	HostKey   ssh.PublicKey // the pin; required
}

// Client is an authenticated connection with keepalive running.
type Client struct {
	*ssh.Client
	Endpoint Endpoint
	Attempts []Attempt // failed attempts on earlier endpoints
	stop     chan struct{}
}

// Close stops the keepalive and closes the connection.
func (c *Client) Close() error {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	return c.Client.Close()
}

var (
	errHostKeyMismatch = errors.New("host key does not match the pinned key")
	errProbeDone       = errors.New("probe: host key read")
)

// handshakeState is filled in by the host key callback.
type handshakeState struct {
	keyAccepted bool
	mismatch    bool
	presented   ssh.PublicKey
}

// Dial connects to t with signer, trying the endpoints in order under the
// rules in the package comment. Only signer is offered (IdentitiesOnly).
func (c Config) Dial(ctx context.Context, t Target, signer ssh.Signer) (*Client, error) {
	if t.HostKey == nil {
		return nil, &Error{Class: ClassInvalid, Detail: "host " + t.HostID + " has no pinned key; enroll it first"}
	}
	if err := CheckHostKey(t.HostKey); err != nil {
		return nil, &Error{Class: ClassInvalid, Detail: err.Error()}
	}
	if len(t.Endpoints) == 0 || len(t.Endpoints) > MaxEndpoints {
		return nil, &Error{Class: ClassInvalid, Detail: fmt.Sprintf("need 1..%d endpoints", MaxEndpoints)}
	}
	if t.User == "" || signer == nil {
		return nil, &Error{Class: ClassInvalid, Detail: "user and signer are required"}
	}
	pin := t.HostKey.Marshal()
	var attempts []Attempt
	handshakeRetried := false
	for _, ep := range t.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, &Error{Class: ClassCanceled, Attempts: attempts, Detail: err.Error()}
		}
		conn, err := c.dialTCP(ctx, ep)
		if err != nil {
			attempts = append(attempts, Attempt{Endpoint: ep, Stage: StageTCP, Err: err})
			continue
		}
		st := &handshakeState{}
		cfg := &ssh.ClientConfig{
			User: t.User,
			Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				st.presented = key
				if string(key.Marshal()) != string(pin) {
					st.mismatch = true
					return errHostKeyMismatch
				}
				st.keyAccepted = true
				return nil
			},
			HostKeyAlgorithms: pinnedAlgorithms(t.HostKey),
			// The banner is untrusted host data and is never shown.
			BannerCallback: func(string) error { return nil },
		}
		sc, err := c.handshake(ctx, conn, ep, cfg)
		if err == nil {
			cl := &Client{Client: sc, Endpoint: ep, Attempts: attempts, stop: make(chan struct{})}
			iv, n := c.keepalive()
			go keepalive(cl, iv, n)
			return cl, nil
		}
		switch {
		case ctx.Err() != nil:
			return nil, &Error{Class: ClassCanceled, Attempts: append(attempts, Attempt{Endpoint: ep, Stage: StageHandshake, Err: err}), Detail: ctx.Err().Error()}
		case st.mismatch:
			return nil, &Error{Class: ClassHostKeyMismatch, Presented: st.presented,
				Attempts: append(attempts, Attempt{Endpoint: ep, Stage: StageHostKey, Err: err}),
				Detail:   fmt.Sprintf("%s presented %s, pinned %s", ep, Fingerprint(st.presented), Fingerprint(t.HostKey))}
		case st.keyAccepted:
			return nil, &Error{Class: ClassAuth, Attempts: append(attempts, Attempt{Endpoint: ep, Stage: StageAuth, Err: err}),
				Detail: "authentication failed on " + ep.String() + "; no other endpoint tried"}
		case noCommonHostKeyAlgorithm(err):
			// The host offers no key of the pinned type: as serious as a
			// different key (a downgrade or a replaced host).
			return nil, &Error{Class: ClassHostKeyMismatch,
				Attempts: append(attempts, Attempt{Endpoint: ep, Stage: StageHostKey, Err: err}),
				Detail:   fmt.Sprintf("%s offers no %s host key", ep, t.HostKey.Type())}
		default:
			attempts = append(attempts, Attempt{Endpoint: ep, Stage: StageHandshake, Err: err})
			if handshakeRetried {
				return nil, &Error{Class: ClassUnreachable, Attempts: attempts, Detail: "second handshake failure"}
			}
			handshakeRetried = true
		}
	}
	return nil, &Error{Class: ClassUnreachable, Attempts: attempts}
}

// noCommonHostKeyAlgorithm recognizes the negotiation failure for the host
// key algorithm: the host offers no key of the pinned type.
func noCommonHostKeyAlgorithm(err error) bool {
	var ne *ssh.AlgorithmNegotiationError
	if errors.As(err, &ne) {
		return ne.What == "host key"
	}
	return err != nil && strings.Contains(err.Error(), "no common algorithm for host key")
}

// handshake runs the SSH handshake on conn within the connect timeout. On
// error conn is closed.
func (c Config) handshake(ctx context.Context, conn net.Conn, ep Endpoint, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(c.connectTimeout())); err != nil {
		conn.Close()
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, ep.Address(), cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		sc.Close()
		return nil, err
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// keepalive sends keepalive@openssh.com every interval and closes the
// connection after max consecutive intervals without a reply. Any reply,
// including a failure reply, counts.
func keepalive(c *Client, interval time.Duration, max int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	missed := 0
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
		reply := make(chan error, 1)
		go func() {
			_, _, err := c.Client.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		select {
		case <-c.stop:
			return
		case err := <-reply:
			if err != nil {
				c.Client.Close()
				return
			}
			missed = 0
		case <-time.After(interval):
			missed++
			if missed >= max {
				c.Client.Close()
				return
			}
		}
	}
}

// Probe reads the host key of one endpoint for enrollment. It aborts the
// handshake as soon as the key is known, so no user name and no credential
// is ever sent. The key is checked with CheckHostKey.
func (c Config) Probe(ctx context.Context, ep Endpoint) (ssh.PublicKey, error) {
	return c.probe(ctx, ep, preferredAlgorithms)
}

// ProbeAs is Probe offering only the key type of like, the way a pinned
// host is connected: a host's new key of the pinned type is what a
// mismatch block records, whatever other key types the host has.
func (c Config) ProbeAs(ctx context.Context, ep Endpoint, like ssh.PublicKey) (ssh.PublicKey, error) {
	return c.probe(ctx, ep, pinnedAlgorithms(like))
}

func (c Config) probe(ctx context.Context, ep Endpoint, algorithms []string) (ssh.PublicKey, error) {
	conn, err := c.dialTCP(ctx, ep)
	if err != nil {
		return nil, &Error{Class: ClassUnreachable, Attempts: []Attempt{{Endpoint: ep, Stage: StageTCP, Err: err}}}
	}
	var key ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "nebula-probe", // never sent: the handshake stops before authentication
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errProbeDone
		},
		HostKeyAlgorithms: algorithms,
	}
	_, err = c.handshake(ctx, conn, ep, cfg)
	if key == nil {
		if ctx.Err() != nil {
			return nil, &Error{Class: ClassCanceled, Detail: ctx.Err().Error()}
		}
		return nil, &Error{Class: ClassUnreachable, Attempts: []Attempt{{Endpoint: ep, Stage: StageHandshake, Err: err}}}
	}
	if err := CheckHostKey(key); err != nil {
		return nil, &Error{Class: ClassInvalid, Detail: err.Error()}
	}
	return key, nil
}
