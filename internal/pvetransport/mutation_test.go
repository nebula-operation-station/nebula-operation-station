// SPDX-License-Identifier: AGPL-3.0-or-later

package pvetransport

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newMutationRequest builds a request the way pveapi.Writer does: a form
// body from strings.NewReader, so net/http sets GetBody and the body could
// be replayed.
func newMutationRequest(t *testing.T, method, rawURL string, withBody bool) *http.Request {
	t.Helper()
	var body io.Reader
	if withBody {
		body = strings.NewReader("timeout=30")
	}
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	if withBody && req.GetBody == nil {
		t.Fatal("test precondition: GetBody must be set")
	}
	return req
}

// TestMutationTimeoutAfterSendNeverFailsOver: a timeout after the request
// reached an endpoint must never resend it to the next endpoint (ADR 0008:
// nothing is ever redispatched blindly), even though the body is replayable.
func TestMutationTimeoutAfterSendNeverFailsOver(t *testing.T) {
	for _, tc := range []struct {
		method   string
		withBody bool
	}{
		{http.MethodPost, true},
		{http.MethodPost, false},
		{http.MethodPut, true},
		{http.MethodDelete, false},
	} {
		t.Run(tc.method, func(t *testing.T) {
			ca := newTestCA(t, "pve-root-ca")
			var slowHits, fastHits atomic.Int64
			release := make(chan struct{})
			slow := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				slowHits.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			fast := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fastHits.Add(1)
			}))
			// Registered after the servers, so it runs before their Close.
			t.Cleanup(func() { close(release) })
			client := newTestClient(t, Options{
				Trust:     Trust{CA: ca.cert},
				Endpoints: []*url.URL{mustParseURL(t, slow.URL), mustParseURL(t, fast.URL)},
				Timeout:   300 * time.Millisecond,
			})
			resp, err := client.Do(newMutationRequest(t, tc.method, slow.URL+"/api2/json/nodes/pve1/qemu/100/status/stop", tc.withBody))
			if err == nil {
				resp.Body.Close()
				t.Fatal("mutation succeeded after a timeout; want an error")
			}
			if !errors.Is(err, ErrMaybeSent) {
				t.Fatalf("err = %v, want ErrMaybeSent", err)
			}
			if got := slowHits.Load(); got != 1 {
				t.Fatalf("first endpoint hits = %d, want 1", got)
			}
			if got := fastHits.Load(); got != 0 {
				t.Fatalf("second endpoint hits = %d, want 0: the mutation was resent", got)
			}
		})
	}
}

// TestMutationConnectionLostAfterSendNeverFailsOver: a connection the
// endpoint drops after reading the request is not failed over either.
func TestMutationConnectionLostAfterSendNeverFailsOver(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	var dropHits, fastHits atomic.Int64
	drop := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dropHits.Add(1)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no hijacker")
			return
		}
		c, _, err := hj.Hijack()
		if err == nil {
			c.Close()
		}
	}))
	fast := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fastHits.Add(1)
	}))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, drop.URL), mustParseURL(t, fast.URL)},
		Timeout:   5 * time.Second,
	})
	resp, err := client.Do(newMutationRequest(t, http.MethodPost, drop.URL+"/api2/json/nodes/pve1/qemu/100/status/stop", true))
	if err == nil {
		resp.Body.Close()
		t.Fatal("mutation succeeded on a dropped connection")
	}
	if !errors.Is(err, ErrMaybeSent) {
		t.Fatalf("err = %v, want ErrMaybeSent", err)
	}
	if dropHits.Load() != 1 || fastHits.Load() != 0 {
		t.Fatalf("hits = %d/%d, want 1/0", dropHits.Load(), fastHits.Load())
	}
}

// TestMutationResetAfterSendNeverFailsOver: a TCP reset after the endpoint
// read the request is a net.Error, the kind of failure reads fail over
// on; a mutation is still not resent.
func TestMutationResetAfterSendNeverFailsOver(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	var dropHits, fastHits atomic.Int64
	drop := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dropHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if tc, ok := c.(*tls.Conn); ok {
			if tcp, ok := tc.NetConn().(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
		}
		c.Close()
	}))
	fast := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fastHits.Add(1)
	}))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, drop.URL), mustParseURL(t, fast.URL)},
		Timeout:   5 * time.Second,
	})
	resp, err := client.Do(newMutationRequest(t, http.MethodPost, drop.URL+"/api2/json/nodes/pve1/qemu/100/status/stop", true))
	if err == nil {
		resp.Body.Close()
		t.Fatal("mutation succeeded on a reset connection")
	}
	if !errors.Is(err, ErrMaybeSent) {
		t.Fatalf("err = %v, want ErrMaybeSent", err)
	}
	if dropHits.Load() != 1 || fastHits.Load() != 0 {
		t.Fatalf("hits = %d/%d, want 1/0", dropHits.Load(), fastHits.Load())
	}
}

// TestMutationDialFailureFailsOver: an endpoint that cannot be connected
// to received nothing, so a mutation still fails over, exactly once.
func TestMutationDialFailureFailsOver(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	var hits atomic.Int64
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		if string(b) != "timeout=30" {
			t.Errorf("body = %q", b)
		}
	}))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, deadEndpoint(t)), mustParseURL(t, srv.URL)},
		Timeout:   5 * time.Second,
	})
	resp, err := client.Do(newMutationRequest(t, http.MethodPost, srv.URL+"/api2/json/nodes/pve1/qemu/100/status/shutdown", true))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
}

// TestMutationTrustMismatchIsNotMaySent: a trust failure happens in the
// handshake, before any request byte, so it is never reported as possibly
// sent.
func TestMutationTrustMismatchIsNotMaySent(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	other := newTestCA(t, "other-ca")
	var hits atomic.Int64
	srv := newTLSServer(t, other.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
	})
	resp, err := client.Do(newMutationRequest(t, http.MethodPost, srv.URL+"/x", true))
	if err == nil {
		resp.Body.Close()
		t.Fatal("want trust failure")
	}
	if !errors.Is(err, ErrTrustMismatch) || errors.Is(err, ErrMaybeSent) || hits.Load() != 0 {
		t.Fatalf("err = %v hits = %d", err, hits.Load())
	}
}

// TestReadTimeoutStillFailsOver keeps the read failover of ADR 0006.
func TestReadTimeoutStillFailsOver(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	release := make(chan struct{})
	slow := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	var hits atomic.Int64
	fast := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(func() { close(release) })
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, slow.URL), mustParseURL(t, fast.URL)},
		Timeout:   300 * time.Millisecond,
	})
	resp, err := client.Get(slow.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
}

// TestMutationRedirectIsMaybeSentNeverFailsOver: an endpoint that answers
// a mutation with a 3xx received it, so the answer is ErrMaybeSent (the
// writer then reports an unknown outcome, never "not sent") and the
// mutation goes neither to the redirect target nor to the next endpoint.
// A read gets a plain ErrRedirect.
func TestMutationRedirectIsMaybeSentNeverFailsOver(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	var redirectHits, fastHits atomic.Int64
	fast := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fastHits.Add(1)
	}))
	redirect := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHits.Add(1)
		http.Redirect(w, r, fast.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, redirect.URL), mustParseURL(t, fast.URL)},
		Timeout:   5 * time.Second,
	})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		resp, err := client.Do(newMutationRequest(t, method, redirect.URL+"/api2/json/nodes/pve1/qemu/100/status/stop", method != http.MethodDelete))
		if err == nil {
			resp.Body.Close()
			t.Fatalf("%s: redirected mutation succeeded", method)
		}
		if !errors.Is(err, ErrMaybeSent) || !errors.Is(err, ErrRedirect) {
			t.Fatalf("%s: err = %v, want ErrMaybeSent and ErrRedirect", method, err)
		}
	}
	if redirectHits.Load() != 3 || fastHits.Load() != 0 {
		t.Fatalf("hits = %d/%d, want 3/0", redirectHits.Load(), fastHits.Load())
	}
	resp, err := client.Get(redirect.URL + "/api2/json/nodes")
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirected read succeeded")
	}
	if !errors.Is(err, ErrRedirect) || errors.Is(err, ErrMaybeSent) {
		t.Fatalf("read: err = %v, want ErrRedirect only", err)
	}
	if fastHits.Load() != 0 {
		t.Fatalf("read followed the redirect: %d", fastHits.Load())
	}
}
