// SPDX-License-Identifier: AGPL-3.0-or-later

package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
)

// Fixture addresses (EN-09): the peer P is the loopback address the test
// client connects from; T2 is a second trusted proxy used only inside
// headers; A is the named client, C the address an appending proxy adds.
const (
	addrP  = "127.0.0.1"
	addrT2 = "192.0.2.250"
	addrA  = "192.0.2.10"
	addrC  = "203.0.113.20"
)

// call is one recorded executor call.
type call struct{ id, client, peer string }

// stubExecutor releases each open offer once and records every call.
type stubExecutor struct {
	mu     sync.Mutex
	open   map[string][]byte
	calls  []call
	err    error // returned for every call when set
	badSum bool  // return a wrong hash
	n      uint64
}

func newStub() *stubExecutor { return &stubExecutor{open: map[string][]byte{}} }

// offer creates a fresh open offer and returns its ID.
func (s *stubExecutor) offer() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	var raw [20]byte
	binary.BigEndian.PutUint64(raw[12:], s.n)
	copy(raw[:4], "offr")
	id := strings.ToLower(base32.StdEncoding.EncodeToString(raw[:]))
	s.open[id] = []byte("#!/bin/sh\n# offer " + id[len(id)-6:] + "\nexit 0\n")
	return id
}

func (s *stubExecutor) FetchEnrollScript(_ context.Context, in *executorv1.FetchEnrollScriptRequest, _ ...grpc.CallOption) (*executorv1.FetchEnrollScriptResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call{in.GetOfferId(), in.GetClientAddr(), in.GetPeerAddr()})
	if s.err != nil {
		return nil, s.err
	}
	b, ok := s.open[in.GetOfferId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "enrollment offer not available")
	}
	delete(s.open, in.GetOfferId())
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	if s.badSum {
		h = strings.Repeat("0", 64)
	}
	return &executorv1.FetchEnrollScriptResponse{Script: append([]byte(nil), b...), ScriptSha256: h}, nil
}

func (s *stubExecutor) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stubExecutor) lastCall() call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

// fixedClock is an injected clock that only moves when told to.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClock() *fixedClock { return &fixedClock{t: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)} }

// syncBuffer is a log sink safe for the server goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// server is a loopback test server around one handler.
type server struct {
	h   *Handler
	srv *httptest.Server
}

func newServer(t *testing.T, cfg clientaddr.Config, ex Executor, l *Limiter, log *slog.Logger) *server {
	t.Helper()
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	res, err := clientaddr.New(cfg, log)
	if err != nil {
		t.Fatalf("clientaddr.New: %v", err)
	}
	h, err := New(Options{Executor: ex, ClientAddr: res, Limiter: l, Log: log})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(PathPrefix, h)
	srv := httptest.NewServer(mux) // listens on 127.0.0.1 only
	t.Cleanup(srv.Close)
	return &server{h: h, srv: srv}
}

// response is what a test checks of an answer.
type response struct {
	code   int
	header http.Header
	body   []byte
}

func (s *server) get(t *testing.T, path string, xff ...string) response {
	t.Helper()
	return s.do(t, http.MethodGet, path, xff...)
}

func (s *server) do(t *testing.T, method, path string, xff ...string) response {
	t.Helper()
	req, err := http.NewRequest(method, s.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	resp, err := s.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	h := resp.Header.Clone()
	h.Del("Date")
	return response{resp.StatusCode, h, b}
}

// wantHeaders are the download headers present on 200 and every 404.
var wantHeaders = map[string]string{
	"Content-Type":            "text/plain; charset=utf-8",
	"Content-Disposition":     `attachment; filename="nebula-enroll.sh"`,
	"Cache-Control":           "no-store",
	"X-Content-Type-Options":  "nosniff",
	"Content-Security-Policy": "default-src 'none'; sandbox",
	"X-Accel-Buffering":       "no",
}

func checkHeaders(t *testing.T, r response) {
	t.Helper()
	for k, v := range wantHeaders {
		if got := r.header.Values(k); len(got) != 1 || got[0] != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
}

// reference404 is the uniform refusal every 404 must equal.
var reference404 = response{
	code: http.StatusNotFound,
	header: http.Header{
		"Content-Type":            {"text/plain; charset=utf-8"},
		"Content-Disposition":     {`attachment; filename="nebula-enroll.sh"`},
		"Cache-Control":           {"no-store"},
		"X-Content-Type-Options":  {"nosniff"},
		"Content-Security-Policy": {"default-src 'none'; sandbox"},
		"X-Accel-Buffering":       {"no"},
		"Content-Length":          {"10"},
	},
	body: []byte("not found\n"),
}

func assertUniform404(t *testing.T, r response) {
	t.Helper()
	if r.code != reference404.code || !bytes.Equal(r.body, reference404.body) {
		t.Fatalf("got %d %q, want uniform 404", r.code, r.body)
	}
	if len(r.header) != len(reference404.header) {
		t.Fatalf("headers %v, want %v", r.header, reference404.header)
	}
	for k, v := range reference404.header {
		if got := r.header.Values(k); len(got) != 1 || got[0] != v[0] {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
}

func assert200(t *testing.T, r response) {
	t.Helper()
	if r.code != http.StatusOK {
		t.Fatalf("code = %d, body %q", r.code, r.body)
	}
	checkHeaders(t, r)
}

func trustedP() clientaddr.Config {
	return clientaddr.Config{TrustedProxies: []string{addrP}}
}

func TestDownloadHeadersOn200And404(t *testing.T) {
	ex := newStub()
	s := newServer(t, clientaddr.Config{}, ex, NewLimiter(0, newClock().now), nil)
	id := ex.offer()
	want := append([]byte(nil), ex.open[id]...)
	r := s.get(t, PathPrefix+id)
	assert200(t, r)
	if !bytes.Equal(r.body, want) {
		t.Fatalf("body = %q", r.body)
	}
	assertUniform404(t, s.get(t, PathPrefix+ex.offer()[:31]+"a"))
}

func TestSecondDownloadRefused(t *testing.T) {
	ex := newStub()
	s := newServer(t, clientaddr.Config{}, ex, NewLimiter(0, newClock().now), nil)
	id := ex.offer()
	assert200(t, s.get(t, PathPrefix+id))
	assertUniform404(t, s.get(t, PathPrefix+id))
}

func TestHeadDoesNotConsume(t *testing.T) {
	ex := newStub()
	s := newServer(t, clientaddr.Config{}, ex, NewLimiter(0, newClock().now), nil)
	id := ex.offer()
	r := s.do(t, http.MethodHead, PathPrefix+id)
	if r.code != http.StatusNotFound {
		t.Fatalf("HEAD code = %d", r.code)
	}
	if ex.callCount() != 0 {
		t.Fatal("HEAD called the executor")
	}
	assert200(t, s.get(t, PathPrefix+id))
}

// TestUniform404ForEveryRefusal covers unknown, consumed (expired, revoked
// and failed offers are the same NotFound from the executor), malformed,
// executor failures, a bad hash, rate-limited and a refused forwarded
// header: all equal the reference 404.
func TestUniform404ForEveryRefusal(t *testing.T) {
	ex := newStub()
	clock := newClock()
	s := newServer(t, trustedP(), ex, NewLimiter(0, clock.now), nil)
	refusals := map[string]func() response{
		"unknown": func() response { return s.get(t, PathPrefix+strings.Repeat("a", 32), addrA) },
		"consumed": func() response {
			id := ex.offer()
			assert200(t, s.get(t, PathPrefix+id, addrA))
			return s.get(t, PathPrefix+id, addrA)
		},
		"malformed short":     func() response { return s.get(t, PathPrefix+"abc", addrA) },
		"malformed uppercase": func() response { return s.get(t, PathPrefix+strings.ToUpper(ex.offer()), addrA) },
		"malformed digit":     func() response { return s.get(t, PathPrefix+strings.Repeat("1", 32), addrA) },
		"malformed padding":   func() response { return s.get(t, PathPrefix+strings.Repeat("a", 31)+"=", addrA) },
		"malformed subpath":   func() response { return s.get(t, PathPrefix+ex.offer()+"/x", addrA) },
		"empty id":            func() response { return s.get(t, PathPrefix, addrA) },
		"refused header":      func() response { return s.get(t, PathPrefix+ex.offer(), "not-an-ip") },
		"executor unavailable": func() response {
			ex.mu.Lock()
			ex.err = status.Error(codes.Unavailable, "down")
			ex.mu.Unlock()
			defer func() { ex.mu.Lock(); ex.err = nil; ex.mu.Unlock() }()
			return s.get(t, PathPrefix+ex.offer(), addrA)
		},
		"executor refused": func() response {
			ex.mu.Lock()
			ex.err = status.Error(codes.FailedPrecondition, "no")
			ex.mu.Unlock()
			defer func() { ex.mu.Lock(); ex.err = nil; ex.mu.Unlock() }()
			return s.get(t, PathPrefix+ex.offer(), addrA)
		},
		"hash mismatch": func() response {
			ex.mu.Lock()
			ex.badSum = true
			ex.mu.Unlock()
			defer func() { ex.mu.Lock(); ex.badSum = false; ex.mu.Unlock() }()
			return s.get(t, PathPrefix+ex.offer(), addrA)
		},
	}
	for name, f := range refusals {
		// A fresh hour per refusal, so the rate limit does not interfere.
		clock.add(time.Hour + time.Minute)
		t.Run(name, func(t *testing.T) { assertUniform404(t, f()) })
	}
	clock.add(time.Hour + time.Minute)
	// Rate limited: exhaust one client's minute, then the next is refused.
	for i := 0; i < PerMinute; i++ {
		assert200(t, s.get(t, PathPrefix+ex.offer(), "198.51.100.77"))
	}
	assertUniform404(t, s.get(t, PathPrefix+ex.offer(), "198.51.100.77"))
}

func TestPathNeverLogged(t *testing.T) {
	ex := newStub()
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := newServer(t, trustedP(), ex, NewLimiter(0, newClock().now), log)
	ids := []string{ex.offer(), ex.offer(), strings.Repeat("q", 32)}
	assert200(t, s.get(t, PathPrefix+ids[0], addrA))
	s.get(t, PathPrefix+ids[0], addrA)
	s.get(t, PathPrefix+ids[1], "garbage")
	s.get(t, PathPrefix+ids[2])
	ex.mu.Lock()
	ex.err = status.Error(codes.Internal, "boom")
	ex.mu.Unlock()
	s.get(t, PathPrefix+ids[1], addrA)
	for i := 0; i < PerMinute+1; i++ {
		s.get(t, PathPrefix+ids[2], addrC)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("expected some log lines")
	}
	for _, id := range ids {
		if strings.Contains(out, id) {
			t.Fatalf("offer ID logged: %q", out)
		}
	}
	if strings.Contains(out, "/enroll") {
		t.Fatalf("path logged: %q", out)
	}
}

func TestAuditCarriesForwardedClientAndPeer(t *testing.T) {
	ex := newStub()
	var buf syncBuffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	s := newServer(t, trustedP(), ex, NewLimiter(0, newClock().now), log)
	assert200(t, s.get(t, PathPrefix+ex.offer(), "198.51.100.3, "+addrA))
	if c := ex.lastCall(); c.client != addrA || c.peer != addrP {
		t.Fatalf("executor got %+v", c)
	}
	out := buf.String()
	for _, want := range []string{`"msg":"audit"`, `"kind":"enroll_script_downloaded"`, `"client":"192.0.2.10"`, `"peer":"127.0.0.1"`, `"forwarded":true`} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit %q lacks %s", out, want)
		}
	}
}

func TestForgedHeaderFromUntrustedPeerIgnored(t *testing.T) {
	ex := newStub()
	var buf syncBuffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	s := newServer(t, clientaddr.Config{TrustedProxies: []string{"10.0.0.5"}}, ex, NewLimiter(0, newClock().now), log)
	for i := 0; i < PerMinute; i++ {
		// A different forged client every time cannot open new buckets.
		forged := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}).String()
		assert200(t, s.get(t, PathPrefix+ex.offer(), forged))
		if c := ex.lastCall(); c.client != addrP || c.peer != addrP {
			t.Fatalf("executor got %+v", c)
		}
	}
	assertUniform404(t, s.get(t, PathPrefix+ex.offer(), "192.0.2.99"))
	if strings.Contains(buf.String(), "192.0.2.") {
		t.Fatalf("forged address reached the log: %q", buf.String())
	}
	if !strings.Contains(buf.String(), `"forwarded":false`) {
		t.Fatalf("audit %q", buf.String())
	}
}

func TestForwardedClientsGetSeparateBuckets(t *testing.T) {
	ex := newStub()
	l := NewLimiter(0, newClock().now)
	s := newServer(t, trustedP(), ex, l, nil)
	for i := 0; i < PerMinute; i++ {
		assert200(t, s.get(t, PathPrefix+ex.offer(), addrA))
	}
	assertUniform404(t, s.get(t, PathPrefix+ex.offer(), addrA))
	for i := 0; i < PerMinute; i++ {
		assert200(t, s.get(t, PathPrefix+ex.offer(), addrC))
	}
	assertUniform404(t, s.get(t, PathPrefix+ex.offer(), addrC))
	if l.size() != 2 {
		t.Fatalf("buckets = %d, want 2", l.size())
	}
}

func TestMinuteAndHourLimits(t *testing.T) {
	ex := newStub()
	clock := newClock()
	s := newServer(t, clientaddr.Config{}, ex, NewLimiter(0, clock.now), nil)
	for i := 0; i < PerMinute; i++ {
		assert200(t, s.get(t, PathPrefix+ex.offer()))
	}
	fresh := ex.offer()
	assertUniform404(t, s.get(t, PathPrefix+fresh)) // 11th in the minute
	clock.add(time.Minute)
	assert200(t, s.get(t, PathPrefix+fresh)) // not consumed by the refusal
	for i := 1; i < PerHour-PerMinute; i++ {
		if i%PerMinute == 0 {
			clock.add(time.Minute)
		}
		assert200(t, s.get(t, PathPrefix+ex.offer()))
	}
	clock.add(time.Minute)
	assertUniform404(t, s.get(t, PathPrefix+ex.offer())) // 61st in the hour
	clock.add(time.Hour)
	assert200(t, s.get(t, PathPrefix+ex.offer()))
}

func TestLimiterIPv6Per64AndMappedIPv4(t *testing.T) {
	l := NewLimiter(0, newClock().now)
	charge := func(s string, n int) int {
		ok := 0
		for i := 0; i < n; i++ {
			a, err := clientaddr.Normalize(s)
			if err != nil {
				t.Fatal(err)
			}
			if l.Charge(a) {
				ok++
			}
		}
		return ok
	}
	if got := charge("2001:db8:1:2::1", 6) + charge("2001:db8:1:2:ffff::9", 6); got != PerMinute {
		t.Fatalf("same /64 allowed %d, want %d", got, PerMinute)
	}
	if got := charge("2001:db8:1:3::1", PerMinute); got != PerMinute {
		t.Fatalf("other /64 allowed %d", got)
	}
	if got := charge("192.0.2.7", 6) + charge("::ffff:192.0.2.7", 6); got != PerMinute {
		t.Fatalf("mapped IPv4 allowed %d, want shared bucket", got)
	}
	if l.size() != 3 {
		t.Fatalf("buckets = %d, want 3", l.size())
	}
}

func TestLimiterTableBoundedLRU(t *testing.T) {
	const size = 4
	l := NewLimiter(size, newClock().now)
	first := netip.MustParseAddr("2001:db8:0:1::1")
	for i := 0; i < PerMinute; i++ {
		if !l.Charge(first) {
			t.Fatal("refused")
		}
	}
	if l.Charge(first) {
		t.Fatal("limit not enforced")
	}
	for i := 2; i < 50; i++ {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, byte(i), 15: 1})
		if !l.Charge(a) {
			t.Fatalf("request %d refused because the table is full", i)
		}
		if l.size() > size {
			t.Fatalf("table grew to %d", l.size())
		}
	}
	if l.size() != size {
		t.Fatalf("size = %d", l.size())
	}
	// The first bucket was evicted: its counters restart (fail open).
	if !l.Charge(first) {
		t.Fatal("evicted bucket still limited")
	}
	// The most recently used bucket survives eviction by newer ones.
	recent := netip.MustParseAddr("2001:db8:0:aa::1")
	for i := 0; i < PerMinute; i++ {
		l.Charge(recent)
	}
	for i := 0; i < size-1; i++ {
		l.Charge(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 1, byte(i), 15: 1}))
		l.Charge(recent) // keep it most recently used
	}
	if l.Charge(recent) {
		t.Fatal("recently used bucket was evicted")
	}
}

func TestNewRequiresOptions(t *testing.T) {
	res, err := clientaddr.New(clientaddr.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []Options{
		{ClientAddr: res, Limiter: NewLimiter(0, nil)},
		{Executor: newStub(), Limiter: NewLimiter(0, nil)},
		{Executor: newStub(), ClientAddr: res},
	} {
		if _, err := New(o); !errors.Is(err, errMissingOption) {
			t.Fatalf("New(%+v) err = %v", o, err)
		}
	}
}
