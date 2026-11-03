// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestBuiltinTrustBannerTrustedHidesBanner(t *testing.T) {
	st := &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			{Name: "core", TrustedVersion: "1.0.0", TrustedSha256: "aa", ReleaseVersion: "1.0.0", ReleaseSha256: "aa"},
		},
	}
	if v := builtinTrustBanner(st); v != nil {
		t.Fatalf("trusted state: banner %+v, want nil", v)
	}
}

func TestBuiltinTrustBannerFailsClosed(t *testing.T) {
	for name, st := range map[string]*pb.GetBuiltinTrustStatusResponse{
		"unspecified":  {},
		"nil response": nil,
		"unknown enum": {State: pb.BuiltinTrustState(9999)},
		"unavailable":  {State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE},
	} {
		v := builtinTrustBanner(st)
		if v == nil || v.Kind != unavailableBuiltinTrust().Kind {
			t.Errorf("%s: banner %+v, want the unavailable banner", name, v)
		}
	}
}

func TestBuiltinTrustBannerUntrustedListsAffectedVersions(t *testing.T) {
	st := &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			// New module: nothing trusted yet.
			{Name: "netprobe", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_NEW, ReleaseVersion: "2.1.0", ReleaseSha256: "bb"},
			// Changed: a different version is trusted.
			{Name: "core", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED, TrustedVersion: "1.0.0", TrustedSha256: "aa", ReleaseVersion: "1.1.0", ReleaseSha256: "cc"},
			// Unchanged: this exact version is trusted.
			{Name: "facts", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_UNCHANGED, TrustedVersion: "3.0.0", TrustedSha256: "dd", ReleaseVersion: "3.0.0", ReleaseSha256: "dd"},
			// Removed from the release: affected, with its own wording.
			{Name: "oldmod", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_REMOVED, TrustedVersion: "0.9.0", TrustedSha256: "ee"},
		},
	}
	v := builtinTrustBanner(st)
	if v == nil {
		t.Fatal("untrusted state: banner nil, want non-nil")
	}
	if v.Kind != "untrusted" {
		t.Errorf("Kind %q, want untrusted", v.Kind)
	}
	if v.Command != "nebula artifact trust-builtins" {
		t.Errorf("Command %q, want the local CLI command", v.Command)
	}
	if v.Headline == "" {
		t.Error("headline empty")
	}
	// Lease-replacement guidance (ADR 0007 E17).
	if !strings.Contains(v.Detail, "lease") {
		t.Errorf("Detail %q does not explain lease replacement", v.Detail)
	}
	want := []builtinTrustEntryView{
		{Name: "netprobe", Version: "2.1.0"},
		{Name: "core", Version: "1.1.0", Trusted: "1.0.0"},
		{Name: "oldmod", Trusted: "0.9.0", Removed: true},
	}
	if len(v.Affected) != len(want) {
		t.Fatalf("Affected %v, want %v", v.Affected, want)
	}
	for i := range want {
		if v.Affected[i] != want[i] {
			t.Errorf("Affected[%d] %+v, want %+v", i, v.Affected[i], want[i])
		}
	}
}

func TestBuiltinTrustBannerUnavailableIsDistinct(t *testing.T) {
	untrusted := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
	})
	v := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE,
	})
	if v == nil {
		t.Fatal("unavailable state: banner nil, want non-nil")
	}
	if v.Kind != "unavailable" {
		t.Errorf("Kind %q, want unavailable", v.Kind)
	}
	if v.Command != "" || len(v.Affected) != 0 {
		t.Errorf("unavailable banner must name no command or versions, got %+v", v)
	}
	if v.Headline == untrusted.Headline {
		t.Error("unavailable and untrusted banners share the same headline")
	}
	// Unreachable is not a trust verdict.
	if strings.Contains(v.Headline, "untrusted") || strings.Contains(v.Detail, "untrusted") {
		t.Errorf("unavailable banner claims the built-ins are untrusted: %+v", v)
	}
}

// The executor's per-module verdict decides what is affected: a module
// marked CHANGED with identical versions and hashes (retained bytes
// missing or corrupt) must be listed, not re-derived away as trusted.
func TestBuiltinTrustBannerListsChangedWithIdenticalHashes(t *testing.T) {
	v := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			{Name: "core", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED, TrustedVersion: "1.0.0", TrustedSha256: "aa", ReleaseVersion: "1.0.0", ReleaseSha256: "aa"},
		},
	})
	want := builtinTrustEntryView{Name: "core", Version: "1.0.0", Trusted: "1.0.0"}
	if v == nil || len(v.Affected) != 1 || v.Affected[0] != want {
		t.Fatalf("banner %+v, want Affected [%+v]", v, want)
	}
}

// A REMOVED module alone makes the executor report UNTRUSTED; the
// banner must name it rather than show an empty affected list.
func TestBuiltinTrustBannerListsRemovedOnly(t *testing.T) {
	v := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			{Name: "oldmod", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_REMOVED, TrustedVersion: "0.9.0", TrustedSha256: "ee"},
		},
	})
	want := builtinTrustEntryView{Name: "oldmod", Trusted: "0.9.0", Removed: true}
	if v == nil || len(v.Affected) != 1 || v.Affected[0] != want {
		t.Fatalf("banner %+v, want Affected [%+v]", v, want)
	}
}

// countingTrust counts RPCs; block, when non-nil, holds each call until
// it is closed.
type countingTrust struct {
	calls atomic.Int32
	mu    sync.Mutex
	resp  *pb.GetBuiltinTrustStatusResponse
	err   error
	block chan struct{}
}

func (f *countingTrust) set(resp *pb.GetBuiltinTrustStatusResponse, err error, block chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp, f.err, f.block = resp, err, block
}

func (f *countingTrust) GetBuiltinTrustStatus(ctx context.Context, in *pb.GetBuiltinTrustStatusRequest, opts ...grpc.CallOption) (*pb.GetBuiltinTrustStatusResponse, error) {
	f.calls.Add(1)
	f.mu.Lock()
	resp, err, block := f.resp, f.err, f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return resp, err
}

// fakeClock is a settable clock for the cache.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testTrustCache(p BuiltinTrustProvider, clk *fakeClock, log *slog.Logger) *builtinTrustCache {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c := newBuiltinTrustCache(p, clk.now, log)
	c.wait = 2 * time.Second // generous: the fakes answer at once
	return c
}

var (
	trustedStatus   = &pb.GetBuiltinTrustStatusResponse{State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED}
	untrustedStatus = &pb.GetBuiltinTrustStatusResponse{State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED}
)

func TestBuiltinTrustCacheNoRPCWithinTTL(t *testing.T) {
	p := &countingTrust{resp: untrustedStatus}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := testTrustCache(p, clk, nil)
	for range 5 {
		if v := c.get(context.Background()); v == nil || v.Kind != "untrusted" {
			t.Fatalf("banner %+v, want untrusted", v)
		}
		clk.advance(builtinTrustTTL / 10)
	}
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("%d RPCs within the TTL, want 1", n)
	}
	clk.advance(builtinTrustTTL)
	c.get(context.Background())
	if n := p.calls.Load(); n != 2 {
		t.Fatalf("%d RPCs after the TTL expired, want 2", n)
	}
}

// A cached TRUSTED verdict that has expired is stale: when the refresh
// fails it renders as unavailable, never as trusted (no banner).
func TestBuiltinTrustCacheFailureAfterTrustedRendersUnavailable(t *testing.T) {
	p := &countingTrust{resp: trustedStatus}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := testTrustCache(p, clk, nil)
	if v := c.get(context.Background()); v != nil {
		t.Fatalf("trusted: banner %+v, want nil", v)
	}
	p.set(nil, errors.New("connection refused"), nil)
	clk.advance(builtinTrustTTL + time.Second)
	if v := c.get(context.Background()); v == nil || v.Kind != "unavailable" {
		t.Fatalf("failed refresh after trusted: banner %+v, want unavailable", v)
	}
}

// A slow or hung executor must not hold up the page past the short
// page wait, and the stale TRUSTED verdict must not be shown meanwhile.
func TestBuiltinTrustCacheSlowRefreshRendersUnavailable(t *testing.T) {
	p := &countingTrust{resp: trustedStatus}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := testTrustCache(p, clk, nil)
	if v := c.get(context.Background()); v != nil {
		t.Fatalf("trusted: banner %+v, want nil", v)
	}
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	p.set(untrustedStatus, nil, block)
	clk.advance(builtinTrustTTL + time.Second)
	c.wait = 20 * time.Millisecond
	start := time.Now()
	for range 3 {
		if v := c.get(context.Background()); v == nil || v.Kind != "unavailable" {
			t.Fatalf("pending refresh: banner %+v, want unavailable", v)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("renders took %v with a hung executor", d)
	}
	// Single flight: the renders share the one pending refresh.
	if n := p.calls.Load(); n != 2 {
		t.Fatalf("%d RPCs, want 2 (initial + one pending refresh)", n)
	}
}

func TestBuiltinTrustCacheLogsFailureOncePerStateChange(t *testing.T) {
	var logged bytes.Buffer
	p := &countingTrust{err: errors.New("dial unix: connection refused")}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := testTrustCache(p, clk, slog.New(slog.NewTextHandler(&logged, nil)))
	for range 3 {
		if v := c.get(context.Background()); v == nil || v.Kind != "unavailable" {
			t.Fatalf("RPC failure: banner %+v, want unavailable", v)
		}
		clk.advance(builtinTrustFailTTL + time.Second)
	}
	if n := p.calls.Load(); n != 3 {
		t.Fatalf("%d RPCs, want 3", n)
	}
	if n := strings.Count(logged.String(), "level=ERROR"); n != 1 {
		t.Fatalf("%d error log lines for one failing state, want 1:\n%s", n, logged.String())
	}
	p.set(trustedStatus, nil, nil)
	if v := c.get(context.Background()); v != nil {
		t.Fatalf("recovered: banner %+v, want nil", v)
	}
	p.set(nil, errors.New("dial unix: connection refused"), nil)
	clk.advance(builtinTrustTTL + time.Second)
	c.get(context.Background())
	if n := strings.Count(logged.String(), "level=ERROR"); n != 2 {
		t.Fatalf("%d error log lines after fail/recover/fail, want 2:\n%s", n, logged.String())
	}
}
