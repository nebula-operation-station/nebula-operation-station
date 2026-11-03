// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

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

// The executor's module list is untrusted input: the banner lists at
// most builtinTrustMaxModules entries and says how many it left out.
func TestBuiltinTrustBannerCapsModuleCount(t *testing.T) {
	for _, tc := range []struct {
		n        int
		omitted  int
		wantNote bool
	}{
		{n: builtinTrustMaxModules, omitted: 0},
		{n: builtinTrustMaxModules + 1, omitted: 1, wantNote: true},
		{n: builtinTrustMaxModules + 500, omitted: 500, wantNote: true},
	} {
		st := &pb.GetBuiltinTrustStatusResponse{State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED}
		// Unchanged modules are not affected and must not count.
		st.Modules = append(st.Modules, &pb.BuiltinTrustEntry{Name: "same", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_UNCHANGED})
		for i := range tc.n {
			st.Modules = append(st.Modules, &pb.BuiltinTrustEntry{
				Name: fmt.Sprintf("mod%d", i), Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_NEW, ReleaseVersion: "1.0.0",
			})
		}
		v := builtinTrustBanner(st)
		if v == nil {
			t.Fatalf("n=%d: banner nil", tc.n)
		}
		if want := tc.n - tc.omitted; len(v.Affected) != want {
			t.Errorf("n=%d: %d affected listed, want %d", tc.n, len(v.Affected), want)
		}
		if len(v.Affected) > 0 && v.Affected[0].Name != "mod0" {
			t.Errorf("n=%d: first listed %q, want mod0 (executor order kept)", tc.n, v.Affected[0].Name)
		}
		note := fmt.Sprintf("%d more affected built-in", tc.omitted)
		if got := strings.Contains(v.Detail, note); got != tc.wantNote {
			t.Errorf("n=%d: Detail %q contains %q = %v, want %v", tc.n, v.Detail, note, got, tc.wantNote)
		}
		if !strings.Contains(v.Detail, "lease") {
			t.Errorf("n=%d: Detail %q lost the lease guidance", tc.n, v.Detail)
		}
	}
}

// Module names and versions are capped in bytes, cut on a rune
// boundary, marked with an ellipsis and always valid UTF-8.
func TestBuiltinTrustBannerCapsNameAndVersionLength(t *testing.T) {
	longName := strings.Repeat("n", builtinTrustMaxNameBytes+100)
	longVer := strings.Repeat("v", builtinTrustMaxVersionBytes+100)
	// Multi-byte runes straddle the cut.
	runeName := strings.Repeat("é", builtinTrustMaxNameBytes)
	// Invalid UTF-8 expands to U+FFFD (3 bytes each): still capped.
	badName := strings.Repeat("\xff", builtinTrustMaxNameBytes)
	exactName := strings.Repeat("x", builtinTrustMaxNameBytes)
	exactVer := strings.Repeat("y", builtinTrustMaxVersionBytes)

	v := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			{Name: longName, Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED, ReleaseVersion: longVer, TrustedVersion: longVer},
			{Name: runeName, Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_NEW, ReleaseVersion: "1"},
			{Name: badName, Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_NEW, ReleaseVersion: "\xfe1.0"},
			{Name: exactName, Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_NEW, ReleaseVersion: exactVer},
		},
	})
	if v == nil || len(v.Affected) != 4 {
		t.Fatalf("banner %+v, want 4 affected", v)
	}
	for i, e := range v.Affected {
		for _, f := range []struct {
			what, s string
			max     int
		}{
			{"Name", e.Name, builtinTrustMaxNameBytes},
			{"Version", e.Version, builtinTrustMaxVersionBytes},
			{"Trusted", e.Trusted, builtinTrustMaxVersionBytes},
		} {
			if len(f.s) > f.max {
				t.Errorf("Affected[%d].%s: %d bytes, limit %d", i, f.what, len(f.s), f.max)
			}
			if !utf8.ValidString(f.s) {
				t.Errorf("Affected[%d].%s: invalid UTF-8 %q", i, f.what, f.s)
			}
		}
	}
	long := v.Affected[0]
	if !strings.HasPrefix(long.Name, "nnnn") || !strings.HasSuffix(long.Name, "…") {
		t.Errorf("long name %q: want kept prefix and ellipsis", long.Name)
	}
	if !strings.HasPrefix(long.Version, "vvvv") || !strings.HasSuffix(long.Version, "…") ||
		!strings.HasSuffix(long.Trusted, "…") {
		t.Errorf("long versions %q / %q: want kept prefix and ellipsis", long.Version, long.Trusted)
	}
	if !strings.HasPrefix(v.Affected[1].Name, "éé") || !strings.HasSuffix(v.Affected[1].Name, "…") {
		t.Errorf("multi-byte name %q: want kept prefix and ellipsis", v.Affected[1].Name)
	}
	if !strings.Contains(v.Affected[2].Version, "1.0") {
		t.Errorf("invalid UTF-8 version %q lost its valid text", v.Affected[2].Version)
	}
	if v.Affected[3].Name != exactName || v.Affected[3].Version != exactVer {
		t.Errorf("values at the limit were changed: %+v", v.Affected[3])
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

// A failed refresh is cached for failTTL: renders within that window
// show unavailable without asking the executor again.
func TestBuiltinTrustCacheFailureCachedForFailTTL(t *testing.T) {
	p := &countingTrust{err: errors.New("dial unix: connection refused")}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := testTrustCache(p, clk, nil)
	if v := c.get(context.Background()); v == nil || v.Kind != "unavailable" {
		t.Fatalf("RPC failure: banner %+v, want unavailable", v)
	}
	for range 3 {
		clk.advance(builtinTrustFailTTL / 4)
		if v := c.get(context.Background()); v == nil || v.Kind != "unavailable" {
			t.Fatalf("cached failure: banner %+v, want unavailable", v)
		}
	}
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("%d RPCs within failTTL after a failure, want 1", n)
	}
	clk.advance(builtinTrustFailTTL / 2) // now past failTTL
	c.get(context.Background())
	if n := p.calls.Load(); n != 2 {
		t.Fatalf("%d RPCs after failTTL expired, want 2", n)
	}
}

// ctxBlockingTrust blocks every call until its context is done and
// records whether the context carried a deadline.
type ctxBlockingTrust struct {
	hadDeadline atomic.Bool
}

func (f *ctxBlockingTrust) GetBuiltinTrustStatus(ctx context.Context, in *pb.GetBuiltinTrustStatusRequest, opts ...grpc.CallOption) (*pb.GetBuiltinTrustStatusResponse, error) {
	_, ok := ctx.Deadline()
	f.hadDeadline.Store(ok)
	<-ctx.Done()
	return nil, ctx.Err()
}

// The background refresh is detached from the request but bounded by
// callTimeout: a hung executor cannot pin the single-flight slot.
func TestBuiltinTrustCacheRefreshBoundedByCallTimeout(t *testing.T) {
	p := &ctxBlockingTrust{}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := testTrustCache(p, clk, nil)
	c.wait = 10 * time.Millisecond
	c.callTimeout = 100 * time.Millisecond

	start := time.Now()
	if v := c.get(context.Background()); v == nil || v.Kind != "unavailable" {
		t.Fatalf("hung executor: banner %+v, want unavailable", v)
	}
	c.mu.Lock()
	ch := c.inflight
	c.mu.Unlock()
	if ch == nil {
		t.Fatal("no refresh in flight after a timed-out render")
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("background refresh still running 5s after callTimeout: it has no deadline")
	}
	if d := time.Since(start); d < c.callTimeout {
		t.Fatalf("refresh ended after %v, before callTimeout %v", d, c.callTimeout)
	}
	if !p.hadDeadline.Load() {
		t.Fatal("refresh context had no deadline")
	}
	c.mu.Lock()
	inflight := c.inflight
	c.mu.Unlock()
	if inflight != nil {
		t.Fatal("single-flight slot still held after the refresh ended")
	}
	if v := c.get(context.Background()); v == nil || v.Kind != "unavailable" {
		t.Fatalf("after timed-out refresh: banner %+v, want unavailable", v)
	}
}
