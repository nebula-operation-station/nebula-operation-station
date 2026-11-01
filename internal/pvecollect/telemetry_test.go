// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var telT0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type telReader struct {
	mu    sync.Mutex
	reads []TelemetryRead
	fn    func(ctx context.Context, r TelemetryRead) ([]TelemetrySample, error)
}

func (f *telReader) ReadTelemetry(ctx context.Context, r TelemetryRead) ([]TelemetrySample, error) {
	f.mu.Lock()
	f.reads = append(f.reads, r)
	fn := f.fn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, r)
	}
	return []TelemetrySample{{Target: r.Target, Metric: TelemetryMetricCPU, Value: 0.5}}, nil
}

func (f *telReader) take() []TelemetryRead {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.reads
	f.reads = nil
	return out
}

type telSink struct {
	mu      sync.Mutex
	samples []TelemetrySample
}

func (s *telSink) RecordTelemetry(_ context.Context, smp TelemetrySample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples = append(s.samples, smp)
	return nil
}

func (s *telSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.samples)
}

var testPin = strings.Repeat("ab", 32)

func provTarget(remote string, vmid, gen uint64) TelemetryTarget {
	t := TelemetryTarget{Source: TelemetryProvider, RemoteID: remote, TrustPin: testPin, TrustGeneration: 1, Node: "pve1"}
	if vmid == 0 {
		t.Kind = TelemetryKindNode
	} else {
		t.Kind, t.VMID, t.Generation = TelemetryKindQEMU, vmid, gen
	}
	return t
}

func sshTarget(host, action string) TelemetryTarget {
	return TelemetryTarget{Source: TelemetrySSH, HostID: host, HostKey: "SHA256:hostkey-" + host, ActionID: action}
}

func lease(id string, sched, onDemand bool, exp time.Time, budget int, targets ...TelemetryTarget) TelemetryLease {
	return TelemetryLease{GrantID: id, GrantDigest: "digest-" + id, Scheduled: sched, OnDemand: onDemand, ExpiresAt: exp,
		MinInterval: TelemetryLiveInterval, RunBudget: budget, Targets: targets}
}

func newTel(t *testing.T, r *telReader, leases ...TelemetryLease) (*TelemetryScheduler, *fakeClock, *telSink) {
	t.Helper()
	clk := &fakeClock{t: telT0}
	sink := &telSink{}
	s, err := NewTelemetryScheduler(r, sink, TelemetryConfig{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLeases(leases); err != nil {
		t.Fatal(err)
	}
	return s, clk, sink
}

func TestTelemetryValidPinFixture(t *testing.T) {
	if !provTarget("remote-a", 0, 0).Valid() {
		t.Fatal("fixture provider target must be valid")
	}
}

func TestTelemetryHistoryOnlyUnderScheduledLeaseEveryFiveMinutes(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	s, clk, sink := newTel(t, r, lease("g1", true, false, telT0.Add(24*time.Hour), 100, tg))
	ctx := context.Background()

	if rep := s.RunOnce(ctx); rep.Issued != 1 || rep.Recorded != 1 {
		t.Fatalf("first pass: %+v", rep)
	}
	reads := r.take()
	if len(reads) != 1 || reads[0].Live || reads[0].GrantID != "g1" || reads[0].Target != tg {
		t.Fatalf("reads = %+v", reads)
	}
	clk.Add(TelemetryHistoryInterval - time.Second)
	if rep := s.RunOnce(ctx); rep.Issued != 0 {
		t.Fatalf("history read before 5 min: %+v", rep)
	}
	clk.Add(time.Second)
	if rep := s.RunOnce(ctx); rep.Issued != 1 {
		t.Fatalf("history read at 5 min: %+v", rep)
	}
	if sink.count() != 2 {
		t.Fatalf("samples = %d", sink.count())
	}
	// A scheduled-only lease gives no live authority.
	if _, err := s.Request("viewer-1", tg); !errors.Is(err, ErrTelemetryNotAuthorized) {
		t.Fatalf("live request under scheduled-only lease: %v", err)
	}
}

func TestTelemetryOnDemandLeaseHasNoBackgroundHistory(t *testing.T) {
	r := &telReader{}
	s, clk, _ := newTel(t, r, lease("g1", false, true, telT0.Add(time.Hour), 100, provTarget("remote-a", 101, 1)))
	for range 3 {
		if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
			t.Fatalf("background read without scheduled trigger: %+v", rep)
		}
		clk.Add(TelemetryHistoryInterval)
	}
}

func TestTelemetryRequestNeedsExactLeasedTarget(t *testing.T) {
	tg := provTarget("remote-a", 101, 3)
	host := sshTarget("host-1", "host.metrics")
	r := &telReader{}
	s, _, _ := newTel(t, r, lease("g1", false, true, telT0.Add(time.Hour), 100, tg, host))

	mut := []struct {
		name string
		f    func(*TelemetryTarget)
	}{
		{"guest generation", func(x *TelemetryTarget) { x.Generation = 4 }},
		{"vmid", func(x *TelemetryTarget) { x.VMID = 102 }},
		{"remote", func(x *TelemetryTarget) { x.RemoteID = "remote-b" }},
		{"trust generation", func(x *TelemetryTarget) { x.TrustGeneration = 2 }},
		{"trust pin", func(x *TelemetryTarget) { x.TrustPin = strings.Repeat("cd", 32) }},
		{"node", func(x *TelemetryTarget) { x.Node = "pve2" }},
		{"kind", func(x *TelemetryTarget) { x.Kind = TelemetryKindLXC }},
	}
	for _, m := range mut {
		x := tg
		m.f(&x)
		if _, err := s.Request("v", x); !errors.Is(err, ErrTelemetryNotAuthorized) && !errors.Is(err, ErrTelemetryInvalid) {
			t.Errorf("%s changed: err = %v", m.name, err)
		}
	}
	sshMut := []struct {
		name string
		f    func(*TelemetryTarget)
	}{
		{"host key", func(x *TelemetryTarget) { x.HostKey = "SHA256:other" }},
		{"host", func(x *TelemetryTarget) { x.HostID = "host-2" }},
		{"action", func(x *TelemetryTarget) { x.ActionID = "gpu.status" }},
		{"non-telemetry action", func(x *TelemetryTarget) { x.ActionID = "package.list_updates" }},
	}
	for _, m := range sshMut {
		x := host
		m.f(&x)
		if _, err := s.Request("v", x); !errors.Is(err, ErrTelemetryNotAuthorized) && !errors.Is(err, ErrTelemetryInvalid) {
			t.Errorf("ssh %s changed: err = %v", m.name, err)
		}
	}
	if _, err := s.Request("v", tg); err != nil {
		t.Fatalf("exact target refused: %v", err)
	}
	if _, err := s.Request("v", host); err != nil {
		t.Fatalf("exact ssh target refused: %v", err)
	}
	if _, err := s.Request("", tg); !errors.Is(err, ErrTelemetryInvalid) {
		t.Fatalf("empty viewer: %v", err)
	}
	if _, err := s.Request(strings.Repeat("v", MaxViewerIDBytes+1), tg); !errors.Is(err, ErrTelemetryInvalid) {
		t.Fatalf("oversized viewer: %v", err)
	}
	if _, err := s.Request("\xff", tg); !errors.Is(err, ErrTelemetryInvalid) {
		t.Fatalf("non-UTF-8 viewer: %v", err)
	}
}

func TestTelemetryLiveCadenceAndViewerExpiry(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	s, clk, _ := newTel(t, r, lease("g1", false, true, telT0.Add(time.Hour), 1000, tg))
	ctx := context.Background()
	exp, err := s.Request("v1", tg)
	if err != nil || !exp.Equal(telT0.Add(TelemetryViewerRenewal)) {
		t.Fatalf("request: %v %v", exp, err)
	}
	if rep := s.RunOnce(ctx); rep.Issued != 1 {
		t.Fatalf("live: %+v", rep)
	}
	if reads := r.take(); len(reads) != 1 || !reads[0].Live {
		t.Fatalf("reads = %+v", reads)
	}
	clk.Add(TelemetryLiveInterval - time.Second)
	if rep := s.RunOnce(ctx); rep.Issued != 0 {
		t.Fatalf("live before 10 s: %+v", rep)
	}
	clk.Add(time.Second)
	if rep := s.RunOnce(ctx); rep.Issued != 1 {
		t.Fatalf("live at 10 s: %+v", rep)
	}
	// No renewal: the request lapses at 30 s and live reads stop.
	clk.Set(telT0.Add(TelemetryViewerRenewal))
	if rep := s.RunOnce(ctx); rep.Issued != 0 {
		t.Fatalf("live after expiry: %+v", rep)
	}
	clk.Add(time.Minute)
	if rep := s.RunOnce(ctx); rep.Issued != 0 {
		t.Fatalf("live long after expiry: %+v", rep)
	}
}

func TestTelemetryCoalescesViewersOfOneTarget(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	s, clk, _ := newTel(t, r, lease("g1", false, true, telT0.Add(time.Hour), 1000, tg))
	ctx := context.Background()
	for _, v := range []string{"v1", "v2", "v3"} {
		if _, err := s.Request(v, tg); err != nil {
			t.Fatal(err)
		}
	}
	if rep := s.RunOnce(ctx); rep.Issued != 1 {
		t.Fatalf("three viewers, one target: %+v", rep)
	}
	s.Release("v1", tg)
	s.Release("v2", tg)
	clk.Add(TelemetryLiveInterval)
	if rep := s.RunOnce(ctx); rep.Issued != 1 {
		t.Fatalf("one viewer left: %+v", rep)
	}
	s.Release("v3", tg)
	clk.Add(TelemetryLiveInterval)
	if rep := s.RunOnce(ctx); rep.Issued != 0 {
		t.Fatalf("all viewers gone: %+v", rep)
	}
}

func TestTelemetryLiveSampleCoalescesHistoryBucket(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	s, clk, _ := newTel(t, r, lease("g1", true, true, telT0.Add(time.Hour), 1000, tg))
	ctx := context.Background()
	if _, err := s.Request("v1", tg); err != nil {
		t.Fatal(err)
	}
	rep := s.RunOnce(ctx)
	if rep.Issued != 1 || rep.Coalesced != 1 {
		t.Fatalf("live and history due together: %+v", rep)
	}
	if reads := r.take(); len(reads) != 1 || !reads[0].Live {
		t.Fatalf("reads = %+v", reads)
	}
	clk.Add(2 * time.Second)
	rep = s.RunOnce(ctx)
	if rep.Issued != 0 || rep.Coalesced != 1 {
		t.Fatalf("history after live sample in bucket: %+v", rep)
	}
	// The viewer leaves; the next bucket gets a real history read.
	s.Release("v1", tg)
	clk.Set(telT0.Add(TelemetryHistoryInterval + 2*time.Second))
	rep = s.RunOnce(ctx)
	if reads := r.take(); rep.Issued != 1 || len(reads) != 1 || reads[0].Live {
		t.Fatalf("next bucket history: %+v %+v", rep, reads)
	}
}

func TestTelemetryFailedLiveReadDoesNotSkipHistory(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	r := &telReader{fn: func(_ context.Context, rd TelemetryRead) ([]TelemetrySample, error) {
		if rd.Live {
			return nil, errors.New("timeout")
		}
		return []TelemetrySample{{Target: rd.Target, Metric: TelemetryMetricCPU, Value: 0.1}}, nil
	}}
	s, clk, sink := newTel(t, r, lease("g1", true, true, telT0.Add(time.Hour), 1000, tg))
	if _, err := s.Request("v1", tg); err != nil {
		t.Fatal(err)
	}
	if rep := s.RunOnce(context.Background()); rep.Failed != 1 {
		t.Fatalf("%+v", rep)
	}
	clk.Add(time.Second)
	rep := s.RunOnce(context.Background())
	if rep.Issued != 1 || sink.count() != 1 {
		t.Fatalf("history must still be read: %+v samples=%d", rep, sink.count())
	}
}

func TestTelemetryRemoteLiveTargetCap(t *testing.T) {
	r := &telReader{}
	var tgs []TelemetryTarget
	for i := range 5 {
		tgs = append(tgs, provTarget("remote-a", uint64(101+i), 1))
	}
	other := provTarget("remote-b", 0, 0)
	s, clk, _ := newTel(t, r, lease("g1", false, true, telT0.Add(time.Hour), 4096, append(tgs, other)...))
	for i, tg := range tgs {
		if _, err := s.Request("v", tg); err != nil {
			t.Fatal(err)
		}
		clk.Add(time.Millisecond) // order of first request = priority
		_ = i
	}
	if _, err := s.Request("v", other); err != nil {
		t.Fatal(err)
	}
	served := map[uint64]bool{}
	var lastRep TelemetryReport
	for range 8 {
		lastRep = s.RunOnce(context.Background())
		for _, rd := range r.take() {
			if rd.Target.RemoteID == "remote-a" {
				served[rd.Target.VMID] = true
			}
		}
		clk.Add(ProviderMetricsSpacing)
	}
	if len(served) != MaxLiveTargetsPerRemote || served[105] {
		t.Fatalf("served = %v", served)
	}
	found := false
	for _, d := range lastRep.Deferred {
		if d.Target.VMID == 105 && d.Reason == DeferLiveTargetCap && d.Live {
			found = true
		}
	}
	if !found {
		t.Fatalf("fifth target not reported deferred: %+v", lastRep.Deferred)
	}
	// Freeing a slot lets the fifth target in.
	s.Release("v", tgs[0])
	clk.Add(TelemetryLiveInterval)
	for range 5 {
		s.RunOnce(context.Background())
		clk.Add(ProviderMetricsSpacing)
	}
	got := false
	for _, rd := range r.take() {
		if rd.Target.VMID == 105 {
			got = true
		}
	}
	if !got {
		t.Fatal("fifth target not served after a slot was freed")
	}
}

func TestTelemetryOneMetricsRequestPerSecondPerRemote(t *testing.T) {
	r := &telReader{}
	a1, a2 := provTarget("remote-a", 101, 1), provTarget("remote-a", 102, 1)
	b1 := provTarget("remote-b", 101, 1)
	s, clk, _ := newTel(t, r, lease("g1", true, false, telT0.Add(time.Hour), 1000, a1, a2, b1))
	rep := s.RunOnce(context.Background())
	if rep.Issued != 2 {
		t.Fatalf("one per remote: %+v", rep)
	}
	perRemote := map[string]int{}
	for _, rd := range r.take() {
		perRemote[rd.Target.RemoteID]++
	}
	if perRemote["remote-a"] != 1 || perRemote["remote-b"] != 1 {
		t.Fatalf("per remote = %v", perRemote)
	}
	if len(rep.Deferred) != 1 || rep.Deferred[0].Reason != DeferRequestRate {
		t.Fatalf("deferred = %+v", rep.Deferred)
	}
	clk.Add(ProviderMetricsSpacing - time.Millisecond)
	if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
		t.Fatalf("within 1 s: %+v", rep)
	}
	clk.Add(time.Millisecond)
	if rep := s.RunOnce(context.Background()); rep.Issued != 1 {
		t.Fatalf("after 1 s: %+v", rep)
	}
}

func TestTelemetryRollingHourBudgetPerRemoteAndHost(t *testing.T) {
	r := &telReader{}
	var tgs []TelemetryTarget
	for i := range 5 {
		tgs = append(tgs, provTarget("remote-a", uint64(101+i), 1))
	}
	host := []TelemetryTarget{sshTarget("host-1", "host.metrics"), sshTarget("host-1", "filesystem.list"), sshTarget("host-1", "gpu.status")}
	s, clk, _ := newTel(t, r,
		lease("g1", true, false, telT0.Add(48*time.Hour), 3, tgs...),
		lease("g2", true, false, telT0.Add(48*time.Hour), 2, host...))
	issued := map[string]int{}
	var last TelemetryReport
	for range 10 {
		last = s.RunOnce(context.Background())
		for _, rd := range r.take() {
			issued[rd.Target.scope()]++
		}
		clk.Add(ProviderMetricsSpacing)
	}
	if issued[tgs[0].scope()] != 3 || issued[host[0].scope()] != 2 {
		t.Fatalf("issued = %v", issued)
	}
	budget := 0
	for _, d := range last.Deferred {
		if d.Reason == DeferBudget {
			budget++
		}
	}
	if budget != 3 { // 2 remote targets + 1 host action left over
		t.Fatalf("budget deferrals = %d: %+v", budget, last.Deferred)
	}
	// The window rolls: an hour after the first reads the budget is back.
	clk.Set(telT0.Add(telemetryBudgetWindow + time.Second))
	for range 3 {
		s.RunOnce(context.Background())
		clk.Add(ProviderMetricsSpacing)
	}
	if n := len(r.take()); n == 0 {
		t.Fatal("budget did not roll over")
	}
}

func TestTelemetryOneReadInFlightPerHost(t *testing.T) {
	var mu sync.Mutex
	inFlight, maxInFlight := map[string]int{}, 0
	r := &telReader{fn: func(_ context.Context, rd TelemetryRead) ([]TelemetrySample, error) {
		mu.Lock()
		inFlight[rd.Target.HostID]++
		maxInFlight = max(maxInFlight, inFlight[rd.Target.HostID])
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		inFlight[rd.Target.HostID]--
		mu.Unlock()
		return nil, nil
	}}
	s, _, _ := newTel(t, r, lease("g1", true, false, telT0.Add(time.Hour), 100,
		sshTarget("host-1", "host.metrics"), sshTarget("host-1", "filesystem.list"), sshTarget("host-2", "host.metrics")))
	rep := s.RunOnce(context.Background())
	if rep.Issued != 2 || maxInFlight != 1 {
		t.Fatalf("issued %d, max in flight per host %d", rep.Issued, maxInFlight)
	}
	if len(rep.Deferred) != 1 || rep.Deferred[0].Reason != DeferHostBusy {
		t.Fatalf("deferred = %+v", rep.Deferred)
	}
}

func TestTelemetryLockStopsReadsAndRequests(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	s, clk, _ := newTel(t, r, lease("g1", true, true, telT0.Add(time.Hour), 100, tg))
	if _, err := s.Request("v", tg); err != nil {
		t.Fatal(err)
	}
	s.Lock()
	if _, err := s.Request("v", tg); !errors.Is(err, ErrTelemetryLocked) {
		t.Fatalf("request while locked: %v", err)
	}
	for range 3 {
		if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
			t.Fatalf("read while locked: %+v", rep)
		}
		clk.Add(TelemetryHistoryInterval)
	}
	s.Unlock()
	rep := s.RunOnce(context.Background())
	if rep.Issued != 1 {
		t.Fatalf("after unlock: %+v", rep)
	}
	// Lock dropped the viewer request: only the history read runs.
	if reads := r.take(); reads[0].Live {
		t.Fatal("viewer request survived the lock")
	}
}

func TestTelemetryLockDuringReadCancelsAndDiscards(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	var s *TelemetryScheduler
	r := &telReader{}
	r.fn = func(ctx context.Context, rd TelemetryRead) ([]TelemetrySample, error) {
		s.Lock()
		if ctx.Err() == nil {
			t.Error("in-flight read not cancelled by Lock")
		}
		return []TelemetrySample{{Target: rd.Target, Metric: TelemetryMetricCPU, Value: 0.3}}, nil
	}
	var sink *telSink
	s, _, sink = newTel(t, r, lease("g1", true, false, telT0.Add(time.Hour), 100, tg))
	rep := s.RunOnce(context.Background())
	if rep.Issued != 1 || rep.Recorded != 0 || rep.Discarded != 1 || sink.count() != 0 {
		t.Fatalf("sample recorded after lock: %+v samples=%d", rep, sink.count())
	}
	if _, ok := s.LastObserved(tg); ok {
		t.Fatal("discarded sample counted as observation")
	}
}

func TestTelemetryLeaseExpiryStopsReads(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	exp := telT0.Add(7 * time.Minute)
	s, clk, _ := newTel(t, r, lease("g1", true, true, exp, 1000, tg))
	if _, err := s.Request("v", tg); err != nil {
		t.Fatal(err)
	}
	if rep := s.RunOnce(context.Background()); rep.Issued != 1 {
		t.Fatalf("%+v", rep)
	}
	clk.Set(exp)
	if _, err := s.Request("v", tg); !errors.Is(err, ErrTelemetryNotAuthorized) {
		t.Fatalf("request after expiry: %v", err)
	}
	for range 3 {
		if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
			t.Fatalf("read after expiry: %+v", rep)
		}
		clk.Add(TelemetryHistoryInterval)
	}
}

func TestTelemetryExpiryDuringReadDiscardsResult(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	exp := telT0.Add(time.Minute)
	var clk *fakeClock
	r := &telReader{fn: func(_ context.Context, rd TelemetryRead) ([]TelemetrySample, error) {
		clk.Set(exp) // the read completes after the lease expired
		return []TelemetrySample{{Target: rd.Target, Metric: TelemetryMetricCPU, Value: 0.3}}, nil
	}}
	var s *TelemetryScheduler
	var sink *telSink
	s, clk, sink = newTel(t, r, lease("g1", true, false, exp, 100, tg))
	rep := s.RunOnce(context.Background())
	if rep.Issued != 1 || rep.Recorded != 0 || sink.count() != 0 {
		t.Fatalf("result of expired lease recorded: %+v", rep)
	}
}

func TestTelemetryRevocationDropsViewersAndInFlight(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	var s *TelemetryScheduler
	r := &telReader{}
	r.fn = func(ctx context.Context, rd TelemetryRead) ([]TelemetrySample, error) {
		if err := s.SetLeases(nil); err != nil {
			t.Error(err)
		}
		if ctx.Err() == nil {
			t.Error("in-flight read not cancelled by revocation")
		}
		return []TelemetrySample{{Target: rd.Target, Metric: TelemetryMetricCPU, Value: 0.3}}, nil
	}
	var sink *telSink
	var clk *fakeClock
	s, clk, sink = newTel(t, r, lease("g1", false, true, telT0.Add(time.Hour), 100, tg))
	if _, err := s.Request("v", tg); err != nil {
		t.Fatal(err)
	}
	rep := s.RunOnce(context.Background())
	if rep.Recorded != 0 || sink.count() != 0 {
		t.Fatalf("revoked read recorded: %+v", rep)
	}
	// The viewer request went with the lease; re-adding the lease does not
	// resurrect it.
	r.fn = nil
	if err := s.SetLeases([]TelemetryLease{lease("g1", false, true, telT0.Add(time.Hour), 100, tg)}); err != nil {
		t.Fatal(err)
	}
	clk.Add(TelemetryLiveInterval)
	if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
		t.Fatalf("viewer resurrected: %+v", rep)
	}
}

func TestTelemetryChangedDigestDiscardsInFlight(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	var s *TelemetryScheduler
	r := &telReader{}
	r.fn = func(_ context.Context, rd TelemetryRead) ([]TelemetrySample, error) {
		l := lease("g1", true, false, telT0.Add(time.Hour), 100, tg)
		l.GrantDigest = "digest-renewed"
		if err := s.SetLeases([]TelemetryLease{l}); err != nil {
			t.Error(err)
		}
		return []TelemetrySample{{Target: rd.Target, Metric: TelemetryMetricCPU, Value: 0.3}}, nil
	}
	var sink *telSink
	s, _, sink = newTel(t, r, lease("g1", true, false, telT0.Add(time.Hour), 100, tg))
	if rep := s.RunOnce(context.Background()); rep.Recorded != 0 || sink.count() != 0 {
		t.Fatalf("result under a replaced grant version recorded: %+v", rep)
	}
}

func TestTelemetryExecutorRefusalStopsTarget(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.NotFound, codes.FailedPrecondition} {
		tg := provTarget("remote-a", 101, 1)
		r := &telReader{fn: func(context.Context, TelemetryRead) ([]TelemetrySample, error) {
			return nil, status.Error(code, "read_grant_inactive")
		}}
		s, clk, _ := newTel(t, r, lease("g1", true, true, telT0.Add(time.Hour), 100, tg))
		if rep := s.RunOnce(context.Background()); rep.Failed != 1 {
			t.Fatalf("%v: %+v", code, rep)
		}
		clk.Add(TelemetryHistoryInterval)
		if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
			t.Fatalf("%v: refused target read again: %+v", code, rep)
		}
		if _, err := s.Request("v", tg); !errors.Is(err, ErrTelemetryNotAuthorized) {
			t.Fatalf("%v: live request after refusal: %v", code, err)
		}
	}
}

func TestTelemetryRateRefusalKeepsCadence(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	r := &telReader{fn: func(context.Context, TelemetryRead) ([]TelemetrySample, error) {
		return nil, status.Error(codes.ResourceExhausted, "budget")
	}}
	s, clk, _ := newTel(t, r, lease("g1", true, false, telT0.Add(time.Hour), 100, tg))
	s.RunOnce(context.Background())
	clk.Add(time.Minute)
	if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
		t.Fatalf("retry before the interval: %+v", rep)
	}
	clk.Add(TelemetryHistoryInterval)
	if rep := s.RunOnce(context.Background()); rep.Issued != 1 {
		t.Fatalf("not retried at the next interval: %+v", rep)
	}
}

func TestTelemetryDropsForeignAndInvalidSamples(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	other := provTarget("remote-a", 101, 2)
	r := &telReader{fn: func(_ context.Context, rd TelemetryRead) ([]TelemetrySample, error) {
		return []TelemetrySample{
			{Target: other, Metric: TelemetryMetricCPU, Value: 0.1},
			{Target: rd.Target, Metric: "load", Value: 0.1},
			{Target: rd.Target, Metric: TelemetryMetricCPU, Value: math.NaN()},
			{Target: rd.Target, Metric: TelemetryMetricCPU, Value: 1.5},
			{Target: rd.Target, Metric: TelemetryMetricRAM, Value: -0.1},
			{Target: rd.Target, Metric: TelemetryMetricRAM, Value: 0.4},
			{Target: rd.Target, Metric: TelemetryMetricRAM, Value: 0.5}, // duplicate metric
		}, nil
	}}
	s, _, sink := newTel(t, r, lease("g1", true, false, telT0.Add(time.Hour), 100, tg))
	rep := s.RunOnce(context.Background())
	if rep.Recorded != 1 || rep.Discarded != 6 || sink.count() != 1 {
		t.Fatalf("%+v", rep)
	}
	got := sink.samples[0]
	if got.Value != 0.4 || got.Target != tg || got.Live || !got.ObservedAt.Equal(telT0) {
		t.Fatalf("sample = %+v", got)
	}
}

func TestTelemetrySetLeasesRejectsMalformed(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	good := lease("g1", true, true, telT0.Add(time.Hour), 10, tg)
	cases := map[string]func(*TelemetryLease){
		"no grant id":      func(l *TelemetryLease) { l.GrantID = "" },
		"no digest":        func(l *TelemetryLease) { l.GrantDigest = "" },
		"no trigger":       func(l *TelemetryLease) { l.Scheduled, l.OnDemand = false, false },
		"no expiry":        func(l *TelemetryLease) { l.ExpiresAt = time.Time{} },
		"interval < 10 s":  func(l *TelemetryLease) { l.MinInterval = 9 * time.Second },
		"budget 0":         func(l *TelemetryLease) { l.RunBudget = 0 },
		"budget too large": func(l *TelemetryLease) { l.RunBudget = MaxTelemetryRunBudget + 1 },
		"no targets":       func(l *TelemetryLease) { l.Targets = nil },
		"duplicate target": func(l *TelemetryLease) { l.Targets = []TelemetryTarget{tg, tg} },
		"node with vmid": func(l *TelemetryLease) {
			x := provTarget("remote-a", 0, 0)
			x.VMID = 101
			l.Targets = []TelemetryTarget{x}
		},
		"guest without generation": func(l *TelemetryLease) { l.Targets = []TelemetryTarget{provTarget("remote-a", 101, 0)} },
		"mixed source fields": func(l *TelemetryLease) {
			x := tg
			x.HostID = "host-1"
			l.Targets = []TelemetryTarget{x}
		},
		"non-telemetry ssh action": func(l *TelemetryLease) { l.Targets = []TelemetryTarget{sshTarget("h", "package.list_updates")} },
		"no source":                func(l *TelemetryLease) { l.Targets = []TelemetryTarget{{RemoteID: "remote-a"}} },
	}
	r := &telReader{}
	s, _, _ := newTel(t, r, good)
	for name, mut := range cases {
		l := good
		l.Targets = []TelemetryTarget{tg}
		mut(&l)
		if err := s.SetLeases([]TelemetryLease{l}); !errors.Is(err, ErrTelemetryInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := s.SetLeases([]TelemetryLease{good, good}); !errors.Is(err, ErrTelemetryInvalid) {
		t.Errorf("duplicate lease: %v", err)
	}
	many := make([]TelemetryLease, MaxTelemetryLeases+1)
	if err := s.SetLeases(many); !errors.Is(err, ErrTelemetryLimit) {
		t.Errorf("too many leases: %v", err)
	}
	// A failed SetLeases keeps the previous set.
	if _, err := s.Request("v", tg); err != nil {
		t.Fatalf("previous lease lost: %v", err)
	}
}

func TestTelemetryLongerGrantIntervalWins(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	l := lease("g1", true, true, telT0.Add(time.Hour), 1000, tg)
	l.MinInterval = 30 * time.Second
	s, clk, _ := newTel(t, r, l)
	if _, err := s.Request("v", tg); err != nil {
		t.Fatal(err)
	}
	s.RunOnce(context.Background())
	r.take()
	clk.Add(TelemetryLiveInterval)
	if _, err := s.Request("v", tg); err != nil {
		t.Fatal(err)
	}
	if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
		t.Fatalf("live faster than grant interval: %+v", rep)
	}
}

func TestTelemetryClockStepBackDoesNotReadEarly(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	s, clk, _ := newTel(t, r, lease("g1", true, false, telT0.Add(time.Hour), 1000, tg))
	s.RunOnce(context.Background())
	clk.Set(telT0.Add(-10 * time.Minute))
	if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
		t.Fatalf("clock step back read: %+v", rep)
	}
	clk.Add(TelemetryHistoryInterval - time.Second)
	if rep := s.RunOnce(context.Background()); rep.Issued != 0 {
		t.Fatalf("read before a full interval after step: %+v", rep)
	}
	clk.Add(time.Second)
	if rep := s.RunOnce(context.Background()); rep.Issued != 1 {
		t.Fatalf("interval after step: %+v", rep)
	}
}

func TestTelemetryViewerTableIsBounded(t *testing.T) {
	r := &telReader{}
	tg := provTarget("remote-a", 101, 1)
	s, _, _ := newTel(t, r, lease("g1", false, true, telT0.Add(time.Hour), 10, tg))
	for i := range MaxTelemetryViewers {
		if _, err := s.Request("v"+strings.Repeat("x", i%50)+string(rune('a'+i%26))+itoa(i), tg); err != nil {
			t.Fatalf("viewer %d: %v", i, err)
		}
	}
	if _, err := s.Request("one-too-many", tg); !errors.Is(err, ErrTelemetryLimit) {
		t.Fatalf("over limit: %v", err)
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}
