// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
)

var hubT0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// clock is an injectable, advanceable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: hubT0} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func nodeTarget(remote, node string) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{
		Source: pvecollect.TelemetryProvider, RemoteID: remote,
		TrustPin: strings.Repeat("ab", 32), TrustGeneration: 1,
		Node: node, Kind: pvecollect.TelemetryKindNode,
	}
}

func guestTarget(remote, node string, vmid, gen uint64) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{
		Source: pvecollect.TelemetryProvider, RemoteID: remote,
		TrustPin: strings.Repeat("ab", 32), TrustGeneration: 1,
		Node: node, Kind: pvecollect.TelemetryKindQEMU, VMID: vmid, Generation: gen,
	}
}

func hostTarget(host string) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{
		Source: pvecollect.TelemetrySSH, HostID: host,
		HostKey: "SHA256:" + strings.Repeat("A", 43), ActionID: "host.metrics",
	}
}

func lease(id string, onDemand bool, c *clock, targets ...pvecollect.TelemetryTarget) pvecollect.TelemetryLease {
	return pvecollect.TelemetryLease{
		GrantID: id, GrantDigest: "digest-" + id,
		OnDemand: onDemand, Scheduled: !onDemand,
		ExpiresAt:   c.Now().Add(time.Hour),
		MinInterval: pvecollect.TelemetryLiveInterval,
		RunBudget:   pvecollect.MaxTelemetryRunBudget,
		Targets:     targets,
	}
}

// fakeReader answers every read with one CPU sample and counts reads.
type fakeReader struct {
	mu    sync.Mutex
	c     *clock
	reads []pvecollect.TelemetryRead
}

func (r *fakeReader) ReadTelemetry(_ context.Context, read pvecollect.TelemetryRead) ([]pvecollect.TelemetrySample, error) {
	r.mu.Lock()
	r.reads = append(r.reads, read)
	r.mu.Unlock()
	return []pvecollect.TelemetrySample{{
		Target: read.Target, Metric: pvecollect.TelemetryMetricCPU, Value: 0.42,
		Live: read.Live, ObservedAt: r.c.Now(),
	}}, nil
}

func (r *fakeReader) liveReads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rd := range r.reads {
		if rd.Live {
			n++
		}
	}
	return n
}

// hubSink forwards scheduler samples to the hub built after it.
type hubSink struct{ hub *Hub }

func (s *hubSink) RecordTelemetry(ctx context.Context, smp pvecollect.TelemetrySample) error {
	return s.hub.RecordTelemetry(ctx, smp)
}

type rig struct {
	c      *clock
	reader *fakeReader
	sched  *pvecollect.TelemetryScheduler
	hub    *Hub
}

func newRig(t *testing.T, leases ...pvecollect.TelemetryLease) *rig {
	t.Helper()
	c := newClock()
	reader := &fakeReader{c: c}
	sink := &hubSink{}
	sched, err := pvecollect.NewTelemetryScheduler(reader, sink, pvecollect.TelemetryConfig{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := sched.SetLeases(leases); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub(sched, nil, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	sink.hub = hub
	t.Cleanup(hub.Close)
	return &rig{c: c, reader: reader, sched: sched, hub: hub}
}

func mustViewer(t *testing.T) string {
	t.Helper()
	id, err := newViewerID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// drain returns the events queued on ch without blocking.
func drain(ch <-chan Event) []Event {
	var out []Event
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		default:
			return out
		}
	}
}

func valueIDs(t *testing.T, evs []Event) []string {
	t.Helper()
	var ids []string
	for _, ev := range evs {
		if ev.Name != "value" {
			continue
		}
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(ev.Data, &p); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, p.ID)
	}
	return ids
}

func TestViewersOfOneTargetShareOneRead(t *testing.T) {
	c := newClock()
	tgt := nodeTarget("remote-a", "pve1")
	r := newRig(t, lease("g1", true, c, tgt))
	v1, v2 := mustViewer(t), mustViewer(t)
	ch1, err := r.hub.Add(v1, "sess-a")
	if err != nil {
		t.Fatal(err)
	}
	ch2, err := r.hub.Add(v2, "sess-b")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ id, sess string }{{v1, "sess-a"}, {v2, "sess-b"}} {
		got, err := r.hub.SetBoxes(v.id, v.sess, map[string][]pvecollect.TelemetryTarget{"node:pve1": {tgt}})
		if err != nil || !slices.Equal(got, []string{"node:pve1"}) {
			t.Fatalf("SetBoxes = %v, %v", got, err)
		}
	}
	r.sched.RunOnce(context.Background())
	if n := r.reader.liveReads(); n != 1 {
		t.Fatalf("live reads = %d, want 1 (coalesced)", n)
	}
	for i, ch := range []<-chan Event{ch1, ch2} {
		if ids := valueIDs(t, drain(ch)); !slices.Equal(ids, []string{"node:pve1"}) {
			t.Fatalf("viewer %d got %v, want one value for node:pve1", i, ids)
		}
	}
}

func TestSampleCarriesEachViewersOwnBoxID(t *testing.T) {
	c := newClock()
	tgt := hostTarget("web01")
	r := newRig(t, lease("g1", true, c, tgt))
	v1, v2 := mustViewer(t), mustViewer(t)
	ch1, _ := r.hub.Add(v1, "s")
	ch2, _ := r.hub.Add(v2, "s")
	if _, err := r.hub.SetBoxes(v1, "s", map[string][]pvecollect.TelemetryTarget{"host:web01": {tgt}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.hub.SetBoxes(v2, "s", map[string][]pvecollect.TelemetryTarget{"guest:pve1:101": {tgt}}); err != nil {
		t.Fatal(err)
	}
	r.sched.RunOnce(context.Background())
	if ids := valueIDs(t, drain(ch1)); !slices.Equal(ids, []string{"host:web01"}) {
		t.Fatalf("viewer 1 got %v", ids)
	}
	if ids := valueIDs(t, drain(ch2)); !slices.Equal(ids, []string{"guest:pve1:101"}) {
		t.Fatalf("viewer 2 got %v", ids)
	}
}

func TestUnleasedTargetIsNotGranted(t *testing.T) {
	c := newClock()
	leased := nodeTarget("remote-a", "pve1")
	other := nodeTarget("remote-a", "pve2")
	historyOnly := nodeTarget("remote-a", "pve3")
	r := newRig(t, lease("g1", true, c, leased), lease("g2", false, c, historyOnly))
	v := mustViewer(t)
	ch, _ := r.hub.Add(v, "s")
	got, err := r.hub.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{
		"node:pve1": {leased}, "node:pve2": {other}, "node:pve3": {historyOnly},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"node:pve1"}) {
		t.Fatalf("granted = %v, want only node:pve1", got)
	}
	r.sched.RunOnce(context.Background())
	// History samples of pve3 and the live sample of pve1 are recorded;
	// only the live one of the requested target reaches the viewer.
	if ids := valueIDs(t, drain(ch)); !slices.Equal(ids, []string{"node:pve1"}) {
		t.Fatalf("viewer got %v, want only node:pve1", ids)
	}
}

func TestHistorySampleIsNotDelivered(t *testing.T) {
	c := newClock()
	tgt := nodeTarget("remote-a", "pve1")
	r := newRig(t, lease("g1", true, c, tgt))
	v := mustViewer(t)
	ch, _ := r.hub.Add(v, "s")
	if _, err := r.hub.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{"node:pve1": {tgt}}); err != nil {
		t.Fatal(err)
	}
	r.hub.Record(pvecollect.TelemetrySample{Target: tgt, Metric: pvecollect.TelemetryMetricCPU, Value: 0.5, ObservedAt: c.Now()})
	if evs := drain(ch); len(evs) != 0 {
		t.Fatalf("history sample delivered: %v", evs)
	}
}

func TestSetBoxesRequiresOwningSession(t *testing.T) {
	c := newClock()
	tgt := nodeTarget("remote-a", "pve1")
	r := newRig(t, lease("g1", true, c, tgt))
	v := mustViewer(t)
	if _, err := r.hub.Add(v, "sess-a"); err != nil {
		t.Fatal(err)
	}
	boxes := map[string][]pvecollect.TelemetryTarget{"node:pve1": {tgt}}
	if _, err := r.hub.SetBoxes(v, "sess-b", boxes); !errors.Is(err, ErrUnknownViewer) {
		t.Fatalf("foreign session: err = %v, want ErrUnknownViewer", err)
	}
	if _, err := r.hub.SetBoxes(mustViewer(t), "sess-a", boxes); !errors.Is(err, ErrUnknownViewer) {
		t.Fatalf("unknown viewer: err = %v, want ErrUnknownViewer", err)
	}
	r.sched.RunOnce(context.Background())
	if n := r.reader.liveReads(); n != 0 {
		t.Fatalf("live reads = %d after refused requests, want 0", n)
	}
}

func TestSetBoxesRejectsMalformedInput(t *testing.T) {
	c := newClock()
	tgt := nodeTarget("remote-a", "pve1")
	r := newRig(t, lease("g1", true, c, tgt))
	v := mustViewer(t)
	if _, err := r.hub.Add(v, "s"); err != nil {
		t.Fatal(err)
	}
	many := map[string][]pvecollect.TelemetryTarget{}
	for i := 0; i <= maxViewerBoxes; i++ {
		many["node:n"+strconv.Itoa(i)] = []pvecollect.TelemetryTarget{tgt}
	}
	tooManyTargets := make([]pvecollect.TelemetryTarget, maxTargetsPerBox+1)
	for i := range tooManyTargets {
		tooManyTargets[i] = tgt
	}
	for name, boxes := range map[string]map[string][]pvecollect.TelemetryTarget{
		"too many boxes":   many,
		"too many targets": {"node:pve1": tooManyTargets},
		"bad box id":       {"node:pve1\nevent: x": {tgt}},
	} {
		if _, err := r.hub.SetBoxes(v, "s", boxes); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := r.hub.SetBoxes("not-a-viewer", "s", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad viewer id: err = %v, want ErrInvalid", err)
	}
}

// recSched records Request/Release calls and grants everything.
type recSched struct {
	mu       sync.Mutex
	active   map[string]map[pvecollect.TelemetryTarget]bool
	last     map[pvecollect.TelemetryTarget]time.Time
	requests int
}

func newRecSched() *recSched {
	return &recSched{active: map[string]map[pvecollect.TelemetryTarget]bool{}, last: map[pvecollect.TelemetryTarget]time.Time{}}
}

func (s *recSched) Request(v string, t pvecollect.TelemetryTarget) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if s.active[v] == nil {
		s.active[v] = map[pvecollect.TelemetryTarget]bool{}
	}
	s.active[v][t] = true
	return time.Time{}, nil
}

func (s *recSched) Release(v string, t pvecollect.TelemetryTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active[v], t)
}

func (s *recSched) LastObserved(t pvecollect.TelemetryTarget) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, ok := s.last[t]
	return ts, ok
}

func (s *recSched) activeCount(v string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active[v])
}

func newRecHub(t *testing.T) (*Hub, *recSched, *clock) {
	t.Helper()
	c := newClock()
	s := newRecSched()
	h, err := NewHub(s, nil, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, s, c
}

func TestHiddenBoxIsReleased(t *testing.T) {
	h, s, _ := newRecHub(t)
	v := mustViewer(t)
	if _, err := h.Add(v, "s"); err != nil {
		t.Fatal(err)
	}
	a, b := nodeTarget("remote-a", "pve1"), nodeTarget("remote-a", "pve2")
	if _, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{"node:pve1": {a}, "node:pve2": {b}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{"node:pve1": {a}}); err != nil {
		t.Fatal(err)
	}
	if s.active[v][b] || !s.active[v][a] {
		t.Fatalf("after hiding pve2: active = %v", s.active[v])
	}
	// Hidden page: empty list releases everything.
	if _, err := h.SetBoxes(v, "s", nil); err != nil {
		t.Fatal(err)
	}
	if n := s.activeCount(v); n != 0 {
		t.Fatalf("after hiding the page: %d targets still requested", n)
	}
}

func TestDisconnectReleasesAllTargets(t *testing.T) {
	h, s, _ := newRecHub(t)
	v := mustViewer(t)
	ch, _ := h.Add(v, "s")
	if _, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{
		"node:pve1": {nodeTarget("remote-a", "pve1")}, "host:web01": {hostTarget("web01")},
	}); err != nil {
		t.Fatal(err)
	}
	h.Remove(v)
	if n := s.activeCount(v); n != 0 {
		t.Fatalf("after disconnect: %d targets still requested", n)
	}
	if _, ok := <-ch; ok {
		t.Fatal("channel still open after Remove")
	}
	if _, err := h.SetBoxes(v, "s", nil); !errors.Is(err, ErrUnknownViewer) {
		t.Fatalf("SetBoxes after disconnect: err = %v, want ErrUnknownViewer", err)
	}
}

func TestUnrenewedViewerExpiresAfterThirtySeconds(t *testing.T) {
	h, s, c := newRecHub(t)
	v := mustViewer(t)
	ch, _ := h.Add(v, "s")
	tgt := nodeTarget("remote-a", "pve1")
	if _, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{"node:pve1": {tgt}}); err != nil {
		t.Fatal(err)
	}
	// Renewed inside the lease: kept.
	c.Advance(20 * time.Second)
	if _, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{"node:pve1": {tgt}}); err != nil {
		t.Fatal(err)
	}
	c.Advance(25 * time.Second)
	h.Tick()
	if n := s.activeCount(v); n != 1 {
		t.Fatalf("renewed viewer: %d targets requested, want 1", n)
	}
	// Not renewed for more than 30 s: released, and samples stop.
	c.Advance(10 * time.Second)
	h.Record(pvecollect.TelemetrySample{Target: tgt, Metric: pvecollect.TelemetryMetricCPU, Value: 0.5, Live: true, ObservedAt: c.Now()})
	if evs := drain(ch); len(evs) != 0 {
		t.Fatalf("expired viewer received %v", evs)
	}
	h.Tick()
	if n := s.activeCount(v); n != 0 {
		t.Fatalf("expired viewer: %d targets still requested", n)
	}
	// The next renewal re-requests.
	if got, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{"node:pve1": {tgt}}); err != nil || len(got) != 1 {
		t.Fatalf("renewal after expiry = %v, %v", got, err)
	}
}

func TestDeferredBoxShowsAge(t *testing.T) {
	h, s, c := newRecHub(t)
	v := mustViewer(t)
	ch, _ := h.Add(v, "s")
	fresh, stale := nodeTarget("remote-a", "pve1"), nodeTarget("remote-a", "pve2")
	never := nodeTarget("remote-a", "pve3")
	s.last[fresh] = c.Now().Add(-5 * time.Second)
	s.last[stale] = c.Now().Add(-90 * time.Second)
	if _, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{
		"node:pve1": {fresh}, "node:pve2": {stale}, "node:pve3": {never},
	}); err != nil {
		t.Fatal(err)
	}
	h.Tick()
	evs := drain(ch)
	if len(evs) != 1 || evs[0].Name != "age" {
		t.Fatalf("events = %v, want one age label", evs)
	}
	var p struct {
		ID  string `json:"id"`
		Age int    `json:"age"`
	}
	if err := json.Unmarshal(evs[0].Data, &p); err != nil {
		t.Fatal(err)
	}
	if p.ID != "node:pve2" || p.Age != 90 {
		t.Fatalf("age label = %+v, want node:pve2 90", p)
	}
}

func TestStreamLimits(t *testing.T) {
	h, _, _ := newRecHub(t)
	for i := 0; i < maxViewersPerSession; i++ {
		if _, err := h.Add(mustViewer(t), "s"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Add(mustViewer(t), "s"); !errors.Is(err, ErrTooManyViewers) {
		t.Fatalf("per-session limit: err = %v", err)
	}
	if _, err := h.Add(mustViewer(t), "other"); err != nil {
		t.Fatalf("other session refused: %v", err)
	}
	if _, err := h.Add("short", "s2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad viewer id: err = %v", err)
	}
	if _, err := h.Add(mustViewer(t), ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty session: err = %v", err)
	}
}

func TestFullQueueDoesNotBlock(t *testing.T) {
	h, _, c := newRecHub(t)
	v := mustViewer(t)
	if _, err := h.Add(v, "s"); err != nil {
		t.Fatal(err)
	}
	tgt := nodeTarget("remote-a", "pve1")
	if _, err := h.SetBoxes(v, "s", map[string][]pvecollect.TelemetryTarget{"node:pve1": {tgt}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < viewerEventQueue*3; i++ {
			h.Record(pvecollect.TelemetrySample{Target: tgt, Metric: pvecollect.TelemetryMetricCPU, Value: 0.5, Live: true, ObservedAt: c.Now()})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a full viewer queue")
	}
}
