// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/live"
)

// liveLeaseRefresh is how often the live chart re-reads the approved
// telemetry grants (a revoked or expired grant stops reads within it;
// the executor refuses such reads immediately regardless).
const liveLeaseRefresh = 30 * time.Second

// Provider live handoff (ADR 0006 P1-37): the server never reads
// provider metrics itself; it publishes the visible provider targets to
// the collector's want-list and reads the collector's per-remote samples.
const (
	// liveHandoffRoot is the collector's spool root holding requests/
	// and live/ (nebula-pve-collector's default -spool).
	liveHandoffRoot = "/var/lib/nebula/pve"
	// liveProviderTick is the cadence of want-list updates and sample
	// polls; the want-list is written at most once per tick.
	liveProviderTick = time.Second
	// liveWantExpiry is how long one written want-list stays in force.
	liveWantExpiry = pvecontract.LiveWantMaxExpiry * time.Second
	// liveWantRefresh rewrites an unchanged want-list well inside
	// liveWantExpiry, so a live target never lapses while visible.
	liveWantRefresh = 10 * time.Second
	// liveShutdownTimeout bounds the final empty want-list on shutdown.
	liveShutdownTimeout = 2 * time.Second
)

// liveExecutor is the executor surface of the live chart (server role).
// It deliberately has no ReadPVE: provider metrics come from the
// collector handoff.
type liveExecutor interface {
	ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListReadGrantsResponse, error)
	ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error)
	ListPVERemotes(ctx context.Context, in *pb.ListPVERemotesRequest, opts ...grpc.CallOption) (*pb.ListPVERemotesResponse, error)
	RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error)
}

// liveHandoff is the server side of the collector's live handoff
// (*pvecollect.LiveHandoff).
type liveHandoff interface {
	WriteLiveWant(ctx context.Context, want pvecontract.LiveWant) error
	ReadLiveSamples(ctx context.Context, remoteID string) (pvecontract.LiveSamples, error)
}

// liveChart is the wired live chart delivery (ADR 0006 P1-37).
type liveChart struct {
	handler *live.Handler
	hub     *live.Hub
	sched   *pvecollect.TelemetryScheduler
	prov    *liveScheduler
	exec    liveExecutor
	log     *slog.Logger
	now     func() time.Time
	leases  atomic.Pointer[[]pvecollect.TelemetryLease]

	// handoffRoot is liveHandoffRoot.
	handoffRoot string
	// Want-list writer state; only the provider loop touches it.
	wantSig   string
	wantAt    time.Time
	wantFail  bool
	pollFails map[string]bool
}

// hubSink forwards scheduler samples to the hub, which is built after
// the scheduler (the hub needs the scheduler for its requests).
type hubSink struct{ hub *live.Hub }

func (s *hubSink) RecordTelemetry(ctx context.Context, smp pvecollect.TelemetrySample) error {
	return s.hub.RecordTelemetry(ctx, smp)
}

// newLiveChart builds the live chart: an on-demand-only telemetry
// scheduler over SSH telemetry reads, the provider handoff, the fan-out
// hub and the handler. recheck re-validates an open stream's session
// without recording activity (live.PeekSession over the web session
// store).
func newLiveChart(exec liveExecutor, hosts pvecollect.TelemetryHosts, tree func(context.Context) (pveinventory.Tree, error),
	recheck func(context.Context, *http.Request) (time.Time, bool), log *slog.Logger) (*liveChart, error) {
	return buildLiveChart(exec, hosts, tree, recheck, log, nil, time.Now)
}

// buildLiveChart is newLiveChart with the session key (nil: the web
// session) and the clock injected.
func buildLiveChart(exec liveExecutor, hosts pvecollect.TelemetryHosts, tree func(context.Context) (pveinventory.Tree, error),
	recheck func(context.Context, *http.Request) (time.Time, bool), log *slog.Logger,
	session func(*http.Request) (string, bool), now func() time.Time) (*liveChart, error) {
	lc := &liveChart{exec: exec, log: log, now: now, handoffRoot: liveHandoffRoot, pollFails: map[string]bool{}}
	lc.leases.Store(&[]pvecollect.TelemetryLease{})
	sink := &hubSink{}
	sched, err := pvecollect.NewTelemetryScheduler(pvecollect.SSHTelemetryReader{Exec: exec, Hosts: hosts}, sink, pvecollect.TelemetryConfig{})
	if err != nil {
		return nil, fmt.Errorf("live chart scheduler: %w", err)
	}
	lc.prov = &liveScheduler{
		ssh: sched, now: now,
		leases: func() []pvecollect.TelemetryLease { return *lc.leases.Load() },
		reqs:   map[pvecollect.TelemetryTarget]map[string]time.Time{},
		last:   map[pvecollect.TelemetryTarget]time.Time{},
	}
	hub, err := live.NewHub(lc.prov, log, now)
	if err != nil {
		return nil, fmt.Errorf("live chart hub: %w", err)
	}
	sink.hub = hub
	h, err := live.New(live.Options{
		Hub: hub,
		Log: log,
		Leases: func(context.Context) ([]pvecollect.TelemetryLease, error) {
			return *lc.leases.Load(), nil
		},
		Tree:    tree,
		Recheck: recheck,
		Session: session,
	})
	if err != nil {
		return nil, fmt.Errorf("live chart handler: %w", err)
	}
	lc.handler, lc.hub, lc.sched = h, hub, sched
	return lc, nil
}

// run refreshes the leases and runs the scheduler, the provider handoff
// and the hub until ctx ends; then it waits for them to stop and every
// viewer is closed.
func (lc *liveChart) run(ctx context.Context) {
	defer lc.hub.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { lc.hub.Start(ctx) })
	wg.Go(func() {
		if err := lc.sched.Run(ctx); err != nil && ctx.Err() == nil {
			lc.log.Error("live chart scheduler stopped", "error", err)
		}
	})
	wg.Go(func() { lc.runProvider(ctx) })
	t := time.NewTicker(liveLeaseRefresh)
	defer t.Stop()
	for {
		lc.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// refresh derives the live leases from the executor's approved grants.
// Any failure clears them (fail closed: no reads without a fresh list).
func (lc *liveChart) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	leases, err := lc.loadLeases(ctx)
	if err != nil {
		lc.log.Warn("live chart: telemetry leases unavailable", "error", err)
		leases = nil
	}
	lc.applyLeases(leases)
}

// applyLeases installs the live leases: the SSH targets go to the SSH
// scheduler, every target to the handler and the provider scheduler.
func (lc *liveChart) applyLeases(leases []pvecollect.TelemetryLease) {
	if err := lc.sched.SetLeases(sshLeases(leases)); err != nil {
		lc.log.Error("live chart: set telemetry leases", "error", err)
		leases = nil
		_ = lc.sched.SetLeases(nil)
	}
	if leases == nil {
		leases = []pvecollect.TelemetryLease{}
	}
	lc.leases.Store(&leases)
}

func (lc *liveChart) loadLeases(ctx context.Context) ([]pvecollect.TelemetryLease, error) {
	resp, err := lc.exec.ListReadGrants(ctx, &pb.ListReadGrantsRequest{})
	if err != nil {
		return nil, fmt.Errorf("list read grants: %w", err)
	}
	keys, err := pvecollect.TelemetryHostKeys(ctx, lc.exec)
	if err != nil {
		return nil, fmt.Errorf("list host keys: %w", err)
	}
	// Without the remote list no provider target matches its trust
	// binding: provider leases drop out, SSH leases stay.
	var remotes []*pb.PVERemoteInfo
	if rr, err := lc.exec.ListPVERemotes(ctx, &pb.ListPVERemotesRequest{}); err != nil {
		lc.log.Warn("live chart: PVE remotes unavailable", "error", err)
	} else {
		remotes = rr.GetRemotes()
	}
	all := pvecollect.TelemetryLeasesFromGrants(resp.GetGrants(), pvecollect.TelemetryIdentities{Remotes: remotes, HostKeys: keys}, lc.now())
	return liveLeases(all), nil
}

// liveLeases keeps what the server may serve live: on-demand leases
// only (no background history reads are started here), with their SSH
// and provider targets. Provider targets are never read by the server
// (ReadPVE is a collector-role RPC); they reach the collector's
// want-list. It never adds a target.
func liveLeases(all []pvecollect.TelemetryLease) []pvecollect.TelemetryLease {
	out := make([]pvecollect.TelemetryLease, 0, len(all))
	for _, l := range all {
		if !l.OnDemand || len(l.Targets) == 0 {
			continue
		}
		l.Scheduled = false
		out = append(out, l)
	}
	return out
}

// sshLeases narrows leases to their SSH targets, the only ones the SSH
// scheduler reads.
func sshLeases(leases []pvecollect.TelemetryLease) []pvecollect.TelemetryLease {
	out := make([]pvecollect.TelemetryLease, 0, len(leases))
	for _, l := range leases {
		var targets []pvecollect.TelemetryTarget
		for _, t := range l.Targets {
			if t.Source == pvecollect.TelemetrySSH {
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			continue
		}
		l.Targets = targets
		out = append(out, l)
	}
	return out
}

// runProvider opens the collector handoff (retrying every
// liveLeaseRefresh while it is missing) and runs providerTick every
// liveProviderTick until ctx ends; then it withdraws the want-list.
func (lc *liveChart) runProvider(ctx context.Context) {
	var h *pvecollect.LiveHandoff
	var tried time.Time
	defer func() {
		if h == nil {
			return
		}
		sctx, cancel := context.WithTimeout(context.Background(), liveShutdownTimeout)
		defer cancel()
		now := lc.now()
		_ = h.WriteLiveWant(sctx, pvecontract.LiveWant{Version: pvecontract.LiveWantVersion, WrittenUnix: now.Unix(), ExpiresUnix: now.Unix()})
		_ = h.Close()
	}()
	t := time.NewTicker(liveProviderTick)
	defer t.Stop()
	for {
		if h == nil && (tried.IsZero() || time.Since(tried) >= liveLeaseRefresh) {
			tried = time.Now()
			var err error
			if h, err = pvecollect.OpenLiveHandoff(lc.handoffRoot); err != nil {
				h = nil
				lc.log.Warn("live chart: provider handoff unavailable", "root", lc.handoffRoot, "error", err)
			}
		}
		if h != nil {
			lc.providerTick(ctx, h)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// providerTick publishes the visible, covered provider targets of all
// viewers and feeds the samples of their remotes to the viewers.
func (lc *liveChart) providerTick(ctx context.Context, h liveHandoff) {
	now := lc.now()
	want := lc.prov.wanted(now)
	lc.writeWant(ctx, h, want, now)
	lc.pollSamples(ctx, h, want, now)
}

// writeWant writes the want-list when its target set changed, or to
// refresh it every liveWantRefresh, but at most once per
// liveProviderTick. No visible target writes an empty list.
func (lc *liveChart) writeWant(ctx context.Context, h liveHandoff, want []pvecollect.TelemetryTarget, now time.Time) {
	targets := make([]pvecontract.LiveTarget, 0, len(want))
	sig := ""
	for _, t := range want {
		lt := pvecontract.LiveTarget{Remote: t.RemoteID, Kind: t.Kind, Node: t.Node, VMID: t.VMID}
		if n := len(targets); n > 0 && targets[n-1] == lt {
			continue // same box, another trust or guest generation
		}
		if len(targets) >= pvecontract.MaxLiveTargets {
			break
		}
		targets = append(targets, lt)
		sig += fmt.Sprintf("%s\x00%s\x00%s\x00%d\x01", lt.Remote, lt.Kind, lt.Node, lt.VMID)
	}
	if !lc.wantAt.IsZero() {
		age := now.Sub(lc.wantAt)
		if age >= 0 && age < liveProviderTick {
			return
		}
		if sig == lc.wantSig && age >= 0 && age < liveWantRefresh {
			return
		}
	}
	err := h.WriteLiveWant(ctx, pvecontract.LiveWant{
		Version:     pvecontract.LiveWantVersion,
		WrittenUnix: now.Unix(),
		ExpiresUnix: now.Add(liveWantExpiry).Unix(),
		Targets:     targets,
	})
	if err != nil {
		if !lc.wantFail {
			lc.log.Warn("live chart: write provider want-list", "error", err)
		}
		lc.wantFail = true
		return
	}
	lc.wantFail = false
	lc.wantSig, lc.wantAt = sig, now
}

// pollSamples reads the samples of every remote with a wanted target and
// records the new ones of exactly the wanted targets through the hub
// (the same path as SSH samples). Samples older than live.StaleAfter
// only move the last-observed time, so the hub labels them with their
// age instead of showing a fresh-looking value.
func (lc *liveChart) pollSamples(ctx context.Context, h liveHandoff, want []pvecollect.TelemetryTarget, now time.Time) {
	byRemote := map[string][]pvecollect.TelemetryTarget{}
	for _, t := range want {
		byRemote[t.RemoteID] = append(byRemote[t.RemoteID], t)
	}
	for _, remote := range slices.Sorted(maps.Keys(byRemote)) {
		doc, err := h.ReadLiveSamples(ctx, remote)
		if err != nil {
			if !lc.pollFails[remote] {
				lc.log.Debug("live chart: provider samples unavailable", "remote", remote, "error", err)
			}
			lc.pollFails[remote] = true
			continue
		}
		delete(lc.pollFails, remote)
		for _, s := range doc.Samples {
			t, ok := matchSample(byRemote[remote], s)
			if !ok {
				continue
			}
			observed := time.Unix(s.ObservedUnix, 0)
			if observed.After(now) {
				observed = now // CheckClock allows a few seconds of skew
			}
			if !lc.prov.observe(t, observed) || now.Sub(observed) > live.StaleAfter {
				continue
			}
			for _, smp := range providerSamples(t, s, observed) {
				lc.hub.Record(smp)
			}
		}
	}
	for remote := range lc.pollFails {
		if _, ok := byRemote[remote]; !ok {
			delete(lc.pollFails, remote)
		}
	}
}

// matchSample returns the single wanted target the sample describes. A
// sample matching several targets (the document carries no trust or
// guest generation) is ambiguous and dropped.
func matchSample(targets []pvecollect.TelemetryTarget, s pvecontract.LiveSample) (pvecollect.TelemetryTarget, bool) {
	var found pvecollect.TelemetryTarget
	n := 0
	for _, t := range targets {
		if t.Node == s.Node && t.Kind == s.Kind && t.VMID == s.VMID {
			found = t
			n++
		}
	}
	return found, n == 1
}

// providerSamples maps one validated handoff sample to the live
// fraction metrics, like pvecollect.ProviderTelemetryReader: CPU and
// memory only (disk figures are allocation, not utilization).
func providerSamples(t pvecollect.TelemetryTarget, s pvecontract.LiveSample, observed time.Time) []pvecollect.TelemetrySample {
	var out []pvecollect.TelemetrySample
	if s.CPU >= 0 && s.CPU <= 1 {
		out = append(out, pvecollect.TelemetrySample{Target: t, Metric: pvecollect.TelemetryMetricCPU, Value: s.CPU, Live: true, ObservedAt: observed})
	}
	if s.MemTotal > 0 && s.MemUsed >= 0 && s.MemUsed <= s.MemTotal {
		out = append(out, pvecollect.TelemetrySample{Target: t, Metric: pvecollect.TelemetryMetricRAM, Value: s.MemUsed / s.MemTotal, Live: true, ObservedAt: observed})
	}
	return out
}

// liveScheduler is the hub's scheduler: SSH targets go to the SSH
// telemetry scheduler unchanged; provider targets are only recorded as
// visible-target requests, each checked against an active on-demand
// lease that lists it exactly. It adds no authority.
type liveScheduler struct {
	ssh    *pvecollect.TelemetryScheduler
	now    func() time.Time
	leases func() []pvecollect.TelemetryLease

	mu    sync.Mutex
	reqs  map[pvecollect.TelemetryTarget]map[string]time.Time // target → viewer → expiry
	nReqs int
	last  map[pvecollect.TelemetryTarget]time.Time // last observed provider sample
}

var _ live.Scheduler = (*liveScheduler)(nil)

// covered reports whether an unexpired on-demand lease lists exactly t.
func (s *liveScheduler) covered(t pvecollect.TelemetryTarget, now time.Time) bool {
	for _, l := range s.leases() {
		if l.OnDemand && now.Before(l.ExpiresAt) && slices.Contains(l.Targets, t) {
			return true
		}
	}
	return false
}

// Request implements live.Scheduler.
func (s *liveScheduler) Request(viewerID string, t pvecollect.TelemetryTarget) (time.Time, error) {
	if t.Source != pvecollect.TelemetryProvider {
		return s.ssh.Request(viewerID, t)
	}
	if viewerID == "" || len(viewerID) > pvecollect.MaxViewerIDBytes || !t.Valid() {
		return time.Time{}, pvecollect.ErrTelemetryInvalid
	}
	now := s.now()
	if !s.covered(t, now) {
		return time.Time{}, pvecollect.ErrTelemetryNotAuthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vs, ok := s.reqs[t]
	if !ok {
		if len(s.reqs) >= pvecontract.MaxLiveTargets {
			return time.Time{}, pvecollect.ErrTelemetryLimit
		}
		vs = map[string]time.Time{}
	}
	if _, ok := vs[viewerID]; !ok {
		if s.nReqs >= pvecollect.MaxTelemetryViewers {
			return time.Time{}, pvecollect.ErrTelemetryLimit
		}
		s.nReqs++
	}
	exp := now.Add(pvecollect.TelemetryViewerRenewal)
	vs[viewerID] = exp
	s.reqs[t] = vs
	return exp, nil
}

// Release implements live.Scheduler.
func (s *liveScheduler) Release(viewerID string, t pvecollect.TelemetryTarget) {
	if t.Source != pvecollect.TelemetryProvider {
		s.ssh.Release(viewerID, t)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(t, viewerID)
}

// dropLocked removes one viewer request; the caller holds s.mu.
func (s *liveScheduler) dropLocked(t pvecollect.TelemetryTarget, viewerID string) {
	vs, ok := s.reqs[t]
	if !ok {
		return
	}
	if _, ok := vs[viewerID]; ok {
		delete(vs, viewerID)
		s.nReqs--
	}
	if len(vs) == 0 {
		delete(s.reqs, t)
		delete(s.last, t)
	}
}

// LastObserved implements live.Scheduler.
func (s *liveScheduler) LastObserved(t pvecollect.TelemetryTarget) (time.Time, bool) {
	if t.Source != pvecollect.TelemetryProvider {
		return s.ssh.LastObserved(t)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, ok := s.last[t]
	return ts, ok
}

// wanted drops expired requests and returns the requested provider
// targets an on-demand lease still covers, sorted by remote, node, kind
// and VMID.
func (s *liveScheduler) wanted(now time.Time) []pvecollect.TelemetryTarget {
	s.mu.Lock()
	var out []pvecollect.TelemetryTarget
	for t, vs := range s.reqs {
		for v, exp := range vs {
			if !now.Before(exp) {
				s.dropLocked(t, v)
			}
		}
		if _, ok := s.reqs[t]; ok {
			out = append(out, t)
		}
	}
	s.mu.Unlock()
	out = slices.DeleteFunc(out, func(t pvecollect.TelemetryTarget) bool { return !s.covered(t, now) })
	slices.SortFunc(out, func(a, b pvecollect.TelemetryTarget) int {
		return cmp.Or(cmp.Compare(a.RemoteID, b.RemoteID), cmp.Compare(a.Node, b.Node), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.VMID, b.VMID), cmp.Compare(a.TrustPin, b.TrustPin),
			cmp.Compare(a.TrustGeneration, b.TrustGeneration), cmp.Compare(a.Generation, b.Generation))
	})
	return out
}

// observe records ts as t's newest observation; it reports false when t
// is no longer requested or ts is not newer than the last one.
func (s *liveScheduler) observe(t pvecollect.TelemetryTarget, ts time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reqs[t]; !ok {
		return false
	}
	if last, ok := s.last[t]; ok && !ts.After(last) {
		return false
	}
	s.last[t] = ts
	return true
}
