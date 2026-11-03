// SPDX-License-Identifier: AGPL-3.0-or-later

// Collector-side live reads for visible node/guest boxes (spec 12
// "Visible-target requests", spec 17 "SSH/provider telemetry leases").
//
// The LiveWatcher turns the server's want-list into live provider metrics
// reads. The want-list adds no authority: a wanted box is read only if an
// on-demand provider_telemetry lease the collector derived itself from the
// executor's approved read grants lists it exactly, and its remote is
// currently configured and active. All reads go through the shared
// TelemetryScheduler, so ProviderMetricsSpacing, the live target cap and the
// leases' run budgets apply. The executor re-authorizes every read.

package pvecollect

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Live watcher limits.
const (
	// liveWatchTick paces the watcher: the want-list is read every second.
	liveWatchTick = time.Second
	// liveLeaseRefresh is the minimum spacing of two lease refreshes
	// (ListPVERemotes and ListReadGrants).
	liveLeaseRefresh = 10 * time.Second
	// liveCallTimeout bounds one executor list call.
	liveCallTimeout = 10 * time.Second
	// liveSampleMaxAge drops a published sample that has not been renewed
	// for three live intervals (failing or deferred reads).
	liveSampleMaxAge = 3 * TelemetryLiveInterval
	// maxLiveDirEntries bounds the live directory entries one sweep reads.
	maxLiveDirEntries = 4096
	// liveDirBatch is the batch size of one directory read.
	liveDirBatch = 256
	// liveViewerID is the scheduler viewer that stands for the want-list.
	liveViewerID = "live-want"
)

// errLiveUnwanted is returned by the live sink for a sample of a target that
// is not in the current effective target set.
var errLiveUnwanted = errors.New("pvecollect: live sample of an unwanted target")

// LiveExecutor is the executor surface the live watcher uses: the provider
// reads plus the approved read-grant registry.
type LiveExecutor interface {
	Reader
	ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListReadGrantsResponse, error)
}

// LiveWatcherConfig carries the live watcher's tunables.
type LiveWatcherConfig struct {
	// Now returns the current time; defaults to time.Now.
	Now func() time.Time
	// Log receives operational messages; defaults to slog.Default().
	Log *slog.Logger
}

// LiveWatcher serves the live want-list with on-demand provider reads and
// publishes the samples per remote. Run drives it; it is not safe to run
// twice concurrently.
type LiveWatcher struct {
	exec  LiveExecutor
	h     *LiveHandoff
	sched *TelemetryScheduler
	sink  *liveSink
	now   func() time.Time
	log   *slog.Logger

	// State owned by the Run goroutine.
	refreshed   bool
	lastRefresh time.Time
	remotes     map[string]bool  // active remote IDs at the last refresh
	leases      []TelemetryLease // on-demand provider leases at the last refresh
	leaseSig    string           // signature of the leases given to the scheduler
	active      map[string]TelemetryTarget
}

// NewLiveWatcher builds a live watcher reading through exec and publishing
// through h.
func NewLiveWatcher(exec LiveExecutor, h *LiveHandoff, cfg LiveWatcherConfig) (*LiveWatcher, error) {
	if exec == nil || h == nil {
		return nil, fmt.Errorf("%w: executor and live handoff are required", ErrTelemetryInvalid)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	sink := &liveSink{wanted: map[string]TelemetryTarget{}, entries: map[string]*liveEntry{}, dirty: map[string]bool{}}
	sched, err := NewTelemetryScheduler(ProviderTelemetryReader{Reader: exec}, sink, TelemetryConfig{Now: cfg.Now})
	if err != nil {
		return nil, fmt.Errorf("pvecollect: live scheduler: %w", err)
	}
	return &LiveWatcher{
		exec: exec, h: h, sched: sched, sink: sink, now: cfg.Now, log: cfg.Log,
		active: map[string]TelemetryTarget{},
	}, nil
}

// Run serves the want-list every second until ctx is cancelled. On return
// all reads have finished and the published samples are removed.
func (w *LiveWatcher) Run(ctx context.Context) error {
	t := time.NewTicker(liveWatchTick)
	defer t.Stop()
	var wg sync.WaitGroup
	for ctx.Err() == nil {
		w.step(ctx, &wg)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
	// stop cancels the in-flight reads; once they have finished, sweep the
	// samples files again in case a read completed during the first sweep.
	w.stop(context.WithoutCancel(ctx))
	wg.Wait()
	w.sweep(context.WithoutCancel(ctx), nil)
	return nil
}

// step performs one pass: read the want-list, refresh the leases when due,
// derive the effective targets, publish finished samples and start the reads
// that are due. Reads run in goroutines tracked by wg.
func (w *LiveWatcher) step(ctx context.Context, wg *sync.WaitGroup) {
	now := w.now()
	want, err := w.h.ReadLiveWant(ctx)
	if err != nil {
		w.log.Warn("live want-list refused", "error", err)
		want = pvecontract.LiveWant{}
	}
	if len(want.Targets) == 0 || !want.Live(now.Unix()) {
		w.stop(ctx) // flush sweeps every samples file
		return
	}
	if !w.refreshed || now.Before(w.lastRefresh) || now.Sub(w.lastRefresh) >= liveLeaseRefresh {
		w.refresh(ctx, now)
	}
	w.apply(w.effective(want, now))
	w.flush(ctx, now)
	w.sched.start(ctx, wg)
}

// stop drops every live target: no further reads, in-flight reads are
// cancelled and their results discarded.
func (w *LiveWatcher) stop(ctx context.Context) {
	w.apply(nil)
	w.flush(ctx, w.now())
}

// refresh re-derives the on-demand provider leases from the executor's
// approved read grants and the current remote list. Any failure drops all
// leases (fail closed) until the next refresh.
func (w *LiveWatcher) refresh(ctx context.Context, now time.Time) {
	w.refreshed, w.lastRefresh = true, now
	w.remotes, w.leases = nil, nil
	cctx, cancel := context.WithTimeout(ctx, liveCallTimeout)
	defer cancel()
	rs, err := w.exec.ListPVERemotes(cctx, &pb.ListPVERemotesRequest{})
	if err != nil {
		w.log.Warn("live lease refresh: list remotes", "code", status.Code(err).String())
		return
	}
	gs, err := w.exec.ListReadGrants(cctx, &pb.ListReadGrantsRequest{})
	if err != nil {
		w.log.Warn("live lease refresh: list read grants", "code", status.Code(err).String())
		return
	}
	remotes := map[string]bool{}
	for _, r := range rs.GetRemotes() {
		if r != nil && r.GetState() == pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE && pvecontract.ValidRemoteID(r.GetRemoteId()) {
			remotes[r.GetRemoteId()] = true
		}
	}
	w.remotes = remotes
	w.leases = liveLeases(TelemetryLeasesFromGrants(gs.GetGrants(), TelemetryIdentities{Remotes: rs.GetRemotes()}, now))
}

// liveLeases keeps the on-demand leases and only their provider targets.
// The scheduled trigger is cleared: the live watcher never takes history
// samples.
func liveLeases(ls []TelemetryLease) []TelemetryLease {
	var out []TelemetryLease
	for _, l := range ls {
		if !l.OnDemand {
			continue
		}
		var ts []TelemetryTarget
		for _, t := range l.Targets {
			if t.Source == TelemetryProvider {
				ts = append(ts, t)
			}
		}
		if len(ts) == 0 {
			continue
		}
		l.Scheduled, l.Targets = false, ts
		out = append(out, l)
	}
	return out
}

// effective returns the wanted targets that an on-demand lease covers at now
// and whose remote is configured, keyed by target key. A wanted box listed
// with several guest generations resolves to the newest.
func (w *LiveWatcher) effective(want pvecontract.LiveWant, now time.Time) map[string]TelemetryTarget {
	out := map[string]TelemetryTarget{}
	for _, wt := range want.Targets {
		if !w.remotes[wt.Remote] {
			continue
		}
		var best TelemetryTarget
		found := false
		for i := range w.leases {
			l := &w.leases[i]
			for _, t := range l.Targets {
				if t.RemoteID != wt.Remote || t.Node != wt.Node || t.Kind != wt.Kind || t.VMID != wt.VMID {
					continue
				}
				if !l.covers(t, now) {
					continue
				}
				if !found || t.Generation > best.Generation {
					best, found = t, true
				}
			}
		}
		if found {
			out[best.key()] = best
		}
	}
	return out
}

// apply hands the effective targets to the scheduler: leases restricted to
// those targets and one renewed viewer request per target.
func (w *LiveWatcher) apply(eff map[string]TelemetryTarget) {
	var leases []TelemetryLease
	for _, l := range w.leases {
		var ts []TelemetryTarget
		for _, t := range l.Targets {
			if _, ok := eff[t.key()]; ok {
				ts = append(ts, t)
			}
		}
		if len(ts) == 0 {
			continue
		}
		l.Targets = ts
		leases = append(leases, l)
	}
	if len(eff) == 0 {
		leases = nil
	}
	if sig := leaseSignature(leases); sig != w.leaseSig {
		if err := w.sched.SetLeases(leases); err != nil {
			w.log.Warn("live leases refused", "error", err)
			_ = w.sched.SetLeases(nil)
			w.sink.setWanted(nil)
			w.leaseSig = ""
			w.active = map[string]TelemetryTarget{}
			return
		}
		w.leaseSig = sig
	}
	w.sink.setWanted(eff)
	for k, t := range w.active {
		if _, ok := eff[k]; !ok {
			w.sched.Release(liveViewerID, t)
		}
	}
	w.active = map[string]TelemetryTarget{}
	for k, t := range eff {
		if _, err := w.sched.Request(liveViewerID, t); err != nil {
			w.log.Warn("live target request refused", "remote", t.RemoteID, "error", err)
			continue
		}
		w.active[k] = t
	}
}

// leaseSignature identifies a lease set so the scheduler is only updated
// when it changes (SetLeases resets the executor-refusal memory).
func leaseSignature(ls []TelemetryLease) string {
	parts := make([]string, 0, len(ls))
	for _, l := range ls {
		keys := make([]string, 0, len(l.Targets))
		for _, t := range l.Targets {
			keys = append(keys, t.key())
		}
		slices.Sort(keys)
		parts = append(parts, strings.Join([]string{
			l.GrantID, l.GrantDigest, strconv.FormatInt(l.ExpiresAt.UnixNano(), 10),
			l.MinInterval.String(), strconv.Itoa(l.RunBudget), strings.Join(keys, "\x01"),
		}, "\x02"))
	}
	slices.Sort(parts)
	return strings.Join(parts, "\x03")
}

// flush publishes the changed per-remote samples and removes the files of
// remotes without wanted samples.
func (w *LiveWatcher) flush(ctx context.Context, now time.Time) {
	publish, keep := w.sink.take(now)
	remotes := make([]string, 0, len(publish))
	for r := range publish {
		remotes = append(remotes, r)
	}
	slices.Sort(remotes)
	for _, r := range remotes {
		if err := w.h.WriteLiveSamples(ctx, pvecontract.LiveSamples{
			Version: pvecontract.LiveSamplesVersion, Remote: r, WrittenUnix: now.Unix(), Samples: publish[r],
		}); err != nil {
			w.log.Warn("publish live samples", "remote", r, "error", err)
			w.sink.markDirty(r)
		}
	}
	w.sweep(ctx, keep)
}

// sweep removes every live/<remote>.json whose remote is not in keep. Other
// entries are left alone.
func (w *LiveWatcher) sweep(ctx context.Context, keep map[string]bool) {
	fd, err := unix.Openat(int(w.h.liveDir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		w.log.Warn("sweep live directory", "error", err)
		return
	}
	dir := os.NewFile(uintptr(fd), liveDirName)
	defer dir.Close()
	var stale []string
	for n := 0; n < maxLiveDirEntries; n += liveDirBatch {
		names, err := dir.Readdirnames(liveDirBatch)
		for _, name := range names {
			remote, ok := strings.CutSuffix(name, ".json")
			if ok && pvecontract.ValidRemoteID(remote) && !keep[remote] {
				stale = append(stale, remote)
			}
		}
		if errors.Is(err, io.EOF) || len(names) < liveDirBatch {
			break
		}
		if err != nil {
			w.log.Warn("sweep live directory", "error", err)
			break
		}
	}
	for _, r := range stale {
		if err := w.h.RemoveLiveSamples(ctx, r); err != nil && !errors.Is(err, unix.ENOENT) {
			w.log.Warn("remove live samples", "remote", r, "error", err)
		}
	}
}

// liveEntry is the latest live sample of one wanted target.
type liveEntry struct {
	remote string
	sample pvecontract.LiveSample
	hasCPU bool
}

// liveSink collects live samples of the wanted targets. It is the
// scheduler's sink and safe for concurrent use.
type liveSink struct {
	mu      sync.Mutex
	wanted  map[string]TelemetryTarget
	entries map[string]*liveEntry
	dirty   map[string]bool
}

// RecordTelemetry stores one live sample of a wanted provider target. The
// RAM fraction is published as mem_used of mem_total 1; a total of 0 means
// unknown.
func (s *liveSink) RecordTelemetry(_ context.Context, smp TelemetrySample) error {
	t := smp.Target
	if t.Source != TelemetryProvider || !smp.Live {
		return errLiveUnwanted
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := t.key()
	if _, ok := s.wanted[k]; !ok {
		return errLiveUnwanted
	}
	e, ok := s.entries[k]
	if !ok {
		e = &liveEntry{remote: t.RemoteID, sample: pvecontract.LiveSample{Kind: t.Kind, Node: t.Node, VMID: t.VMID}}
		s.entries[k] = e
	}
	switch smp.Metric {
	case TelemetryMetricCPU:
		e.sample.CPU, e.hasCPU = smp.Value, true
	case TelemetryMetricRAM:
		e.sample.MemUsed, e.sample.MemTotal = smp.Value, 1
	default:
		return nil
	}
	e.sample.ObservedUnix = smp.ObservedAt.Unix()
	s.dirty[t.RemoteID] = true
	return nil
}

// setWanted replaces the wanted targets and forgets samples of the others.
func (s *liveSink) setWanted(eff map[string]TelemetryTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wanted = make(map[string]TelemetryTarget, len(eff))
	for k, t := range eff {
		s.wanted[k] = t
	}
	for k, e := range s.entries {
		if _, ok := s.wanted[k]; !ok {
			delete(s.entries, k)
			s.dirty[e.remote] = true
		}
	}
}

// markDirty schedules remote for republishing.
func (s *liveSink) markDirty(remote string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty[remote] = true
}

// take drops samples older than liveSampleMaxAge and returns the samples
// of the changed remotes to publish and the set of remotes that still have
// samples.
func (s *liveSink) take(now time.Time) (map[string][]pvecontract.LiveSample, map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-liveSampleMaxAge).Unix()
	keep := map[string]bool{}
	byRemote := map[string][]pvecontract.LiveSample{}
	for k, e := range s.entries {
		if e.sample.ObservedUnix < cutoff {
			delete(s.entries, k)
			s.dirty[e.remote] = true
			continue
		}
		if !e.hasCPU {
			continue
		}
		keep[e.remote] = true
		byRemote[e.remote] = append(byRemote[e.remote], e.sample)
	}
	publish := map[string][]pvecontract.LiveSample{}
	for r := range s.dirty {
		if !keep[r] {
			continue
		}
		smp := byRemote[r]
		slices.SortFunc(smp, func(a, b pvecontract.LiveSample) int {
			return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Node, b.Node), cmp.Compare(a.VMID, b.VMID))
		})
		if len(smp) > pvecontract.MaxLiveSamples {
			smp = smp[:pvecontract.MaxLiveSamples]
		}
		publish[r] = smp
	}
	s.dirty = map[string]bool{}
	return publish, keep
}
