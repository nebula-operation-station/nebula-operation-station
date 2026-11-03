// SPDX-License-Identifier: AGPL-3.0-or-later

// Collector-side live reads for visible node/guest boxes (spec 12
// "Visible-target requests", spec 17 "SSH/provider telemetry leases").
//
// The LiveWatcher turns the server's want-list into live provider metrics
// reads. The want-list adds no authority: a wanted box is read only if an
// on-demand provider_telemetry lease the collector derived itself from the
// executor's approved read grants lists it exactly, and its remote is
// currently configured and active. All reads go through the watcher's own
// TelemetryScheduler, so ProviderMetricsSpacing, the live target cap and the
// leases' run budgets apply to the live reads; that scheduler does not share
// its spacing or budget counters with other schedulers in the process. A
// box's last read and an executor refusal are remembered across want-list
// changes, so a churning want-list cannot shorten the grant's MinInterval or
// the live cadence, nor retry a refused box early. The executor
// re-authorizes every read.

package pvecollect

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	// liveDenyBackoff is how long a box the executor refused under a grant
	// version (PermissionDenied, NotFound) is not read again under it.
	liveDenyBackoff = 5 * time.Minute
	// maxLiveCadenceEntries bounds the remembered reads and the remembered
	// refusals each.
	maxLiveCadenceEntries = MaxTelemetryTargets
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
	cad   *liveCadence
	now   func() time.Time
	log   *slog.Logger

	// State owned by the Run goroutine.
	refreshed   bool
	lastRefresh time.Time
	remotes     map[string]bool  // active remote IDs at the last refresh
	leases      []TelemetryLease // on-demand provider leases at the last refresh
	leaseSig    string           // signature of the leases given to the scheduler
	refusedSig  string           // signature of a lease set SetLeases refused
	active      map[string]TelemetryTarget
	refused     map[string]bool // targets whose viewer request was refused
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
	cad := newLiveCadence()
	reader := liveReader{r: ProviderTelemetryReader{Reader: exec}, cad: cad, now: cfg.Now}
	sched, err := NewTelemetryScheduler(reader, sink, TelemetryConfig{Now: cfg.Now})
	if err != nil {
		return nil, fmt.Errorf("pvecollect: live scheduler: %w", err)
	}
	return &LiveWatcher{
		exec: exec, h: h, sched: sched, sink: sink, cad: cad, now: cfg.Now, log: cfg.Log,
		active: map[string]TelemetryTarget{}, refused: map[string]bool{},
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
	w.cad.prune(now)
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
	w.apply(w.effective(want, now), now)
	w.flush(ctx, now)
	w.sched.start(ctx, wg)
}

// stop drops every live target: no further reads, in-flight reads are
// cancelled and their results discarded.
func (w *LiveWatcher) stop(ctx context.Context) {
	now := w.now()
	w.apply(nil, now)
	w.flush(ctx, now)
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
	w.cad.setGrants(w.leases)
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
// the targets that may be read now and one renewed viewer request per
// target. A target that is not already being served waits until its last
// read (remembered across want-list changes) is max(TelemetryLiveInterval,
// MinInterval) old; a target the executor refused under a grant version is
// left out of that lease until its backoff ends.
func (w *LiveWatcher) apply(eff map[string]TelemetryTarget, now time.Time) {
	ready := map[string]TelemetryTarget{}
	for k, t := range eff {
		iv, ok := w.liveInterval(t, now)
		if !ok {
			continue
		}
		if _, served := w.active[k]; !served && !w.cad.due(t, iv, now) {
			continue
		}
		ready[k] = t
	}
	var leases []TelemetryLease
	for _, l := range w.leases {
		var ts []TelemetryTarget
		for _, t := range l.Targets {
			if _, ok := ready[t.key()]; ok && !w.cad.isDenied(t, l.GrantID, l.GrantDigest, now) {
				ts = append(ts, t)
			}
		}
		if len(ts) == 0 {
			continue
		}
		l.Targets = ts
		leases = append(leases, l)
	}
	if sig := leaseSignature(leases); sig != w.leaseSig {
		if sig == w.refusedSig {
			w.dropAll()
			return
		}
		if err := w.sched.SetLeases(leases); err != nil {
			// Logged once per refused set; retried only when it changes.
			w.log.Warn("live leases refused", "error", err)
			w.refusedSig = sig
			w.dropAll()
			return
		}
		w.leaseSig, w.refusedSig = sig, ""
	}
	w.sink.setWanted(eff)
	for k, t := range w.active {
		if _, ok := ready[k]; !ok {
			w.sched.Release(liveViewerID, t)
		}
	}
	w.active = map[string]TelemetryTarget{}
	refused := map[string]bool{}
	var firstErr error
	for k, t := range ready {
		if _, err := w.sched.Request(liveViewerID, t); err != nil {
			refused[k] = true
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		w.active[k] = t
	}
	if len(refused) > 0 && !maps.Equal(refused, w.refused) {
		w.log.Warn("live target requests refused", "targets", len(refused), "error", firstErr)
	}
	w.refused = refused
}

// dropAll clears the scheduler's leases and every live target.
func (w *LiveWatcher) dropAll() {
	if w.leaseSig != "" {
		_ = w.sched.SetLeases(nil)
		w.leaseSig = ""
	}
	w.sink.setWanted(nil)
	w.active = map[string]TelemetryTarget{}
}

// liveInterval returns the read spacing of t: max(TelemetryLiveInterval,
// the largest MinInterval of the leases listing t that have not been
// refused for it). ok is false when no such lease exists.
func (w *LiveWatcher) liveInterval(t TelemetryTarget, now time.Time) (iv time.Duration, ok bool) {
	iv = TelemetryLiveInterval
	k := t.key()
	for i := range w.leases {
		l := &w.leases[i]
		if !slices.ContainsFunc(l.Targets, func(x TelemetryTarget) bool { return x.key() == k }) ||
			w.cad.isDenied(t, l.GrantID, l.GrantDigest, now) {
			continue
		}
		iv, ok = max(iv, l.MinInterval), true
	}
	return iv, ok
}

// leaseSignature identifies a lease set so the scheduler is only updated
// when it changes. SetLeases resets the scheduler's executor-refusal
// memory; the watcher keeps its own in liveCadence.
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
		if err != nil {
			if !errors.Is(err, io.EOF) {
				w.log.Warn("sweep live directory", "error", err)
			}
			break
		}
		if len(names) < liveDirBatch {
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

// liveReader wraps the provider reader and remembers each read and each
// executor refusal in the watcher's cadence state.
type liveReader struct {
	r   TelemetryReader
	cad *liveCadence
	now func() time.Time
}

// ReadTelemetry records the read, performs it and records a refusal.
func (l liveReader) ReadTelemetry(ctx context.Context, read TelemetryRead) ([]TelemetrySample, error) {
	l.cad.noteRead(read, l.now())
	smp, err := l.r.ReadTelemetry(ctx, read)
	if err != nil {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.NotFound:
			l.cad.noteDenied(read, l.now())
		}
	}
	return smp, err
}

// liveRead is the last read of one target.
type liveRead struct {
	at        time.Time // when the read started
	holdUntil time.Time // earliest next read under the interval at that time
}

// liveGrant is what the cadence state needs of a current lease.
type liveGrant struct {
	digest      string
	minInterval time.Duration
}

// liveCadence is the per-target read cadence and executor-refusal memory
// of the live watcher. It is keyed by the exact target identity and
// independent of the want-list, bounded, and aged out once an entry can no
// longer delay a read. It is safe for concurrent use.
type liveCadence struct {
	mu     sync.Mutex
	reads  map[string]liveRead  // target key → last read
	denied map[string]time.Time // grant ID, digest, target key → refused until
	grants map[string]liveGrant // grant ID → current lease facts
}

func newLiveCadence() *liveCadence {
	return &liveCadence{reads: map[string]liveRead{}, denied: map[string]time.Time{}, grants: map[string]liveGrant{}}
}

func deniedKey(t TelemetryTarget, grantID, digest string) string {
	return grantID + "\x00" + digest + "\x00" + t.key()
}

// setGrants records the current leases' digests and minimum intervals.
func (c *liveCadence) setGrants(ls []TelemetryLease) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grants = make(map[string]liveGrant, len(ls))
	for _, l := range ls {
		c.grants[l.GrantID] = liveGrant{digest: l.GrantDigest, minInterval: l.MinInterval}
	}
}

// noteRead records a read issued under read.GrantID at now.
func (c *liveCadence) noteRead(read TelemetryRead, now time.Time) {
	c.mu.Lock()
	g := c.grants[read.GrantID]
	c.mu.Unlock()
	c.recordRead(read.Target, max(TelemetryLiveInterval, g.minInterval), now)
}

// noteDenied records an executor refusal of read at now.
func (c *liveCadence) noteDenied(read TelemetryRead, now time.Time) {
	c.mu.Lock()
	g := c.grants[read.GrantID]
	c.mu.Unlock()
	c.recordDenied(read.Target, read.GrantID, g.digest, now)
}

// recordRead remembers a read of t at now that holds the next read back
// for interval. When full, the entry that expires first is evicted.
func (c *liveCadence) recordRead(t TelemetryTarget, interval time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := t.key()
	hold := now.Add(interval)
	if e, ok := c.reads[k]; ok && e.holdUntil.After(hold) {
		hold = e.holdUntil
	}
	if _, ok := c.reads[k]; !ok && len(c.reads) >= maxLiveCadenceEntries {
		evictFirst(c.reads, func(e liveRead) time.Time { return e.holdUntil })
	}
	c.reads[k] = liveRead{at: now, holdUntil: hold}
}

// recordDenied remembers that the executor refused t under the grant
// version until now+liveDenyBackoff. When full, the entry that expires
// first is evicted.
func (c *liveCadence) recordDenied(t TelemetryTarget, grantID, digest string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := deniedKey(t, grantID, digest)
	if _, ok := c.denied[k]; !ok && len(c.denied) >= maxLiveCadenceEntries {
		evictFirst(c.denied, func(u time.Time) time.Time { return u })
	}
	c.denied[k] = now.Add(liveDenyBackoff)
}

// evictFirst deletes the entry of m with the earliest expiry.
func evictFirst[V any](m map[string]V, expiry func(V) time.Time) {
	first, found := "", false
	var at time.Time
	for k, v := range m {
		if e := expiry(v); !found || e.Before(at) || e.Equal(at) && k < first {
			first, at, found = k, e, true
		}
	}
	if found {
		delete(m, first)
	}
}

// isDenied reports whether the executor refused t under the grant version
// and the backoff has not ended at now.
func (c *liveCadence) isDenied(t TelemetryTarget, grantID, digest string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.denied[deniedKey(t, grantID, digest)]
	return ok && now.Before(u)
}

// due reports whether t may be read at now: its last read is at least
// interval old and its hold has ended. A clock step backwards restarts the
// hold at now instead of reading early.
func (c *liveCadence) due(t TelemetryTarget, interval time.Duration, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := t.key()
	e, ok := c.reads[k]
	if !ok {
		return true
	}
	if now.Before(e.at) {
		c.reads[k] = liveRead{at: now, holdUntil: now.Add(e.holdUntil.Sub(e.at))}
		return false
	}
	return !now.Before(e.holdUntil) && now.Sub(e.at) >= interval
}

// prune forgets reads whose hold has ended and refusals whose backoff has
// ended at now.
func (c *liveCadence) prune(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.reads {
		if !now.Before(e.holdUntil) && !now.Before(e.at) {
			delete(c.reads, k)
		}
	}
	for k, u := range c.denied {
		if !now.Before(u) {
			delete(c.denied, k)
		}
	}
}
