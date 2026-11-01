// SPDX-License-Identifier: AGPL-3.0-or-later

// Telemetry collection scheduling (ADR 0006 P1-26; spec 07 "Telemetry
// profile", spec 12 "Visible-target requests", spec 17 "SSH/provider
// telemetry leases").
//
// The TelemetryScheduler decides which metrics reads to issue and when. It
// creates no authority: every read it issues is covered by an approved
// telemetry lease (a read grant with the provider_telemetry or telemetry
// rate profile) that lists the exact target, and the executor re-checks
// that authority and its budgets on every read. The scheduler only avoids
// asking for reads the executor would refuse, keeps within the per-remote
// and per-host budgets, and coalesces work:
//
//   - five-minute history samples only for targets of leases whose trigger
//     includes "scheduled";
//   - ten-second live samples only for targets a viewer currently requests
//     (renewed every 30 s) and whose lease trigger includes "on_demand";
//   - viewer requests must name an exact leased target (remote, trust pin
//     and generation, node, kind, VMID and guest generation; or SSH host,
//     host key and action) and are coalesced per target;
//   - at most four live targets and one metrics request per second per
//     remote, at most one read in flight per SSH host, and each lease's
//     rolling-hour run budget per remote/host;
//   - a live sample in the current five-minute bucket satisfies that
//     bucket's history sample;
//   - Lock and lease expiry/revocation stop new reads, cancel in-flight
//     reads and discard their results.
//
// All timing uses the injected Now; Run's ticker only paces the loop.

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Telemetry limits (spec 07/12/17). Values not fixed by the spec are
// conservative and named here.
const (
	// TelemetryHistoryInterval is the cadence of background history samples.
	TelemetryHistoryInterval = schedgrant.TelemetryHistoryInterval
	// TelemetryLiveInterval is the cadence of live samples of a visible target.
	TelemetryLiveInterval = schedgrant.TelemetryLiveInterval
	// TelemetryViewerRenewal is how long a visible-target request lives
	// without renewal.
	TelemetryViewerRenewal = 30 * time.Second
	// MaxLiveTargetsPerRemote caps concurrently served live targets per remote.
	MaxLiveTargetsPerRemote = 4
	// ProviderMetricsSpacing is the minimum spacing of two metrics requests
	// to one remote (one request per second).
	ProviderMetricsSpacing = time.Second
	// MaxTelemetryRunBudget is the largest rolling-hour run budget a lease
	// may carry per remote or host.
	MaxTelemetryRunBudget = schedgrant.MaxTelemetryRunBudget
	// telemetryBudgetWindow is the rolling budget window.
	telemetryBudgetWindow = time.Hour
	// MaxTelemetryLeases bounds the leases one scheduler holds.
	MaxTelemetryLeases = 256
	// MaxTelemetryTargets bounds the targets across all leases.
	MaxTelemetryTargets = 4096
	// MaxTelemetryViewers bounds the active (viewer, target) requests.
	MaxTelemetryViewers = 1024
	// MaxViewerIDBytes bounds a viewer identifier.
	MaxViewerIDBytes = 128
	// maxGrantIDBytes bounds a lease's grant ID and digest.
	maxGrantIDBytes = 128
	// maxHostIDBytes bounds an SSH host ID, host key fingerprint or action ID.
	maxHostIDBytes = 256
	// MaxSamplesPerRead bounds the samples one read may contribute.
	MaxSamplesPerRead = 16
	// defaultTelemetryTick paces Run.
	defaultTelemetryTick = time.Second
	// defaultTelemetryReadTimeout bounds one telemetry read.
	defaultTelemetryReadTimeout = 30 * time.Second
)

// TelemetrySource is the read path of a telemetry target.
type TelemetrySource int

const (
	// TelemetryProvider is a PVE status read through the executor (ReadPVE
	// METRICS) under a provider_telemetry lease.
	TelemetryProvider TelemetrySource = iota + 1
	// TelemetrySSH is a read-only SSH telemetry action on an enrolled host
	// under a telemetry lease.
	TelemetrySSH
)

// Provider metrics target kinds.
const (
	TelemetryKindNode = "node"
	TelemetryKindQEMU = "qemu"
	TelemetryKindLXC  = "lxc"
)

// Sample metric names: fraction-valued box metrics in [0,1] (P1-25).
const (
	TelemetryMetricCPU  = "cpu"
	TelemetryMetricRAM  = "ram"
	TelemetryMetricDisk = "disk"
)

// TelemetryTarget is one exact telemetry target. Provider targets bind the
// remote with its trust pin and trust generation, the node, the kind, and
// for guests the VMID and local guest generation. SSH targets bind the
// host, its pinned host key and the telemetry action.
type TelemetryTarget struct {
	Source TelemetrySource

	RemoteID        string
	TrustPin        string
	TrustGeneration uint64
	Node            string
	Kind            string
	VMID            uint64
	Generation      uint64

	HostID   string
	HostKey  string
	ActionID string
}

// Valid reports whether t is a well-formed target of its source.
func (t TelemetryTarget) Valid() bool {
	switch t.Source {
	case TelemetryProvider:
		if t.HostID != "" || t.HostKey != "" || t.ActionID != "" {
			return false
		}
		if !pvecontract.ValidRemoteID(t.RemoteID) || !pvecontract.ValidTrustPin(t.TrustPin) || t.TrustGeneration < 1 || !pvecontract.ValidNodeName(t.Node) {
			return false
		}
		switch t.Kind {
		case TelemetryKindNode:
			return t.VMID == 0 && t.Generation == 0
		case TelemetryKindQEMU, TelemetryKindLXC:
			return t.VMID >= pvecontract.MinVMID && t.VMID <= pvecontract.MaxVMID &&
				t.Generation >= 1 && t.Generation <= pvecontract.MaxGuestGeneration
		}
		return false
	case TelemetrySSH:
		if t.RemoteID != "" || t.TrustPin != "" || t.TrustGeneration != 0 || t.Node != "" || t.Kind != "" || t.VMID != 0 || t.Generation != 0 {
			return false
		}
		return boundedText(t.HostID, maxHostIDBytes) && boundedText(t.HostKey, maxHostIDBytes) &&
			schedgrant.IsTelemetryAction(t.ActionID)
	}
	return false
}

// key is the exact identity of t: every bound field takes part, so a
// re-pinned remote, recreated guest or replaced host key is a different
// target.
func (t TelemetryTarget) key() string {
	if t.Source == TelemetryProvider {
		return "pve\x00" + t.RemoteID + "\x00" + t.TrustPin + "\x00" + strconv.FormatUint(t.TrustGeneration, 10) + "\x00" +
			t.Node + "\x00" + t.Kind + "\x00" + strconv.FormatUint(t.VMID, 10) + "\x00" + strconv.FormatUint(t.Generation, 10)
	}
	return "ssh\x00" + t.HostID + "\x00" + t.HostKey + "\x00" + t.ActionID
}

// scope is the budget scope of t: its remote or its host.
func (t TelemetryTarget) scope() string {
	if t.Source == TelemetryProvider {
		return "pve\x00" + t.RemoteID
	}
	return "ssh\x00" + t.HostID
}

// boundedText reports whether s is non-empty valid UTF-8 of at most limit bytes.
func boundedText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s)
}

// TelemetryLease is the scheduler's view of one approved telemetry read
// grant. It selects work only; the executor enforces the grant itself.
type TelemetryLease struct {
	// GrantID and GrantDigest identify the approved grant version.
	GrantID     string
	GrantDigest string
	// Scheduled permits five-minute history samples; OnDemand permits
	// ten-second live samples of visible targets.
	Scheduled bool
	OnDemand  bool
	// ExpiresAt is the grant's absolute expiry.
	ExpiresAt time.Time
	// MinInterval is the grant's minimum interval per target; it can only
	// lengthen the history and live cadences.
	MinInterval time.Duration
	// RunBudget is the grant's rolling-hour budget per remote or host.
	RunBudget int
	// Targets lists the exact targets.
	Targets []TelemetryTarget
}

// validate checks a lease's shape.
func (l TelemetryLease) validate() error {
	switch {
	case !boundedText(l.GrantID, maxGrantIDBytes) || !boundedText(l.GrantDigest, maxGrantIDBytes):
		return errors.New("grant id or digest malformed")
	case !l.Scheduled && !l.OnDemand:
		return errors.New("no trigger")
	case l.ExpiresAt.IsZero():
		return errors.New("no expiry")
	case l.MinInterval < TelemetryLiveInterval:
		return fmt.Errorf("min interval below %s", TelemetryLiveInterval)
	case l.RunBudget < 1 || l.RunBudget > MaxTelemetryRunBudget:
		return fmt.Errorf("run budget must be 1 to %d", MaxTelemetryRunBudget)
	case len(l.Targets) == 0:
		return errors.New("no targets")
	}
	seen := make(map[string]bool, len(l.Targets))
	for _, t := range l.Targets {
		if !t.Valid() {
			return errors.New("malformed target")
		}
		if seen[t.key()] {
			return errors.New("target listed twice")
		}
		seen[t.key()] = true
	}
	return nil
}

// covers reports whether l lists exactly t and is unexpired at now.
func (l *TelemetryLease) covers(t TelemetryTarget, now time.Time) bool {
	return now.Before(l.ExpiresAt) && slices.ContainsFunc(l.Targets, func(x TelemetryTarget) bool { return x.key() == t.key() })
}

// TelemetryRead is one read the scheduler issues.
type TelemetryRead struct {
	Target TelemetryTarget
	// Live selects the ten-second on-demand path; otherwise the read is a
	// scheduled history sample.
	Live bool
	// GrantID names the lease the read is scheduled under.
	GrantID string
}

// TelemetrySample is one validated fraction-valued metric sample.
type TelemetrySample struct {
	Target     TelemetryTarget
	Metric     string
	Value      float64
	Live       bool
	ObservedAt time.Time
}

// TelemetryReader performs one read. Implementations return only samples
// of read.Target; anything else is discarded.
type TelemetryReader interface {
	ReadTelemetry(ctx context.Context, read TelemetryRead) ([]TelemetrySample, error)
}

// TelemetrySink receives validated samples (the P1-25 metric buckets).
type TelemetrySink interface {
	RecordTelemetry(ctx context.Context, s TelemetrySample) error
}

// Errors of the telemetry scheduler.
var (
	// ErrTelemetryLocked is returned while the scheduler is locked.
	ErrTelemetryLocked = errors.New("pvecollect: telemetry locked")
	// ErrTelemetryNotAuthorized is returned for a request no active
	// on-demand lease covers exactly.
	ErrTelemetryNotAuthorized = errors.New("pvecollect: telemetry target not authorized")
	// ErrTelemetryLimit is returned when a bounded table is full.
	ErrTelemetryLimit = errors.New("pvecollect: telemetry limit reached")
	// ErrTelemetryInvalid is returned for malformed input.
	ErrTelemetryInvalid = errors.New("pvecollect: invalid telemetry input")
)

// Deferral reasons.
const (
	DeferLiveTargetCap = "live target cap"
	DeferRequestRate   = "request rate"
	DeferBudget        = "budget"
	DeferHostBusy      = "host busy"
)

// TelemetryDeferral reports a due read that was not issued, with the age
// basis for the "last observed" label.
type TelemetryDeferral struct {
	Target       TelemetryTarget
	Live         bool
	Reason       string
	LastObserved time.Time
}

// TelemetryReport summarizes one RunOnce pass.
type TelemetryReport struct {
	Now       time.Time
	Issued    int
	Recorded  int
	Failed    int
	Discarded int
	Coalesced int
	Deferred  []TelemetryDeferral
}

// TelemetryConfig carries the scheduler's tunables.
type TelemetryConfig struct {
	// Now returns the current time; defaults to time.Now.
	Now func() time.Time
	// Tick paces Run (default 1 s).
	Tick time.Duration
	// ReadTimeout bounds one read (default 30 s).
	ReadTimeout time.Duration
}

type viewerSet struct {
	target    TelemetryTarget
	firstSeen time.Time
	viewers   map[string]time.Time // viewer → expiry
}

type targetState struct {
	lastHistory time.Time // last history attempt (or coalesced slot)
	lastLive    time.Time // last live attempt
	lastSample  time.Time // last recorded sample
	inFlight    bool
}

type scopeState struct {
	attempts    []time.Time
	lastRequest time.Time
	inFlight    int
}

type inflight struct {
	read   TelemetryRead
	digest string
	cancel context.CancelFunc
}

// TelemetryScheduler schedules authorized telemetry reads. Its methods are
// safe for concurrent use.
type TelemetryScheduler struct {
	reader TelemetryReader
	sink   TelemetrySink
	cfg    TelemetryConfig

	// gate serializes Lock/SetLeases against result recording: once Lock
	// or SetLeases returns, no sample of a stopped read is recorded.
	gate sync.RWMutex

	mu       sync.Mutex
	locked   bool
	leases   []TelemetryLease
	denied   map[string]bool // grant ID + target key refused by the executor
	viewers  map[string]*viewerSet
	nViewers int
	targets  map[string]*targetState
	scopes   map[string]*scopeState
	running  map[uint64]*inflight
	nextID   uint64
}

// NewTelemetryScheduler builds a scheduler with no leases.
func NewTelemetryScheduler(reader TelemetryReader, sink TelemetrySink, cfg TelemetryConfig) (*TelemetryScheduler, error) {
	if reader == nil || sink == nil {
		return nil, fmt.Errorf("%w: reader and sink are required", ErrTelemetryInvalid)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Tick <= 0 {
		cfg.Tick = defaultTelemetryTick
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = defaultTelemetryReadTimeout
	}
	return &TelemetryScheduler{
		reader: reader, sink: sink, cfg: cfg,
		denied:  map[string]bool{},
		viewers: map[string]*viewerSet{},
		targets: map[string]*targetState{},
		scopes:  map[string]*scopeState{},
		running: map[uint64]*inflight{},
	}, nil
}

// Lock stops all reads: new reads are not scheduled, viewer requests are
// refused and dropped, in-flight reads are cancelled and their results
// discarded. Lock waits for a sample being recorded to finish.
func (s *TelemetryScheduler) Lock() {
	s.gate.Lock()
	defer s.gate.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = true
	s.viewers = map[string]*viewerSet{}
	s.nViewers = 0
	for _, r := range s.running {
		r.cancel()
	}
}

// Unlock resumes scheduling within the current leases.
func (s *TelemetryScheduler) Unlock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = false
}

// SetLeases replaces the active leases. Leases that fail validation make
// the whole call fail and leave the previous set in place. Viewer requests
// and in-flight reads no longer covered are dropped and cancelled; budget
// counters are kept.
func (s *TelemetryScheduler) SetLeases(leases []TelemetryLease) error {
	if len(leases) > MaxTelemetryLeases {
		return fmt.Errorf("%w: more than %d leases", ErrTelemetryLimit, MaxTelemetryLeases)
	}
	total := 0
	ids := map[string]bool{}
	cp := make([]TelemetryLease, 0, len(leases))
	for _, l := range leases {
		if err := l.validate(); err != nil {
			return fmt.Errorf("%w: lease %q: %v", ErrTelemetryInvalid, l.GrantID, err)
		}
		if ids[l.GrantID] {
			return fmt.Errorf("%w: lease %q listed twice", ErrTelemetryInvalid, l.GrantID)
		}
		ids[l.GrantID] = true
		total += len(l.Targets)
		if total > MaxTelemetryTargets {
			return fmt.Errorf("%w: more than %d targets", ErrTelemetryLimit, MaxTelemetryTargets)
		}
		l.Targets = slices.Clone(l.Targets)
		cp = append(cp, l)
	}
	slices.SortFunc(cp, func(a, b TelemetryLease) int {
		if a.GrantID < b.GrantID {
			return -1
		}
		if a.GrantID > b.GrantID {
			return 1
		}
		return 0
	})

	s.gate.Lock()
	defer s.gate.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	s.leases = cp
	s.denied = map[string]bool{}
	for k, v := range s.viewers {
		if _, ok := s.leaseFor(v.target, true, now); !ok {
			s.nViewers -= len(v.viewers)
			delete(s.viewers, k)
		}
	}
	for k := range s.targets {
		if !s.anyLease(k) {
			delete(s.targets, k)
		}
	}
	for _, r := range s.running {
		if !s.stillAuthorized(r, now) {
			r.cancel()
		}
	}
	return nil
}

// anyLease reports whether any lease lists the target key.
func (s *TelemetryScheduler) anyLease(key string) bool {
	for i := range s.leases {
		for _, t := range s.leases[i].Targets {
			if t.key() == key {
				return true
			}
		}
	}
	return false
}

// leaseFor returns the first unexpired lease that covers t for the path
// and has not been refused for t. Caller holds s.mu.
func (s *TelemetryScheduler) leaseFor(t TelemetryTarget, live bool, now time.Time) (*TelemetryLease, bool) {
	for i := range s.leases {
		l := &s.leases[i]
		if live && !l.OnDemand || !live && !l.Scheduled {
			continue
		}
		if s.denied[l.GrantID+"\x00"+t.key()] || !l.covers(t, now) {
			continue
		}
		return l, true
	}
	return nil, false
}

// stillAuthorized reports whether an in-flight read's lease is unchanged,
// unexpired and still covers it. Caller holds s.mu.
func (s *TelemetryScheduler) stillAuthorized(r *inflight, now time.Time) bool {
	if s.locked {
		return false
	}
	l, ok := s.leaseFor(r.read.Target, r.read.Live, now)
	return ok && l.GrantID == r.read.GrantID && l.GrantDigest == r.digest
}

// Request registers or renews a visible-target request of viewerID for
// the exact target t and returns its expiry. It adds no authority: t must
// be listed by an active on-demand lease.
func (s *TelemetryScheduler) Request(viewerID string, t TelemetryTarget) (time.Time, error) {
	if !boundedText(viewerID, MaxViewerIDBytes) || !t.Valid() {
		return time.Time{}, ErrTelemetryInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return time.Time{}, ErrTelemetryLocked
	}
	now := s.cfg.Now()
	if _, ok := s.leaseFor(t, true, now); !ok {
		return time.Time{}, ErrTelemetryNotAuthorized
	}
	k := t.key()
	v, ok := s.viewers[k]
	if !ok {
		if s.nViewers >= MaxTelemetryViewers {
			return time.Time{}, ErrTelemetryLimit
		}
		v = &viewerSet{target: t, firstSeen: now, viewers: map[string]time.Time{}}
		s.viewers[k] = v
	}
	if _, ok := v.viewers[viewerID]; !ok {
		if s.nViewers >= MaxTelemetryViewers {
			return time.Time{}, ErrTelemetryLimit
		}
		s.nViewers++
	}
	exp := now.Add(TelemetryViewerRenewal)
	v.viewers[viewerID] = exp
	return exp, nil
}

// Release ends viewerID's request for t (a hidden or closed page).
func (s *TelemetryScheduler) Release(viewerID string, t TelemetryTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := t.key()
	v, ok := s.viewers[k]
	if !ok {
		return
	}
	if _, ok := v.viewers[viewerID]; ok {
		delete(v.viewers, viewerID)
		s.nViewers--
	}
	if len(v.viewers) == 0 {
		delete(s.viewers, k)
	}
}

// LastObserved returns the time of the last recorded sample of t.
func (s *TelemetryScheduler) LastObserved(t TelemetryTarget) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.targets[t.key()]
	if !ok || st.lastSample.IsZero() {
		return time.Time{}, false
	}
	return st.lastSample, true
}

// planned is one reserved read.
type planned struct {
	id     uint64
	read   TelemetryRead
	digest string
	ctx    context.Context
}

// due reports whether last is at least interval before now. A clock step
// backwards restarts the interval at now instead of reading early.
func due(last *time.Time, now time.Time, interval time.Duration) bool {
	if last.IsZero() {
		return true
	}
	if now.Before(*last) {
		*last = now
		return false
	}
	return now.Sub(*last) >= interval
}

func (s *TelemetryScheduler) target(k string) *targetState {
	st, ok := s.targets[k]
	if !ok {
		st = &targetState{}
		s.targets[k] = st
	}
	return st
}

func (s *TelemetryScheduler) scopeOf(k string) *scopeState {
	sc, ok := s.scopes[k]
	if !ok {
		sc = &scopeState{}
		s.scopes[k] = sc
	}
	return sc
}

// plan reserves the reads due at now. Caller holds s.mu.
func (s *TelemetryScheduler) plan(ctx context.Context, now time.Time, rep *TelemetryReport) []planned {
	if s.locked {
		return nil
	}
	// Expire viewer requests.
	for k, v := range s.viewers {
		for id, exp := range v.viewers {
			if !now.Before(exp) {
				delete(v.viewers, id)
				s.nViewers--
			}
		}
		if len(v.viewers) == 0 {
			delete(s.viewers, k)
		}
	}
	// Prune budget windows.
	for _, sc := range s.scopes {
		i := 0
		for i < len(sc.attempts) && !sc.attempts[i].After(now.Add(-telemetryBudgetWindow)) {
			i++
		}
		sc.attempts = sc.attempts[i:]
	}

	type cand struct {
		read  TelemetryRead
		lease *TelemetryLease
	}
	var cands []cand
	liveSlots := map[string]int{}

	// Live candidates first (visible boxes take priority), oldest request first.
	sets := make([]*viewerSet, 0, len(s.viewers))
	for _, v := range s.viewers {
		sets = append(sets, v)
	}
	slices.SortFunc(sets, func(a, b *viewerSet) int {
		if c := a.firstSeen.Compare(b.firstSeen); c != 0 {
			return c
		}
		if a.target.key() < b.target.key() {
			return -1
		}
		return 1
	})
	for _, v := range sets {
		l, ok := s.leaseFor(v.target, true, now)
		if !ok {
			continue
		}
		k := v.target.key()
		st := s.target(k)
		if v.target.Source == TelemetryProvider {
			sk := v.target.scope()
			if liveSlots[sk] >= MaxLiveTargetsPerRemote {
				rep.Deferred = append(rep.Deferred, TelemetryDeferral{Target: v.target, Live: true, Reason: DeferLiveTargetCap, LastObserved: st.lastSample})
				continue
			}
			liveSlots[sk]++
		}
		if st.inFlight || !due(&st.lastLive, now, max(TelemetryLiveInterval, l.MinInterval)) {
			continue
		}
		cands = append(cands, cand{TelemetryRead{Target: v.target, Live: true, GrantID: l.GrantID}, l})
	}
	// History candidates.
	seen := map[string]bool{}
	bucket := now.Truncate(TelemetryHistoryInterval)
	for i := range s.leases {
		for _, t := range s.leases[i].Targets {
			k := t.key()
			if seen[k] {
				continue
			}
			l, ok := s.leaseFor(t, false, now)
			if !ok {
				continue
			}
			seen[k] = true
			st := s.target(k)
			if st.inFlight || !due(&st.lastHistory, now, max(TelemetryHistoryInterval, l.MinInterval)) {
				continue
			}
			if !st.lastSample.Before(bucket) && !st.lastSample.After(now) {
				// A live sample already fills this bucket.
				st.lastHistory = now
				rep.Coalesced++
				continue
			}
			cands = append(cands, cand{TelemetryRead{Target: t, GrantID: l.GrantID}, l})
		}
	}

	var out []planned
	usedScope := map[string]bool{}
	chosen := map[string]bool{}
	for _, c := range cands {
		k := c.read.Target.key()
		st := s.target(k)
		if chosen[k] {
			// A live read of this target is already planned: its sample
			// fills the history bucket too (the next pass sees it there;
			// if the live read fails, history is read then).
			rep.Coalesced++
			continue
		}
		sk := c.read.Target.scope()
		sc := s.scopeOf(sk)
		reason := ""
		switch {
		case len(sc.attempts) >= c.lease.RunBudget:
			reason = DeferBudget
		case c.read.Target.Source == TelemetryProvider && (usedScope[sk] || !sc.lastRequest.IsZero() && !now.Before(sc.lastRequest) && now.Sub(sc.lastRequest) < ProviderMetricsSpacing):
			reason = DeferRequestRate
		case c.read.Target.Source == TelemetrySSH && (usedScope[sk] || sc.inFlight > 0):
			reason = DeferHostBusy
		}
		if reason != "" {
			rep.Deferred = append(rep.Deferred, TelemetryDeferral{Target: c.read.Target, Live: c.read.Live, Reason: reason, LastObserved: st.lastSample})
			continue
		}
		usedScope[sk] = true
		chosen[k] = true
		sc.attempts = append(sc.attempts, now)
		sc.lastRequest = now
		sc.inFlight++
		st.inFlight = true
		if c.read.Live {
			st.lastLive = now
		} else {
			st.lastHistory = now
		}
		s.nextID++
		rctx, cancel := context.WithTimeout(ctx, s.cfg.ReadTimeout)
		s.running[s.nextID] = &inflight{read: c.read, digest: c.lease.GrantDigest, cancel: cancel}
		out = append(out, planned{id: s.nextID, read: c.read, digest: c.lease.GrantDigest, ctx: rctx})
	}
	return out
}

// RunOnce plans the reads due now, performs them concurrently (at most one
// per remote/host) and records the validated samples. It returns when all
// reads have finished.
func (s *TelemetryScheduler) RunOnce(ctx context.Context) TelemetryReport {
	s.mu.Lock()
	now := s.cfg.Now()
	rep := TelemetryReport{Now: now}
	reads := s.plan(ctx, now, &rep)
	s.mu.Unlock()
	rep.Issued = len(reads)

	type outcome struct {
		recorded, discarded int
		failed              bool
	}
	results := make([]outcome, len(reads))
	var wg sync.WaitGroup
	for i, p := range reads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, disc, failed := s.perform(p)
			results[i] = outcome{rec, disc, failed}
		}()
	}
	wg.Wait()
	for _, o := range results {
		rep.Recorded += o.recorded
		rep.Discarded += o.discarded
		if o.failed {
			rep.Failed++
		}
	}
	return rep
}

// perform runs one planned read and records its samples if the read is
// still authorized when it completes.
func (s *TelemetryScheduler) perform(p planned) (recorded, discarded int, failed bool) {
	samples, err := s.reader.ReadTelemetry(p.ctx, p.read)

	s.gate.RLock()
	defer s.gate.RUnlock()
	s.mu.Lock()
	r := s.running[p.id]
	delete(s.running, p.id)
	if r != nil {
		r.cancel()
	}
	k := p.read.Target.key()
	st := s.targets[k]
	if sc := s.scopes[p.read.Target.scope()]; sc != nil && sc.inFlight > 0 {
		sc.inFlight--
	}
	if st != nil {
		st.inFlight = false
	}
	now := s.cfg.Now()
	if err != nil {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.NotFound, codes.FailedPrecondition, codes.Unauthenticated:
			// The executor no longer honours this lease for the target:
			// stop until the leases are refreshed.
			s.denied[p.read.GrantID+"\x00"+k] = true
		}
		s.mu.Unlock()
		return 0, 0, true
	}
	if r == nil || !s.stillAuthorized(&inflight{read: p.read, digest: p.digest}, now) {
		s.mu.Unlock()
		return 0, len(samples), false
	}
	valid := make([]TelemetrySample, 0, len(samples))
	seen := map[string]bool{}
	for _, smp := range samples {
		if len(valid) >= MaxSamplesPerRead || !validSample(smp, p.read.Target) || seen[smp.Metric] {
			discarded++
			continue
		}
		seen[smp.Metric] = true
		smp.Live = p.read.Live
		smp.ObservedAt = now
		valid = append(valid, smp)
	}
	s.mu.Unlock()

	// gate is held for reading: Lock and SetLeases wait until these
	// samples are recorded and cannot interleave with them.
	for _, smp := range valid {
		if err := s.sink.RecordTelemetry(context.WithoutCancel(p.ctx), smp); err != nil {
			discarded++
			continue
		}
		recorded++
	}
	s.mu.Lock()
	if st := s.targets[k]; st != nil && recorded > 0 {
		st.lastSample = now
	}
	s.mu.Unlock()
	return recorded, discarded, false
}

// validSample reports whether smp is a finite fraction of a known metric
// for exactly target t.
func validSample(smp TelemetrySample, t TelemetryTarget) bool {
	if smp.Target.key() != t.key() {
		return false
	}
	switch smp.Metric {
	case TelemetryMetricCPU, TelemetryMetricRAM, TelemetryMetricDisk:
	default:
		return false
	}
	return !math.IsNaN(smp.Value) && !math.IsInf(smp.Value, 0) && smp.Value >= 0 && smp.Value <= 1
}

// Run calls RunOnce every Tick until ctx is cancelled.
func (s *TelemetryScheduler) Run(ctx context.Context) error {
	t := time.NewTicker(s.cfg.Tick)
	defer t.Stop()
	for {
		s.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
