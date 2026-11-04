// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Defaults for Limits.
const (
	// Retention is how long hourly buckets are kept (ADR 0009: 21 days).
	Retention = 21 * 24 * time.Hour
	// DefaultMaxBuckets bounds the (hour, flow) buckets held in memory;
	// one bucket takes roughly 200 bytes including map overhead.
	DefaultMaxBuckets = 2_000_000
	// DefaultMaxReporters bounds the tracked (host, tier) reporters.
	DefaultMaxReporters = 65536
	// DefaultMaxClockSkew is how far a report may lie in the future.
	DefaultMaxClockSkew = 5 * time.Minute
	// DefaultMaxInterval is the longest accepted report interval. A
	// collector that was away for longer must start over with a baseline
	// (Diff with a nil previous snapshot).
	DefaultMaxInterval = time.Hour
	// MaxHostAddrs bounds the addresses passed for one reporter.
	MaxHostAddrs = 1024
	// DefaultOverviewN is the per-node top set size of the overview.
	DefaultOverviewN = 5
)

const secondsPerHour = 3600

// Errors returned by Aggregator.Ingest. A rejected report changes nothing.
var (
	// ErrInvalidReport marks a malformed report.
	ErrInvalidReport = errors.New("invalid flow report")
	// ErrDuplicateReport marks a report whose interval does not start at or
	// after the end of the last accepted report of the same host and tier.
	ErrDuplicateReport = errors.New("duplicate or overlapping flow report")
	// ErrOutOfWindow marks a report older than the retention or too far in
	// the future.
	ErrOutOfWindow = errors.New("flow report outside the accepted time window")
	// ErrLimit marks a report that would exceed the reporter limit.
	ErrLimit = errors.New("flow aggregation limit reached")
	// ErrIntervalTooLong marks a report whose interval exceeds
	// Limits.MaxInterval. Its bytes cannot be placed in hours reliably; the
	// collector must start over with a baseline.
	ErrIntervalTooLong = errors.New("flow report interval too long")
)

// Limits bounds the memory of an Aggregator. Zero fields take the defaults.
type Limits struct {
	MaxBuckets   int
	MaxReporters int
	Retention    time.Duration
	MaxClockSkew time.Duration
	// MaxInterval bounds From..To of a report; each observation touches
	// at most MaxInterval/1h+1 hourly buckets.
	MaxInterval time.Duration
}

// DefaultLimits returns the package defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxBuckets:   DefaultMaxBuckets,
		MaxReporters: DefaultMaxReporters,
		Retention:    Retention,
		MaxClockSkew: DefaultMaxClockSkew,
		MaxInterval:  DefaultMaxInterval,
	}
}

// sideAcc accumulates the reports of one end of a flow within one hour.
// reporter is the index of the first host that reported this end; zero
// means no report.
type sideAcc struct {
	reporter    uint32
	lowerBound  bool
	ab, ba      uint64
	conns       uint64
	first, last int64 // unix seconds of report end times
}

func (s *sideAcc) add(o *Observation, p *hourPart) {
	at := p.at
	s.ab = satAdd(s.ab, p.share(o.BytesAB))
	s.ba = satAdd(s.ba, p.share(o.BytesBA))
	s.conns = satAdd(s.conns, p.share(o.Connections))
	s.lowerBound = s.lowerBound || o.LowerBound
	if s.first == 0 || at < s.first {
		s.first = at
	}
	if at > s.last {
		s.last = at
	}
}

// bucket is one flow in one hour, kept separately per reporting end.
type bucket struct {
	server, client sideAcc
}

type reporterKey struct{ host, tier string }

type reporterState struct {
	idx    uint32
	lastTo time.Time
}

// IngestResult tells what happened to the observations of an accepted
// report. An observation whose interval spans an hour boundary is split
// into one part per hour; Applied, Dropped and Conflicts count parts.
type IngestResult struct {
	// Applied parts were added to a bucket.
	Applied int
	// Dropped parts needed a new bucket beyond Limits.MaxBuckets.
	Dropped int
	// Conflicts were ignored because another host already reported the
	// same end of the flow in that hour.
	Conflicts int
	// Foreign observations were refused because the end they claim (the
	// server end if ServerReported, otherwise the client end) is not one
	// of the reporter's addresses.
	Foreign int
}

// hourPart is the share of a report interval that falls into one hour.
// num/den is the fraction of the interval and done the part of it that
// lies before this hour.
type hourPart struct {
	hour     int64
	at       int64 // unix seconds of the end of the part
	num, den uint64
	done     uint64 // nanoseconds of the interval before this part
}

// share returns this part's share of v: floor(v*end/den) - floor(v*start/den)
// over the cumulative interval, so rounding never loses or adds a unit.
func (p *hourPart) share(v uint64) uint64 {
	if p.den == 0 {
		return v
	}
	upTo := func(n uint64) uint64 {
		if n >= p.den {
			return v
		}
		hi, lo := bits.Mul64(v, n)
		q, _ := bits.Div64(hi, lo, p.den)
		return q
	}
	return upTo(p.done+p.num) - upTo(p.done)
}

// splitHours divides [from, to) into hourly parts. A zero-length interval
// is one part in the hour of to; an interval that ends exactly on an hour
// boundary does not touch the following hour.
func splitHours(from, to time.Time) []hourPart {
	total := to.Sub(from)
	if total <= 0 {
		return []hourPart{{hour: hourOf(to), at: to.Unix()}}
	}
	var parts []hourPart
	var done uint64
	for h := hourOf(from); ; h++ {
		start := time.Unix(h*secondsPerHour, 0)
		end := time.Unix((h+1)*secondsPerHour, 0)
		if start.Before(from) {
			start = from
		}
		if end.After(to) {
			end = to
		}
		if seg := end.Sub(start); seg > 0 {
			parts = append(parts, hourPart{hour: h, at: end.Unix(), num: uint64(seg), den: uint64(total), done: done})
			done += uint64(seg)
		}
		if !end.Before(to) {
			break
		}
	}
	return parts
}

// Aggregator holds hourly flow buckets. It is safe for concurrent use.
type Aggregator struct {
	mu        sync.Mutex
	limits    Limits
	now       func() time.Time
	hours     map[int64]map[FlowKey]*bucket
	buckets   int
	reporters map[reporterKey]*reporterState
	nextIdx   uint32
	dropped   uint64
	// prunedHour is the hour of now at the last automatic prune.
	prunedHour int64
	pruned     bool
}

// NewAggregator returns an empty aggregator. now supplies the current time
// for the accepted ingest window and automatic pruning.
func NewAggregator(l Limits, now func() time.Time) *Aggregator {
	d := DefaultLimits()
	if l.MaxBuckets <= 0 {
		l.MaxBuckets = d.MaxBuckets
	}
	if l.MaxReporters <= 0 {
		l.MaxReporters = d.MaxReporters
	}
	if l.Retention <= 0 {
		l.Retention = d.Retention
	}
	if l.MaxClockSkew <= 0 {
		l.MaxClockSkew = d.MaxClockSkew
	}
	if l.MaxInterval <= 0 {
		l.MaxInterval = d.MaxInterval
	}
	return &Aggregator{
		limits:    l,
		now:       now,
		hours:     make(map[int64]map[FlowKey]*bucket),
		reporters: make(map[reporterKey]*reporterState),
	}
}

func hourOf(t time.Time) int64 {
	s := t.Unix()
	h := s / secondsPerHour
	if s%secondsPerHour < 0 {
		h--
	}
	return h
}

func validateReport(r *Report) error {
	if err := validName(r.Host, MaxHostIDLen); err != nil {
		return fmt.Errorf("%w: host: %v", ErrInvalidReport, err)
	}
	if err := validTier(r.Tier); err != nil {
		return fmt.Errorf("%w: host %q: tier: %v", ErrInvalidReport, r.Host, err)
	}
	if r.To.IsZero() || r.From.IsZero() || r.From.After(r.To) {
		return fmt.Errorf("%w: host %q: invalid interval", ErrInvalidReport, r.Host)
	}
	if len(r.Observations) > MaxSocketsPerSnapshot {
		return fmt.Errorf("%w: host %q: %d observations exceed limit %d", ErrInvalidReport, r.Host, len(r.Observations), MaxSocketsPerSnapshot)
	}
	for i := range r.Observations {
		k := r.Observations[i].Key
		if err := k.validate(); err != nil {
			return fmt.Errorf("%w: host %q: observation %d: %v", ErrInvalidReport, r.Host, i, err)
		}
		if k.Tier != r.Tier {
			return fmt.Errorf("%w: host %q: observation %d: tier %q differs from report", ErrInvalidReport, r.Host, i, k.Tier)
		}
		if i > 0 && compareKey(r.Observations[i-1].Key, k) >= 0 {
			return fmt.Errorf("%w: host %q: observation %d: keys not strictly sorted", ErrInvalidReport, r.Host, i)
		}
	}
	return nil
}

// ownSet validates and normalizes the reporter's addresses.
func ownSet(host string, own []netip.Addr) (map[netip.Addr]struct{}, error) {
	if len(own) == 0 {
		return nil, fmt.Errorf("%w: host %q: no reporter addresses", ErrInvalidReport, host)
	}
	if len(own) > MaxHostAddrs {
		return nil, fmt.Errorf("%w: host %q: %d reporter addresses exceed limit %d", ErrInvalidReport, host, len(own), MaxHostAddrs)
	}
	set := make(map[netip.Addr]struct{}, len(own))
	for i, a := range own {
		a = normalizeNode(a)
		if !a.IsValid() || a.IsUnspecified() {
			return nil, fmt.Errorf("%w: host %q: reporter address %d invalid", ErrInvalidReport, host, i)
		}
		set[a] = struct{}{}
	}
	return set, nil
}

// reporterEnd returns the address of the flow end the observation claims
// for its reporter.
func reporterEnd(o *Observation) netip.Addr {
	server := o.Key.ServerAddr()
	if o.ServerReported {
		return server
	}
	if server == o.Key.A {
		return o.Key.B
	}
	return o.Key.A
}

// Ingest adds a report to the hourly buckets.
//
// own lists the addresses that belong to the reporting host r.Host. The
// caller takes them from the server's own records of that managed host
// (for example its registered and inventoried addresses), never from the
// report itself, and leaves out addresses that more than one host claims.
// An observation is applied only when the end it claims (the server end if
// ServerReported, otherwise the client end) is one of these addresses;
// other observations are refused before they can take a bucket slot and
// are counted in IngestResult.Foreign. So a host can only speak for its own
// end of its own flows and cannot displace the reports of two other hosts
// about their flow. A report without addresses is rejected.
//
// Hours: the interval r.From..r.To is split across the hours it covers in
// proportion to the time spent in each hour (the rate is assumed constant
// within one report), so every hour of a flow is counted from reports of
// the same time span on both ends and an hour boundary inside an interval
// never puts the same bytes into two hours. Intervals longer than
// Limits.MaxInterval are rejected with ErrIntervalTooLong rather than
// spread over many hours: after such a gap the collector starts over with
// a baseline (Diff with a nil previous snapshot), which counts nothing.
// Parts that fall into hours already outside the retention are skipped.
//
// Reports of one (host, tier) must not overlap: r.From must be at or after
// and r.To strictly after the end of the previous accepted report, so a
// report submitted twice is rejected with ErrDuplicateReport instead of
// being counted twice. Collectors must keep the previous snapshot across
// restarts or start over with a baseline.
//
// For every flow and hour the bytes reported by the server end are used
// when present; the client end's report is kept as confirmation and used
// only when the server end did not report. A second host that reports the
// same end of the same flow in the same hour is ignored (counted in
// IngestResult.Conflicts), so the same bytes are never summed from two
// reporters.
//
// New buckets beyond Limits.MaxBuckets are dropped and counted; existing
// buckets keep accepting data. A rejected report changes nothing.
func (a *Aggregator) Ingest(r Report, own []netip.Addr) (IngestResult, error) {
	if err := validateReport(&r); err != nil {
		return IngestResult{}, err
	}
	if d := r.To.Sub(r.From); d > a.limits.MaxInterval {
		return IngestResult{}, fmt.Errorf("%w: host %q: interval %s exceeds %s", ErrIntervalTooLong, r.Host, d, a.limits.MaxInterval)
	}
	mine, err := ownSet(r.Host, own)
	if err != nil {
		return IngestResult{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	cutoff := now.Add(-a.limits.Retention)
	if r.To.Before(cutoff) || r.To.After(now.Add(a.limits.MaxClockSkew)) {
		return IngestResult{}, fmt.Errorf("%w: host %q: report ends %s, now %s", ErrOutOfWindow, r.Host,
			r.To.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	rk := reporterKey{host: r.Host, tier: r.Tier}
	rs := a.reporters[rk]
	if rs != nil {
		if r.From.Before(rs.lastTo) || !r.To.After(rs.lastTo) {
			return IngestResult{}, fmt.Errorf("%w: host %q tier %q: report %s..%s, last accepted ended %s", ErrDuplicateReport,
				r.Host, r.Tier, r.From.UTC().Format(time.RFC3339), r.To.UTC().Format(time.RFC3339), rs.lastTo.UTC().Format(time.RFC3339))
		}
	} else if len(a.reporters) >= a.limits.MaxReporters || a.nextIdx == math.MaxUint32 {
		return IngestResult{}, fmt.Errorf("%w: host %q: %d reporters", ErrLimit, r.Host, len(a.reporters))
	}

	// The report is accepted. Prune at most once per hour of the clock,
	// then look the reporter up again: pruning may have removed it.
	if h := hourOf(now); !a.pruned || h != a.prunedHour {
		a.pruneLocked(cutoff)
		a.pruned, a.prunedHour = true, h
	}
	if rs = a.reporters[rk]; rs == nil {
		a.nextIdx++
		rs = &reporterState{idx: a.nextIdx}
		a.reporters[rk] = rs
	}
	rs.lastTo = r.To

	var res IngestResult
	parts := splitHours(r.From, r.To)
	limit := cutoff.Unix()
	for i := range r.Observations {
		o := &r.Observations[i]
		if _, ok := mine[reporterEnd(o)]; !ok {
			res.Foreign++
			continue
		}
		for j := range parts {
			p := &parts[j]
			if (p.hour+1)*secondsPerHour <= limit {
				continue
			}
			switch a.applyLocked(o, p, rs.idx) {
			case applied:
				res.Applied++
			case dropped:
				res.Dropped++
			case conflict:
				res.Conflicts++
			}
		}
	}
	a.dropped += uint64(res.Dropped)
	return res, nil
}

type applyResult uint8

const (
	applied applyResult = iota
	dropped
	conflict
)

// applyLocked adds one hourly part of an observation.
func (a *Aggregator) applyLocked(o *Observation, p *hourPart, idx uint32) applyResult {
	hm := a.hours[p.hour]
	b := hm[o.Key]
	if b == nil {
		if a.buckets >= a.limits.MaxBuckets {
			return dropped
		}
		if hm == nil {
			hm = make(map[FlowKey]*bucket)
			a.hours[p.hour] = hm
		}
		b = &bucket{}
		hm[o.Key] = b
		a.buckets++
	}
	side := &b.client
	if o.ServerReported {
		side = &b.server
	}
	switch side.reporter {
	case 0:
		side.reporter = idx
	case idx:
	default:
		return conflict
	}
	side.add(o, p)
	return applied
}

// Cutoff removes every hour that ends at or before now-retention and every
// reporter whose last report lies in such an hour. It returns the number of
// removed buckets.
func (a *Aggregator) Cutoff(now time.Time, retention time.Duration) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pruneLocked(now.Add(-retention))
}

func (a *Aggregator) pruneLocked(cutoff time.Time) int {
	removed := 0
	limit := cutoff.Unix()
	for h, hm := range a.hours {
		if (h+1)*secondsPerHour <= limit {
			removed += len(hm)
			delete(a.hours, h)
		}
	}
	a.buckets -= removed
	// A reporter goes with the hour of its last report, so a host never
	// meets its own buckets under a new index.
	for k, rs := range a.reporters {
		if (hourOf(rs.lastTo)+1)*secondsPerHour <= limit {
			delete(a.reporters, k)
		}
	}
	return removed
}

// Buckets returns the number of (hour, flow) buckets held.
func (a *Aggregator) Buckets() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buckets
}

// Reporters returns the number of tracked (host, tier) reporters.
func (a *Aggregator) Reporters() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.reporters)
}

// Dropped returns how many observations were dropped at the bucket limit.
func (a *Aggregator) Dropped() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}

// Window is a time range [From, To). An hourly bucket is included when its
// hour overlaps the range, so partial hours count in full.
type Window struct {
	From, To time.Time
}

func (w Window) includes(hour int64) bool {
	start := time.Unix(hour*secondsPerHour, 0)
	end := time.Unix((hour+1)*secondsPerHour, 0)
	return start.Before(w.To) && end.After(w.From)
}

// FlowTotal is a flow summed over a window.
type FlowTotal struct {
	Key              FlowKey
	BytesAB, BytesBA uint64
	Connections      uint64
	// FirstSeen and LastSeen are the end times of the first and last
	// counted report.
	FirstSeen, LastSeen time.Time
	// ServerReported is set when at least one hour was counted from the
	// server end.
	ServerReported bool
	// Confirmed is set when both ends reported in every counted hour.
	Confirmed bool
	// LowerBound is set when any counted hour may miss bytes.
	LowerBound bool
}

// Total returns BytesAB + BytesBA, saturating.
func (f FlowTotal) Total() uint64 { return satAdd(f.BytesAB, f.BytesBA) }

func (f *FlowTotal) add(b *bucket) {
	s := &b.client
	if b.server.reporter != 0 {
		s = &b.server
		f.ServerReported = true
	}
	confirmed := b.server.reporter != 0 && b.client.reporter != 0
	first, last := time.Unix(s.first, 0).UTC(), time.Unix(s.last, 0).UTC()
	if f.FirstSeen.IsZero() {
		f.Confirmed = confirmed
		f.FirstSeen, f.LastSeen = first, last
	} else {
		f.Confirmed = f.Confirmed && confirmed
		if first.Before(f.FirstSeen) {
			f.FirstSeen = first
		}
		if last.After(f.LastSeen) {
			f.LastSeen = last
		}
	}
	f.BytesAB = satAdd(f.BytesAB, s.ab)
	f.BytesBA = satAdd(f.BytesBA, s.ba)
	f.Connections = satAdd(f.Connections, s.conns)
	f.LowerBound = f.LowerBound || s.lowerBound
}

// compareTotal orders by total bytes descending, then by key.
func compareTotal(a, b *FlowTotal) int {
	if c := cmp.Compare(b.Total(), a.Total()); c != 0 {
		return c
	}
	return compareKey(a.Key, b.Key)
}

func normalizeNode(n netip.Addr) netip.Addr { return n.Unmap().WithZone("") }

// totalsLocked sums the buckets in w for flows that touch one of nodes.
// It walks every bucket of the hours in w under the aggregator mutex (up to
// Limits.MaxBuckets), so a query blocks ingest for that time; callers that
// query often should cache results per window.
func (a *Aggregator) totalsLocked(w Window, nodes map[netip.Addr]struct{}) map[FlowKey]*FlowTotal {
	out := make(map[FlowKey]*FlowTotal)
	if !w.From.Before(w.To) || len(nodes) == 0 {
		return out
	}
	for h, hm := range a.hours {
		if !w.includes(h) {
			continue
		}
		for k, b := range hm {
			_, okA := nodes[k.A]
			_, okB := nodes[k.B]
			if !okA && !okB {
				continue
			}
			t := out[k]
			if t == nil {
				t = &FlowTotal{Key: k}
				out[k] = t
			}
			t.add(b)
		}
	}
	return out
}

// topOf returns the n largest totals in deterministic order.
func topOf(ts []*FlowTotal, n int) []*FlowTotal {
	slices.SortFunc(ts, compareTotal)
	if len(ts) > n {
		ts = ts[:n]
	}
	return ts
}

func values(ts []*FlowTotal) []FlowTotal {
	out := make([]FlowTotal, len(ts))
	for i, t := range ts {
		out[i] = *t
	}
	return out
}

// TopN returns the n flows of node with the most bytes (both directions)
// in w, largest first; ties are ordered by key. n <= 0 returns nothing.
func (a *Aggregator) TopN(node netip.Addr, w Window, n int) []FlowTotal {
	if n <= 0 {
		return nil
	}
	a.mu.Lock()
	totals := a.totalsLocked(w, map[netip.Addr]struct{}{normalizeNode(node): {}})
	a.mu.Unlock()
	ts := make([]*FlowTotal, 0, len(totals))
	for _, t := range totals {
		ts = append(ts, t)
	}
	return values(topOf(ts, n))
}

// OverviewUnion returns the union of the top-n sets of every node in nodes
// over w, largest first with ties ordered by key. n <= 0 means
// DefaultOverviewN. Duplicate nodes are ignored.
func (a *Aggregator) OverviewUnion(nodes []netip.Addr, w Window, n int) []FlowTotal {
	if n <= 0 {
		n = DefaultOverviewN
	}
	set := make(map[netip.Addr]struct{}, len(nodes))
	for _, nd := range nodes {
		set[normalizeNode(nd)] = struct{}{}
	}
	a.mu.Lock()
	totals := a.totalsLocked(w, set)
	a.mu.Unlock()
	perNode := make(map[netip.Addr][]*FlowTotal, len(set))
	for _, t := range totals {
		if _, ok := set[t.Key.A]; ok {
			perNode[t.Key.A] = append(perNode[t.Key.A], t)
		}
		if _, ok := set[t.Key.B]; ok {
			perNode[t.Key.B] = append(perNode[t.Key.B], t)
		}
	}
	union := make(map[FlowKey]*FlowTotal)
	for _, ts := range perNode {
		for _, t := range topOf(ts, n) {
			union[t.Key] = t
		}
	}
	out := make([]*FlowTotal, 0, len(union))
	for _, t := range union {
		out = append(out, t)
	}
	slices.SortFunc(out, compareTotal)
	return values(out)
}
