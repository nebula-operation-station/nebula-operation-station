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
	// DefaultMaxBucketsPerReporter bounds the buckets one host may create
	// (ADR 0009 D7: per-host bounds), so a single host cannot fill
	// MaxBuckets and keep other hosts' new flows out. It is 5% of
	// DefaultMaxBuckets.
	DefaultMaxBucketsPerReporter = DefaultMaxBuckets / 20
	// DefaultMaxReporters bounds the tracked reporting hosts.
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
	// ErrOutOfWindow marks a report older than the retention, ending in an
	// hour removed by Cutoff, or too far in the future.
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
	MaxBuckets int
	// MaxBucketsPerReporter bounds the buckets created by one host; it is
	// clamped to MaxBuckets.
	MaxBucketsPerReporter int
	// MaxReporters bounds the tracked reporting hosts.
	MaxReporters int
	Retention    time.Duration
	MaxClockSkew time.Duration
	// MaxInterval bounds From..To of a report; each observation touches
	// at most MaxInterval/1h+1 hourly buckets. It is clamped to Retention.
	MaxInterval time.Duration
}

// DefaultLimits returns the package defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxBuckets:            DefaultMaxBuckets,
		MaxBucketsPerReporter: DefaultMaxBucketsPerReporter,
		MaxReporters:          DefaultMaxReporters,
		Retention:             Retention,
		MaxClockSkew:          DefaultMaxClockSkew,
		MaxInterval:           DefaultMaxInterval,
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
// owner is the host whose report created it and whose per-reporter bucket
// count it takes.
type bucket struct {
	server, client sideAcc
	owner          *reporterState
}

// reporterState is one reporting host. Hosts are keyed by their identity
// alone; each of the fixed tiers keeps its own report sequence.
type reporterState struct {
	idx uint32
	// lastTo is the end of the last accepted report per tier; zero means
	// none.
	lastTo [numTiers]time.Time
	// buckets counts the buckets this host created and that still exist.
	buckets int
	// capped counts the parts dropped at
	// Limits.MaxBucketsPerReporter; cappedByHour keeps the same per the
	// hour the part fell into, so the marker expires with the pruned
	// hours.
	capped       uint64
	cappedByHour map[int64]uint64
}

// latest returns the end of the host's most recent report of any tier.
func (rs *reporterState) latest() time.Time {
	var t time.Time
	for _, l := range rs.lastTo {
		if l.After(t) {
			t = l
		}
	}
	return t
}

// IngestResult tells what happened to the observations of an accepted
// report. An observation whose interval spans an hour boundary is split
// into one part per hour; Applied, Dropped and Conflicts count parts.
type IngestResult struct {
	// Applied parts were added to a bucket.
	Applied int
	// Dropped parts needed a new bucket beyond Limits.MaxBuckets.
	Dropped int
	// Capped parts needed a new bucket while the reporting host already
	// held Limits.MaxBucketsPerReporter buckets. They are dropped; other
	// hosts' buckets are never evicted to make room.
	Capped int
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
	reporters map[string]*reporterState
	nextIdx   uint32
	dropped   uint64
	capped    uint64
	// closed holds the hours removed by Cutoff or the automatic prune,
	// as sorted, disjoint, non-adjacent runs of hour indices. Reports and
	// parts before floorLocked(now) are not accepted again, so replay
	// protection survives a backwards clock step. See floorLocked for the
	// invariant that keeps clock jumps from locking out reports.
	closed []hourRange
	// cappedHours indexes, per hour, the reporters that had parts
	// dropped in it, so pruning the hour drops their capped marker
	// with it.
	cappedHours map[int64]map[*reporterState]struct{}
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
	if l.MaxBucketsPerReporter <= 0 {
		l.MaxBucketsPerReporter = d.MaxBucketsPerReporter
	}
	l.MaxBucketsPerReporter = min(l.MaxBucketsPerReporter, l.MaxBuckets)
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
	l.MaxInterval = min(l.MaxInterval, l.Retention)
	return &Aggregator{
		limits:      l,
		now:         now,
		hours:       make(map[int64]map[FlowKey]*bucket),
		reporters:   make(map[string]*reporterState),
		cappedHours: make(map[int64]map[*reporterState]struct{}),
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
// The caller sets r.Host from the server's own record of the execution's
// target — the managed host the collection ran on — never from the host's
// output (Snapshot.Host): the report arrives over SSH from that host, so
// a value it chose would let it report under another host's identity and
// reuse or corrupt that host's report sequence.
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
// Reports of one host and tier must not overlap: r.From must be at or after
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
// New buckets beyond Limits.MaxBuckets, or beyond
// Limits.MaxBucketsPerReporter for the reporting host, are dropped and
// counted (IngestResult.Dropped and Capped); existing buckets keep
// accepting data and no other host's bucket is evicted. Hosts are counted
// against Limits.MaxReporters by identity, whatever tiers they report.
//
// Expired hours and hosts are pruned at most once per hour of the clock,
// before the report is checked against the limits, so expired hosts never
// keep new ones out. Apart from that, a rejected report changes nothing.
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
	ti, _ := tierIndex(r.Tier) // validated above
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	cutoff := now.Add(-a.limits.Retention)
	if r.To.Before(cutoff) || r.To.After(now.Add(a.limits.MaxClockSkew)) {
		return IngestResult{}, fmt.Errorf("%w: host %q: report ends %s, now %s", ErrOutOfWindow, r.Host,
			r.To.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	floor := a.floorLocked(now)
	if r.To.Unix() < floor {
		return IngestResult{}, fmt.Errorf("%w: host %q: report ends %s, in an hour removed by cutoff", ErrOutOfWindow, r.Host,
			r.To.UTC().Format(time.RFC3339))
	}
	// Prune at most once per hour of the clock, before the limit check,
	// so expired reporters do not keep new hosts out. The pruned hours
	// are closed, so a replayed report from a pruned reporter is refused
	// even after a backwards clock step.
	if h := hourOf(now); !a.pruned || h != a.prunedHour {
		a.pruneLocked(cutoff, cutoff)
		a.pruned, a.prunedHour = true, h
		floor = a.floorLocked(now)
	}
	rs := a.reporters[r.Host]
	if rs != nil {
		last := rs.lastTo[ti]
		if !last.IsZero() && (r.From.Before(last) || !r.To.After(last)) {
			return IngestResult{}, fmt.Errorf("%w: host %q tier %q: report %s..%s, last accepted ended %s", ErrDuplicateReport,
				r.Host, r.Tier, r.From.UTC().Format(time.RFC3339), r.To.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339))
		}
	} else {
		if len(a.reporters) >= a.limits.MaxReporters || a.nextIdx == math.MaxUint32 {
			return IngestResult{}, fmt.Errorf("%w: host %q: %d reporters", ErrLimit, r.Host, len(a.reporters))
		}
		a.nextIdx++
		rs = &reporterState{idx: a.nextIdx}
		a.reporters[r.Host] = rs
	}
	rs.lastTo[ti] = r.To

	var res IngestResult
	parts := splitHours(r.From, r.To)
	limit := max(cutoff.Unix(), floor)
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
			switch a.applyLocked(o, p, rs) {
			case applied:
				res.Applied++
			case dropped:
				res.Dropped++
			case capped:
				res.Capped++
			case conflict:
				res.Conflicts++
			}
		}
	}
	a.dropped += uint64(res.Dropped)
	a.capped += uint64(res.Capped)
	rs.capped += uint64(res.Capped)
	return res, nil
}

type applyResult uint8

const (
	applied applyResult = iota
	dropped
	capped
	conflict
)

// applyLocked adds one hourly part of an observation reported by rs.
func (a *Aggregator) applyLocked(o *Observation, p *hourPart, rs *reporterState) applyResult {
	idx := rs.idx
	hm := a.hours[p.hour]
	b := hm[o.Key]
	if b == nil {
		if a.buckets >= a.limits.MaxBuckets {
			return dropped
		}
		if rs.buckets >= a.limits.MaxBucketsPerReporter {
			a.noteCappedLocked(rs, p.hour)
			return capped
		}
		if hm == nil {
			hm = make(map[FlowKey]*bucket)
			a.hours[p.hour] = hm
		}
		b = &bucket{owner: rs}
		hm[o.Key] = b
		a.buckets++
		rs.buckets++
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

// noteCappedLocked records one part dropped at the per-reporter limit in
// hour, so the host's truncated marker (CappedHosts) expires with the
// hour. The per-host and global counters are updated by applyLocked.
func (a *Aggregator) noteCappedLocked(rs *reporterState, hour int64) {
	if rs.cappedByHour == nil {
		rs.cappedByHour = make(map[int64]uint64)
	}
	rs.cappedByHour[hour]++
	if a.cappedHours[hour] == nil {
		a.cappedHours[hour] = make(map[*reporterState]struct{})
	}
	a.cappedHours[hour][rs] = struct{}{}
}

// dropCappedLocked drops the capped parts of the pruned hour, so a host
// is not marked truncated for data that no longer exists.
func (a *Aggregator) dropCappedLocked(hour int64) {
	for rs := range a.cappedHours[hour] {
		if c := rs.cappedByHour[hour]; c > 0 {
			delete(rs.cappedByHour, hour)
			rs.capped -= c
		}
	}
	delete(a.cappedHours, hour)
}

// hourRange is a run of hour indices lo..hi, both inclusive.
type hourRange struct{ lo, hi int64 }

// maxClosedRanges bounds Aggregator.closed. Steady operation needs one
// run plus one per quiet gap and per clock jump; beyond the bound the two
// oldest runs are merged (see closeHoursLocked).
const maxClosedRanges = 64

// floorLocked returns the unix second before which reports and report
// parts are refused at clock reading now: the end of the newest closed
// hour that lies before the hour containing now.
//
// Invariant: the floor never exceeds the start of the hour containing
// now, and every closed hour before that hour lies below the floor.
//
//   - No sequence of clock jumps can lock out reports: whatever the clock
//     did before, a report ending in the current hour of the clock is
//     never refused for the floor. Hours closed while the clock ran ahead
//     only count once the clock has passed them again, so a forward jump
//     of any length followed by a return leaves the floor at the newest
//     hour pruned before the present, not in the future.
//   - Replay protection survives a backwards clock step: a report ending
//     in, or a part falling into, a pruned hour before the current one
//     is refused.
//
// The only exception to replay protection is the current hour itself
// after it was pruned while the clock ran at least Retention ahead; its
// reports are accepted into fresh buckets rather than locking the hour.
func (a *Aggregator) floorLocked(now time.Time) int64 {
	cur := hourOf(now)
	floor := int64(math.MinInt64)
	for _, r := range a.closed {
		if r.lo >= cur {
			break
		}
		floor = (min(r.hi, cur-1) + 1) * secondsPerHour
	}
	return floor
}

// closeHoursLocked adds the hours lo..hi to the closed runs, merging
// overlapping and adjacent runs. Past maxClosedRanges the two oldest
// runs are merged, which closes the quiet hours between them as well:
// that only refuses more late reports after a backwards clock step and
// keeps the invariant of floorLocked.
func (a *Aggregator) closeHoursLocked(lo, hi int64) {
	if lo > hi {
		return
	}
	i, _ := slices.BinarySearchFunc(a.closed, lo, func(r hourRange, lo int64) int { return cmp.Compare(r.lo, lo) })
	a.closed = slices.Insert(a.closed, i, hourRange{lo, hi})
	if i > 0 {
		i--
	}
	j := i
	out := a.closed[:i]
	for ; j < len(a.closed); j++ {
		r := a.closed[j]
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	a.closed = out
	for len(a.closed) > maxClosedRanges {
		a.closed[1].lo = a.closed[0].lo
		a.closed = slices.Delete(a.closed, 0, 1)
	}
}

// Cutoff removes every hour that ends at or before now-retention. It
// returns the number of removed buckets.
//
// Reporters are removed only once their last report lies in an hour outside
// Limits.Retention as well, so a shorter retention (ADR 0009 D3) keeps the
// duplicate check of reports still inside the ingest window. Reports ending
// before, and report parts falling into, the removed hours are not accepted
// again, so a late or replayed report cannot bring deleted data back.
func (a *Aggregator) Cutoff(now time.Time, retention time.Duration) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	hours := now.Add(-retention)
	// A retention shorter than Limits.Retention closes the hours it cuts
	// from the ingest window even where they hold no data, so a late
	// report cannot fill them again.
	a.closeHoursLocked(hourOf(now.Add(-a.limits.Retention)), hourOf(hours)-1)
	return a.pruneLocked(hours, now.Add(-max(retention, a.limits.Retention)))
}

// pruneLocked removes the hours that end at or before hours and the
// reporters whose last report lies in an hour that ends at or before
// reporters. It closes every hour it removed data from, and the hours of
// the removed reporters' last reports, so they are not filled again.
func (a *Aggregator) pruneLocked(hours, reporters time.Time) int {
	removed := 0
	var gone []int64
	limit := hours.Unix()
	for h, hm := range a.hours {
		if (h+1)*secondsPerHour <= limit {
			for _, b := range hm {
				b.owner.buckets--
			}
			removed += len(hm)
			delete(a.hours, h)
			gone = append(gone, h)
		}
	}
	a.buckets -= removed
	// Capped parts expire with their hour, so the truncated marker of a
	// host reflects the data that still exists. The capped hours are
	// walked separately: a host can be capped in an hour in which it
	// holds no bucket.
	for h := range a.cappedHours {
		if (h+1)*secondsPerHour <= limit {
			a.dropCappedLocked(h)
			gone = append(gone, h)
		}
	}
	// A reporter goes with the hour of its last report (of any tier). All
	// its buckets lie in that hour or earlier, so reporters is never after
	// hours and a host never meets its own buckets under a new index.
	rlimit := reporters.Unix()
	for k, rs := range a.reporters {
		if (hourOf(rs.latest())+1)*secondsPerHour <= rlimit {
			delete(a.reporters, k)
			for _, l := range rs.lastTo {
				if !l.IsZero() {
					gone = append(gone, hourOf(l))
				}
			}
		}
	}
	slices.Sort(gone)
	for i := 0; i < len(gone); {
		j := i + 1
		for j < len(gone) && gone[j] <= gone[j-1]+1 {
			j++
		}
		a.closeHoursLocked(gone[i], gone[j-1])
		i = j
	}
	return removed
}

// Buckets returns the number of (hour, flow) buckets held.
func (a *Aggregator) Buckets() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buckets
}

// Reporters returns the number of tracked reporting hosts.
func (a *Aggregator) Reporters() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.reporters)
}

// Dropped returns how many observation parts were dropped at the global
// bucket limit.
func (a *Aggregator) Dropped() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}

// Capped returns how many observation parts were dropped at the
// per-reporter bucket limit.
func (a *Aggregator) Capped() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.capped
}

// CappedHosts returns the tracked hosts that had parts dropped at the
// per-reporter bucket limit in an hour that still exists, sorted, so the
// map can mark their flows as truncated (ADR 0009 D7). The marker expires
// with the pruned hours: once every hour holding a capped part of a host
// is gone, the host is no longer reported.
func (a *Aggregator) CappedHosts() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for h, rs := range a.reporters {
		if rs.capped > 0 {
			out = append(out, h)
		}
	}
	slices.Sort(out)
	return out
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
