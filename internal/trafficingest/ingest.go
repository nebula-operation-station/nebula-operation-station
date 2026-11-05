// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	nfresult "github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions/netfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// ActionID is the built-in read action whose results are ingested.
const ActionID = "net.facts"

// maxResultSkew is how far an execution's recorded finish time may lie
// in the future of the ingester's clock.
const maxResultSkew = flowagg.DefaultMaxClockSkew

// Result is one host's net.facts result as the server recorded it.
type Result struct {
	// ExecutionID is the server's execution ID.
	ExecutionID string
	// Host is the execution's target host ID from the server's records.
	Host string
	// Finished is the server's finish time of the host run.
	Finished time.Time
	// Data is the raw result document: untrusted host output.
	Data []byte
}

// Source returns the latest successful net.facts result of a host.
type Source interface {
	LatestNetFacts(ctx context.Context, host string) (Result, bool, error)
}

// Records returns the server's own records of every managed host: its
// interface MACs and addresses from the inventory, keyed by host ID. The
// values must not come from host output (see Exclusive).
type Records interface {
	HostIdentities(ctx context.Context) (map[string]trafficstore.Identity, error)
}

// Store is the subset of *trafficstore.Store the ingester writes to.
type Store interface {
	UpsertEndpoint(ctx context.Context, e trafficstore.Endpoint, own trafficstore.Identity) error
	UpsertBucket(ctx context.Context, b trafficstore.Bucket, own []netip.Addr) error
	ReconcileIdentities(ctx context.Context, current map[string]trafficstore.Identity) (trafficstore.ReconcileResult, error)
	Prune(ctx context.Context) (buckets, endpoints int64, err error)
}

// Outcome says what happened to a host's latest result.
type Outcome string

// Outcomes of HostResult.
const (
	// OutcomeNoResult: the host has no successful net.facts result.
	OutcomeNoResult Outcome = "no-result"
	// OutcomeUnchanged: the latest result was already ingested.
	OutcomeUnchanged Outcome = "unchanged"
	// OutcomeStale: the latest result is not newer than the one
	// ingested before (a clock step on the server); it is ignored.
	OutcomeStale Outcome = "stale"
	// OutcomeInvalid: the result violates the net.facts contract or
	// carries an unusable time; nothing of it is used.
	OutcomeInvalid Outcome = "invalid"
	// OutcomeBaseline: endpoints were written and the socket table is
	// the start of the next diff; no bytes were counted (first snapshot,
	// a gap longer than flowagg.DefaultMaxInterval, or a previous
	// snapshot that could not be diffed).
	OutcomeBaseline Outcome = "baseline"
	// OutcomeNoFlows: endpoints were written, but the socket table was
	// incomplete, so no flows were counted and the next complete
	// snapshot is a baseline.
	OutcomeNoFlows Outcome = "no-flows"
	// OutcomeFlows: endpoints and flow buckets were written.
	OutcomeFlows Outcome = "flows"
	// OutcomeDuplicate: the flow report overlaps one already accepted
	// (flowagg.ErrDuplicateReport); no buckets were written.
	OutcomeDuplicate Outcome = "duplicate"
)

// HostResult reports the ingestion of one host.
type HostResult struct {
	Host        string
	ExecutionID string
	Outcome     Outcome
	// Incomplete is set when the result lost data (spec 09); it must be
	// shown as incomplete.
	Incomplete bool
	// Truncated is set when MaxEndpointsPerResult or an address bound
	// cut the endpoints.
	Truncated bool
	// Endpoints counts endpoints written; EndpointsRefused those the
	// store refused (limits, out of range, invalid).
	Endpoints, EndpointsRefused int
	// Buckets counts hourly bucket parts written. Foreign, Conflicts and
	// Limited count parts the store refused (ErrForeign, ErrConflict,
	// ErrLimit or ErrOutOfRange).
	Buckets, Foreign, Conflicts, Limited int
	// LowerBound is set when the counted bytes are a lower bound.
	LowerBound bool
	// Gateways are the host's default gateways (reporter's claim).
	Gateways []Gateway
	// Err is the error that stopped this host, if any.
	Err error
}

// SyncResult reports one Sync.
type SyncResult struct {
	Hosts []HostResult
	// Reconciled is set when ReconcileIdentities ran; Reconcile is its
	// result.
	Reconciled bool
	Reconcile  trafficstore.ReconcileResult
	// Pruned is set when the hourly Prune ran.
	Pruned bool
}

// hostState is what the ingester keeps per host between results.
type hostState struct {
	execID string
	at     time.Time
	// snap is the last complete socket snapshot, nil when the next
	// complete one is a baseline.
	snap *flowagg.Snapshot
	net  HostNet
}

// Ingester ingests net.facts results. It is safe for concurrent use;
// Sync calls are serialized.
type Ingester struct {
	src     Source
	records Records
	store   Store
	agg     *flowagg.Aggregator
	now     func() time.Time
	log     *slog.Logger

	mu    sync.Mutex
	hosts map[string]*hostState
	// identities are the exclusive identities last reconciled;
	// reconciledHour is the clock hour of that reconcile.
	identities     map[string]trafficstore.Identity
	reconciledHour int64
	reconciled     bool
}

// Config configures an Ingester.
type Config struct {
	Source  Source
	Records Records
	Store   Store
	// Limits bound the in-memory aggregator that guards against
	// overlapping reports; zero fields take flowagg's defaults.
	Limits flowagg.Limits
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Log receives one line per refused or failed host; nil discards.
	Log *slog.Logger
}

// New returns an Ingester.
func New(c Config) (*Ingester, error) {
	if c.Source == nil || c.Records == nil || c.Store == nil {
		return nil, errors.New("trafficingest: source, records and store are required")
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	log := c.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Ingester{
		src: c.Source, records: c.Records, store: c.Store, now: now, log: log,
		agg:   flowagg.NewAggregator(c.Limits, now),
		hosts: map[string]*hostState{},
	}, nil
}

// HostNet returns the routing view of host from its latest ingested
// result, for drawing flows through the gateway hop.
func (in *Ingester) HostNet(host string) (HostNet, bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	st, ok := in.hosts[host]
	if !ok {
		return HostNet{}, false
	}
	return st.net, true
}

// Reconcile loads the server's host records and calls
// ReconcileIdentities with their exclusive identities. Callers run it
// whenever host records change; Sync also runs it when the records it
// loads differ from the last reconciled ones and once per clock hour.
func (in *Ingester) Reconcile(ctx context.Context) (trafficstore.ReconcileResult, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	ids, err := in.loadIdentities(ctx)
	if err != nil {
		return trafficstore.ReconcileResult{}, err
	}
	return in.reconcileLocked(ctx, ids)
}

func (in *Ingester) loadIdentities(ctx context.Context) (map[string]trafficstore.Identity, error) {
	recs, err := in.records.HostIdentities(ctx)
	if err != nil {
		return nil, fmt.Errorf("trafficingest: load host records: %w", err)
	}
	return Exclusive(recs), nil
}

func (in *Ingester) reconcileLocked(ctx context.Context, ids map[string]trafficstore.Identity) (trafficstore.ReconcileResult, error) {
	res, err := in.store.ReconcileIdentities(ctx, ids)
	if err != nil {
		return res, fmt.Errorf("trafficingest: reconcile identities: %w", err)
	}
	if len(res.Skipped) > 0 {
		in.log.Warn("traffic ingest: host records skipped by reconcile", "hosts", res.Skipped)
	}
	in.identities = ids
	in.reconciledHour = floorHour(in.now())
	in.reconciled = true
	return res, nil
}

// Sync runs one ingestion round: it loads the server's host records,
// reconciles endpoint ownership when they changed or a clock hour
// passed (then also prunes), and ingests the latest net.facts result of
// every recorded host. A host's failure is reported in its HostResult
// and does not stop the others; the returned error is for failures that
// stop the whole round (records, reconcile, context).
func (in *Ingester) Sync(ctx context.Context) (SyncResult, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	var out SyncResult
	ids, err := in.loadIdentities(ctx)
	if err != nil {
		return out, err
	}
	hour := floorHour(in.now())
	hourly := !in.reconciled || hour != in.reconciledHour
	if hourly || !identitiesEqual(ids, in.identities) {
		res, err := in.reconcileLocked(ctx, ids)
		if err != nil {
			return out, err
		}
		out.Reconciled, out.Reconcile = true, res
	}
	if hourly {
		if _, _, err := in.store.Prune(ctx); err != nil {
			return out, fmt.Errorf("trafficingest: prune: %w", err)
		}
		out.Pruned = true
	}
	// Forget hosts that are no longer managed.
	for h := range in.hosts {
		if _, ok := ids[h]; !ok {
			delete(in.hosts, h)
		}
	}
	hosts := make([]string, 0, len(ids))
	for h := range ids {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		r := in.ingestHost(ctx, h, ids[h])
		if r.Err != nil {
			in.log.Warn("traffic ingest: host failed", "host", h, "execution", r.ExecutionID, "err", r.Err)
		}
		out.Hosts = append(out.Hosts, r)
	}
	return out, nil
}

// ingestHost ingests the latest result of host. own is the host's
// exclusive identity from the server's records.
func (in *Ingester) ingestHost(ctx context.Context, host string, own trafficstore.Identity) HostResult {
	hr := HostResult{Host: host}
	res, ok, err := in.src.LatestNetFacts(ctx, host)
	if err != nil {
		hr.Err = fmt.Errorf("load latest net.facts of %s: %w", host, err)
		return hr
	}
	if !ok {
		hr.Outcome = OutcomeNoResult
		return hr
	}
	hr.ExecutionID = res.ExecutionID
	prev := in.hosts[host]
	switch {
	case res.Host != host:
		// The source must return the requested host's record; anything
		// else would let one host's output be labeled as another's.
		hr.Outcome, hr.Err = OutcomeInvalid, fmt.Errorf("source returned host %q for %q", res.Host, host)
		return hr
	case prev != nil && prev.execID == res.ExecutionID:
		hr.Outcome = OutcomeUnchanged
		return hr
	case prev != nil && !res.Finished.After(prev.at):
		hr.Outcome = OutcomeStale
		return hr
	}
	now := in.now()
	if res.Finished.IsZero() || res.Finished.After(now.Add(maxResultSkew)) {
		hr.Outcome = OutcomeInvalid
		hr.Err = fmt.Errorf("execution %s: finish time %s not usable", res.ExecutionID, res.Finished.UTC().Format(time.RFC3339))
		in.markInvalid(host, res.ExecutionID, prev)
		return hr
	}
	facts, err := nfresult.Decode(res.Data)
	if err != nil {
		hr.Outcome, hr.Err = OutcomeInvalid, fmt.Errorf("execution %s: %w", res.ExecutionID, err)
		in.markInvalid(host, res.ExecutionID, prev)
		return hr
	}
	hr.Incomplete = facts.Incomplete()

	// The time is the server's; the reporter label is the server's host ID.
	at := res.Finished
	eps, truncated := endpointsOf(host, at, facts)
	hr.Truncated = truncated
	for _, e := range eps {
		err := in.store.UpsertEndpoint(ctx, e, own)
		switch {
		case err == nil:
			hr.Endpoints++
		case errors.Is(err, trafficstore.ErrInvalidEndpoint), errors.Is(err, trafficstore.ErrLimit),
			errors.Is(err, trafficstore.ErrOutOfRange):
			hr.EndpointsRefused++
		default:
			// Nothing of the flows is written yet: the next Sync retries
			// the whole result, and endpoint upserts are idempotent.
			hr.Err = fmt.Errorf("execution %s: write endpoint: %w", res.ExecutionID, err)
			return hr
		}
	}

	hn := DeriveHostNet(host, append(slices.Clone(facts.Routes.Entries), facts.Routes6.Entries...),
		append(slices.Clone(facts.Neigh.Entries), facts.Neigh6.Entries...))
	hr.Gateways = hn.Defaults

	snap, usable := snapshotOf(host, at, facts)
	if !usable {
		hr.Outcome = OutcomeNoFlows
		in.markSeen(host, res, nil, hn)
		return hr
	}
	if prev == nil || prev.snap == nil {
		hr.Outcome = OutcomeBaseline
		in.markSeen(host, res, snap, hn)
		return hr
	}
	report, err := flowagg.Observe(prev.snap, snap)
	if err != nil {
		// Not comparable (cannot happen for snapshots built here with
		// increasing server times): start over.
		hr.Outcome = OutcomeBaseline
		in.markSeen(host, res, snap, hn)
		return hr
	}
	// From here on the result counts as ingested whatever the store
	// says: a retry must never add the same diff twice.
	in.markSeen(host, res, snap, hn)
	if _, err := in.agg.Ingest(report, own.Addrs); err != nil {
		switch {
		case errors.Is(err, flowagg.ErrIntervalTooLong), errors.Is(err, flowagg.ErrOutOfWindow):
			hr.Outcome = OutcomeBaseline
		case errors.Is(err, flowagg.ErrDuplicateReport):
			hr.Outcome = OutcomeDuplicate
		case errors.Is(err, flowagg.ErrInvalidReport):
			// No own addresses on record: flows cannot be attributed.
			hr.Outcome = OutcomeNoFlows
		default:
			hr.Outcome, hr.Err = OutcomeNoFlows, fmt.Errorf("execution %s: aggregate: %w", res.ExecutionID, err)
		}
		return hr
	}
	hr.Outcome = OutcomeFlows
	hr.LowerBound = report.LowerBound
	if err := in.writeBuckets(ctx, &hr, report, own.Addrs); err != nil {
		hr.Err = fmt.Errorf("execution %s: %w", res.ExecutionID, err)
	}
	return hr
}

// markInvalid records an unusable execution so it is not retried every
// round. The time cursor stays where it was (an unusable time must not
// make later results look stale) and the next usable socket table is a
// baseline.
func (in *Ingester) markInvalid(host, execID string, prev *hostState) {
	st := &hostState{execID: execID, net: HostNet{Reporter: host}}
	if prev != nil {
		st.at, st.net = prev.at, prev.net
	}
	in.hosts[host] = st
}

func (in *Ingester) markSeen(host string, res Result, snap *flowagg.Snapshot, hn HostNet) {
	in.hosts[host] = &hostState{execID: res.ExecutionID, at: res.Finished, snap: snap, net: hn}
}

// writeBuckets stores the hourly parts of every observation of report.
func (in *Ingester) writeBuckets(ctx context.Context, hr *HostResult, report flowagg.Report, own []netip.Addr) error {
	parts := splitHours(report.From, report.To)
	for _, o := range report.Observations {
		for _, p := range parts {
			b := trafficstore.Bucket{
				Hour: p.start, Key: o.Key, Reporter: report.Host, ServerReported: o.ServerReported,
				BytesAB: p.share(o.BytesAB), BytesBA: p.share(o.BytesBA), Connections: p.share(o.Connections),
				LowerBound: o.LowerBound,
			}
			err := in.store.UpsertBucket(ctx, b, own)
			switch {
			case err == nil:
				hr.Buckets++
			case errors.Is(err, trafficstore.ErrForeign):
				hr.Foreign++
			case errors.Is(err, trafficstore.ErrConflict):
				hr.Conflicts++
			case errors.Is(err, trafficstore.ErrLimit), errors.Is(err, trafficstore.ErrOutOfRange),
				errors.Is(err, trafficstore.ErrInvalidBucket):
				hr.Limited++
			default:
				return fmt.Errorf("write bucket: %w", err)
			}
		}
	}
	return nil
}
