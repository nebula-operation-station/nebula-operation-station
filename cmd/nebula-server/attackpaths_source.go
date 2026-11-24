// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/sources"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/paths"
)

// attackPathInterval is how often the server recomputes the attack paths
// (ADR 0011 D10). A computation also runs once at start.
const attackPathInterval = 15 * time.Minute

// errNoAttackPathDB marks a source built without the server database.
var errNoAttackPathDB = errors.New("attack paths: no server database")

// attackPathHostID is the attack-path node ID of an inventory host.
func attackPathHostID(id string) string { return attackPathHostPrefix + id }

// attackPathSource computes the attack paths from the stored data (ADR 0011
// D10) and serves the last successful result. Snapshot reads only the
// cache; Refresh runs one computation. A computation that fails for any
// reason is discarded: the previous snapshot stays, with its ComputedAt, so
// the pages show its age and never an empty result for a failed run.
type attackPathSource struct {
	db        *sql.DB
	vuln      *vulnService
	retention time.Duration
	log       *slog.Logger
	now       func() time.Time

	// Readers of the adapters; the server fills them with the real stores
	// (newAttackPathSource), tests may replace them.
	hosts      sources.HostLister
	placements sources.PlacementReader
	flows      sources.FlowReader

	mu   sync.RWMutex
	snap paths.Snapshot
}

// newAttackPathSource returns the source over the server's stores. It reads
// the stores only; it writes nothing but its cache.
func newAttackPathSource(d serverDeps) *attackPathSource {
	s := &attackPathSource{
		db:        d.db,
		vuln:      d.vuln,
		retention: d.retention,
		log:       d.log,
		now:       time.Now,
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if d.inventory != nil {
		s.hosts = d.inventory
	}
	if d.pveStore != nil {
		s.placements = d.pveStore
	}
	if d.db != nil {
		// A retention outside the store's bounds leaves the reader nil: the
		// flow adapter then reports the source unavailable, never "no flows".
		if ts, err := trafficstore.NewWithRetention(d.db, d.retention); err == nil {
			s.flows = ts
		}
	}
	return s
}

// Snapshot implements paths.Source. It reads the cache only.
func (s *attackPathSource) Snapshot(context.Context) (paths.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap, nil
}

// run recomputes the attack paths every attackPathInterval until ctx ends.
// A failed computation is logged and the previous snapshot stays.
func (s *attackPathSource) run(ctx context.Context) {
	t := time.NewTicker(attackPathInterval)
	defer t.Stop()
	for {
		if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("attack paths: computation discarded, previous result kept", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Refresh runs one computation and replaces the snapshot when it succeeds.
// With no crown jewel there is nothing to compute: the snapshot becomes
// "not computed" (no result), never an empty result.
func (s *attackPathSource) Refresh(ctx context.Context) error {
	snap, err := s.compute(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
	return nil
}

// compute builds the graph from the adapters and scores the paths to the
// crown jewels. Every adapter error discards the run. Docker, firewall and
// VLAN are not read here: Merge reports them as missing, so the coverage
// never reads complete for them.
func (s *attackPathSource) compute(ctx context.Context) (paths.Snapshot, error) {
	if s.db == nil {
		return paths.Snapshot{}, errNoAttackPathDB
	}
	js, err := jewels.New(s.db, s.log, nil)
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: crown jewels: %w", err)
	}
	targets, err := js.Targets(ctx)
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: targets: %w", err)
	}
	if len(targets) == 0 {
		return paths.Snapshot{}, nil
	}
	jewelList, err := js.List(ctx)
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: crown jewels: %w", err)
	}
	executor := ""
	for _, j := range jewelList {
		if j.Role == jewels.RoleExecutorHost {
			executor, _ = strings.CutPrefix(j.Node, attackPathHostPrefix)
			break
		}
	}
	if s.placements == nil || s.flows == nil || s.hosts == nil {
		return paths.Snapshot{}, errors.New("attack paths: a source reader is missing")
	}

	cred, err := sources.Credentials(ctx, sources.CredentialConfig{Hosts: s.hosts, ExecutorHostID: executor})
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: credentials: %w", err)
	}
	place, err := sources.Placements(ctx, sources.PlacementConfig{Reader: s.placements})
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: placements: %w", err)
	}
	owners, err := s.owners(ctx)
	if err != nil {
		return paths.Snapshot{}, err
	}
	lookback := sources.DefaultFlowLookback
	if s.retention > 0 && s.retention < lookback {
		lookback = s.retention
	}
	flow, err := sources.Flows(ctx, sources.FlowConfig{
		Reader:   s.flows,
		Hosts:    s.hosts,
		Managed:  sources.ManagedNodes(place),
		Aliases:  place.Aliases,
		Owners:   owners,
		Now:      s.now,
		Lookback: lookback,
	})
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: flows: %w", err)
	}

	b := attackpath.NewBuilder()
	rep, err := sources.Merge(b, cred, place, flow)
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: merge: %w", err)
	}
	g := b.Build()

	findings, byKey, err := s.findings(ctx)
	if err != nil {
		return paths.Snapshot{}, err
	}
	tg := make([]attackpath.Target, len(targets))
	copy(tg, targets)
	res, err := attackpath.Compute(g, findings, tg, attackpath.Options{Now: s.now})
	if err != nil {
		return paths.Snapshot{}, fmt.Errorf("attack paths: compute: %w", err)
	}

	labels := make(map[string]string, len(g.Nodes()))
	for _, n := range g.Nodes() {
		if n.Label != "" {
			labels[n.ID] = n.Label
		}
	}
	info := map[paths.FindingRef]paths.FindingInfo{}
	addInfo := func(node, key string) {
		ref := paths.FindingRef{Node: node, Key: key}
		if fi, ok := byKey[ref]; ok {
			info[ref] = fi
		}
	}
	for _, t := range res.Targets {
		for _, p := range t.Paths {
			for _, st := range p.Steps {
				if st.Finding != "" {
					addInfo(st.To, st.Finding)
				}
			}
		}
	}
	for _, c := range res.ChokePoints {
		if c.Kind == attackpath.FixFinding {
			addInfo(c.Node, c.Finding)
		}
	}
	return paths.Snapshot{
		Result:     res,
		Report:     &rep,
		ComputedAt: s.now(),
		Labels:     labels,
		Findings:   info,
	}, nil
}

// owners maps each managed address to the host that owns it. An address
// claimed by more than one host has no owner and is not queried.
func (s *attackPathSource) owners(ctx context.Context) ([]sources.AddressOwner, error) {
	byAddr, err := ipam.FromInventory(s.hosts.List)(ctx)
	if err != nil {
		return nil, fmt.Errorf("attack paths: host addresses: %w", err)
	}
	hosts, err := s.hosts.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("attack paths: hosts: %w", err)
	}
	names := make(map[string]string, len(hosts))
	for _, h := range hosts {
		names[h.ID] = h.DisplayName
	}
	var out []sources.AddressOwner
	for a, ids := range byAddr {
		if len(ids) != 1 {
			continue
		}
		out = append(out, sources.AddressOwner{Addr: a, NodeID: attackPathHostID(ids[0]), Kind: attackpath.NodeHost, Label: names[ids[0]]})
	}
	return out, nil
}

// findings reads the open findings of the vulnerability store as attack
// path findings on their host nodes. A finding that is fixed is not read;
// one on an image or device is not on the host graph and is not passed.
// A list that the store cut is an error: a partial list would read as a
// finding-free host.
func (s *attackPathSource) findings(ctx context.Context) ([]attackpath.Finding, map[paths.FindingRef]paths.FindingInfo, error) {
	if s.vuln == nil || s.vuln.store == nil {
		return nil, nil, errors.New("attack paths: no findings store")
	}
	fs, more, err := s.vuln.store.List(ctx, vulnstore.ListQuery{ExcludeFixed: true, Limit: vulnstore.MaxListFindings})
	if err != nil {
		return nil, nil, fmt.Errorf("attack paths: findings: %w", err)
	}
	if more {
		return nil, nil, errors.New("attack paths: findings list cut by the store limit")
	}
	out := make([]attackpath.Finding, 0, len(fs))
	info := make(map[paths.FindingRef]paths.FindingInfo, len(fs))
	for _, f := range fs {
		if f.Record.SubjectKind != "host" {
			continue
		}
		r := f.Record
		node := attackPathHostID(r.SubjectRef.ID)
		key := f.Key.String()
		var fg attackpath.Finding
		fg.Node, fg.Key = node, key
		if r.Scores.CVSS != nil {
			fg.Vector = r.Scores.CVSS.Vector
		}
		fg.KEV = r.Scores.KEV != nil
		if r.Scores.EPSS != nil {
			fg.EPSS, fg.EPSSKnown = r.Scores.EPSS.Probability, true
		}
		switch f.State {
		case vulnstore.StateAcceptedRisk:
			fg.State = attackpath.FindingAcceptedRisk
		case vulnstore.StateFalsePositive:
			fg.State = attackpath.FindingFalsePositive
		default:
			fg.State = attackpath.FindingOpen
		}
		out = append(out, fg)
		info[paths.FindingRef{Node: node, Key: key}] = paths.FindingInfo{VulnID: r.Vuln.ID, Package: r.Component.SourcePackage}
	}
	return out, info, nil
}
