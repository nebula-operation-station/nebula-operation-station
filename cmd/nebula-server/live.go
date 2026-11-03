// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/live"
)

// liveLeaseRefresh is how often the live chart re-reads the approved
// telemetry grants (a revoked or expired grant stops reads within it;
// the executor refuses such reads immediately regardless).
const liveLeaseRefresh = 30 * time.Second

// liveExecutor is the executor surface of the live chart (server role).
type liveExecutor interface {
	ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListReadGrantsResponse, error)
	ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error)
	RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error)
}

// liveChart is the wired live chart delivery (ADR 0006 P1-37).
type liveChart struct {
	handler *live.Handler
	hub     *live.Hub
	sched   *pvecollect.TelemetryScheduler
	exec    liveExecutor
	log     *slog.Logger
	now     func() time.Time
	leases  atomic.Pointer[[]pvecollect.TelemetryLease]
}

// hubSink forwards scheduler samples to the hub, which is built after
// the scheduler (the hub needs the scheduler for its requests).
type hubSink struct{ hub *live.Hub }

func (s *hubSink) RecordTelemetry(ctx context.Context, smp pvecollect.TelemetrySample) error {
	return s.hub.RecordTelemetry(ctx, smp)
}

// newLiveChart builds the live chart: an on-demand-only telemetry
// scheduler over SSH telemetry reads, the fan-out hub and the handler.
func newLiveChart(exec liveExecutor, hosts pvecollect.TelemetryHosts, tree func(context.Context) (pveinventory.Tree, error), log *slog.Logger) (*liveChart, error) {
	lc := &liveChart{exec: exec, log: log, now: time.Now}
	lc.leases.Store(&[]pvecollect.TelemetryLease{})
	sink := &hubSink{}
	sched, err := pvecollect.NewTelemetryScheduler(pvecollect.SSHTelemetryReader{Exec: exec, Hosts: hosts}, sink, pvecollect.TelemetryConfig{})
	if err != nil {
		return nil, fmt.Errorf("live chart scheduler: %w", err)
	}
	hub, err := live.NewHub(sched, log, nil)
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
		Tree: tree,
	})
	if err != nil {
		return nil, fmt.Errorf("live chart handler: %w", err)
	}
	lc.handler, lc.hub, lc.sched = h, hub, sched
	return lc, nil
}

// run refreshes the leases and runs the scheduler and the hub until ctx
// ends; then every viewer is closed.
func (lc *liveChart) run(ctx context.Context) {
	defer lc.hub.Close()
	go lc.hub.Start(ctx)
	go func() {
		if err := lc.sched.Run(ctx); err != nil && ctx.Err() == nil {
			lc.log.Error("live chart scheduler stopped", "error", err)
		}
	}()
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
	if err := lc.sched.SetLeases(leases); err != nil {
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
	all := pvecollect.TelemetryLeasesFromGrants(resp.GetGrants(), pvecollect.TelemetryIdentities{HostKeys: keys}, lc.now())
	return liveLeases(all), nil
}

// liveLeases keeps what the server may serve live: on-demand leases
// only (no background history reads are started here) and SSH targets
// only — provider metrics reads (ReadPVE) are a collector-role RPC the
// server may not call. It never adds a target.
func liveLeases(all []pvecollect.TelemetryLease) []pvecollect.TelemetryLease {
	out := make([]pvecollect.TelemetryLease, 0, len(all))
	for _, l := range all {
		if !l.OnDemand {
			continue
		}
		var targets []pvecollect.TelemetryTarget
		for _, t := range l.Targets {
			if t.Source == pvecollect.TelemetrySSH {
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			continue
		}
		l.Scheduled = false
		l.Targets = targets
		out = append(out, l)
	}
	return out
}
