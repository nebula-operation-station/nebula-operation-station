// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func liveTestLease(id string, onDemand, scheduled bool, targets ...pvecollect.TelemetryTarget) pvecollect.TelemetryLease {
	return pvecollect.TelemetryLease{
		GrantID: id, GrantDigest: "d-" + id, OnDemand: onDemand, Scheduled: scheduled,
		ExpiresAt: time.Now().Add(time.Hour), MinInterval: pvecollect.TelemetryLiveInterval,
		RunBudget: 1, Targets: targets,
	}
}

func TestLiveLeasesKeepOnlyOnDemandSSHTargets(t *testing.T) {
	ssh := pvecollect.TelemetryTarget{Source: pvecollect.TelemetrySSH, HostID: "web01", HostKey: "SHA256:" + strings.Repeat("A", 43), ActionID: "host.metrics"}
	pve := pvecollect.TelemetryTarget{Source: pvecollect.TelemetryProvider, RemoteID: "remote-a", TrustPin: strings.Repeat("ab", 32), TrustGeneration: 1, Node: "pve1", Kind: pvecollect.TelemetryKindNode}
	got := liveLeases([]pvecollect.TelemetryLease{
		liveTestLease("both", true, true, ssh, pve),
		liveTestLease("history", false, true, ssh),
		liveTestLease("provider", true, false, pve),
	})
	if len(got) != 1 || got[0].GrantID != "both" {
		t.Fatalf("leases = %+v, want only \"both\"", got)
	}
	if got[0].Scheduled || !got[0].OnDemand {
		t.Fatalf("live lease triggers = scheduled %v on-demand %v, want on-demand only", got[0].Scheduled, got[0].OnDemand)
	}
	if len(got[0].Targets) != 1 || got[0].Targets[0] != ssh {
		t.Fatalf("targets = %+v, want only the SSH target", got[0].Targets)
	}
}

// failingExec fails every call.
type failingExec struct{}

var errExecDown = errors.New("executor down")

func (failingExec) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	return nil, errExecDown
}

func (failingExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return nil, errExecDown
}

func (failingExec) RunReadGrant(context.Context, *pb.RunReadGrantRequest, ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	return nil, errExecDown
}

type noHosts struct{}

func (noHosts) Get(context.Context, string) (inventory.Host, error) {
	return inventory.Host{}, errors.New("no host")
}

func TestLiveRefreshFailureClearsLeases(t *testing.T) {
	lc, err := newLiveChart(failingExec{}, noHosts{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ssh := pvecollect.TelemetryTarget{Source: pvecollect.TelemetrySSH, HostID: "web01", HostKey: "SHA256:" + strings.Repeat("A", 43), ActionID: "host.metrics"}
	stale := []pvecollect.TelemetryLease{liveTestLease("old", true, false, ssh)}
	lc.leases.Store(&stale)
	if err := lc.sched.SetLeases(stale); err != nil {
		t.Fatal(err)
	}
	if _, err := lc.sched.Request(strings.Repeat("a", 32), ssh); err != nil {
		t.Fatalf("request under the stale lease: %v", err)
	}
	lc.refresh(context.Background())
	if n := len(*lc.leases.Load()); n != 0 {
		t.Fatalf("leases after failed refresh = %d, want 0", n)
	}
	if _, err := lc.sched.Request(strings.Repeat("a", 32), ssh); !errors.Is(err, pvecollect.ErrTelemetryNotAuthorized) {
		t.Fatalf("request after failed refresh: err = %v, want not authorized", err)
	}
}
