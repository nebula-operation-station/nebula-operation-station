// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// floorFake answers RunReadGrant the way the executor does for an action
// with its own interval floor (permit.ReadActionMinInterval): a run of the
// same action on the same host sooner than the floor after the last accepted
// one is refused with ResourceExhausted. Every request is recorded in runs,
// accepted or not.
type floorFake struct {
	*leaseRunFake
	clock    *time.Time
	accepted map[string]time.Time // action and host -> last accepted run
}

func (f *floorFake) RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	action, host := in.GetRun().GetActionId(), in.GetRun().GetHostId()
	key := action + "\x00" + host
	if floor := permit.ReadActionMinInterval(action); floor > 0 {
		if at, ok := f.accepted[key]; ok && f.clock.Sub(at) < floor {
			f.runs = append(f.runs, in)
			return nil, status.Error(codes.ResourceExhausted, "read_grant_budget_exhausted: read interval or rolling-hour budget exhausted")
		}
	}
	f.accepted[key] = *f.clock
	return f.leaseRunFake.RunReadGrant(ctx, in, opts...)
}

// floorLease is an approved lease on web with core.facts,
// package.list_installed and package.list_updates in that order. The budget
// is the maximum, so only the interval rules are under test.
func floorLease(t *testing.T, n time.Time) *pb.ReadGrant {
	t.Helper()
	doc := leaseDoc(t, n, []string{"web"}, "core.facts", "package.list_installed", "package.list_updates")
	doc.RunBudget = permit.MaxRunBudget
	return leaseEntry(t, doc, n)
}

// setupFloorLease is setupLeases with the floor-enforcing executor double.
func setupFloorLease(t *testing.T, now *time.Time) (*Service, *floorFake) {
	t.Helper()
	s, f := setupLeases(t, now, func(n time.Time) *pb.ReadGrant { return floorLease(t, n) })
	ff := &floorFake{leaseRunFake: f, clock: now, accepted: map[string]time.Time{}}
	s.exec = ff
	return s, ff
}

// requestsSince returns the action IDs of the requests made after the first n.
func requestsSince(f *floorFake, n int) []string {
	var out []string
	for _, r := range f.runs[n:] {
		out = append(out, r.GetRun().GetActionId())
	}
	return out
}

// containsAction reports whether v is one of the action IDs in s.
func containsAction(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// newRestartedService is a second Service on the same database and executor,
// as after a server restart. It serves the single host web.
func newRestartedService(t *testing.T, old *Service, f *floorFake, now *time.Time) *Service {
	t.Helper()
	hosts := fakeHosts{"web": {ID: "web", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}}}}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, f, old.db, hosts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.now = func() time.Time { return *now }
	t.Cleanup(func() { cancel(); s.Wait() })
	return s
}

func TestPackageListInstalledIsAskedOnItsSixHourFloor(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	start := now
	s, f := setupFloorLease(t, &now)
	ctx := context.Background()

	var installed []time.Duration
	for step := 0; step <= 28; step++ { // 15-minute steps over seven hours
		before := len(f.runs)
		s.RunDueReadGrants(ctx)
		got := requestsSince(f, before)
		elapsed := now.Sub(start)
		if !containsAction(got, "core.facts") || !containsAction(got, "package.list_updates") {
			t.Fatalf("at %v the other actions were not asked: %v", elapsed, got)
		}
		if containsAction(got, "package.list_installed") {
			installed = append(installed, elapsed)
		}
		now = now.Add(15 * time.Minute)
	}
	if len(installed) != 2 || installed[0] != 0 || installed[1] != 6*time.Hour {
		t.Fatalf("package.list_installed asked at %v, want at 0h and 6h", installed)
	}
}

func TestFloorSurvivesARestart(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	start := now
	s, f := setupFloorLease(t, &now)
	ctx := context.Background()
	s.RunDueReadGrants(ctx) // the stored run of package.list_installed at 0 h

	// A restarted runner keeps no memory: only the stored executions remain.
	restarted := newRestartedService(t, s, f, &now)
	var asked []time.Duration
	for step := 1; step <= 24; step++ { // 15-minute steps up to 6 h
		now = now.Add(15 * time.Minute)
		before := len(f.runs)
		restarted.RunDueReadGrants(ctx)
		if containsAction(requestsSince(f, before), "package.list_installed") {
			asked = append(asked, now.Sub(start))
		}
	}
	if len(asked) != 1 || asked[0] != 6*time.Hour {
		t.Fatalf("after the restart package.list_installed asked at %v, want only at 6h", asked)
	}
}
