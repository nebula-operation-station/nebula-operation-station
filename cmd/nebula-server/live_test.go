// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/live"
)

func liveTestLease(id string, onDemand, scheduled bool, targets ...pvecollect.TelemetryTarget) pvecollect.TelemetryLease {
	return pvecollect.TelemetryLease{
		GrantID: id, GrantDigest: "d-" + id, OnDemand: onDemand, Scheduled: scheduled,
		ExpiresAt: time.Now().Add(time.Hour), MinInterval: pvecollect.TelemetryLiveInterval,
		RunBudget: 1, Targets: targets,
	}
}

func liveSSHTarget(host string) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{Source: pvecollect.TelemetrySSH, HostID: host, HostKey: "SHA256:" + strings.Repeat("A", 43), ActionID: "host.metrics"}
}

func liveNodeTarget(remote, node string) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{Source: pvecollect.TelemetryProvider, RemoteID: remote, TrustPin: strings.Repeat("ab", 32), TrustGeneration: 1, Node: node, Kind: pvecollect.TelemetryKindNode}
}

func liveGuestTarget(remote, node string, vmid, gen uint64) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{Source: pvecollect.TelemetryProvider, RemoteID: remote, TrustPin: strings.Repeat("ab", 32), TrustGeneration: 1, Node: node, Kind: pvecollect.TelemetryKindQEMU, VMID: vmid, Generation: gen}
}

func TestLiveLeasesKeepOnDemandSSHAndProviderTargets(t *testing.T) {
	ssh := liveSSHTarget("web01")
	node := liveNodeTarget("remote-a", "pve1")
	guest := liveGuestTarget("remote-a", "pve1", 101, 3)
	got := liveLeases([]pvecollect.TelemetryLease{
		liveTestLease("both", true, true, ssh, node),
		liveTestLease("history", false, true, ssh, node),
		liveTestLease("node-only", true, false, node),
		liveTestLease("guest-only", true, false, guest),
	})
	ids := []string{}
	for _, l := range got {
		ids = append(ids, l.GrantID)
		if l.Scheduled || !l.OnDemand {
			t.Fatalf("lease %s triggers = scheduled %v on-demand %v, want on-demand only", l.GrantID, l.Scheduled, l.OnDemand)
		}
	}
	if strings.Join(ids, ",") != "both,node-only,guest-only" {
		t.Fatalf("leases = %v, want both,node-only,guest-only", ids)
	}
	if len(got[0].Targets) != 2 || got[1].Targets[0] != node || got[2].Targets[0] != guest {
		t.Fatalf("targets = %+v", got)
	}
	// The SSH scheduler only ever sees SSH targets.
	sshOnly := sshLeases(got)
	if len(sshOnly) != 1 || len(sshOnly[0].Targets) != 1 || sshOnly[0].Targets[0] != ssh {
		t.Fatalf("ssh leases = %+v, want only the SSH target of lease both", sshOnly)
	}
}

// TestLiveExecutorHasNoReadPVE pins the server role: the live chart's
// executor surface cannot issue provider reads (ReadPVE is collector-only).
func TestLiveExecutorHasNoReadPVE(t *testing.T) {
	typ := reflect.TypeFor[liveExecutor]()
	if _, ok := typ.MethodByName("ReadPVE"); ok {
		t.Fatal("liveExecutor exposes ReadPVE; the server must not read provider metrics")
	}
	if _, ok := typ.MethodByName("ListPVERemotes"); !ok {
		t.Fatal("liveExecutor lacks ListPVERemotes (provider targets need the remote identities)")
	}
}

// fakeHandoff records want-lists and serves fixed samples per remote.
type fakeHandoff struct {
	wants   []pvecontract.LiveWant
	samples map[string]pvecontract.LiveSamples
	reads   []string
}

func (f *fakeHandoff) WriteLiveWant(_ context.Context, w pvecontract.LiveWant) error {
	if _, err := pvecontract.ValidateLiveWant(w); err != nil {
		return err
	}
	f.wants = append(f.wants, w)
	return nil
}

func (f *fakeHandoff) ReadLiveSamples(_ context.Context, remote string) (pvecontract.LiveSamples, error) {
	f.reads = append(f.reads, remote)
	s, ok := f.samples[remote]
	if !ok {
		return pvecontract.LiveSamples{}, errors.New("no samples")
	}
	return s, nil
}

func (f *fakeHandoff) lastWant(t *testing.T) pvecontract.LiveWant {
	t.Helper()
	if len(f.wants) == 0 {
		t.Fatal("no want-list written")
	}
	return f.wants[len(f.wants)-1]
}

type liveFixture struct {
	lc    *liveChart
	clock time.Time
	h     *fakeHandoff
}

func (f *liveFixture) now() time.Time { return f.clock }

// newLiveFixture builds a live chart over a fixed tree (remote-a: pve1
// with guest 101 generation 3, pve2; remote-b: pve9) whose viewers all
// belong to session "s".
func newLiveFixture(t *testing.T, leases ...pvecollect.TelemetryLease) *liveFixture {
	t.Helper()
	f := &liveFixture{clock: time.Unix(1_800_000_000, 0), h: &fakeHandoff{samples: map[string]pvecontract.LiveSamples{}}}
	tree := pveinventory.Tree{Roots: []pveinventory.Box{
		{Kind: pveinventory.KindPVENode, Name: "pve1", RemoteID: "remote-a", Children: []pveinventory.Box{
			{Kind: pveinventory.KindGuest, VMID: 101, Generation: 3},
		}},
		{Kind: pveinventory.KindPVENode, Name: "pve2", RemoteID: "remote-a"},
		{Kind: pveinventory.KindPVENode, Name: "pve9", RemoteID: "remote-b"},
	}}
	lc, err := buildLiveChart(failingExec{}, noHosts{},
		func(context.Context) (pveinventory.Tree, error) { return tree, nil }, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(*http.Request) (string, bool) { return "s", true }, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for i := range leases {
		leases[i].ExpiresAt = f.clock.Add(time.Hour)
	}
	lc.applyLeases(liveLeases(leases))
	f.lc = lc
	return f
}

func (f *liveFixture) viewer(t *testing.T, n int) (string, <-chan live.Event) {
	t.Helper()
	id := fmt.Sprintf("%032x", n)
	ch, err := f.lc.hub.Add(id, "s")
	if err != nil {
		t.Fatal(err)
	}
	return id, ch
}

type liveTargetsReply struct {
	Granted []string `json:"granted"`
	Denied  []string `json:"denied"`
}

func (f *liveFixture) show(t *testing.T, viewer, boxes string) liveTargetsReply {
	t.Helper()
	body := `{"viewer":"` + viewer + `","boxes":[` + boxes + `]}`
	rec := httptest.NewRecorder()
	f.lc.handler.Targets(rec, httptest.NewRequest(http.MethodPost, live.TargetsPath, strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("targets: status %d %s", rec.Code, rec.Body.String())
	}
	var r liveTargetsReply
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLiveNodeBoxGrantedOnlyWhenCovered(t *testing.T) {
	f := newLiveFixture(t,
		liveTestLease("ondemand", true, false, liveNodeTarget("remote-a", "pve1")),
		liveTestLease("history", false, true, liveNodeTarget("remote-a", "pve2")),
	)
	v, _ := f.viewer(t, 1)
	r := f.show(t, v, `{"kind":"node","name":"pve1"},{"kind":"node","name":"pve2"},{"kind":"node","name":"pve9"}`)
	if strings.Join(r.Granted, ",") != "node:pve1" || strings.Join(r.Denied, ",") != "node:pve2,node:pve9" {
		t.Fatalf("granted %v denied %v, want granted [node:pve1], denied [node:pve2 node:pve9]", r.Granted, r.Denied)
	}
	// The provider scheduler itself refuses an uncovered target.
	if _, err := f.lc.prov.Request(v, liveNodeTarget("remote-a", "pve2")); !errors.Is(err, pvecollect.ErrTelemetryNotAuthorized) {
		t.Fatalf("request uncovered node: err = %v, want not authorized", err)
	}
	// Once the lease is gone the node is no longer granted.
	f.lc.applyLeases(nil)
	r = f.show(t, v, `{"kind":"node","name":"pve1"}`)
	if len(r.Granted) != 0 {
		t.Fatalf("granted after lease removal = %v, want none", r.Granted)
	}
}

func TestLiveUnlinkedGuestBoxGranted(t *testing.T) {
	f := newLiveFixture(t, liveTestLease("guest", true, false, liveGuestTarget("remote-a", "pve1", 101, 3)))
	v, _ := f.viewer(t, 1)
	r := f.show(t, v, `{"kind":"guest","node":"pve1","vmid":101}`)
	if strings.Join(r.Granted, ",") != "guest:pve1:101" {
		t.Fatalf("granted %v denied %v, want guest:pve1:101", r.Granted, r.Denied)
	}
}

func TestLiveWantListHasExactlyVisibleCoveredProviderTargets(t *testing.T) {
	node1 := liveNodeTarget("remote-a", "pve1")
	guest := liveGuestTarget("remote-a", "pve1", 101, 3)
	f := newLiveFixture(t,
		liveTestLease("a", true, false, node1, guest, liveNodeTarget("remote-a", "pve2")),
		liveTestLease("b", true, false, liveNodeTarget("remote-b", "pve9")),
		liveTestLease("ssh", true, false, liveSSHTarget("web01")),
	)
	va, _ := f.viewer(t, 1)
	vb, _ := f.viewer(t, 2)
	f.show(t, va, `{"kind":"node","name":"pve1"},{"kind":"guest","node":"pve1","vmid":101}`)
	f.show(t, vb, `{"kind":"node","name":"pve1"},{"kind":"host","id":"web01"}`)
	f.lc.providerTick(context.Background(), f.h)
	w := f.h.lastWant(t)
	want := []pvecontract.LiveTarget{
		{Remote: "remote-a", Kind: "node", Node: "pve1"},
		{Remote: "remote-a", Kind: "qemu", Node: "pve1", VMID: 101},
	}
	if !reflect.DeepEqual(w.Targets, want) {
		t.Fatalf("want-list targets = %+v, want %+v", w.Targets, want)
	}
	if w.WrittenUnix != f.clock.Unix() || w.ExpiresUnix != f.clock.Unix()+30 {
		t.Fatalf("want-list times = %d..%d, want %d..%d", w.WrittenUnix, w.ExpiresUnix, f.clock.Unix(), f.clock.Unix()+30)
	}
	// Only the remote with visible boxes is polled.
	if strings.Join(f.h.reads, ",") != "remote-a" {
		t.Fatalf("polled remotes = %v, want [remote-a]", f.h.reads)
	}

	// At most one write per second, even when the set changes.
	f.show(t, va, `{"kind":"node","name":"pve1"}`)
	f.lc.providerTick(context.Background(), f.h)
	if len(f.h.wants) != 1 {
		t.Fatalf("writes within one second = %d, want 1", len(f.h.wants))
	}
	f.clock = f.clock.Add(time.Second)
	f.lc.providerTick(context.Background(), f.h)
	if len(f.h.wants) != 2 || !reflect.DeepEqual(f.h.lastWant(t).Targets, want[:1]) {
		t.Fatalf("want-list after hiding the guest = %+v, want %+v", f.h.wants, want[:1])
	}
	// An unchanged set is not rewritten every second, only refreshed
	// well before its 30-s expiry.
	f.clock = f.clock.Add(time.Second)
	f.lc.providerTick(context.Background(), f.h)
	if len(f.h.wants) != 2 {
		t.Fatal("unchanged want-list rewritten after 1 s")
	}
	f.clock = f.clock.Add(liveWantRefresh)
	f.lc.providerTick(context.Background(), f.h)
	if len(f.h.wants) != 3 {
		t.Fatalf("want-list not refreshed after %s", liveWantRefresh)
	}

	// A revoked lease drops its target from the want-list.
	f.clock = f.clock.Add(time.Second)
	f.lc.applyLeases(liveLeases([]pvecollect.TelemetryLease{liveTestLease("ssh", true, false, liveSSHTarget("web01"))}))
	f.lc.providerTick(context.Background(), f.h)
	if n := len(f.h.lastWant(t).Targets); n != 0 {
		t.Fatalf("want-list after revocation has %d targets, want 0", n)
	}
}

func TestLiveNoViewerWritesEmptyWantList(t *testing.T) {
	f := newLiveFixture(t, liveTestLease("a", true, false, liveNodeTarget("remote-a", "pve1")))
	f.lc.providerTick(context.Background(), f.h)
	if w := f.h.lastWant(t); len(w.Targets) != 0 {
		t.Fatalf("want-list without viewers = %+v, want empty", w.Targets)
	}
	if len(f.h.reads) != 0 {
		t.Fatalf("polled %v without viewers", f.h.reads)
	}
	v, _ := f.viewer(t, 1)
	f.show(t, v, `{"kind":"node","name":"pve1"}`)
	f.clock = f.clock.Add(time.Second)
	f.lc.providerTick(context.Background(), f.h)
	if n := len(f.h.lastWant(t).Targets); n != 1 {
		t.Fatalf("want-list with a viewer has %d targets, want 1", n)
	}
	f.lc.hub.Remove(v)
	f.clock = f.clock.Add(time.Second)
	f.lc.providerTick(context.Background(), f.h)
	if n := len(f.h.lastWant(t).Targets); n != 0 {
		t.Fatalf("want-list after the viewer left has %d targets, want 0", n)
	}
}

func liveEvents(ch <-chan live.Event) []string {
	var out []string
	for {
		select {
		case ev := <-ch:
			out = append(out, ev.Name+" "+string(ev.Data))
		default:
			return out
		}
	}
}

func TestLiveProviderSamplesReachViewerAndAgeOut(t *testing.T) {
	f := newLiveFixture(t, liveTestLease("a", true, false, liveNodeTarget("remote-a", "pve1"), liveGuestTarget("remote-a", "pve1", 101, 3)))
	v, ch := f.viewer(t, 1)
	f.show(t, v, `{"kind":"node","name":"pve1"},{"kind":"guest","node":"pve1","vmid":101}`)
	now := f.clock.Unix()
	f.h.samples["remote-a"] = pvecontract.LiveSamples{Version: 1, Remote: "remote-a", WrittenUnix: now, Samples: []pvecontract.LiveSample{
		{Kind: "node", Node: "pve1", CPU: 0.25, MemUsed: 1, MemTotal: 4, ObservedUnix: now},
		// Older than 15 s: not sent as a fresh value.
		{Kind: "qemu", Node: "pve1", VMID: 101, CPU: 0.5, ObservedUnix: now - 20},
		// Not requested: never reaches the viewer.
		{Kind: "node", Node: "pve2", CPU: 0.9, ObservedUnix: now},
	}}
	f.lc.providerTick(context.Background(), f.h)
	got := liveEvents(ch)
	want := []string{
		fmt.Sprintf(`value {"id":"node:pve1","metric":"cpu","value":0.25,"ts":%d}`, now),
		fmt.Sprintf(`value {"id":"node:pve1","metric":"ram","value":0.25,"ts":%d}`, now),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %q, want %q", got, want)
	}
	// Re-reading the same document sends nothing new.
	f.clock = f.clock.Add(time.Second)
	f.lc.providerTick(context.Background(), f.h)
	if got := liveEvents(ch); len(got) != 0 {
		t.Fatalf("events on unchanged samples = %q, want none", got)
	}
	// The stale guest is labelled with its age right away; the node once
	// its value is older than 15 s.
	f.lc.hub.Tick()
	if got := liveEvents(ch); !reflect.DeepEqual(got, []string{`age {"id":"guest:pve1:101","age":21}`}) {
		t.Fatalf("age events = %q", got)
	}
	f.clock = f.clock.Add(15 * time.Second)
	f.lc.hub.Tick()
	got = liveEvents(ch)
	slices.Sort(got)
	if !reflect.DeepEqual(got, []string{`age {"id":"guest:pve1:101","age":36}`, `age {"id":"node:pve1","age":16}`}) {
		t.Fatalf("age events after 16 s = %q", got)
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

func (failingExec) ListPVERemotes(context.Context, *pb.ListPVERemotesRequest, ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
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
