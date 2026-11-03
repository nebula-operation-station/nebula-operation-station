// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// liveExec is a fake executor: remotes, read grants and metrics reads.
type liveExec struct {
	mu         sync.Mutex
	remotes    []*pb.PVERemoteInfo
	grants     []*pb.ReadGrant
	grantsErr  error
	grantCalls int
	reads      []*pb.PVEReadMetricsParams
	readAt     []time.Time
	readRemote []string
	clk        *fakeClock
}

func (e *liveExec) ListPVERemotes(context.Context, *pb.ListPVERemotesRequest, ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &pb.ListPVERemotesResponse{Remotes: e.remotes}, nil
}

func (e *liveExec) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.grantCalls++
	if e.grantsErr != nil {
		return nil, e.grantsErr
	}
	return &pb.ListReadGrantsResponse{Grants: e.grants}, nil
}

func (e *liveExec) ReadPVE(_ context.Context, req *pb.ReadPVERequest, _ ...grpc.CallOption) (*pb.ReadPVEResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := req.GetMetrics()
	e.reads = append(e.reads, m)
	e.readAt = append(e.readAt, e.clk.Now())
	e.readRemote = append(e.readRemote, req.GetRemoteId())
	return metricsResp(req.GetRemoteId(), m.GetNode(), m.GetKind(), m.GetVmid(),
		&pb.PVEMetric{Name: "cpu", Unit: "ratio", Value: 0.25},
		&pb.PVEMetric{Name: "mem_used", Unit: "bytes", Value: 1 << 30},
		&pb.PVEMetric{Name: "mem_total", Unit: "bytes", Value: 4 << 30},
	), nil
}

func (e *liveExec) takeReads() []*pb.PVEReadMetricsParams {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.reads
	e.reads = nil
	return out
}

func (e *liveExec) setGrants(g ...*pb.ReadGrant) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.grants = g
}

type liveFixture struct {
	t    *testing.T
	clk  *fakeClock
	exec *liveExec
	h    *LiveHandoff
	w    *LiveWatcher
}

// onDemandMut makes the fixture grant on-demand only.
func onDemandMut(d *permit.ReadGrantDoc) { d.Trigger = permit.TriggerOnDemand }

func newLiveFixture(t *testing.T, grants ...*pb.ReadGrant) *liveFixture {
	t.Helper()
	clk := &fakeClock{t: telT0}
	exec := &liveExec{remotes: []*pb.PVERemoteInfo{activeRemoteInfo()}, grants: grants, clk: clk}
	h := newTestHandoff(t)
	h.now = clk.Now
	w, err := NewLiveWatcher(exec, h, LiveWatcherConfig{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &liveFixture{t: t, clk: clk, exec: exec, h: h, w: w}
}

// tick runs one watcher pass, waits for its reads and publishes their samples.
func (f *liveFixture) tick() {
	f.t.Helper()
	var wg sync.WaitGroup
	f.w.step(context.Background(), &wg)
	wg.Wait()
	f.w.flush(context.Background(), f.clk.Now())
}

func (f *liveFixture) want(targets ...pvecontract.LiveTarget) {
	f.t.Helper()
	now := f.clk.Now().Unix()
	if err := f.h.WriteLiveWant(context.Background(), pvecontract.LiveWant{
		Version: pvecontract.LiveWantVersion, WrittenUnix: now, ExpiresUnix: now + pvecontract.LiveWantMaxExpiry, Targets: targets,
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *liveFixture) liveFiles() []string {
	f.t.Helper()
	ents, err := os.ReadDir(f.h.LiveDir())
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

var (
	wantNode  = pvecontract.LiveTarget{Remote: "remote-a", Kind: pvecontract.LiveKindNode, Node: "pve1"}
	wantGuest = pvecontract.LiveTarget{Remote: "remote-a", Kind: pvecontract.LiveKindQEMU, Node: "pve1", VMID: 101}
)

func TestLiveWatcherReadsCoveredTargetAndPublishes(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantGuest)
	f.tick()
	reads := f.exec.takeReads()
	if len(reads) != 1 || reads[0].GetVmid() != 101 || reads[0].GetGeneration() != 2 || !reads[0].GetLive() {
		t.Fatalf("reads = %v", reads)
	}
	got, err := f.h.ReadLiveSamples(context.Background(), "remote-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Samples) != 1 {
		t.Fatalf("samples = %+v", got.Samples)
	}
	s := got.Samples[0]
	if s.Kind != "qemu" || s.Node != "pve1" || s.VMID != 101 || s.CPU != 0.25 || s.MemTotal == 0 || s.MemUsed/s.MemTotal != 0.25 ||
		s.ObservedUnix != telT0.Unix() || s.DiskTotal != 0 {
		t.Fatalf("sample = %+v", s)
	}
}

func TestLiveWatcherNoWantNoReads(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	for range 3 {
		f.tick()
		f.clk.Add(time.Second)
	}
	if r := f.exec.takeReads(); len(r) != 0 {
		t.Fatalf("reads without want-list: %v", r)
	}
	if f.exec.grantCalls != 0 {
		t.Fatalf("lease refresh without want-list: %d", f.exec.grantCalls)
	}
}

func TestLiveWatcherUncoveredTargetNeverRead(t *testing.T) {
	// The grant lists node pve1 and guest 101 only.
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(pvecontract.LiveTarget{Remote: "remote-a", Kind: pvecontract.LiveKindQEMU, Node: "pve1", VMID: 102},
		pvecontract.LiveTarget{Remote: "remote-a", Kind: pvecontract.LiveKindNode, Node: "pve2"},
		pvecontract.LiveTarget{Remote: "remote-a", Kind: pvecontract.LiveKindLXC, Node: "pve1", VMID: 101})
	for range 12 {
		f.tick()
		f.clk.Add(time.Second)
	}
	if r := f.exec.takeReads(); len(r) != 0 {
		t.Fatalf("uncovered targets read: %v", r)
	}
	if files := f.liveFiles(); len(files) != 0 {
		t.Fatalf("live files = %v", files)
	}
}

func TestLiveWatcherScheduledOnlyGrantGivesNoLiveReads(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, func(d *permit.ReadGrantDoc) { d.Trigger = permit.TriggerScheduled }))
	f.want(wantGuest, wantNode)
	for range 12 {
		f.tick()
		f.clk.Add(time.Second)
	}
	if r := f.exec.takeReads(); len(r) != 0 {
		t.Fatalf("scheduled-only grant read live: %v", r)
	}
}

func TestLiveWatcherBothTriggerGrantReadsOnlyWantedLive(t *testing.T) {
	// A grant with trigger "both" must not make the live watcher take
	// history samples of unwanted targets.
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, nil))
	f.want(wantGuest)
	for range 25 {
		f.tick()
		f.clk.Add(time.Second)
	}
	for _, r := range f.exec.takeReads() {
		if r.GetKind() != "qemu" || !r.GetLive() {
			t.Fatalf("unwanted or non-live read: %v", r)
		}
	}
}

func TestLiveWatcherUnknownRemoteIgnored(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(pvecontract.LiveTarget{Remote: "remote-z", Kind: pvecontract.LiveKindNode, Node: "pve1"})
	for range 3 {
		f.tick()
		f.clk.Add(time.Second)
	}
	if r := f.exec.takeReads(); len(r) != 0 {
		t.Fatalf("unknown remote read: %v", r)
	}
	if files := f.liveFiles(); len(files) != 0 {
		t.Fatalf("live files = %v", files)
	}
}

func TestLiveWatcherRemovedRemoteStopsReads(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantNode)
	f.tick()
	if len(f.exec.takeReads()) != 1 {
		t.Fatal("covered target not read")
	}
	f.exec.mu.Lock()
	f.exec.remotes = nil
	f.exec.mu.Unlock()
	for range 25 {
		f.clk.Add(time.Second)
		f.want(wantNode)
		f.tick()
	}
	if r := f.exec.takeReads(); len(r) > 1 {
		t.Fatalf("reads after remote removal: %v", r)
	}
	if files := f.liveFiles(); len(files) != 0 {
		t.Fatalf("live files after remote removal = %v", files)
	}
}

func TestLiveWatcherExpiredWantStopsReadsAndRemovesFiles(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantNode)
	f.tick()
	if len(f.exec.takeReads()) != 1 {
		t.Fatal("covered target not read")
	}
	if files := f.liveFiles(); len(files) != 1 || files[0] != "remote-a.json" {
		t.Fatalf("live files = %v", files)
	}
	// The want-list expires after LiveWantMaxExpiry seconds without renewal.
	f.clk.Add(pvecontract.LiveWantMaxExpiry * time.Second)
	f.tick()
	if r := f.exec.takeReads(); len(r) != 0 {
		t.Fatalf("reads after expiry: %v", r)
	}
	if files := f.liveFiles(); len(files) != 0 {
		t.Fatalf("live files after expiry = %v", files)
	}
	for range 15 {
		f.clk.Add(time.Second)
		f.tick()
	}
	if r := f.exec.takeReads(); len(r) != 0 {
		t.Fatalf("reads after expiry: %v", r)
	}
}

func TestLiveWatcherStaleFilesRemovedWhenIdle(t *testing.T) {
	f := newLiveFixture(t)
	// Left over by an earlier run.
	if err := f.h.WriteLiveSamples(context.Background(), testSamples("remote-old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.h.LiveDir(), "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if files := f.liveFiles(); len(files) != 1 || files[0] != "notes.txt" {
		t.Fatalf("live files = %v", files)
	}
}

func TestLiveWatcherDroppedTargetRemovedFromFile(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantNode, wantGuest)
	f.tick()
	f.clk.Add(time.Second)
	f.tick()
	got, err := f.h.ReadLiveSamples(context.Background(), "remote-a")
	if err != nil || len(got.Samples) != 2 {
		t.Fatalf("samples = %+v, %v", got, err)
	}
	f.clk.Add(time.Second)
	f.want(wantGuest)
	f.tick()
	got, err = f.h.ReadLiveSamples(context.Background(), "remote-a")
	if err != nil || len(got.Samples) != 1 || got.Samples[0].VMID != 101 {
		t.Fatalf("samples after drop = %+v, %v", got, err)
	}
}

func TestLiveWatcherRevokedLeaseStopsWithinOneRefresh(t *testing.T) {
	g := grantFixture(t, gid1, telT0, onDemandMut)
	f := newLiveFixture(t, g)
	f.want(wantNode)
	f.tick()
	if len(f.exec.takeReads()) != 1 || f.exec.grantCalls != 1 {
		t.Fatalf("first pass: grant calls %d", f.exec.grantCalls)
	}
	rev := grantFixture(t, gid1, telT0, onDemandMut)
	rev.RevokedUnix = telT0.Unix() + 1
	f.exec.setGrants(rev)
	for i := 1; i <= 2*int(liveLeaseRefresh/time.Second); i++ {
		f.clk.Add(time.Second)
		f.want(wantNode)
		f.tick()
		if time.Duration(i)*time.Second >= liveLeaseRefresh {
			if r := f.exec.takeReads(); len(r) != 0 {
				t.Fatalf("read %v after the refresh at +%ds saw the revocation", r, i)
			}
		}
	}
	if f.exec.grantCalls != 3 {
		t.Fatalf("grant calls = %d, want one per %s", f.exec.grantCalls, liveLeaseRefresh)
	}
	if files := f.liveFiles(); len(files) != 0 {
		t.Fatalf("live files after revocation = %v", files)
	}
}

func TestLiveWatcherLeaseRefreshFailureFailsClosed(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantNode)
	f.tick()
	f.exec.takeReads()
	f.exec.mu.Lock()
	f.exec.grantsErr = errors.New("executor unavailable")
	f.exec.mu.Unlock()
	for range 25 {
		f.clk.Add(time.Second)
		f.want(wantNode)
		f.tick()
	}
	if r := f.exec.takeReads(); len(r) > 1 {
		t.Fatalf("reads after failed refresh: %v", r)
	}
}

func TestLiveWatcherExpiredLeaseStopsBeforeRefresh(t *testing.T) {
	g := grantFixture(t, gid1, telT0, onDemandMut)
	g.ExpiryUnix = telT0.Unix() + 15
	f := newLiveFixture(t, g)
	f.want(wantNode)
	for range 25 {
		f.tick()
		f.clk.Add(time.Second)
		f.want(wantNode)
	}
	f.exec.mu.Lock()
	defer f.exec.mu.Unlock()
	for _, at := range f.exec.readAt {
		if !at.Before(time.Unix(g.ExpiryUnix, 0)) {
			t.Fatalf("read at %v after lease expiry", at)
		}
	}
}

func TestLiveWatcherRespectsSpacingAndCadence(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantNode, wantGuest)
	for range 30 {
		f.tick()
		f.clk.Add(250 * time.Millisecond)
		if f.clk.Now().Sub(telT0)%(5*time.Second) == 0 {
			f.want(wantNode, wantGuest)
		}
	}
	f.exec.mu.Lock()
	defer f.exec.mu.Unlock()
	if len(f.exec.readAt) < 2 {
		t.Fatalf("reads = %d", len(f.exec.readAt))
	}
	last := map[string]time.Time{}
	perTarget := map[string]time.Time{}
	for i, at := range f.exec.readAt {
		rem := f.exec.readRemote[i]
		if p, ok := last[rem]; ok && at.Sub(p) < ProviderMetricsSpacing {
			t.Fatalf("two reads of %s %v apart", rem, at.Sub(p))
		}
		last[rem] = at
		k := f.exec.reads[i].GetKind()
		if p, ok := perTarget[k]; ok && at.Sub(p) < TelemetryLiveInterval {
			t.Fatalf("target %s read %v apart", k, at.Sub(p))
		}
		perTarget[k] = at
	}
}

func TestLiveWatcherRespectsLeaseBudget(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, func(d *permit.ReadGrantDoc) {
		d.Trigger = permit.TriggerOnDemand
		d.RunBudget = 2
	}))
	for range 60 {
		f.want(wantNode, wantGuest)
		f.tick()
		f.clk.Add(time.Second)
	}
	if r := f.exec.takeReads(); len(r) != 2 {
		t.Fatalf("reads = %d, want the run budget 2", len(r))
	}
}

func TestLiveWatcherHostileWantListIgnored(t *testing.T) {
	cases := map[string]func(f *liveFixture){
		"garbage": func(f *liveFixture) {
			writeWantRaw(t, f, []byte("{not json"))
		},
		"unknown field": func(f *liveFixture) {
			now := f.clk.Now().Unix()
			writeWantRaw(t, f, []byte(`{"version":1,"written_unix":`+itoa(int(now))+`,"expires_unix":`+itoa(int(now+20))+
				`,"targets":[{"remote":"remote-a","kind":"node","node":"pve1","vmid":0,"trust_pin":"x"}]}`))
		},
		"future dated": func(f *liveFixture) {
			now := f.clk.Now().Unix() + 3600
			writeWantRaw(t, f, []byte(`{"version":1,"written_unix":`+itoa(int(now))+`,"expires_unix":`+itoa(int(now+20))+
				`,"targets":[{"remote":"remote-a","kind":"node","node":"pve1","vmid":0}]}`))
		},
		"oversize": func(f *liveFixture) {
			writeWantRaw(t, f, []byte(strings.Repeat(" ", pvecontract.MaxLiveWantBytes+1)))
		},
		"symlink": func(f *liveFixture) {
			other := filepath.Join(t.TempDir(), "want.json")
			now := f.clk.Now().Unix()
			if err := os.WriteFile(other, []byte(`{"version":1,"written_unix":`+itoa(int(now))+`,"expires_unix":`+itoa(int(now+20))+
				`,"targets":[{"remote":"remote-a","kind":"node","node":"pve1","vmid":0}]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(f.h.RequestsDir(), liveWantName)
			_ = os.Remove(p)
			if err := os.Symlink(other, p); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
			f.want(wantNode)
			f.tick()
			f.exec.takeReads()
			setup(f)
			for range 12 {
				f.clk.Add(time.Second)
				f.tick()
			}
			if r := f.exec.takeReads(); len(r) != 0 {
				t.Fatalf("reads under hostile want-list: %v", r)
			}
			if files := f.liveFiles(); len(files) != 0 {
				t.Fatalf("live files = %v", files)
			}
		})
	}
}

func writeWantRaw(t *testing.T, f *liveFixture, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.h.RequestsDir(), liveWantName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLiveWatcherSinkRejectsUnwanted(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantNode)
	f.tick()
	err := f.w.sink.RecordTelemetry(context.Background(), TelemetrySample{
		Target: provTarget("remote-a", 101, 2), Metric: TelemetryMetricCPU, Value: 0.9, Live: true, ObservedAt: f.clk.Now(),
	})
	if err == nil {
		t.Fatal("sink accepted a sample of an unwanted target")
	}
}

func TestNewLiveWatcherRequiresDependencies(t *testing.T) {
	if _, err := NewLiveWatcher(nil, newTestHandoff(t), LiveWatcherConfig{}); err == nil {
		t.Fatal("nil executor accepted")
	}
	if _, err := NewLiveWatcher(&liveExec{}, nil, LiveWatcherConfig{}); err == nil {
		t.Fatal("nil handoff accepted")
	}
}

func TestLiveWatcherRunStopsAndCleansUp(t *testing.T) {
	f := newLiveFixture(t, grantFixture(t, gid1, telT0, onDemandMut))
	f.want(wantNode)
	f.tick()
	if len(f.liveFiles()) != 1 {
		t.Fatal("no live file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if files := f.liveFiles(); len(files) != 0 {
		t.Fatalf("live files after Run = %v", files)
	}
}
