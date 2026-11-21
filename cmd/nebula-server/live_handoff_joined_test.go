// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The joined live handoff test runs both halves of the provider live
// values on one spool directory: the server half is the real live chart
// (buildLiveChart, OpenLiveHandoff, the webServer chain with its login
// wrapper and origin check, the SSE stream); the collector half is the real
// LiveHandoff (NewLiveHandoff) and LiveWatcher (Run). Only the executor
// is a stand-in: it approves one on-demand read grant, reports one active
// remote and returns fixed metrics for each asked node or guest.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/live"
)

const (
	// joinedRemote and joinedPin are the approved remote of the stand-in.
	joinedRemote = "remote-a"
	joinedPin    = "ab"
	// joinedHost is the host of swOrigin, sent as the request Host.
	joinedHost = "nebula.example.org"
	// joinedWait bounds one wait for a cross-process effect.
	joinedWait = 15 * time.Second
	// joinedNodeBox and joinedGuestBox are the two boxes the viewer shows.
	joinedNodeBox  = "node:pve1"
	joinedGuestBox = "guest:pve1:101"
)

// joinedNodeTarget and joinedGuestTarget are the two want-list targets.
var (
	joinedNodeTarget  = pvecontract.LiveTarget{Remote: joinedRemote, Kind: pvecontract.LiveKindNode, Node: "pve1"}
	joinedGuestTarget = pvecontract.LiveTarget{Remote: joinedRemote, Kind: pvecontract.LiveKindQEMU, Node: "pve1", VMID: 101}
	// joinedCPU is the fixed CPU fraction the stand-in returns per target.
	joinedCPU = map[pvecontract.LiveTarget]float64{joinedNodeTarget: 0.25, joinedGuestTarget: 0.5}
)

// joinedClock is the injected clock of both halves: the real clock moved by
// an offset the test may advance.
type joinedClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *joinedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *joinedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.off += d
}

// joinedSpool creates the spool root with the directories and modes that
// install.sh (lines 800-828) gives the collector's spool: the root 2750,
// requests/ 2770 and live/ 2750. The setgid bit is set where the test user
// may set it; otherwise the note is logged and NewLiveHandoff reports the
// missing bit.
func joinedSpool(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "pve")
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{root, 0o750 | os.ModeSetgid},
		{filepath.Join(root, "requests"), 0o770 | os.ModeSetgid},
		{filepath.Join(root, "live"), 0o750 | os.ModeSetgid},
	}
	for _, d := range dirs {
		if err := os.Mkdir(d.path, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(d.path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSetgid == 0 {
			t.Logf("%s: setgid not set (test user is not in the directory's group); modes without setgid", d.path)
		}
	}
	return root
}

// joinedExec is the executor stand-in. It is the only fake of the joined
// test: both sides reach it through their real executor surface.
type joinedExec struct {
	grants []*pb.ReadGrant
	reads  chan pvecontract.LiveTarget

	mu    sync.Mutex
	asked map[pvecontract.LiveTarget]int
}

func (e *joinedExec) ListPVERemotes(context.Context, *pb.ListPVERemotesRequest, ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
	return &pb.ListPVERemotesResponse{Remotes: []*pb.PVERemoteInfo{{
		RemoteId: joinedRemote, TrustPin: strings.Repeat(joinedPin, 32), TrustGeneration: 1,
		State: pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE,
	}}}, nil
}

func (e *joinedExec) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	return &pb.ListReadGrantsResponse{Grants: e.grants}, nil
}

func (e *joinedExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{}, nil
}

func (e *joinedExec) RunReadGrant(context.Context, *pb.RunReadGrantRequest, ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	return nil, fmt.Errorf("joined test: RunReadGrant is not used")
}

// ReadPVE returns the fixed metrics of a node or guest and counts the ask.
// A target without a fixed value is refused, so an unexpected ask fails.
func (e *joinedExec) ReadPVE(_ context.Context, req *pb.ReadPVERequest, _ ...grpc.CallOption) (*pb.ReadPVEResponse, error) {
	m := req.GetMetrics()
	k := pvecontract.LiveTarget{Remote: req.GetRemoteId(), Kind: m.GetKind(), Node: m.GetNode(), VMID: m.GetVmid()}
	cpu, ok := joinedCPU[k]
	if !ok {
		return nil, fmt.Errorf("joined test: no fixed value for %+v", k)
	}
	e.mu.Lock()
	e.asked[k]++
	e.mu.Unlock()
	select {
	case e.reads <- k:
	default:
	}
	return &pb.ReadPVEResponse{RemoteId: req.GetRemoteId(), Payload: &pb.ReadPVEResponse_Metrics{Metrics: &pb.PVEMetrics{
		State: pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE, Node: k.Node, Kind: k.Kind, Vmid: k.VMID,
		Metrics: []*pb.PVEMetric{
			{Name: "cpu", Unit: "ratio", Value: cpu},
			{Name: "mem_used", Unit: "bytes", Value: 1 << 30},
			{Name: "mem_total", Unit: "bytes", Value: 4 << 30},
		},
	}}}, nil
}

// asked returns a copy of the ask counts per target.
func (e *joinedExec) askedCounts() map[pvecontract.LiveTarget]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[pvecontract.LiveTarget]int, len(e.asked))
	for k, v := range e.asked {
		out[k] = v
	}
	return out
}

// joinedGrant is an approved on-demand provider read grant for the two
// joined targets: node pve1 and guest 101 at generation 3.
func joinedGrant(t *testing.T, now time.Time) *pb.ReadGrant {
	t.Helper()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: "6f1c2a7e-8d3b-4c52-9a10-2b7e5d4c3f01", Issuer: "admin",
		CreatedUnix: now.Add(-time.Hour).Unix(), ExpiryUnix: now.Add(6 * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerOnDemand, MinIntervalS: 10, RunBudget: 600,
		RateProfile: permit.ProviderTelemetryProfile,
		ProviderTargets: []permit.ProviderTarget{{
			RemoteID: joinedRemote, TrustPin: strings.Repeat(joinedPin, 32), TrustGeneration: 1, CredentialVersion: 1,
			Methods: []string{permit.ProviderMethodMetrics},
			MetricsTargets: []permit.ProviderMetricsTarget{
				{Node: "pve1", Kind: "node"},
				{Node: "pve1", Kind: "qemu", VMID: 101, Generation: 3},
			},
		}},
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	_, canon, digest, err := permit.ParseReadGrant(raw, now)
	if err != nil {
		t.Fatalf("grant fixture invalid: %v", err)
	}
	return &pb.ReadGrant{GrantId: d.ID, GrantDigest: digest, CanonicalGrant: canon, ApprovedBy: "admin", CreatedUnix: d.CreatedUnix, ExpiryUnix: d.ExpiryUnix}
}

// joinedRig is the server (live chart behind webServer) and the executor
// stand-in, with the spool root that both halves share.
type joinedRig struct {
	t      *testing.T
	ctx    context.Context
	root   string
	clk    *joinedClock
	exec   *joinedExec
	lc     *liveChart
	srv    *httptest.Server
	cookie string
	log    *slog.Logger
}

func newJoinedRig(t *testing.T, clk *joinedClock) *joinedRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := slog.New(slog.DiscardHandler)
	root := joinedSpool(t)
	exec := &joinedExec{
		grants: []*pb.ReadGrant{joinedGrant(t, time.Now())},
		reads:  make(chan pvecontract.LiveTarget, 256),
		asked:  map[pvecontract.LiveTarget]int{},
	}
	tree := pveinventory.Tree{Roots: []pveinventory.Box{
		{Kind: pveinventory.KindPVENode, Name: "pve1", RemoteID: joinedRemote, Children: []pveinventory.Box{
			{Kind: pveinventory.KindGuest, VMID: 101, Generation: 3},
		}},
		{Kind: pveinventory.KindPVENode, Name: "pve2", RemoteID: joinedRemote},
	}}
	lc, err := buildLiveChart(exec, noHosts{},
		func(context.Context) (pveinventory.Tree, error) { return tree, nil }, nil, log, nil, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	lc.handoffRoot = root
	// The leases are loaded before any request, so the first POST already
	// sees the grant (the loop's own refresh runs later, asynchronously).
	lc.refresh(ctx)

	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(ctx, "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	lc.handler.Register(pages)
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return &joinedRig{t: t, ctx: ctx, root: root, clk: clk, exec: exec, lc: lc, srv: ts, cookie: token, log: log}
}

// startCollector runs the collector half exactly as the collector's main
// does: NewLiveHandoff on the spool root and the watcher's Run loop.
func (r *joinedRig) startCollector(t *testing.T) {
	t.Helper()
	h, err := pvecollect.NewLiveHandoff(r.root)
	if err != nil {
		t.Fatalf("collector NewLiveHandoff: %v", err)
	}
	w, err := pvecollect.NewLiveWatcher(r.exec, h, pvecollect.LiveWatcherConfig{Now: r.clk.Now, Log: r.log})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(r.ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = w.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
		_ = h.Close()
	})
}

// startServer runs the server's live loops (the same run the server starts).
func (r *joinedRig) startServer(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(r.ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.lc.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
}

// request sends one request through the real server chain over loopback.
// cookie is the session cookie value ("" for none), origin the Origin
// header ("" for none).
func (r *joinedRig) request(ctx context.Context, method, path, cookie, origin, body string) *http.Response {
	r.t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, r.srv.URL+path, strings.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Host = joinedHost
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

type sseEvent struct{ name, data string }

// openEvents opens the viewer's SSE stream with the session and returns the
// viewer ID from the hello event and the stream's later events.
func (r *joinedRig) openEvents(t *testing.T) (string, <-chan sseEvent) {
	t.Helper()
	ctx, cancel := context.WithCancel(r.ctx)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.srv.URL+live.EventsPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = joinedHost
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: r.cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d, want 200", resp.StatusCode)
	}
	ch := make(chan sseEvent, 256)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			case line == "":
				if ev.name != "" {
					ch <- ev
				}
				ev = sseEvent{}
			}
		}
	}()
	select {
	case ev, ok := <-ch:
		if !ok || ev.name != "hello" {
			t.Fatalf("first event = %+v, want hello", ev)
		}
		var hello struct {
			Viewer string `json:"viewer"`
		}
		if err := json.Unmarshal([]byte(ev.data), &hello); err != nil || hello.Viewer == "" {
			t.Fatalf("hello data %q: %v", ev.data, err)
		}
		return hello.Viewer, ch
	case <-time.After(joinedWait):
		t.Fatal("no hello event")
	}
	return "", nil
}

// postTargets posts the viewer's boxes to the targets path and returns the
// status and, on 200, the granted and denied box IDs.
func (r *joinedRig) postTargets(t *testing.T, viewer, cookie, origin string, boxes string) (int, []string, []string) {
	t.Helper()
	body := `{"viewer":"` + viewer + `","boxes":[` + boxes + `]}`
	resp := r.request(r.ctx, http.MethodPost, live.TargetsPath, cookie, origin, body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	var reply struct {
		Granted []string `json:"granted"`
		Denied  []string `json:"denied"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, reply.Granted, reply.Denied
}

// twoBoxes are the node pve1 and guest 101 boxes of the tree.
const twoBoxes = `{"kind":"node","name":"pve1"},{"kind":"guest","node":"pve1","vmid":101}`

// waitValues reads the viewer's stream until every wanted box has a cpu
// value, and checks each value against the stand-in's fixed value.
func waitValues(t *testing.T, events <-chan sseEvent, want map[string]float64) {
	t.Helper()
	got := map[string]float64{}
	deadline := time.After(joinedWait)
	for len(got) < len(want) {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("stream ended with values %v, want %v", got, want)
			}
			if ev.name != "value" {
				continue
			}
			var v struct {
				ID     string  `json:"id"`
				Metric string  `json:"metric"`
				Value  float64 `json:"value"`
			}
			if err := json.Unmarshal([]byte(ev.data), &v); err != nil {
				t.Fatalf("value event %q: %v", ev.data, err)
			}
			if v.Metric == "cpu" {
				got[v.ID] = v.Value
			}
		case <-deadline:
			t.Fatalf("values %v, want %v", got, want)
		}
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("value of %s = %v, want %v (the stand-in's value)", id, got[id], w)
		}
	}
}

// TestLiveValuesJoinedServedFromCollector is the end-to-end handoff: the
// server writes the want-list of two boxes, the collector reads it on the
// same directory, asks the stand-in for exactly those two targets, publishes
// the samples, and the server serves the stand-in's values to the viewer.
func TestLiveValuesJoinedServedFromCollector(t *testing.T) {
	t.Parallel()
	r := newJoinedRig(t, &joinedClock{})
	r.startCollector(t)
	r.startServer(t)
	viewer, events := r.openEvents(t)

	status, granted, denied := r.postTargets(t, viewer, r.cookie, swOrigin, twoBoxes)
	if status != http.StatusOK {
		t.Fatalf("targets status %d, want 200", status)
	}
	if !slices.Equal(sortedCopy(granted), []string{joinedGuestBox, joinedNodeBox}) || len(denied) != 0 {
		t.Fatalf("granted %v denied %v, want both boxes granted", granted, denied)
	}
	waitValues(t, events, map[string]float64{joinedNodeBox: 0.25, joinedGuestBox: 0.5})

	// The stand-in was asked for exactly the two wanted targets and nothing else.
	counts := r.exec.askedCounts()
	if len(counts) != 2 || counts[joinedNodeTarget] == 0 || counts[joinedGuestTarget] == 0 {
		t.Fatalf("stand-in asked for %v, want exactly %v and %v", counts, joinedNodeTarget, joinedGuestTarget)
	}
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// TestLiveValuesJoinedNoSessionOrOriginNoTargets: without the session the
// server refuses the targets, and without an Origin the origin check does,
// so the want-list carries no target and the collector asks nothing.
func TestLiveValuesJoinedNoSessionOrOriginNoTargets(t *testing.T) {
	t.Parallel()
	r := newJoinedRig(t, &joinedClock{})
	r.startCollector(t)
	r.startServer(t)
	viewer, _ := r.openEvents(t)

	body := `{"viewer":"` + viewer + `","boxes":[` + twoBoxes + `]}`
	noSession := r.request(r.ctx, http.MethodPost, live.TargetsPath, "", swOrigin, body)
	if noSession.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST without session: status %d, want 401", noSession.StatusCode)
	}
	noOrigin := r.request(r.ctx, http.MethodPost, live.TargetsPath, r.cookie, "", body)
	if noOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without origin: status %d, want 403", noOrigin.StatusCode)
	}

	// Let the collector's watcher and the server's loops run for a few
	// ticks: no target may reach the stand-in.
	time.Sleep(2500 * time.Millisecond)
	if n := len(r.exec.askedCounts()); n != 0 {
		t.Fatalf("stand-in asked for %d targets, want none", n)
	}
	if _, err := os.Stat(filepath.Join(r.root, "requests", "live.json")); err == nil {
		raw, err := os.ReadFile(filepath.Join(r.root, "requests", "live.json"))
		if err != nil {
			t.Fatal(err)
		}
		want, err := pvecontract.DecodeLiveWant(raw)
		if err != nil || len(want.Targets) != 0 {
			t.Fatalf("want-list = %+v (%v), want no targets", want, err)
		}
	}
}

// waitGone polls for a file to disappear; the collector removes its samples
// when the want-list expires, after its next tick.
func waitGone(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(joinedWait)
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still present after the want-list expired", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestLiveWantExpiryStopsCollectorReads: the server's want-list lasts
// pvecontract.LiveWantMaxExpiry seconds; once the collector's clock is past
// that, it stops reading and removes the samples. The server writes one
// want-list tick and then announces nothing more.
func TestLiveWantExpiryStopsCollectorReads(t *testing.T) {
	t.Parallel()
	clk := &joinedClock{}
	r := newJoinedRig(t, clk)
	r.startCollector(t)
	viewer, _ := r.openEvents(t)
	if status, _, _ := r.postTargets(t, viewer, r.cookie, swOrigin, twoBoxes); status != http.StatusOK {
		t.Fatalf("targets status %d, want 200", status)
	}
	serverH, err := pvecollect.OpenLiveHandoff(r.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverH.Close() })
	// One server tick writes the want-list with the server's clock.
	r.lc.providerTick(r.ctx, serverH)

	seen := map[pvecontract.LiveTarget]bool{}
	deadline := time.After(joinedWait)
	for !(seen[joinedNodeTarget] && seen[joinedGuestTarget]) {
		select {
		case k := <-r.exec.reads:
			seen[k] = true
		case <-deadline:
			t.Fatalf("collector asked for %v, want both targets", seen)
		}
	}

	raw, err := os.ReadFile(filepath.Join(r.root, "requests", "live.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := pvecontract.DecodeLiveWant(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := want.ExpiresUnix - want.WrittenUnix; got != pvecontract.LiveWantMaxExpiry {
		t.Fatalf("want-list lasts %d s, want the contract's %d s", got, pvecontract.LiveWantMaxExpiry)
	}

	// Past the expiry the server's tick is gone; the collector must stop.
	clk.Advance((pvecontract.LiveWantMaxExpiry + 1) * time.Second)
	waitGone(t, filepath.Join(r.root, "live", joinedRemote+".json"))
	before := sumCounts(r.exec.askedCounts())
	time.Sleep(1500 * time.Millisecond)
	if after := sumCounts(r.exec.askedCounts()); after != before {
		t.Fatalf("collector asked %d more times after the want-list expired", after-before)
	}
}

func sumCounts(m map[pvecontract.LiveTarget]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// TestLiveWantOverTargetLimitRefusedNoFile: a want-list above the target
// limit is refused by the server's handoff writer, and no file is written
// that the collector would have to discard. The viewer's box count is
// bounded by the targets endpoint as well.
func TestLiveWantOverTargetLimitRefusedNoFile(t *testing.T) {
	t.Parallel()
	r := newJoinedRig(t, &joinedClock{})
	serverH, err := pvecollect.OpenLiveHandoff(r.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverH.Close() })

	targets := make([]pvecontract.LiveTarget, 0, pvecontract.MaxLiveTargets+1)
	for i := range pvecontract.MaxLiveTargets + 1 {
		targets = append(targets, pvecontract.LiveTarget{
			Remote: joinedRemote, Kind: pvecontract.LiveKindQEMU, Node: "pve1", VMID: uint64(pvecontract.MinVMID + i),
		})
	}
	now := r.clk.Now().Unix()
	err = serverH.WriteLiveWant(r.ctx, pvecontract.LiveWant{
		Version: pvecontract.LiveWantVersion, WrittenUnix: now, ExpiresUnix: now + pvecontract.LiveWantMaxExpiry, Targets: targets,
	})
	if err == nil {
		t.Fatalf("WriteLiveWant with %d targets accepted, want refusal", len(targets))
	}
	if _, statErr := os.Stat(filepath.Join(r.root, "requests", "live.json")); !os.IsNotExist(statErr) {
		t.Fatalf("refused want-list left a file behind (stat: %v)", statErr)
	}

	// The targets endpoint bounds the boxes of one viewer (32).
	viewer, _ := r.openEvents(t)
	var boxes []string
	for i := range 33 {
		boxes = append(boxes, fmt.Sprintf(`{"kind":"node","name":"pve%d"}`, i+1))
	}
	if status, _, _ := r.postTargets(t, viewer, r.cookie, swOrigin, strings.Join(boxes, ",")); status != http.StatusBadRequest {
		t.Fatalf("33 boxes: status %d, want 400", status)
	}
}

// TestLiveSamplesOlderThanReadWindowNotCurrent: a samples file the collector
// wrote is read by the server, but a sample older than the server's read
// window (live.StaleAfter) is not sent to the viewer as a fresh value.
func TestLiveSamplesOlderThanReadWindowNotCurrent(t *testing.T) {
	t.Parallel()
	clk := &joinedClock{}
	target := pvecollect.TelemetryTarget{
		Source: pvecollect.TelemetryProvider, RemoteID: joinedRemote, TrustPin: strings.Repeat(joinedPin, 32),
		TrustGeneration: 1, Node: "pve1", Kind: pvecollect.TelemetryKindNode,
	}
	wantList := []pvecollect.TelemetryTarget{target}
	stale := int64(live.StaleAfter/time.Second) + 5

	// The same collector write, once fresh (control) and once stale.
	run := func(t *testing.T, observedAge int64) (fresh bool) {
		t.Helper()
		r := newJoinedRig(t, clk)
		lc := r.lc
		hub := lc.hub
		viewer := fmt.Sprintf("%032x", 1)
		ch, err := hub.Add(viewer, "s")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hub.SetBoxes(viewer, "s", map[string][]pvecollect.TelemetryTarget{joinedNodeBox: wantList}); err != nil {
			t.Fatal(err)
		}
		collector, err := pvecollect.NewLiveHandoff(r.root)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = collector.Close() })
		now := clk.Now().Unix()
		if err := collector.WriteLiveSamples(r.ctx, pvecontract.LiveSamples{
			Version: pvecontract.LiveSamplesVersion, Remote: joinedRemote, WrittenUnix: now,
			Samples: []pvecontract.LiveSample{{
				Kind: pvecontract.LiveKindNode, Node: "pve1", CPU: 0.25, MemUsed: 1, MemTotal: 4, ObservedUnix: now - observedAge,
			}},
		}); err != nil {
			t.Fatal(err)
		}
		serverH, err := pvecollect.OpenLiveHandoff(r.root)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = serverH.Close() })
		lc.pollSamples(r.ctx, serverH, wantList, clk.Now())
		return len(ch) > 0
	}

	if !run(t, 0) {
		t.Fatal("fresh samples did not reach the viewer; the control is broken")
	}
	if run(t, stale) {
		t.Fatalf("samples %d s old reached the viewer as a current value", stale)
	}
}

// TestLiveSpoolPathStandards: the server's default spool root is the
// collector's default -spool and the path of its systemd unit.
func TestLiveSpoolPathStandards(t *testing.T) {
	if liveHandoffRoot != serverconfig.DefaultPVESpoolDir {
		t.Fatalf("server live root %q != serverconfig.DefaultPVESpoolDir %q", liveHandoffRoot, serverconfig.DefaultPVESpoolDir)
	}
	main, err := os.ReadFile("../nebula-pve-collector/main.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`defaultSpool\s*=\s*"([^"]+)"`).FindSubmatch(main)
	if m == nil || string(m[1]) != liveHandoffRoot {
		t.Fatalf("collector defaultSpool = %q, want %q", m, liveHandoffRoot)
	}
	unit, err := os.ReadFile("../../deploy/systemd/nebula-pve-collector.service")
	if err != nil {
		t.Fatal(err)
	}
	u := regexp.MustCompile(`-spool\s+(\S+)`).FindSubmatch(unit)
	if u == nil || string(u[1]) != liveHandoffRoot {
		t.Fatalf("systemd unit -spool = %q, want %q", u, liveHandoffRoot)
	}
}
