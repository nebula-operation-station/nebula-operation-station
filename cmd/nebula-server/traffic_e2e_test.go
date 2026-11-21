// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	tmapi "github.com/nebula-operation-station/nebula-operation-station/internal/web/api/trafficmap"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// The traffic map chain, end to end (ADR 0009, guide 9.9): the net.facts
// script runs on two hosts through hostrun over SSH, the executions
// service stores each result with its real save step (finishHost), the
// ingest turns the stored results into flows, and the map API answers
// behind the session chain of the web server.
//
// Only the network tools and the executor's gRPC side are fakes. ip prints
// the recorded output of the fixtures in internal/trafficingest/testdata;
// ss prints the socket table written by the test for each round. The
// executor fake pins the two hosts, approves the proposal (approval is the
// executor's business, not this chain's) and runs each attached run as the
// real script, unchanged apart from a PATH in front, over the host's SSH
// client. Everything else is the real script, the real hostrun classifier,
// the real executions service, the real ingest and the real map API.

// e2eExecIDs make the attached-run IDs, which must be lowercase UUIDs.
var e2eExecIDs = map[string]string{
	"host-a": "5d1c2f0e-7a4b-4e8d-9c31-0000000000a1",
	"host-b": "5d1c2f0e-7a4b-4e8d-9c31-0000000000b2",
}

// e2eHost is one managed host of the chain: its own hostruntest SSH
// server, a PATH with the fake network tools, and the socket table its
// fake ss prints.
type e2eHost struct {
	t      *testing.T
	name   string
	dir    string
	bin    string
	client *ssh.Client
}

// newE2EHost starts a host whose recorded addr, link, route and neigh
// output is the fixture dir of the same name.
func newE2EHost(t *testing.T, name string, signer ssh.Signer) *e2eHost {
	t.Helper()
	fix, err := filepath.Abs(filepath.Join(trafficFixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	h := &e2eHost{t: t, name: name, dir: t.TempDir()}
	h.bin = filepath.Join(h.dir, "bin")
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The script's own utilities; net.facts finds the others absent.
	for _, tool := range []string{"base64", "head", "cat", "tr"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("%s not available: %v", tool, err)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	ip := fmt.Sprintf(`#!/bin/sh
case "$*" in
"-j addr") cat '%[1]s/addr.json' ;;
"-j -d link") cat '%[1]s/link.json' ;;
"-j route") cat '%[1]s/route.json' ;;
"-j neigh") cat '%[1]s/neigh.json' ;;
"-j -6 route" | "-j -6 neigh") echo "Error: Address family not supported by protocol." >&2; exit 1 ;;
*) echo "unexpected ip $*" >&2; exit 2 ;;
esac
`, fix)
	ss := fmt.Sprintf(`#!/bin/sh
[ "$*" = "-tinuaH" ] || { echo "unexpected ss $*" >&2; exit 2; }
cat '%s/ss.txt'
`, h.dir)
	h.write("ip", ip)
	h.write("ss", ss)

	srv := hostruntest.Start(t, signer.PublicKey())
	c, err := ssh.Dial("tcp", srv.Addr, &ssh.ClientConfig{User: "nebula", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	h.client = c
	return h
}

func (h *e2eHost) write(name, body string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte(body), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

// setSS sets the socket table the fake ss prints from now on.
func (h *e2eHost) setSS(table string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, "ss.txt"), []byte(table), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// attached runs script on h as an attached run (hostrun.Attached over
// SSH), with PATH set to the fake tools in front of it.
func (h *e2eHost) attached(ctx context.Context, script []byte, params []byte, timeout time.Duration) (hostrun.Result, error) {
	pre := "PATH='" + h.bin + "'; export PATH\n"
	return hostrun.Attached(ctx, h.client, e2eExecIDs[h.name], params, append([]byte(pre), script...), timeout)
}

// ssConn is one established TCP socket in the format of `ss -tinuaH`.
func ssConn(local, peer string, sent, acked, recv uint64) string {
	return fmt.Sprintf("tcp   ESTAB  0      0         %s %s\n\t cubic wscale:7,7 rto:204 rtt:1.5/0.7 ato:40 mss:1448 cwnd:10 bytes_sent:%d bytes_acked:%d bytes_received:%d segs_out:10 segs_in:8\n",
		local, peer, sent, acked, recv)
}

// ssListen is a listening TCP socket in the format of `ss -tinuaH`.
func ssListen(local string) string {
	return fmt.Sprintf("tcp   LISTEN 0      4096         %s 0.0.0.0:*\n\t cubic cwnd:10\n", local)
}

// The connection A -> B: A (192.168.10.37) is the client of B's
// 192.168.10.20:9100. Both hosts see the same socket with mirrored
// counters. Round 0 is the baseline; round 1 is 3000 bytes A -> B and
// 700 bytes B -> A later.
const (
	e2eA0 = "192.168.10.37:40122"
	e2eB0 = "192.168.10.20:9100"
)

func e2eSocketsA(sent, recv uint64) string {
	return ssConn(e2eA0, e2eB0, sent, sent, recv)
}

// e2eSocketsB is host-b's view of the same socket: its own sent and
// received counters, which mirror host-a's (B sent what A received).
func e2eSocketsB(sent, recv uint64) string {
	return ssListen("*:9100") + ssConn(e2eB0, e2eA0, sent, sent, recv)
}

// e2eExec is the executor side the executions service talks to. It pins
// both hosts, approves every proposal, and answers each attached run with
// the real net.facts script run over the host's SSH client. The results
// it answers are kept, so the stored results can be compared with them.
// Any other executor call is unexpected and panics through the nil
// embedded interface.
type e2eExec struct {
	executions.Executor
	hosts map[string]*e2eHost
	seq   int

	mu  sync.Mutex
	got map[string]hostrun.Result
}

func (x *e2eExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	var pins []*pb.HostKeyPin
	for id := range x.hosts {
		pins = append(pins, &pb.HostKeyPin{HostId: id, Fingerprint: "SHA256:e2e-" + id})
	}
	return &pb.ListHostKeysResponse{Hosts: pins}, nil
}

func (x *e2eExec) ProposeExecution(context.Context, *pb.ProposeExecutionRequest, ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	x.mu.Lock()
	x.seq++
	digest := fmt.Sprintf("%064x", x.seq)
	x.mu.Unlock()
	return &pb.ProposeExecutionResponse{ExecutionDigest: digest, State: pb.PermitState_PERMIT_STATE_APPROVED}, nil
}

func (x *e2eExec) RunAttached(ctx context.Context, in *pb.RunAttachedRequest, _ ...grpc.CallOption) (*pb.RunAttachedResponse, error) {
	id := in.GetRun().GetHostId()
	h, ok := x.hosts[id]
	if !ok {
		return nil, fmt.Errorf("e2e executor: no host %q", id)
	}
	r, err := h.attached(ctx, in.GetRun().GetArtifact(), in.GetRun().GetParametersJson(), time.Duration(in.GetTimeoutSeconds())*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%s: attached run: %w", id, err)
	}
	x.mu.Lock()
	x.got[id] = r
	x.mu.Unlock()
	return &pb.RunAttachedResponse{Class: r.Class, Detail: r.Detail, ExitCode: int32(r.ExitCode), Result: r.Result, Log: r.Log, LogTruncated: r.LogTruncated}, nil
}

// answered returns what the executor answered for host in the last run.
func (x *e2eExec) answered(host string) hostrun.Result {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.got[host]
}

// e2eRig is the chain of one test: the server database with the traffic
// ingest wired to it, the executions service on that database, the
// executor fake, and the two hosts.
type e2eRig struct {
	e    *trafficEnv
	ops  *executions.Service
	exec *e2eExec
	a, b *e2eHost
}

// e2eSetup builds the lab, the two hosts, the executions service on the
// server database, and the traffic ingest wired to it.
func e2eSetup(t *testing.T) *e2eRig {
	t.Helper()
	signer := e2eSigner(t)
	e := newTrafficEnv(t)
	e.now = time.Now().UTC()
	e2eLab(t, e)
	r := &e2eRig{e: e, a: newE2EHost(t, "host-a", signer), b: newE2EHost(t, "host-b", signer)}
	r.exec = &e2eExec{hosts: map[string]*e2eHost{"host-a": r.a, "host-b": r.b}, got: map[string]hostrun.Result{}}
	r.ops = executions.New(t.Context(), r.exec, e.db, e.inv, slog.New(slog.DiscardHandler))
	t.Cleanup(r.ops.Wait)
	return r
}

// e2eRound runs net.facts on host-a and host-b as one execution through
// the executions service with the given socket tables, and lets the wired
// ingest sync. It returns the stored host records by host ID.
func e2eRound(t *testing.T, r *e2eRig, sockA, sockB string) map[string]executions.Host {
	t.Helper()
	e := r.e
	// Finished times have one-second resolution: each round finishes in a
	// later second than the one before.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	r.a.setSS(sockA)
	r.b.setSS(sockB)
	created, err := r.ops.Create(t.Context(), "admin", trafficingest.ActionID, []string{"host-a", "host-b"}, nil)
	if err != nil {
		t.Fatalf("create net.facts run: %v", err)
	}
	if created.State != "approved" {
		t.Fatalf("execution state %s, want approved by the executor", created.State)
	}
	r.ops.Wait()
	ex, err := r.ops.Get(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("read execution: %v", err)
	}
	if ex.State != "finished" {
		t.Fatalf("execution state %s, want finished", ex.State)
	}
	stored := map[string]executions.Host{}
	for _, h := range ex.Hosts {
		stored[h.HostID] = h
	}
	if len(stored) != 2 {
		t.Fatalf("stored hosts %v, want host-a and host-b", ex.Hosts)
	}
	// The stored record is what finishHost wrote from the executor's answer.
	for _, id := range []string{"host-a", "host-b"} {
		h, want := stored[id], r.exec.answered(id)
		if h.State != "finished" || h.Class != want.Class || h.ExitCode != want.ExitCode ||
			!bytes.Equal(h.Result, want.Result) || h.FinishedAt.IsZero() {
			t.Fatalf("%s stored as state %s class %s exit %d finished %v; the executor answered class %s exit %d",
				id, h.State, h.Class, h.ExitCode, h.FinishedAt, want.Class, want.ExitCode)
		}
	}
	e.now = time.Now().UTC().Add(time.Minute)
	if _, err := e.sync.Sync(t.Context()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	return stored
}

// e2eOutcome returns the ingest outcome of host in the last sync. It fails
// when the sync did not report the host at all.
func e2eOutcome(t *testing.T, e *trafficEnv, host string) trafficingest.HostResult {
	t.Helper()
	for _, h := range e.sync.last.Hosts {
		if h.Host == host {
			return h
		}
	}
	t.Fatalf("sync result has no %s: %+v", host, e.sync.last.Hosts)
	return trafficingest.HostResult{}
}

// e2eLab records the two hosts, their NICs and their inventory, the way
// an admin records them: host-a with its address, host-b with its own.
func e2eLab(t *testing.T, e *trafficEnv) {
	t.Helper()
	e.host("host-a", tfAddrA.String())
	e.host("host-b", tfAddrB.String())
	e.nic("nic-a", tfMACA, "host-a", tfAddrA)
	e.nic("nic-b", tfMACB, "host-b", tfAddrB)
}

// e2eMapFixture is the server's HTTP chain (webServer) with the traffic
// map mounted on the database of e, as run mounts it, and a real session.
func e2eMapFixture(t *testing.T, e *trafficEnv) *swFixture {
	t.Helper()
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	log := slog.New(slog.DiscardHandler)
	if err := mountTrafficMap(pages, swOrigin, e.db, e.inv.List, e.ipam, log, trafficstore.DefaultRetention); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewStore(e.db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(context.Background(), "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	tokenAPI := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "token API", http.StatusTeapot) })
	srv, err := webServer(swOrigin, login, pages, tokenAPI)
	if err != nil {
		t.Fatal(err)
	}
	return &swFixture{srv: srv, token: token}
}

// e2eModel is the part of the map model the chain test checks.
type e2eModel struct {
	Nodes []e2eNode     `json:"nodes"`
	Edges []e2eEdgeJSON `json:"edges"`
}

type e2eNode struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type e2eEdgeJSON struct {
	A        string       `json:"a"`
	B        string       `json:"b"`
	BytesAB  uint64       `json:"bytes_ab"`
	BytesBA  uint64       `json:"bytes_ba"`
	Services []e2eService `json:"services"`
}

type e2eService struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}

// e2eEdge returns the edge between host-a and host-b from the model, or nil.
func e2eEdge(m e2eModel) *e2eEdgeJSON {
	for i := range m.Edges {
		e := &m.Edges[i]
		if (e.A == "host-a" && e.B == "host-b") || (e.A == "host-b" && e.B == "host-a") {
			return e
		}
	}
	return nil
}

// e2eResp is the status, Location and body of a model request.
type e2eResp struct {
	Code     int
	Location string
	Body     string
}

// getModel fetches the overview model through the session chain.
func getModel(t *testing.T, f *swFixture, token string) (*e2eResp, e2eModel) {
	t.Helper()
	rec := f.do(t, http.MethodGet, "/api/v1/trafficmap?window=1h", token, "", "")
	var m e2eModel
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("model: %v: %s", err, rec.Body)
		}
	}
	return &e2eResp{Code: rec.Code, Location: rec.Header().Get("Location"), Body: rec.Body.String()}, m
}

func e2eSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestTrafficMapFromNetFactsScriptOutput runs the whole chain on two
// hosts: the script's output over hostrun is stored by the executions
// service, ingested, and the map behind the session shows the connection
// host-a -> host-b on tcp/9100 with the counted bytes in each direction;
// without a session it shows nothing.
func TestTrafficMapFromNetFactsScriptOutput(t *testing.T) {
	r := e2eSetup(t)
	e := r.e
	e2eRound(t, r, e2eSocketsA(1000, 200), e2eSocketsB(200, 1000))
	e2eRound(t, r, e2eSocketsA(4000, 900), e2eSocketsB(900, 4000))
	for _, id := range []string{"host-a", "host-b"} {
		if o := e2eOutcome(t, e, id); o.Outcome != trafficingest.OutcomeFlows || o.Err != nil {
			t.Fatalf("%s: outcome %s err %v, want flows", id, o.Outcome, o.Err)
		}
	}

	f := e2eMapFixture(t, e)
	resp, m := getModel(t, f, f.token)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET model with session: status %d: %s", resp.Code, resp.Body)
	}
	nodes := map[string]bool{}
	for _, n := range m.Nodes {
		nodes[n.ID] = true
	}
	if !nodes["host-a"] || !nodes["host-b"] {
		t.Fatalf("nodes %v, want host-a and host-b", m.Nodes)
	}
	if len(m.Edges) != 1 {
		t.Fatalf("%d edges, want exactly the A-B edge: %s", len(m.Edges), resp.Body)
	}
	edge := e2eEdge(m)
	if edge == nil {
		t.Fatalf("no edge between host-a and host-b: %s", resp.Body)
	}
	// host-a is the client: it sent 3000 bytes to host-b's 9100 and
	// received 700 back. The edge is A < B by ID, so BytesAB is host-a's
	// output.
	if edge.A != "host-a" || edge.B != "host-b" {
		t.Errorf("edge %s - %s, want host-a - host-b", edge.A, edge.B)
	}
	if edge.BytesAB != 3000 || edge.BytesBA != 700 {
		t.Errorf("bytes ab %d ba %d, want 3000 from host-a to host-b and 700 back", edge.BytesAB, edge.BytesBA)
	}
	if len(edge.Services) != 1 || edge.Services[0].Proto != "tcp" || edge.Services[0].Port != 9100 {
		t.Errorf("services %+v, want tcp/9100", edge.Services)
	}

	// The session gate redirects a GET without a session to /login (303);
	// the map is not in the answer.
	noSession, _ := getModel(t, f, "")
	if noSession.Code != http.StatusSeeOther || noSession.Location != "/login" {
		t.Errorf("model without session: status %d location %q, want 303 to /login", noSession.Code, noSession.Location)
	}
	if strings.Contains(noSession.Body, "host-") || strings.Contains(noSession.Body, `"nodes"`) {
		t.Errorf("model without session leaks the map: %q", noSession.Body)
	}
}

// TestTrafficMapEdgeSurvivesTruncatedScriptOutput: a socket table larger
// than the script's section bound is cut by the script (truncated:true).
// The cut result is stored as it is and ingested as incomplete: the spec
// (09, "Incomplete") and the ingest (snapshotOf) take no flows from a
// truncated sockets section, so host-a's outcome is no-flows without an
// error. The A -> B edge then comes from host-b's untruncated report alone,
// with the exact bytes of that one side, not doubled by host-a's result.
func TestTrafficMapEdgeSurvivesTruncatedScriptOutput(t *testing.T) {
	r := e2eSetup(t)
	e := r.e

	// Filler sockets of A to unrelated peers push the table past the
	// section bound of net.facts (262144 bytes); the A-B socket comes first.
	var filler strings.Builder
	filler.WriteString(e2eSocketsA(4000, 900))
	for i := 0; filler.Len() <= 300*1024; i++ {
		filler.WriteString(ssConn(fmt.Sprintf("192.168.10.37:%d", 41000+i%20000), "203.0.113.9:443", 10, 10, 10))
	}
	e2eRound(t, r, e2eSocketsA(1000, 200), e2eSocketsB(200, 1000))

	stored := e2eRound(t, r, filler.String(), e2eSocketsB(900, 4000))
	var doc struct {
		Sockets struct {
			Truncated bool `json:"truncated"`
		} `json:"sockets"`
	}
	if err := json.Unmarshal(stored["host-a"].Result, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Sockets.Truncated {
		t.Fatal("the script did not cut the socket table; the fixture is too small")
	}
	if o := e2eOutcome(t, e, "host-a"); o.Outcome != trafficingest.OutcomeNoFlows || o.Err != nil {
		t.Fatalf("host-a's cut result: outcome %s err %v, want no-flows (incomplete) without error", o.Outcome, o.Err)
	}
	if o := e2eOutcome(t, e, "host-b"); o.Outcome != trafficingest.OutcomeFlows || o.Err != nil {
		t.Fatalf("host-b: outcome %s err %v, want flows", o.Outcome, o.Err)
	}

	f := e2eMapFixture(t, e)
	resp, m := getModel(t, f, f.token)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET model: status %d: %s", resp.Code, resp.Body)
	}
	edge := e2eEdge(m)
	if edge == nil {
		t.Fatalf("the truncated result of host-a cost the A-B edge: %s", resp.Body)
	}
	if edge.A != "host-a" || edge.B != "host-b" || edge.BytesAB != 3000 || edge.BytesBA != 700 {
		t.Errorf("edge %s - %s ab %d ba %d, want host-a - host-b 3000 and 700 once", edge.A, edge.B, edge.BytesAB, edge.BytesBA)
	}
}

// TestTrafficMapOverviewAddressCapMatchesStore checks the two bounds of
// the map and the store against each other: the map's overview query
// never carries more addresses than trafficstore accepts. The map cuts
// its addresses at its own cap; the store must accept exactly that many,
// so the query succeeds.
func TestTrafficMapOverviewAddressCapMatchesStore(t *testing.T) {
	e := newTrafficEnv(t)
	store, err := trafficstore.NewWithRetention(e.db, trafficstore.DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	// Enough nodes, each with the maximum of addresses, to exceed the cap.
	const nodes, perNode = 300, tmapi.MaxAddrsPerNode
	var in tmapi.Inventory
	for i := range nodes {
		var addrs []netip.Addr
		for j := range perNode {
			addrs = append(addrs, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), byte(j + 1)}))
		}
		in.Nodes = append(in.Nodes, tmapi.NodeInput{ID: fmt.Sprintf("n%03d", i), Label: "n", Kind: "host", Addrs: addrs})
	}
	spy := &capSpy{store: store}
	b, err := tmapi.NewBuilder(func(context.Context) (tmapi.Inventory, error) { return in, nil }, spy, nil, tmapi.Limits{Retention: trafficstore.DefaultRetention})
	if err != nil {
		t.Fatal(err)
	}
	body, err := b.Build(context.Background(), tmapi.Query{Window: "24h"})
	if err != nil {
		t.Fatalf("overview with %d addresses: %v", nodes*perNode, err)
	}
	if spy.max != trafficstore.MaxOverviewNodes {
		t.Errorf("largest overview query %d addresses, want exactly the store's %d", spy.max, trafficstore.MaxOverviewNodes)
	}
	var m struct {
		Omitted struct {
			Addresses int `json:"addresses"`
		} `json:"omitted"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if want := nodes*perNode - trafficstore.MaxOverviewNodes; m.Omitted.Addresses != want {
		t.Errorf("omitted addresses %d, want %d", m.Omitted.Addresses, want)
	}
}

// capSpy records the largest overview query the map sends to the store.
type capSpy struct {
	store *trafficstore.Store
	max   int
}

func (s *capSpy) TopN(ctx context.Context, n netip.Addr, w flowagg.Window, k int) ([]flowagg.FlowTotal, error) {
	return s.store.TopN(ctx, n, w, k)
}

func (s *capSpy) OverviewUnion(ctx context.Context, nodes []netip.Addr, w flowagg.Window, k int) ([]flowagg.FlowTotal, error) {
	s.max = max(s.max, len(nodes))
	return s.store.OverviewUnion(ctx, nodes, w, k)
}

// TestTrafficChainFailedSocketTableIsNoFlows: ss fails on host-a in the
// second round (permission denied, exit 1). net.facts still returns class
// success with the sockets section "failed" and no data. The ingest must
// report host-a as no-flows without an error, and no A-B traffic may be
// counted: host-b's socket counters do not move in this round, so any
// bytes on the A-B edge would come from a failed table read as data.
func TestTrafficChainFailedSocketTableIsNoFlows(t *testing.T) {
	r := e2eSetup(t)
	e := r.e

	e2eRound(t, r, e2eSocketsA(1000, 200), e2eSocketsB(200, 1000))
	r.a.write("ss", "#!/bin/sh\necho 'ss: permission denied' >&2\nexit 1\n")
	stored := e2eRound(t, r, e2eSocketsA(4000, 900), e2eSocketsB(200, 1000))

	var doc struct {
		Sockets struct {
			Status string `json:"status"`
		} `json:"sockets"`
	}
	if err := json.Unmarshal(stored["host-a"].Result, &doc); err != nil {
		t.Fatal(err)
	}
	if stored["host-a"].Class != hostrun.ClassSuccess || doc.Sockets.Status != "failed" {
		t.Fatalf("class %s, sockets %q: Befund ug08 changed, re-check the script's failure path", stored["host-a"].Class, doc.Sockets.Status)
	}
	if o := e2eOutcome(t, e, "host-a"); o.Outcome != trafficingest.OutcomeNoFlows || o.Err != nil {
		t.Fatalf("host-a: outcome %s err %v, want no-flows without error", o.Outcome, o.Err)
	}
	f := e2eMapFixture(t, e)
	resp, m := getModel(t, f, f.token)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET model: status %d: %s", resp.Code, resp.Body)
	}
	if edge := e2eEdge(m); edge != nil && edge.BytesAB+edge.BytesBA != 0 {
		t.Fatalf("a failed socket table counted %d+%d bytes on the A-B edge", edge.BytesAB, edge.BytesBA)
	}
}
