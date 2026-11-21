// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	tmapi "github.com/nebula-operation-station/nebula-operation-station/internal/web/api/trafficmap"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// The traffic map chain, end to end (ADR 0009, guide 9.9): the net.facts
// script runs on two hosts through hostrun over SSH, its stdout is what
// the server stores as the execution result, the ingest turns the stored
// results into flows, and the map API answers behind the session chain.
//
// Only the network tools are fakes. ip prints the recorded output of the
// fixtures in internal/trafficingest/testdata; ss prints the socket table
// written by the test for each round. Everything else is the real script,
// the real hostrun classifier and the real ingest.
//
// Befund ug08: the stored execution result is taken from the hostrun
// result and written with e.runAction, not through the executions
// service's finishHost (unexported, needs the executor). The save step
// therefore is not part of this chain; its own tests live in
// internal/executions.

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

// netFacts runs the built-in net.facts script on h as an attached run
// (hostrun.Attached over SSH), with PATH set to the fake tools in front of
// the unchanged script.
func (h *e2eHost) netFacts(t *testing.T) hostrun.Result {
	t.Helper()
	a, ok := actions.Lookup("net.facts")
	if !ok {
		t.Fatal("net.facts is not a built-in action")
	}
	script := "PATH='" + h.bin + "'; export PATH\n" + string(a.Script)
	r, err := hostrun.Attached(context.Background(), h.client, e2eExecIDs[h.name], []byte(`{}`), []byte(script), a.Timeout)
	if err != nil {
		t.Fatalf("%s: attached run: %v", h.name, err)
	}
	return r
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

func e2eSocketsB(sent, recv uint64) string {
	return ssListen("*:9100") + ssConn(e2eB0, e2eA0, recv, recv, sent)
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

// e2eRound runs net.facts on both hosts with the given socket tables,
// stores each result as the server does after a run (see the file comment
// for what is not part of the chain), and lets the wired ingest sync.
func e2eRound(t *testing.T, e *trafficEnv, a, b *e2eHost, at time.Time, sockA, sockB string) []hostrun.Result {
	t.Helper()
	a.setSS(sockA)
	b.setSS(sockB)
	var out []hostrun.Result
	for _, h := range []*e2eHost{a, b} {
		r := h.netFacts(t)
		if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
			t.Fatalf("%s: class %s (%s), exit %d, log %q", h.name, r.Class, r.Detail, r.ExitCode, r.Log)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(r.Result, &doc); err != nil {
			t.Fatalf("%s: result is not one JSON document: %v", h.name, err)
		}
		e.run(h.name, at, r.Result)
		out = append(out, r)
	}
	e.now = at.Add(time.Minute)
	if _, err := e.sync.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	return out
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

// e2eEdge returns the edge between A and B from the model, or nil.
func e2eEdge(m e2eModel) *e2eEdgeJSON {
	for i := range m.Edges {
		e := &m.Edges[i]
		if (e.A == "host-a" && e.B == "host-b") || (e.A == "host-b" && e.B == "host-a") {
			return e
		}
	}
	return nil
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
	return &e2eResp{Code: rec.Code, Body: rec.Body.String()}, m
}

// e2eResp is the status and body of a model request.
type e2eResp struct {
	Code int
	Body string
}

// TestTrafficMapFromNetFactsScriptOutput runs the whole chain on two
// hosts: the script's output over hostrun is stored, ingested, and the map
// behind the session shows the connection A -> B on port 9100 and both
// hosts; without a session it shows nothing.
func TestTrafficMapFromNetFactsScriptOutput(t *testing.T) {
	signer := e2eSigner(t)
	e := newTrafficEnv(t)
	e2eLab(t, e)
	a := newE2EHost(t, "host-a", signer)
	b := newE2EHost(t, "host-b", signer)

	base := time.Now().UTC().Truncate(time.Minute).Add(-20 * time.Minute)
	e2eRound(t, e, a, b, base, e2eSocketsA(1000, 200), e2eSocketsB(200, 1000))
	e2eRound(t, e, a, b, base.Add(5*time.Minute), e2eSocketsA(4000, 900), e2eSocketsB(900, 4000))

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
	edge := e2eEdge(m)
	if edge == nil {
		t.Fatalf("no edge between host-a and host-b: %s", resp.Body)
	}
	if len(m.Edges) != 1 {
		t.Errorf("%d edges, want exactly the A-B edge: %s", len(m.Edges), resp.Body)
	}
	if len(edge.Services) != 1 || edge.Services[0].Proto != "tcp" || edge.Services[0].Port != 9100 {
		t.Errorf("services %+v, want tcp/9100", edge.Services)
	}
	// Flows are the difference of the two rounds: 3000 bytes from A to
	// B and 700 back, however the edge is oriented.
	if edge.BytesAB+edge.BytesBA != 3700 {
		t.Errorf("bytes %d+%d, want 3700 in total", edge.BytesAB, edge.BytesBA)
	}

	noSession, _ := getModel(t, f, "")
	if noSession.Code == http.StatusOK || strings.Contains(noSession.Body, "host-b") {
		t.Errorf("model without session: status %d, body leaks the map", noSession.Code)
	}
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

// TestTrafficMapEdgeSurvivesTruncatedScriptOutput: a socket table larger
// than the script's section bound is cut by the script (truncated:true).
// The cut result is still accepted by the ingest, and the map still shows
// the A -> B connection, which is listed before the cut.
func TestTrafficMapEdgeSurvivesTruncatedScriptOutput(t *testing.T) {
	signer := e2eSigner(t)
	e := newTrafficEnv(t)
	e2eLab(t, e)
	a := newE2EHost(t, "host-a", signer)
	b := newE2EHost(t, "host-b", signer)

	// Filler sockets of A to unrelated peers push the table past the
	// section bound of net.facts (262144 bytes); the A-B socket comes first.
	var filler strings.Builder
	filler.WriteString(e2eSocketsA(4000, 900))
	for i := 0; filler.Len() <= 300*1024; i++ {
		filler.WriteString(ssConn(fmt.Sprintf("192.168.10.37:%d", 41000+i%20000), "203.0.113.9:443", 10, 10, 10))
	}
	base := time.Now().UTC().Truncate(time.Minute).Add(-20 * time.Minute)
	e2eRound(t, e, a, b, base, e2eSocketsA(1000, 200), e2eSocketsB(200, 1000))

	rounds := e2eRound(t, e, a, b, base.Add(5*time.Minute), filler.String(), e2eSocketsB(900, 4000))
	var doc struct {
		Sockets struct {
			Truncated bool `json:"truncated"`
		} `json:"sockets"`
	}
	if err := json.Unmarshal(rounds[0].Result, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Sockets.Truncated {
		t.Fatal("the script did not cut the socket table; the fixture is too small")
	}

	f := e2eMapFixture(t, e)
	resp, m := getModel(t, f, f.token)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET model: status %d: %s", resp.Code, resp.Body)
	}
	if edge := e2eEdge(m); edge == nil {
		t.Fatalf("the cut result lost the A-B edge: %s", resp.Body)
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

// TestTrafficChainFailedSocketTableIsNoFlows records the current behaviour
// when ss fails on a host (here: permission denied, exit 1). Befund ug08:
// net.facts still returns class success with the sockets section
// "failed" and no data, so the run looks healthy; the ingest reports the
// host as no-flows without an error, and the map shows no A-B edge from
// that host's side. The script is not changed here (ue06h/ud09f own it).
func TestTrafficChainFailedSocketTableIsNoFlows(t *testing.T) {
	signer := e2eSigner(t)
	e := newTrafficEnv(t)
	e2eLab(t, e)
	a := newE2EHost(t, "host-a", signer)
	b := newE2EHost(t, "host-b", signer)
	a.write("ss", "#!/bin/sh\necho 'ss: permission denied' >&2\nexit 1\n")

	base := time.Now().UTC().Truncate(time.Minute).Add(-20 * time.Minute)
	rounds := e2eRound(t, e, a, b, base, e2eSocketsA(1000, 200), e2eSocketsB(200, 1000))
	var doc struct {
		Sockets struct {
			Status string `json:"status"`
		} `json:"sockets"`
	}
	if err := json.Unmarshal(rounds[0].Result, &doc); err != nil {
		t.Fatal(err)
	}
	if rounds[0].Class != hostrun.ClassSuccess || doc.Sockets.Status != "failed" {
		t.Fatalf("class %s, sockets %q: Befund ug08 changed, re-check the script's failure path", rounds[0].Class, doc.Sockets.Status)
	}
	for _, h := range e.sync.last.Hosts {
		if h.Host == "host-a" && (h.Outcome != trafficingest.OutcomeNoFlows || h.Err != nil) {
			t.Fatalf("host-a: outcome %s err %v, want no-flows without error", h.Outcome, h.Err)
		}
	}
	f := e2eMapFixture(t, e)
	resp, m := getModel(t, f, f.token)
	if resp.Code != http.StatusOK || e2eEdge(m) != nil {
		t.Fatalf("status %d, edge %v: a failed socket table must not invent flows", resp.Code, e2eEdge(m))
	}
}
