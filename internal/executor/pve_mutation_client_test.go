// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeMutPVE is a pinned TLS PVE API that accepts the allowlisted writes
// with the action token only and serves guest, node and task reads with the
// read token only. Every write creates a task in its task list.
type fakeMutPVE struct {
	srv  *httptest.Server
	host string
	port uint16

	mu       sync.Mutex
	kind     string // the kind of guest 101 (and 9000)
	status   string
	qmp      string
	gen      string
	name     string
	writes   []string // "METHOD path"
	tasks    []string
	running  map[string]bool
	sources  []string
	badAuth  int
	requests int
	// hang, if set, makes every write block (after its task was created)
	// until the request ends: a response lost after the remote acted.
	hang bool
	// drop, if set, closes the connection after a write's task was
	// created, without an answer.
	drop bool
}

var fakePVEGuestPath = regexp.MustCompile(`^/nodes/pve1/(qemu|lxc)/([0-9]+)(/.*)?$`)

func newFakeMutPVE(t *testing.T, cert tls.Certificate, kind string) *fakeMutPVE {
	t.Helper()
	f := &fakeMutPVE{kind: kind, status: "running", qmp: "running", gen: strings.Repeat("9f", 20), name: "web", running: map[string]bool{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	host, port, err := net.SplitHostPort(f.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	f.host, f.port = host, uint16(p)
	return f
}

func (f *fakeMutPVE) endpoint() pvecontract.Endpoint {
	return pvecontract.Endpoint{Host: f.host, Port: f.port}
}

func (f *fakeMutPVE) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakeMutPVE) serve(w http.ResponseWriter, r *http.Request) {
	path, ok := strings.CutPrefix(r.URL.Path, "/api2/json")
	want := "PVEAPIToken=" + mutReadToken
	if r.Method != http.MethodGet {
		want = "PVEAPIToken=" + mutActionToken
	}
	f.mu.Lock()
	f.requests++
	if !ok || r.Header.Get("Authorization") != want {
		f.badAuth++
		f.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		body, status := f.read(path, r)
		f.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
		return
	}
	if err := r.ParseForm(); err != nil {
		f.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	upid, status := f.write(r.Method, path, r)
	hang, drop := f.hang, f.drop
	f.mu.Unlock()
	if drop && status == http.StatusOK {
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				// Reset (RST), so the client sees a net.Error, the kind
				// of failure the transport fails reads over on.
				if tc, ok := c.(*tls.Conn); ok {
					if tcp, ok := tc.NetConn().(*net.TCPConn); ok {
						_ = tcp.SetLinger(0)
					}
				}
				c.Close()
			}
		}
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if hang {
		<-r.Context().Done()
		return
	}
	_, _ = fmt.Fprintf(w, `{"data":%q}`, upid)
}

// read serves one GET; f.mu is held.
func (f *fakeMutPVE) read(path string, r *http.Request) (string, int) {
	switch {
	case path == "/nodes":
		return `{"data":[{"node":"pve1","status":"online"},{"node":"pve2","status":"offline"}]}`, http.StatusOK
	case path == "/nodes/pve1/tasks":
		f.sources = append(f.sources, r.URL.Query().Get("source"))
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		var page []map[string]string
		for i := start; i < len(f.tasks) && i < start+limit; i++ {
			page = append(page, map[string]string{"upid": f.tasks[i]})
		}
		if page == nil {
			page = []map[string]string{}
		}
		raw, _ := json.Marshal(map[string]any{"data": page})
		return string(raw), http.StatusOK
	case strings.HasPrefix(path, "/nodes/pve1/tasks/") && strings.HasSuffix(path, "/status"):
		upid := strings.TrimSuffix(strings.TrimPrefix(path, "/nodes/pve1/tasks/"), "/status")
		for _, u := range f.tasks {
			if u == upid {
				if f.running[upid] {
					return fmt.Sprintf(`{"data":{"upid":%q,"status":"running"}}`, upid), http.StatusOK
				}
				return fmt.Sprintf(`{"data":{"upid":%q,"status":"stopped","exitstatus":"OK"}}`, upid), http.StatusOK
			}
		}
		return `{"data":null}`, http.StatusInternalServerError
	}
	m := fakePVEGuestPath.FindStringSubmatch(path)
	if m == nil || m[1] != f.kind || m[2] != "101" {
		return `{"data":null}`, http.StatusInternalServerError
	}
	switch m[3] {
	case "/config":
		return fmt.Sprintf(`{"data":{"digest":%q,"name":%q,"cores":2,"memory":"2048","net0":"virtio=BC:24:11:00:00:01,bridge=vmbr0"}}`, f.gen, f.name), http.StatusOK
	case "/status/current":
		vmid := `101`
		if f.kind == permit.ProviderKindLXC {
			vmid = `"101"`
		}
		if f.kind == permit.ProviderKindQemu {
			return fmt.Sprintf(`{"data":{"vmid":%s,"status":%q,"qmpstatus":%q}}`, vmid, f.status, f.qmp), http.StatusOK
		}
		return fmt.Sprintf(`{"data":{"vmid":%s,"status":%q}}`, vmid, f.status), http.StatusOK
	}
	return `{"data":null}`, http.StatusInternalServerError
}

// write records one POST/PUT and creates its task; f.mu is held.
func (f *fakeMutPVE) write(method, path string, r *http.Request) (string, int) {
	f.writes = append(f.writes, method+" "+path)
	var typ, id string
	switch {
	case path == "/nodes/pve1/qemu" && method == http.MethodPost:
		typ, id = "qmcreate", r.PostForm.Get("vmid")
	case strings.HasPrefix(path, "/nodes/pve1/storage/") && strings.HasSuffix(path, "/download-url"):
		typ, id = "download", r.PostForm.Get("filename")
	default:
		m := fakePVEGuestPath.FindStringSubmatch(path)
		if m == nil {
			return "", http.StatusNotImplemented
		}
		prefix := "qm"
		if m[1] == permit.ProviderKindLXC {
			prefix = "vz"
		}
		id = m[2]
		switch m[3] {
		case "/status/shutdown", "/status/reboot", "/status/stop", "/status/reset", "/status/start":
			typ = prefix + strings.TrimPrefix(m[3], "/status/")
		case "/clone":
			typ = "qmclone"
		case "/config":
			typ = "qmconfig"
		case "/resize":
			typ = "resize"
		case "/template":
			typ = "qmtemplate"
		default:
			return "", http.StatusNotImplemented
		}
	}
	upid := testTaskUPID("pve1", time.Now(), typ, id, mutActionUser, len(f.tasks)+1)
	f.tasks = append(f.tasks, upid)
	return upid, http.StatusOK
}

func tokenOf(secret string) pveapi.TokenSupplier {
	return func(context.Context) (string, error) { return "PVEAPIToken=" + secret, nil }
}

// testMutClient returns the production client pinned to chain's CA.
func testMutClient(chain testChain) *pveMutationClient {
	return &pveMutationClient{
		trust: func(context.Context, executordb.PveRemote) (pvetransport.Trust, error) {
			return pvetransport.Trust{CA: chain.ca}, nil
		},
		now: time.Now,
	}
}

func testMutRemote(eps ...pvecontract.Endpoint) executordb.PveRemote {
	return executordb.PveRemote{RemoteID: mutRemote, Kind: pvecontract.KindCluster, Endpoints: eps, State: executordb.StateActive}
}

func mkStep(method, args string) PveMutationStep {
	return PveMutationStep{Method: method, Args: json.RawMessage(args)}
}

const fakeSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// mutStepCases is one allowlisted step of every family with the request it
// must send and the task it creates.
var mutStepCases = []struct {
	kind, write, taskType, taskID string
	step                          PveMutationStep
}{
	{"qemu", "POST /nodes/pve1/qemu/101/status/shutdown", "qmshutdown", "101", mkStep("guest.qemu.shutdown", `{"vmid":101,"timeout_sec":60}`)},
	{"qemu", "POST /nodes/pve1/qemu/101/status/reboot", "qmreboot", "101", mkStep("guest.qemu.reboot", `{"vmid":101,"timeout_sec":60}`)},
	{"qemu", "POST /nodes/pve1/qemu/101/status/stop", "qmstop", "101", mkStep("guest.qemu.stop", `{"vmid":101}`)},
	{"qemu", "POST /nodes/pve1/qemu/101/status/reset", "qmreset", "101", mkStep("guest.qemu.reset", `{"vmid":101}`)},
	{"lxc", "POST /nodes/pve1/lxc/101/status/shutdown", "vzshutdown", "101", mkStep("guest.lxc.shutdown", `{"vmid":101,"timeout_sec":60}`)},
	{"lxc", "POST /nodes/pve1/lxc/101/status/stop", "vzstop", "101", mkStep("guest.lxc.stop", `{"vmid":101}`)},
	{"qemu", "POST /nodes/pve1/qemu/9000/clone", "qmclone", "9000", mkStep("pve.guest.clone", `{"source_vmid":9000,"new_vmid":101,"name":"web","storage":"local-lvm"}`)},
	{"qemu", "PUT /nodes/pve1/qemu/101/resize", "resize", "101", mkStep("pve.guest.resize", `{"vmid":101,"disk":"scsi0","size_gib":20}`)},
	{"qemu", "POST /nodes/pve1/qemu/101/status/start", "qmstart", "101", mkStep("pve.guest.start", `{"vmid":101}`)},
	{"qemu", "POST /nodes/pve1/storage/local/download-url", "download", "noble-0123456789abcdef.qcow2",
		mkStep("pve.image.download", `{"storage":"local","filename":"noble-0123456789abcdef.qcow2","url":"https://cloud-images.example/noble.img","sha256":"`+fakeSHA+`"}`)},
	{"qemu", "POST /nodes/pve1/qemu", "qmcreate", "9000",
		mkStep("pve.image.create_vm", `{"vmid":9000,"name":"tpl-noble","storage":"local-lvm","import_storage":"local","import_filename":"noble-0123456789abcdef.qcow2"}`)},
	{"qemu", "POST /nodes/pve1/qemu/9000/template", "qmtemplate", "9000", mkStep("pve.image.template", `{"vmid":9000}`)},
}

// TestPveMutationClientDispatchRoutesEveryStepKind: guest power,
// provisioning and image steps each send exactly their one typed request
// with the action token and return the UPID of the task they created.
func TestPveMutationClientDispatchRoutesEveryStepKind(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	for _, tc := range mutStepCases {
		t.Run(tc.step.Method, func(t *testing.T) {
			f := newFakeMutPVE(t, chain.tls, tc.kind)
			upid, err := c.Dispatch(context.Background(), testMutRemote(f.endpoint()), "pve1", tc.step, tokenOf(mutActionToken))
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			u, ok := executordb.ParsePveUPID(upid)
			if !ok || u.Type != tc.taskType || u.ID != tc.taskID || u.Node != "pve1" {
				t.Fatalf("upid %q", upid)
			}
			if f.badAuth != 0 || len(f.writes) != 1 || f.writes[0] != tc.write {
				t.Fatalf("writes %v badAuth %d", f.writes, f.badAuth)
			}
			if tt, ok := c.TaskType(tc.step.Method); !ok || tt != tc.taskType {
				t.Fatalf("TaskType = %q %v", tt, ok)
			}
			if id, ok := c.TaskID(tc.step); !ok || id != tc.taskID {
				t.Fatalf("TaskID = %q %v", id, ok)
			}
		})
	}
}

// TestPveMutationClientRefusesUnsendableStepsUnsent: an unknown method, a
// malformed step or a read token never reaches the remote as a write.
func TestPveMutationClientRefusesUnsendableStepsUnsent(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	f := newFakeMutPVE(t, chain.tls, "qemu")
	for _, s := range []PveMutationStep{
		mkStep("guest.qemu.destroy", `{"vmid":101}`),
		mkStep("guest.lxc.reset", `{"vmid":101}`),
		mkStep("guest.qemu.stop", `{"vmid":101,"force":1}`),
		mkStep("guest.qemu.shutdown", `{"vmid":101}`),
		mkStep("pve.image.download", `{"storage":"local","filename":"../x.qcow2","url":"https://a.example/x","sha256":"`+fakeSHA+`"}`),
		mkStep("node.update", `{}`),
	} {
		if _, err := c.Dispatch(context.Background(), testMutRemote(f.endpoint()), "pve1", s, tokenOf(mutActionToken)); !errors.Is(err, ErrPveRejected) {
			t.Fatalf("%s: err = %v, want ErrPveRejected", s.Method, err)
		}
		if _, ok := c.TaskType(s.Method); ok && strings.HasPrefix(s.Method, "node.") {
			t.Fatalf("%s is allowlisted", s.Method)
		}
	}
	if f.writeCount() != 0 {
		t.Fatalf("writes sent: %v", f.writes)
	}
	// A write with the read token is refused by the remote (HTTP 401).
	_, err := c.Dispatch(context.Background(), testMutRemote(f.endpoint()), "pve1", mkStep("guest.qemu.stop", `{"vmid":101}`), tokenOf(mutReadToken))
	if !errors.Is(err, ErrPveRejected) || f.writeCount() != 0 || f.badAuth != 1 {
		t.Fatalf("read token write: err %v writes %d badAuth %d", err, f.writeCount(), f.badAuth)
	}
}

// TestPveMutationClientTimeoutAfterSendNeverRedispatches: the remote acted
// on the write but its answer never came. The dispatch is "may have been
// received" (not rejected) and the write is never sent to another
// endpoint, although the transport could replay the body (ADR 0008).
func TestPveMutationClientTimeoutAfterSendNeverRedispatches(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	first := newFakeMutPVE(t, chain.tls, "qemu")
	first.hang = true
	second := newFakeMutPVE(t, chain.tls, "qemu")
	rm := testMutRemote(first.endpoint(), second.endpoint())
	for _, tc := range mutStepCases {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, err := c.Dispatch(ctx, rm, "pve1", tc.step, tokenOf(mutActionToken))
		cancel()
		if err == nil || errors.Is(err, ErrPveRejected) {
			t.Fatalf("%s: err = %v, want an uncertain dispatch", tc.step.Method, err)
		}
	}
	if first.writeCount() != len(mutStepCases) {
		t.Fatalf("first endpoint writes = %d, want %d", first.writeCount(), len(mutStepCases))
	}
	if second.writeCount() != 0 {
		t.Fatalf("second endpoint got %d writes: a mutation was resent", second.writeCount())
	}
}

// TestPveMutationClientLostConnectionAfterSendNeverRedispatches: the
// remote acted and then reset the connection while the call's deadline is
// far away. The step is uncertain (never rejected) and is never sent to
// the next endpoint. (The transport-level guard itself is tested in
// pvetransport: TestMutation*NeverFailsOver.)
func TestPveMutationClientLostConnectionAfterSendNeverRedispatches(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	first := newFakeMutPVE(t, chain.tls, "qemu")
	first.drop = true
	second := newFakeMutPVE(t, chain.tls, "qemu")
	rm := testMutRemote(first.endpoint(), second.endpoint())
	for _, tc := range mutStepCases {
		_, err := c.Dispatch(context.Background(), rm, "pve1", tc.step, tokenOf(mutActionToken))
		if err == nil || errors.Is(err, ErrPveRejected) {
			t.Fatalf("%s: err = %v, want an uncertain dispatch", tc.step.Method, err)
		}
	}
	if first.writeCount() != len(mutStepCases) {
		t.Fatalf("first endpoint writes = %d, want %d", first.writeCount(), len(mutStepCases))
	}
	if second.writeCount() != 0 {
		t.Fatalf("second endpoint got %d writes: a mutation was resent", second.writeCount())
	}
}

// TestPveMutationClientDialFailureFailsOverOnce: an endpoint that cannot
// be connected to received nothing, so the write moves on, exactly once.
func TestPveMutationClientDialFailureFailsOverOnce(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	f := newFakeMutPVE(t, chain.tls, "qemu")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	port, _ := strconv.ParseUint(p, 10, 16)
	rm := testMutRemote(pvecontract.Endpoint{Host: "127.0.0.1", Port: uint16(port)}, f.endpoint())
	if _, err := c.Dispatch(context.Background(), rm, "pve1", mkStep("guest.qemu.stop", `{"vmid":101}`), tokenOf(mutActionToken)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if f.writeCount() != 1 {
		t.Fatalf("writes = %d, want 1", f.writeCount())
	}
}

// TestPveMutationClientTrustMismatchIsRejectedUnsent: an endpoint that
// fails pin verification receives no byte, so the step is refused (not
// left uncertain) and no credential is sent.
func TestPveMutationClientTrustMismatchIsRejectedUnsent(t *testing.T) {
	chain, other := makeTestChain(t), makeTestChain(t)
	c := testMutClient(other)
	f := newFakeMutPVE(t, chain.tls, "qemu")
	_, err := c.Dispatch(context.Background(), testMutRemote(f.endpoint()), "pve1", mkStep("guest.qemu.stop", `{"vmid":101}`), tokenOf(mutActionToken))
	if !errors.Is(err, ErrPveRejected) || !errors.Is(err, errPveReadTrust) {
		t.Fatalf("err = %v", err)
	}
	if f.requests != 0 {
		t.Fatalf("requests reached the endpoint: %d", f.requests)
	}
	if strings.Contains(err.Error(), "actionsecret") {
		t.Fatal("error carries the token")
	}
	// A trust source failure is refused unsent as well.
	c.trust = func(context.Context, executordb.PveRemote) (pvetransport.Trust, error) {
		return pvetransport.Trust{}, errPveReadUnreachable
	}
	if _, err := c.Dispatch(context.Background(), testMutRemote(f.endpoint()), "pve1", mkStep("guest.qemu.stop", `{"vmid":101}`), tokenOf(mutActionToken)); !errors.Is(err, ErrPveRejected) {
		t.Fatalf("err = %v", err)
	}
}

// TestPveMutationClientTargetState: kind, node, power status, QMP status,
// generation and configuration digest come from the live guest; any
// change of the configuration changes the digest; a node target must be
// listed online; malformed answers fail.
func TestPveMutationClientTargetState(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	read := tokenOf(mutReadToken)
	ctx := context.Background()

	q := newFakeMutPVE(t, chain.tls, "qemu")
	q.qmp = "paused"
	live, err := c.TargetState(ctx, testMutRemote(q.endpoint()), "qemu", "pve1", 101, read)
	if err != nil {
		t.Fatal(err)
	}
	if live.Node != "pve1" || live.Kind != "qemu" || live.Status != "running" || live.QMPStatus != "paused" || live.Generation != q.gen || len(live.ConfigDigest) != 64 {
		t.Fatalf("live = %+v", live)
	}
	again, _ := c.TargetState(ctx, testMutRemote(q.endpoint()), "qemu", "pve1", 101, read)
	if again.ConfigDigest != live.ConfigDigest {
		t.Fatal("digest is not stable")
	}
	q.mu.Lock()
	q.name = "web2"
	q.mu.Unlock()
	changed, _ := c.TargetState(ctx, testMutRemote(q.endpoint()), "qemu", "pve1", 101, read)
	if changed.ConfigDigest == live.ConfigDigest {
		t.Fatal("digest ignores a configuration change")
	}
	if q.badAuth != 0 || q.writeCount() != 0 {
		t.Fatalf("badAuth %d writes %d", q.badAuth, q.writeCount())
	}
	// The other kind, another VMID or node: no such guest.
	for _, tc := range []struct {
		kind, node string
		vmid       uint64
	}{{"lxc", "pve1", 101}, {"qemu", "pve1", 102}, {"qemu", "pve2", 101}} {
		if _, err := c.TargetState(ctx, testMutRemote(q.endpoint()), tc.kind, tc.node, tc.vmid, read); err == nil {
			t.Fatalf("%+v: read succeeded", tc)
		}
	}
	// Malformed shapes never cause I/O.
	before := q.requests
	for _, tc := range []struct {
		kind, node string
		vmid       uint64
	}{{"qemu", "pve1", 0}, {"node", "pve1", 101}, {"vm", "pve1", 101}, {"qemu", "../x", 101}} {
		if _, err := c.TargetState(ctx, testMutRemote(q.endpoint()), tc.kind, tc.node, tc.vmid, read); !errors.Is(err, ErrPveMutationRequest) {
			t.Fatalf("%+v: err = %v", tc, err)
		}
	}
	if q.requests != before {
		t.Fatal("malformed target caused I/O")
	}
	// A malformed generation fails.
	q.mu.Lock()
	q.gen = "not-a-digest"
	q.mu.Unlock()
	if _, err := c.TargetState(ctx, testMutRemote(q.endpoint()), "qemu", "pve1", 101, read); err == nil {
		t.Fatal("malformed generation accepted")
	}

	l := newFakeMutPVE(t, chain.tls, "lxc")
	lx, err := c.TargetState(ctx, testMutRemote(l.endpoint()), "lxc", "pve1", 101, read)
	if err != nil || lx.Kind != "lxc" || lx.Status != "running" || lx.QMPStatus != "" {
		t.Fatalf("lxc = %+v %v", lx, err)
	}

	n, err := c.TargetState(ctx, testMutRemote(q.endpoint()), "node", "pve1", 0, read)
	if err != nil || n.Node != "pve1" || n.Kind != "" || n.Generation != "" || len(n.ConfigDigest) != 64 {
		t.Fatalf("node = %+v %v", n, err)
	}
	if _, err := c.TargetState(ctx, testMutRemote(q.endpoint()), "node", "pve2", 0, read); err == nil {
		t.Fatal("offline node accepted")
	}
}

// TestPveMutationClientTasks: the task list includes running tasks
// (source=all), is paged, and a list longer than the client reads is an
// error, never a partial answer. Task status reports running and exit.
func TestPveMutationClientTasks(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	read := tokenOf(mutReadToken)
	ctx := context.Background()
	f := newFakeMutPVE(t, chain.tls, "qemu")
	rm := testMutRemote(f.endpoint())
	f.mu.Lock()
	for i := 0; i < pveMutationTaskPage+20; i++ {
		f.tasks = append(f.tasks, testTaskUPID("pve1", time.Now(), "qmstart", "101", mutActionUser, i))
	}
	f.tasks = append(f.tasks, "UPID:bogus")
	f.running[f.tasks[0]] = true
	f.mu.Unlock()
	got, err := c.RecentTasks(ctx, rm, "pve1", time.Now().Add(-time.Hour), read)
	if err != nil || len(got) != pveMutationTaskPage+20 {
		t.Fatalf("tasks = %d %v", len(got), err)
	}
	if len(f.sources) != 2 || f.sources[0] != "all" {
		t.Fatalf("sources %v", f.sources)
	}
	st, err := c.TaskStatus(ctx, rm, "pve1", f.tasks[0], read)
	if err != nil || !st.Running {
		t.Fatalf("status %+v %v", st, err)
	}
	st, err = c.TaskStatus(ctx, rm, "pve1", f.tasks[1], read)
	if err != nil || st.Running || st.ExitStatus != "OK" {
		t.Fatalf("status %+v %v", st, err)
	}
	if _, err := c.TaskStatus(ctx, rm, "pve2", f.tasks[1], read); err == nil {
		t.Fatal("task of another node accepted")
	}
	if _, err := c.TaskStatus(ctx, rm, "pve1", testTaskUPID("pve1", time.Now(), "qmstop", "101", mutActionUser, 99999), read); err == nil || errors.Is(err, ErrPveTaskNotFound) {
		t.Fatalf("missing task: %v", err)
	}
	f.mu.Lock()
	for len(f.tasks) < pveMutationTaskPage*pveMutationMaxTaskPages {
		f.tasks = append(f.tasks, testTaskUPID("pve1", time.Now(), "qmstart", "101", mutActionUser, len(f.tasks)))
	}
	f.mu.Unlock()
	if _, err := c.RecentTasks(ctx, rm, "pve1", time.Time{}, read); !errors.Is(err, errPveMutationTaskList) {
		t.Fatalf("long list: %v", err)
	}
	if f.badAuth != 0 {
		t.Fatalf("badAuth %d", f.badAuth)
	}
}

// prodPowerEnv is a guest power environment whose engine uses the
// production client against the fake PVE.
func prodPowerEnv(t *testing.T, kind string) (*powerEnv, *fakeMutPVE, *pveMutationClient) {
	t.Helper()
	e := newPowerEnv(t, kind)
	chain := makeTestChain(t)
	f := newFakeMutPVE(t, chain.tls, kind)
	if _, err := e.pe.db.SetEndpoints(mutRemote, []pvecontract.Endpoint{f.endpoint()}, "admin"); err != nil {
		t.Fatal(err)
	}
	c := testMutClient(chain)
	e.g.Mutations.Client = c
	return e, f, c
}

// TestGuestPowerProductionClientRunsAgainstFakePVE: an approved power
// action runs end to end over the production client: one write with the
// action token, the task observed to success.
func TestGuestPowerProductionClientRunsAgainstFakePVE(t *testing.T) {
	for _, tc := range []struct{ kind, verb, write string }{
		{"qemu", PveGuestPowerStop, "POST /nodes/pve1/qemu/101/status/stop"},
		{"qemu", PveGuestPowerShutdown, "POST /nodes/pve1/qemu/101/status/shutdown"},
		{"lxc", PveGuestPowerReboot, "POST /nodes/pve1/lxc/101/status/reboot"},
	} {
		t.Run(tc.kind+"-"+tc.verb, func(t *testing.T) {
			e, f, _ := prodPowerEnv(t, tc.kind)
			req := e.approve(powerReq(tc.kind, tc.verb))
			res, err := e.g.Run(context.Background(), req)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded {
				t.Fatalf("steps %+v", res.Steps)
			}
			if f.writeCount() != 1 || f.writes[0] != tc.write || f.badAuth != 0 {
				t.Fatalf("writes %v badAuth %d", f.writes, f.badAuth)
			}
		})
	}
}

// TestGuestPowerProductionClientPausedGuestGetsNothing keeps the QMP
// precondition: a paused QEMU guest is refused before any write.
func TestGuestPowerProductionClientPausedGuestGetsNothing(t *testing.T) {
	e, f, _ := prodPowerEnv(t, "qemu")
	f.mu.Lock()
	f.qmp = "paused"
	f.mu.Unlock()
	if _, err := e.propose(powerReq("qemu", PveGuestPowerStop)); err == nil {
		t.Fatal("proposal for a paused guest accepted")
	}
	if f.writeCount() != 0 {
		t.Fatalf("writes %v", f.writes)
	}
}

// TestGuestPowerProductionClientLostResponseReconcilesAfterRestart: the
// remote acted but the answer was lost and the executor restarted. The
// restarted engine's Reconcile identifies the task from the task list and
// observes it; the write is never sent again.
func TestGuestPowerProductionClientLostResponseReconcilesAfterRestart(t *testing.T) {
	e, f, c := prodPowerEnv(t, "qemu")
	f.mu.Lock()
	f.hang = true
	f.mu.Unlock()
	req := e.approve(powerReq("qemu", PveGuestPowerStop))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	res, err := e.g.Run(ctx, req)
	cancel()
	if err == nil || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
	if f.writeCount() != 1 {
		t.Fatalf("writes = %d", f.writeCount())
	}
	f.mu.Lock()
	f.hang = false
	f.mu.Unlock()

	e.restart()
	e.g.Mutations.Client = c
	if err := e.g.Mutations.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	steps, err := e.pe.db.PveJobSteps(res.ExecutionID)
	if err != nil || len(steps) != 1 {
		t.Fatalf("steps %v %v", steps, err)
	}
	f.mu.Lock()
	upid := f.tasks[0]
	f.mu.Unlock()
	if steps[0].State != executordb.PveJobSucceeded || steps[0].UPID != upid {
		t.Fatalf("step %+v, want succeeded with %s", steps[0], upid)
	}
	if f.writeCount() != 1 {
		t.Fatalf("writes = %d after reconcile: redispatched", f.writeCount())
	}
	// The permit was consumed: the same approval cannot dispatch again.
	if _, err := e.g.Run(context.Background(), req); err == nil {
		t.Fatal("second run accepted")
	}
	if f.writeCount() != 1 {
		t.Fatalf("writes = %d", f.writeCount())
	}
}

// TestPveMutationsWiresProductionClient: the executor's single engine
// carries the production client over the pinned read trust, so the guest
// power RPCs no longer answer "not configured".
func TestPveMutationsWiresProductionClient(t *testing.T) {
	e := newReconcileEnv(t)
	m := e.svc.pveMutations()
	c, ok := m.Client.(*pveMutationClient)
	if !ok || c.trust == nil || c.secrets == nil || c.now == nil {
		t.Fatalf("client = %#v", m.Client)
	}
	if e.svc.pveMutations() != m {
		t.Fatal("engine is not single")
	}
}

// TestServiceGuestPowerReachesTheRemoteChecks: with the wired client the
// RPCs go on to the remote checks (here: no action credential) instead of
// answering "not configured".
func TestServiceGuestPowerReachesTheRemoteChecks(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	target := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	_, err := e.svc.ProposePVEGuestPower(context.Background(), &pb.ProposePVEGuestPowerRequest{Target: target})
	st := status.Convert(err)
	if st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "no action credential") {
		t.Fatalf("propose: %v", err)
	}
	if e.pve.requests.Load() != 0 {
		t.Fatalf("a read-only remote was contacted: %d", e.pve.requests.Load())
	}
}
