// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
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
	if !ok || c.trust == nil || c.secrets == nil || c.now == nil || c.block == nil {
		t.Fatalf("client = %#v", m.Client)
	}
	if e.svc.pveMutations() != m {
		t.Fatal("engine is not single")
	}
}

// TestPveMutationsClientBlocksLikeTheReadPath: the wired client's trust
// failure hook blocks the remote persistently, as the read path does, and
// revokes its provider grants.
func TestPveMutationsClientBlocksLikeTheReadPath(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
	c := e.svc.pveMutations().Client.(*pveMutationClient)
	c.block(e.remote())
	if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", got)
	}
	assertGrantsRevoked(t, e)
}

func assertGrantsRevoked(t *testing.T, e *pveReadEnv) {
	t.Helper()
	grants, err := e.svc.auth.ReadGrants()
	if err != nil || len(grants) != 1 || grants[0].RevokedAt.IsZero() {
		t.Fatalf("provider grant not revoked: %+v %v", grants, err)
	}
}

// approvedServicePower proposes and approves a guest power action on the
// service env's remote: a live mutation permit of the remote.
func approvedServicePower(t *testing.T, e *pveReadEnv) {
	t.Helper()
	target := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	out, err := e.svc.ProposePVEGuestPower(context.Background(), &pb.ProposePVEGuestPowerRequest{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	d, err := canonical.ParseDigest(out.GetPermit().GetExecutionDigest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveCLI(d, 0, "admin"); err != nil {
		t.Fatal(err)
	}
}

// TestPveMutationClientTrustHookRevokesAuthority: the production trust
// failure hook revokes the remote's provider grants and mutation permits
// with the block; a hook that only changed the remote's state fails here.
func TestPveMutationClientTrustHookRevokesAuthority(t *testing.T) {
	e, _, _, _, _ := newServicePowerEnv(t)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
	approvedServicePower(t, e)
	rm := e.remote()
	e.svc.newPveMutationClient().block(rm)
	if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", got)
	}
	assertGrantsRevoked(t, e)
	if n := e.svc.auth.RevokeProviderMutations(pveReadRemote, "test probe"); n != 0 {
		t.Fatalf("%d mutation permits of the blocked remote still live", n)
	}
	// A second trust failure of the now blocked remote is not a failure.
	if err := e.svc.blockPveMutation(pveReadRemote, pveTrustKeyOf(rm)); err != nil {
		t.Fatalf("block of a blocked remote: %v", err)
	}
}

// TestPveMutationClientUnrecordedBlockFailsClosed: when the block of a
// remote that failed trust verification cannot be persisted, the error is
// logged, the remote's mutation permits are revoked anyway, and every
// further call of the client to the remote is refused with a distinct
// error before any connection, until the block is persisted.
func TestPveMutationClientUnrecordedBlockFailsClosed(t *testing.T) {
	e, _, _, _, _ := newServicePowerEnv(t)
	approvedServicePower(t, e)
	rm := e.remote()
	// The registry write of the block fails (SQLite trigger); the
	// authority keeps its permits in memory.
	reopenServiceDB(t, e, `CREATE TRIGGER reject_pve_block BEFORE UPDATE OF state ON pve_remotes WHEN NEW.state = 'blocked' BEGIN SELECT RAISE(ABORT, 'injected block failure'); END`)

	c := e.svc.newPveMutationClient()
	e.svc.pveMutations().Client = c
	c.block(rm)
	if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateActive {
		t.Fatalf("remote state = %s, want the injected failure to keep it active", got)
	}
	if !blockLogged(e, "pve mutation trust block not recorded") {
		t.Fatal("unrecorded block not logged")
	}
	if n := e.svc.auth.RevokeProviderMutations(pveReadRemote, "test probe"); n != 0 {
		t.Fatalf("%d mutation permits live after an unrecorded block", n)
	}
	if err := e.svc.blockPveMutation(pveReadRemote, pveTrustKeyOf(rm)); !errors.Is(err, errPveTrustBlockNotRecorded) {
		t.Fatalf("failing block store: %v", err)
	}
	// Proposals against the fenced trust are refused and audited.
	assertProposalFenced(t, e)

	ctx := context.Background()
	read := tokenOf(mutReadToken)
	upid := testTaskUPID("pve1", time.Now(), "qmstop", "101", mutActionUser, 1)
	calls := map[string]func() error{
		"dispatch": func() error {
			_, err := c.Dispatch(ctx, rm, "pve1", mkStep("guest.qemu.stop", `{"vmid":101}`), tokenOf(mutActionToken))
			if !errors.Is(err, ErrPveRejected) {
				// %v ends the chain: a Dispatch that drops ErrPveRejected
				// fails the unrecorded-block check below.
				return fmt.Errorf("not reported unsent: %v", err)
			}
			return err
		},
		"target state": func() error { _, err := c.TargetState(ctx, rm, "qemu", "pve1", 101, read); return err },
		"task status":  func() error { _, err := c.TaskStatus(ctx, rm, "pve1", upid, read); return err },
		"task list":    func() error { _, err := c.RecentTasks(ctx, rm, "pve1", time.Time{}, read); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, errPveTrustBlockNotRecorded) {
			t.Fatalf("%s: err = %v, want the unrecorded block", name, err)
		}
	}
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("requests reached the endpoint: %d", n)
	}

	// Once the store accepts the block again, the next call records it
	// and is still refused.
	rebuildServiceAuth(t, e, reopenServiceDB(t, e, `DROP TRIGGER reject_pve_block`))
	if _, err := c.RecentTasks(ctx, rm, "pve1", time.Time{}, read); err == nil || errors.Is(err, errPveTrustBlockNotRecorded) {
		t.Fatalf("call after the store recovered: %v", err)
	}
	if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", got)
	}
	if _, fenced := e.svc.pveTrustFence().covers(rm); fenced {
		t.Fatal("fence kept after the block was recorded")
	}
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("requests reached the endpoint: %d", n)
	}
}

// rebuildServiceAuth gives the service of e a new authority over db (as
// after a restart of the executor's state store): approved grants are
// read from db, in-memory permits are gone. The engine reads db too.
func rebuildServiceAuth(t *testing.T, e *pveReadEnv, db *executordb.DB) {
	t.Helper()
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if e.svc.auth, err = permit.New(permit.Options{Verifier: v, Store: db, RiskPolicy: risk, Leases: db, Now: e.clock.Now}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	e.svc.pveMutations().DB = db
}

// assertProposalFenced fails unless guest power and snapshot proposals
// against the env's remote are refused by the trust fence, with an audit
// event, and nothing reached the remote.
func assertProposalFenced(t *testing.T, e *pveReadEnv) {
	t.Helper()
	ctx := context.Background()
	_, perr := e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: &pb.PVEGuestPowerTarget{
		RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}})
	_, serr := e.svc.ProposePVEGuestSnapshot(ctx, &pb.ProposePVEGuestSnapshotRequest{Target: &pb.PVEGuestSnapshotTarget{
		RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Op: "create", Name: "fenced"}})
	for name, err := range map[string]error{"power": perr, "snapshot": serr} {
		st := status.Convert(err)
		if st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "failed trust verification") {
			t.Fatalf("%s proposal against a fenced remote: %v", name, err)
		}
	}
	if !auditLogged(e, "pve_proposal_refused_trust_fenced") {
		t.Fatal("fenced proposal not audited")
	}
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("requests reached the endpoint: %d", n)
	}
}

// TestPveTrustFenceCoversOnlyTheFailedTrust: the fence covers the failed
// trust generation (and stale older records of the remote), never another
// remote, and a newer generation (a re-pin) drops it.
func TestPveTrustFenceCoversOnlyTheFailedTrust(t *testing.T) {
	failed := executordb.PveRemote{RemoteID: "pve-a", TrustPin: strings.Repeat("aa", 32), TrustGeneration: 3}
	at := func(id, pin string, gen uint64) executordb.PveRemote {
		return executordb.PveRemote{RemoteID: id, TrustPin: pin, TrustGeneration: gen}
	}
	var nilFence *pveTrustFence
	if _, ok := nilFence.covers(failed); ok {
		t.Fatal("nil fence covers")
	}
	f := &pveTrustFence{}
	f.add(failed)
	f.add(at("pve-a", failed.TrustPin, 2)) // a stale failure keeps the newer entry
	for _, tc := range []struct {
		name string
		rm   executordb.PveRemote
		want bool
	}{
		{"failed trust", failed, true},
		{"stale older record", at("pve-a", strings.Repeat("bb", 32), 2), true},
		{"same generation, other pin", at("pve-a", strings.Repeat("cc", 32), 3), true},
		{"other remote", at("pve-b", failed.TrustPin, 3), false},
	} {
		if k, ok := f.covers(tc.rm); ok != tc.want || (ok && k != pveTrustKeyOf(failed)) {
			t.Fatalf("%s: covers = %v %+v, want %v", tc.name, ok, k, tc.want)
		}
	}
	f.remove("pve-a", pveTrustKey{pin: failed.TrustPin, generation: 2}) // not the fenced trust
	if _, ok := f.covers(failed); !ok {
		t.Fatal("remove of another trust dropped the fence")
	}
	if _, ok := f.covers(at("pve-a", strings.Repeat("dd", 32), 4)); ok {
		t.Fatal("re-pinned remote is fenced by the old failure")
	}
	if _, ok := f.covers(failed); ok {
		t.Fatal("fence kept after a re-pin was seen")
	}
}

// TestPveUnrecordedBlockRevokesAndRefusesReads: when the block cannot be
// persisted, the remote's provider read grants are revoked with its
// mutation permits, so ReadPVE is refused, and the provisioning reader
// refuses the fenced trust before any connection.
func TestPveUnrecordedBlockRevokesAndRefusesReads(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
	if _, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES); err != nil {
		t.Fatalf("read before the trust failure: %v", err)
	}
	before := e.pve.requests.Load()
	rm := e.remote()
	rebuildServiceAuth(t, e, reopenServiceDB(t, e, `CREATE TRIGGER reject_pve_block BEFORE UPDATE OF state ON pve_remotes WHEN NEW.state = 'blocked' BEGIN SELECT RAISE(ABORT, 'injected block failure'); END`))

	c := e.svc.pveMutations().Client.(*pveMutationClient)
	c.block(rm)
	if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateActive {
		t.Fatalf("remote state = %s, want the injected failure to keep it active", got)
	}
	assertGrantsRevoked(t, e)
	if _, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES); err == nil {
		t.Fatal("read of a fenced remote succeeded")
	}
	r := pveProvisionReaderAPI{agent: pveGuestAgentAPI{s: e.svc}}
	if _, err := r.ClusterInventory(context.Background(), rm, tokenOf(pveReadToken)); !errors.Is(err, errPveTrustBlockNotRecorded) {
		t.Fatalf("provisioning read of a fenced remote: %v", err)
	}
	if _, err := r.NodeStorage(context.Background(), rm, "pve1", "local", tokenOf(pveReadToken)); !errors.Is(err, errPveTrustBlockNotRecorded) {
		t.Fatalf("provisioning storage read of a fenced remote: %v", err)
	}
	if n := e.pve.requests.Load(); n != before {
		t.Fatalf("requests reached the endpoint: %d", n-before)
	}
}

// TestPveRepinClearsUnrecordedTrustFence: a re-pin while the failed trust
// is fenced is not blocked for the old failure: its proposals pass the
// fence, a retried block of the old trust leaves it active, and calls of
// the client to it are not refused as unrecorded.
func TestPveRepinClearsUnrecordedTrustFence(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	rm := e.remote()
	rebuildServiceAuth(t, e, reopenServiceDB(t, e, `CREATE TRIGGER reject_pve_block BEFORE UPDATE OF state ON pve_remotes WHEN NEW.state = 'blocked' BEGIN SELECT RAISE(ABORT, 'injected block failure'); END`))
	c := e.svc.pveMutations().Client.(*pveMutationClient)
	c.block(rm)
	assertProposalFenced(t, e)

	// An admin re-pin (the trust generation rises) while the store accepts
	// blocks again.
	db := reopenServiceDB(t, e, `DROP TRIGGER reject_pve_block; UPDATE pve_remotes SET trust_generation = trust_generation + 1 WHERE remote_id = '`+pveReadRemote+`'`)
	rebuildServiceAuth(t, e, db)
	repinned, ok, err := db.GetRemote(pveReadRemote)
	if err != nil || !ok || repinned.TrustGeneration != rm.TrustGeneration+1 {
		t.Fatalf("re-pinned remote: %+v %v %v", repinned, ok, err)
	}
	// The old failure, retried, does not block the re-pinned remote.
	if err := e.svc.blockPveMutation(pveReadRemote, pveTrustKeyOf(rm)); err != nil {
		t.Fatalf("retried block of the superseded trust: %v", err)
	}
	if got := remoteState(t, db, pveReadRemote); got != executordb.StateActive {
		t.Fatalf("re-pinned remote state = %s, want active", got)
	}
	// Proposals reach the remote checks (no action credential here).
	_, err = e.svc.ProposePVEGuestPower(context.Background(), &pb.ProposePVEGuestPowerRequest{Target: &pb.PVEGuestPowerTarget{
		RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}})
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "no action credential") {
		t.Fatalf("proposal against the re-pinned remote: %v", err)
	}
	if _, err := c.RecentTasks(context.Background(), repinned, "pve1", time.Time{}, tokenOf(mutReadToken)); errors.Is(err, errPveTrustBlockNotRecorded) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("call to the re-pinned remote: %v", err)
	}
	if got := remoteState(t, db, pveReadRemote); got != executordb.StateActive {
		t.Fatalf("re-pinned remote state = %s, want active", got)
	}
	if _, fenced := e.svc.pveTrustFence().covers(rm); fenced {
		t.Fatal("old trust still fenced after the re-pin was seen")
	}
}

// TestPveBlockReportsFailedRevocationPrecisely: when the block is recorded
// and only the revocation of the remote's grants fails, error and log say
// so instead of "not recorded", and the remote is not fenced (the registry
// block refuses it).
func TestPveBlockReportsFailedRevocationPrecisely(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
	rm := e.remote()
	// The registry is reopened, the authority keeps its closed store:
	// BlockRemote succeeds, RevokeProviderGrants fails.
	db := reopenServiceDB(t, e, `SELECT 1`)
	e.svc.pveMutations().DB = db
	c := e.svc.pveMutations().Client.(*pveMutationClient)
	c.block(rm)
	if got := remoteState(t, db, pveReadRemote); got != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", got)
	}
	if !blockLogged(e, "pve mutation trust block recorded; authority revocation failed") {
		t.Fatal("failed revocation not logged")
	}
	if blockLogged(e, "pve mutation trust block not recorded") {
		t.Fatal("recorded block logged as not recorded")
	}
	if _, fenced := e.svc.pveTrustFence().covers(rm); fenced {
		t.Fatal("recorded block fenced as unrecorded")
	}
	err := e.svc.blockPveMutation(pveReadRemote, pveTrustKeyOf(rm))
	if !errors.Is(err, errPveTrustAuthorityNotRevoked) || errors.Is(err, errPveTrustBlockNotRecorded) {
		t.Fatalf("block with failing revocation: %v", err)
	}
}

// reopenServiceDB closes the service database of e, applies stmt to the
// file over a plain SQLite connection (the executor DB locks it
// exclusively while open) and gives the service the reopened database.
func reopenServiceDB(t *testing.T, e *pveReadEnv, stmt string) *executordb.DB {
	t.Helper()
	dir := filepath.Dir(e.jobs.JobRoot)
	if err := e.svc.db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(dir, executordb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(stmt)
	closeErr := raw.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.svc.db = db
	return db
}

// blockLogged reports whether msg was logged for the env's remote with an
// error.
func blockLogged(e *pveReadEnv, msg string) bool {
	e.logs.mu.Lock()
	defer e.logs.mu.Unlock()
	for _, r := range e.logs.records {
		if r.msg == msg && r.attrs["remote"] == pveReadRemote && r.attrs["err"] != nil {
			return true
		}
	}
	return false
}

// auditLogged reports whether an audit event of kind was logged for the
// env's remote.
func auditLogged(e *pveReadEnv, kind string) bool {
	e.logs.mu.Lock()
	defer e.logs.mu.Unlock()
	for _, r := range e.logs.records {
		if r.msg == "audit" && r.attrs["kind"] == kind && r.attrs["remote"] == pveReadRemote {
			return true
		}
	}
	return false
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
