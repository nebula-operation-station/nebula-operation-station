// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

const mixedCaseNode = "ProxmoxBAI"

// The pveapi check is the contract's single label, nothing wider or narrower.
func TestValidNodeNameIsTheContractLabel(t *testing.T) {
	for _, node := range []string{
		mixedCaseNode, "proxmoxbai", "pve1", "PVE1", "Pve-1", "7", strings.Repeat("A", 63),
		"", ".", "..", "../x", "a/b", "-a", "a-", "A-", "pve_1", "PVE_1", "pve1.lab", "ProxmoxBAI.lab",
		"has space", "pve1\n", "pve%2f1", "pröxmox", strings.Repeat("A", 64), strings.Repeat("a", 254),
	} {
		want := pvecontract.ValidNodeLabel(node)
		if got := validNodeName(node) == nil; got != want {
			t.Errorf("validNodeName(%q) accepted = %v, want %v", node, got, want)
		}
	}
}

func TestReadersReachMixedCaseNode(t *testing.T) {
	cases := map[string]struct {
		want string
		read func(*Client) error
	}{
		"storages": {"/nodes/ProxmoxBAI/storage", func(c *Client) error {
			_, err := c.ListStorages(context.Background(), mixedCaseNode)
			return err
		}},
		"snapshots": {"/nodes/ProxmoxBAI/qemu/100/snapshot", func(c *Client) error {
			_, err := c.ListSnapshots(context.Background(), mixedCaseNode, "qemu", 100)
			return err
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var got string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":[]}`))
			}))
			defer ts.Close()
			if err := tc.read(testClient(t, ts)); err != nil {
				t.Fatalf("read: %v", err)
			}
			if !strings.HasSuffix(got, tc.want) {
				t.Fatalf("path = %q, want suffix %q", got, tc.want)
			}
		})
	}
}

func TestWritersReachMixedCaseNode(t *testing.T) {
	ctx := context.Background()
	calls := map[string]struct {
		upidNode, upidType string
		want               string
		write              func(*Writer) error
	}{
		"start": {mixedCaseNode, "qmstart", "/nodes/ProxmoxBAI/qemu/120/status/start", func(w *Writer) error {
			_, err := w.StartVM(ctx, mixedCaseNode, 120)
			return err
		}},
		"reset": {mixedCaseNode, "qmreset", "/nodes/ProxmoxBAI/qemu/120/status/reset", func(w *Writer) error {
			_, err := w.ResetGuest(ctx, mixedCaseNode, 120)
			return err
		}},
		"stop lxc": {mixedCaseNode, "vzstop", "/nodes/ProxmoxBAI/lxc/120/status/stop", func(w *Writer) error {
			_, err := w.StopGuest(ctx, KindLXC, mixedCaseNode, 120)
			return err
		}},
		"migrate target": {"pve1", "qmigrate", "/nodes/pve1/qemu/120/migrate", func(w *Writer) error {
			_, err := w.MigrateGuest(ctx, MigrateRequest{Kind: KindQEMU, Node: "pve1", VMID: 120, Target: mixedCaseNode, Online: true})
			return err
		}},
	}
	for name, tc := range calls {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody("UPID:" + tc.upidNode + ":00001234:00ABCDEF:6900A000:" + tc.upidType + ":120:nos@pve!action:")}
			if err := tc.write(newTestWriter(t, f)); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := f.only(t).path; !strings.HasSuffix(got, tc.want) {
				t.Fatalf("path = %q, want suffix %q", got, tc.want)
			}
		})
	}
}

// A task on a case variant of the node is a task on another node.
func TestWriterRefusesTaskOfCaseVariantNode(t *testing.T) {
	f := &fakeWriteServer{body: upidBody("UPID:proxmoxbai:00001234:00ABCDEF:6900A000:qmstart:120:nos@pve!action:")}
	if _, err := newTestWriter(t, f).StartVM(context.Background(), mixedCaseNode, 120); err == nil {
		t.Fatal("task of a case-variant node accepted")
	}
}

func TestRebootNodeReachesMixedCaseNode(t *testing.T) {
	f := &fakeWriteServer{body: `{"data":null}`}
	if err := newTestWriter(t, f).RebootNode(context.Background(), mixedCaseNode); err != nil {
		t.Fatal(err)
	}
	if got := f.only(t).path; !strings.Contains(got, "/nodes/ProxmoxBAI/") {
		t.Fatalf("path = %q", got)
	}
}

func TestTaskStatusKeepsMixedCaseNode(t *testing.T) {
	const upid = "UPID:ProxmoxBAI:00001234:00ABCDEF:6900A000:qmclone:9000:nos@pve!action:"
	f := &fakeWriteServer{body: taskStatusBody(upid, "running", "")}
	got, err := newTestWriter(t, f).TaskStatus(context.Background(), upid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Node != mixedCaseNode || !strings.Contains(f.only(t).path, "/nodes/ProxmoxBAI/tasks/") {
		t.Fatalf("result %+v, path %q", got, f.only(t).path)
	}
}

// nodeReaders lists every reader that puts a node name into a request path.
func nodeReaders(t *testing.T, f *fakePVE) map[string]func(string) error {
	t.Helper()
	ctx := context.Background()
	c := clusterTestClient(t, f)
	m, err := NewMetricsClient(f.srv.URL+"/api2/json", f.srv.Client(), func(context.Context) (string, string, error) {
		return "Authorization", testSecret, nil
	})
	if err != nil {
		t.Fatalf("NewMetricsClient: %v", err)
	}
	return map[string]func(string) error{
		"qemu list":     func(n string) error { _, err := c.ListQemu(ctx, n); return err },
		"lxc list":      func(n string) error { _, err := c.ListLxc(ctx, n); return err },
		"qemu config":   func(n string) error { _, err := c.GetQemuConfig(ctx, n, 100); return err },
		"lxc config":    func(n string) error { _, err := c.GetLxcConfig(ctx, n, 100); return err },
		"agent":         func(n string) error { _, err := c.agentGet(ctx, n, 100, "get-fsinfo"); return err },
		"agent file":    func(n string) error { _, err := c.AgentFileRead(ctx, n, 100, "/etc/hostname", 1024); return err },
		"tasks":         func(n string) error { _, err := c.NodeTasks(ctx, n, TaskFilter{}); return err },
		"pci":           func(n string) error { _, err := c.NodePCIDevices(ctx, n); return err },
		"storages":      func(n string) error { _, err := c.ListStorages(ctx, n); return err },
		"node status":   func(n string) error { _, err := m.NodeStatus(ctx, n); return err },
		"guest status":  func(n string) error { _, err := m.GuestStatus(ctx, n, KindQEMU, 100); return err },
		"node history":  func(n string) error { _, err := m.NodeRRDData(ctx, n, TimeframeHour, 1024); return err },
		"guest history": func(n string) error { _, err := m.GuestRRDData(ctx, n, KindQEMU, 100, TimeframeHour); return err },
	}
}

// outsideTheLabel are node names the wider pveapi checks used to take.
func outsideTheLabel() []string {
	return []string{"pve1.lab", "ProxmoxBAI.lab", "pve_1", "Proxmox_BAI", "pve1-", "pve1.", strings.Repeat("a", 64)}
}

func TestReadersRefuseNodeOutsideTheContractLabel(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{})
	for name, read := range nodeReaders(t, f) {
		for _, node := range outsideTheLabel() {
			if err := read(node); err == nil {
				t.Errorf("%s accepted node %q", name, node)
			}
		}
	}
	if len(f.hits) != 0 {
		t.Fatalf("refused node reached the server: %v", f.hits)
	}
}

// Whatever the answer, a valid label must reach PVE unchanged.
func TestReadersSendEveryContractLabel(t *testing.T) {
	for _, node := range []string{mixedCaseNode, strings.Repeat("a", 63)} {
		f := newFakePVE(t, map[string]fakeRoute{})
		for name, read := range nodeReaders(t, f) {
			clear(f.hits)
			_ = read(node)
			reached := false
			for path := range f.hits {
				reached = reached || strings.Contains(path, "/nodes/"+node+"/")
			}
			if !reached {
				t.Errorf("%s did not reach node %q: %v", name, node, f.hits)
			}
		}
	}
}

// The node lists PVE answers with are held to the same label.
func TestNodeListsApplyTheContractLabel(t *testing.T) {
	ctx := context.Background()
	reads := map[string]struct {
		route, body string
		read        func(*Client) error
	}{
		"nodes": {"/api2/json/nodes", `{"data":[{"node":"NODE"}]}`, func(c *Client) error {
			_, err := c.ListNodes(ctx)
			return err
		}},
		"votes": {"/api2/json/cluster/config/nodes", `{"data":[{"node":"NODE"}]}`, func(c *Client) error {
			_, err := c.ClusterNodeVotes(ctx)
			return err
		}},
		"ha lrm": {"/api2/json/cluster/ha/status/current", `{"data":[{"id":"lrm:NODE","type":"lrm","node":"NODE","status":"x"}]}`, func(c *Client) error {
			_, err := c.HAStatus(ctx)
			return err
		}},
	}
	for name, tc := range reads {
		run := func(node string) error {
			f := newFakePVE(t, map[string]fakeRoute{
				"/api2/json/cluster/ha/resources": {body: `{"data":[]}`},
				tc.route:                          {body: strings.ReplaceAll(tc.body, "NODE", node)},
			})
			return tc.read(clusterTestClient(t, f))
		}
		if err := run(mixedCaseNode); err != nil {
			t.Errorf("%s refused %q: %v", name, mixedCaseNode, err)
		}
		for _, node := range outsideTheLabel() {
			if err := run(node); err == nil {
				t.Errorf("%s accepted node %q", name, node)
			}
		}
	}
}

// upidOn builds a well-formed UPID whose node field is node.
func upidOn(node string) string {
	return "UPID:" + node + ":00001234:00ABCDEF:6900A000:qmstart:120:nos@pve!action:"
}

// The node field of a UPID is the contract's single label, so a task read
// back from PVE can always be matched to a node that can be addressed.
func TestParseUPIDNodeIsTheContractLabel(t *testing.T) {
	for _, node := range []string{
		mixedCaseNode, "proxmoxbai", "pve1", "Pve-1", "7", strings.Repeat("A", 63),
		"", ".", "..", "-a", "a-", "pve_1", "pve1.lab", "ProxmoxBAI.lab", "a/b", "has space", "pröxmox",
		strings.Repeat("A", 64), strings.Repeat("a", 65), strings.Repeat("a", 254),
	} {
		task, err := parseUPID(upidOn(node))
		if !pvecontract.ValidNodeLabel(node) {
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("parseUPID on node %q err = %v, want ErrMalformed", node, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUPID on node %q: %v", node, err)
			continue
		}
		if task.Node != node {
			t.Errorf("parseUPID node = %q, want %q", task.Node, node)
		}
	}
}

func TestParseUPIDBoundsTheNodeLabel(t *testing.T) {
	if task, err := parseUPID(upidOn(mixedCaseNode)); err != nil || task.Node != mixedCaseNode {
		t.Fatalf("mixed-case node: task %+v, err %v", task, err)
	}
	longest := strings.Repeat("a", 63)
	if task, err := parseUPID(upidOn(longest)); err != nil || task.Node != longest {
		t.Fatalf("63-character node: task %+v, err %v", task, err)
	}
	if _, err := parseUPID(upidOn(longest + "a")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("64-character node err = %v, want ErrMalformed", err)
	}
}

// The UPID names the same node the caller asked for, so only the grammar can
// refuse it.
func TestDispatchRefusesOverlongNodeInUPID(t *testing.T) {
	node := strings.Repeat("a", 64)
	f := &fakeWriteServer{body: upidBody(upidOn(node))}
	r := writeRequest{op: "test", method: http.MethodPost, path: "/nodes/x/test"}
	if _, err := newTestWriter(t, f).dispatch(context.Background(), r, node, "qmstart", "120"); err == nil {
		t.Fatal("dispatch accepted a UPID with a 64-character node")
	}
}

func TestTaskStatusRefusesOverlongNodeInUPID(t *testing.T) {
	f := &fakeWriteServer{body: `{"data":null}`}
	_, err := newTestWriter(t, f).TaskStatus(context.Background(), upidOn(strings.Repeat("a", 64)))
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
	if f.count() != 0 {
		t.Fatal("UPID with an overlong node reached the server")
	}
}

// A malformed name never leaves the process, whatever its case.
func TestWriterRefusesMalformedMixedCaseNode(t *testing.T) {
	for _, node := range []string{"Proxmox/BAI", "../ProxmoxBAI", "-ProxmoxBAI", "ProxmoxBAI-", "Proxmox_BAI", "ProxmoxBAI.lab"} {
		f := &fakeWriteServer{body: `{"data":null}`}
		if err := newTestWriter(t, f).RebootNode(context.Background(), node); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("RebootNode(%q) err = %v", node, err)
		}
		if f.count() != 0 {
			t.Errorf("RebootNode(%q) reached the server", node)
		}
	}
}
