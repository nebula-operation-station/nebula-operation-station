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
		"has space", "pve1\n", "pve%2f1", "pröxmox", strings.Repeat("A", 64), strings.Repeat("a", MaxNodeNameBytes+1),
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
