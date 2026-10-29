// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

// fixtureServer serves the given fixture files under /api2/json. keys are
// paths relative to /api2/json, values are testdata file paths.
func fixtureServer(t *testing.T, fixtures map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path[len("/api2/json"):]
		file, ok := fixtures[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"errors":{%q:"no such endpoint"}}`, key)
			return
		}
		body, err := os.ReadFile(path.Join("testdata", file))
		if err != nil {
			t.Errorf("read fixture %s: %v", file, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s}`, body)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func clientFor(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	c, err := New(ts.URL, ts.Client(), func(ctx context.Context) (string, error) {
		return testToken, nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestListNodesPVE8(t *testing.T) {
	ts := fixtureServer(t, map[string]string{"/nodes": "pve8/nodes.json"})
	c := clientFor(t, ts)
	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("got %d nodes, want 3", len(nodes))
	}
	want := []Node{
		{Name: "pve1", Status: "online", Type: "pve"},
		{Name: "pve2", Status: "online", Type: "pve"},
		{Name: "pve3", Status: "offline", Type: "pve"},
	}
	for i, n := range want {
		if nodes[i] != n {
			t.Errorf("nodes[%d] = %+v, want %+v", i, nodes[i], n)
		}
	}
}

func TestListNodesPVE9IgnoresExtraFields(t *testing.T) {
	ts := fixtureServer(t, map[string]string{"/nodes": "pve9/nodes.json"})
	c := clientFor(t, ts)
	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 3 || nodes[0].Name != "pve1" || nodes[0].Status != "online" {
		t.Fatalf("nodes = %+v, want 3 nodes with pve1 online", nodes)
	}
}

func TestListQemuAndLxc(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/qemu": "pve8/qemu_pve1.json",
		"/nodes/pve1/lxc":  "pve8/lxc_pve1.json",
	})
	c := clientFor(t, ts)
	q, err := c.ListQemu(context.Background(), "pve1")
	if err != nil {
		t.Fatalf("ListQemu: %v", err)
	}
	if len(q) != 2 {
		t.Fatalf("got %d guests, want 2", len(q))
	}
	if q[0].VMID != 100 || q[0].Kind != KindQemu || q[0].Status != "running" ||
		q[0].MaxCPU != 4 || q[0].MaxMemory != 8589934592 || q[0].UptimeSeconds != 3600 {
		t.Errorf("q[0] = %+v", q[0])
	}
	if q[1].Status != "stopped" || q[1].UptimeSeconds != 0 {
		t.Errorf("q[1] = %+v", q[1])
	}
	l, err := c.ListLxc(context.Background(), "pve1")
	if err != nil {
		t.Fatalf("ListLxc: %v", err)
	}
	if len(l) != 1 || l[0].VMID != 200 || l[0].Kind != KindLxc || l[0].Node != "pve1" {
		t.Fatalf("l = %+v", l)
	}
}

func TestListQemuPVE9CarriesReuseHints(t *testing.T) {
	ts := fixtureServer(t, map[string]string{"/nodes/pve1/qemu": "pve9/qemu_pve1.json"})
	c := clientFor(t, ts)
	q, err := c.ListQemu(context.Background(), "pve1")
	if err != nil {
		t.Fatalf("ListQemu: %v", err)
	}
	if len(q) != 2 {
		t.Fatalf("got %d guests, want 2", len(q))
	}
	if q[0].UUID != "11111111-2222-3333-4444-555555555555" || q[0].Ctime == nil ||
		q[0].Ctime.Unix() != 1750000000 {
		t.Errorf("q[0] reuse hints = (ctime %v, uuid %q)", q[0].Ctime, q[0].UUID)
	}
}

func TestListRejectsBadNodeName(t *testing.T) {
	ts := fixtureServer(t, map[string]string{})
	c := clientFor(t, ts)
	for _, name := range []string{"../etc", "a b", "pve1;rm", strings.Repeat("x", 200)} {
		if _, err := c.ListQemu(context.Background(), name); err == nil {
			t.Errorf("ListQemu(%q): expected error", name)
		}
	}
}

func TestGuestListRejectsBadVMID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"vmid":-1,"name":"x","status":"stopped"}]}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	if _, err := c.ListQemu(context.Background(), "pve1"); err == nil {
		t.Fatal("ListQemu: expected error for negative vmid")
	}
}

func TestGuestListTooManyObjects(t *testing.T) {
	var b []byte
	for i := 0; i < MaxObjectsPerPage+1; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, fmt.Sprintf(`{"vmid":%d,"name":"g","status":"stopped"}`, i)...)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu", func(w http.ResponseWriter, r *http.Request) {
		w.Write(append([]byte(`{"data":[`), b...))
		w.Write([]byte(`]}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	if _, err := c.ListQemu(context.Background(), "pve1"); err == nil {
		t.Fatal("ListQemu: expected error for oversized list")
	}
}

func TestEnumerateClusterPartial(t *testing.T) {
	fixtures := map[string]string{
		"/nodes":           "pve8/nodes.json",
		"/nodes/pve1/qemu": "pve8/qemu_pve1.json",
		"/nodes/pve1/lxc":  "pve8/lxc_pve1.json",
		"/nodes/pve2/qemu": "pve8/qemu_pve2.json",
		"/nodes/pve2/lxc":  "pve8/lxc_pve2.json",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path[len("/api2/json"):]
		if key == "/nodes/pve3/qemu" || key == "/nodes/pve3/lxc" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"errors":{%q:"node is down"}}`, key)
			return
		}
		file, ok := fixtures[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := os.ReadFile(path.Join("testdata", file))
		if err != nil {
			t.Errorf("read fixture %s: %v", file, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"data":%s}`, body)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)

	inv, err := c.EnumerateCluster(context.Background())
	if err != nil {
		t.Fatalf("EnumerateCluster: %v", err)
	}
	if !inv.Partial {
		t.Error("Partial = false, want true for down node pve3")
	}
	if len(inv.Nodes) != 3 {
		t.Errorf("got %d nodes, want 3", len(inv.Nodes))
	}
	if len(inv.Guests) != 4 {
		t.Errorf("got %d guests, want 4 from pve1+pve2", len(inv.Guests))
	}
	reason, ok := inv.NodeErrors["pve3"]
	if !ok || !strings.Contains(reason, "node is down") {
		t.Errorf("NodeErrors[pve3] = %q, want 'node is down' reason", reason)
	}
	if _, ok := inv.NodeErrors["pve1"]; ok {
		t.Error("NodeErrors has entry for healthy node pve1")
	}
}

func TestEnumerateClusterStandalone(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes":           "standalone/nodes.json",
		"/nodes/pve0/qemu": "standalone/qemu_pve0.json",
		"/nodes/pve0/lxc":  "standalone/lxc_pve0.json",
	})
	c := clientFor(t, ts)
	inv, err := c.EnumerateCluster(context.Background())
	if err != nil {
		t.Fatalf("EnumerateCluster: %v", err)
	}
	if inv.Partial || inv.Truncated {
		t.Errorf("inv = %+v, want complete non-partial", inv)
	}
	if len(inv.Nodes) != 1 || len(inv.Guests) != 2 {
		t.Fatalf("nodes=%d guests=%d, want 1 node and 2 guests", len(inv.Nodes), len(inv.Guests))
	}
	kinds := map[GuestKind]int{}
	for _, g := range inv.Guests {
		kinds[g.Kind]++
	}
	if kinds[KindQemu] != 1 || kinds[KindLxc] != 1 {
		t.Errorf("kinds = %v, want 1 qemu and 1 lxc", kinds)
	}
}

func TestEnumerateClusterNodesErrorIsHard(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":{"/nodes":"internal error"}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	if _, err := c.EnumerateCluster(context.Background()); err == nil {
		t.Fatal("EnumerateCluster: expected error when /nodes fails")
	}
}

func TestIncarnationMatches(t *testing.T) {
	t1 := time.Unix(1750000000, 0)
	t2 := time.Unix(1750003600, 0)
	cases := []struct {
		name  string
		a, b  Incarnation
		same  bool
		known bool
	}{
		{"same uuid", Incarnation{UUID: "u1"}, Incarnation{UUID: "u1"}, true, true},
		{"different uuid", Incarnation{UUID: "u1"}, Incarnation{UUID: "u2"}, false, true},
		{"one side missing uuid", Incarnation{UUID: "u1"}, Incarnation{Ctime: &t1}, false, true},
		{"same ctime", Incarnation{Ctime: &t1}, Incarnation{Ctime: &t1}, true, true},
		{"different ctime", Incarnation{Ctime: &t1}, Incarnation{Ctime: &t2}, false, true},
		{"no hints", Incarnation{}, Incarnation{}, false, false},
	}
	for _, tc := range cases {
		same, known := tc.a.Matches(tc.b)
		if same != tc.same || known != tc.known {
			t.Errorf("%s: Matches = (%v, %v), want (%v, %v)", tc.name, same, known, tc.same, tc.known)
		}
	}
}

func TestValidateVMID(t *testing.T) {
	for _, vmid := range []int{-1, 0, 1 << 31} {
		if err := validateVMID(vmid); err == nil {
			t.Errorf("validateVMID(%d): expected error", vmid)
		}
	}
	if err := validateVMID(100); err != nil {
		t.Errorf("validateVMID(100): %v", err)
	}
}

func TestGuestListCanonicalResources(t *testing.T) {
	for _, version := range []string{"pve8", "pve9"} {
		t.Run(version, func(t *testing.T) {
			c := clientFor(t, fixtureServer(t, map[string]string{
				"/nodes/pve1/qemu": version + "/qemu_pve1.json",
				"/nodes/pve1/lxc":  "pve8/lxc_pve1.json",
			}))
			q, err := c.ListQemu(context.Background(), "pve1")
			if err != nil {
				t.Fatal(err)
			}
			if len(q) != 2 || q[0].MaxCPU != 4 || q[0].MaxMemory != 8<<30 || q[1].MaxCPU != 8 || q[1].MaxMemory != 16<<30 {
				t.Errorf("qemu resources = %+v", q)
			}
			l, err := c.ListLxc(context.Background(), "pve1")
			if err != nil {
				t.Fatal(err)
			}
			if len(l) != 1 || l[0].MaxCPU != 2 || l[0].MaxMemory != 4<<30 {
				t.Errorf("lxc resources = %+v", l)
			}
		})
	}
	for _, resource := range []string{`"cpus":-1`, `"maxmem":-1`} {
		if _, err := parseGuestList([]byte(`[{"vmid":100,`+resource+`}]`), "pve1", KindQemu); err == nil {
			t.Errorf("negative resource accepted: %s", resource)
		}
	}
}

func TestListsRejectNullAndAcceptEmptyArrays(t *testing.T) {
	for _, payload := range []string{`null`, ` null `, `[]`} {
		t.Run(payload, func(t *testing.T) {
			c := newTestClient(t, serveData(t, payload), nil)
			nodes, nerr := c.ListNodes(context.Background())
			qemu, qerr := c.ListQemu(context.Background(), "pve1")
			lxc, lerr := c.ListLxc(context.Background(), "pve1")
			for i, err := range []error{nerr, qerr, lerr} {
				if (err != nil) != (payload != "[]") {
					t.Errorf("list %d: err=%v for payload %s", i, err, payload)
				}
			}
			if payload == "[]" && (len(nodes) != 0 || len(qemu) != 0 || len(lxc) != 0) {
				t.Error("empty array returned nonempty list")
			}
		})
	}
}

func TestEnumerateClusterNullListsNeverProduceCompleteInventory(t *testing.T) {
	for _, endpoint := range []string{"/nodes", "/nodes/pve1/qemu", "/nodes/pve1/lxc", "none"} {
		t.Run(endpoint, func(t *testing.T) {
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := strings.TrimPrefix(r.URL.Path, apiRoot)
				switch {
				case p == endpoint:
					fmt.Fprint(w, `{"data":null}`)
				case p == "/nodes":
					fmt.Fprint(w, `{"data":[{"node":"pve1","status":"online"}]}`)
				default:
					fmt.Fprint(w, `{"data":[]}`)
				}
			}), nil)
			inv, err := c.EnumerateCluster(context.Background())
			if endpoint == "/nodes" {
				if err == nil {
					t.Fatal("null nodes produced an inventory")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if endpoint == "none" {
				if inv.Partial || len(inv.Guests) != 0 || len(inv.NodeErrors) != 0 {
					t.Errorf("explicit empty lists should be complete: %+v", inv)
				}
			} else if !inv.Partial || inv.NodeErrors["pve1"] == "" {
				t.Errorf("null guest list should be partial: %+v", inv)
			}
		})
	}
}
