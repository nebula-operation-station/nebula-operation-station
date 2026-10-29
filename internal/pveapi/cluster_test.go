// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRoute is one canned response of the fake PVE server.
type fakeRoute struct {
	status int
	body   string
	delay  time.Duration
}

// fakePVE is a loopback test server that answers fixed PVE API routes.
type fakePVE struct {
	srv    *httptest.Server
	routes map[string]fakeRoute
	auth   []string
	hits   map[string]int
}

func newFakePVE(t *testing.T, routes map[string]fakeRoute) *fakePVE {
	t.Helper()
	f := &fakePVE{routes: routes, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits[r.URL.Path]++
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		rt, ok := f.routes[r.URL.Path]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		if rt.delay > 0 {
			time.Sleep(rt.delay)
		}
		if rt.status == 0 {
			rt.status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rt.status)
		_, _ = w.Write([]byte(rt.body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newTestClient(t *testing.T, f *fakePVE) *Client {
	t.Helper()
	return &Client{
		HTTP:    f.srv.Client(),
		BaseURL: f.srv.URL + "/api2/json",
		Token:   func(context.Context) (string, error) { return "PVEAPIToken=root@pam!test!abc", nil },
		Timeout: 5 * time.Second,
	}
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

func wantUnavailable(t *testing.T, available bool, reason, what string) {
	t.Helper()
	if available {
		t.Fatalf("%s: want unavailable, got available (%q)", what, reason)
	}
	if reason == "" {
		t.Fatalf("%s: unavailable without reason", what)
	}
}

func TestClusterStatusPVE8(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: fixture(t, "cluster_status_pve8.json")},
	})
	c := newTestClient(t, f)

	got, err := c.ClusterStatus(context.Background())
	if err != nil {
		t.Fatalf("ClusterStatus: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if got.Name != "pve-cluster" {
		t.Errorf("Name = %q, want pve-cluster", got.Name)
	}
	if !got.Quorum {
		t.Error("Quorum = false, want true")
	}
	if got.NodesOnline != 2 || got.NodesTotal != 3 {
		t.Errorf("NodesOnline/NodesTotal = %d/%d, want 2/3", got.NodesOnline, got.NodesTotal)
	}
}

func TestClusterStatusPVE9(t *testing.T) {
	// PVE 9 shape: same core fields plus unknown extras that must be
	// dropped, quorum currently lost.
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: fixture(t, "cluster_status_pve9.json")},
	})
	c := newTestClient(t, f)

	got, err := c.ClusterStatus(context.Background())
	if err != nil {
		t.Fatalf("ClusterStatus: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if got.Name != "pve-cluster" {
		t.Errorf("Name = %q, want pve-cluster", got.Name)
	}
	if got.Quorum {
		t.Error("Quorum = true, want false")
	}
	if got.NodesOnline != 3 || got.NodesTotal != 3 {
		t.Errorf("NodesOnline/NodesTotal = %d/%d, want 3/3", got.NodesOnline, got.NodesTotal)
	}
}

func TestClusterStatusStandalone(t *testing.T) {
	// A standalone host returns only the local node, with no cluster entry.
	// That is "unavailable", never an empty cluster with zero nodes.
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: fixture(t, "cluster_status_standalone.json")},
	})
	c := newTestClient(t, f)

	got, err := c.ClusterStatus(context.Background())
	if err != nil {
		t.Fatalf("ClusterStatus: %v", err)
	}
	wantUnavailable(t, got.Available, got.Reason, "standalone")
	if !strings.Contains(got.Reason, "standalone") {
		t.Errorf("Reason = %q, want standalone explanation", got.Reason)
	}
}

func TestClusterStatusUnavailable(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{})
	f.srv.Close()
	c := newTestClient(t, f)

	got, err := c.ClusterStatus(context.Background())
	if err != nil {
		t.Fatalf("ClusterStatus: %v", err)
	}
	wantUnavailable(t, got.Available, got.Reason, "closed server")
}

func TestClusterStatusMalformed(t *testing.T) {
	// quorum out of range; the body carries a marker that must not leak
	// into the error.
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: `{"data":[{"type":"cluster","id":"cluster","name":"marker-xyz","nodes":1,"quorate":7}]}`},
	})
	c := newTestClient(t, f)

	_, err := c.ClusterStatus(context.Background())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if strings.Contains(err.Error(), "marker-xyz") {
		t.Error("error message leaks response body")
	}
}

func TestClusterStatusInvalidJSON(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: `{"data":`},
	})
	c := newTestClient(t, f)

	_, err := c.ClusterStatus(context.Background())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestClusterStatusNullData(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: `{"data":null}`},
	})
	c := newTestClient(t, f)

	_, err := c.ClusterStatus(context.Background())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestClusterStatusOversize(t *testing.T) {
	body := `{"data":[{"type":"cluster","id":"cluster","name":"` + strings.Repeat("x", 300) + `","nodes":1,"quorate":1}]}`
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: body},
	})
	c := newTestClient(t, f)
	c.MaxBody = 100

	_, err := c.ClusterStatus(context.Background())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestClusterStatusNodesOutOfRange(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: `{"data":[{"type":"cluster","id":"cluster","name":"c","nodes":-1,"quorate":1}]}`},
	})
	c := newTestClient(t, f)

	_, err := c.ClusterStatus(context.Background())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestTokenHeaderSent(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: fixture(t, "cluster_status_pve8.json")},
	})
	c := newTestClient(t, f)

	if _, err := c.ClusterStatus(context.Background()); err != nil {
		t.Fatalf("ClusterStatus: %v", err)
	}
	if len(f.auth) != 1 || f.auth[0] != "PVEAPIToken=root@pam!test!abc" {
		t.Fatalf("Authorization header = %v, want the supplied token", f.auth)
	}
}

func TestTokenSupplierError(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {body: fixture(t, "cluster_status_pve8.json")},
	})
	c := newTestClient(t, f)
	c.Token = func(context.Context) (string, error) {
		return "", errors.New("vault locked")
	}

	if _, err := c.ClusterStatus(context.Background()); err == nil {
		t.Fatal("want error from token supplier")
	}
}

func TestHAStatusPVE8(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/ha/resources":      {body: fixture(t, "ha_resources_pve8.json")},
		"/api2/json/cluster/ha/status/current": {body: fixture(t, "ha_status_pve8.json")},
	})
	c := newTestClient(t, f)

	got, err := c.HAStatus(context.Background())
	if err != nil {
		t.Fatalf("HAStatus: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if len(got.Resources) != 2 {
		t.Fatalf("len(Resources) = %d, want 2", len(got.Resources))
	}
	vm := got.Resources[0]
	if vm.VMID != 100 || vm.Type != "vm" || !vm.Managed {
		t.Errorf("vm 100 = %+v, want vmid 100 vm managed", vm)
	}
	if vm.DesiredState != "started" || vm.State != "started" {
		t.Errorf("vm 100 desired/observed = %q/%q, want started/started", vm.DesiredState, vm.State)
	}
	if vm.Node != "pve1" {
		t.Errorf("vm 100 node = %q, want pve1", vm.Node)
	}
	if !vm.LastStateChange.IsZero() || vm.LastStateChangeBy != "" || vm.StartAttempts != 0 {
		t.Errorf("HA status must leave unavailable metadata unknown: %+v", vm)
	}
	ct := got.Resources[1]
	if ct.VMID != 200 || ct.Type != "ct" {
		t.Errorf("vm 200 = %+v, want vmid 200 ct", ct)
	}
	if ct.DesiredState != "stopped" || ct.State != "stopped" {
		t.Errorf("vm 200 desired/observed = %q/%q, want stopped/stopped", ct.DesiredState, ct.State)
	}
}

func TestHAStatusPVE9(t *testing.T) {
	// Mixed manager and service entries are joined with configuration
	// independently of status order and desired state.
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/ha/resources":      {body: fixture(t, "ha_resources_pve9.json")},
		"/api2/json/cluster/ha/status/current": {body: fixture(t, "ha_status_pve9.json")},
	})
	c := newTestClient(t, f)

	got, err := c.HAStatus(context.Background())
	if err != nil {
		t.Fatalf("HAStatus: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if len(got.Resources) != 2 {
		t.Fatalf("len(Resources) = %d, want 2", len(got.Resources))
	}
	ct := got.Resources[1]
	if ct.State != "migrate" || ct.Node != "pve2" {
		t.Errorf("ct 200 = %+v, want observed migrate on pve2", ct)
	}
	if ct.DesiredState != "started" || !ct.Managed {
		t.Errorf("ct 200 = %+v, want desired started and managed", ct)
	}
	if ct.StateReason != "" || ct.StateReasonDetail != "" || ct.StartAttempts != 0 {
		t.Errorf("HA status must leave unavailable metadata unknown: %+v", ct)
	}
}

func TestHAStatusNotEnabled(t *testing.T) {
	// A remote without HA has no HA endpoints at all: unavailable, never
	// an empty resource list.
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/ha/resources":      {status: http.StatusNotFound},
		"/api2/json/cluster/ha/status/current": {status: http.StatusNotFound},
	})
	c := newTestClient(t, f)

	got, err := c.HAStatus(context.Background())
	if err != nil {
		t.Fatalf("HAStatus: %v", err)
	}
	wantUnavailable(t, got.Available, got.Reason, "ha not enabled")
	if !strings.Contains(got.Reason, "HA not enabled") {
		t.Errorf("Reason = %q, want HA not enabled", got.Reason)
	}
}

func TestHAStatusEmpty(t *testing.T) {
	// HA enabled but no resources: a valid empty result, distinct from
	// unavailable.
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/ha/resources":      {body: `{"data":[]}`},
		"/api2/json/cluster/ha/status/current": {body: `{"data":[]}`},
	})
	c := newTestClient(t, f)

	got, err := c.HAStatus(context.Background())
	if err != nil {
		t.Fatalf("HAStatus: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if len(got.Resources) != 0 {
		t.Errorf("len(Resources) = %d, want 0", len(got.Resources))
	}
}

func TestHAStatusMalformed(t *testing.T) {
	tests := []struct {
		name string
		res  string
	}{
		{"negative vmid", `{"data":[{"sid":"vm:-5","type":"vm"}]}`},
		{"vmid out of range", `{"data":[{"sid":"vm:9999999999","type":"vm"}]}`},
		{"unknown type", `{"data":[{"sid":"lxc:100","type":"lxc"}]}`},
		{"inconsistent type", `{"data":[{"sid":"vm:100","type":"ct"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakePVE(t, map[string]fakeRoute{
				"/api2/json/cluster/ha/resources":      {body: tt.res},
				"/api2/json/cluster/ha/status/current": {body: `{"data":[]}`},
			})
			c := newTestClient(t, f)
			if _, err := c.HAStatus(context.Background()); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestHAStatusOversize(t *testing.T) {
	body := `{"data":[{"sid":"vm:100","type":"vm","state":"` + strings.Repeat("x", 300) + `"}]}`
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/ha/resources":      {body: body},
		"/api2/json/cluster/ha/status/current": {body: `{"data":[]}`},
	})
	c := newTestClient(t, f)
	c.MaxBody = 100

	if _, err := c.HAStatus(context.Background()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestRedirectDestinationsReceiveNoRequest(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var hits atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte(`{"data":[]}`))
			}))
			defer destination.Close()
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, destination.URL, code)
			}))
			defer source.Close()
			hc := source.Client() // Ordinary injected client follows redirects by default.
			c := &Client{HTTP: hc, BaseURL: source.URL, Token: func(context.Context) (string, error) { return "test-token", nil }}
			got, err := c.ClusterStatus(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantUnavailable(t, got.Available, got.Reason, "redirect")
			if hits.Load() != 0 {
				t.Fatalf("redirected destination received %d requests", hits.Load())
			}
			if hc.CheckRedirect != nil {
				t.Fatal("injected client was mutated")
			}
		})
	}
}

func TestResponsesRejectInvalidUTF8BeforeDecoding(t *testing.T) {
	for _, endpoint := range []string{"cluster", "resources", "status", "tasks"} {
		t.Run(endpoint, func(t *testing.T) {
			routes := map[string]fakeRoute{
				"/api2/json/cluster/status":            {body: fixture(t, "cluster_status_pve8.json")},
				"/api2/json/cluster/ha/resources":      {body: fixture(t, "ha_resources_pve8.json")},
				"/api2/json/cluster/ha/status/current": {body: fixture(t, "ha_status_pve8.json")},
				tasksPath:                              {body: fixture(t, "tasklist_pve8.json")},
			}
			path := map[string]string{"cluster": "/api2/json/cluster/status", "resources": "/api2/json/cluster/ha/resources", "status": "/api2/json/cluster/ha/status/current", "tasks": tasksPath}[endpoint]
			// Even ignored fields must not allow malformed response bytes.
			routes[path] = fakeRoute{body: strings.Replace(routes[path].body, "{", "{\"ignored\":\"\xff\",", 1)}
			f := newFakePVE(t, routes)
			c := newTestClient(t, f)
			var err error
			switch endpoint {
			case "cluster":
				_, err = c.ClusterStatus(context.Background())
			case "resources", "status":
				_, err = c.HAStatus(context.Background())
			case "tasks":
				_, err = c.NodeTasks(context.Background(), "pve1", TaskFilter{})
			}
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestHAStatusJoinsBySID(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/ha/resources":      {body: `{"data":[{"sid":"vm:100","type":"vm","state":"started"},{"sid":"ct:100","type":"ct","state":"stopped"},{"sid":"vm:200","type":"vm","state":"disabled"}]}`},
		"/api2/json/cluster/ha/status/current": {body: `{"data":[{"id":"quorum","type":"quorum","status":"OK"},{"id":"service:ct:100","type":"service","sid":"ct:100","state":"stopped","node":"pve2"},{"id":"service:vm:100","type":"service","sid":"vm:100","state":"started","node":"pve1"}]}`},
	})
	got, err := newTestClient(t, f).HAStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Resources) != 3 {
		t.Fatalf("resources = %+v, want three configured resources", got.Resources)
	}
	if got.Resources[0].Node != "pve1" || got.Resources[1].Node != "pve2" || got.Resources[2].State != "" || got.Resources[2].DesiredState != "disabled" {
		t.Fatalf("incorrect SID join: %+v", got.Resources)
	}
}

func TestClusterStatusRejectsMalformedEntries(t *testing.T) {
	for _, body := range []string{
		`{"data":[{"type":"cluster","name":"c","nodes":1001,"quorate":1}]}`,
		`{"data":[{"type":"cluster","name":"c","nodes":1,"quorate":1},{"type":"cluster","name":"c","nodes":1,"quorate":1}]}`,
		`{"data":[{"type":"node","name":"pve1","online":2}]}`,
		`{"data":[{"type":"cluster","name":"c","nodes":0,"quorate":1},{"type":"node","name":"pve1","online":1}]}`,
		`{"data":[{"type":"unknown"}]}`,
	} {
		f := newFakePVE(t, map[string]fakeRoute{"/api2/json/cluster/status": {body: body}})
		if _, err := newTestClient(t, f).ClusterStatus(context.Background()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	}
}

func TestHAStatusRejectsMalformedServices(t *testing.T) {
	for _, status := range []string{
		`{"data":[{"type":"service","id":"service:vm:100","sid":"vm:-5"}]}`,
		`{"data":[{"type":"service","id":"service:vm:200","sid":"vm:100"}]}`,
		`{"data":[{"type":"service","id":"service:vm:100","sid":"vm:100"},{"type":"service","id":"service:vm:100","sid":"vm:100"}]}`,
		`{"data":[{"type":"service","id":"service:vm:100","sid":"vm:100","node":"` + strings.Repeat("x", maxTextLen+1) + `"}]}`,
	} {
		f := newFakePVE(t, map[string]fakeRoute{
			"/api2/json/cluster/ha/resources":      {body: fixture(t, "ha_resources_pve8.json")},
			"/api2/json/cluster/ha/status/current": {body: status},
		})
		if _, err := newTestClient(t, f).HAStatus(context.Background()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	}
}
