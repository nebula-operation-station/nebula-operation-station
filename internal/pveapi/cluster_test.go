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
	// A standalone host has no cluster entry: the endpoint is absent.
	// That is "unavailable", never an empty cluster with zero nodes.
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/status": {status: http.StatusNotFound},
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
		"/api2/json/cluster/status": {body: `{"data":{"cluster":"marker-xyz","quorum":7}}`},
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
	body := `{"data":{"cluster":"` + strings.Repeat("x", 300) + `","quorum":1}}`
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
		"/api2/json/cluster/status": {body: `{"data":{"cluster":"c","nodes_online":-1}}`},
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
	if vm.Node != "pve1" || vm.LastStateChangeBy != "root@pam" {
		t.Errorf("vm 100 node/by = %q/%q, want pve1/root@pam", vm.Node, vm.LastStateChangeBy)
	}
	want := time.Unix(1761580000, 0).UTC()
	if !vm.LastStateChange.Equal(want) {
		t.Errorf("vm 100 LastStateChange = %v, want %v", vm.LastStateChange, want)
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
	// PVE 9 shape: digest/placement/state-reason-detail fields; unknown
	// fields are dropped, observed state wins over the resource copy.
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
	if ct.State != "relocating" || ct.StateReason != "relocate to pve1" {
		t.Errorf("vm 200 state/reason = %q/%q, want relocating/relocate to pve1", ct.State, ct.StateReason)
	}
	if ct.StateReasonDetail != "migration in progress" {
		t.Errorf("vm 200 StateReasonDetail = %q", ct.StateReasonDetail)
	}
	if ct.DesiredState != "started" {
		t.Errorf("vm 200 DesiredState = %q, want started", ct.DesiredState)
	}
	if ct.StartAttempts != 1 {
		t.Errorf("vm 200 StartAttempts = %d, want 1", ct.StartAttempts)
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
		{"vmid out of range", `{"data":[{"id":-5,"type":"vm"}]}`},
		{"unknown type", `{"data":[{"id":100,"type":"lxc"}]}`},
		{"managed out of range", `{"data":[{"id":100,"type":"vm","managed":2}]}`},
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
	body := `{"data":[{"id":100,"type":"vm","node":"` + strings.Repeat("x", 300) + `"}]}`
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
