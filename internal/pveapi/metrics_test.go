// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testSecret is a fake PVE token value; tests assert it never leaks into
// errors.
const testSecret = "PVEAPIToken=nosread@pam!1001=SECRET-TOKEN-VALUE"

// testServer is an httptest server that serves JSON fixtures per path
// and records requests for assertions.
type testServer struct {
	srv      *httptest.Server
	requests *atomic.Int64
	lastAuth *atomic.Value
	lastReq  *atomic.Value
}

func newTestServer(t *testing.T, routes map[string]string) *testServer {
	t.Helper()
	ts := &testServer{requests: &atomic.Int64{}, lastAuth: &atomic.Value{}, lastReq: &atomic.Value{}}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.requests.Add(1)
		ts.lastAuth.Store(r.Header.Get("Authorization"))
		ts.lastReq.Store(r.URL.RequestURI())
		fixture, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"data":null,"errors":"no such endpoint","status":"ERROR"}`))
			return
		}
		data, err := os.ReadFile(path.Join("testdata", fixture))
		if err != nil {
			t.Errorf("read fixture %s: %v", fixture, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func newTestClient(t *testing.T, ts *testServer, opts ...Option) *MetricsClient {
	t.Helper()
	supplier := func(ctx context.Context) (string, string, error) {
		return "Authorization", testSecret, nil
	}
	c, err := NewMetricsClient(ts.srv.URL+"/api2/json", ts.srv.Client(), supplier, opts...)
	if err != nil {
		t.Fatalf("NewMetricsClient: %v", err)
	}
	return c
}

func mustFloat64(t *testing.T, v *float64) float64 {
	t.Helper()
	if v == nil {
		t.Fatal("expected non-nil float64, got nil")
	}
	return *v
}

func mustInt64(t *testing.T, v *int64) int64 {
	t.Helper()
	if v == nil {
		t.Fatal("expected non-nil int64, got nil")
	}
	return *v
}

// --- constructor ---

func TestNewMetricsClientRejectsBadConfig(t *testing.T) {
	supplier := func(ctx context.Context) (string, string, error) { return "Authorization", "x", nil }
	cases := []struct {
		name string
		base string
		hc   *http.Client
		auth AuthHeaderSupplier
		opts []Option
	}{
		{"nil http client", "https://pve:8006/api2/json", nil, supplier, nil},
		{"nil auth supplier", "https://pve:8006/api2/json", &http.Client{}, nil, nil},
		{"bad scheme", "ftp://pve:8006/api2/json", &http.Client{}, supplier, nil},
		{"no host", "https:///api2/json", &http.Client{}, supplier, nil},
		{"user info in URL", "https://user:pass@pve:8006/api2/json", &http.Client{}, supplier, nil},
		{"max body too small", "https://pve:8006/api2/json", &http.Client{}, supplier, []Option{WithMaxResponseBytes(100)}},
		{"timeout too small", "https://pve:8006/api2/json", &http.Client{}, supplier, []Option{WithPerCallTimeout(0)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewMetricsClient(tc.base, tc.hc, tc.auth, tc.opts...)
			if !errors.Is(err, ErrBadParam) {
				t.Fatalf("expected ErrBadParam, got %v", err)
			}
		})
	}
}

// --- NodeStatus ---

func TestNodeStatusPVE8(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/status": "node_status_pve8.json",
	})
	c := newTestClient(t, ts)

	m, err := c.NodeStatus(context.Background(), "pve1")
	if err != nil {
		t.Fatalf("NodeStatus: %v", err)
	}
	if m.Node != "pve1" || m.Status != "online" {
		t.Errorf("node/status = %q/%q, want pve1/online", m.Node, m.Status)
	}
	if got := mustFloat64(t, m.CPU); got != 0.1875 {
		t.Errorf("CPU = %v, want 0.1875", got)
	}
	if got := mustInt64(t, m.MemUsed); got != 16106127360 {
		t.Errorf("MemUsed = %d, want 16106127360", got)
	}
	if got := mustInt64(t, m.MemTotal); got != 65987027456 {
		t.Errorf("MemTotal = %d, want 65987027456", got)
	}
	if got := mustInt64(t, m.DiskRead); got != 1258291 {
		t.Errorf("DiskRead = %d, want 1258291", got)
	}
	if got := mustInt64(t, m.DiskWrite); got != 3145728 {
		t.Errorf("DiskWrite = %d, want 3145728", got)
	}
	if got := mustInt64(t, m.NetIn); got != 10485760 {
		t.Errorf("NetIn = %d, want 10485760", got)
	}
	if got := mustInt64(t, m.NetOut); got != 5242880 {
		t.Errorf("NetOut = %d, want 5242880", got)
	}
	if got := ts.lastAuth.Load().(string); got != testSecret {
		t.Errorf("Authorization header = %q, want the supplier value", got)
	}
}

func TestNodeStatusPVE9(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/status": "node_status_pve9.json",
	})
	c := newTestClient(t, ts)

	m, err := c.NodeStatus(context.Background(), "pve1")
	if err != nil {
		t.Fatalf("NodeStatus: %v", err)
	}
	if m.Status != "online" {
		t.Errorf("Status = %q, want online", m.Status)
	}
	if got := mustFloat64(t, m.CPU); got != 0.2031 {
		t.Errorf("CPU = %v, want 0.2031", got)
	}
	if got := mustInt64(t, m.MemUsed); got != 17179869184 {
		t.Errorf("MemUsed = %d, want 17179869184", got)
	}
	if got := mustInt64(t, m.NetIn); got != 11534336 {
		t.Errorf("NetIn = %d, want 11534336", got)
	}
}

func TestNodeStatusPartialStaysMissing(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/status": "node_status_partial.json",
	})
	c := newTestClient(t, ts)

	m, err := c.NodeStatus(context.Background(), "pve1")
	if err != nil {
		t.Fatalf("NodeStatus: %v", err)
	}
	if got := mustFloat64(t, m.CPU); got != 0.1 {
		t.Errorf("CPU = %v, want 0.1", got)
	}
	if got := mustInt64(t, m.NetIn); got != 1048576 {
		t.Errorf("NetIn = %d, want 1048576", got)
	}
	for field, v := range map[string]*int64{
		"MemUsed":   m.MemUsed,
		"MemTotal":  m.MemTotal,
		"DiskRead":  m.DiskRead,
		"DiskWrite": m.DiskWrite,
		"NetOut":    m.NetOut,
	} {
		if v != nil {
			t.Errorf("%s = %d, want nil (missing stays missing)", field, *v)
		}
	}
}

func TestNodeStatusRejectsInvalidRanges(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
	}{
		{"cpu above 1", "node_status_cpu_invalid.json"},
		{"negative memory", "node_status_mem_negative.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, map[string]string{
				"/api2/json/nodes/pve1/status": tc.fixture,
			})
			c := newTestClient(t, ts)
			_, err := c.NodeStatus(context.Background(), "pve1")
			if !errors.Is(err, ErrInvalidRange) {
				t.Fatalf("expected ErrInvalidRange, got %v", err)
			}
		})
	}
}

func TestNodeStatusRejectsBadNode(t *testing.T) {
	ts := newTestServer(t, map[string]string{})
	c := newTestClient(t, ts)
	for _, node := range []string{"", "a/b", "../x", "a b", strings.Repeat("x", 100), "a..b.."} {
		if _, err := c.NodeStatus(context.Background(), node); !errors.Is(err, ErrBadParam) {
			t.Errorf("node %q: expected ErrBadParam, got %v", node, err)
		}
	}
	if n := ts.requests.Load(); n != 0 {
		t.Errorf("requests sent = %d, want 0 for rejected params", n)
	}
}

func TestNodeStatusUnavailable(t *testing.T) {
	ts := newTestServer(t, map[string]string{})
	c := newTestClient(t, ts)

	// Unknown endpoint (404) is unavailable, not empty.
	_, err := c.NodeStatus(context.Background(), "ghost")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("error leaks the auth header: %v", err)
	}
}

func TestNodeStatusErrorDoesNotLeakBodyOrSecret(t *testing.T) {
	const marker = "BODY-MARKER-XYZ-123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(marker))
	}))
	t.Cleanup(srv.Close)
	supplier := func(ctx context.Context) (string, string, error) {
		return "Authorization", testSecret, nil
	}
	c, err := NewMetricsClient(srv.URL+"/api2/json", srv.Client(), supplier)
	if err != nil {
		t.Fatalf("NewMetricsClient: %v", err)
	}
	_, err = c.NodeStatus(context.Background(), "pve1")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("error leaks response body: %v", err)
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("error leaks the auth header: %v", err)
	}
}

func TestNodeStatusAuthFailureStopsRequest(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/status": "node_status_pve8.json",
	})
	supplier := func(ctx context.Context) (string, string, error) {
		return "", "", errors.New("vault locked")
	}
	c, err := NewMetricsClient(ts.srv.URL+"/api2/json", ts.srv.Client(), supplier)
	if err != nil {
		t.Fatalf("NewMetricsClient: %v", err)
	}
	if _, err := c.NodeStatus(context.Background(), "pve1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if n := ts.requests.Load(); n != 0 {
		t.Errorf("requests sent = %d, want 0 after auth failure", n)
	}
}

func TestNodeStatusPerCallTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"data":{"status":"online"}}`))
	}))
	t.Cleanup(srv.Close)
	supplier := func(ctx context.Context) (string, string, error) {
		return "Authorization", testSecret, nil
	}
	c, err := NewMetricsClient(srv.URL+"/api2/json", srv.Client(), supplier,
		WithPerCallTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("NewMetricsClient: %v", err)
	}
	start := time.Now()
	_, err = c.NodeStatus(context.Background(), "pve1")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("call took %s, per-call timeout not enforced", elapsed)
	}
}

func TestNodeStatusResponseTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 4 KiB body, above the configured 1 KiB limit.
		_, _ = w.Write([]byte(`{"data":{"status":"online","pad":"` + strings.Repeat("x", 4096) + `"}}`))
	}))
	t.Cleanup(srv.Close)
	supplier := func(ctx context.Context) (string, string, error) {
		return "Authorization", testSecret, nil
	}
	c, err := NewMetricsClient(srv.URL+"/api2/json", srv.Client(), supplier,
		WithMaxResponseBytes(1024))
	if err != nil {
		t.Fatalf("NewMetricsClient: %v", err)
	}
	if _, err := c.NodeStatus(context.Background(), "pve1"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestNodeStatusMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not json"))
	}))
	t.Cleanup(srv.Close)
	supplier := func(ctx context.Context) (string, string, error) {
		return "Authorization", testSecret, nil
	}
	c, err := NewMetricsClient(srv.URL+"/api2/json", srv.Client(), supplier)
	if err != nil {
		t.Fatalf("NewMetricsClient: %v", err)
	}
	if _, err := c.NodeStatus(context.Background(), "pve1"); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange, got %v", err)
	}
}

// --- GuestStatus ---

func TestGuestStatusQemuRunningPVE8(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/qemu/101/status/current": "qemu_status_running_pve8.json",
	})
	c := newTestClient(t, ts)

	m, err := c.GuestStatus(context.Background(), "pve1", KindQEMU, 101)
	if err != nil {
		t.Fatalf("GuestStatus: %v", err)
	}
	if m.Node != "pve1" || m.Kind != KindQEMU || m.VMID != 101 || m.Status != "running" {
		t.Errorf("identity = %+v, want pve1/qemu/101/running", m)
	}
	if got := mustFloat64(t, m.CPU); got != 0.3125 {
		t.Errorf("CPU = %v, want 0.3125", got)
	}
	if got := mustInt64(t, m.MemUsed); got != 4294967296 {
		t.Errorf("MemUsed = %d, want 4294967296", got)
	}
	if got := mustInt64(t, m.MemTotal); got != 8589934592 {
		t.Errorf("MemTotal = %d, want 8589934592", got)
	}
	if got := mustInt64(t, m.DiskRead); got != 262144 {
		t.Errorf("DiskRead = %d, want 262144", got)
	}
	if got := mustInt64(t, m.DiskWrite); got != 1048576 {
		t.Errorf("DiskWrite = %d, want 1048576", got)
	}
	if got := mustInt64(t, m.NetIn); got != 2097152 {
		t.Errorf("NetIn = %d, want 2097152", got)
	}
	if got := mustInt64(t, m.NetOut); got != 1048576 {
		t.Errorf("NetOut = %d, want 1048576", got)
	}
	if got := mustInt64(t, m.DiskAllocated); got != 107374182400 {
		t.Errorf("DiskAllocated = %d, want 107374182400", got)
	}
}

func TestGuestStatusStoppedStaysMissing(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/qemu/102/status/current": "qemu_status_stopped.json",
	})
	c := newTestClient(t, ts)

	m, err := c.GuestStatus(context.Background(), "pve1", KindQEMU, 102)
	if err != nil {
		t.Fatalf("GuestStatus: %v", err)
	}
	if m.Status != "stopped" {
		t.Errorf("Status = %q, want stopped", m.Status)
	}
	for _, field := range []string{"CPU", "MemUsed", "MemTotal", "DiskRead", "DiskWrite", "NetIn", "NetOut", "DiskAllocated"} {
		v := reflect.ValueOf(m).FieldByName(field)
		if !v.IsNil() {
			t.Errorf("%s = %v, want nil for a stopped guest", field, v.Interface())
		}
	}
}

func TestGuestStatusLxcPVE9(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/lxc/201/status/current": "lxc_status_running_pve9.json",
	})
	c := newTestClient(t, ts)

	m, err := c.GuestStatus(context.Background(), "pve1", KindLXC, 201)
	if err != nil {
		t.Fatalf("GuestStatus: %v", err)
	}
	if m.Kind != KindLXC || m.VMID != 201 || m.Status != "running" {
		t.Errorf("identity = %+v, want pve1/lxc/201/running", m)
	}
	if got := mustFloat64(t, m.CPU); got != 0.125 {
		t.Errorf("CPU = %v, want 0.125", got)
	}
	if got := mustInt64(t, m.MemUsed); got != 2147483648 {
		t.Errorf("MemUsed = %d, want 2147483648", got)
	}
	if got := mustInt64(t, m.MemTotal); got != 4294967296 {
		t.Errorf("MemTotal = %d, want 4294967296", got)
	}
	if got := mustInt64(t, m.DiskAllocated); got != 53687091200 {
		t.Errorf("DiskAllocated = %d, want 53687091200", got)
	}
}

func TestGuestStatusRejectsBadParams(t *testing.T) {
	ts := newTestServer(t, map[string]string{})
	c := newTestClient(t, ts)
	cases := []struct {
		name string
		node string
		kind GuestKind
		vmid int
	}{
		{"bad kind", "pve1", "kvm", 101},
		{"empty kind", "pve1", "", 101},
		{"vmid zero", "pve1", KindQEMU, 0},
		{"vmid negative", "pve1", KindLXC, -3},
		{"bad node", "a/b", KindQEMU, 101},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.GuestStatus(context.Background(), tc.node, tc.kind, tc.vmid); !errors.Is(err, ErrBadParam) {
				t.Fatalf("expected ErrBadParam, got %v", err)
			}
		})
	}
	if n := ts.requests.Load(); n != 0 {
		t.Errorf("requests sent = %d, want 0 for rejected params", n)
	}
}

// TestGuestMetricsHasNoFilesystemUsageField guards the ADR 0006 rule
// that PVE disk allocation must never be presented as filesystem usage:
// GuestMetrics may only carry the I/O rates and the explicitly named
// allocation field, never a used/total filesystem pair.
func TestGuestMetricsHasNoFilesystemUsageField(t *testing.T) {
	typ := reflect.TypeOf(GuestMetrics{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		switch f.Name {
		case "DiskRead", "DiskWrite", "DiskAllocated":
			// allowed
		default:
			if strings.Contains(f.Name, "Disk") {
				t.Errorf("GuestMetrics has unexpected disk field %s", f.Name)
			}
		}
	}
}

// --- NodeRRDData ---

func TestNodeRRDDataHourPVE8(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/rrddata": "node_rrd_hour_pve8.json",
	})
	c := newTestClient(t, ts)

	points, err := c.NodeRRDData(context.Background(), "pve1", TimeframeHour, 65987027456)
	if err != nil {
		t.Fatalf("NodeRRDData: %v", err)
	}
	if len(points) != 5 {
		t.Fatalf("len(points) = %d, want 5", len(points))
	}
	if got := ts.lastReq.Load().(string); !strings.Contains(got, "timeframe=hour") {
		t.Errorf("request URI = %q, want timeframe=hour query", got)
	}
	// Point 0: fractional mem converted to bytes.
	p0 := points[0]
	if !p0.Time.Equal(time.Unix(1761600000, 0).UTC()) {
		t.Errorf("point[0].Time = %v, want 1761600000 UTC", p0.Time)
	}
	if got := mustFloat64(t, p0.CPU); got != 0.15 {
		t.Errorf("point[0].CPU = %v, want 0.15", got)
	}
	if got := mustInt64(t, p0.MemUsed); got != 16180019132 {
		t.Errorf("point[0].MemUsed = %d, want 16180019132 (0.2452 * total)", got)
	}
	if got := mustInt64(t, p0.MemTotal); got != 65987027456 {
		t.Errorf("point[0].MemTotal = %d, want 65987027456", got)
	}
	if got := mustInt64(t, p0.NetOut); got != 2621440 {
		t.Errorf("point[0].NetOut = %d, want 2621440", got)
	}
	// Point 2: partial point, mem and netout missing, stays missing.
	p2 := points[2]
	if p2.MemUsed != nil {
		t.Errorf("point[2].MemUsed = %d, want nil (partial point)", *p2.MemUsed)
	}
	if p2.NetOut != nil {
		t.Errorf("point[2].NetOut = %d, want nil (partial point)", *p2.NetOut)
	}
	if got := mustInt64(t, p2.MemTotal); got != 65987027456 {
		t.Errorf("point[2].MemTotal = %d, want 65987027456", got)
	}
	if got := mustInt64(t, p2.NetIn); got != 4194304 {
		t.Errorf("point[2].NetIn = %d, want 4194304", got)
	}
}

func TestNodeRRDDataDayPVE9(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/rrddata": "node_rrd_day_pve9.json",
	})
	c := newTestClient(t, ts)

	points, err := c.NodeRRDData(context.Background(), "pve1", TimeframeDay, 65987027456)
	if err != nil {
		t.Fatalf("NodeRRDData: %v", err)
	}
	if len(points) != 4 {
		t.Fatalf("len(points) = %d, want 4", len(points))
	}
	if got := ts.lastReq.Load().(string); !strings.Contains(got, "timeframe=day") {
		t.Errorf("request URI = %q, want timeframe=day query", got)
	}
	if got := mustFloat64(t, points[2].CPU); got != 0.23 {
		t.Errorf("point[2].CPU = %v, want 0.23 (unknown PVE 9 field ignored)", got)
	}
	if got := mustInt64(t, points[3].DiskWrite); got != 3145728 {
		t.Errorf("point[3].DiskWrite = %d, want 3145728", got)
	}
}

func TestNodeRRDDataEmptyIsNotUnavailable(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/rrddata": "rrd_empty.json",
	})
	c := newTestClient(t, ts)

	points, err := c.NodeRRDData(context.Background(), "pve1", TimeframeHour, 65987027456)
	if err != nil {
		t.Fatalf("empty RRD is a success, got error: %v", err)
	}
	if points == nil || len(points) != 0 {
		t.Errorf("points = %v, want empty non-nil slice", points)
	}

	// Unavailable (404) must be an error, kept distinct from empty.
	if _, err := c.NodeRRDData(context.Background(), "ghost", TimeframeHour, 0); !errors.Is(err, ErrUnavailable) {
		t.Errorf("expected ErrUnavailable for unknown node, got %v", err)
	}
}

func TestNodeRRDDataRejectsBadParams(t *testing.T) {
	ts := newTestServer(t, map[string]string{})
	c := newTestClient(t, ts)
	cases := []struct {
		name          string
		node          string
		tf            Timeframe
		memTotalBytes int64
	}{
		{"timeframe week", "pve1", "week", 0},
		{"timeframe uppercase", "pve1", "HOUR", 0},
		{"timeframe empty", "pve1", "", 0},
		{"bad node", "a/b", TimeframeHour, 0},
		{"negative mem total", "pve1", TimeframeDay, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.NodeRRDData(context.Background(), tc.node, tc.tf, tc.memTotalBytes); !errors.Is(err, ErrBadParam) {
				t.Fatalf("expected ErrBadParam, got %v", err)
			}
		})
	}
	if n := ts.requests.Load(); n != 0 {
		t.Errorf("requests sent = %d, want 0 for rejected params", n)
	}
}

func TestNodeRRDDataRejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
	}{
		{"cpu above 1", "node_rrd_cpu_invalid.json"},
		{"negative diskread", "node_rrd_diskread_negative.json"},
		{"mem fraction above 1", "node_rrd_mem_invalid.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, map[string]string{
				"/api2/json/nodes/pve1/rrddata": tc.fixture,
			})
			c := newTestClient(t, ts)
			if _, err := c.NodeRRDData(context.Background(), "pve1", TimeframeHour, 65987027456); !errors.Is(err, ErrInvalidRange) {
				t.Fatalf("expected ErrInvalidRange, got %v", err)
			}
		})
	}
}

func TestNodeRRDDataWithoutMemTotalStaysMissing(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/rrddata": "node_rrd_hour_pve8.json",
	})
	c := newTestClient(t, ts)

	points, err := c.NodeRRDData(context.Background(), "pve1", TimeframeHour, 0)
	if err != nil {
		t.Fatalf("NodeRRDData: %v", err)
	}
	if len(points) != 5 {
		t.Fatalf("len(points) = %d, want 5", len(points))
	}
	for i, p := range points {
		if p.MemUsed != nil {
			t.Errorf("point[%d].MemUsed = %d, want nil without total memory", i, *p.MemUsed)
		}
		if p.MemTotal != nil {
			t.Errorf("point[%d].MemTotal = %d, want nil without total memory", i, *p.MemTotal)
		}
	}
	if points[0].CPU == nil {
		t.Error("point[0].CPU = nil, want 0.15 (other fields unaffected)")
	}
}

// --- GuestRRDData ---

func TestGuestRRDDataQemuHourPVE8(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/qemu/101/rrddata": "qemu_rrd_hour_pve8.json",
	})
	c := newTestClient(t, ts)

	points, err := c.GuestRRDData(context.Background(), "pve1", KindQEMU, 101, TimeframeHour)
	if err != nil {
		t.Fatalf("GuestRRDData: %v", err)
	}
	if len(points) != 3 {
		t.Fatalf("len(points) = %d, want 3", len(points))
	}
	p0 := points[0]
	// Guest RRD "mem" is already bytes: no conversion.
	if got := mustInt64(t, p0.MemUsed); got != 4026531840 {
		t.Errorf("point[0].MemUsed = %d, want 4026531840", got)
	}
	if got := mustInt64(t, p0.MemTotal); got != 8589934592 {
		t.Errorf("point[0].MemTotal = %d, want 8589934592", got)
	}
	if got := mustFloat64(t, p0.CPU); got != 0.25 {
		t.Errorf("point[0].CPU = %v, want 0.25", got)
	}
	if !p0.Time.Equal(time.Unix(1761600000, 0).UTC()) {
		t.Errorf("point[0].Time = %v, want 1761600000 UTC", p0.Time)
	}
	// Partial point: mem missing stays missing.
	if points[2].MemUsed != nil {
		t.Errorf("point[2].MemUsed = %d, want nil (partial point)", *points[2].MemUsed)
	}
	if got := mustInt64(t, points[2].MemTotal); got != 8589934592 {
		t.Errorf("point[2].MemTotal = %d, want 8589934592", got)
	}
}

func TestGuestRRDDataLxcDayPVE9(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/lxc/201/rrddata": "lxc_rrd_day_pve9.json",
	})
	c := newTestClient(t, ts)

	points, err := c.GuestRRDData(context.Background(), "pve1", KindLXC, 201, TimeframeDay)
	if err != nil {
		t.Fatalf("GuestRRDData: %v", err)
	}
	if len(points) != 3 {
		t.Fatalf("len(points) = %d, want 3", len(points))
	}
	if got := mustInt64(t, points[1].MemUsed); got != 2061584384 {
		t.Errorf("point[1].MemUsed = %d, want 2061584384", got)
	}
	if got := mustInt64(t, points[2].DiskWrite); got != 49152 {
		t.Errorf("point[2].DiskWrite = %d, want 49152 (unknown PVE 9 field ignored)", got)
	}
}

func TestGuestRRDDataRejectsBadParams(t *testing.T) {
	ts := newTestServer(t, map[string]string{})
	c := newTestClient(t, ts)
	cases := []struct {
		name string
		kind GuestKind
		vmid int
		tf   Timeframe
	}{
		{"bad kind", "kvm", 101, TimeframeHour},
		{"vmid zero", KindLXC, 0, TimeframeDay},
		{"timeframe month", KindQEMU, 101, "month"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.GuestRRDData(context.Background(), "pve1", tc.kind, tc.vmid, tc.tf); !errors.Is(err, ErrBadParam) {
				t.Fatalf("expected ErrBadParam, got %v", err)
			}
		})
	}
	if n := ts.requests.Load(); n != 0 {
		t.Errorf("requests sent = %d, want 0 for rejected params", n)
	}
}

func TestGuestRRDDataEmptyIsNotUnavailable(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/lxc/201/rrddata": "rrd_empty.json",
	})
	c := newTestClient(t, ts)

	points, err := c.GuestRRDData(context.Background(), "pve1", KindLXC, 201, TimeframeDay)
	if err != nil {
		t.Fatalf("empty RRD is a success, got error: %v", err)
	}
	if len(points) != 0 {
		t.Errorf("len(points) = %d, want 0", len(points))
	}
}
