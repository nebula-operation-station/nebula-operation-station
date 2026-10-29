// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"fmt"
	"math"
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

func TestNewMetricsClientSanitizesMalformedCredentialURLs(t *testing.T) {
	supplier := func(context.Context) (string, string, error) { return "", "", nil }
	for _, suffix := range []string{"host:bad/api2/json", "host/%zz", "[broken/api2/json", "host/\n"} {
		base := "https://user:password-marker@" + suffix
		_, err := NewMetricsClient(base, &http.Client{}, supplier)
		if !errors.Is(err, ErrBadParam) {
			t.Fatalf("expected ErrBadParam, got %v", err)
		}
		if strings.Contains(err.Error(), "password-marker") || strings.Contains(err.Error(), base) {
			t.Fatal("constructor error contains credential-bearing input")
		}
	}
}

func TestMetricsClientNeverFollowsRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, customPolicy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/custom-policy=%t", code, customPolicy), func(t *testing.T) {
				var destinationRequests, policyCalls atomic.Int64
				destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					destinationRequests.Add(1)
					_, _ = w.Write([]byte(`{"data":{"cpu":0.1}}`))
				}))
				t.Cleanup(destination.Close)
				source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != testSecret {
						t.Error("source did not receive authentication")
					}
					http.Redirect(w, r, destination.URL, code)
				}))
				t.Cleanup(source.Close)
				hc := source.Client()
				if customPolicy {
					hc.CheckRedirect = func(*http.Request, []*http.Request) error {
						policyCalls.Add(1)
						return nil
					}
				}
				c, err := NewMetricsClient(source.URL, hc, func(context.Context) (string, string, error) {
					return "Authorization", testSecret, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.NodeStatus(context.Background(), "pve1"); !errors.Is(err, ErrUnavailable) {
					t.Errorf("redirect response: expected ErrUnavailable, got %v", err)
				}
				if n := destinationRequests.Load(); n != 0 {
					t.Errorf("redirected destination received %d requests, want 0", n)
				}
				if n := policyCalls.Load(); n != 0 {
					t.Errorf("injected redirect policy called %d times, want 0", n)
				}
				if c.http == hc || c.http.Transport != hc.Transport || c.http.Timeout != hc.Timeout || c.http.Jar != hc.Jar {
					t.Error("expected a cloned client preserving transport, timeout and cookie jar")
				}
				if customPolicy {
					if hc.CheckRedirect == nil || hc.CheckRedirect(nil, nil) != nil || policyCalls.Load() != 1 {
						t.Error("injected client's redirect policy changed")
					}
				} else if hc.CheckRedirect != nil {
					t.Error("injected client's redirect policy changed")
				}
			})
		}
	}
}

func newJSONTestClient(t *testing.T, body string) *MetricsClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := NewMetricsClient(srv.URL, srv.Client(), func(context.Context) (string, string, error) {
		return "", "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRRDDataPreservesFractionalAverages(t *testing.T) {
	for _, schema := range []string{"node", "qemu", "lxc"} {
		t.Run(schema, func(t *testing.T) {
			memoryFields := `"memused":1024.25,"memtotal":2048.5`
			if schema != "node" {
				memoryFields = `"mem":1024.25,"maxmem":2048.5`
			}
			c := newJSONTestClient(t, `{"data":[{"time":1761600000,"cpu":0.125,`+memoryFields+`,"diskread":1.25,"diskwrite":2.5,"netin":3.75,"netout":4.125}]}`)
			var points []RRDPoint
			var err error
			if schema == "node" {
				points, err = c.NodeRRDData(context.Background(), "pve1", TimeframeHour, 0)
			} else {
				points, err = c.GuestRRDData(context.Background(), "pve1", GuestKind(schema), 101, TimeframeHour)
			}
			if err != nil || len(points) != 1 {
				t.Fatalf("RRD data: len=%d, error=%v", len(points), err)
			}
			p := points[0]
			for field, pair := range map[string]struct {
				got  *float64
				want float64
			}{
				"cpu": {p.CPU, 0.125}, "memory used": {p.MemUsed, 1024.25}, "memory total": {p.MemTotal, 2048.5},
				"disk read": {p.DiskRead, 1.25}, "disk write": {p.DiskWrite, 2.5}, "net in": {p.NetIn, 3.75}, "net out": {p.NetOut, 4.125},
			} {
				if got := mustFloat64(t, pair.got); got != pair.want {
					t.Errorf("%s = %g, want %g", field, got, pair.want)
				}
			}
		})
	}
}

func TestGuestStatusCountersAreDistinctFromRRDRates(t *testing.T) {
	for _, kind := range []GuestKind{KindQEMU, KindLXC} {
		t.Run(string(kind), func(t *testing.T) {
			statusClient := newJSONTestClient(t, `{"data":{"diskread":1000,"diskwrite":2000,"netin":3000,"netout":4000}}`)
			m, err := statusClient.GuestStatus(context.Background(), "pve1", kind, 101)
			if err != nil {
				t.Fatal(err)
			}
			rrdClient := newJSONTestClient(t, `{"data":[{"time":1761600000,"diskread":1.5,"diskwrite":2.5,"netin":3.5,"netout":4.5}]}`)
			points, err := rrdClient.GuestRRDData(context.Background(), "pve1", kind, 101, TimeframeHour)
			if err != nil || len(points) != 1 {
				t.Fatalf("RRD data: len=%d, error=%v", len(points), err)
			}
			for i, v := range []*int64{m.DiskReadBytes, m.DiskWriteBytes, m.NetInBytes, m.NetOutBytes} {
				if got := mustInt64(t, v); got != int64(i+1)*1000 {
					t.Errorf("counter[%d] = %d, want cumulative bytes", i, got)
				}
			}
			for i, v := range []*float64{points[0].DiskRead, points[0].DiskWrite, points[0].NetIn, points[0].NetOut} {
				if got := mustFloat64(t, v); got != float64(i)+1.5 {
					t.Errorf("rate[%d] = %g, want bytes per second", i, got)
				}
			}
			for _, name := range []string{"DiskRead", "DiskWrite", "NetIn", "NetOut"} {
				if _, ok := reflect.TypeOf(m).FieldByName(name); ok {
					t.Errorf("status exposes ambiguous rate field %s", name)
				}
			}
		})
	}
}

func TestMetricResponsesRejectInvalidNumericRanges(t *testing.T) {
	for _, schema := range []string{"node-rrd", "guest-status", "guest-rrd"} {
		fields := []string{"cpu", "mem", "maxmem", "diskread", "diskwrite", "netin", "netout"}
		if schema == "node-rrd" {
			fields[1], fields[2] = "memused", "memtotal"
		}
		if schema == "guest-status" {
			fields = append(fields, "maxdisk")
		}
		for _, field := range fields {
			invalid := []string{"-0.5", "9223372036854775808", "1e309", `"NaN"`, `"Infinity"`}
			if schema == "guest-status" && field != "cpu" {
				invalid = append(invalid, "-1", "0.5")
			}
			if field == "cpu" {
				invalid = append(invalid, "1.01")
			}
			for _, value := range invalid {
				for _, kind := range []GuestKind{KindQEMU, KindLXC} {
					if schema == "node-rrd" && kind == KindLXC {
						continue
					}
					t.Run(schema+"/"+string(kind)+"/"+field+"/"+value, func(t *testing.T) {
						data := fmt.Sprintf(`{"time":1761600000,%q:%s}`, field, value)
						if schema != "guest-status" {
							// A bad second sample must reject the whole response.
							data = `[{"time":1761599940},` + data + `]`
						}
						c := newJSONTestClient(t, `{"data":`+data+`}`)
						var err error
						switch schema {
						case "node-rrd":
							var points []RRDPoint
							points, err = c.NodeRRDData(context.Background(), "pve1", TimeframeHour, 0)
							if points != nil {
								t.Error("invalid response returned partial points")
							}
						case "guest-rrd":
							var points []RRDPoint
							points, err = c.GuestRRDData(context.Background(), "pve1", kind, 101, TimeframeHour)
							if points != nil {
								t.Error("invalid response returned partial points")
							}
						default:
							var m GuestMetrics
							m, err = c.GuestStatus(context.Background(), "pve1", kind, 101)
							if !reflect.DeepEqual(m, GuestMetrics{}) {
								t.Error("invalid response returned partial metrics")
							}
						}
						if !errors.Is(err, ErrInvalidRange) {
							t.Fatalf("expected ErrInvalidRange, got %v", err)
						}
					})
				}
			}
		}
	}
}

func TestRRDValidationRejectsNonFiniteValues(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if err := checkCPU("/rrddata", "cpu", &value); !errors.Is(err, ErrInvalidRange) {
			t.Errorf("non-finite CPU: expected ErrInvalidRange, got %v", err)
		}
		if err := checkRRDBytes("/rrddata", "mem", &value); !errors.Is(err, ErrInvalidRange) {
			t.Errorf("non-finite RRD bytes: expected ErrInvalidRange, got %v", err)
		}
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
	if got := mustInt64(t, m.DiskReadBytes); got != 262144 {
		t.Errorf("DiskReadBytes = %d, want 262144", got)
	}
	if got := mustInt64(t, m.DiskWriteBytes); got != 1048576 {
		t.Errorf("DiskWriteBytes = %d, want 1048576", got)
	}
	if got := mustInt64(t, m.NetInBytes); got != 2097152 {
		t.Errorf("NetInBytes = %d, want 2097152", got)
	}
	if got := mustInt64(t, m.NetOutBytes); got != 1048576 {
		t.Errorf("NetOutBytes = %d, want 1048576", got)
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
	for _, field := range []string{"CPU", "MemUsed", "MemTotal", "DiskReadBytes", "DiskWriteBytes", "NetInBytes", "NetOutBytes", "DiskAllocated"} {
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
// GuestMetrics may only carry the cumulative I/O byte counters and the explicitly named
// allocation field, never a used/total filesystem pair.
func TestGuestMetricsHasNoFilesystemUsageField(t *testing.T) {
	typ := reflect.TypeOf(GuestMetrics{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		switch f.Name {
		case "DiskReadBytes", "DiskWriteBytes", "DiskAllocated":
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
	// Point 0: memory bytes come directly from the RRD sample.
	p0 := points[0]
	if !p0.Time.Equal(time.Unix(1761600000, 0).UTC()) {
		t.Errorf("point[0].Time = %v, want 1761600000 UTC", p0.Time)
	}
	if got := mustFloat64(t, p0.CPU); got != 0.15 {
		t.Errorf("point[0].CPU = %v, want 0.15", got)
	}
	if got := mustFloat64(t, p0.MemUsed); got != 16180019132 {
		t.Errorf("point[0].MemUsed = %g, want 16180019132", got)
	}
	if got := mustFloat64(t, p0.MemTotal); got != 65987027456 {
		t.Errorf("point[0].MemTotal = %g, want 65987027456", got)
	}
	if got := mustFloat64(t, p0.NetOut); got != 2621440 {
		t.Errorf("point[0].NetOut = %g, want 2621440", got)
	}
	// Point 2: partial point, mem and netout missing, stays missing.
	p2 := points[2]
	if p2.MemUsed != nil {
		t.Errorf("point[2].MemUsed = %g, want nil (partial point)", *p2.MemUsed)
	}
	if p2.NetOut != nil {
		t.Errorf("point[2].NetOut = %g, want nil (partial point)", *p2.NetOut)
	}
	if got := mustFloat64(t, p2.MemTotal); got != 65987027456 {
		t.Errorf("point[2].MemTotal = %g, want 65987027456", got)
	}
	if got := mustFloat64(t, p2.NetIn); got != 4194304 {
		t.Errorf("point[2].NetIn = %g, want 4194304", got)
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
	if got := mustFloat64(t, points[3].DiskWrite); got != 3145728 {
		t.Errorf("point[3].DiskWrite = %g, want 3145728", got)
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
		{"negative memory bytes", "node_rrd_mem_invalid.json"},
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

func TestNodeRRDDataUsesReportedMemoryWithoutStatusTotal(t *testing.T) {
	ts := newTestServer(t, map[string]string{
		"/api2/json/nodes/pve1/rrddata": "node_rrd_hour_pve8.json",
	})
	c := newTestClient(t, ts)
	for _, statusTotal := range []int64{0, 1, 65987027456} {
		points, err := c.NodeRRDData(context.Background(), "pve1", TimeframeHour, statusTotal)
		if err != nil {
			t.Fatalf("NodeRRDData: %v", err)
		}
		if len(points) != 5 {
			t.Fatalf("len(points) = %d, want 5", len(points))
		}
		if got := mustFloat64(t, points[0].MemUsed); got != 16180019132 {
			t.Errorf("MemUsed = %g, want reported byte value", got)
		}
		if got := mustFloat64(t, points[0].MemTotal); got != 65987027456 {
			t.Errorf("MemTotal = %g, want reported byte value", got)
		}
		if points[2].MemUsed != nil {
			t.Error("missing memused must stay nil")
		}
		if points[4].MemTotal != nil {
			t.Error("missing memtotal must stay nil, even with a status total")
		}
		if points[0].CPU == nil {
			t.Error("point[0].CPU = nil, want 0.15")
		}
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
	if got := mustFloat64(t, p0.MemUsed); got != 4026531840 {
		t.Errorf("point[0].MemUsed = %g, want 4026531840", got)
	}
	if got := mustFloat64(t, p0.MemTotal); got != 8589934592 {
		t.Errorf("point[0].MemTotal = %g, want 8589934592", got)
	}
	if got := mustFloat64(t, p0.CPU); got != 0.25 {
		t.Errorf("point[0].CPU = %v, want 0.25", got)
	}
	if !p0.Time.Equal(time.Unix(1761600000, 0).UTC()) {
		t.Errorf("point[0].Time = %v, want 1761600000 UTC", p0.Time)
	}
	// Partial point: mem missing stays missing.
	if points[2].MemUsed != nil {
		t.Errorf("point[2].MemUsed = %g, want nil (partial point)", *points[2].MemUsed)
	}
	if got := mustFloat64(t, points[2].MemTotal); got != 8589934592 {
		t.Errorf("point[2].MemTotal = %g, want 8589934592", got)
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
	if got := mustFloat64(t, points[1].MemUsed); got != 2061584384 {
		t.Errorf("point[1].MemUsed = %g, want 2061584384", got)
	}
	if got := mustFloat64(t, points[2].DiskWrite); got != 49152 {
		t.Errorf("point[2].DiskWrite = %g, want 49152 (unknown PVE 9 field ignored)", got)
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
