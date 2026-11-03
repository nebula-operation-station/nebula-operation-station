// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// readerRoute is one canned answer of readerFakePVE. file names a fixture
// under testdata; raw fixtures (bare data values) are wrapped in the PVE
// envelope, others are served verbatim. body is served when file is empty.
type readerRoute struct {
	file string
	raw  bool
	body string
}

// readerRoutes covers every read endpoint of Client, keyed by the path
// below /api2/json.
var readerRoutes = map[string]readerRoute{
	"/nodes":                                            {file: "pve8/nodes.json", raw: true},
	"/nodes/pve1/qemu":                                  {file: "pve8/qemu_pve1.json", raw: true},
	"/nodes/pve2/qemu":                                  {file: "pve8/qemu_pve2.json", raw: true},
	"/nodes/pve1/lxc":                                   {file: "pve8/lxc_pve1.json", raw: true},
	"/nodes/pve2/lxc":                                   {file: "pve8/lxc_pve2.json", raw: true},
	"/nodes/pve1/qemu/100/config":                       {file: "pve8/qemu_config_100.json", raw: true},
	"/nodes/pve1/lxc/200/config":                        {file: "pve8/lxc_config_200.json", raw: true},
	"/nodes/pve1/qemu/100/agent/get-osinfo":             {file: "pve8/agent_osinfo_100.json", raw: true},
	"/nodes/pve1/qemu/100/agent/get-fsinfo":             {file: "pve8/agent_fsinfo_100.json", raw: true},
	"/nodes/pve1/qemu/100/agent/file-read":              {body: `{"data":{"content":"web1\n"}}`},
	"/cluster/status":                                   {file: "cluster_status_pve9.json"},
	"/cluster/config/nodes":                             {body: `{"data":[{"node":"pve1","quorum_votes":"1"},{"node":"pve2"}]}`},
	"/cluster/ha/resources":                             {file: "ha_resources_pve9.json"},
	"/cluster/ha/status/current":                        {file: "ha_status_pve9.json"},
	"/nodes/pve1/tasks":                                 {file: "tasklist_pve9.json"},
	"/nodes/pve1/hardware/pci":                          {body: `{"data":[{"id":"0000:01:00.0","vendor":"0x10de","device":"0x1b80"}]}`},
	"/nodes/pve1/storage":                               {file: "storage_pve9.json"},
	"/nodes/pve1/storage/local/status":                  {file: "storage_single.json"},
	"/nodes/pve1/qemu/100/snapshot":                     {file: "snapshot_qemu_pve9.json"},
	"/nodes/pve1/storage/local/content":                 {file: "content-vzdump-pve8.json"},
	"/cluster/backup":                                   {file: "jobs-pve8.json"},
	"/nodes/pve1/qemu/100/agent/network-get-interfaces": {file: "pve8/agent_net_100.json", raw: true},
}

// readerFakePVE is a loopback PVE API that answers readerRoutes and records
// every request. Unknown paths answer 404.
type readerFakePVE struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []*http.Request
}

func (f *readerFakePVE) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.seen...)
}

func newReaderFakePVE(t *testing.T) *readerFakePVE {
	t.Helper()
	f := &readerFakePVE{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.Clone(context.Background()))
		f.mu.Unlock()
		rt, ok := readerRoutes[strings.TrimPrefix(r.URL.Path, apiRoot)]
		if !ok || !strings.HasPrefix(r.URL.Path, apiRoot+"/") {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"data":null}`)
			return
		}
		body := rt.body
		if rt.file != "" {
			b, err := os.ReadFile(filepath.Join("testdata", rt.file))
			if err != nil {
				t.Errorf("read fixture %s: %v", rt.file, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			body = string(b)
			if rt.raw {
				body = `{"data":` + body + `}`
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

const readerTestToken = "PVEAPIToken=nos@pve!read=reader-test-value"

// readerBuilders are every supported way to construct a Client. Each must
// yield a client on which every read method works.
func readerBuilders() map[string]func(t *testing.T, srv *httptest.Server) *Client {
	tok := func(context.Context) (string, error) { return readerTestToken, nil }
	return map[string]func(t *testing.T, srv *httptest.Server) *Client{
		"NewClient": func(t *testing.T, srv *httptest.Server) *Client {
			c, err := NewClient(srv.Client(), srv.URL+apiRoot, tok)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			return c
		},
		"New": func(t *testing.T, srv *httptest.Server) *Client {
			c, err := New(srv.URL, srv.Client(), tok, WithTimeout(5*time.Second))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			return c
		},
		"NewBackupClient": func(t *testing.T, srv *httptest.Server) *Client {
			c, err := NewBackupClient(srv.URL+apiRoot, srv.Client(), func() string { return readerTestToken })
			if err != nil {
				t.Fatalf("NewBackupClient: %v", err)
			}
			return c
		},
		"exported fields": func(_ *testing.T, srv *httptest.Server) *Client {
			return &Client{HTTP: srv.Client(), BaseURL: srv.URL + apiRoot, Token: tok, Timeout: 5 * time.Second}
		},
	}
}

// availability turns a Dataset-style Available/Reason pair into an error.
func availability(ok bool, reason string) error {
	if !ok {
		return fmt.Errorf("unavailable: %s", reason)
	}
	return nil
}

// readerCalls invokes every exported read method of Client once with
// arguments that match readerRoutes and checks a little of each result.
func readerCalls() map[string]func(ctx context.Context, c *Client) error {
	return map[string]func(ctx context.Context, c *Client) error{
		"ListNodes": func(ctx context.Context, c *Client) error {
			n, err := c.ListNodes(ctx)
			if err == nil && len(n) != 3 {
				err = fmt.Errorf("nodes = %d", len(n))
			}
			return err
		},
		"ListQemu": func(ctx context.Context, c *Client) error {
			g, err := c.ListQemu(ctx, "pve1")
			if err == nil && len(g) != 2 {
				err = fmt.Errorf("qemu = %d", len(g))
			}
			return err
		},
		"ListLxc": func(ctx context.Context, c *Client) error {
			g, err := c.ListLxc(ctx, "pve1")
			if err == nil && len(g) != 1 {
				err = fmt.Errorf("lxc = %d", len(g))
			}
			return err
		},
		"EnumerateCluster": func(ctx context.Context, c *Client) error {
			_, err := c.EnumerateCluster(ctx)
			return err
		},
		"GetQemuConfig": func(ctx context.Context, c *Client) error {
			_, err := c.GetQemuConfig(ctx, "pve1", 100)
			return err
		},
		"GetLxcConfig": func(ctx context.Context, c *Client) error {
			_, err := c.GetLxcConfig(ctx, "pve1", 200)
			return err
		},
		"AgentNetworkInterfaces": func(ctx context.Context, c *Client) error {
			_, err := c.AgentNetworkInterfaces(ctx, "pve1", 100)
			return err
		},
		"AgentOSInfo": func(ctx context.Context, c *Client) error {
			_, err := c.AgentOSInfo(ctx, "pve1", 100)
			return err
		},
		"AgentFSInfo": func(ctx context.Context, c *Client) error {
			_, err := c.AgentFSInfo(ctx, "pve1", 100)
			return err
		},
		"AgentFileRead": func(ctx context.Context, c *Client) error {
			b, err := c.AgentFileRead(ctx, "pve1", 100, "/etc/hostname", 64)
			if err == nil && string(b) != "web1\n" {
				err = fmt.Errorf("content = %q", b)
			}
			return err
		},
		"ClusterStatus": func(ctx context.Context, c *Client) error {
			s, err := c.ClusterStatus(ctx)
			if err != nil {
				return err
			}
			return availability(s.Available, s.Reason)
		},
		"ClusterNodeVotes": func(ctx context.Context, c *Client) error {
			v, err := c.ClusterNodeVotes(ctx)
			if err != nil {
				return err
			}
			return availability(v.Available, v.Reason)
		},
		"HAStatus": func(ctx context.Context, c *Client) error {
			s, err := c.HAStatus(ctx)
			if err != nil {
				return err
			}
			return availability(s.Available, s.Reason)
		},
		"NodeTasks": func(ctx context.Context, c *Client) error {
			l, err := c.NodeTasks(ctx, "pve1", TaskFilter{Limit: 10})
			if err != nil {
				return err
			}
			return availability(l.Available, l.Reason)
		},
		"NodePCIDevices": func(ctx context.Context, c *Client) error {
			l, err := c.NodePCIDevices(ctx, "pve1")
			if err != nil {
				return err
			}
			return availability(l.Available, l.Reason)
		},
		"ListStorages": func(ctx context.Context, c *Client) error {
			_, err := c.ListStorages(ctx, "pve1")
			return err
		},
		"GetStorage": func(ctx context.Context, c *Client) error {
			_, err := c.GetStorage(ctx, "pve1", "local")
			return err
		},
		"ListSnapshots": func(ctx context.Context, c *Client) error {
			l, err := c.ListSnapshots(ctx, "pve1", "qemu", 100)
			if err == nil && len(l.Snapshots) != 2 {
				err = fmt.Errorf("snapshots = %d", len(l.Snapshots))
			}
			return err
		},
		"PlanSnapshotRollback": func(ctx context.Context, c *Client) error {
			_, err := c.PlanSnapshotRollback(ctx, GuestQEMU, "pve1", 100, "snap1", false)
			return err
		},
		"ReadBackups": func(ctx context.Context, c *Client) error {
			obs, err := c.ReadBackups(ctx, BackupsOptions{
				Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
				Scope:   ReadScope{FullContent: true},
			})
			if err != nil {
				return err
			}
			if !obs.Catalog.IsAvailable() || !obs.Jobs.IsAvailable() {
				return fmt.Errorf("catalog %s, jobs %s", obs.Catalog.State, obs.Jobs.State)
			}
			return nil
		},
	}
}

// TestEveryReadMethodWorksOnEveryConstructor is the regression test for
// the split between unexported (NewClient/New) and exported connection
// fields: ClusterStatus and HAStatus used to fail with "incomplete client"
// on a NewClient-built client, and other readers failed on the other
// constructors. Every read method must reach the fake PVE API under one
// /api2/json root, with GET and the read token, whatever constructor built
// the client.
func TestEveryReadMethodWorksOnEveryConstructor(t *testing.T) {
	for bname, build := range readerBuilders() {
		for mname, call := range readerCalls() {
			t.Run(bname+"/"+mname, func(t *testing.T) {
				f := newReaderFakePVE(t)
				if err := call(context.Background(), build(t, f.srv)); err != nil {
					t.Fatalf("%s: %v", mname, err)
				}
				reqs := f.requests()
				if len(reqs) == 0 {
					t.Fatal("no request reached the fake PVE API")
				}
				for _, r := range reqs {
					if r.Method != http.MethodGet {
						t.Errorf("%s %s: read used %s", mname, r.URL.Path, r.Method)
					}
					if !strings.HasPrefix(r.URL.Path, apiRoot+"/") || strings.HasPrefix(r.URL.Path, apiRoot+apiRoot) {
						t.Errorf("%s: path %q is not under a single %s root", mname, r.URL.Path, apiRoot)
					}
					if got := r.Header.Get("Authorization"); got != readerTestToken {
						t.Errorf("%s %s: Authorization = %q", mname, r.URL.Path, got)
					}
				}
			})
		}
	}
}

// TestReadMethodsNeverFollowRedirects checks that no read path forwards the
// token to a redirect destination, for every constructor, even when the
// injected http.Client would follow redirects.
func TestReadMethodsNeverFollowRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	for bname, build := range readerBuilders() {
		for mname, call := range readerCalls() {
			c := build(t, source)
			c.HTTP = &http.Client{} // the default client follows redirects
			if err := call(context.Background(), c); err == nil {
				t.Errorf("%s/%s: redirect answer accepted", bname, mname)
			}
			if n := targetHits.Load(); n != 0 {
				t.Fatalf("%s/%s: redirect target received %d requests", bname, mname, n)
			}
		}
	}
}

// TestZeroClientReturnsErrorNotPanic checks that a Client without a
// constructor or fields fails every read method with ErrIncompleteClient
// instead of panicking or sending a request.
func TestZeroClientReturnsErrorNotPanic(t *testing.T) {
	for mname, call := range readerCalls() {
		t.Run(mname, func(t *testing.T) {
			if err := call(context.Background(), &Client{}); !errors.Is(err, ErrIncompleteClient) {
				t.Fatalf("%s on zero Client: err = %v, want ErrIncompleteClient", mname, err)
			}
		})
	}
}

// TestGuestConfigReadsDefaultPendingView pins the documented decision for
// GET .../config: GetQemuConfig and GetLxcConfig read PVE's default view
// (pending changes applied) and never send current=1. See the Client doc
// comment for the reasoning.
func TestGuestConfigReadsDefaultPendingView(t *testing.T) {
	f := newReaderFakePVE(t)
	c := readerBuilders()["NewClient"](t, f.srv)
	if _, err := c.GetQemuConfig(context.Background(), "pve1", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetLxcConfig(context.Background(), "pve1", 200); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2", len(reqs))
	}
	for _, r := range reqs {
		if r.URL.RawQuery != "" {
			t.Errorf("%s: query %q, want none (default pending view)", r.URL.Path, r.URL.RawQuery)
		}
	}
}
