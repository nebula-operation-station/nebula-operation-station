// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the PVE remote pages and deep links (ADR 0006, P1-13). They
// cover the acceptance criteria: hostile names rendered as text, approved
// origins only get deep links, source/staleness labels, read-only access
// and the logged-out redirect.

package ui_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const pveOrigin = "https://nebula.example.org"

// pveTestEnv is a UI handler backed by a real pveinventory store on a
// temporary server DB.
type pveTestEnv struct {
	t       *testing.T
	srv     *httptest.Server
	store   *pveinventory.Store
	metas   []ui.PVERemoteMeta
	metaErr error
}

func newPVEEnv(t *testing.T, metas []ui.PVERemoteMeta, clocks ...func() time.Time) *pveTestEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	e := &pveTestEnv{t: t, store: pveinventory.New(db), metas: metas}
	var now func() time.Time
	if len(clocks) > 0 {
		now = clocks[0]
	}
	u, err := ui.New(ui.Options{
		PublicOrigin: pveOrigin,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		PVE:          e.store,
		PVERemotes:   e.remotes,
		Now:          now,
	})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	e.srv = httptest.NewServer(u.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

func (e *pveTestEnv) remotes(ctx context.Context) ([]ui.PVERemoteMeta, error) {
	if e.metaErr != nil {
		return nil, e.metaErr
	}
	return e.metas, nil
}

func (e *pveTestEnv) get(path string) (int, string) {
	e.t.Helper()
	res, err := http.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	return res.StatusCode, string(body)
}

func pvePin(c byte) string { return strings.Repeat(strings.ToLower(string(rune('a'+c))), 64) }

func seedRemote(t *testing.T, s *pveinventory.Store, r pvecontract.Remote) {
	t.Helper()
	if err := s.UpsertRemote(context.Background(), r); err != nil {
		t.Fatalf("UpsertRemote %s: %v", r.RemoteID, err)
	}
}

func seedObs(t *testing.T, s *pveinventory.Store, obs pvecontract.Observation) {
	t.Helper()
	if _, err := s.IngestObservation(context.Background(), obs); err != nil {
		t.Fatalf("IngestObservation %s: %v", obs.RemoteID, err)
	}
}

// newPVEObs assembles a minimal valid observation for remoteID observed at
// at; all datasets are unavailable unless the caller fills them in.
func newPVEObs(remoteID string, at time.Time) pvecontract.Observation {
	return pvecontract.Observation{
		RemoteID:             remoteID,
		ObservedAt:           at,
		Source:               "test-collector",
		CollectionGeneration: 1,
		Complete:             true,
		Nodes:                pvecontract.UnavailableDataset[[]pvecontract.NodeObservation]("not read"),
		Guests:               pvecontract.UnavailableDataset[[]pvecontract.GuestObservation]("not read"),
		Storages:             pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("not read"),
		Cluster:              pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("not read"),
		Tasks:                pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("not read"),
	}
}

func pveNodeObs(name string, status pvecontract.NodeStatus) pvecontract.NodeObservation {
	return pvecontract.NodeObservation{
		Node:          name,
		Status:        status,
		UptimeSeconds: 3600,
		CPUCount:      8,
		RAMTotalBytes: 32 << 30,
		RAMUsedBytes:  8 << 30,
		Details:       pvecontract.UnavailableDataset[pvecontract.NodeDetails]("not read"),
	}
}

func pveGuestObs(vmid uint64, kind pvecontract.GuestKind, node, name string, status pvecontract.GuestStatus) pvecontract.GuestObservation {
	return pvecontract.GuestObservation{
		VMID:       vmid,
		Kind:       kind,
		Node:       node,
		Name:       name,
		Status:     status,
		Generation: 1,
		Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
		Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("not read"),
		Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
		Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
		Backups:    pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("not read"),
	}
}

func TestPVEListPageShowsStoredRemotes(t *testing.T) {
	now := time.Now()
	e := newPVEEnv(t, []ui.PVERemoteMeta{
		{
			RemoteID: "remote-fresh", Name: "Lab cluster", Kind: string(pvecontract.KindCluster),
			Endpoints: []ui.PVEEndpoint{{Host: "pve1.lab", Port: 8006}},
			TrustPin:  pvePin(0), TrustGeneration: 1, State: "active",
		},
		{
			RemoteID: "remote-stale", Name: "Standalone one", Kind: string(pvecontract.KindStandalone),
			Endpoints: []ui.PVEEndpoint{{Host: "192.168.0.10", Port: 8006}},
			TrustPin:  pvePin(1), TrustGeneration: 2, State: "active",
		},
	})
	seedRemote(t, e.store, pvecontract.Remote{
		RemoteID: "remote-fresh", Name: "Lab cluster", Kind: pvecontract.KindCluster,
		Endpoints: []pvecontract.Endpoint{{Host: "pve1.lab", Port: 8006}},
		TrustPin:  pvePin(0), TrustGeneration: 1,
	})
	seedRemote(t, e.store, pvecontract.Remote{
		RemoteID: "remote-stale", Name: "Standalone one", Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "192.168.0.10", Port: 8006}},
		TrustPin:  pvePin(1), TrustGeneration: 2,
	})
	fresh := newPVEObs("remote-fresh", now.Add(-time.Minute))
	fresh.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("pve1.lab", pvecontract.NodeOnline)})
	seedObs(t, e.store, fresh)
	// The stale remote's last observation predates three poll intervals.
	stale := newPVEObs("remote-stale", now.Add(-time.Hour))
	stale.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("proxmox1", pvecontract.NodeOnline)})
	seedObs(t, e.store, stale)

	code, body := e.get("/pve")
	if code != http.StatusOK {
		t.Fatalf("GET /pve = %d, want 200\n%s", code, body)
	}
	for _, want := range []string{
		">Lab cluster<", ">Standalone one<",
		"cluster", "standalone",
		`href="https://pve1.lab:8006/"`,
		`href="https://192.168.0.10:8006/"`,
		pvePin(0), pvePin(1),
		"test-collector",
		`href="/pve"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list page missing %q", want)
		}
	}
	if got := strings.Count(body, ">stale<"); got != 1 {
		t.Errorf("list page has %d stale labels, want 1", got)
	}
}

func TestPVEListPageHostileNamesAreText(t *testing.T) {
	now := time.Now()
	hostileName := `"><script>alert(1)</script> https://evil.example`
	e := newPVEEnv(t, []ui.PVERemoteMeta{
		{
			RemoteID: "remote-a", Name: hostileName, Kind: string(pvecontract.KindStandalone),
			Endpoints: []ui.PVEEndpoint{{Host: "pve-a", Port: 8006}},
			TrustPin:  pvePin(0), TrustGeneration: 1, State: "active",
		},
	})
	seedRemote(t, e.store, pvecontract.Remote{
		RemoteID: "remote-a", Name: hostileName, Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "pve-a", Port: 8006}},
		TrustPin:  pvePin(0), TrustGeneration: 1,
	})
	obs := newPVEObs("remote-a", now)
	obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("pve-a", pvecontract.NodeOnline)})
	obs.Guests = pvecontract.AvailableDataset([]pvecontract.GuestObservation{
		pveGuestObs(100, pvecontract.GuestQEMU, "pve-a", `<img src=x onerror=alert(1)>`, pvecontract.GuestRunning),
	})
	seedObs(t, e.store, obs)

	code, body := e.get("/pve")
	if code != http.StatusOK {
		t.Fatalf("GET /pve = %d, want 200", code)
	}
	if strings.Contains(body, `<script>alert(1)`) {
		t.Error("hostile remote name rendered as live script")
	}
	if !strings.Contains(body, `&lt;script&gt;alert(1)&lt;/script&gt;`) {
		t.Error("hostile remote name not rendered as escaped text")
	}
	if strings.Contains(body, `href="https://evil.example`) || strings.Contains(body, `">https://evil.example`) {
		t.Error("hostile name produced a link to an unapproved origin")
	}

	code, body = e.get("/pve/remote-a")
	if code != http.StatusOK {
		t.Fatalf("GET /pve/remote-a = %d, want 200", code)
	}
	if strings.Contains(body, `<img`) {
		t.Error("hostile guest name rendered as live markup")
	}
	if !strings.Contains(body, `&lt;img src=x onerror=alert(1)&gt;`) {
		t.Error("hostile guest name not rendered as escaped text")
	}
}

func TestPVEListPageUnapprovedOriginGetsNoLink(t *testing.T) {
	now := time.Now()
	// Four remotes: no endpoints, malformed host, port zero, and one the
	// registry does not know at all. None of them may get a deep link.
	e := newPVEEnv(t, []ui.PVERemoteMeta{
		{RemoteID: "remote-a", Name: "No endpoints", Kind: string(pvecontract.KindStandalone),
			TrustPin: pvePin(0), TrustGeneration: 1, State: "active"},
		{RemoteID: "remote-b", Name: "Bad host", Kind: string(pvecontract.KindStandalone),
			Endpoints: []ui.PVEEndpoint{{Host: "bad host", Port: 8006}},
			TrustPin:  pvePin(1), TrustGeneration: 1, State: "active"},
		{RemoteID: "remote-c", Name: "Bad port", Kind: string(pvecontract.KindStandalone),
			Endpoints: []ui.PVEEndpoint{{Host: "pve-c", Port: 0}},
			TrustPin:  pvePin(2), TrustGeneration: 1, State: "active"},
	})
	for _, id := range []string{"remote-a", "remote-b", "remote-c", "remote-d"} {
		seedRemote(t, e.store, pvecontract.Remote{
			RemoteID: id, Name: id, Kind: pvecontract.KindStandalone,
			Endpoints: []pvecontract.Endpoint{{Host: "pve-x", Port: 8006}},
			TrustPin:  pvePin(3), TrustGeneration: 1,
		})
		obs := newPVEObs(id, now)
		obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("pve-x", pvecontract.NodeOnline)})
		seedObs(t, e.store, obs)
	}

	code, body := e.get("/pve")
	if code != http.StatusOK {
		t.Fatalf("GET /pve = %d, want 200", code)
	}
	for _, name := range []string{">No endpoints<", ">Bad host<", ">Bad port<", ">remote-d<"} {
		if !strings.Contains(body, name) {
			t.Errorf("list page missing remote %q", name)
		}
	}
	if strings.Contains(body, `href="https://`) {
		t.Errorf("unapproved origin produced a deep link:\n%s", body)
	}
}

func TestPVEDetailPageShowsNodesAndGuests(t *testing.T) {
	now := time.Now()
	e := newPVEEnv(t, []ui.PVERemoteMeta{
		{
			RemoteID: "remote-a", Name: "Lab cluster", Kind: string(pvecontract.KindCluster),
			Endpoints: []ui.PVEEndpoint{{Host: "pve1.lab", Port: 8006}, {Host: "pve2.lab", Port: 8006}},
			TrustPin:  pvePin(0), TrustGeneration: 1, State: "active",
		},
	})
	seedRemote(t, e.store, pvecontract.Remote{
		RemoteID: "remote-a", Name: "Lab cluster", Kind: pvecontract.KindCluster,
		Endpoints: []pvecontract.Endpoint{{Host: "pve1.lab", Port: 8006}, {Host: "pve2.lab", Port: 8006}},
		TrustPin:  pvePin(0), TrustGeneration: 1,
	})
	obs := newPVEObs("remote-a", now)
	// pve3.lab has no approved endpoint: it must not get a link.
	obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{
		pveNodeObs("pve1.lab", pvecontract.NodeOnline),
		pveNodeObs("pve2.lab", pvecontract.NodeOnline),
		pveNodeObs("pve3.lab", pvecontract.NodeOffline),
	})
	obs.Guests = pvecontract.AvailableDataset([]pvecontract.GuestObservation{
		pveGuestObs(101, pvecontract.GuestQEMU, "pve1.lab", "web-1", pvecontract.GuestRunning),
		pveGuestObs(200, pvecontract.GuestLXC, "pve2.lab", "c-1", pvecontract.GuestStopped),
		pveGuestObs(300, pvecontract.GuestQEMU, "pve3.lab", "nolink", pvecontract.GuestRunning),
	})
	seedObs(t, e.store, obs)

	code, body := e.get("/pve/remote-a")
	if code != http.StatusOK {
		t.Fatalf("GET /pve/remote-a = %d, want 200\n%s", code, body)
	}
	for _, want := range []string{
		">web-1<", ">c-1<", ">nolink<",
		">101<", ">200<", ">300<",
		"running", "stopped",
		`href="https://pve1.lab:8006/#v1:0:=qemu%2F101:4:::::::"`,
		`href="https://pve2.lab:8006/#v1:0:=lxc%2F200:4:::::::"`,
		`href="https://pve1.lab:8006/#v1:0:=node%2Fpve1.lab:4:::::::"`,
		// Dataset status table.
		">nodes<", ">guests<",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page missing %q", want)
		}
	}
	if strings.Contains(body, "node%2Fpve3.lab") || strings.Contains(body, "qemu%2F300") {
		t.Errorf("node without an approved endpoint got a deep link:\n%s", body)
	}
}

func TestPVEDetailPageStaleAndUnknownLabels(t *testing.T) {
	now := time.Now()
	e := newPVEEnv(t, nil, func() time.Time { return now })
	obsAt := map[string]time.Time{
		"remote-fresh": now.Add(-time.Minute),
		"remote-stale": now.Add(-4 * time.Minute),
	}
	for id, at := range obsAt {
		seedRemote(t, e.store, pvecontract.Remote{
			RemoteID: id, Name: id, Kind: pvecontract.KindStandalone,
			Endpoints: []pvecontract.Endpoint{{Host: "pve-x", Port: 8006}},
			TrustPin:  pvePin(0), TrustGeneration: 1,
		})
		obs := newPVEObs(id, at)
		obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("pve-x", pvecontract.NodeOnline)})
		seedObs(t, e.store, obs)
	}
	// Never observed: upserted, but no observation ever arrived.
	seedRemote(t, e.store, pvecontract.Remote{
		RemoteID: "remote-never", Name: "remote-never", Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "pve-x", Port: 8006}},
		TrustPin:  pvePin(0), TrustGeneration: 1,
	})

	code, body := e.get("/pve")
	if code != http.StatusOK {
		t.Fatalf("GET /pve = %d, want 200", code)
	}
	if got := strings.Count(body, ">stale<"); got != 1 {
		t.Errorf("list page has %d stale labels, want 1", got)
	}
	if got := strings.Count(body, ">unknown<"); got != 1 {
		t.Errorf("list page has %d unknown labels, want 1", got)
	}
	code, body = e.get("/pve/remote-stale")
	if code != http.StatusOK || strings.Count(body, ">stale<") != 2 {
		t.Errorf("four-minute-old remote and node must be stale: status=%d body=%s", code, body)
	}
}

func TestPVEDetailPageUnknownRemoteIs404(t *testing.T) {
	e := newPVEEnv(t, nil)
	for _, path := range []string{"/pve/remote-missing", "/pve/not%20a%20slug"} {
		code, _ := e.get(path)
		if code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
	}
}

func TestPVEPagesHiddenWithoutStore(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	defer db.Close()
	u, err := ui.New(ui.Options{
		PublicOrigin: pveOrigin,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	srv := httptest.NewServer(u.Handler())
	defer srv.Close()
	for _, path := range []string{"/pve", "/pve/remote-a"} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 without a PVE store", path, res.StatusCode)
		}
	}
}

func TestPVEPagesHaveNoInlineScriptOrStyle(t *testing.T) {
	now := time.Now()
	e := newPVEEnv(t, []ui.PVERemoteMeta{
		{
			RemoteID: "remote-a", Name: "Lab cluster", Kind: string(pvecontract.KindCluster),
			Endpoints: []ui.PVEEndpoint{{Host: "pve1.lab", Port: 8006}},
			TrustPin:  pvePin(0), TrustGeneration: 1, State: "active",
		},
	})
	seedRemote(t, e.store, pvecontract.Remote{
		RemoteID: "remote-a", Name: "Lab cluster", Kind: pvecontract.KindCluster,
		Endpoints: []pvecontract.Endpoint{{Host: "pve1.lab", Port: 8006}},
		TrustPin:  pvePin(0), TrustGeneration: 1,
	})
	obs := newPVEObs("remote-a", now)
	obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("pve1.lab", pvecontract.NodeOnline)})
	obs.Guests = pvecontract.AvailableDataset([]pvecontract.GuestObservation{
		pveGuestObs(101, pvecontract.GuestQEMU, "pve1.lab", "web-1", pvecontract.GuestRunning),
	})
	seedObs(t, e.store, obs)

	for _, path := range []string{"/pve", "/pve/remote-a"} {
		code, body := e.get(path)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, code)
		}
		// The layout loads exactly three scripts (htmx, time, nav); the
		// PVE pages must not add a second chart script or any other one.
		if got := strings.Count(body, "<script"); got != 3 {
			t.Errorf("%s loads %d scripts, want 3", path, got)
		}
		for _, bad := range []string{
			"<script>", "<style", "style=", " onclick=", " onerror=", " onload=", "javascript:",
		} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
	}
}

func TestPVEListPageMetaErrorStillRendersWithoutLinks(t *testing.T) {
	now := time.Now()
	e := newPVEEnv(t, nil)
	e.metaErr = errors.New("executor unavailable")
	seedRemote(t, e.store, pvecontract.Remote{
		RemoteID: "remote-a", Name: "Lab cluster", Kind: pvecontract.KindCluster,
		Endpoints: []pvecontract.Endpoint{{Host: "pve1.lab", Port: 8006}},
		TrustPin:  pvePin(0), TrustGeneration: 1,
	})
	obs := newPVEObs("remote-a", now)
	obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("pve1.lab", pvecontract.NodeOnline)})
	seedObs(t, e.store, obs)

	code, body := e.get("/pve")
	if code != http.StatusOK {
		t.Fatalf("GET /pve = %d, want 200", code)
	}
	if !strings.Contains(body, ">Lab cluster<") {
		t.Error("list page does not show the stored remote")
	}
	if strings.Contains(body, `href="https://`) {
		t.Error("deep links rendered although the registry is unavailable")
	}
}

// pveFakeExec is an auth.Executor stub for the logged-out redirect test.
type pveFakeExec struct{}

func (pveFakeExec) BeginLogin(context.Context, *pb.BeginLoginRequest, ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) FinishLogin(context.Context, *pb.FinishLoginRequest, ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) BeginRegistration(context.Context, *pb.BeginRegistrationRequest, ...grpc.CallOption) (*pb.BeginRegistrationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) FinishRegistration(context.Context, *pb.FinishRegistrationRequest, ...grpc.CallOption) (*pb.FinishRegistrationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) BeginPrivilegedSession(context.Context, *pb.BeginPrivilegedSessionRequest, ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) CompletePrivilegedSession(context.Context, *pb.CompletePrivilegedSessionRequest, ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) Lock(context.Context, *pb.LockRequest, ...grpc.CallOption) (*pb.LockResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) CheckCredential(context.Context, *pb.CheckCredentialRequest, ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}
func (pveFakeExec) RecoveryLogin(context.Context, *pb.RecoveryLoginRequest, ...grpc.CallOption) (*pb.RecoveryLoginResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not needed")
}

func TestPVEPageRedirectsWhenLoggedOut(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	defer db.Close()
	store := pveinventory.New(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, err := ui.New(ui.Options{
		PublicOrigin: pveOrigin,
		Log:          log,
		PVE:          store,
		PVERemotes:   func(context.Context) ([]ui.PVERemoteMeta, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	sessions := auth.NewStore(db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	srv := httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: pveOrigin}, a.Wrap(u.Handler())))
	defer srv.Close()

	// The default client would follow the 303 to /login (200); inspect
	// the redirect itself.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Get(srv.URL + "/pve")
	if err != nil {
		t.Fatalf("GET /pve: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther && res.StatusCode != http.StatusFound {
		t.Fatalf("GET /pve logged out = %d, want redirect", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/login" {
		t.Errorf("redirect Location = %q, want /login", loc)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/pve", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", pveOrigin)
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /pve: %v", err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /pve logged out = %d, want 401", res2.StatusCode)
	}
}

func TestPVERetainedVersionsHaveIndependentFreshness(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		age         time.Duration
		unavailable bool
		label       string
	}{
		{"available", 10 * time.Minute, false, ""},
		{"stale", time.Hour, false, "stale"},
		{"retained unavailable", time.Hour, true, "unavailable"},
		{"never observed", 0, true, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPVEEnv(t, nil, func() time.Time { return now })
			seedRemote(t, e.store, pvecontract.Remote{RemoteID: "remote-a", Name: "Lab", Kind: pvecontract.KindStandalone, Endpoints: []pvecontract.Endpoint{{Host: "pve.lab", Port: 8006}}, TrustPin: pvePin(0), TrustGeneration: 1})
			n := pveNodeObs("pve.lab", pvecontract.NodeOnline)
			if tc.age > 0 {
				n.Details = pvecontract.AvailableDataset(pvecontract.NodeDetails{PVEVersion: "9.0.1", KernelVersion: "6.8.0"})
				old := newPVEObs("remote-a", now.Add(-tc.age))
				old.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{n})
				seedObs(t, e.store, old)
			}
			if tc.unavailable {
				n.Details = pvecontract.UnavailableDataset[pvecontract.NodeDetails]("details denied")
			}
			fresh := newPVEObs("remote-a", now)
			// A fresh inventory must not refresh retained detail values.
			if tc.unavailable {
				fresh.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{n})
				seedObs(t, e.store, fresh)
			}
			code, body := e.get("/pve/remote-a")
			if code != 200 {
				t.Fatalf("status %d", code)
			}
			for _, version := range []string{"9.0.1", "6.8.0"} {
				if tc.age == 0 {
					version = "—"
				}
				start := strings.Index(body, "<td>"+version)
				if start < 0 {
					t.Fatalf("missing version %q", version)
				}
				cell := body[start:]
				cell = cell[:strings.Index(cell, "</td>")]
				if tc.label == "" && strings.Contains(cell, "badge--warning") {
					t.Errorf("available details falsely labelled: %s", cell)
				}
				if tc.label != "" && !strings.Contains(cell, ">"+tc.label+"<") {
					t.Errorf("version cell lacks %s: %s", tc.label, cell)
				}
				if tc.age > 0 && !strings.Contains(cell, pveExpectedAge(tc.age)) {
					t.Errorf("missing detail age: %s", cell)
				}
			}
		})
	}
}
func pveExpectedAge(age time.Duration) string {
	if age >= time.Hour {
		return "1h ago"
	}
	return "10m ago"
}
