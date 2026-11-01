// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	pveReadToken   = "nosread@pve!read=s3cr3t-token-value"
	pveReadGrantID = "00000000-0000-4000-8000-0000000000e8"
	pveReadRemote  = "lab"
)

// fakePVE is a pinned TLS PVE API that serves fixed JSON bodies and counts
// authenticated requests.
type fakePVE struct {
	srv      *httptest.Server
	host     string
	port     uint16
	mu       sync.Mutex
	bodies   map[string]string
	requests atomic.Int64
	badAuth  atomic.Int64
	// before runs before each response (lock/revoke while in flight).
	before func()
}

func defaultPVEBodies() map[string]string {
	return map[string]string{
		"/api2/json/nodes":                     `{"data":[{"node":"pve1","status":"online","type":"node","maxcpu":8,"maxmem":1000,"mem":400,"uptime":99}]}`,
		"/api2/json/nodes/pve1/qemu":           `{"data":[{"vmid":100,"name":"web","status":"running","uuid":"0F8FAD5B-D9CB-469F-A165-70867728950E"}]}`,
		"/api2/json/nodes/pve1/lxc":            `{"data":[{"vmid":200,"name":"dns","status":"stopped"}]}`,
		"/api2/json/nodes/pve1/storage":        `{"data":[{"storage":"local","type":"dir","content":"iso,backup,rootdir,import","active":1,"shared":0,"used":100,"total":1000}]}`,
		"/api2/json/cluster/status":            `{"data":[{"type":"cluster","id":"cluster","name":"lab","nodes":1,"quorate":1},{"type":"node","id":"node/pve1","name":"pve1","online":1}]}`,
		"/api2/json/cluster/ha/resources":      `{"data":[{"sid":"vm:100","type":"vm","state":"started"}]}`,
		"/api2/json/cluster/ha/status/current": `{"data":[{"id":"service:vm:100","type":"service","sid":"vm:100","state":"started","node":"pve1"}]}`,
	}
}

func newFakePVE(t *testing.T, cert tls.Certificate) *fakePVE {
	t.Helper()
	f := &fakePVE{bodies: defaultPVEBodies()}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken="+pveReadToken {
			f.badAuth.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.requests.Add(1)
		f.mu.Lock()
		body, ok := f.bodies[r.URL.Path]
		before := f.before
		f.mu.Unlock()
		if before != nil {
			before()
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
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

func (f *fakePVE) set(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[path] = body
}

type pveReadEnv struct {
	*reconcileEnv
	chain testChain
	pve   *fakePVE
}

// newPveReadEnv registers one remote of kind with the fake PVE endpoint,
// stores its read token in the unlocked vault and enables read dispatch.
func newPveReadEnv(t *testing.T, kind pvecontract.Kind) *pveReadEnv {
	t.Helper()
	e := newReconcileEnv(t)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth, err = permit.New(permit.Options{Verifier: v, Store: e.db, RiskPolicy: risk, Leases: e.db, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	e.svc.SetVaultParams(vault.MinParams)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Init(pass, vault.MinParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	chain := makeTestChain(t)
	pve := newFakePVE(t, chain.tls)
	ref := PveVaultID(pveReadRemote, PvePurposeRead)
	version, err := e.svc.vault.Put(ref, []byte(pveReadToken), "test")
	if err != nil {
		t.Fatal(err)
	}
	pin := fpHex(chain.leaf)
	if kind == pvecontract.KindCluster {
		pin = fpHex(chain.ca)
	}
	if _, err := e.db.AddRemote(pvecontract.Remote{RemoteID: pveReadRemote, Name: "Lab", Kind: kind,
		Endpoints: []pvecontract.Endpoint{{Host: pve.host, Port: pve.port}}, TrustPin: pin, TrustGeneration: 1},
		executordb.PveRemoteCredentials{ReadRef: ref, ReadVersion: version}, "test"); err != nil {
		t.Fatal(err)
	}
	return &pveReadEnv{reconcileEnv: e, chain: chain, pve: pve}
}

func (e *pveReadEnv) remote() executordb.PveRemote {
	e.t.Helper()
	rm, ok, err := e.db.GetRemote(pveReadRemote)
	if err != nil || !ok {
		e.t.Fatalf("remote: %v %v", ok, err)
	}
	return rm
}

func (e *pveReadEnv) grantDoc(id string, budget int64, methods ...string) []byte {
	e.t.Helper()
	rm := e.remote()
	now := e.clock.Now()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: id, Issuer: "root", CreatedUnix: now.Unix(),
		ExpiryUnix: now.Add(permit.DefaultReadGrantLifetime).Unix(), Trigger: permit.TriggerScheduled,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: 60, RunBudget: budget, RateProfile: permit.ProviderReadProfile,
		ProviderTargets: []permit.ProviderTarget{{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, TrustGeneration: rm.TrustGeneration,
			CredentialVersion: rm.Credentials.ReadVersion, Methods: methods}},
	}
	raw, err := json.Marshal(d)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// approve proposes the grant over the RPC (registry checks included) and
// approves it on the CLI path.
func (e *pveReadEnv) approve(raw []byte) {
	e.t.Helper()
	ctx := context.Background()
	p, err := e.svc.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	if _, err := e.svc.auth.ApproveReadGrantCLI(p.GetGrantDigest(), "test"); err != nil {
		e.t.Fatalf("approve: %v", err)
	}
}

func (e *pveReadEnv) read(method pb.PVEReadMethod) (*pb.ReadPVEResponse, error) {
	return e.svc.ReadPVE(context.Background(), &pb.ReadPVERequest{RemoteId: pveReadRemote, Method: method})
}

func allPveMethods() []string {
	return []string{permit.ProviderMethodNodes, permit.ProviderMethodGuests, permit.ProviderMethodStorage, permit.ProviderMethodCluster}
}

func wantPveCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("code = %v, want %v: %v", status.Code(err), code, err)
	}
	if err != nil && strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("token in error: %v", err)
	}
}

func TestReadPVEReturnsTypedDataUnderProviderGrant(t *testing.T) {
	for _, kind := range []pvecontract.Kind{pvecontract.KindStandalone, pvecontract.KindCluster} {
		t.Run(string(kind), func(t *testing.T) {
			e := newPveReadEnv(t, kind)
			e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))

			got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES)
			if err != nil {
				t.Fatal(err)
			}
			n := got.GetNodes()
			if n.GetState() != pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE || len(n.GetNodes()) != 1 {
				t.Fatalf("nodes = %v", n)
			}
			if nd := n.GetNodes()[0]; nd.GetNode() != "pve1" || nd.GetStatus() != "online" || nd.GetCpuCount() != 8 ||
				nd.GetRamTotalBytes() != 1000 || nd.GetRamUsedBytes() != 400 || nd.GetUptimeSeconds() != 99 {
				t.Fatalf("node = %v", nd)
			}

			got, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_GUESTS)
			if err != nil {
				t.Fatal(err)
			}
			if g := got.GetGuests(); g.GetState() != pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE || len(g.GetGuests()) != 2 ||
				g.GetGuests()[0].GetUuid() != "0f8fad5b-d9cb-469f-a165-70867728950e" || g.GetGuests()[1].GetKind() != "lxc" {
				t.Fatalf("guests = %v", g)
			}

			got, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_STORAGE)
			if err != nil {
				t.Fatal(err)
			}
			s := got.GetStorages()
			if s.GetState() != pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE || len(s.GetStorages()) != 1 {
				t.Fatalf("storages = %v", s)
			}
			if st := s.GetStorages()[0]; st.GetName() != "local" || st.GetSizeBytes() != 1000 || st.GetFreeBytes() != 900 ||
				strings.Join(st.GetContent(), ",") != "iso,backup,container" {
				t.Fatalf("storage = %v", st)
			}

			got, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER)
			if err != nil {
				t.Fatal(err)
			}
			c := got.GetCluster()
			if c.GetState() != pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE || c.GetQuorum() != "quorate" || len(c.GetNodes()) != 1 ||
				len(c.GetHaResources()) != 1 || c.GetHaResources()[0].GetId() != "vm-100" || c.GetHaResources()[0].GetObserved() != "started" {
				t.Fatalf("cluster = %v", c)
			}
			if e.pve.badAuth.Load() != 0 {
				t.Fatal("a request carried the wrong credential")
			}
			if strings.Contains(fmt.Sprint(e.logs.records), "s3cr3t") {
				t.Fatal("token value reached the log")
			}
		})
	}
}

func TestReadPVEDeniedWithoutCoveringGrant(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	_, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES)
	wantPveCode(t, err, codes.PermissionDenied)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
	_, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_GUESTS)
	wantPveCode(t, err, codes.PermissionDenied)
	if e.pve.requests.Load() != 0 {
		t.Fatalf("%d requests reached PVE without authority", e.pve.requests.Load())
	}
	// Methods without a mapping yet stay Unimplemented; the collector role
	// cannot reach anything else.
	_, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_METRICS)
	wantPveCode(t, err, codes.Unimplemented)
	_, err = e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
	wantPveCode(t, err, codes.Unimplemented)
}

func TestReadPVEEnforcesIntervalAndBudget(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 2, permit.ProviderMethodNodes, permit.ProviderMethodGuests))
	if _, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES); err != nil {
		t.Fatal(err)
	}
	before := e.pve.requests.Load()
	_, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES)
	wantPveCode(t, err, codes.ResourceExhausted)
	if _, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_GUESTS); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(2 * time.Minute)
	_, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES)
	wantPveCode(t, err, codes.ResourceExhausted)
	if got := e.pve.requests.Load(); got != before+3 { // guests: nodes + qemu + lxc
		t.Fatalf("requests = %d, want %d: a denied read reached PVE", got, before+3)
	}
}

func TestReadPVERefusesChangedRemoteState(t *testing.T) {
	cases := map[string]struct {
		mutate func(e *pveReadEnv)
		code   codes.Code
	}{
		"blocked": {func(e *pveReadEnv) {
			if _, err := e.db.BlockRemote(pveReadRemote, "test", "test"); err != nil {
				t.Fatal(err)
			}
		}, codes.FailedPrecondition},
		"removed": {func(e *pveReadEnv) {
			if _, err := e.db.BlockRemote(pveReadRemote, "test", "test"); err != nil {
				t.Fatal(err)
			}
			if _, err := e.db.RemoveRemote(pveReadRemote, "test"); err != nil {
				t.Fatal(err)
			}
		}, codes.NotFound},
		"credential rotated": {func(e *pveReadEnv) {
			rm := e.remote()
			v, err := e.svc.vault.Put(rm.Credentials.ReadRef, []byte(pveReadToken), "test")
			if err != nil {
				t.Fatal(err)
			}
			rm.Credentials.ReadVersion = v
			if _, err := e.db.SetRemoteCredentials(pveReadRemote, rm.Credentials, "test"); err != nil {
				t.Fatal(err)
			}
		}, codes.PermissionDenied},
		"vault secret replaced behind the registry": {func(e *pveReadEnv) {
			if _, err := e.svc.vault.Put(e.remote().Credentials.ReadRef, []byte(pveReadToken), "test"); err != nil {
				t.Fatal(err)
			}
		}, codes.FailedPrecondition},
		"vault locked":    {func(e *pveReadEnv) { e.svc.vault.Lock() }, codes.FailedPrecondition},
		"executor locked": {func(e *pveReadEnv) { e.svc.auth.Lock("test") }, codes.PermissionDenied},
		"grant revoked": {func(e *pveReadEnv) {
			if err := e.svc.auth.RevokeReadGrant(pveReadGrantID, "test"); err != nil {
				t.Fatal(err)
			}
		}, codes.PermissionDenied},
		"grant expired": {func(e *pveReadEnv) { e.clock.Add(permit.DefaultReadGrantLifetime) }, codes.PermissionDenied},
		"recovery pending": {func(e *pveReadEnv) {
			if err := e.db.SetRecoveryPending(); err != nil {
				t.Fatal(err)
			}
		}, codes.FailedPrecondition},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindStandalone)
			e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
			tc.mutate(e)
			_, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES)
			wantPveCode(t, err, tc.code)
			if e.pve.requests.Load() != 0 {
				t.Fatal("refused read reached PVE")
			}
		})
	}
}

// A lock or revocation while the request is in flight discards the result.
func TestReadPVEDiscardsResultInvalidatedInFlight(t *testing.T) {
	for name, act := range map[string]func(e *pveReadEnv){
		"lock":   func(e *pveReadEnv) { e.svc.auth.Lock("test") },
		"revoke": func(e *pveReadEnv) { _ = e.svc.auth.RevokeReadGrant(pveReadGrantID, "test") },
	} {
		t.Run(name, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindStandalone)
			e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
			var once sync.Once
			e.pve.before = func() { once.Do(func() { act(e) }) }
			got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES)
			if err == nil || got != nil {
				t.Fatalf("result survived %s: %v", name, got)
			}
			wantPveCode(t, err, codes.PermissionDenied)
		})
	}
}

// A changed trust identity blocks the remote persistently and revokes its
// provider grants; the token is never sent to the impostor.
func TestReadPVETrustChangeBlocksRemote(t *testing.T) {
	for _, kind := range []pvecontract.Kind{pvecontract.KindStandalone, pvecontract.KindCluster} {
		t.Run(string(kind), func(t *testing.T) {
			e := newPveReadEnv(t, kind)
			e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes, permit.ProviderMethodGuests))
			// Same address, different certificate chain.
			impostor := makeTestChain(t)
			e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
			e.pve.srv.CloseClientConnections()
			_, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES)
			wantPveCode(t, err, codes.FailedPrecondition)
			if e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
				t.Fatal("a request reached the impostor")
			}
			if rm := e.remote(); rm.State != executordb.StateBlocked {
				t.Fatalf("remote state = %s, want blocked", rm.State)
			}
			grants, err := e.svc.auth.ReadGrants()
			if err != nil || len(grants) != 1 || grants[0].RevokedAt.IsZero() {
				t.Fatalf("provider grant not revoked: %v %v", grants, err)
			}
			e.pve.srv.TLS.Certificates = []tls.Certificate{e.chain.tls}
			_, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_GUESTS)
			wantPveCode(t, err, codes.FailedPrecondition)
		})
	}
}

// Hostile or malformed PVE values become an unavailable dataset with a
// fixed reason; nothing from the response is echoed.
func TestReadPVERejectsHostileValues(t *testing.T) {
	cases := map[string]struct {
		path, body string
		method     pb.PVEReadMethod
	}{
		"node with zero cpus":   {"/api2/json/nodes", `{"data":[{"node":"pve1","status":"online","maxcpu":0,"maxmem":1,"mem":0}]}`, pb.PVEReadMethod_PVE_READ_METHOD_NODES},
		"node used above total": {"/api2/json/nodes", `{"data":[{"node":"pve1","status":"online","maxcpu":2,"maxmem":1,"mem":5}]}`, pb.PVEReadMethod_PVE_READ_METHOD_NODES},
		"uppercase node name":   {"/api2/json/nodes", `{"data":[{"node":"PVE1<script>","status":"online","maxcpu":2}]}`, pb.PVEReadMethod_PVE_READ_METHOD_NODES},
		"guest list unreadable": {"/api2/json/nodes/pve1/lxc", `{"data":"<script>"}`, pb.PVEReadMethod_PVE_READ_METHOD_GUESTS},
		"storage bad type":      {"/api2/json/nodes/pve1/storage", `{"data":[{"storage":"local","type":"Dir!","content":"iso","active":1,"shared":0}]}`, pb.PVEReadMethod_PVE_READ_METHOD_STORAGE},
		"cluster bad member":    {"/api2/json/cluster/status", `{"data":[{"type":"cluster","id":"c","name":"lab","nodes":1,"quorate":1},{"type":"node","id":"n","name":"../etc","online":1}]}`, pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindStandalone)
			e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))
			e.pve.set(tc.path, tc.body)
			got, err := e.read(tc.method)
			if err != nil {
				t.Fatal(err)
			}
			text := got.String()
			if strings.Contains(text, "<script>") || strings.Contains(text, "../etc") {
				t.Fatalf("hostile value passed: %s", text)
			}
			var st pb.PVEDatasetState
			switch tc.method {
			case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
				st = got.GetNodes().GetState()
			case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
				st = got.GetGuests().GetState()
			case pb.PVEReadMethod_PVE_READ_METHOD_STORAGE:
				st = got.GetStorages().GetState()
			case pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER:
				st = got.GetCluster().GetState()
			}
			if st != pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE {
				t.Fatalf("state = %v, want unavailable", st)
			}
		})
	}
}

// Overlong labels are bounded, never passed through.
func TestReadPVEBoundsGuestLabels(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodGuests))
	e.pve.set("/api2/json/nodes/pve1/qemu", `{"data":[{"vmid":100,"name":"`+strings.Repeat("x", 300)+`","status":"running"}]}`)
	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_GUESTS)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range got.GetGuests().GetGuests() {
		if len(g.GetName()) > pvecontract.MaxLabelBytes {
			t.Fatalf("guest name of %d bytes passed", len(g.GetName()))
		}
	}
}

// The executor refuses to propose a provider grant for a remote whose
// registry identity differs from the document.
func TestProposeProviderGrantChecksRegistry(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	var d permit.ReadGrantDoc
	if err := json.Unmarshal(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes), &d); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*permit.ProviderTarget){
		"unknown remote":   func(p *permit.ProviderTarget) { p.RemoteID = "other" },
		"stale pin":        func(p *permit.ProviderTarget) { p.TrustPin = strings.Repeat("a", 64) },
		"stale generation": func(p *permit.ProviderTarget) { p.TrustGeneration = 2 },
		"stale credential": func(p *permit.ProviderTarget) { p.CredentialVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			c := d
			c.ProviderTargets = []permit.ProviderTarget{d.ProviderTargets[0]}
			mutate(&c.ProviderTargets[0])
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.svc.ProposeReadGrant(context.Background(), &pb.ProposeReadGrantRequest{GrantJson: raw})
			wantPveCode(t, err, codes.InvalidArgument)
		})
	}
}

// Removing a remote through the admin path revokes its provider grants.
func TestRemovePVERemoteRevokesProviderGrants(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
	if _, err := e.svc.pveAdmin().RemoveRemote(context.Background(), PveRemove{RemoteID: pveReadRemote, By: "test"}); err != nil {
		t.Fatal(err)
	}
	grants, err := e.svc.auth.ReadGrants()
	if err != nil || len(grants) != 1 || grants[0].RevokedAt.IsZero() {
		t.Fatalf("grant not revoked on removal: %v %v", grants, err)
	}
}

// TestReadPVEStorageReportsPerNodeWithSharedFlag checks that STORAGE returns
// one entry per (node, storage) with the reporting node and PVE's shared
// flag, keeps node-local usage per node, and reports an inactive storage
// without capacity.
func TestReadPVEStorageReportsPerNodeWithSharedFlag(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	e.pve.set("/api2/json/nodes", `{"data":[{"node":"pve1","status":"online","type":"node"},{"node":"pve2","status":"online","type":"node"},{"node":"pve3","status":"offline","type":"node"}]}`)
	e.pve.set("/api2/json/nodes/pve1/storage", `{"data":[`+
		`{"storage":"nfs","type":"nfs","content":"images","active":1,"shared":1,"used":400,"total":1000},`+
		`{"storage":"local","type":"dir","content":"iso","active":1,"shared":0,"used":10,"total":100}]}`)
	e.pve.set("/api2/json/nodes/pve2/storage", `{"data":[`+
		`{"storage":"nfs","type":"nfs","content":"images","active":1,"shared":1,"used":400,"total":1000},`+
		`{"storage":"local","type":"dir","content":"iso","active":1,"shared":0,"used":90,"total":100},`+
		`{"storage":"gone","type":"dir","content":"iso","active":0,"shared":0,"used":5,"total":50}]}`)
	e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))

	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_STORAGE)
	if err != nil {
		t.Fatal(err)
	}
	s := got.GetStorages()
	if s.GetState() != pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE || len(s.GetStorages()) != 5 {
		t.Fatalf("storages = %v", s)
	}
	type key struct{ node, name string }
	by := map[key]*pb.PVEStorage{}
	for _, st := range s.GetStorages() {
		by[key{st.GetNode(), st.GetName()}] = st
	}
	for _, n := range []string{"pve1", "pve2"} {
		if st := by[key{n, "nfs"}]; st == nil || !st.GetShared() || st.GetSizeBytes() != 1000 || st.GetFreeBytes() != 600 {
			t.Fatalf("%s nfs = %v", n, st)
		}
	}
	if st := by[key{"pve1", "local"}]; st == nil || st.GetShared() || st.GetFreeBytes() != 90 {
		t.Fatalf("pve1 local = %v", st)
	}
	if st := by[key{"pve2", "local"}]; st == nil || st.GetShared() || st.GetFreeBytes() != 10 {
		t.Fatalf("pve2 local = %v", st)
	}
	if st := by[key{"pve2", "gone"}]; st == nil || st.GetActive() || st.GetSizeBytes() != 0 || st.GetFreeBytes() != 0 {
		t.Fatalf("inactive storage carries capacity: %v", st)
	}
}

// TestReadPVEStorageInconsistentSharedFlagUnavailable checks that a remote
// reporting the same storage as shared on one node and local on another
// yields an unavailable dataset instead of a guessed answer.
func TestReadPVEStorageInconsistentSharedFlagUnavailable(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	e.pve.set("/api2/json/nodes", `{"data":[{"node":"pve1","status":"online","type":"node"},{"node":"pve2","status":"online","type":"node"}]}`)
	e.pve.set("/api2/json/nodes/pve1/storage", `{"data":[{"storage":"nfs","type":"nfs","content":"images","active":1,"shared":1,"used":1,"total":10}]}`)
	e.pve.set("/api2/json/nodes/pve2/storage", `{"data":[{"storage":"nfs","type":"nfs","content":"images","active":1,"shared":0,"used":1,"total":10}]}`)
	e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))

	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_STORAGE)
	if err != nil {
		t.Fatal(err)
	}
	if st := got.GetStorages().GetState(); st != pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE {
		t.Fatalf("state = %v, want unavailable", st)
	}
}
