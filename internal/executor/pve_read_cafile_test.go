// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

const leafOnlyRemote = "leafy"

// switchableLeafPVE is a PVE-like API on loopback whose nodes serve only
// their leaf; the served leaf can be switched (a re-keyed cluster).
type switchableLeafPVE struct {
	cert     atomic.Pointer[tls.Certificate]
	requests atomic.Int64
	ep       pvecontract.Endpoint
}

func newSwitchableLeafPVE(t *testing.T, cert tls.Certificate) *switchableLeafPVE {
	t.Helper()
	p := &switchableLeafPVE{}
	p.cert.Store(&cert)
	bodies := defaultPVEBodies()
	bodies["/api2/json/version"] = `{"data":{"version":"9.0"}}`
	bodies["/api2/json/access/permissions"] = `{"data":{"/":{"Sys.Audit":1},"/vms":{"VM.Audit":1},"/storage":{"Datastore.Audit":1},"/pool":{"Pool.Audit":1}}}`
	bodies["/api2/json/access/users"] = `{"data":[{"userid":"nosread@pve","tokens":[{"tokenid":"read","privsep":1,"expire":4000000000}]}]}`
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken="+pveReadToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p.requests.Add(1)
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	// GetConfigForClient always applies (GetCertificate is skipped without
	// SNI, which an IP endpoint never sends).
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{*p.cert.Load()}}, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	p.ep = pvecontract.Endpoint{Host: host, Port: uint16(port)}
	return p
}

// dropPveCACache empties the connection CA cache, as an executor restart
// does.
func dropPveCACache(s *Service) {
	s.pveRead.mu.Lock()
	s.pveRead.cas = nil
	s.pveRead.mu.Unlock()
}

// registerLeafOnlyCluster registers a leaf-only cluster pinned to c's CA
// directly in the registry, with its read token and CA in the vault, and
// nothing in the CA cache (the state after an executor restart).
func registerLeafOnlyCluster(t *testing.T, e *pveReadEnv, c leafOnlyCluster, ep pvecontract.Endpoint) executordb.PveRemote {
	t.Helper()
	ref := PveVaultID(leafOnlyRemote, PvePurposeRead)
	version, err := e.svc.vault.Put(ref, []byte(pveReadToken), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&PveAdmin{Vault: e.svc.vault}).storeClusterCA(leafOnlyRemote, fpHex(c.ca), c.ca, "test"); err != nil {
		t.Fatal(err)
	}
	rm, err := e.db.AddRemote(pvecontract.Remote{RemoteID: leafOnlyRemote, Name: "Leafy", Kind: pvecontract.KindCluster,
		Endpoints: []pvecontract.Endpoint{ep}, TrustPin: fpHex(c.ca), TrustGeneration: 1},
		executordb.PveRemoteCredentials{ReadRef: ref, ReadVersion: version}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return rm
}

func (e *pveReadEnv) remoteByID(id string) executordb.PveRemote {
	e.t.Helper()
	rm, ok, err := e.db.GetRemote(id)
	if err != nil || !ok {
		e.t.Fatalf("remote %s: %v %v", id, ok, err)
	}
	return rm
}

// approveNodesGrant approves a read grant for the nodes of remote id at
// its current pin, generation and credential.
func (e *pveReadEnv) approveNodesGrant(grantID, id string) {
	e.t.Helper()
	rm := e.remoteByID(id)
	now := e.clock.Now()
	raw, err := json.Marshal(permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: grantID, Issuer: "root", CreatedUnix: now.Unix(),
		ExpiryUnix: now.Add(permit.DefaultReadGrantLifetime).Unix(), Trigger: permit.TriggerScheduled,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: 60, RunBudget: 10, RateProfile: permit.ProviderReadProfile,
		ProviderTargets: []permit.ProviderTarget{{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, TrustGeneration: rm.TrustGeneration,
			CredentialVersion: rm.Credentials.ReadVersion, Methods: []string{permit.ProviderMethodNodes}}},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.approve(raw)
}

func (e *pveReadEnv) readNodesOf(id string) (*pb.ReadPVEResponse, error) {
	return e.svc.ReadPVE(context.Background(), &pb.ReadPVERequest{RemoteId: id, Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES})
}

func (e *pveReadEnv) requireActive(id string) {
	e.t.Helper()
	rm := e.remoteByID(id)
	if rm.State != executordb.StateActive {
		e.t.Fatalf("remote %s state = %s, want active", id, rm.State)
	}
	if err := e.svc.pveTrustFenceGate(rm); err != nil {
		e.t.Fatalf("remote %s fenced: %v", id, err)
	}
}

// TestPveLeafOnlyClusterReadAfterRestartLoadsStoredCA: with an empty CA
// cache (restart), the trust of a leaf-only cluster comes from the stored
// CA, and a ReadPVE succeeds instead of blocking the remote.
func TestPveLeafOnlyClusterReadAfterRestartLoadsStoredCA(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
	rm := registerLeafOnlyCluster(t, e, c, pve.ep)

	trust, err := e.svc.pveReadTrust(context.Background(), rm)
	if err != nil || trust.CA == nil || !bytes.Equal(trust.CA.Raw, c.ca.Raw) {
		t.Fatalf("pveReadTrust after restart = %+v, %v; want the stored CA", trust, err)
	}
	if ca := e.svc.pveRead.cachedCA(rm); ca == nil || !bytes.Equal(ca.Raw, c.ca.Raw) {
		t.Fatal("stored CA not cached after load")
	}

	dropPveCACache(e.svc)
	e.approveNodesGrant("00000000-0000-4000-8000-0000000000f1", leafOnlyRemote)
	out, err := e.readNodesOf(leafOnlyRemote)
	if err != nil {
		t.Fatalf("ReadPVE of leaf-only cluster after restart: %v", err)
	}
	if out.GetNodes().GetState() != pveAvailable {
		t.Fatalf("nodes = %v, want available", out.GetNodes())
	}
	e.requireActive(leafOnlyRemote)
}

// TestPveLeafOnlyClusterWithoutStoredCAStillFailsTrust: the stored CA is
// the only trust source of a leaf-only cluster; without it the endpoints
// present nothing matching the pin, which stays a trust failure.
func TestPveLeafOnlyClusterWithoutStoredCAStillFailsTrust(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
	rm := registerLeafOnlyCluster(t, e, c, pve.ep)
	if err := e.svc.vault.Delete(pveCAVaultID(rm.RemoteID, rm.TrustPin)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.pveReadTrust(context.Background(), rm); !errors.Is(err, errPveReadTrust) {
		t.Fatalf("pveReadTrust without stored CA = %v, want errPveReadTrust", err)
	}
}

// TestPveLeafOnlyClusterLockedVaultOnCacheMissIsNotTrustFailure: a locked
// vault on a cache miss returns the locked error on every connection path
// and never blocks the remote.
func TestPveLeafOnlyClusterLockedVaultOnCacheMissIsNotTrustFailure(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
	rm := registerLeafOnlyCluster(t, e, c, pve.ep)
	e.svc.vault.Lock()

	_, err := e.svc.pveReadTrust(context.Background(), rm)
	if !errors.Is(err, vault.ErrLocked) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("pveReadTrust with locked vault = %v, want vault.ErrLocked", err)
	}
	// Provisioning and guest join reads.
	_, _, _, _, err = e.svc.pveReaderConn(context.Background(), rm)
	if !errors.Is(err, vault.ErrLocked) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("pveReaderConn with locked vault = %v, want vault.ErrLocked", err)
	}
	// The mutation client.
	_, _, _, err = e.svc.newPveMutationClient().conn(context.Background(), rm)
	if !errors.Is(err, vault.ErrLocked) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("mutation conn with locked vault = %v, want vault.ErrLocked", err)
	}
	e.requireActive(leafOnlyRemote)
	if n := pve.requests.Load(); n != 0 {
		t.Fatalf("%d authenticated requests with a locked vault", n)
	}
}

// TestPveStoredCAUnusableOnCacheMissIsNotTrustFailure: a stored CA that
// does not match the pin (tampered vault entry) refuses the read with an
// error, but is local and does not block the remote.
func TestPveStoredCAUnusableOnCacheMissIsNotTrustFailure(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
	rm := registerLeafOnlyCluster(t, e, c, pve.ep)
	other := makeLeafOnlyCluster(t)
	if _, err := e.svc.vault.Put(pveCAVaultID(rm.RemoteID, rm.TrustPin), other.ca.Raw, "test"); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.pveReadTrust(context.Background(), rm)
	if !errors.Is(err, errPveStoredCA) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("pveReadTrust with mismatching stored CA = %v, want errPveStoredCA", err)
	}
	e.approveNodesGrant("00000000-0000-4000-8000-0000000000f2", leafOnlyRemote)
	if _, err := e.readNodesOf(leafOnlyRemote); status.Code(err) != codes.Internal {
		t.Fatalf("ReadPVE with mismatching stored CA = %v, want Internal", err)
	}
	e.requireActive(leafOnlyRemote)
	if n := pve.requests.Load(); n != 0 {
		t.Fatalf("%d authenticated requests with an unusable stored CA", n)
	}
}

// TestPveAddAndRepinLeafOnlyClusterRPCReadAfterRestart drives the
// AddPVERemote and CommitPVERepin RPCs against a real leaf-only endpoint
// and reads after each with an empty CA cache.
func TestPveAddAndRepinLeafOnlyClusterRPCReadAfterRestart(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	ctx := context.Background()
	c1 := makeLeafOnlyCluster(t, "127.0.0.1")
	pve := newSwitchableLeafPVE(t, c1.tls["127.0.0.1"])
	eps := []*pb.PVEEndpoint{{Host: pve.ep.Host, Port: uint32(pve.ep.Port)}}
	pin1 := fpHex(c1.ca)

	added, err := e.svc.AddPVERemote(ctx, &pb.AddPVERemoteRequest{RemoteId: leafOnlyRemote, Kind: "cluster", Endpoints: eps,
		ConfirmedPin: pin1, ReadToken: []byte(pveReadToken), CaPem: c1.caPEM})
	if err != nil {
		t.Fatalf("AddPVERemote: %v", err)
	}
	if added.GetRemote().GetTrustPin() != pin1 {
		t.Fatalf("pin = %s, want %s", added.GetRemote().GetTrustPin(), pin1)
	}
	dropPveCACache(e.svc)
	e.approveNodesGrant("00000000-0000-4000-8000-0000000000f3", leafOnlyRemote)
	if _, err := e.readNodesOf(leafOnlyRemote); err != nil {
		t.Fatalf("ReadPVE after add and restart: %v", err)
	}
	e.requireActive(leafOnlyRemote)

	// The cluster is re-keyed: its node now serves a leaf of a new CA.
	c2 := makeLeafOnlyCluster(t, "127.0.0.1")
	pve.cert.Store(func() *tls.Certificate { c := c2.tls["127.0.0.1"]; return &c }())
	pin2 := fpHex(c2.ca)
	proposed, err := e.svc.ProposePVERepin(ctx, &pb.ProposePVERepinRequest{RemoteId: leafOnlyRemote, OldPin: pin1, ConfirmedNewPin: pin2, CaPem: c2.caPEM})
	if err != nil {
		t.Fatalf("ProposePVERepin: %v", err)
	}
	d, err := canonical.ParseDigest(proposed.GetPermit().ExecutionDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveCLI(d, 0, "personal-admin"); err != nil {
		t.Fatal(err)
	}
	repinned, err := e.svc.CommitPVERepin(ctx, &pb.CommitPVERepinRequest{RemoteId: leafOnlyRemote, OldPin: pin1, ConfirmedNewPin: pin2,
		ExecutionDigest: proposed.GetPermit().ExecutionDigest, CaPem: c2.caPEM})
	if err != nil {
		t.Fatalf("CommitPVERepin: %v", err)
	}
	if repinned.GetRemote().GetTrustPin() != pin2 || repinned.GetRemote().GetTrustGeneration() != 2 {
		t.Fatalf("repinned = %v", repinned.GetRemote())
	}
	if _, err := e.svc.vault.Open(pveCAVaultID(leafOnlyRemote, pin1)); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("old CA still stored: %v", err)
	}
	dropPveCACache(e.svc)
	e.clock.Add(2 * time.Minute) // past the provider read interval
	e.approveNodesGrant("00000000-0000-4000-8000-0000000000f4", leafOnlyRemote)
	if _, err := e.readNodesOf(leafOnlyRemote); err != nil {
		t.Fatalf("ReadPVE after repin and restart: %v", err)
	}
	e.requireActive(leafOnlyRemote)
}

// TestPveAddRPCFailsWhenStoredCACannotBeLoaded: the RPC reports a CA that
// cannot be loaded after the add instead of returning success.
func TestPveAddRPCFailsWhenStoredCACannotBeLoaded(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	rm := executordb.PveRemote{RemoteID: leafOnlyRemote, Kind: pvecontract.KindCluster, TrustPin: fpHex(c.ca)}
	other := makeLeafOnlyCluster(t)
	if _, err := e.svc.vault.Put(pveCAVaultID(rm.RemoteID, rm.TrustPin), other.ca.Raw, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.seedPveClusterCA(e.svc.pveAdmin(), rm); status.Code(err) != codes.Internal {
		t.Fatalf("seed with mismatching stored CA = %v, want Internal", err)
	}
	if e.svc.pveRead.cachedCA(rm) != nil {
		t.Fatal("unusable CA cached")
	}
	e.svc.vault.Lock()
	if err := e.svc.seedPveClusterCA(e.svc.pveAdmin(), rm); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("seed with locked vault = %v, want FailedPrecondition", err)
	}
}

// TestPveRepinRemovesNewCAWhenRegistrySwitchFails: a re-pin whose registry
// switch fails leaves no stored CA for the new pin, and the current pin's
// CA intact.
func TestPveRepinRemovesNewCAWhenRegistrySwitchFails(t *testing.T) {
	e := newPveTestEnv(t)
	c1 := makeLeafOnlyCluster(t, labHosts...)
	e.probe.result = c1.probe(labHosts...)
	rm, err := e.addWithCA(t, "nebulanetwork", pveEndpoints(labHosts...), fpHex(c1.ca), c1.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin1 := rm.TrustPin
	c2 := makeLeafOnlyCluster(t, labHosts...)
	pin2 := fpHex(c2.ca)
	e.probe.result = c2.probe(labHosts...)
	// The registry changes between approval and switch (a concurrent
	// re-pin): RepinRemote refuses the stale old pin.
	e.admin.AuthorizeRepin = func(context.Context, executordb.PveRemote, PveRepin) error {
		c3 := makeLeafOnlyCluster(t)
		if _, err := e.db.RepinRemote("nebulanetwork", pin1, fpHex(c3.ca), "other-admin"); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if _, err := e.admin.Repin(context.Background(), PveRepin{RemoteID: "nebulanetwork", OldPin: pin1, ConfirmedNewPin: pin2, CAPEM: c2.caPEM, By: "admin"}); err == nil {
		t.Fatal("repin over a concurrently changed registry succeeded")
	}
	if _, err := e.vault.Open(pveCAVaultID("nebulanetwork", pin2)); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("new CA left behind after failed switch: %v", err)
	}
	if _, err := e.vault.Open(pveCAVaultID("nebulanetwork", pin1)); err != nil {
		t.Fatalf("current CA removed by failed repin: %v", err)
	}
}
