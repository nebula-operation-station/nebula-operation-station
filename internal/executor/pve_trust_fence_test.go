// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const rejectPveBlockTrigger = `CREATE TRIGGER reject_pve_block BEFORE UPDATE OF state ON pve_remotes WHEN NEW.state = 'blocked' BEGIN SELECT RAISE(ABORT, 'injected block failure'); END`

// assertConnectionsFenced fails unless every connection path to rm (the
// provisioning reader, the guest join reads with the read token and the
// scoped guest-agent credential, ReadPVE and the mutation client) is
// refused before any request reaches the endpoint, with want in the
// error chain of the non-RPC paths.
func assertConnectionsFenced(t *testing.T, e *pveReadEnv, rm executordb.PveRemote, want error) {
	t.Helper()
	ctx := context.Background()
	before := e.pve.requests.Load()
	r := pveProvisionReaderAPI{agent: pveGuestAgentAPI{s: e.svc}}
	a := pveGuestAgentAPI{s: e.svc}
	c := e.svc.newPveMutationClient()
	for name, call := range map[string]func() error{
		"provision inventory": func() error { _, err := r.ClusterInventory(ctx, rm, tokenOf(pveReadToken)); return err },
		"provision storage": func() error {
			_, err := r.NodeStorage(ctx, rm, "pve1", "local", tokenOf(pveReadToken))
			return err
		},
		"join live guest": func() error { _, err := a.LiveGuest(ctx, rm, "pve1", 101, tokenOf(pveReadToken)); return err },
		"join agent file read": func() error {
			_, err := a.AgentFileRead(ctx, rm, "pve1", 101, pveJoinHostKeyPath, maxPveAgentHostKeyBytes, tokenOf(guestRPCAgentToken))
			return err
		},
		"mutation task list": func() error {
			_, err := c.RecentTasks(ctx, rm, "pve1", time.Time{}, tokenOf(mutReadToken))
			return err
		},
	} {
		if err := call(); !errors.Is(err, want) {
			t.Fatalf("%s: err = %v, want %v", name, err, want)
		}
	}
	if _, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_NODES); err == nil || err.Error() != pveReadFencedStatus.Error() {
		t.Fatalf("ReadPVE of a fenced trust: %v", err)
	}
	if n := e.pve.requests.Load(); n != before {
		t.Fatalf("requests reached the endpoint: %d", n-before)
	}
}

// TestPveReaderTrustFailureFencesUnrecordedBlock: a trust failure that a
// provisioning or guest join read detects itself, on the
// connection (cluster CA) or on a request (standalone leaf), takes the
// same path as the mutation client: when the block cannot be persisted,
// the remote's grants are revoked and exactly the failed trust (pin and
// generation) is fenced, so every further connection to it is refused
// before any request, until the block is recorded.
func TestPveReaderTrustFailureFencesUnrecordedBlock(t *testing.T) {
	for _, kind := range []pvecontract.Kind{pvecontract.KindStandalone, pvecontract.KindCluster} {
		for _, reader := range []string{"provision", "join"} {
			t.Run(string(kind)+"/"+reader, func(t *testing.T) {
				e := newPveReadEnv(t, kind)
				e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
				rm := e.remote()
				rebuildServiceAuth(t, e, reopenServiceDB(t, e, rejectPveBlockTrigger))
				impostor := makeTestChain(t)
				e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
				e.pve.srv.CloseClientConnections()

				ctx := context.Background()
				var err error
				switch reader {
				case "provision":
					_, err = pveProvisionReaderAPI{agent: pveGuestAgentAPI{s: e.svc}}.ClusterInventory(ctx, rm, tokenOf(pveReadToken))
				case "join":
					_, err = pveGuestAgentAPI{s: e.svc}.LiveGuest(ctx, rm, "pve1", 101, tokenOf(pveReadToken))
				}
				if !errors.Is(err, errPveReadTrust) || !errors.Is(err, errPveTrustBlockNotRecorded) {
					t.Fatalf("read of an impostor: %v", err)
				}
				if n := e.pve.requests.Load(); n != 0 || e.pve.badAuth.Load() != 0 {
					t.Fatal("a request reached the impostor")
				}
				if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateActive {
					t.Fatalf("remote state = %s, want the injected failure to keep it active", got)
				}
				if !blockLogged(e, "pve mutation trust block not recorded") {
					t.Fatal("unrecorded block not logged")
				}
				assertGrantsRevoked(t, e)
				if k, fenced := e.svc.pveTrustFence().covers(rm); !fenced || k != pveTrustKeyOf(rm) {
					t.Fatalf("fence = %+v %v, want exactly the failed trust", k, fenced)
				}

				// The genuine endpoint is back: the fenced trust stays refused
				// on every path, and proposals are refused.
				e.pve.srv.TLS.Certificates = []tls.Certificate{e.chain.tls}
				e.pve.srv.CloseClientConnections()
				assertConnectionsFenced(t, e, rm, errPveTrustBlockNotRecorded)
				assertProposalFenced(t, e)

				// Once the store accepts the block, the next connection
				// records it, drops the fence and is still refused.
				rebuildServiceAuth(t, e, reopenServiceDB(t, e, `DROP TRIGGER reject_pve_block`))
				if _, err := (pveGuestAgentAPI{s: e.svc}).LiveGuest(ctx, rm, "pve1", 101, tokenOf(pveReadToken)); !errors.Is(err, errPveTrustFenced) || errors.Is(err, errPveTrustBlockNotRecorded) {
					t.Fatalf("connection after the store recovered: %v", err)
				}
				if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateBlocked {
					t.Fatalf("remote state = %s, want blocked", got)
				}
				if _, fenced := e.svc.pveTrustFence().covers(rm); fenced {
					t.Fatal("fence kept after the block was recorded")
				}
				if n := e.pve.requests.Load(); n != 0 {
					t.Fatalf("requests reached the endpoint: %d", n)
				}
			})
		}
	}
}

// TestPveReaderStaleTrustFailureSparesRepin: a reader-detected failure of
// a trust that an admin has re-pinned since (a newer generation) neither
// blocks nor fences the re-pinned remote.
func TestPveReaderStaleTrustFailureSparesRepin(t *testing.T) {
	for _, reader := range []string{"provision", "join"} {
		t.Run(reader, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindStandalone)
			stale := e.remote()
			db := reopenServiceDB(t, e, `UPDATE pve_remotes SET trust_generation = trust_generation + 1 WHERE remote_id = '`+pveReadRemote+`'`)
			rebuildServiceAuth(t, e, db)
			impostor := makeTestChain(t)
			e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
			e.pve.srv.CloseClientConnections()
			var err error
			if reader == "provision" {
				_, err = pveProvisionReaderAPI{agent: pveGuestAgentAPI{s: e.svc}}.ClusterInventory(context.Background(), stale, tokenOf(pveReadToken))
			} else {
				_, err = pveGuestAgentAPI{s: e.svc}.LiveGuest(context.Background(), stale, "pve1", 101, tokenOf(pveReadToken))
			}
			if !errors.Is(err, errPveReadTrust) {
				t.Fatalf("read of an impostor: %v", err)
			}
			if got := remoteState(t, db, pveReadRemote); got != executordb.StateActive {
				t.Fatalf("re-pinned remote state = %s, want active", got)
			}
			if _, fenced := e.svc.pveTrustFence().covers(stale); fenced {
				t.Fatal("superseded trust fenced")
			}
		})
	}
}

// TestPveGuestJoinRefusesFencedTrust: a guest join against a fenced trust
// is refused at propose and commit time with an audit event, and the
// guest join reads (read token and scoped guest-agent credential) refuse
// it before any connection, so the agent credential, which grant
// revocation does not cover, never reaches the failed trust.
func TestPveGuestJoinRefusesFencedTrust(t *testing.T) {
	e := newGuestRPCEnv(t)
	rm := e.remote()
	rebuildServiceAuth(t, e.pveReadEnv, reopenServiceDB(t, e.pveReadEnv, rejectPveBlockTrigger))
	e.svc.pveTrustFence().add(rm)
	ctx := context.Background()

	_, err := e.svc.ProposeGuestJoin(ctx, e.rpcRequest())
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "failed trust verification") {
		t.Fatalf("guest join proposal against a fenced trust: %v", err)
	}
	req := e.rpcRequest()
	_, err = e.svc.CommitGuestJoin(ctx, &pb.CommitGuestJoinRequest{ExecutionDigest: strings.Repeat("ab", 32),
		Guest: req.Guest, Host: req.Host, JoinMethod: PveJoinMethodReview})
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "failed trust verification") {
		t.Fatalf("guest join commit against a fenced trust: %v", err)
	}
	if !auditLogged(e.pveReadEnv, "pve_proposal_refused_trust_fenced") {
		t.Fatal("fenced guest join not audited")
	}
	// The join's own reader (scoped agent credential) is refused too and
	// falls back to a review without reading anything.
	p, err := e.readerPropose()
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != PveJoinMethodReview {
		t.Fatalf("method = %s, want review", p.Method)
	}
	assertConnectionsFenced(t, e.pveReadEnv, rm, errPveTrustBlockNotRecorded)
	if n := e.pve.requests.Load(); n != 0 || e.pve.badAuth.Load() != 0 {
		t.Fatalf("requests reached the fenced trust: %d", n)
	}
}

// TestPveGuestProvisionProposalRefusesFencedTrust: a guest provisioning
// proposal against a fenced trust is refused with an audit event before
// the provisioner reads or reserves anything; without the fence the same
// proposal reaches the provisioner's checks.
func TestPveGuestProvisionProposalRefusesFencedTrust(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	dir := t.TempDir()
	e.svc.SetBackupDirs(dir, filepath.Join(dir, "keys"))
	e.svc.keys = testAutomationKeyring(t)
	tpl := PveTemplateBinding{PveTemplateKey: PveTemplateKey{RemoteID: pveReadRemote, Node: "pve1", Storage: "local-lvm", ImageID: imgUbuntuID},
		VMID: 9000, Generation: 1, SourceSHA256: imgUbuntuSHA}
	spec := testProvisionSpec(tpl, PveAutomationCredentialRef)
	spec.RemoteId = pveReadRemote
	propose := func() error {
		_, err := e.svc.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{Spec: spec})
		return err
	}
	e.svc.pveTrustFence().add(e.remote())
	if st := status.Convert(propose()); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "failed trust verification") {
		t.Fatalf("provisioning proposal against a fenced trust: %v", st.Err())
	}
	if !auditLogged(e, "pve_proposal_refused_trust_fenced") {
		t.Fatal("fenced provisioning proposal not audited")
	}
	e.svc.pveTrustFence().remove(pveReadRemote, pveTrustKeyOf(e.remote()))
	if st := status.Convert(propose()); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "no action credential") {
		t.Fatalf("provisioning proposal without the fence: %v", st.Err())
	}
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("requests reached the endpoint: %d", n)
	}
}

// TestPveBlockOfUnknownRemoteIsNotUnrecorded: a trust failure of a remote
// that is no longer in the registry is not reported as an unrecorded
// block (nothing is left to block), so it is not fenced.
func TestPveBlockOfUnknownRemoteIsNotUnrecorded(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	rm := e.remote()
	rm.RemoteID = "pve-gone"
	if err := e.svc.pveTrustFailed(rm); err != nil {
		t.Fatalf("block of an unknown remote: %v", err)
	}
	if _, fenced := e.svc.pveTrustFence().covers(rm); fenced {
		t.Fatal("unknown remote fenced")
	}
}

// rotateReadToken rotates the read token of the env's remote over the RPC.
func rotateReadToken(e *pveReadEnv) error {
	_, err := e.svc.RotatePVEToken(context.Background(), &pb.RotatePVETokenRequest{
		RemoteId: pveReadRemote, Purpose: PvePurposeRead, Token: []byte(pveReadToken)})
	return err
}

// TestPveRotateTokenRefusesFencedTrust: a token rotation of a remote whose
// trust is fenced (its block is not recorded, so it is still active) is
// refused before any secret is opened or any connection is made, so the
// new token never reaches the failed trust. Once the store accepts the
// block, the next rotation records it and is still refused.
func TestPveRotateTokenRefusesFencedTrust(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	rm := e.remote()
	rebuildServiceAuth(t, e, reopenServiceDB(t, e, rejectPveBlockTrigger))
	e.svc.pveTrustFence().add(rm)
	conns := e.pve.conns.Load()

	err := rotateReadToken(e)
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "failed trust verification") {
		t.Fatalf("rotation of a fenced trust: %v", err)
	}
	if n := e.pve.conns.Load() - conns; n != 0 || e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
		t.Fatalf("rotation of a fenced trust reached the endpoint: %d connections", n)
	}
	cur := svcRemote(t, e)
	if cur.State != executordb.StateActive || cur.Credentials.ReadVersion != rm.Credentials.ReadVersion {
		t.Fatalf("remote after a refused rotation: %+v", cur)
	}
	if k, fenced := e.svc.pveTrustFence().covers(rm); !fenced || k != pveTrustKeyOf(rm) {
		t.Fatalf("fence = %+v %v, want the failed trust kept", k, fenced)
	}

	rebuildServiceAuth(t, e, reopenServiceDB(t, e, `DROP TRIGGER reject_pve_block`))
	if st := status.Convert(rotateReadToken(e)); st.Code() != codes.FailedPrecondition {
		t.Fatalf("rotation after the store recovered: %v", st.Err())
	}
	if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", got)
	}
	if _, fenced := e.svc.pveTrustFence().covers(rm); fenced {
		t.Fatal("fence kept after the block was recorded")
	}
	if n := e.pve.conns.Load() - conns; n != 0 {
		t.Fatalf("rotation reached the endpoint: %d connections", n)
	}
}

// TestPveRotateTokenTrustFailureUsesTheFence: a trust failure that token
// rotation detects itself takes the path of every other connection
// (pveTrustFailed): when the block cannot be recorded, the remote's
// grants are revoked and exactly the failed trust (pin and generation) is
// fenced; when it can, the remote is blocked. The token is never sent.
func TestPveRotateTokenTrustFailureUsesTheFence(t *testing.T) {
	for _, kind := range []pvecontract.Kind{pvecontract.KindStandalone, pvecontract.KindCluster} {
		for _, recorded := range []bool{false, true} {
			name := string(kind) + "/unrecorded"
			if recorded {
				name = string(kind) + "/recorded"
			}
			t.Run(name, func(t *testing.T) {
				e := newPveReadEnv(t, kind)
				e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodNodes))
				rm := e.remote()
				if !recorded {
					rebuildServiceAuth(t, e, reopenServiceDB(t, e, rejectPveBlockTrigger))
				}
				impostor := makeTestChain(t)
				e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
				e.pve.srv.CloseClientConnections()

				err := rotateReadToken(e)
				st := status.Convert(err)
				k, fenced := e.svc.pveTrustFence().covers(rm)
				if recorded {
					if st.Code() != codes.InvalidArgument {
						t.Fatalf("rotation against an impostor: %v", err)
					}
					if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateBlocked {
						t.Fatalf("remote state = %s, want blocked", got)
					}
					if fenced {
						t.Fatal("recorded block fenced")
					}
				} else {
					if st.Code() != codes.Internal || !strings.Contains(st.Message(), "could not be recorded") {
						t.Fatalf("rotation against an impostor: %v", err)
					}
					if got := remoteState(t, e.svc.db, pveReadRemote); got != executordb.StateActive {
						t.Fatalf("remote state = %s, want the injected failure to keep it active", got)
					}
					if !blockLogged(e, "pve mutation trust block not recorded") {
						t.Fatal("unrecorded block not logged")
					}
					if !fenced || k != pveTrustKeyOf(rm) {
						t.Fatalf("fence = %+v %v, want exactly the failed trust", k, fenced)
					}
				}
				assertGrantsRevoked(t, e)
				if e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
					t.Fatal("a request reached the impostor")
				}
				if cur := svcRemote(t, e); cur.Credentials.ReadVersion != rm.Credentials.ReadVersion {
					t.Fatalf("read version = %d, want %d", cur.Credentials.ReadVersion, rm.Credentials.ReadVersion)
				}
			})
		}
	}
}

// svcRemote reads the env's remote from the service's current registry.
func svcRemote(t *testing.T, e *pveReadEnv) executordb.PveRemote {
	t.Helper()
	rm, ok, err := e.svc.db.GetRemote(pveReadRemote)
	if err != nil || !ok {
		t.Fatalf("remote: %v %v", ok, err)
	}
	return rm
}
