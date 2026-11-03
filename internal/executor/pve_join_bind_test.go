// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// pendingGuest returns the guest binding of the one pending permit as the
// approver sees it (the canonical parameters).
func (e *joinEnv) pendingGuest() map[string]any {
	e.t.Helper()
	got, err := e.svc.ListPending(context.Background(), &pb.ListPendingRequest{})
	if err != nil || len(got.GetPermits()) != 1 {
		e.t.Fatalf("pending = %v, %v", got, err)
	}
	var doc struct {
		Guest map[string]any `json:"guest"`
	}
	if err := json.Unmarshal(got.GetPermits()[0].GetCanonicalParameters(), &doc); err != nil {
		e.t.Fatal(err)
	}
	return doc.Guest
}

func (e *joinEnv) approve(p PveGuestJoinProposal) canonical.Digest {
	e.t.Helper()
	d, err := canonical.ParseDigest(p.Permit.GetExecutionDigest())
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveCLI(d, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *joinEnv) pinned(host string) bool {
	e.t.Helper()
	_, ok, err := e.db.HostKey(host)
	if err != nil {
		e.t.Fatal(err)
	}
	return ok
}

func TestGuestJoinApprovalShowsGuestAndJoinMethod(t *testing.T) {
	for _, method := range []string{PveJoinMethodAgent, PveJoinMethodReview} {
		t.Run(method, func(t *testing.T) {
			e := newJoinEnv(t, true)
			if method == PveJoinMethodReview {
				e.agent.err = errors.New("agent not running")
			}
			p, err := e.join.Propose(context.Background(), e.request())
			if err != nil {
				t.Fatal(err)
			}
			g := e.pendingGuest()
			want := map[string]any{"remote": mutRemote, "node": "pve1", "vmid": float64(101), "generation": float64(1),
				"name": "web1.lab.test", "uuid": testJoinUUID, "join_method": method}
			for k, v := range want {
				if g[k] != v {
					t.Fatalf("approval shows guest %v, want %s=%v", g, k, v)
				}
			}
			if p.Guest.GetRemoteId() != mutRemote || p.Guest.GetVmid() != 101 || p.Guest.GetGeneration() != 1 ||
				p.Guest.GetNode() != "pve1" || p.Guest.GetGuestName() != "web1.lab.test" || p.Method != method {
				t.Fatalf("proposal guest = %+v, method %s", p.Guest, p.Method)
			}
		})
	}
}

func TestGuestJoinCommitPinsOnlyTheApprovedBinding(t *testing.T) {
	e := newJoinEnv(t, true)
	ctx := context.Background()
	p, err := e.join.Propose(ctx, e.request())
	if err != nil {
		t.Fatal(err)
	}
	d := e.approve(p)
	type change func(h *pb.EnrollHost, g *pb.GuestJoinTarget, m *string)
	changes := map[string]change{
		"host id":    func(h *pb.EnrollHost, _ *pb.GuestJoinTarget, _ *string) { h.HostId = "web2" },
		"endpoint":   func(h *pb.EnrollHost, _ *pb.GuestJoinTarget, _ *string) { h.Endpoint = "127.0.0.1:2" },
		"ssh user":   func(h *pb.EnrollHost, _ *pb.GuestJoinTarget, _ *string) { h.SshUser = "root" },
		"credential": func(h *pb.EnrollHost, _ *pb.GuestJoinTarget, _ *string) { h.CredentialRef = "other-cred" },
		"fingerprint": func(h *pb.EnrollHost, _ *pb.GuestJoinTarget, _ *string) {
			h.Fingerprint = "SHA256:" + strings.Repeat("A", 43)
		},
		"guest uuid": func(_ *pb.EnrollHost, g *pb.GuestJoinTarget, _ *string) {
			g.GuestUuid = "11111111-2222-4333-8444-555555555555"
		},
		"no uuid":    func(_ *pb.EnrollHost, g *pb.GuestJoinTarget, _ *string) { g.GuestUuid = "" },
		"remote":     func(_ *pb.EnrollHost, g *pb.GuestJoinTarget, _ *string) { g.RemoteId = "other-pve" },
		"node":       func(_ *pb.EnrollHost, g *pb.GuestJoinTarget, _ *string) { g.Node = "pve2" },
		"vmid":       func(_ *pb.EnrollHost, g *pb.GuestJoinTarget, _ *string) { g.Vmid = 102 },
		"generation": func(_ *pb.EnrollHost, g *pb.GuestJoinTarget, _ *string) { g.Generation = 2 },
		"guest name": func(_ *pb.EnrollHost, g *pb.GuestJoinTarget, _ *string) { g.GuestName = "web2.lab.test" },
		"method":     func(_ *pb.EnrollHost, _ *pb.GuestJoinTarget, m *string) { *m = PveJoinMethodReview },
	}
	for name, mod := range changes {
		t.Run(name, func(t *testing.T) {
			h := &pb.EnrollHost{HostId: p.Host.GetHostId(), Endpoint: p.Host.GetEndpoint(), SshUser: p.Host.GetSshUser(),
				CredentialRef: p.Host.GetCredentialRef(), Fingerprint: p.Host.GetFingerprint(), KeyType: p.Host.GetKeyType()}
			g := &pb.GuestJoinTarget{RemoteId: p.Guest.GetRemoteId(), Node: p.Guest.GetNode(), Vmid: p.Guest.GetVmid(),
				Generation: p.Guest.GetGeneration(), GuestName: p.Guest.GetGuestName(), GuestUuid: p.Guest.GetGuestUuid()}
			m := p.Method
			mod(h, g, &m)
			if _, err := e.join.Commit(ctx, d, h, g, m); !errors.Is(err, ErrPveJoinNotApproved) {
				t.Fatalf("err = %v, want ErrPveJoinNotApproved", err)
			}
			if e.pinned("web1") || e.pinned("web2") {
				t.Fatal("nothing may be pinned")
			}
		})
	}
	c, err := e.join.Commit(ctx, d, p.Host, p.Guest, p.Method)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Result.GetPinned() || c.Result.GetFingerprint() != p.Fingerprint || !e.pinned("web1") {
		t.Fatalf("commit = %+v, want web1 pinned", c.Result)
	}
	if c.Host.GetHostId() != "web1" || c.Host.GetEndpoint() != p.Host.GetEndpoint() || c.Guest.GetVmid() != 101 ||
		c.Guest.GetGeneration() != 1 || c.JoinMethod != PveJoinMethodAgent {
		t.Fatalf("committed binding = %+v %+v %s", c.Host, c.Guest, c.JoinMethod)
	}
	if recs := e.logs.find("guest_join_committed", ""); len(recs) != 1 || recs[0].attrs["method"] != PveJoinMethodAgent {
		t.Fatalf("audit = %+v", recs)
	}
}

func TestGuestJoinAndBulkEnrollApprovalsAreNotInterchangeable(t *testing.T) {
	ctx := context.Background()
	t.Run("bulk commit of a guest join approval", func(t *testing.T) {
		e := newJoinEnv(t, true)
		p, err := e.join.Propose(ctx, e.request())
		if err != nil {
			t.Fatal(err)
		}
		d := e.approve(p)
		_, err = e.svc.CommitEnroll(ctx, &pb.CommitEnrollRequest{ExecutionDigest: d.String(), Hosts: []*pb.EnrollHost{p.Host}})
		if status.Code(err) != codes.PermissionDenied || e.pinned("web1") {
			t.Fatalf("err = %v, want PermissionDenied and nothing pinned", err)
		}
	})
	t.Run("guest commit of a bulk approval", func(t *testing.T) {
		e := newJoinEnv(t, true)
		resp, err := e.svc.ProposeEnroll(ctx, &pb.ProposeEnrollRequest{Hosts: []*pb.EnrollHost{{HostId: "web1",
			Endpoint: e.ssh.addr, SshUser: "nos", CredentialRef: "cred"}}})
		if err != nil || resp.GetPermit() == nil {
			t.Fatalf("propose enroll: %v %v", resp, err)
		}
		d, _ := canonical.ParseDigest(resp.GetPermit().GetExecutionDigest())
		if _, err := e.svc.auth.ApproveCLI(d, 0, "admin"); err != nil {
			t.Fatal(err)
		}
		g := &pb.GuestJoinTarget{RemoteId: mutRemote, Node: "pve1", Vmid: 101, Generation: 1, GuestName: "web1.lab.test", GuestUuid: testJoinUUID}
		if _, err := e.join.Commit(ctx, d, resp.GetHosts()[0], g, PveJoinMethodReview); !errors.Is(err, ErrPveJoinNotApproved) {
			t.Fatalf("err = %v, want ErrPveJoinNotApproved", err)
		}
		if e.pinned("web1") {
			t.Fatal("nothing may be pinned")
		}
	})
}

func TestGuestJoinChecksLiveGuestBeforeAgentRead(t *testing.T) {
	cases := map[string]func(e *joinEnv){
		"reused vmid":         func(e *joinEnv) { e.agent.name = "someone-else" },
		"recreated same name": func(e *joinEnv) { e.agent.uuid = "11111111-2222-4333-8444-555555555555" },
		"no live uuid":        func(e *joinEnv) { e.agent.uuid = "" },
		"guest not there":     func(e *joinEnv) { e.agent.nameErr = errors.New("pveapi: HTTP 500") },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newJoinEnv(t, true)
			mod(e)
			p, err := e.join.Propose(context.Background(), e.request())
			if err != nil {
				t.Fatal(err)
			}
			if p.Method != PveJoinMethodReview || p.AgentDetail == "" {
				t.Fatalf("proposal = %+v, want review", p)
			}
			if len(e.agent.nameCalls) != 1 || e.agent.nameCalls[0] != mutRemote+"|pve1|101" {
				t.Fatalf("live guest reads = %v", e.agent.nameCalls)
			}
			if len(e.agent.calls) != 0 {
				t.Fatal("the agent of an unconfirmed guest must not be read")
			}
			if g := e.pendingGuest(); g["join_method"] != PveJoinMethodReview {
				t.Fatalf("approval shows %v", g)
			}
		})
	}
}

func TestGuestJoinSwapDuringAgentReadFallsBack(t *testing.T) {
	e := newJoinEnv(t, true)
	e.agent.afterRead = &PveGuestIdentity{Name: "web1.lab.test", UUID: "11111111-2222-4333-8444-555555555555"}
	p, err := e.join.Propose(context.Background(), e.request())
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != PveJoinMethodReview || len(e.agent.calls) != 1 || len(e.agent.nameCalls) != 2 {
		t.Fatalf("proposal %+v, reads %d/%d: a guest swapped during the read must not be agent-verified",
			p, len(e.agent.calls), len(e.agent.nameCalls))
	}
	if recs := e.logs.find("guest_join_identity_mismatch", ""); len(recs) != 1 || recs[0].attrs["when"] != "after" {
		t.Fatalf("audit = %+v", recs)
	}
}

// guardDetails are the fixed reasons a guard must report itself (another
// guard could otherwise mask a missing one).
var guardDetails = map[string]string{
	"no scoped credential source": pveJoinNoCredential,
	"no scoped credential":        pveJoinNoCredential,
	"recovery pending":            "executor recovery pending",
	"no read grant":               "no read grant covers the guest list",
	"no uuid recorded":            "the provisioned guest has no recorded incarnation identity",
}

func TestGuestJoinAgentReadGuards(t *testing.T) {
	cases := map[string]func(e *joinEnv){
		"no scoped credential source": func(e *joinEnv) { e.join.AgentCredentials = nil },
		"no scoped credential":        func(e *joinEnv) { e.creds.none = true },
		"scoped credential error":     func(e *joinEnv) { e.creds.err = errors.New("vault") },
		"no uuid recorded": func(e *joinEnv) {
			e.reqMod = func(r *PveGuestJoinRequest) { r.GuestUUID = "" }
		},
		"recovery pending": func(e *joinEnv) {
			if err := e.db.SetRecoveryPending(); err != nil {
				e.t.Fatal(err)
			}
		},
		"no read grant": func(e *joinEnv) {
			grants, err := e.svc.auth.ReadGrants()
			if err != nil || len(grants) != 1 {
				e.t.Fatalf("grants: %v %v", grants, err)
			}
			if err := e.svc.auth.RevokeReadGrant(grants[0].ID, "test"); err != nil {
				e.t.Fatal(err)
			}
		},
		"blocked remote": func(e *joinEnv) {
			if _, err := e.mut.pe.db.BlockRemote(mutRemote, "trust", "test"); err != nil {
				e.t.Fatal(err)
			}
		},
		"read token ref not registered": func(e *joinEnv) {
			rm, _, _ := e.mut.pe.db.GetRemote(mutRemote)
			creds := rm.Credentials
			// A usable token under another vault ID is still not the
			// remote's registered read token.
			ref := PveVaultID(mutRemote, PvePurposeAction)
			v, err := e.mut.pe.vault.Put(ref, []byte(mutReadToken), "test")
			if err != nil {
				e.t.Fatal(err)
			}
			creds.ReadRef, creds.ReadVersion = ref, v
			if _, err := e.mut.pe.db.SetRemoteCredentials(mutRemote, creds, "test"); err != nil {
				e.t.Fatal(err)
			}
		},
		"read token not in the vault": func(e *joinEnv) {
			if err := e.mut.pe.vault.Delete(PveVaultID(mutRemote, PvePurposeRead)); err != nil {
				e.t.Fatal(err)
			}
		},
		"vault locked": func(e *joinEnv) { e.mut.pe.vault.Lock() },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newJoinEnv(t, true)
			mod(e)
			req := e.request()
			if e.reqMod != nil {
				e.reqMod(&req)
			}
			p, err := e.join.Propose(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if p.Method != PveJoinMethodReview || p.AgentDetail == "" {
				t.Fatalf("proposal = %+v, want review", p)
			}
			if want, ok := guardDetails[name]; ok && p.AgentDetail != want {
				t.Fatalf("detail = %q, want %q", p.AgentDetail, want)
			}
			if recs := e.logs.find("guest_join_agent_fallback", ""); len(recs) != 1 || recs[0].attrs["reason"] != p.AgentDetail {
				t.Fatalf("fallback audit = %+v", recs)

			}
			if len(e.agent.calls) != 0 || len(e.agent.nameCalls) != 0 {
				t.Fatal("nothing may be read without an active remote and its read token")
			}
		})
	}
	t.Run("read is bounded in time", func(t *testing.T) {
		e := newJoinEnv(t, true)
		if _, err := e.join.Propose(context.Background(), e.request()); err != nil {
			t.Fatal(err)
		}
		if e.agent.deadline <= 0 || e.agent.deadline > pveAgentReadTimeout {
			t.Fatalf("agent read deadline %v, want within %v", e.agent.deadline, pveAgentReadTimeout)
		}
	})
}

func TestGuestJoinRPCIsServerOnly(t *testing.T) {
	for _, m := range []string{pb.ExecutorService_ProposeGuestJoin_FullMethodName, pb.ExecutorService_CommitGuestJoin_FullMethodName} {
		if got := MethodRoles()[m]; !slices.Equal(got, []peercred.Role{peercred.RoleServer}) {
			t.Fatalf("%s roles = %v, want server only", m, got)
		}
	}
}

// guestRPCEnv is a Service whose PVE remote is a pinned TLS fake with a
// read grant covering the guest list, and a loopback SSH guest.
type guestRPCEnv struct {
	*pveReadEnv
	ssh *testSSH
}

const guestRPCAgentToken = "PVEAPIToken=nosagent@pve!agent=scoped-agent-secret"

func newGuestRPCEnv(t *testing.T) *guestRPCEnv {
	t.Helper()
	re := newPveReadEnv(t, pvecontract.KindStandalone)
	re.approve(re.grantDoc(pveReadGrantID, 240, permit.ProviderMethodGuests))
	srv := startTestSSH(t, re.userPub, sshModeNormal)
	re.pve.set("/api2/json/nodes/pve1/qemu", `{"data":[{"vmid":101,"name":"web1.lab.test","status":"running","uuid":"0F8FAD5B-D9CB-469F-A165-70867728950E"}]}`)
	line, _ := json.Marshal(string(authorizedLine(srv.hostKey.PublicKey(), "root@web1")))
	re.pve.set("/api2/json/nodes/pve1/qemu/101/agent/file-read", `{"data":{"content":`+string(line)+`}}`)
	// The file read accepts only the scoped guest-agent credential.
	re.pve.tokens = map[string]string{"/api2/json/nodes/pve1/qemu/101/agent/file-read": guestRPCAgentToken}
	return &guestRPCEnv{pveReadEnv: re, ssh: srv}
}

func (e *guestRPCEnv) rpcRequest() *pb.ProposeGuestJoinRequest {
	return &pb.ProposeGuestJoinRequest{
		Guest: &pb.GuestJoinTarget{RemoteId: pveReadRemote, Node: "pve1", Vmid: 101, Generation: 1, GuestName: "web1.lab.test", GuestUuid: testJoinUUID},
		Host:  &pb.EnrollHost{HostId: "web1", Endpoint: e.ssh.addr, SshUser: "nos", CredentialRef: "cred"},
	}
}

// readerJoin is the production reader with a scoped guest-agent credential
// (no production credential source exists yet).
func (e *guestRPCEnv) readerJoin() *PveGuestJoin {
	j := e.svc.pveGuestJoin()
	j.AgentCredentials = &fakeAgentCreds{token: guestRPCAgentToken}
	return j
}

func (e *guestRPCEnv) readerPropose() (PveGuestJoinProposal, error) {
	r := e.rpcRequest()
	return e.readerJoin().Propose(context.Background(), PveGuestJoinRequest{RemoteID: pveReadRemote, Node: "pve1", VMID: 101,
		Generation: 1, GuestName: "web1.lab.test", GuestUUID: testJoinUUID, HostID: "web1", Endpoint: r.Host.Endpoint,
		SSHUser: "nos", CredentialRef: "cred"})
}

func TestGuestJoinRPCIsFingerprintReviewWithoutScopedCredential(t *testing.T) {
	e := newGuestRPCEnv(t)
	ctx := context.Background()
	resp, err := e.svc.ProposeGuestJoin(ctx, e.rpcRequest())
	if err != nil {
		t.Fatal(err)
	}
	want := sshtransport.Fingerprint(e.ssh.hostKey.PublicKey())
	if resp.GetJoinMethod() != PveJoinMethodReview || resp.GetAgentDetail() != pveJoinNoCredential || resp.GetHost().GetFingerprint() != want {
		t.Fatalf("response = %+v, want review of %s without credential", resp, want)
	}
	if e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
		t.Fatal("without a scoped guest-agent credential nothing may be read from the remote")
	}
	if recs := e.logs.find("guest_join_agent_fallback", ""); len(recs) != 1 || recs[0].attrs["reason"] != pveJoinNoCredential {
		t.Fatalf("fallback audit = %+v", recs)
	}
	d, _ := canonical.ParseDigest(resp.GetPermit().GetExecutionDigest())
	if _, err := e.svc.auth.ApproveCLI(d, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	c, err := e.svc.CommitGuestJoin(ctx, &pb.CommitGuestJoinRequest{ExecutionDigest: d.String(), Guest: resp.GetGuest(),
		Host: resp.GetHost(), JoinMethod: resp.GetJoinMethod()})
	if err != nil {
		t.Fatal(err)
	}
	if !c.GetResult().GetPinned() || c.GetExecutionDigest() != d.String() || c.GetJoinMethod() != PveJoinMethodReview ||
		c.GetGuest().GetVmid() != 101 || c.GetGuest().GetGuestUuid() != testJoinUUID || c.GetHost().GetHostId() != "web1" ||
		c.GetHost().GetKeyType() != "" {
		t.Fatalf("commit = %+v", c)
	}
	_, err = e.svc.CommitGuestJoin(ctx, &pb.CommitGuestJoinRequest{ExecutionDigest: d.String(), Guest: resp.GetGuest(),
		Host: resp.GetHost(), JoinMethod: PveJoinMethodAgent})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("changed join method: err = %v, want PermissionDenied", err)
	}
}

func TestGuestJoinReaderUsesScopedCredentialOverPinnedChannel(t *testing.T) {
	e := newGuestRPCEnv(t)
	p, err := e.readerPropose()
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != PveJoinMethodAgent || p.Fingerprint != sshtransport.Fingerprint(e.ssh.hostKey.PublicKey()) {
		t.Fatalf("proposal = %+v, want agent-verified", p)
	}
	// Guest list before and after the read with the read token, the file
	// read with the scoped credential only.
	if e.pve.badAuth.Load() != 0 || e.pve.requests.Load() != 3 {
		t.Fatalf("requests = %d (bad auth %d)", e.pve.requests.Load(), e.pve.badAuth.Load())
	}
}

func TestGuestJoinReaderNeverSendsReadTokenToFileRead(t *testing.T) {
	e := newGuestRPCEnv(t)
	j := e.readerJoin()
	j.AgentCredentials = &fakeAgentCreds{token: "PVEAPIToken=" + pveReadToken}
	r := e.rpcRequest()
	p, err := j.Propose(context.Background(), PveGuestJoinRequest{RemoteID: pveReadRemote, Node: "pve1", VMID: 101,
		Generation: 1, GuestName: "web1.lab.test", GuestUUID: testJoinUUID, HostID: "web1", Endpoint: r.Host.Endpoint,
		SSHUser: "nos", CredentialRef: "cred"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != PveJoinMethodReview || e.pve.badAuth.Load() != 1 {
		t.Fatalf("method %s, refused requests %d: the file read must not accept the read token", p.Method, e.pve.badAuth.Load())
	}
}

func TestGuestJoinReaderFallsBackOnUnsafeAgentAnswer(t *testing.T) {
	cases := map[string]string{
		"truncated":  `{"data":{"content":"ssh-ed25519 AAAA","truncated":1}}`,
		"oversize":   `{"data":{"content":"` + strings.Repeat("A", maxPveAgentHostKeyBytes+1) + `"}}`,
		"extra":      `{"data":{"content":"x","size":1}}`,
		"not a key":  `{"data":{"content":"\u001b]0;pwned\u0007\n"}}`,
		"agent down": ``,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newGuestRPCEnv(t)
			if body == "" {
				e.pve.mu.Lock()
				delete(e.pve.bodies, "/api2/json/nodes/pve1/qemu/101/agent/file-read")
				e.pve.mu.Unlock()
			} else {
				e.pve.set("/api2/json/nodes/pve1/qemu/101/agent/file-read", body)
			}
			p, err := e.readerPropose()
			if err != nil {
				t.Fatal(err)
			}
			if p.Method != PveJoinMethodReview || p.AgentDetail == "" || strings.ContainsAny(p.AgentDetail, "\x1b\x07") {
				t.Fatalf("proposal = %+v, want review with a fixed reason", p)
			}
		})
	}
}

func TestGuestJoinReaderTrustChangeBlocksRemote(t *testing.T) {
	e := newGuestRPCEnv(t)
	impostor := makeTestChain(t)
	e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
	e.pve.srv.CloseClientConnections()
	p, err := e.readerPropose()
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != PveJoinMethodReview {
		t.Fatalf("method = %s, want review", p.Method)
	}
	if e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
		t.Fatal("a request reached the impostor")
	}
	if rm := e.remote(); rm.State != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", rm.State)
	}
}

func TestGuestJoinRPCMapsErrors(t *testing.T) {
	e := newGuestRPCEnv(t)
	_, err := e.svc.ProposeGuestJoin(context.Background(), &pb.ProposeGuestJoinRequest{
		Guest: &pb.GuestJoinTarget{RemoteId: pveReadRemote, Node: "pve1", Vmid: 1, Generation: 1, GuestName: "web1.lab.test"},
		Host:  &pb.EnrollHost{HostId: "web1", Endpoint: e.ssh.addr},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
	_, err = e.svc.CommitGuestJoin(context.Background(), &pb.CommitGuestJoinRequest{ExecutionDigest: "nope"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}
