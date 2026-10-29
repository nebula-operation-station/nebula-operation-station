// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestPveAdminRPCRequiresConfiguredAdminRole(t *testing.T) {
	methods := []string{
		pb.ExecutorService_ProbePVERemote_FullMethodName,
		pb.ExecutorService_AddPVERemote_FullMethodName,
		pb.ExecutorService_RotatePVEToken_FullMethodName,
		pb.ExecutorService_RemovePVERemote_FullMethodName,
		pb.ExecutorService_ListPVEAdminRemotes_FullMethodName,
		pb.ExecutorService_ProposePVERepin_FullMethodName,
		pb.ExecutorService_CommitPVERepin_FullMethodName,
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		10001: {peercred.RoleAdmin}, // Personal admin, independent of daemon UID.
		10002: {peercred.RoleServer},
		10003: {peercred.RolePVECollector},
	}, MethodRoles())
	for _, method := range methods {
		if _, ok := policy.Allowed(10001, method); !ok {
			t.Fatalf("personal admin denied %s", method)
		}
		for _, uid := range []uint32{10002, 10003, 10004} {
			if _, ok := policy.Allowed(uid, method); ok {
				t.Fatalf("nonadmin %d allowed %s", uid, method)
			}
		}
	}
	// Also exercise the real Unix handshake and interceptor with a known
	// nonadmin UID. Filesystem/socket access must not confer administration.
	e := newReconcileEnv(t)
	sock := filepath.Join(t.TempDir(), "pve.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewGRPCServer(e.svc, peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}, MethodRoles()), e.svc.log)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); _ = ln.Close() })
	conn, err := grpc.NewClient("passthrough:///executor", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return peercred.DialVerified(ctx, sock, uint32(os.Getuid()))
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = pb.NewExecutorServiceClient(conn).ListPVEAdminRemotes(ctx, &pb.ListPVEAdminRemotesRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("nonadmin RPC: %v", err)
	}
}

func TestPveRepinRequiresExactSingleUseHighApproval(t *testing.T) {
	e := newPveTestEnv(t)
	approval := newReconcileEnv(t)
	svc := approval.svc
	svc.db, svc.vault = e.db, e.vault
	oldChain, newChain := makeTestChain(t), makeTestChain(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{newChain.tls}}
	srv.StartTLS()
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.ParseUint(portText, 10, 16)
	eps := []pvecontract.Endpoint{{Host: host, Port: uint16(port)}}
	e.probe.result = probeResultFrom(oldChain, host)
	oldPin, newPin := fpHex(oldChain.ca), fpHex(newChain.ca)
	if _, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, oldPin, []byte("nosread@pve!read=value")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request := &pb.CommitPVERepinRequest{RemoteId: "lab-pve", OldPin: oldPin, ConfirmedNewPin: newPin}
	if _, err := svc.CommitPVERepin(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("approval bypass: %v", err)
	}
	proposed, err := svc.ProposePVERepin(ctx, &pb.ProposePVERepinRequest{RemoteId: "lab-pve", OldPin: oldPin, ConfirmedNewPin: newPin})
	if err != nil {
		t.Fatal(err)
	}
	proposal := proposed.GetPermit()
	if proposal.RiskClass != pb.RiskClass_RISK_CLASS_HIGH || proposal.ApprovalRequirement != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		t.Fatalf("re-pin approval is not HIGH with UV: %v", proposal)
	}
	request.ExecutionDigest = proposal.ExecutionDigest
	if _, err := svc.CommitPVERepin(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("pending permit accepted: %v", err)
	}
	d, err := canonical.ParseDigest(proposal.ExecutionDigest)
	if err != nil {
		t.Fatal(err)
	}
	// The authenticated local CLI is the existing HIGH approval alternative.
	if _, err := svc.auth.ApproveCLI(d, 0, "personal-admin"); err != nil {
		t.Fatal(err)
	}
	rm, _, _ := e.db.GetRemote("lab-pve")
	for _, change := range []struct {
		name  string
		apply func()
	}{
		{"remote", func() { rm.RemoteID = "other" }},
		{"old pin", func() { rm.TrustPin = fpHex(makeTestChain(t).ca) }},
		{"new pin", func() { request.ConfirmedNewPin = oldPin }},
		{"generation", func() { rm.TrustGeneration++ }},
		{"credential", func() { rm.Credentials.ReadVersion++ }},
		{"endpoint", func() { rm.Endpoints = []pvecontract.Endpoint{{Host: "other.example.test", Port: 8006}} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			rm, _, _ = e.db.GetRemote("lab-pve")
			request.ConfirmedNewPin = newPin
			change.apply()
			if err := svc.authorizePVERepin(ctx, rm, PveRepin{ApprovalDigest: proposal.ExecutionDigest, ConfirmedNewPin: request.ConfirmedNewPin}); err == nil {
				t.Fatal("approval accepted changed binding")
			}
		})
	}
	request.ConfirmedNewPin = newPin
	result, err := svc.CommitPVERepin(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.GetRemote().TrustPin != newPin || result.GetRemote().TrustGeneration != 2 {
		t.Fatalf("re-pin result: %v", result)
	}
	if _, err := svc.CommitPVERepin(ctx, request); err == nil {
		t.Fatal("approval replay accepted")
	}
}
