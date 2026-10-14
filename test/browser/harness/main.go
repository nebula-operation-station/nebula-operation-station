// SPDX-License-Identifier: AGPL-3.0-or-later

// Command harness runs the executor service in-process together with the
// web login for the browser test (make test-browser). It is test code: it
// serves /__code, which issues a registration code like `nebula webauthn
// code`, without any authentication. Never build it into a release.
//
//	harness PORT DIR
//
// RP ID is "localhost" and the origin http://localhost:PORT, which browsers
// treat as a secure context.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/totp"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// direct calls the service without gRPC; role checks are covered by
// test/security.
type direct struct{ s *executor.Service }

func (d direct) ProposeRepin(ctx context.Context, in *pb.ProposeRepinRequest, _ ...grpc.CallOption) (*pb.ProposeRepinResponse, error) {
	return d.s.ProposeRepin(ctx, in)
}
func (d direct) ProposeEnroll(ctx context.Context, in *pb.ProposeEnrollRequest, _ ...grpc.CallOption) (*pb.ProposeEnrollResponse, error) {
	return d.s.ProposeEnroll(ctx, in)
}
func (d direct) CommitEnroll(ctx context.Context, in *pb.CommitEnrollRequest, _ ...grpc.CallOption) (*pb.CommitEnrollResponse, error) {
	return d.s.CommitEnroll(ctx, in)
}
func (d direct) CommitRepin(ctx context.Context, in *pb.CommitRepinRequest, _ ...grpc.CallOption) (*pb.CommitRepinResponse, error) {
	return d.s.CommitRepin(ctx, in)
}

func (d direct) BeginLogin(ctx context.Context, in *pb.BeginLoginRequest, _ ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	return d.s.BeginLogin(ctx, in)
}
func (d direct) FinishLogin(ctx context.Context, in *pb.FinishLoginRequest, _ ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	return d.s.FinishLogin(ctx, in)
}
func (d direct) BeginRegistration(ctx context.Context, in *pb.BeginRegistrationRequest, _ ...grpc.CallOption) (*pb.BeginRegistrationResponse, error) {
	return d.s.BeginRegistration(ctx, in)
}
func (d direct) FinishRegistration(ctx context.Context, in *pb.FinishRegistrationRequest, _ ...grpc.CallOption) (*pb.FinishRegistrationResponse, error) {
	return d.s.FinishRegistration(ctx, in)
}

func (d direct) BeginPrivilegedSession(ctx context.Context, in *pb.BeginPrivilegedSessionRequest, _ ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error) {
	return d.s.BeginPrivilegedSession(ctx, in)
}

func (d direct) CompletePrivilegedSession(ctx context.Context, in *pb.CompletePrivilegedSessionRequest, _ ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	return d.s.CompletePrivilegedSession(ctx, in)
}

func (d direct) Lock(ctx context.Context, in *pb.LockRequest, _ ...grpc.CallOption) (*pb.LockResponse, error) {
	return d.s.Lock(ctx, in)
}

func (d direct) GetStatus(ctx context.Context, in *pb.GetStatusRequest, _ ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	return d.s.GetStatus(ctx, in)
}

func (d direct) CheckCredential(ctx context.Context, in *pb.CheckCredentialRequest, _ ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	return d.s.CheckCredential(ctx, in)
}

func (d direct) RecoveryLogin(ctx context.Context, in *pb.RecoveryLoginRequest, _ ...grpc.CallOption) (*pb.RecoveryLoginResponse, error) {
	return d.s.RecoveryLogin(ctx, in)
}

func (d direct) ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, _ ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return d.s.ListHostKeys(ctx, in)
}

func (d direct) ProposeExecution(ctx context.Context, in *pb.ProposeExecutionRequest, _ ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	return d.s.ProposeExecution(ctx, in)
}

func (d direct) SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, _ ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	return d.s.SubmitAssertion(ctx, in)
}

func (d direct) RunAttached(ctx context.Context, in *pb.RunAttachedRequest, _ ...grpc.CallOption) (*pb.RunAttachedResponse, error) {
	return d.s.RunAttached(ctx, in)
}

func (d direct) StartDurable(ctx context.Context, in *pb.StartDurableRequest, _ ...grpc.CallOption) (*pb.StartDurableResponse, error) {
	return d.s.StartDurable(ctx, in)
}

func (d direct) GetRun(ctx context.Context, in *pb.GetRunRequest, _ ...grpc.CallOption) (*pb.GetRunResponse, error) {
	return d.s.GetRun(ctx, in)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	port, dir := os.Args[1], os.Args[2]
	origin := "http://localhost:" + port
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	exDir := filepath.Join(dir, "ex")
	must(os.MkdirAll(exDir, 0o700))
	db, err := executordb.Open(exDir)
	must(err)
	creds, err := executor.LoadCredentials(db, exDir, log)
	must(err)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "localhost", Origins: []string{origin}, Counters: db}, creds)
	must(err)
	rp, err := riskpolicy.New(db)
	must(err)
	a, err := permit.New(permit.Options{Verifier: v, Store: db, RiskPolicy: rp})
	must(err)
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "localhost", Origins: []string{origin}, Audit: executor.RegistrationAuditLogger(log)}, v, db)
	must(err)
	kd := filepath.Join(dir, "keys")
	must(os.MkdirAll(kd, 0o700))
	svc := executor.NewService(a, keyring.New(kd), db, reg, log)
	svc.SetJobConfig(hostrun.JobConfig{JobRoot: filepath.Join(dir, "remote", "jobs"), RunRoot: filepath.Join(dir, "remote", "run")})

	// An enrolled test host: an in-process SSH server that runs commands
	// locally, pinned like `nebula host pin`, with Nebula's key unlocked.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	const keyPass = "browser test passphrase, not a secret"
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "nebula-default", []byte(keyPass))
	must(err)
	must(os.WriteFile(filepath.Join(kd, "nebula-default.key"), pem.EncodeToMemory(block), 0o600))
	_, err = svc.Unlock(context.Background(), &pb.UnlockRequest{Passphrase: []byte(keyPass)})
	must(err)
	sshPub, err := ssh.NewPublicKey(pub)
	must(err)
	host, _, err := hostruntest.Serve(sshPub)
	must(err)
	probe, err := svc.ProbeHostKey(context.Background(), &pb.ProbeHostKeyRequest{Endpoint: host.Addr})
	must(err)
	_, err = svc.PinHostKey(context.Background(), &pb.PinHostKeyRequest{HostId: "e2e-host", AuthorizedKey: probe.GetAuthorizedKey(),
		ExpectedFingerprint: probe.GetFingerprint(), SshUser: "nebula", CredentialRef: "nebula-default", Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE})
	must(err)
	// A host whose key changed: pinned on one server, then reached at
	// another one, which blocks it (re-pin from the dashboard).
	movedOld, _, err := hostruntest.Serve(sshPub)
	must(err)
	movedNew, _, err := hostruntest.Serve(sshPub)
	must(err)
	mp, err := svc.ProbeHostKey(context.Background(), &pb.ProbeHostKeyRequest{Endpoint: movedOld.Addr})
	must(err)
	_, err = svc.PinHostKey(context.Background(), &pb.PinHostKeyRequest{HostId: "e2e-moved", AuthorizedKey: mp.GetAuthorizedKey(),
		ExpectedFingerprint: mp.GetFingerprint(), SshUser: "nebula", CredentialRef: "nebula-default", Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE})
	must(err)
	_, err = svc.TestConnection(context.Background(), &pb.TestConnectionRequest{HostId: "e2e-moved", Endpoints: []string{movedNew.Addr}})
	must(err)
	hostAddr, hostPort, err := net.SplitHostPort(host.Addr)
	must(err)
	portNum, err := strconv.Atoi(hostPort)
	must(err)

	sdb, err := serverdb.Open(filepath.Join(dir, "server.db"))
	must(err)
	ah, err := auth.New(auth.Options{Executor: direct{svc}, Sessions: auth.NewStore(sdb, nil), Log: log})
	must(err)
	inv := inventory.New(sdb)
	_, err = inv.Create(context.Background(), inventory.Host{ID: "e2e-host", DisplayName: "E2E host", Environment: inventory.EnvDev,
		Criticality: inventory.CriticalityLow, Endpoints: []inventory.Endpoint{{Address: hostAddr, Port: portNum}}}, inventory.CreateOptions{})
	must(err)
	// A new host in the inventory, not yet enrolled (bulk enrollment).
	fresh, _, err := hostruntest.Serve(sshPub)
	must(err)
	freshAddr, freshPort, err := net.SplitHostPort(fresh.Addr)
	must(err)
	freshPortNum, err := strconv.Atoi(freshPort)
	must(err)
	_, err = inv.Create(context.Background(), inventory.Host{ID: "e2e-new", DisplayName: "E2E new host", Environment: inventory.EnvDev,
		Criticality: inventory.CriticalityLow, Endpoints: []inventory.Endpoint{{Address: freshAddr, Port: freshPortNum}}}, inventory.CreateOptions{})
	must(err)
	ops := executions.New(context.Background(), direct{svc}, sdb, inv, log)
	hostKeys := func(ctx context.Context) ([]*pb.HostKeyPin, error) {
		r, err := svc.ListHostKeys(ctx, &pb.ListHostKeysRequest{})
		return r.GetHosts(), err
	}
	u, err := ui.New(ui.Options{PublicOrigin: origin, Status: direct{svc}, Hosts: inv.List, HostKeys: hostKeys, Inventory: inv, Operations: ops, Repin: direct{svc}, Enroll: direct{svc}, Log: log})
	must(err)
	mux := http.NewServeMux()
	// Test hook: issue a one-time code like `nebula webauthn code`.
	mux.HandleFunc("/__code", func(w http.ResponseWriter, r *http.Request) {
		c, err := svc.CreateRegistrationCode(r.Context(), &pb.CreateRegistrationCodeRequest{UserName: "axel", Label: "e2e"})
		must(err)
		fmt.Fprint(w, c.GetCode())
	})
	// Test hooks: set up TOTP recovery like `nebula totp setup`, and give
	// the code for the next step (the current one is used by the setup).
	var totpSecret []byte
	mux.HandleFunc("/__totp/setup", func(w http.ResponseWriter, r *http.Request) {
		b, err := svc.BeginTOTPSetup(r.Context(), &pb.BeginTOTPSetupRequest{})
		must(err)
		totpSecret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b.GetSecretBase32())
		must(err)
		_, err = svc.ConfirmTOTPSetup(r.Context(), &pb.ConfirmTOTPSetupRequest{Code: totp.Code(totpSecret, time.Now())})
		must(err)
	})
	mux.HandleFunc("/__totp/next", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, totp.Code(totpSecret, time.Now().Add(totp.Step)))
	})
	mux.Handle("/", middleware.Handler(middleware.Options{PublicOrigin: origin}, ah.Wrap(u.Handler())))
	must(http.ListenAndServe("127.0.0.1:"+port, mux))
}
