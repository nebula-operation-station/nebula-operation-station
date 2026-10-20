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

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modules"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
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

func (d direct) ListEvents(ctx context.Context, in *pb.ListEventsRequest, _ ...grpc.CallOption) (*pb.ListEventsResponse, error) {
	return d.s.ListEvents(ctx, in)
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

func (d direct) BeginGate(ctx context.Context, in *pb.BeginGateRequest, _ ...grpc.CallOption) (*pb.BeginGateResponse, error) {
	return d.s.BeginGate(ctx, in)
}

func (d direct) CommitGate(ctx context.Context, in *pb.CommitGateRequest, _ ...grpc.CallOption) (*pb.CommitGateResponse, error) {
	return d.s.CommitGate(ctx, in)
}

func (d direct) AbortRollout(ctx context.Context, in *pb.AbortRolloutRequest, _ ...grpc.CallOption) (*pb.AbortRolloutResponse, error) {
	return d.s.AbortRollout(ctx, in)
}

func (d direct) GetRollout(ctx context.Context, in *pb.GetRolloutRequest, _ ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	return d.s.GetRollout(ctx, in)
}

func (d direct) ProposeScheduleGrant(ctx context.Context, in *pb.ProposeScheduleGrantRequest, _ ...grpc.CallOption) (*pb.ProposeScheduleGrantResponse, error) {
	return d.s.ProposeScheduleGrant(ctx, in)
}

func (d direct) CommitScheduleGrant(ctx context.Context, in *pb.CommitScheduleGrantRequest, _ ...grpc.CallOption) (*pb.CommitScheduleGrantResponse, error) {
	return d.s.CommitScheduleGrant(ctx, in)
}

func (d direct) RevokeScheduleGrant(ctx context.Context, in *pb.RevokeScheduleGrantRequest, _ ...grpc.CallOption) (*pb.RevokeScheduleGrantResponse, error) {
	return d.s.RevokeScheduleGrant(ctx, in)
}

func (d direct) RunScheduled(ctx context.Context, in *pb.RunScheduledRequest, _ ...grpc.CallOption) (*pb.RunScheduledResponse, error) {
	return d.s.RunScheduled(ctx, in)
}

func (d direct) ListScheduleGrants(ctx context.Context, in *pb.ListScheduleGrantsRequest, _ ...grpc.CallOption) (*pb.ListScheduleGrantsResponse, error) {
	return d.s.ListScheduleGrants(ctx, in)
}

func (d direct) BeginTrustArtifact(ctx context.Context, in *pb.BeginTrustArtifactRequest, _ ...grpc.CallOption) (*pb.BeginTrustArtifactResponse, error) {
	return d.s.BeginTrustArtifact(ctx, in)
}

func (d direct) CommitTrustArtifact(ctx context.Context, in *pb.CommitTrustArtifactRequest, _ ...grpc.CallOption) (*pb.CommitTrustArtifactResponse, error) {
	return d.s.CommitTrustArtifact(ctx, in)
}

func (d direct) GetArtifactTrust(ctx context.Context, in *pb.GetArtifactTrustRequest, _ ...grpc.CallOption) (*pb.GetArtifactTrustResponse, error) {
	return d.s.GetArtifactTrust(ctx, in)
}

func (d direct) RegisterModule(ctx context.Context, in *pb.RegisterModuleRequest, _ ...grpc.CallOption) (*pb.RegisterModuleResponse, error) {
	return d.s.RegisterModule(ctx, in)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	port, dir := os.Args[1], os.Args[2]
	origin := "http://localhost:" + port
	base := slog.NewTextHandler(os.Stderr, nil)
	exDir := filepath.Join(dir, "ex")
	must(os.MkdirAll(exDir, 0o700))
	db, err := executordb.Open(exDir)
	must(err)
	// The executor's audit lines go to its signed event chain (M10-1).
	eventKey, _, err := events.LoadOrCreateKey(exDir)
	must(err)
	chain := events.NewChain(db, eventKey)
	log := slog.New(events.NewHandler(base, chain))
	creds, err := executor.LoadCredentials(db, exDir, log)
	must(err)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "localhost", Origins: []string{origin}, Counters: db}, creds)
	must(err)
	rp, err := riskpolicy.New(db)
	must(err)
	a, err := permit.New(permit.Options{Verifier: v, Store: db, RiskPolicy: rp, Schedules: db})
	must(err)
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "localhost", Origins: []string{origin}, Audit: executor.RegistrationAuditLogger(log)}, v, db)
	must(err)
	kd := filepath.Join(dir, "keys")
	must(os.MkdirAll(kd, 0o700))
	svc := executor.NewService(a, keyring.New(kd), db, reg, log)
	svc.SetEventKey(chain.PublicKey())
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
	// service.list is trusted as LOW (read-only) and e2e-host is recorded
	// LOW, so it can be scheduled (schedule grants).
	sl, ok := actions.Lookup("service.list")
	if !ok {
		panic("service.list")
	}
	_, err = svc.TrustArtifact(context.Background(), &pb.TrustArtifactRequest{ActionId: sl.ID, ModuleVersion: sl.Version,
		RiskClass: pb.RiskClass_RISK_CLASS_LOW, Artifact: sl.Script, Label: "browser test", ExpectedSha256: sl.SHA256()})
	must(err)
	_, err = svc.SetHostCriticality(context.Background(), &pb.SetHostCriticalityRequest{HostId: "e2e-host",
		HostKeyFingerprint: probe.GetFingerprint(), Criticality: pb.RiskClass_RISK_CLASS_LOW})
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
	// A second enrolled host for the staged rollout (canary first).
	two, _, err := hostruntest.Serve(sshPub)
	must(err)
	tp, err := svc.ProbeHostKey(context.Background(), &pb.ProbeHostKeyRequest{Endpoint: two.Addr})
	must(err)
	_, err = svc.PinHostKey(context.Background(), &pb.PinHostKeyRequest{HostId: "e2e-two", AuthorizedKey: tp.GetAuthorizedKey(),
		ExpectedFingerprint: tp.GetFingerprint(), SshUser: "nebula", CredentialRef: "nebula-default", Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE})
	must(err)
	twoAddr, twoPort, err := net.SplitHostPort(two.Addr)
	must(err)
	twoPortNum, err := strconv.Atoi(twoPort)
	must(err)
	_, err = inv.Create(context.Background(), inventory.Host{ID: "e2e-two", DisplayName: "E2E second host", Environment: inventory.EnvDev,
		Criticality: inventory.CriticalityLow, Endpoints: []inventory.Endpoint{{Address: twoAddr, Port: twoPortNum}}}, inventory.CreateOptions{})
	must(err)
	ops := executions.New(context.Background(), direct{svc}, sdb, inv, log)
	rb := runbooks.New(sdb)
	ops.SetRunbooks(rb)
	mods := modules.New(sdb, direct{svc})
	ops.SetModules(mods)
	hostKeys := func(ctx context.Context) ([]*pb.HostKeyPin, error) {
		r, err := svc.ListHostKeys(ctx, &pb.ListHostKeysRequest{})
		return r.GetHosts(), err
	}
	// Discovery with a spool; the test hook below answers queued jobs the
	// way nebula-discovery would, with fixed hosts.
	spool := discoveryjob.Spool{Dir: filepath.Join(dir, "discovery")}
	must(os.MkdirAll(spool.JobsDir(), 0o750))
	must(os.MkdirAll(spool.ResultsDir(), 0o750))
	ipamStore := ipam.New(sdb, ipam.FromInventory(inv.List))
	disc := discovery.New(sdb, spool, ipamStore, ipam.FromInventory(inv.List), log)
	audit := auditlog.New(sdb, true)
	u, err := ui.New(ui.Options{PublicOrigin: origin, Events: direct{svc}, Audit: audit, Status: direct{svc}, Hosts: inv.List, HostKeys: hostKeys, Inventory: inv, Operations: ops, Schedules: ops, Runbooks: rb, Trust: direct{svc}, Modules: mods, LastResult: ops.LastResult, Network: ipamStore, Discovery: disc, Repin: direct{svc}, Enroll: direct{svc}, Log: slog.New(auditlog.NewHandler(base, audit))})
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
	mux.HandleFunc("/__discovery/answer", func(w http.ResponseWriter, r *http.Request) {
		jobs, _, err := spool.PendingJobs()
		must(err)
		for _, j := range jobs {
			must(spool.WriteResult(discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: j.ID, StartedAt: time.Now().Unix(), FinishedAt: time.Now().Unix(), OK: true,
				Hosts: []discoveryjob.Host{{Address: "192.168.10.21", MAC: "aa:bb:cc:dd:ee:21"},
					{Address: "192.168.10.60", Hostname: "printer.lan", Vendor: "<b>ACME</b>", Ports: []discoveryjob.Port{{Port: 631, Protocol: "tcp", State: "open", Service: "ipp"}}}}}))
		}
		must(disc.Poll(r.Context()))
		fmt.Fprint(w, len(jobs))
	})
	mux.Handle("/", middleware.Handler(middleware.Options{PublicOrigin: origin}, ah.Wrap(u.Handler())))
	must(http.ListenAndServe("127.0.0.1:"+port, mux))
}
