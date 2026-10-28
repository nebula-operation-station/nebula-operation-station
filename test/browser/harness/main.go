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
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/descope/virtualwebauthn"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
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

func (d direct) BackupExecutor(ctx context.Context, in *pb.BackupExecutorRequest, _ ...grpc.CallOption) (*pb.BackupExecutorResponse, error) {
	return d.s.BackupExecutor(ctx, in)
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

func (d direct) GetPermitState(ctx context.Context, in *pb.GetPermitStateRequest, _ ...grpc.CallOption) (*pb.GetPermitStateResponse, error) {
	return d.s.GetPermitState(ctx, in)
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
	args := os.Args[1:]
	// -preview serves the UI without the WebAuthn session check and seeds
	// demo data, for a human to look at the pages (make test-browser uses
	// the harness without the flag and must keep its login flow).
	preview := false
	if len(args) > 0 && args[0] == "-preview" {
		preview = true
		args = args[1:]
	}
	if len(args) < 2 {
		panic("usage: harness [-preview] PORT DIR")
	}
	port, dir := args[0], args[1]
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
	_, _, err = db.RegisterEventKey(chain.PublicKey())
	must(err)
	svc.SetBackupDirs(exDir, kd)
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
	securityKeys := func(ctx context.Context) ([]*pb.WebAuthnCredential, error) {
		r, err := svc.ListWebAuthnCredentials(ctx, &pb.ListWebAuthnCredentialsRequest{})
		return r.GetCredentials(), err
	}
	totpStatus := func(ctx context.Context) (*pb.GetTOTPStatusResponse, error) {
		return svc.GetTOTPStatus(ctx, &pb.GetTOTPStatusRequest{})
	}
	// Discovery with a spool; the test hook below answers queued jobs the
	// way nebula-discovery would, with fixed hosts.
	spool := discoveryjob.Spool{Dir: filepath.Join(dir, "discovery")}
	must(os.MkdirAll(spool.JobsDir(), 0o750))
	must(os.MkdirAll(spool.ResultsDir(), 0o750))
	ipamStore := ipam.New(sdb, ipam.FromInventory(inv.List))
	disc := discovery.New(sdb, spool, ipamStore, ipam.FromInventory(inv.List), log)
	audit := auditlog.New(sdb, true)
	u, err := ui.New(ui.Options{PublicOrigin: origin, Events: direct{svc}, Audit: audit, Status: direct{svc}, Hosts: inv.List, HostKeys: hostKeys, Inventory: inv, Operations: ops, Pins: inv, Schedules: ops, Runbooks: rb, Trust: direct{svc}, Modules: mods, LastResult: ops.LastResult, Network: ipamStore, Discovery: disc, Repin: direct{svc}, Enroll: direct{svc}, SecurityKeys: securityKeys, TOTPStatus: totpStatus, Log: slog.New(auditlog.NewHandler(base, audit))})
	must(err)
	if preview {
		seedPreview(context.Background(), svc, sdb, inv, rb, sshPub, origin)
	}
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
	mount := u.Handler()
	if !preview {
		mount = ah.Wrap(mount)
	}
	mux.Handle("/", middleware.Handler(middleware.Options{PublicOrigin: origin}, mount))
	must(http.ListenAndServe("127.0.0.1:"+port, mux))
}

// ---------------------------------------------------------------------------
// Preview mode (-preview): seed a small lab so a human can look at the pages.
// It is test-only: it never runs in a release and only in this binary.

// newID36 returns a random 36-character identifier (UUID-shaped), the length
// the executions and discovery_jobs tables require.
func newID36() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func jsonDoc(v any) []byte {
	js, err := json.Marshal(v)
	must(err)
	return js
}

// factsResult builds a core.facts result (values base64, spec 09).
func factsResult(osRelease, uname, hostname, uptime string, proxmox bool) []byte {
	return jsonDoc(map[string]any{"os_release": b64(osRelease), "uname": b64(uname),
		"hostname": b64(hostname), "uptime": b64(uptime), "proxmox": proxmox})
}

func dockerListResult(version string, containers ...string) []byte {
	return jsonDoc(map[string]any{"format": "docker-ps-v1", "phase": "done", "present": true,
		"version": b64(version), "containers": b64(strings.Join(containers, "\n"))})
}

func dockerUpdatesResult(lines ...string) []byte {
	return jsonDoc(map[string]any{"format": "docker-updates-v1", "phase": "done",
		"lines": b64(strings.Join(lines, "\n"))})
}

func serviceListResult(units ...string) []byte {
	return jsonDoc(map[string]any{"format": "systemd-units-v1",
		"units": b64(strings.Join(units, "\n"))})
}

// seedExec inserts one execution (and its per-host row) with the real
// action's module version and artifact hash. finishedAt zero means the
// execution has not finished.
func seedExec(ctx context.Context, sdb *sql.DB, actionID, hostID string, result []byte, finishedAt time.Time, execState, hostState, class string) string {
	return seedExecAt(ctx, sdb, actionID, hostID, result, finishedAt.Add(-2*time.Minute), finishedAt, execState, hostState, class)
}

// seedExecAt is seedExec with an explicit creation time (for executions
// that have not finished yet, whose creation is not derived from the
// finish time).
func seedExecAt(ctx context.Context, sdb *sql.DB, actionID, hostID string, result []byte, created, finishedAt time.Time, execState, hostState, class string) string {
	a, ok := actions.Lookup(actionID)
	if !ok {
		panic("no action " + actionID)
	}
	id := newID36()
	var fin interface{}
	if !finishedAt.IsZero() {
		fin = finishedAt.Unix()
	}
	_, err := sdb.ExecContext(ctx, `INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at, finished_at, params)
		VALUES (?, ?, ?, ?, 'LOW', ?, 0, 300, 'demo', ?, ?, '{}')`,
		id, a.ID, a.Version, a.SHA256(), execState, created.Unix(), fin)
	must(err)
	var res interface{}
	if result != nil {
		res = result
	}
	_, err = sdb.ExecContext(ctx, `INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, exit_code, result, started_at, finished_at)
		VALUES (?, ?, 'SHA256:demo', 'nebula-default', '127.0.0.1:22', ?, ?, 0, ?, ?, ?)`,
		id, hostID, hostState, class, res, created.Unix(), fin)
	must(err)
	return id
}

// seedUpdates stores a parsed package.list_updates for host.
func seedUpdates(ctx context.Context, sdb *sql.DB, hostID, execID string, pkgs []osdebian.Package, total, security, kernel int, reboot bool, observedAt time.Time) {
	js, err := json.Marshal(pkgs)
	must(err)
	var rebootI int
	if reboot {
		rebootI = 1
	}
	_, err = sdb.ExecContext(ctx, `INSERT INTO host_updates (host_id, observed_at, execution_id, total, security, kernel, reboot_required, lists_updated, packages)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(host_id) DO UPDATE SET
		observed_at=excluded.observed_at, execution_id=excluded.execution_id, total=excluded.total, security=excluded.security,
		kernel=excluded.kernel, reboot_required=excluded.reboot_required, lists_updated=excluded.lists_updated, packages=excluded.packages`,
		hostID, observedAt.Unix(), execID, total, security, kernel, rebootI, observedAt.Add(-time.Hour).Unix(), string(js))
	must(err)
}

// seedOpsState stores the last Ops State of host.
func seedOpsState(ctx context.Context, sdb *sql.DB, hostID, state, reason string, observedAt time.Time) {
	_, err := sdb.ExecContext(ctx, `INSERT INTO host_ops_state (host_id, state, reason, source, observed_at, changed_at)
		VALUES (?, ?, ?, 'demo', ?, ?) ON CONFLICT(host_id) DO UPDATE SET
		state=excluded.state, reason=excluded.reason, observed_at=excluded.observed_at, changed_at=excluded.changed_at`,
		hostID, state, reason, observedAt.Unix(), observedAt.Unix())
	must(err)
}

// pinHost starts an in-process SSH server, pins its key for id and creates
// the inventory host. It returns the endpoint.
func pinHost(ctx context.Context, svc *executor.Service, inv *inventory.Store, sshPub ssh.PublicKey, id, display string, env inventory.Environment, crit inventory.Criticality) inventory.Endpoint {
	h, _, err := hostruntest.Serve(sshPub)
	must(err)
	probe, err := svc.ProbeHostKey(ctx, &pb.ProbeHostKeyRequest{Endpoint: h.Addr})
	must(err)
	_, err = svc.PinHostKey(ctx, &pb.PinHostKeyRequest{HostId: id, AuthorizedKey: probe.GetAuthorizedKey(),
		ExpectedFingerprint: probe.GetFingerprint(), SshUser: "nebula", CredentialRef: "nebula-default", Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE})
	must(err)
	return createInventoryHost(ctx, inv, id, display, env, crit, h.Addr)
}

// pinBlockedHost pins the key on one server, then reaches the host at a
// different server: the key changed, so the pin blocks.
func pinBlockedHost(ctx context.Context, svc *executor.Service, inv *inventory.Store, sshPub ssh.PublicKey, id, display string, env inventory.Environment, crit inventory.Criticality) inventory.Endpoint {
	old, _, err := hostruntest.Serve(sshPub)
	must(err)
	probe, err := svc.ProbeHostKey(ctx, &pb.ProbeHostKeyRequest{Endpoint: old.Addr})
	must(err)
	_, err = svc.PinHostKey(ctx, &pb.PinHostKeyRequest{HostId: id, AuthorizedKey: probe.GetAuthorizedKey(),
		ExpectedFingerprint: probe.GetFingerprint(), SshUser: "nebula", CredentialRef: "nebula-default", Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE})
	must(err)
	cur, _, err := hostruntest.Serve(sshPub)
	must(err)
	_, err = svc.TestConnection(ctx, &pb.TestConnectionRequest{HostId: id, Endpoints: []string{cur.Addr}})
	must(err)
	return createInventoryHost(ctx, inv, id, display, env, crit, cur.Addr)
}

// unenrolledHost creates an inventory host without a pinned key.
func unenrolledHost(ctx context.Context, inv *inventory.Store, sshPub ssh.PublicKey, id, display string, env inventory.Environment, crit inventory.Criticality) inventory.Endpoint {
	h, _, err := hostruntest.Serve(sshPub)
	must(err)
	return createInventoryHost(ctx, inv, id, display, env, crit, h.Addr)
}

func createInventoryHost(ctx context.Context, inv *inventory.Store, id, display string, env inventory.Environment, crit inventory.Criticality, addr string) inventory.Endpoint {
	a, portStr, err := net.SplitHostPort(addr)
	must(err)
	port, err := strconv.Atoi(portStr)
	must(err)
	ep := inventory.Endpoint{Address: a, Port: port}
	_, err = inv.Create(ctx, inventory.Host{ID: id, DisplayName: display, Environment: env, Criticality: crit, Endpoints: []inventory.Endpoint{ep}}, inventory.CreateOptions{})
	must(err)
	return ep
}

// seedPreviewKeys registers two security keys (a hardware key and a
// passkey) through the real registration RPCs with virtual
// authenticators, and enables TOTP recovery. The second key is confirmed
// with the first, exactly like the browser flow, so the Settings page
// shows a populated key table and the recovery status.
func seedPreviewKeys(ctx context.Context, svc *executor.Service, origin string) {
	rp := virtualwebauthn.RelyingParty{Name: "Nebula", ID: "localhost", Origin: origin}
	type demoKey struct {
		label  string
		aaguid string
	}
	keys := []demoKey{
		{"YubiKey 5C NFC", "4c6f7562694b65790000000000000001"},
		{"MacBook Touch ID", "00112233445566778899aabbccddeeff"},
	}
	var confirm virtualwebauthn.Authenticator
	var confirmCred virtualwebauthn.Credential
	for i, k := range keys {
		ca, err := svc.CreateRegistrationCode(ctx, &pb.CreateRegistrationCodeRequest{UserName: "demo", Label: k.label})
		must(err)
		b, err := svc.BeginRegistration(ctx, &pb.BeginRegistrationRequest{Code: ca.GetCode()})
		must(err)
		opts, err := virtualwebauthn.ParseAttestationOptions(string(b.GetCreationOptionsJson()))
		must(err)
		a := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{})
		if js, err := hex.DecodeString(k.aaguid); err == nil && len(js) == len(a.Aaguid) {
			copy(a.Aaguid[:], js)
		}
		c := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		a.AddCredential(c)
		req := &pb.FinishRegistrationRequest{RegistrationId: b.GetRegistrationId(),
			AttestationJson: []byte(virtualwebauthn.CreateAttestationResponse(rp, a, c, *opts))}
		if b.GetAuthorizationOptionsJson() != nil {
			// Keys already exist: the new one must be confirmed by an
			// existing key (decisions 27, 37).
			ao, err := virtualwebauthn.ParseAssertionOptions(string(b.GetAuthorizationOptionsJson()))
			must(err)
			req.AssertionJson = []byte(virtualwebauthn.CreateAssertionResponse(rp, confirm, confirmCred, *ao))
		}
		_, err = svc.FinishRegistration(ctx, req)
		must(err)
		if i == 0 {
			confirm, confirmCred = a, c
		}
	}
	// TOTP recovery, like `nebula totp setup` on the executor host.
	b, err := svc.BeginTOTPSetup(ctx, &pb.BeginTOTPSetupRequest{})
	must(err)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b.GetSecretBase32())
	must(err)
	_, err = svc.ConfirmTOTPSetup(ctx, &pb.ConfirmTOTPSetupRequest{Code: totp.Code(secret, time.Now())})
	must(err)
}

// seedPreview seeds the demo lab: eight hosts in different states, their
// stored read-only results, update lists, ops states, two networks with
// assets and a finished discovery job. It also registers two security keys
// and enables TOTP recovery so the Settings page shows real content.
func seedPreview(ctx context.Context, svc *executor.Service, sdb *sql.DB, inv *inventory.Store, rb *runbooks.Store, sshPub ssh.PublicKey, origin string) {
	now := time.Now()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }

	// --- Sign-in and security keys (Settings page) ---------------------
	seedPreviewKeys(ctx, svc, origin)

	// --- Hosts ---------------------------------------------------------
	pinHost(ctx, svc, inv, sshPub, "web", "Web server", inventory.EnvProd, inventory.CriticalityMedium)
	pinHost(ctx, svc, inv, sshPub, "nas", "Storage", inventory.EnvProd, inventory.CriticalityHigh)
	pinHost(ctx, svc, inv, sshPub, "pve", "Proxmox", inventory.EnvProd, inventory.CriticalityHigh)
	pinHost(ctx, svc, inv, sshPub, "db", "Database", inventory.EnvProd, inventory.CriticalityCritical)
	pinHost(ctx, svc, inv, sshPub, "cache", "Cache", inventory.EnvDev, inventory.CriticalityLow)
	pinHost(ctx, svc, inv, sshPub, "ci", "CI runner", inventory.EnvDev, inventory.CriticalityLow)
	unenrolledHost(ctx, inv, sshPub, "printer", "Printer", inventory.EnvDev, inventory.CriticalityLow)
	pinBlockedHost(ctx, svc, inv, sshPub, "old", "Old server", inventory.EnvDev, inventory.CriticalityLow)

	// --- Pinned actions (quick-action bar on the host page) -----------
	must(inv.SetPinnedActions(ctx, "web", []string{"core.facts", "service.list", "service.status"}, "demo"))
	must(inv.SetPinnedActions(ctx, "nas", []string{"package.install_security", "system.reboot"}, "demo"))

	// --- A runbook (so the pin-to-hosts box is visible) ---------------
	_, err := rb.Save(ctx, "demo", runbooks.Draft{
		Slug: "backup_check", Title: "Backup check",
		Description: "Read-only check that the nightly backup ran and the latest archive is present.",
		Risk:        "LOW", TimeoutS: 300,
		Body: "ls -1 /var/backups | tail -n 5",
	})
	must(err)

	// --- Facts ---------------------------------------------------------
	deb12 := "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\""
	ubu24 := "PRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\""
	pveOS := "PRETTY_NAME=\"Proxmox Virtual Environment 8.1\"\nID=debian\nVERSION_ID=\"12\""
	seedExec(ctx, sdb, "core.facts", "web", factsResult(deb12, "Linux web 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64", "web", "1234567", false), ago(6*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "core.facts", "nas", factsResult(ubu24, "Linux nas 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC x86_64", "nas", "864000", false), ago(9*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "core.facts", "pve", factsResult(pveOS, "Linux pve 6.8.12-8-pve #1 SMP PVE 6.8.12-8 (2024-05-01) x86_64", "pve", "5184000", true), ago(12*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "core.facts", "db", factsResult(ubu24, "Linux db 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC x86_64", "db", "864000", false), ago(15*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "core.facts", "cache", factsResult(deb12, "Linux cache 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64", "cache", "259200", false), ago(20*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "core.facts", "ci", factsResult(deb12, "Linux ci 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64", "ci", "43200", false), ago(30*time.Minute), "finished", "finished", "success")

	// --- Updates -------------------------------------------------------
	nasPkgs := []osdebian.Package{
		{Name: "openssl", From: "3.0.13-0ubuntu3", To: "3.0.13-0ubuntu3.4", Archives: []string{"ubuntu-security"}, Arch: "amd64", Security: true},
		{Name: "linux-image-generic", From: "6.8.0-40.40", To: "6.8.0-45.45", Archives: []string{"ubuntu-security", "ubuntu-updates"}, Arch: "amd64", Security: true, Kernel: true},
		{Name: "libc6", From: "2.39-0ubuntu8", To: "2.39-0ubuntu8.5", Archives: []string{"ubuntu-security"}, Arch: "amd64", Security: true},
	}
	nasExec := seedExec(ctx, sdb, "package.list_updates", "nas", nil, ago(9*time.Minute), "finished", "finished", "success")
	seedUpdates(ctx, sdb, "nas", nasExec, nasPkgs, 3, 3, 1, true, ago(9*time.Minute))
	dbPkgs := []osdebian.Package{
		{Name: "postgresql-16", From: "16.2-1", To: "16.3-1", Archives: []string{"ubuntu-updates"}, Arch: "amd64"},
	}
	dbExec := seedExec(ctx, sdb, "package.list_updates", "db", nil, ago(15*time.Minute), "finished", "finished", "success")
	seedUpdates(ctx, sdb, "db", dbExec, dbPkgs, 1, 0, 0, false, ago(15*time.Minute))
	seedExec(ctx, sdb, "package.list_updates", "web", nil, ago(6*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "package.list_updates", "pve", nil, ago(12*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "package.list_updates", "cache", nil, ago(20*time.Minute), "finished", "finished", "success")

	// --- Containers ----------------------------------------------------
	// pve: five containers, one exited, one with an image update.
	seedExec(ctx, sdb, "docker.list", "pve", dockerListResult("26.1.4",
		"a1b2c3d4e5f6\tpve-backup\tproxmox/proxmox-backup-server:3.0\trunning\tUp 2 months (healthy)\t0.0.0.0:1020->1020/tcp\t\t\t",
		"b2c3d4e5f6a1\tpve-nginx\tnginx:1.25\trunning\tUp 5 days\t0.0.0.0:80->80/tcp\t\t\t",
		"c3d4e5f6a1b2\tpve-redis\tredis:7\trunning\tUp 5 days (healthy)\t\t\t\t",
		"d4e5f6a1b2c3\tpve-grafana\tgrafana/grafana:10.4\trunning\tUp 3 days\t0.0.0.0:3000->3000/tcp\t\t\t",
		"e5f6a1b2c3d4\tpve-migration\tmigration:2024.05\texited\tExited (0) 2 hours ago\t\t\t\t"), ago(12*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "docker.check_updates", "pve", dockerUpdatesResult(
		"proxmox/proxmox-backup-server:3.0\tcurrent\t"+digest("pve-backup")+"\tlatest",
		"nginx:1.25\tcurrent\t"+digest("nginx")+"\tlatest",
		"redis:7\tcurrent\t"+digest("redis")+"\tlatest",
		"grafana/grafana:10.4\tupdate\t"+digest("grafana")+"\tnew version available"), ago(12*time.Minute), "finished", "finished", "success")
	// db: four containers; one image has an update, one name is a script
	// tag (the bounded parser drops it) and one image carries a script tag
	// (rendered as text only).
	seedExec(ctx, sdb, "docker.list", "db", dockerListResult("26.1.4",
		"f6a1b2c3d4e5\tdb-postgres\tpostgres:16\trunning\tUp 10 days (healthy)\t127.0.0.1:5432->5432/tcp\t\t\t",
		"a7b8c9d0e1f2\tdb-admin\tpgadmin/pgadmin4:8\trunning\tUp 10 days\t0.0.0.0:5050->80/tcp\t\t\t",
		"b8c9d0e1f2a3\tdb-backup\tdb-backup:1.2\texited\tExited (1) 3 days ago\t\t\t\t",
		"c9d0e1f2a3b4\txss-test\tevil <script>alert(1)</script>\trunning\tUp 1 hour\t\t\t\t",
		"d0e1f2a3b4c5\t<script>alert(1)</script>\tevil:1\trunning\tUp 1 hour\t\t\t\t"), ago(15*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "docker.check_updates", "db", dockerUpdatesResult(
		"postgres:16\tcurrent\t"+digest("postgres")+"\tlatest",
		"pgadmin/pgadmin4:8\tupdate\t"+digest("pgadmin")+"\tnew version available",
		"db-backup:1.2\tcurrent\t"+digest("db-backup")+"\tlatest"), ago(15*time.Minute), "finished", "finished", "success")

	// --- Services ------------------------------------------------------
	seedExec(ctx, sdb, "service.list", "web", serviceListResult(
		"nginx.service\tloaded\tactive\trunning\tA high performance web server",
		"ssh.service\tloaded\tactive\trunning\tOpenBSD Secure Shell server",
		"cron.service\tloaded\tactive\trunning\tPackage-based dependency management"), ago(6*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "service.list", "nas", serviceListResult(
		"nfs-kernel-server.service\tloaded\tactive\trunning\tNFS kernel daemon",
		"smartd.service\tloaded\tactive\trunning\tDisk Smart Monitoring",
		"ssh.service\tloaded\tactive\trunning\tOpenBSD Secure Shell server"), ago(9*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "service.list", "pve", serviceListResult(
		"pveproxy.service\tloaded\tactive\trunning\tProxmox Virtual Environment web interface",
		"pve-firewall.service\tloaded\tactive\trunning\tProxmox Virtual Environment firewall",
		"ssh.service\tloaded\tactive\trunning\tOpenBSD Secure Shell server"), ago(12*time.Minute), "finished", "finished", "success")
	seedExec(ctx, sdb, "service.list", "db", serviceListResult(
		"postgresql@16-main.service\tloaded\tactive\trunning\tPostgreSQL 16 database cluster",
		"ssh.service\tloaded\tactive\trunning\tOpenBSD Secure Shell server"), ago(15*time.Minute), "finished", "finished", "success")
	// cache: one failed unit, so the failed-services tile and filter work.
	seedExec(ctx, sdb, "service.list", "cache", serviceListResult(
		"redis-server.service\tloaded\tactive\trunning\tAdvanced key-value store",
		"cups.service\tloaded\tfailed\tfailed\tCUPS printing service",
		"ssh.service\tloaded\tactive\trunning\tOpenBSD Secure Shell server"), ago(20*time.Minute), "finished", "finished", "success")

	// --- Ops states ----------------------------------------------------
	seedOpsState(ctx, sdb, "web", executions.StateReady, "no pending work", ago(6*time.Minute))
	seedOpsState(ctx, sdb, "nas", executions.StateWarning, "3 security updates, reboot required", ago(9*time.Minute))
	seedOpsState(ctx, sdb, "pve", executions.StateReady, "no pending work", ago(12*time.Minute))
	seedOpsState(ctx, sdb, "db", executions.StateReady, "1 update pending", ago(15*time.Minute))
	seedOpsState(ctx, sdb, "cache", executions.StateWarning, "1 failed service", ago(20*time.Minute))
	seedOpsState(ctx, sdb, "ci", executions.StateUnreachable, "no answer on 192.168.10.42:22", ago(30*time.Minute))

	// --- A few executions in other states (operations tab) -------------
	seedExecAt(ctx, sdb, "package.install_security", "nas", nil, ago(5*time.Minute), time.Time{}, "pending", "waiting", "")
	seedExecAt(ctx, sdb, "package.install_security", "web", nil, ago(2*time.Minute), time.Time{}, "running", "running", "")
	seedExec(ctx, sdb, "system.reboot", "nas", nil, ago(2*time.Hour), "failed", "finished", "not_executed")
	seedExec(ctx, sdb, "core.facts", "ci", nil, ago(30*time.Minute), "failed", "finished", "unreachable")

	// --- Stale host ----------------------------------------------------
	// backup was last read 48 h ago: the inventory marks it stale and the
	// dashboard tile counts it.
	pinHost(ctx, svc, inv, sshPub, "backup", "Backup server", inventory.EnvProd, inventory.CriticalityMedium)
	seedExec(ctx, sdb, "core.facts", "backup", factsResult(deb12, "Linux backup 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64", "backup", "432000", false), ago(48*time.Hour), "finished", "finished", "success")

	// --- Schedules -----------------------------------------------------
	seedSchedules(ctx, sdb, now)

	// --- Networks, assets, discovery -----------------------------------
	seedNetworks(ctx, sdb, now)
}

// seedSchedules stores one active and one pending schedule, and one
// finished run of the active one, so the schedules page shows both cards
// with their last run.
func seedSchedules(ctx context.Context, sdb *sql.DB, now time.Time) {
	acts, _ := json.Marshal([]string{"core.facts", "package.list_updates", "docker.list", "service.list"})
	hosts, _ := json.Marshal([]string{"web", "nas", "db"})
	active := newID36()
	_, err := sdb.ExecContext(ctx, `INSERT INTO schedules (id, digest, state, actions, hosts, interval_s, expires_at, options, created_by, created_at, approved_at)
		VALUES (?, ?, 'active', ?, ?, 21600, ?, NULL, 'demo', ?, ?)`,
		active, strings.Repeat("ab", 32), string(acts), string(hosts), now.Add(30*24*time.Hour).Unix(), now.Add(-7*24*time.Hour).Unix(), now.Add(-7*24*time.Hour).Unix())
	must(err)
	// One finished run of the active schedule, two hours ago.
	a, _ := actions.Lookup("core.facts")
	runID := newID36()
	_, err = sdb.ExecContext(ctx, `INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
		durable, timeout_s, created_by, created_at, finished_at, params, schedule_id)
		VALUES (?, '', ?, ?, ?, 'LOW', 'schedule grant', 'finished', 0, ?, 'schedule', ?, ?, '{}', ?)`,
		runID, a.ID, a.Version, a.SHA256(), int64(a.Timeout/time.Second), now.Add(-2*time.Hour).Unix(), now.Add(-2*time.Hour).Unix(), active)
	must(err)
	// Pending: two reads on ci, daily, proposed an hour ago.
	pacts, _ := json.Marshal([]string{"core.facts", "package.list_updates"})
	phosts, _ := json.Marshal([]string{"ci"})
	opts := `{"challenge":"ZGVtby1jaGFsbGVuZ2U","rpId":"demo","timeout":60000,"userVerification":"required"}`
	_, err = sdb.ExecContext(ctx, `INSERT INTO schedules (id, digest, state, actions, hosts, interval_s, expires_at, options, created_by, created_at)
		VALUES (?, ?, 'pending', ?, ?, 86400, ?, ?, 'demo', ?)`,
		newID36(), strings.Repeat("cd", 32), string(pacts), string(phosts), now.Add(30*24*time.Hour).Unix(), opts, now.Add(-time.Hour).Unix())
	must(err)
}

// digest returns a fixed 64-hex sha256 digest for a docker image.
func digest(image string) string {
	return "sha256:" + sha256hex(image)
}

// sha256hex returns a deterministic 64-hex string derived from image (a
// stand-in for a real digest; the parser only checks the shape).
func sha256hex(image string) string {
	const hexd = "0123456789abcdef"
	var out [64]byte
	seed := uint32(0x811c9dc5)
	for i := 0; i < 64; i++ {
		seed ^= uint32(image[i%len(image)])
		seed *= 0x01000193
		out[i] = hexd[seed&0x0f]
	}
	return string(out[:])
}

// seedNetworks stores two networks, their assets and a finished discovery
// job with staged hosts.
func seedNetworks(ctx context.Context, sdb *sql.DB, now time.Time) {
	_, err := sdb.ExecContext(ctx, `INSERT OR IGNORE INTO networks (id, name, prefix, vlan, gateway, notes) VALUES
		('lan', 'Home LAN', '192.168.10.0/24', 1, '192.168.10.1', 'Main switch'),
		('lab', 'Lab', '192.168.60.0/24', 60, '192.168.60.1', 'Isolated lab VLAN')`)
	must(err)
	_, err = sdb.ExecContext(ctx, `INSERT OR IGNORE INTO assets (id, name, kind, hostname, mac, notes, host_id, updated_at) VALUES
		('fw', 'Firewall', 'firewall', 'fw.lan', 'aa:bb:cc:dd:ee:01', 'OPNsense', '', ?),
		('sw', 'Switch', 'switch', 'sw.lan', 'aa:bb:cc:dd:ee:02', 'UniFi', '', ?),
		('prn', 'Printer', 'printer', 'printer.lan', 'aa:bb:cc:dd:ee:21', 'CUPS ipp', '', ?)`,
		now.Unix(), now.Unix(), now.Unix())
	must(err)
	_, err = sdb.ExecContext(ctx, `INSERT OR IGNORE INTO asset_addresses (asset_id, address) VALUES
		('fw', '192.168.10.1'), ('sw', '192.168.10.2'), ('prn', '192.168.10.21')`)
	must(err)
	jid := newID36()
	_, err = sdb.ExecContext(ctx, `INSERT INTO discovery_jobs (id, spec, description, targets, created_by, created_at, state, finished_at, hosts)
		VALUES (?, '{"networks":["192.168.10.0/24"]}', 'Weekly scan', '192.168.10.0/24', 'demo', ?, 'done', ?, 3)`,
		jid, now.Add(-time.Hour).Unix(), now.Add(-59*time.Minute).Unix())
	must(err)
	_, err = sdb.ExecContext(ctx, `INSERT OR IGNORE INTO discovery_staging (job_id, address, mac, vendor, hostname, os, ports) VALUES
		(?, '192.168.10.21', 'aa:bb:cc:dd:ee:21', 'HP', 'printer.lan', 'Linux', '[{"port":631,"protocol":"tcp","state":"open","service":"ipp"}]'),
		(?, '192.168.10.50', 'aa:bb:cc:dd:ee:50', 'Synology', 'nas.lan', 'DiskStation', '[]'),
		(?, '192.168.10.99', 'aa:bb:cc:dd:ee:99', '', '', '', '[]')`, jid, jid, jid)
	must(err)
}
