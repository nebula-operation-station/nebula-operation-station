// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// allRoles may call every executor method, so the tests reach the I1
// gate behind the role check for each of them.
var allRoles = []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector, peercred.RoleNetDevCollector}

// integrityRPCConn serves s on a Unix socket in a temporary directory,
// with the test UID in roles.
func integrityRPCConn(t *testing.T, s *Service, roles ...peercred.Role) *grpc.ClientConn {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "x.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): roles}, MethodRoles())
	srv := NewGRPCServer(s, policy, s.log)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); _ = ln.Close() })
	conn, err := grpc.NewClient("passthrough:///executor", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, sock, uint32(os.Getuid()))
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func lockedMethods() []string {
	var out []string
	for m, locked := range integrityLockedMethods {
		if locked {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// isIntegrityLocked reports the fixed refusal.
func isIntegrityLocked(err error) bool {
	return status.Code(err) == codes.FailedPrecondition && strings.HasPrefix(status.Convert(err).Message(), "integrity_locked:")
}

// invokeEmpty calls method with an empty request; the I1 gate runs before
// any handler reads it.
func invokeEmpty(ctx context.Context, conn *grpc.ClientConn, method string) error {
	return conn.Invoke(ctx, method, &emptypb.Empty{}, &emptypb.Empty{})
}

func tamperedBinary(t *testing.T, e *checkEnv) {
	t.Helper()
	writeMode(t, e.path("/usr/bin/nebula-server"), "server binarY", 0o755)
}

func onlyFinding(t *testing.T, s *Service) IntegrityFinding {
	t.Helper()
	st := s.IntegrityCheckStatus()
	if !st.Lock.Open || len(st.Lock.Findings) != 1 {
		t.Fatalf("lock = %+v", st.Lock)
	}
	return st.Lock.Findings[0]
}

func TestIntegrityLockClassifiesEveryMethod(t *testing.T) {
	roles := MethodRoles()
	for _, m := range pb.ExecutorService_ServiceDesc.Methods {
		full := "/" + pb.ExecutorService_ServiceDesc.ServiceName + "/" + m.MethodName
		if _, ok := integrityLockedMethods[full]; !ok {
			t.Errorf("%s is not classified for the I1 lock", full)
		}
	}
	// Streams go through integrityStreamInterceptor and need a
	// classification exactly like unary methods.
	for _, m := range pb.ExecutorService_ServiceDesc.Streams {
		full := "/" + pb.ExecutorService_ServiceDesc.ServiceName + "/" + m.StreamName
		if _, ok := integrityLockedMethods[full]; !ok {
			t.Errorf("stream %s is not classified for the I1 lock", full)
		}
	}
	for m := range integrityLockedMethods {
		if _, ok := roles[m]; !ok {
			t.Errorf("%s is classified but not in the method table", m)
		}
	}
	// ADR 0015 D4 row 1: unlock and every mutation and read-grant
	// dispatch. The integrity RPCs, Lock and observing a running job are
	// never locked.
	for _, m := range []string{
		pb.ExecutorService_Unlock_FullMethodName, pb.ExecutorService_AuthorizeRun_FullMethodName,
		pb.ExecutorService_RunAttached_FullMethodName, pb.ExecutorService_StartDurable_FullMethodName,
		pb.ExecutorService_RunScheduled_FullMethodName, pb.ExecutorService_RunReadGrant_FullMethodName,
		pb.ExecutorService_RunBatchMember_FullMethodName, pb.ExecutorService_ReadPVE_FullMethodName,
		pb.ExecutorService_CommitPVEGuestPower_FullMethodName,
	} {
		if !integrityLockedMethods[m] {
			t.Errorf("%s is not locked", m)
		}
	}
	for _, m := range []string{
		pb.ExecutorService_GetIntegrityStatus_FullMethodName, pb.ExecutorService_AckIntegrityFinding_FullMethodName,
		pb.ExecutorService_Lock_FullMethodName, pb.ExecutorService_GetRun_FullMethodName, pb.ExecutorService_GetStatus_FullMethodName,
	} {
		if integrityLockedMethods[m] {
			t.Errorf("%s is locked", m)
		}
	}
}

func TestIntegrityLockUnclassifiedMethodIsRefused(t *testing.T) {
	e := newCheckEnv(t)
	if e.svc.IntegrityLockRefuses("/nebula.executor.v1.ExecutorService/Future") {
		t.Fatal("refused without an open lock")
	}
	tamperedBinary(t, e)
	e.run(t)
	if !e.svc.IntegrityLockRefuses("/nebula.executor.v1.ExecutorService/Future") {
		t.Fatal("an unclassified method passes an open lock")
	}
}

func TestIntegrityLockForEveryLockingClass(t *testing.T) {
	cases := []struct {
		path   string
		class  integrity.Class
		status integrity.Status
		locks  bool
	}{
		{"/usr/bin/nebula-server", integrity.ClassBinary, integrity.StatusDifferent, true},
		{"/usr/bin/nebula-evil", integrity.ClassBinary, integrity.StatusExtra, true},
		{"/lib/systemd/system/nebula-server.service", integrity.ClassUnit, integrity.StatusDifferent, true},
		{"/usr/share/nebula/release/builtins.tar", integrity.ClassModule, integrity.StatusDifferent, true},
		{"/usr/share/nebula/release/rootkeys.json", integrity.ClassRootKey, integrity.StatusDifferent, true},
		{"/usr/share/nebula/deploy/nebula.nft", integrity.ClassCode, integrity.StatusMissing, true},
		// Q4: a web asset or template is refused on its own by the server;
		// it never locks the executor.
		{"/usr/share/nebula/web/app.css", integrity.ClassWebAsset, integrity.StatusDifferent, false},
		{"/usr/share/nebula/templates/page.html", integrity.ClassWebAsset, integrity.StatusMissing, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.class)+" "+string(tc.status), func(t *testing.T) {
			e := newCheckEnv(t)
			e.svc.integrityCheck.check = func(context.Context, integrity.Reference, integrity.Options) (integrity.Report, error) {
				return integrity.Report{Complete: true, Files: []integrity.FileResult{{Path: tc.path, Class: tc.class, Status: tc.status}}}, nil
			}
			e.run(t)
			if !tc.locks {
				// The fixture service has no keyring: check the gate
				// itself instead of reaching the handlers.
				for _, m := range lockedMethods() {
					if e.svc.IntegrityLockRefuses(m) {
						t.Fatalf("%s refused for a web asset", m)
					}
				}
				if e.svc.IntegrityLockOpen() {
					t.Fatal("web asset opened the lock")
				}
				return
			}
			conn := integrityRPCConn(t, e.svc, allRoles...)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, m := range lockedMethods() {
				if err := invokeEmpty(ctx, conn, m); !isIntegrityLocked(err) {
					t.Fatalf("%s: err = %v, want the integrity lock", m, err)
				}
			}
			f := onlyFinding(t, e.svc)
			if f.Path != tc.path || f.Class != tc.class || f.Status != tc.status || f.Cause != IntegrityLockDeviation || !validIntegrityFindingID(f.ID) {
				t.Fatalf("finding = %+v", f)
			}
			if !containsKind(e.h.kinds(), "integrity_lock_refused") || !containsKind(e.h.kinds(), "integrity_finding_opened") {
				t.Fatalf("not audited: %v", e.h.kinds())
			}
		})
	}
}

func TestIntegrityConfigurationChangeDoesNotLock(t *testing.T) {
	// A configuration file is not on the signed list: D3 baseline
	// approval handles it, with no lock (Q4).
	e := newCheckEnv(t)
	cfg := []checkTreeFile{{"/etc/nebula/nebula.toml", "listen = \"127.0.0.1\"\n", 0o640}}
	installTree(t, e.root, cfg)
	writeMode(t, e.path("/etc/nebula/nebula.toml"), "listen = \"0.0.0.0\"\n", 0o644)
	if r := e.run(t); r.State != IntegrityRunClean || r.Locking != 0 {
		t.Fatalf("run = %+v", r)
	}
	if e.svc.IntegrityLockOpen() {
		t.Fatal("configuration change opened the lock")
	}
}

func TestIntegrityLockRefusesUnlockWithoutTouchingKeys(t *testing.T) {
	e := newReconcileEnv(t)
	if e.svc.vault == nil {
		e.svc.vault = vault.New(e.db)
	}
	if !e.svc.keys.Unlocked() {
		t.Fatal("fixture keyring is locked")
	}
	statePath := filepath.Join(t.TempDir(), IntegrityCheckStateFile)
	since := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	d := IntegrityDeviation{Path: "/usr/bin/nebula-executor", Class: integrity.ClassBinary, Status: integrity.StatusDifferent, Reason: integrity.ReasonSHA256, Locks: true}
	lock := IntegrityLock{}
	mergeIntegrityFindings(&lock, IntegrityRun{Started: since, Locking: 1, Deviations: []IntegrityDeviation{d}})
	if err := storeIntegrityCheckState(statePath, IntegrityCheckState{Lock: lock}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetIntegrityCheck(IntegrityCheckConfig{StatePath: statePath,
		Flavour: func(context.Context) (string, error) { return "deb:amd64", nil }}); err != nil {
		t.Fatal(err)
	}
	client := pb.NewExecutorServiceClient(integrityRPCConn(t, e.svc, peercred.RoleAdmin, peercred.RoleServer))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.Unlock(ctx, &pb.UnlockRequest{Passphrase: []byte("wrong passphrase")})
	if !isIntegrityLocked(err) {
		t.Fatalf("unlock while locked: %v", err)
	}
	if status.Convert(err).Message() != ErrIntegrityLocked.Error() {
		t.Fatalf("not the fixed error: %v", err)
	}
	if _, err := client.AuthorizeRun(ctx, &pb.AuthorizeRunRequest{}); !isIntegrityLocked(err) {
		t.Fatalf("dispatch while locked: %v", err)
	}
	if _, err := client.RunReadGrant(ctx, &pb.RunReadGrantRequest{}); !isIntegrityLocked(err) {
		t.Fatalf("read-grant dispatch while locked: %v", err)
	}
	// The lock withholds authority only: keys stay loaded, nothing is
	// wiped or revoked, and Lock and status stay available.
	if !e.svc.keys.Unlocked() {
		t.Fatal("the integrity lock wiped the keyring")
	}
	if _, err := client.GetStatus(ctx, &pb.GetStatusRequest{}); err != nil {
		t.Fatalf("status while locked: %v", err)
	}

	f := onlyFinding(t, e.svc)
	if _, err := client.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: f.ID}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	// Unlock reaches the keyring again (and fails on the wrong passphrase).
	if _, err := client.Unlock(ctx, &pb.UnlockRequest{Passphrase: []byte("wrong passphrase")}); err == nil || isIntegrityLocked(err) {
		t.Fatalf("unlock after ack: %v", err)
	}
	if _, err := client.AuthorizeRun(ctx, &pb.AuthorizeRunRequest{}); isIntegrityLocked(err) {
		t.Fatalf("dispatch after ack: %v", err)
	}
}

func TestIntegrityAckClearsExactlyOneFinding(t *testing.T) {
	e := newCheckEnv(t)
	tamperedBinary(t, e)
	writeMode(t, e.path("/usr/bin/nebula-evil"), "implant", 0o755)
	r := e.run(t)
	if r.Locking != 2 {
		t.Fatalf("run = %+v", r)
	}
	st := e.svc.IntegrityCheckStatus()
	if len(st.Lock.Findings) != 2 {
		t.Fatalf("findings = %+v", st.Lock.Findings)
	}
	conn := integrityRPCConn(t, e.svc, peercred.RoleAdmin)
	client := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	first := st.Lock.Findings[0]
	resp, err := client.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Finding.GetId() != first.ID || resp.Finding.GetPath() != first.Path || resp.Remaining != 1 || !resp.Locked {
		t.Fatalf("ack = %v", resp)
	}
	if err := invokeEmpty(ctx, conn, pb.ExecutorService_Unlock_FullMethodName); !isIntegrityLocked(err) {
		t.Fatalf("one finding still open, unlock: %v", err)
	}
	// Acking it again, or an unknown or malformed ID, changes nothing.
	if _, err := client.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: first.ID}); status.Code(err) != codes.NotFound {
		t.Fatalf("second ack: %v", err)
	}
	for _, bad := range []string{"", "i1-", "i1-XYZ", "i1-0123456789abcdef0", "../i1-0123456789abcdef", strings.Repeat("a", 4096)} {
		if _, err := client.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: bad}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("ack %q: %v", bad, err)
		}
	}
	if len(e.svc.IntegrityCheckStatus().Lock.Findings) != 1 {
		t.Fatal("a refused ack changed the findings")
	}
	second := e.svc.IntegrityCheckStatus().Lock.Findings[0]
	resp, err = client.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: second.ID})
	if err != nil || resp.Remaining != 0 || resp.Locked {
		t.Fatalf("last ack = %v, %v", resp, err)
	}
	if e.svc.IntegrityLockOpen() || e.svc.IntegrityLockRefuses(pb.ExecutorService_Unlock_FullMethodName) {
		t.Fatal("lock still open after the last ack")
	}
	kinds := e.h.kinds()
	for _, k := range []string{"integrity_finding_acked", "integrity_lock_closed", "integrity_ack_refused"} {
		if !containsKind(kinds, k) {
			t.Fatalf("%s not audited: %v", k, kinds)
		}
	}
	// The ack deleted, restored and rolled back nothing.
	if raw, err := os.ReadFile(e.path("/usr/bin/nebula-evil")); err != nil || string(raw) != "implant" {
		t.Fatalf("extra binary touched: %q %v", raw, err)
	}
	if raw, err := os.ReadFile(e.path("/usr/bin/nebula-server")); err != nil || string(raw) != "server binarY" {
		t.Fatalf("changed binary touched: %q %v", raw, err)
	}
}

func TestIntegrityAckAuditNamesTheAdmin(t *testing.T) {
	e := newCheckEnv(t)
	tamperedBinary(t, e)
	e.run(t)
	f := onlyFinding(t, e.svc)
	client := pb.NewExecutorServiceClient(integrityRPCConn(t, e.svc, peercred.RoleAdmin))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: f.ID}); err != nil {
		t.Fatal(err)
	}
	want := "admin:uid" + itoa(os.Getuid())
	if !auditHas(e.h, "integrity_finding_acked", "by", want) || !auditHas(e.h, "integrity_finding_acked", "finding", f.ID) {
		t.Fatalf("ack audit lacks by=%s finding=%s", want, f.ID)
	}
}

func TestIntegrityServerRoleCannotAck(t *testing.T) {
	e := newCheckEnv(t)
	tamperedBinary(t, e)
	e.run(t)
	f := onlyFinding(t, e.svc)
	client := pb.NewExecutorServiceClient(integrityRPCConn(t, e.svc, peercred.RoleServer))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: f.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server ack: %v", err)
	}
	// The server may read the status, which grants nothing.
	st, err := client.GetIntegrityStatus(ctx, &pb.GetIntegrityStatusRequest{})
	if err != nil || !st.Locked || len(st.Findings) != 1 || st.Findings[0].Id != f.ID {
		t.Fatalf("status = %v, %v", st, err)
	}
	if !e.svc.IntegrityLockOpen() {
		t.Fatal("the server role lifted the lock")
	}
	for _, role := range []peercred.Role{peercred.RolePVECollector, peercred.RoleNetDevCollector} {
		c := pb.NewExecutorServiceClient(integrityRPCConn(t, e.svc, role))
		if _, err := c.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: f.ID}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s ack: %v", role, err)
		}
	}
}

func TestIntegrityRerunWithSameDeviationLocksAgain(t *testing.T) {
	e := newCheckEnv(t)
	tamperedBinary(t, e)
	e.run(t)
	f := onlyFinding(t, e.svc)
	if _, _, err := e.svc.AckIntegrityFindingLocal(f.ID, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if e.svc.IntegrityLockOpen() {
		t.Fatal("lock open after ack")
	}
	e.clock.Add(time.Hour)
	e.run(t)
	again := onlyFinding(t, e.svc)
	if again.ID != f.ID || !again.FirstSeen.Equal(e.clock.Now()) {
		t.Fatalf("reopened finding = %+v, first = %+v", again, f)
	}
	if !e.svc.IntegrityLockRefuses(pb.ExecutorService_Unlock_FullMethodName) {
		t.Fatal("same deviation did not lock again")
	}
	// A run that finds it while it is still open updates it instead of
	// adding a second finding.
	e.clock.Add(time.Hour)
	e.run(t)
	if f2 := onlyFinding(t, e.svc); f2.ID != f.ID || !f2.LastSeen.Equal(e.clock.Now()) || !f2.FirstSeen.Equal(again.FirstSeen) {
		t.Fatalf("finding = %+v", f2)
	}
}

func TestIntegrityLockSurvivesRestartUntilAck(t *testing.T) {
	e := newCheckEnv(t)
	tamperedBinary(t, e)
	e.run(t)
	f := onlyFinding(t, e.svc)

	s2, _ := startService(t, e.refEnv, "1.4.0")
	e.configure(t, s2, IntegrityCheckConfig{})
	if got := onlyFinding(t, s2); got != f {
		t.Fatalf("finding after restart = %+v, want %+v", got, f)
	}
	conn := integrityRPCConn(t, s2, allRoles...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, m := range lockedMethods() {
		if err := invokeEmpty(ctx, conn, m); !isIntegrityLocked(err) {
			t.Fatalf("%s after restart: %v", m, err)
		}
	}
	if _, err := pb.NewExecutorServiceClient(conn).AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: f.ID}); err != nil {
		t.Fatal(err)
	}
	// The ack is stored: a further restart stays unlocked.
	s3, _ := startService(t, e.refEnv, "1.4.0")
	e.configure(t, s3, IntegrityCheckConfig{})
	if s3.IntegrityLockOpen() {
		t.Fatalf("lock after acked restart = %+v", s3.IntegrityCheckStatus().Lock)
	}
}

func TestIntegrityAckNotStoredClearsNothing(t *testing.T) {
	e := newCheckEnv(t)
	tamperedBinary(t, e)
	e.run(t)
	f := onlyFinding(t, e.svc)
	// The state path becomes a directory: the write fails.
	if err := os.Remove(e.state); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.state, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.AckIntegrityFindingLocal(f.ID, "admin:test"); err == nil {
		t.Fatal("ack succeeded without storing")
	}
	if !e.svc.IntegrityLockOpen() || onlyFinding(t, e.svc) != f {
		t.Fatal("a failed ack cleared the finding")
	}
}

func TestIntegrityAckRefusedWhileCheckRuns(t *testing.T) {
	e := newCheckEnv(t)
	tamperedBinary(t, e)
	e.run(t)
	f := onlyFinding(t, e.svc)
	e.svc.integrityCheck.running.Store(true)
	_, _, err := e.svc.AckIntegrityFindingLocal(f.ID, "admin:test")
	e.svc.integrityCheck.running.Store(false)
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("ack during a run: %v", err)
	}
	if !e.svc.IntegrityLockOpen() {
		t.Fatal("finding cleared during a run")
	}
}

func TestIntegrityLockDoesNotInterruptRunningCall(t *testing.T) {
	e := newCheckEnv(t)
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.integrityUnaryInterceptor(context.Background(), nil,
			&grpc.UnaryServerInfo{FullMethod: pb.ExecutorService_StartDurable_FullMethodName},
			func(ctx context.Context, _ any) (any, error) {
				close(started)
				<-release
				return nil, ctx.Err()
			})
		done <- err
	}()
	<-started
	// The lock opens while the job is being dispatched.
	tamperedBinary(t, e)
	e.run(t)
	if !e.svc.IntegrityLockOpen() {
		t.Fatal("lock not open")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("running call interrupted: %v", err)
	}
	// Observing a running job stays possible; a new dispatch is refused.
	conn := integrityRPCConn(t, e.svc, allRoles...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := invokeEmpty(ctx, conn, pb.ExecutorService_GetRun_FullMethodName); isIntegrityLocked(err) {
		t.Fatalf("GetRun refused: %v", err)
	}
	if err := invokeEmpty(ctx, conn, pb.ExecutorService_StartDurable_FullMethodName); !isIntegrityLocked(err) {
		t.Fatalf("new dispatch: %v", err)
	}
}

func TestIntegrityStatusShowsLastRunFindingsAndNote(t *testing.T) {
	e := newCheckEnv(t)
	client := pb.NewExecutorServiceClient(integrityRPCConn(t, e.svc, peercred.RoleAdmin))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := client.GetIntegrityStatus(ctx, &pb.GetIntegrityStatusRequest{})
	if err != nil || st.LastRun != nil || st.Locked || st.Note != integrity.RootCompromiseNote || !st.Configured {
		t.Fatalf("status before a run = %v, %v", st, err)
	}
	tamperedBinary(t, e)
	r := e.run(t)
	st, err = client.GetIntegrityStatus(ctx, &pb.GetIntegrityStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Locked || st.LockedSinceUnix != r.Started.Unix() || st.TotalRuns != 1 || len(st.Findings) != 1 {
		t.Fatalf("status = %v", st)
	}
	if st.LastRun.GetState() != string(IntegrityRunDeviations) || st.LastRun.GetDifferent() != 1 || st.LastRun.GetLocking() != 1 ||
		len(st.LastRun.GetDeviations()) != 1 || st.LastRun.Deviations[0].Path != "/usr/bin/nebula-server" {
		t.Fatalf("last run = %v", st.LastRun)
	}
	if st.Note != "NOS checks cannot detect a root compromise of the NOS machine; see ADR 0015" {
		t.Fatalf("note = %q", st.Note)
	}
}

func TestIntegrityOmittedLockingDeviationsAreOneFinding(t *testing.T) {
	e := newCheckEnv(t)
	var files []integrity.FileResult
	for i := 0; i < maxIntegrityRunDeviations+3; i++ {
		files = append(files, integrity.FileResult{Path: "/usr/bin/nebula-x" + strings.Repeat("y", i),
			Class: integrity.ClassBinary, Status: integrity.StatusExtra})
	}
	e.svc.integrityCheck.check = func(context.Context, integrity.Reference, integrity.Options) (integrity.Report, error) {
		return integrity.Report{Complete: true, Files: files}, nil
	}
	e.run(t)
	st := e.svc.IntegrityCheckStatus()
	if len(st.Lock.Findings) != maxIntegrityRunDeviations+1 {
		t.Fatalf("findings = %d", len(st.Lock.Findings))
	}
	last := st.Lock.Findings[len(st.Lock.Findings)-1]
	if last.Cause != IntegrityLockOmitted || last.Count != 3 {
		t.Fatalf("omitted finding = %+v", last)
	}
	// Acking every listed finding leaves the omitted one: still locked.
	for _, f := range st.Lock.Findings[:len(st.Lock.Findings)-1] {
		if _, _, err := e.svc.AckIntegrityFindingLocal(f.ID, "admin:test"); err != nil {
			t.Fatal(err)
		}
	}
	if !e.svc.IntegrityLockOpen() {
		t.Fatal("omitted locking deviations did not keep the lock")
	}
	if _, _, err := e.svc.AckIntegrityFindingLocal(last.ID, "admin:test"); err != nil || e.svc.IntegrityLockOpen() {
		t.Fatalf("ack omitted: %v", err)
	}
}

func TestIntegrityFindingsAreBounded(t *testing.T) {
	lock := IntegrityLock{}
	start := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	// Many runs with different locking paths each.
	for run := 0; run < 10; run++ {
		var devs []IntegrityDeviation
		for i := 0; i < maxIntegrityRunDeviations; i++ {
			devs = append(devs, IntegrityDeviation{Path: "/usr/bin/nebula-" + itoa(run) + "-" + itoa(i),
				Class: integrity.ClassBinary, Status: integrity.StatusExtra, Locks: true})
		}
		mergeIntegrityFindings(&lock, IntegrityRun{Started: start.Add(time.Duration(run) * time.Hour), Locking: len(devs), Deviations: devs})
	}
	if len(lock.Findings) != maxIntegrityLockFindings {
		t.Fatalf("findings = %d", len(lock.Findings))
	}
	last := lock.Findings[len(lock.Findings)-1]
	if last.Cause != IntegrityLockOmitted || last.Count != maxIntegrityRunDeviations {
		t.Fatalf("omitted = %+v", last)
	}
	if err := validateIntegrityFindings(lock); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityStoredFindingsAreValidated(t *testing.T) {
	good := IntegrityLock{}
	mergeIntegrityFindings(&good, IntegrityRun{Started: time.Unix(1, 0).UTC(), Locking: 1, Deviations: []IntegrityDeviation{
		{Path: "/usr/bin/nebula-server", Class: integrity.ClassBinary, Status: integrity.StatusDifferent, Locks: true}}})
	cases := map[string]func(l *IntegrityLock){
		"forged id":      func(l *IntegrityLock) { l.Findings[0].ID = "i1-0000000000000000" },
		"closed with":    func(l *IntegrityLock) { l.Open, l.Cause = false, "" },
		"unknown cause":  func(l *IntegrityLock) { l.Findings[0].Cause = "whatever" },
		"control path":   func(l *IntegrityLock) { l.Findings[0].Path = "/usr/bin/\x1b" },
		"duplicate":      func(l *IntegrityLock) { l.Findings = append(l.Findings, l.Findings[0]) },
		"negative count": func(l *IntegrityLock) { l.Findings[0].Count = -1 },
		"path on unreadable": func(l *IntegrityLock) {
			l.Findings[0].Cause = IntegrityLockStateUnreadable
			l.Findings[0].ID = integrityFindingID(IntegrityLockStateUnreadable, IntegrityDeviation{Path: l.Findings[0].Path})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newCheckEnv(t)
			l := good
			l.Findings = append([]IntegrityFinding(nil), good.Findings...)
			mutate(&l)
			if err := storeIntegrityCheckState(e.state, IntegrityCheckState{Lock: l}); err != nil {
				t.Fatal(err)
			}
			s2, h := startService(t, e.refEnv, "1.4.0")
			e.configure(t, s2, IntegrityCheckConfig{})
			// Fail closed: an invalid stored lock is an unreadable state,
			// which locks and can be acked like any finding.
			f := onlyFinding(t, s2)
			if f.Cause != IntegrityLockStateUnreadable || !containsKind(h.kinds(), "integrity_check_state_unreadable") {
				t.Fatalf("finding = %+v", f)
			}
			if _, _, err := s2.AckIntegrityFindingLocal(f.ID, "admin:test"); err != nil || s2.IntegrityLockOpen() {
				t.Fatalf("ack unreadable: %v", err)
			}
		})
	}
}

func TestIntegrityLegacyOpenLockIsAckable(t *testing.T) {
	e := newCheckEnv(t)
	legacy := `{"total":1,"runs":[],"lock":{"open":true,"cause":"deviation","since":"2026-11-12T09:00:00Z","deviations":2}}`
	if err := os.WriteFile(e.state, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, _ := startService(t, e.refEnv, "1.4.0")
	e.configure(t, s2, IntegrityCheckConfig{})
	f := onlyFinding(t, s2)
	if f.Cause != IntegrityLockOmitted || f.Count != 2 || !s2.IntegrityLockRefuses(pb.ExecutorService_Unlock_FullMethodName) {
		t.Fatalf("migrated finding = %+v", f)
	}
	if _, _, err := s2.AckIntegrityFindingLocal(f.ID, "admin:test"); err != nil || s2.IntegrityLockOpen() {
		t.Fatalf("ack legacy: %v", err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// auditHas reports a record of kind with key=value.
func auditHas(h *recordingHandler, kind, key, value string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.recs {
		var gotKind string
		match := false
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "kind":
				gotKind = a.Value.String()
			case key:
				match = a.Value.String() == value
			}
			return true
		})
		if gotKind == kind && match {
			return true
		}
	}
	return false
}
