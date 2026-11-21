// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Relying-party settings for the test executor. No WebAuthn ceremony runs
// here; the verifier and registrar only have to exist.
const (
	testRPID   = "nebula.example.org"
	testOrigin = "https://nebula.example.org"
)

// startRealExecutor serves the production executor: executor.NewService
// with the real Service, executor.NewGRPCServer with the real method-role
// table and the real chained interceptors (peer credentials, role policy,
// integrity lock). The test's own UID holds exactly the given roles. The
// registry is empty.
func startRealExecutor(t *testing.T, roles ...peercred.Role) (socket, execUser string) {
	t.Helper()
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: testRPID, Origins: []string{testOrigin}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: verifier, Store: db, RiskPolicy: risk})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: testRPID, Origins: []string{testOrigin}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	keysDir := t.TempDir()
	if err := os.Chmod(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(auth, keyring.New(keysDir), db, reg, slog.New(slog.DiscardHandler))

	uid := uint32(os.Getuid())
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uid: roles}, executor.MethodRoles())
	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket = filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	srv := executor.NewGRPCServer(svc, policy, slog.New(slog.DiscardHandler))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	return socket, u.Username
}

// probeRecorder keeps what the production client did, so the outcome stays
// visible after run returns: the connect error and the error of every
// registry poll.
type probeRecorder struct {
	connectErr error
	listErrs   []error
}

// recordingClient records the result of each ListNetDeviceInfos call the
// poll loop makes. Everything else is the production client.
type recordingClient struct {
	collectorClient
	rec *probeRecorder
}

func (c *recordingClient) ListNetDeviceInfos(ctx context.Context) ([]*pb.NetDeviceInfo, error) {
	devs, err := c.collectorClient.ListNetDeviceInfos(ctx)
	c.rec.listErrs = append(c.rec.listErrs, err)
	return devs, err
}

// recordProbes wraps the real productionDeps().newClient. It changes nothing
// about the connection; it only records what happened.
func recordProbes(d deps, rec *probeRecorder) deps {
	real := d.newClient
	d.newClient = func(ctx context.Context, o executorclient.Options) (collectorClient, error) {
		c, err := real(ctx, o)
		rec.connectErr = err
		if err != nil {
			return nil, err
		}
		return &recordingClient{collectorClient: c, rec: rec}, nil
	}
	return d
}

// TestProductionCollectorStartsUnderItsRole runs the real productionDeps
// against the production executor whose role table is the real one and whose
// only role for the collector UID is netdev-collector. The collector must
// connect, poll the empty registry without a role error and spool nothing.
func TestProductionCollectorStartsUnderItsRole(t *testing.T) {
	socket, user := startRealExecutor(t, peercred.RoleNetDevCollector)
	spool := filepath.Join(t.TempDir(), "spool")

	d := productionDeps()
	// The test process may run as root; the root refusal is tested
	// separately, so only this check is replaced.
	d.geteuid = func() int { return 1000 }
	var rec probeRecorder
	d = recordProbes(d, &rec)

	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	o := options{socket: socket, executorUser: user, spoolDir: spool, interval: time.Second}
	if err := run(ctx, o, log, d); err != nil {
		t.Fatalf("run under netdev-collector role: %v", err)
	}
	if rec.connectErr != nil {
		t.Fatalf("connect under netdev-collector role: %v", rec.connectErr)
	}
	if len(rec.listErrs) == 0 {
		t.Fatalf("poll loop never listed the registry; logs:\n%s", logs.String())
	}
	for i, err := range rec.listErrs {
		if err != nil {
			t.Fatalf("registry poll %d under netdev-collector role: %v", i, err)
		}
	}
	if bytes.Contains(logs.Bytes(), []byte(`"netdev cycle failed"`)) {
		t.Fatalf("a poll cycle failed under netdev-collector role:\n%s", logs.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"nebula-netdev-collector: starting"`)) {
		t.Fatalf("collector never reached the poll loop:\n%s", logs.String())
	}
	if entries, err := os.ReadDir(spool); err == nil && len(entries) != 0 {
		t.Fatalf("empty registry spooled %d entries", len(entries))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// TestProductionCollectorRefusedUnderForeignRole is the counter-probe: the
// same production wiring with the pve-collector role must not get the
// collector in.
func TestProductionCollectorRefusedUnderForeignRole(t *testing.T) {
	socket, user := startRealExecutor(t, peercred.RolePVECollector)
	d := productionDeps()
	d.geteuid = func() int { return 1000 }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o := options{socket: socket, executorUser: user, spoolDir: t.TempDir(), interval: time.Second}
	err := run(ctx, o, slog.New(slog.DiscardHandler), d)
	if !errors.Is(err, executorclient.ErrPermissionDenied) {
		t.Fatalf("run under pve-collector role: want ErrPermissionDenied, got %v", err)
	}
}
