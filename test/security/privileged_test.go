// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build privileged

// These tests need root because they run helper processes under other UIDs:
//
//	sudo -E go test -tags privileged ./test/security/...
//
// CI runs them on a GitHub-hosted runner (passwordless sudo).
package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fsguard"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Unassigned high UIDs; no passwd entries are needed for setuid.
const (
	uidExecutor = 64501
	uidServer   = 64502
	uidStranger = 64503
	uidAdmin    = 64504
)

const helperEnv = "NEBULA_SECURITY_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helper(mode, os.Args[len(os.Args)-1]))
	}
	os.Exit(m.Run())
}

// helper runs inside a child process with a dropped UID. Exit codes:
// 0 = action succeeded, 10 = permission denied, 1 = other failure.
func helper(mode, arg string) int {
	switch mode {
	case "read":
		_, err := os.ReadFile(arg)
		if errors.Is(err, os.ErrPermission) {
			return 10
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "check-private-dir":
		if err := fsguard.CheckPrivateDir(arg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "rpc-status", "rpc-unlock":
		conn, err := grpc.NewClient("unix://"+arg, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return 1
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c := pb.NewExecutorServiceClient(conn)
		if mode == "rpc-status" {
			_, err = c.GetStatus(ctx, &pb.GetStatusRequest{})
		} else {
			_, err = c.Unlock(ctx, &pb.UnlockRequest{Passphrase: []byte("x")})
		}
		switch status.Code(err) {
		case codes.OK, codes.Unauthenticated:
			// Unauthenticated: the handler rejected the dummy passphrase,
			// so authorization by UID passed.
			return 0
		case codes.PermissionDenied, codes.Unavailable:
			// Unavailable: the executor closed the connection during the
			// handshake because the UID holds no role.
			return 10
		default:
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	return 1
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: sudo -E go test -tags privileged ./test/security/...")
	}
}

// helperBinary copies the test binary to a world-executable location so that
// helper processes with dropped UIDs can run it.
func helperBinary(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "nebula-sec-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "helper")
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
	return dst
}

func runAs(t *testing.T, bin string, uid uint32, mode, arg string) int {
	t.Helper()
	cmd := exec.Command(bin, "-test.run=^$", arg)
	cmd.Env = []string{helperEnv + "=" + mode}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	return 0
}

// publicTempDir returns a temp directory that other UIDs can traverse.
func publicTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "nebula-pub-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestM0Privileged_ServerUserCannotReadExecutorFiles(t *testing.T) {
	requireRoot(t)
	bin := helperBinary(t)

	// Layout as created by the package: /var/lib/nebula/executor (0700,
	// nebula-executor) containing executor.db and keys/.
	base := publicTempDir(t)
	execDir := filepath.Join(base, "executor")
	if err := os.Mkdir(execDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(execDir, "executor.db")
	if err := os.WriteFile(secret, []byte("permits"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{execDir, secret} {
		if err := os.Chown(p, uidExecutor, uidExecutor); err != nil {
			t.Fatal(err)
		}
	}

	if got := runAs(t, bin, uidExecutor, "check-private-dir", execDir); got != 0 {
		t.Fatalf("executor's own fsguard check failed (exit %d)", got)
	}
	if got := runAs(t, bin, uidExecutor, "read", secret); got != 0 {
		t.Fatalf("executor cannot read its own file (exit %d)", got)
	}
	if got := runAs(t, bin, uidServer, "read", secret); got != 10 {
		t.Fatalf("server UID read executor file (exit %d)", got)
	}
	// Even a group-readable mistake on the file is contained by the 0700 directory.
	if err := os.Chmod(secret, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := runAs(t, bin, uidServer, "read", secret); got != 10 {
		t.Fatalf("server UID read executor file through a loose file mode (exit %d)", got)
	}
	// And the executor refuses to start on a loose directory.
	if err := os.Chmod(execDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if got := runAs(t, bin, uidExecutor, "check-private-dir", execDir); got == 0 {
		t.Fatal("fsguard accepted a group-accessible executor directory")
	}
}

func TestM0Privileged_UnknownUIDIsRejectedAcrossProcesses(t *testing.T) {
	requireRoot(t)
	bin := helperBinary(t)
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{
		uidServer: {peercred.RoleServer},
		uidAdmin:  {peercred.RoleAdmin},
	}})
	// The harness socket lives in a 0755 directory with mode 0666, so file
	// permissions let everyone connect: only SO_PEERCRED decides.
	for _, dir := range []string{filepath.Dir(h.socket), filepath.Dir(filepath.Dir(h.socket))} {
		_ = os.Chmod(dir, 0o755)
	}

	cases := []struct {
		name string
		uid  uint32
		mode string
		want int
	}{
		{"server may read status", uidServer, "rpc-status", 0},
		{"stranger is rejected", uidStranger, "rpc-status", 10},
		{"server may not unlock", uidServer, "rpc-unlock", 10},
		{"admin reaches unlock", uidAdmin, "rpc-unlock", 0},
		{"stranger may not unlock", uidStranger, "rpc-unlock", 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runAs(t, bin, c.uid, c.mode, h.socket); got != c.want {
				t.Fatalf("uid %d %s: exit %d, want %d", c.uid, c.mode, got, c.want)
			}
		})
	}
	// The stranger's rejection must come from the executor's handshake, not
	// from an unrelated connection failure.
	h.requireHandshakeRejection(uidStranger)
}
