// SPDX-License-Identifier: AGPL-3.0-or-later

package peercred

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	mStatus = "/nebula.executor.v1.ExecutorService/GetStatus"
	mUnlock = "/nebula.executor.v1.ExecutorService/Unlock"
)

func socketDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

type recorder struct {
	mu     sync.Mutex
	denied []string
}

func (r *recorder) fn(uid uint32, pid int32, method string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denied = append(r.denied, method)
}

func serve(t *testing.T, p *Policy, rec *recorder) pb.ExecutorServiceClient {
	t.Helper()
	return serveWith(t, p, rec, Credentials{})
}

func serveWith(t *testing.T, p *Policy, rec *recorder, creds Credentials) pb.ExecutorServiceClient {
	t.Helper()
	path := filepath.Join(socketDir(t), "executor.sock")
	l, err := Listen(ListenOptions{Path: path, Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(p.UnaryInterceptor(rec.fn)),
		grpc.StreamInterceptor(p.StreamInterceptor(rec.fn)),
	)
	pb.RegisterExecutorServiceServer(srv, pb.UnimplementedExecutorServiceServer{})
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewExecutorServiceClient(conn)
}

func code(err error) codes.Code { return status.Code(err) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestRoleTableIsEnforced(t *testing.T) {
	me := uint32(os.Getuid())
	p := NewPolicy(
		map[uint32][]Role{me: {RoleServer}},
		map[string][]Role{mStatus: {RoleServer, RoleAdmin}, mUnlock: {RoleAdmin}},
	)
	rec := &recorder{}
	c := serve(t, p, rec)

	// Allowed: reaches the (unimplemented) handler.
	if _, err := c.GetStatus(ctx(t), &pb.GetStatusRequest{}); code(err) != codes.Unimplemented {
		t.Fatalf("server role calling GetStatus: %v", err)
	}
	// Admin-only method from a server-role UID.
	if _, err := c.Unlock(ctx(t), &pb.UnlockRequest{}); code(err) != codes.PermissionDenied {
		t.Fatalf("server role calling Unlock: %v", err)
	}
	// Method missing from the table is denied for everyone.
	if _, err := c.Lock(ctx(t), &pb.LockRequest{}); code(err) != codes.PermissionDenied {
		t.Fatalf("unlisted method: %v", err)
	}
	if len(rec.denied) != 2 {
		t.Fatalf("expected 2 recorded denials, got %v", rec.denied)
	}
}

func TestUnknownUIDRejected(t *testing.T) {
	me := uint32(os.Getuid())
	p := NewPolicy(
		map[uint32][]Role{me + 1: {RoleServer, RoleAdmin}},
		map[string][]Role{mStatus: {RoleServer, RoleAdmin}},
	)
	c := serve(t, p, &recorder{})
	if _, err := c.GetStatus(ctx(t), &pb.GetStatusRequest{}); code(err) != codes.PermissionDenied {
		t.Fatalf("unknown uid: %v", err)
	}
}

func TestUnknownUIDDroppedAtHandshake(t *testing.T) {
	me := uint32(os.Getuid())
	p := NewPolicy(
		map[uint32][]Role{me + 1: {RoleServer}},
		map[string][]Role{mStatus: {RoleServer}},
	)
	var mu sync.Mutex
	var rejected []uint32
	c := serveWith(t, p, &recorder{}, Credentials{Policy: p, OnReject: func(uid uint32, _ int32) {
		mu.Lock()
		rejected = append(rejected, uid)
		mu.Unlock()
	}})
	_, err := c.GetStatus(ctx(t), &pb.GetStatusRequest{})
	if code(err) != codes.Unavailable {
		t.Fatalf("unknown uid should be dropped at handshake, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(rejected) == 0 || rejected[0] != me {
		t.Fatalf("rejection not reported: %v", rejected)
	}
}

func TestDialVerifiedChecksServerUID(t *testing.T) {
	dir := socketDir(t)
	path := filepath.Join(dir, "v.sock")
	l, err := Listen(ListenOptions{Path: path, Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	me := uint32(os.Getuid())
	c, err := DialVerified(ctx(t), path, me)
	if err != nil {
		t.Fatalf("own socket rejected: %v", err)
	}
	c.Close()
	if _, err := DialVerified(ctx(t), path, me+1); err == nil {
		t.Fatal("socket served by an unexpected UID was accepted")
	}
}

func TestListenSocketSafety(t *testing.T) {
	dir := socketDir(t)
	path := filepath.Join(dir, "s.sock")

	l, err := Listen(ListenOptions{Path: path, Mode: 0o660})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	// Leave a stale socket behind (no unlink on close) and listen again.
	l.SetUnlinkOnClose(false)
	l.Close()
	l2, err := Listen(ListenOptions{Path: path, Mode: 0o600})
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l2.Close()

	// A regular file at the path is never removed.
	reg := filepath.Join(dir, "file.sock")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ListenOptions{Path: reg, Mode: 0o600}); err == nil {
		t.Fatal("regular file was replaced by a socket")
	}

	// A group-writable directory is refused.
	loose := t.TempDir()
	if err := os.Chmod(loose, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ListenOptions{Path: filepath.Join(loose, "s.sock"), Mode: 0o600}); err == nil {
		t.Fatal("socket in group-writable directory accepted")
	}

	// A symlinked directory is refused.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ListenOptions{Path: filepath.Join(link, "s.sock"), Mode: 0o600}); err == nil {
		t.Fatal("socket in symlinked directory accepted")
	}
}

func TestNonUnixConnectionRejected(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := (Credentials{}).ServerHandshake(c); err != ErrNotUnix {
		t.Fatalf("TCP connection accepted: %v", err)
	}
}
