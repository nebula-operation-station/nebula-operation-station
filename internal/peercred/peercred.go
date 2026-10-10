// SPDX-License-Identifier: AGPL-3.0-or-later

// Package peercred authorizes gRPC calls on a Unix domain socket by the
// caller's kernel-reported UID (SO_PEERCRED).
//
// Socket file permissions only decide who may connect. Authorization is a
// separate step: every method is mapped to the roles allowed to call it, and
// every UID to its roles. Anything not listed is denied, so a new RPC method
// is unusable until someone deliberately adds it to the table.
package peercred

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Role is a caller class.
type Role string

// Roles.
const (
	RoleServer Role = "server"
	RoleAdmin  Role = "admin"
)

// AuthInfo carries the peer's credentials as reported by the kernel at
// connect time.
type AuthInfo struct {
	credentials.CommonAuthInfo
	UID uint32
	GID uint32
	PID int32
}

// AuthType implements credentials.AuthInfo.
func (AuthInfo) AuthType() string { return "peercred" }

// Credentials is a gRPC TransportCredentials implementation for Unix
// sockets. On the server side it records SO_PEERCRED; it adds no encryption
// (the kernel is the transport). If Policy is set, connections from UIDs
// that hold no role are closed during the handshake, before any request
// bytes are read.
type Credentials struct {
	Policy   *Policy
	OnReject func(uid uint32, pid int32)
}

var _ credentials.TransportCredentials = Credentials{}

// ErrUnknownPeer is returned by ServerHandshake for UIDs without any role.
var ErrUnknownPeer = errors.New("peercred: peer UID holds no role")

// ErrNotUnix is returned for connections that are not Unix sockets.
var ErrNotUnix = errors.New("peercred: connection is not a Unix domain socket")

// ServerHandshake reads the peer's credentials.
func (pc Credentials) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, nil, ErrNotUnix
	}
	cred, err := ucred(uc)
	if err != nil {
		return nil, nil, err
	}
	if pc.Policy != nil && !pc.Policy.Known(cred.Uid) {
		if pc.OnReject != nil {
			pc.OnReject(cred.Uid, cred.Pid)
		}
		return nil, nil, ErrUnknownPeer
	}
	return c, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		UID:            cred.Uid,
		GID:            cred.Gid,
		PID:            cred.Pid,
	}, nil
}

func ucred(uc *net.UnixConn) (*unix.Ucred, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, fmt.Errorf("peercred: SO_PEERCRED: %w", credErr)
	}
	return cred, nil
}

// DialVerified connects to a Unix socket and checks that the listening
// process runs as wantUID. Clients that send secrets (nebula unlock) use it
// so that a socket planted by another user never receives them.
func DialVerified(ctx context.Context, path string, wantUID uint32) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, ErrNotUnix
	}
	cred, err := ucred(uc)
	if err != nil {
		c.Close()
		return nil, err
	}
	if cred.Uid != wantUID {
		c.Close()
		return nil, fmt.Errorf("peercred: socket %s is served by uid %d, expected %d; refusing to talk to it", path, cred.Uid, wantUID)
	}
	return c, nil
}

// ClientHandshake is a no-op; clients are identified by the server.
func (Credentials) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, AuthInfo{CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}, nil
}

// Info implements credentials.TransportCredentials.
func (Credentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

// Clone implements credentials.TransportCredentials.
func (pc Credentials) Clone() credentials.TransportCredentials { return pc }

// OverrideServerName implements credentials.TransportCredentials.
func (Credentials) OverrideServerName(string) error { return nil } //nolint:staticcheck // required by interface

// Policy maps UIDs to roles and full gRPC method names to allowed roles.
type Policy struct {
	uidRoles    map[uint32][]Role
	methodRoles map[string][]Role
}

// NewPolicy builds a policy. methodRoles keys are full method names such as
// "/nebula.executor.v1.ExecutorService/Unlock".
func NewPolicy(uidRoles map[uint32][]Role, methodRoles map[string][]Role) *Policy {
	p := &Policy{uidRoles: map[uint32][]Role{}, methodRoles: map[string][]Role{}}
	for u, r := range uidRoles {
		p.uidRoles[u] = slices.Clone(r)
	}
	for m, r := range methodRoles {
		p.methodRoles[m] = slices.Clone(r)
	}
	return p
}

// Allowed reports whether uid may call method, and with which role.
func (p *Policy) Allowed(uid uint32, method string) (Role, bool) {
	allowed, ok := p.methodRoles[method]
	if !ok {
		return "", false
	}
	for _, r := range p.uidRoles[uid] {
		if slices.Contains(allowed, r) {
			return r, true
		}
	}
	return "", false
}

// Known reports whether uid holds any role.
func (p *Policy) Known(uid uint32) bool { return len(p.uidRoles[uid]) > 0 }

// HasRole reports whether uid holds role.
func (p *Policy) HasRole(uid uint32, role Role) bool {
	return slices.Contains(p.uidRoles[uid], role)
}

type ctxKey struct{}

// Caller describes an authorized caller.
type Caller struct {
	UID  uint32
	PID  int32
	Role Role
}

// CallerFrom returns the authorized caller stored by the interceptors.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(ctxKey{}).(Caller)
	return c, ok
}

// Denied is invoked for every rejected call (for the audit log).
type Denied func(uid uint32, pid int32, method string)

func (p *Policy) authorize(ctx context.Context, method string, denied Denied) (context.Context, error) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	ai, ok := pr.AuthInfo.(AuthInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "peer credentials unavailable")
	}
	role, ok := p.Allowed(ai.UID, method)
	if !ok {
		if denied != nil {
			denied(ai.UID, ai.PID, method)
		}
		return nil, status.Errorf(codes.PermissionDenied, "uid %d may not call %s", ai.UID, method)
	}
	return context.WithValue(ctx, ctxKey{}, Caller{UID: ai.UID, PID: ai.PID, Role: role}), nil
}

// UnaryInterceptor enforces the policy for unary calls.
func (p *Policy) UnaryInterceptor(denied Denied) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		ctx, err := p.authorize(ctx, info.FullMethod, denied)
		if err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
}

// StreamInterceptor enforces the policy for streaming calls.
func (p *Policy) StreamInterceptor(denied Denied) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		ctx, err := p.authorize(ss.Context(), info.FullMethod, denied)
		if err != nil {
			return err
		}
		return h(srv, &wrapped{ServerStream: ss, ctx: ctx})
	}
}

type wrapped struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrapped) Context() context.Context { return w.ctx }

// ListenOptions configure the socket file.
type ListenOptions struct {
	Path  string
	Mode  os.FileMode // e.g. 0o660
	Group string      // optional group name for the socket file
}

// Listen creates the Unix socket. A stale socket file is removed, but any
// other kind of file at the path is an error. The parent directory must be a
// real directory (not a symlink) owned by this process's UID or root and not
// writable by group or others, so that nobody else can replace the socket.
//
// Listen changes the process umask briefly; call it during startup only.
func Listen(o ListenOptions) (*net.UnixListener, error) {
	dir := filepath.Dir(o.Path)
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("peercred: socket directory: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("peercred: socket directory %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("peercred: socket directory %s is writable by group or others", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || (int(st.Uid) != os.Geteuid() && st.Uid != 0) {
		return nil, fmt.Errorf("peercred: socket directory %s must be owned by this user or root", dir)
	}
	if st, err := os.Lstat(o.Path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("peercred: %s exists and is not a socket", o.Path)
		}
		if err := os.Remove(o.Path); err != nil {
			return nil, err
		}
	}
	// Create with no access, then open up exactly as configured.
	old := unix.Umask(0o777)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: o.Path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	if o.Group != "" {
		g, err := user.LookupGroup(o.Group)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("peercred: group %q: %w", o.Group, err)
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(o.Path, -1, gid); err != nil {
			l.Close()
			return nil, err
		}
	}
	if err := os.Chmod(o.Path, o.Mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// LookupUID resolves a user name to its UID.
func LookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(n), err
}
