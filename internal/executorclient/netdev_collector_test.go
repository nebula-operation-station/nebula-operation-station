// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestNewWithNetDevCollectorUIDRefused records the current state: New probes
// GetStatus, which only the server and admin roles may call, so a UID whose
// only role is netdev-collector cannot connect through New.
func TestNewWithNetDevCollectorUIDRefused(t *testing.T) {
	h := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleNetDevCollector}},
	})
	c, err := New(h.ctx(), Options{SocketPath: h.socket, ExecutorUser: currentUser(t)})
	if c != nil {
		c.Close()
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("ordinary client with netdev-collector UID: want ErrPermissionDenied, got %v", err)
	}
}

func TestNewNetDevCollectorWithCollectorOnlyUID(t *testing.T) {
	h := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleNetDevCollector}},
	})
	o := Options{SocketPath: h.socket, ExecutorUser: currentUser(t)}
	c, err := NewNetDevCollector(h.ctx(), o)
	if err != nil {
		t.Fatalf("new netdev collector client: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	// Allowed by the role: the handler answers with the empty registry.
	got, err := c.ListNetDevices(h.ctx(), &pb.ListNetDevicesRequest{})
	if err != nil || got == nil || len(got.GetDevices()) != 0 {
		t.Fatalf("collector ListNetDevices: want empty registry, got %v, %v", got, err)
	}
	// Allowed by the role: the call reaches the handler, which is not wired
	// yet (ND-14), so the role policy must not refuse it.
	if _, err := c.ReadNetDevice(h.ctx(), &pb.ReadNetDeviceRequest{DeviceId: "core-sw-01", Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION}); status.Code(err) == codes.PermissionDenied {
		t.Fatalf("collector ReadNetDevice refused by the role policy: %v", err)
	}
	// Refused: GetStatus is server and admin only.
	if _, err := c.GetStatus(h.ctx(), &pb.GetStatusRequest{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("collector GetStatus: want ErrPermissionDenied, got %v", err)
	}
}

func TestNewNetDevCollectorRefusesForeignSocket(t *testing.T) {
	h := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleNetDevCollector}},
	})
	c, err := NewNetDevCollector(h.ctx(), Options{SocketPath: h.socket, ExecutorUser: otherUser(t)})
	if c != nil {
		c.Close()
		t.Fatal("netdev collector client accepted a socket served by the wrong user")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

type netdevProbeService struct {
	pb.UnimplementedExecutorServiceServer
	probeError error
}

func (s *netdevProbeService) ListNetDevices(context.Context, *pb.ListNetDevicesRequest) (*pb.ListNetDevicesResponse, error) {
	if s.probeError != nil {
		return nil, s.probeError
	}
	return &pb.ListNetDevicesResponse{}, nil
}

func TestNewNetDevCollectorProbe(t *testing.T) {
	for _, tc := range []struct {
		name       string
		probeError error
		wantError  error
		// wantRefused is set when the probe fails with an error that has no
		// typed sentinel, such as Unimplemented from a wrong peer.
		wantRefused bool
	}{
		{name: "success"},
		// The executor implements ListNetDevices and wires it, so an
		// Unimplemented answer means a wrong or outdated peer.
		{name: "unimplemented is a wrong peer", probeError: status.Error(codes.Unimplemented, "not wired"), wantRefused: true},
		{name: "permission denied", probeError: status.Error(codes.PermissionDenied, "denied"), wantError: ErrPermissionDenied},
		{name: "unavailable", probeError: status.Error(codes.Unavailable, "unavailable"), wantError: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := startFake(t, &netdevProbeService{probeError: tc.probeError})
			c, err := NewNetDevCollector(testCtx(t), Options{SocketPath: socket, ExecutorUser: currentUser(t)})
			if c != nil {
				defer c.Close()
			}
			if tc.wantRefused {
				if err == nil || c != nil {
					t.Fatalf("wrong peer accepted: client=%v, err=%v", c, err)
				}
				return
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("want %v, got %v", tc.wantError, err)
			}
			if tc.wantError != nil && c != nil {
				t.Fatal("failed probe returned a client")
			}
		})
	}
}
