// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Network device administration RPCs (ADR 0010 D1, D2; ND-11). Plain
// pass-throughs that keep the generated interface implemented; the
// executor's role table admits only the admin role.

// ProbeNetDevice probes a device endpoint without credentials (admin role).
func (c *Client) ProbeNetDevice(ctx context.Context, in *pb.ProbeNetDeviceRequest, opts ...grpc.CallOption) (*pb.ProbeNetDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProbeNetDevice(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// RegisterNetDevice registers a probed device (admin role).
func (c *Client) RegisterNetDevice(ctx context.Context, in *pb.RegisterNetDeviceRequest, opts ...grpc.CallOption) (*pb.RegisterNetDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RegisterNetDevice(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// SetNetDeviceCredential stores a device read credential (admin role).
func (c *Client) SetNetDeviceCredential(ctx context.Context, in *pb.SetNetDeviceCredentialRequest, opts ...grpc.CallOption) (*pb.SetNetDeviceCredentialResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.SetNetDeviceCredential(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// RotateNetDeviceCredential replaces a device read credential (admin role).
func (c *Client) RotateNetDeviceCredential(ctx context.Context, in *pb.RotateNetDeviceCredentialRequest, opts ...grpc.CallOption) (*pb.RotateNetDeviceCredentialResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RotateNetDeviceCredential(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// RepinNetDevice replaces a device trust pin (admin role).
func (c *Client) RepinNetDevice(ctx context.Context, in *pb.RepinNetDeviceRequest, opts ...grpc.CallOption) (*pb.RepinNetDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RepinNetDevice(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// BlockNetDevice blocks every dial to a device (admin role).
func (c *Client) BlockNetDevice(ctx context.Context, in *pb.BlockNetDeviceRequest, opts ...grpc.CallOption) (*pb.BlockNetDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BlockNetDevice(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// UnblockNetDevice lifts a device block (admin role).
func (c *Client) UnblockNetDevice(ctx context.Context, in *pb.UnblockNetDeviceRequest, opts ...grpc.CallOption) (*pb.UnblockNetDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.UnblockNetDevice(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// RemoveNetDevice removes a device (admin role).
func (c *Client) RemoveNetDevice(ctx context.Context, in *pb.RemoveNetDeviceRequest, opts ...grpc.CallOption) (*pb.RemoveNetDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemoveNetDevice(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ListNetDevices lists device registry metadata (admin role).
func (c *Client) ListNetDevices(ctx context.Context, in *pb.ListNetDevicesRequest, opts ...grpc.CallOption) (*pb.ListNetDevicesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListNetDevices(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}
