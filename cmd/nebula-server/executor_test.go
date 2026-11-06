// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestLazyExecutorPVEAdminRPCsNotConnected(t *testing.T) {
	l := new(lazyExecutor)
	t.Run("ProbePVERemote", func(t *testing.T) {
		response, err := l.ProbePVERemote(context.Background(), &pb.ProbePVERemoteRequest{})
		if response != nil || err != errNotConnected {
			t.Fatalf("got (%v, %v), want (nil, errNotConnected)", response, err)
		}
	})
	t.Run("AddPVERemote", func(t *testing.T) {
		response, err := l.AddPVERemote(context.Background(), &pb.AddPVERemoteRequest{})
		if response != nil || err != errNotConnected {
			t.Fatalf("got (%v, %v), want (nil, errNotConnected)", response, err)
		}
	})
	t.Run("RotatePVEToken", func(t *testing.T) {
		response, err := l.RotatePVEToken(context.Background(), &pb.RotatePVETokenRequest{})
		if response != nil || err != errNotConnected {
			t.Fatalf("got (%v, %v), want (nil, errNotConnected)", response, err)
		}
	})
	t.Run("RemovePVERemote", func(t *testing.T) {
		response, err := l.RemovePVERemote(context.Background(), &pb.RemovePVERemoteRequest{})
		if response != nil || err != errNotConnected {
			t.Fatalf("got (%v, %v), want (nil, errNotConnected)", response, err)
		}
	})
	t.Run("ListPVERemotes", func(t *testing.T) {
		response, err := l.ListPVERemotes(context.Background(), &pb.ListPVERemotesRequest{})
		if response != nil || err != errNotConnected {
			t.Fatalf("got (%v, %v), want (nil, errNotConnected)", response, err)
		}
	})
	t.Run("ProposePVERepin", func(t *testing.T) {
		response, err := l.ProposePVERepin(context.Background(), &pb.ProposePVERepinRequest{})
		if response != nil || err != errNotConnected {
			t.Fatalf("got (%v, %v), want (nil, errNotConnected)", response, err)
		}
	})
	t.Run("CommitPVERepin", func(t *testing.T) {
		response, err := l.CommitPVERepin(context.Background(), &pb.CommitPVERepinRequest{})
		if response != nil || err != errNotConnected {
			t.Fatalf("got (%v, %v), want (nil, errNotConnected)", response, err)
		}
	})
}

// TestLazyExecutorReadGrants guards the lease pages: executions.Service
// finds the read-grant RPCs by type assertion on the executor it gets, and
// in nebula-server that executor is a *lazyExecutor.
func TestLazyExecutorReadGrants(t *testing.T) {
	var exec any = new(lazyExecutor)
	rg, ok := exec.(interface {
		ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error)
		RevokeReadGrant(context.Context, *pb.RevokeReadGrantRequest, ...grpc.CallOption) (*pb.RevokeReadGrantResponse, error)
	})
	if !ok {
		t.Fatal("lazyExecutor does not implement the read-grant RPCs; the lease pages would be unavailable")
	}
	if r, err := rg.ListReadGrants(context.Background(), &pb.ListReadGrantsRequest{}); r != nil || err != errNotConnected {
		t.Fatalf("ListReadGrants = (%v, %v), want (nil, errNotConnected)", r, err)
	}
	if r, err := rg.RevokeReadGrant(context.Background(), &pb.RevokeReadGrantRequest{GrantId: "x"}); r != nil || err != errNotConnected {
		t.Fatalf("RevokeReadGrant = (%v, %v), want (nil, errNotConnected)", r, err)
	}
}

// TestLazyExecutorReadGrantProposals guards the lease forms the same way:
// without these methods every proposal reports that the executor does not
// support read grants.
func TestLazyExecutorReadGrantProposals(t *testing.T) {
	var exec any = new(lazyExecutor)
	rg, ok := exec.(interface {
		ProposeReadGrant(context.Context, *pb.ProposeReadGrantRequest, ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error)
		CommitReadGrant(context.Context, *pb.CommitReadGrantRequest, ...grpc.CallOption) (*pb.CommitReadGrantResponse, error)
	})
	if !ok {
		t.Fatal("lazyExecutor does not implement the read-grant proposal RPCs; the lease forms would be unavailable")
	}
	if r, err := rg.ProposeReadGrant(context.Background(), &pb.ProposeReadGrantRequest{}); r != nil || err != errNotConnected {
		t.Fatalf("ProposeReadGrant = (%v, %v), want (nil, errNotConnected)", r, err)
	}
	if r, err := rg.CommitReadGrant(context.Background(), &pb.CommitReadGrantRequest{}); r != nil || err != errNotConnected {
		t.Fatalf("CommitReadGrant = (%v, %v), want (nil, errNotConnected)", r, err)
	}
}

// TestLazyExecutorGuestProvision: the provisioning pass-throughs exist
// (the PV-08 run page finds them by type assertion like the read grants)
// and fail with errNotConnected without an executor.
func TestLazyExecutorGuestProvision(t *testing.T) {
	var exec any = new(lazyExecutor)
	pv, ok := exec.(interface {
		ProposePVEGuestProvision(context.Context, *pb.ProposePVEGuestProvisionRequest, ...grpc.CallOption) (*pb.ProposePVEGuestProvisionResponse, error)
		CommitPVEGuestProvision(context.Context, *pb.CommitPVEGuestProvisionRequest, ...grpc.CallOption) (*pb.CommitPVEGuestProvisionResponse, error)
	})
	if !ok {
		t.Fatal("lazyExecutor does not implement the guest provisioning RPCs")
	}
	if r, err := pv.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{}); r != nil || err != errNotConnected {
		t.Fatalf("ProposePVEGuestProvision = (%v, %v), want (nil, errNotConnected)", r, err)
	}
	if r, err := pv.CommitPVEGuestProvision(context.Background(), &pb.CommitPVEGuestProvisionRequest{}); r != nil || err != errNotConnected {
		t.Fatalf("CommitPVEGuestProvision = (%v, %v), want (nil, errNotConnected)", r, err)
	}
}
