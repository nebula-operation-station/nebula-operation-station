// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"

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
	t.Run("ListPVEAdminRemotes", func(t *testing.T) {
		response, err := l.ListPVEAdminRemotes(context.Background(), &pb.ListPVEAdminRemotesRequest{})
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
