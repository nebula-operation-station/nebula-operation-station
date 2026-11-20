// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
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

// TestLazyExecutorCredentialVersioner guards the credential binding of
// host read lease proposals: executions.Service finds GetSSHPublicKey by
// type assertion on the executor it gets, and in nebula-server that
// executor is a *lazyExecutor. Without it every proposal for an SSH host
// reports the executor's SSH credential versions could not be read.
func TestLazyExecutorCredentialVersioner(t *testing.T) {
	var exec any = new(lazyExecutor)
	cv, ok := exec.(interface {
		GetSSHPublicKey(context.Context, *pb.GetSSHPublicKeyRequest, ...grpc.CallOption) (*pb.GetSSHPublicKeyResponse, error)
	})
	if !ok {
		t.Fatal("lazyExecutor does not implement GetSSHPublicKey; host read lease proposals would fail before any RPC")
	}
	if r, err := cv.GetSSHPublicKey(context.Background(), &pb.GetSSHPublicKeyRequest{CredentialRef: "x"}); r != nil || err != errNotConnected {
		t.Fatalf("GetSSHPublicKey = (%v, %v), want (nil, errNotConnected)", r, err)
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

// TestLazyExecutorRejectPending guards the web rejection: executions.Service
// finds RejectPending by type assertion (executions.Rejecter) on the executor
// it gets, and in nebula-server that executor is a *lazyExecutor. Without the
// pass-through every rejection in the UI fails with ErrRejectUnavailable.
func TestLazyExecutorRejectPending(t *testing.T) {
	var exec any = new(lazyExecutor)
	rej, ok := exec.(executions.Rejecter)
	if !ok {
		t.Fatal("lazyExecutor does not implement executions.Rejecter; rejecting in the UI would be unavailable")
	}
	if r, err := rej.RejectPending(context.Background(), &pb.RejectPendingRequest{Digest: "x"}); r != nil || err != errNotConnected {
		t.Fatalf("RejectPending = (%v, %v), want (nil, errNotConnected)", r, err)
	}
}

// TestWiredServerRejectIsAvailable builds executions.Service the way
// nebula-server does (a lazyExecutor and the server database) and checks that
// Reject gets past the Rejecter check: an unknown execution is ErrNotFound,
// never ErrRejectUnavailable.
func TestWiredServerRejectIsAvailable(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "nebula.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ops := executions.New(t.Context(), new(lazyExecutor), db, nil, log)
	err = ops.Reject(context.Background(), "admin", "no-such-execution", "")
	if errors.Is(err, executions.ErrRejectUnavailable) {
		t.Fatal("Reject in the wired server returned ErrRejectUnavailable")
	}
	if !errors.Is(err, executions.ErrNotFound) {
		t.Fatalf("Reject of an unknown execution = %v, want ErrNotFound", err)
	}
}

// TestWiredServerRejectReachesExecutor sends RejectPending through the
// server's lazyExecutor to a real executor that holds only the server role
// for this UID. With no privileged session open the executor refuses it with
// privileged_session_required (spec 07 v29-07-01): the call is forwarded, and
// the server role is not let through without a session.
func TestWiredServerRejectReachesExecutor(t *testing.T) {
	rig := newProviderRig(t)
	lazy := new(lazyExecutor)
	lazy.c.Store(rig.client)
	_, err := lazy.RejectPending(context.Background(), &pb.RejectPendingRequest{
		Digest: strings.Repeat("ab", 32), RelayedUser: "admin",
	})
	if err == nil {
		t.Fatal("RejectPending without a privileged session succeeded")
	}
	if st, _ := status.FromError(err); st.Code() == codes.Unimplemented || st.Code() == codes.Unavailable {
		t.Fatalf("RejectPending did not reach the executor: %v", err)
	}
	if !strings.Contains(err.Error(), "privileged_session_required") {
		t.Fatalf("RejectPending = %v, want privileged_session_required", err)
	}
}
