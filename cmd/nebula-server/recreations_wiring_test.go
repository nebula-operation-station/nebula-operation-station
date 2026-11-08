// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// recreationRPCs is what the cu04 controls need from the server's
// executor connection.
type recreationRPCs interface {
	ListContainerRecreations(context.Context, *pb.ListContainerRecreationsRequest, ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error)
	ResolveContainerRecreation(context.Context, *pb.ResolveContainerRecreationRequest, ...grpc.CallOption) (*pb.ResolveContainerRecreationResponse, error)
}

// TestLazyExecutorRecreationRPCs: the server's executor connection serves
// the recreation list and the resolve, each failing with errNotConnected
// without an executor; it has no recovery plan pass-through (admin only).
func TestLazyExecutorRecreationRPCs(t *testing.T) {
	var exec any = new(lazyExecutor)
	rr, ok := exec.(recreationRPCs)
	if !ok {
		t.Fatal("lazyExecutor does not serve the container recreation RPCs")
	}
	ctx := context.Background()
	if r, err := rr.ListContainerRecreations(ctx, &pb.ListContainerRecreationsRequest{}); r != nil || err != errNotConnected {
		t.Fatalf("ListContainerRecreations = (%v, %v), want (nil, errNotConnected)", r, err)
	}
	if r, err := rr.ResolveContainerRecreation(ctx, &pb.ResolveContainerRecreationRequest{}); r != nil || err != errNotConnected {
		t.Fatalf("ResolveContainerRecreation = (%v, %v), want (nil, errNotConnected)", r, err)
	}
	if _, ok := exec.(interface {
		SetContainerRecoveryPlan(context.Context, *pb.SetContainerRecoveryPlanRequest, ...grpc.CallOption) (*pb.SetContainerRecoveryPlanResponse, error)
	}); ok {
		t.Fatal("lazyExecutor forwards SetContainerRecoveryPlan; recovery plans are admin only")
	}
	if _, ok := exec.(interface {
		ClearContainerRecoveryPlan(context.Context, *pb.ClearContainerRecoveryPlanRequest, ...grpc.CallOption) (*pb.ClearContainerRecoveryPlanResponse, error)
	}); ok {
		t.Fatal("lazyExecutor forwards ClearContainerRecoveryPlan; recovery plans are admin only")
	}
}

// TestRecreationRPCsThroughRoleTable: through the server's lazyExecutor,
// executorclient and the real executor.MethodRoles as the server role
// (newProviderRig), the list reaches the executor and returns its rows,
// and the resolve reaches the handler, which refuses without a privileged
// session. The recovery plan RPCs are refused by the role table.
func TestRecreationRPCsThroughRoleTable(t *testing.T) {
	r := newProviderRig(t)
	lazy := new(lazyExecutor)
	lazy.c.Store(r.client)
	ctx := t.Context()
	const exec = "00000000-0000-4000-9000-0000000000c1"
	if err := r.db.CreateContainerRecreation(executordb.ContainerRecreation{ExecutionID: exec, BatchDigest: strings.Repeat("d", 64),
		MemberID: "m-01", Kind: "update", HostID: "web-1", HostKey: "SHA256:k", Form: "compose", Unit: "site",
		Binding: []byte(`{"kind":"update"}`), Definition: []byte(`{"project":"site","planted":"def-7a1e"}`)}); err != nil {
		t.Fatal(err)
	}
	list, err := lazy.ListContainerRecreations(ctx, &pb.ListContainerRecreationsRequest{HostId: "web-1"})
	if err != nil || len(list.GetRecreations()) != 1 || list.GetRecreations()[0].GetExecutionId() != exec ||
		list.GetRecreations()[0].GetState() != executordb.RecreationIntent {
		t.Fatalf("list %+v %v", list, err)
	}
	if strings.Contains(list.String(), "def-7a1e") {
		t.Fatal("the list carries the recreation definition")
	}
	roleDenied := func(err error) bool {
		return status.Code(err) == codes.PermissionDenied && strings.Contains(status.Convert(err).Message(), "may not call")
	}
	_, err = lazy.ResolveContainerRecreation(ctx, &pb.ResolveContainerRecreationRequest{ExecutionId: exec,
		PreviewExecutionId: "00000000-0000-4000-9000-0000000000c2"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "privileged session") {
		t.Fatalf("resolve without a session: %v, want the executor's session refusal", err)
	}
	if _, err := r.client.SetContainerRecoveryPlan(ctx, &pb.SetContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site",
		Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}}); !roleDenied(err) {
		t.Fatalf("server SetContainerRecoveryPlan: %v, want the role table's refusal", err)
	}
	if _, err := r.client.ClearContainerRecoveryPlan(ctx, &pb.ClearContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site"}); !roleDenied(err) {
		t.Fatalf("server ClearContainerRecoveryPlan: %v, want the role table's refusal", err)
	}
}
