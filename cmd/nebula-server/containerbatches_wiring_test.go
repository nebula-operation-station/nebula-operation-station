// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// ListContainerRecreations: the plain batch fake records no updates.
func (f *fakeBatchRPC) ListContainerRecreations(context.Context, *pb.ListContainerRecreationsRequest, ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not in this test")
}

// recreationBatchRPC is the batch fake with a recreation list that records
// which hosts were asked.
type recreationBatchRPC struct {
	*fakeBatchRPC
	mu    sync.Mutex
	asked []string
}

func (r *recreationBatchRPC) ListContainerRecreations(_ context.Context, in *pb.ListContainerRecreationsRequest, _ ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, in.GetHostId())
	return &pb.ListContainerRecreationsResponse{}, nil
}

// newContainerWiringBatches builds the server's planner exactly as main
// does (newBatches) over client.
func newContainerWiringBatches(t *testing.T, client func() batchRPC) deployBatches {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	b, _, err := newBatches(context.Background(), serverBatchExecutor{client: client}, db, wiringHosts{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func containerRequest(m executions.BatchMemberSpec) executions.BatchRequest {
	return executions.BatchRequest{Stages: []executions.BatchStageSpec{{Gate: "manual", Members: []executions.BatchMemberSpec{m}}}}
}

// TestServerPlannerReadsRecreationsFromExecutor: the server's planner binds
// a docker.compose_rollback member through the executor connection's
// ListContainerRecreations (asked for the member's host only), and fails
// with errNotConnected while the executor is not connected. A
// docker.compose_update member is planned (here refused for want of a
// preview), not excluded.
func TestServerPlannerReadsRecreationsFromExecutor(t *testing.T) {
	ctx := context.Background()
	const preview = "00000000-0000-4000-8000-0000000000a1"
	rollback := executions.BatchMemberSpec{ActionID: "docker.compose_rollback", HostID: wiringHost,
		Rollback: &executions.ContainerRollbackSpec{PreviewExecutionID: preview, RollbackOf: "00000000-0000-4000-8000-0000000000b1"}}

	r := &recreationBatchRPC{fakeBatchRPC: &fakeBatchRPC{execution: true}}
	b := newContainerWiringBatches(t, func() batchRPC { return r })
	_, err := b.ProposeBatch(ctx, "alice", containerRequest(rollback))
	if !errors.Is(err, executions.ErrBatchRollbackSource) {
		t.Fatalf("rollback without a recorded update = %v, want ErrBatchRollbackSource", err)
	}
	if len(r.asked) != 1 || r.asked[0] != wiringHost {
		t.Fatalf("the planner asked the executor's recreations for %v, want [%s]", r.asked, wiringHost)
	}

	update := executions.BatchMemberSpec{ActionID: "docker.compose_update", HostID: wiringHost,
		Update: &executions.ContainerUpdateSpec{PreviewExecutionID: preview, Project: "site",
			Services: []executions.ContainerServiceSpec{{Service: "web"}}}}
	if _, err := b.ProposeBatch(ctx, "alice", containerRequest(update)); !errors.Is(err, executions.ErrBatchPreviewMissing) {
		t.Fatalf("update without a preview = %v, want ErrBatchPreviewMissing", err)
	}
	if len(r.proposed) != 0 {
		t.Fatal("a refused container plan reached the executor")
	}

	// Not connected: the planner (below the execution gate) reports it.
	nb := newContainerWiringBatches(t, func() batchRPC { return nil })
	if _, err := nb.Batches.ProposeBatch(ctx, "alice", containerRequest(rollback)); !errors.Is(err, errNotConnected) {
		t.Fatalf("rollback without an executor = %v, want errNotConnected", err)
	}
}

// TestServerBatchExecutorForwardsRecreations: the planner's recreation
// source is the server's lazy executor connection.
func TestServerBatchExecutorForwardsRecreations(t *testing.T) {
	var lister executions.RecreationLister = serverBatchExecutor{client: func() batchRPC { return nil }}
	if _, err := lister.ListContainerRecreations(context.Background(), &pb.ListContainerRecreationsRequest{}); !errors.Is(err, errNotConnected) {
		t.Fatalf("not connected = %v, want errNotConnected", err)
	}
	r := &recreationBatchRPC{fakeBatchRPC: &fakeBatchRPC{}}
	lister = serverBatchExecutor{client: func() batchRPC { return r }}
	if _, err := lister.ListContainerRecreations(context.Background(), &pb.ListContainerRecreationsRequest{HostId: "web1"}); err != nil || len(r.asked) != 1 {
		t.Fatalf("connected = %v, asked %v", err, r.asked)
	}
}

// TestServerUIGetsGatedContainerBatches: main hands the UI the batch
// planner twice, as DeployBatches and as ContainerBatches (cu04), both the
// gated planner, so a container proposal is refused while the executor
// does not run batches and nothing reaches it.
func TestServerUIGetsGatedContainerBatches(t *testing.T) {
	r := &recreationBatchRPC{fakeBatchRPC: &fakeBatchRPC{execution: false}}
	b := newContainerWiringBatches(t, func() batchRPC { return r })
	o := withBatchPlanner(ui.Options{PublicOrigin: "https://nebula.example.org"}, b)
	cb, ok := o.ContainerBatches.(deployBatches)
	if !ok || cb.Batches != b.Batches {
		t.Fatalf("ContainerBatches = %#v, want the gated planner", o.ContainerBatches)
	}
	if db, ok := o.DeployBatches.(deployBatches); !ok || db.Batches != b.Batches {
		t.Fatalf("DeployBatches = %#v, want the gated planner", o.DeployBatches)
	}
	update := executions.BatchMemberSpec{ActionID: "docker.compose_update", HostID: wiringHost,
		Update: &executions.ContainerUpdateSpec{PreviewExecutionID: "00000000-0000-4000-8000-0000000000a1", Project: "site",
			Services: []executions.ContainerServiceSpec{{Service: "web"}}}}
	if _, err := o.ContainerBatches.ProposeBatch(context.Background(), "alice", containerRequest(update)); !errors.Is(err, executions.ErrBatchExecutionUnavailable) {
		t.Fatalf("container proposal without batch execution = %v, want ErrBatchExecutionUnavailable", err)
	}
	if len(r.proposed) != 0 || len(r.asked) != 0 {
		t.Fatal("an ungated container proposal reached the executor")
	}
	if _, err := ui.New(o); err != nil {
		t.Fatalf("ui.New with the server's batch options: %v", err)
	}
}
