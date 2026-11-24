// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"google.golang.org/grpc"
)

// imageWiringExec is the executor boundary of the wiring test: it auto-approves
// every proposal and answers every attached run with the given result. Every
// other call of the executor interface panics through the nil embedded value,
// so the test fails loudly if the finish path asks for more.
type imageWiringExec struct {
	executions.Executor
	result []byte
}

func (w imageWiringExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{Hosts: []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:web", CredentialRef: "nebula-default"}}}, nil
}

func (w imageWiringExec) ProposeExecution(context.Context, *pb.ProposeExecutionRequest, ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	return &pb.ProposeExecutionResponse{ExecutionDigest: "dddd", RiskClass: pb.RiskClass_RISK_CLASS_LOW,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED, State: pb.PermitState_PERMIT_STATE_APPROVED}, nil
}

func (w imageWiringExec) RunAttached(context.Context, *pb.RunAttachedRequest, ...grpc.CallOption) (*pb.RunAttachedResponse, error) {
	return &pb.RunAttachedResponse{Class: "success", ExitCode: 0, Result: w.result, Log: []byte("log")}, nil
}

// imageWiringHosts is the inventory of the wiring test: one enrolled host.
type imageWiringHosts struct{}

func (imageWiringHosts) Get(_ context.Context, id string) (inventory.Host, error) {
	if id != "web" {
		return inventory.Host{}, inventory.ErrHostNotFound
	}
	return inventory.Host{ID: "web", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}}}, nil
}

// imageWiringOps returns the executions service of the server with the image
// observer wired the way main does it, on one server database.
func imageWiringOps(t *testing.T) (*executions.Service, *vulnImageService, *vulninventory.Store, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	img, err := newVulnImageService(db, log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := vulninventory.New(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ops := executions.New(ctx, imageWiringExec{result: imageResult("debian", "12.8", "debian")}, db, imageWiringHosts{}, log)
	ops.SetImageObserver(img)
	t.Cleanup(func() { cancel(); ops.Wait() })
	return ops, img, st, db
}

// runImagePackages creates one image.packages execution of imgRef on host web
// and waits until its dispatcher has finished. Create approves it at once, so
// the run is finished by the executions service on the way back.
func runImagePackages(t *testing.T, ops *executions.Service) string {
	t.Helper()
	c, err := ops.Create(context.Background(), "axel", imageActionID, []string{"web"}, map[string]string{"image": imgRef})
	if err != nil {
		t.Fatal(err)
	}
	ops.Wait()
	return c.ID
}

// TestImageRunThroughExecutionsStoresOneRead: an image.packages run that the
// executions service finishes, with a stored docker.inspect naming the image
// on the same host, stores exactly one image read.
func TestImageRunThroughExecutionsStoresOneRead(t *testing.T) {
	ops, _, st, db := imageWiringOps(t)
	inspectRun(t, db, 1, "web", time.Now().Add(-time.Minute), inspectResult(imgHex))
	runImagePackages(t, ops)
	if reads := storedReads(t, st, "web"); len(reads) != 1 {
		t.Fatalf("stored %d reads after one finished run, want 1", len(reads))
	}
}

// TestImageRunWithoutInspectStoresNoRead: the same run with no docker.inspect
// naming the image stores no read.
func TestImageRunWithoutInspectStoresNoRead(t *testing.T) {
	ops, _, st, _ := imageWiringOps(t)
	runImagePackages(t, ops)
	if reads := storedReads(t, st, "web"); len(reads) != 0 {
		t.Fatalf("stored %d reads without an inspect, want 0", len(reads))
	}
}

// TestImageRunSecondFinishStoresNoSecondRead: a second observer call for the
// same finished execution stores nothing more (one read per execution and
// host, migration 0054). The executions service finishes a host once; the
// second call stands for a repeated finish and goes straight to the observer.
func TestImageRunSecondFinishStoresNoSecondRead(t *testing.T) {
	ops, img, st, db := imageWiringOps(t)
	inspectRun(t, db, 1, "web", time.Now().Add(-time.Minute), inspectResult(imgHex))
	id := runImagePackages(t, ops)
	img.ObserveImage(context.Background(), "web", id)
	if reads := storedReads(t, st, "web"); len(reads) != 1 {
		t.Fatalf("stored %d reads after a second finish of one execution, want 1", len(reads))
	}
}
