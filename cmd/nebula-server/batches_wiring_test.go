// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const (
	wiringHost    = "web1"
	wiringCredRef = "nebula-default"
	wiringVersion = uint64(0x5eed0001)
)

var wiringFP = "SHA256:" + strings.Repeat("A", 43)

// fakeBatchRPC is an executor for the batch planner: it pins one host,
// answers credential versions (or credErr) and freezes proposals like the
// executor (parse, canonicalize, answer the canonical bytes).
type fakeBatchRPC struct {
	mu sync.Mutex
	// version is the credential version answered (wiringVersion if 0).
	version uint64
	// credErr fails reads of references; probeErr fails the empty probe,
	// which the real executor answers without reading the keyring.
	credErr  error
	probeErr error
	credRefs [][]string
	proposed []canonical.Batch
}

func (f *fakeBatchRPC) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{Hosts: []*pb.HostKeyPin{{HostId: wiringHost, Fingerprint: wiringFP, CredentialRef: wiringCredRef}}}, nil
}

func (f *fakeBatchRPC) GetBatchCredentialVersions(_ context.Context, in *pb.GetBatchCredentialVersionsRequest, _ ...grpc.CallOption) (*pb.GetBatchCredentialVersionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.credRefs = append(f.credRefs, in.GetCredentialRefs())
	if len(in.GetCredentialRefs()) == 0 {
		if f.probeErr != nil {
			return nil, f.probeErr
		}
		return &pb.GetBatchCredentialVersionsResponse{}, nil
	}
	if f.credErr != nil {
		return nil, f.credErr
	}
	version := f.version
	if version == 0 {
		version = wiringVersion
	}
	out := &pb.GetBatchCredentialVersionsResponse{}
	for _, ref := range in.GetCredentialRefs() {
		if ref == wiringCredRef {
			out.Versions = append(out.Versions, &pb.BatchCredentialVersion{CredentialRef: ref, Version: version, PublicKeyFingerprint: "SHA256:pub"})
		}
	}
	return out, nil
}

func (f *fakeBatchRPC) ProposeBatch(_ context.Context, in *pb.ProposeBatchRequest, _ ...grpc.CallOption) (*pb.ProposeBatchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	plan, _, _, err := canonical.ParseBatch(in.GetBatchJson(), now)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid canonical batch")
	}
	frozen, canon, digest, err := canonical.CanonicalizeBatch(plan, now)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "derived")
	}
	f.proposed = append(f.proposed, frozen)
	return &pb.ProposeBatchResponse{BatchDigest: digest.String(), CanonicalBatch: canon, Risk: pb.RiskClass_RISK_CLASS_MEDIUM,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE, Challenge: []byte("c"),
		ChallengeExpiryUnix: now.Add(5 * time.Minute).Unix(), RequestOptionsJson: []byte(`{"challenge":"c"}`),
		State: pb.PermitState_PERMIT_STATE_PENDING}, nil
}

func (f *fakeBatchRPC) CommitBatch(context.Context, *pb.CommitBatchRequest, ...grpc.CallOption) (*pb.CommitBatchResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "not in this test")
}

func (f *fakeBatchRPC) GetBatchStatus(context.Context, *pb.GetBatchStatusRequest, ...grpc.CallOption) (*pb.GetBatchStatusResponse, error) {
	return nil, status.Error(codes.NotFound, "not in this test")
}

type wiringHosts struct{}

func (wiringHosts) Get(_ context.Context, id string) (inventory.Host, error) {
	if id != wiringHost {
		return inventory.Host{}, inventory.ErrHostNotFound
	}
	return inventory.Host{ID: id, Endpoints: []inventory.Endpoint{{Address: "192.168.10.50", Port: 22}}}, nil
}

func newWiringBatches(t *testing.T, f *fakeBatchRPC) (deployBatches, *ui.BatchPages) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	b, pages, err := newBatches(context.Background(), serverBatchExecutor{client: func() batchRPC { return f }}, db, wiringHosts{},
		nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return b, pages
}

func wiringRequest() executions.BatchRequest {
	return executions.BatchRequest{Stages: []executions.BatchStageSpec{{Gate: "automatic",
		Members: []executions.BatchMemberSpec{{ActionID: "package.install_all", HostID: wiringHost}}}}}
}

// The server's planner binds the executor's credential version for the
// host's pinned reference into every member, read through the new RPC; it
// serves the deployment run (with the executor probe) and the batch pages.
func TestServerBatchesBindExecutorCredentialVersions(t *testing.T) {
	f := &fakeBatchRPC{}
	b, pages := newWiringBatches(t, f)
	var deploy ui.DeployBatches = b
	probe, ok := deploy.(ui.DeployBatchProbe)
	if !ok {
		t.Fatal("the deployment planner has no executor probe")
	}
	ctx := context.Background()
	if avail, err := probe.BatchesAvailable(ctx); !avail || err != nil {
		t.Fatalf("available = %v %v", avail, err)
	}
	c, err := deploy.ProposeBatch(ctx, "alice", wiringRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.proposed) != 1 || len(f.proposed[0].Members) != 1 {
		t.Fatalf("proposed = %+v", f.proposed)
	}
	got := f.proposed[0].Members[0].CredentialVersions
	if len(got) != 1 || got[0] != (canonical.CredentialVersion{Reference: wiringCredRef, Version: wiringVersion}) {
		t.Errorf("credential versions = %+v", got)
	}
	if last := f.credRefs[len(f.credRefs)-1]; len(last) != 1 || last[0] != wiringCredRef {
		t.Errorf("credential read asked for %v", last)
	}
	if v, err := deploy.Batch(ctx, c.ID); err != nil || v.ID != c.ID {
		t.Errorf("batch = %+v %v", v, err)
	}
	mux := http.NewServeMux()
	pages.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/batches", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), c.ID) {
		t.Errorf("GET /batches = %d", rec.Code)
	}
}

// Without the credential-version read (an older executor or no batch
// authority: Unimplemented) the planner never guesses a version and the
// probe reports no batches, so a deployment ends at "joined". A locked
// keyring does not affect the probe (the executor answers the empty probe
// without reading keys) but fails every proposal; an unreachable executor
// makes the probe return an error (transient), not "unavailable".
func TestServerBatchesWithoutCredentialVersions(t *testing.T) {
	ctx := context.Background()
	unimplemented := status.Error(codes.Unimplemented, "batch: authority not configured")
	for _, tc := range []struct {
		name     string
		credErr  error
		probeErr error
		avail    bool
		probe    bool // probe returns an error
	}{
		{"unimplemented", unimplemented, unimplemented, false, false},
		{"locked", status.Error(codes.FailedPrecondition, "keyring is locked; run `nebula unlock`"), nil, true, false},
		{"unreachable", status.Error(codes.Unavailable, "executor down"), status.Error(codes.Unavailable, "executor down"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBatchRPC{credErr: tc.credErr, probeErr: tc.probeErr}
			b, _ := newWiringBatches(t, f)
			_, err := b.ProposeBatch(ctx, "alice", wiringRequest())
			if !errors.Is(err, executions.ErrBatchCredentials) {
				t.Errorf("propose = %v, want ErrBatchCredentials", err)
			}
			if len(f.proposed) != 0 {
				t.Error("a batch without credential versions reached the executor")
			}
			avail, err := b.BatchesAvailable(ctx)
			if avail != tc.avail || (err != nil) != tc.probe {
				t.Errorf("available = %v %v", avail, err)
			}
		})
	}
}

// End to end with real keys: the version the executor derives from a real
// SSH public key (executor.CredentialVersionOf) is bound by the server's
// planner and survives the executor-side canonical parsing and
// canonicalization (the fake freezes proposals exactly like the executor).
func TestServerBatchesBindRealCredentialVersions(t *testing.T) {
	ctx := context.Background()
	for range 16 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		v := executor.CredentialVersionOf(k)
		f := &fakeBatchRPC{version: v}
		b, _ := newWiringBatches(t, f)
		if _, err := b.ProposeBatch(ctx, "alice", wiringRequest()); err != nil {
			t.Fatalf("version %d: %v", v, err)
		}
		if len(f.proposed) != 1 || f.proposed[0].Members[0].CredentialVersions[0].Version != v {
			t.Fatalf("version %d not bound: %+v", v, f.proposed)
		}
	}
}

// Before the executor connection exists every batch call fails as not
// connected, and the probe reports an error (transient), not "no batches".
func TestServerBatchExecutorNotConnected(t *testing.T) {
	e := serverBatchExecutor{client: lazyBatchRPC(new(lazyExecutor))}
	ctx := context.Background()
	calls := map[string]func() error{
		"ListHostKeys": func() error { _, err := e.ListHostKeys(ctx, &pb.ListHostKeysRequest{}); return err },
		"ProposeBatch": func() error { _, err := e.ProposeBatch(ctx, &pb.ProposeBatchRequest{}); return err },
		"CommitBatch":  func() error { _, err := e.CommitBatch(ctx, &pb.CommitBatchRequest{}); return err },
		"GetBatchStatus": func() error {
			_, err := e.GetBatchStatus(ctx, &pb.GetBatchStatusRequest{})
			return err
		},
		"GetBatchCredentialVersions": func() error {
			_, err := e.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{})
			return err
		},
	}
	for name, call := range calls {
		if err := call(); status.Code(err) != codes.Unavailable {
			t.Errorf("%s: %v, want Unavailable", name, err)
		}
	}
	avail, err := deployBatches{exec: e}.BatchesAvailable(ctx)
	if avail || status.Code(err) != codes.Unavailable {
		t.Errorf("available = %v %v", avail, err)
	}
}
