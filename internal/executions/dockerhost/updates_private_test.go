// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	privDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	privSecret = "glpat-dockerhost-test-secret"
)

// privExecutor answers the server-role registry API: "team/app" reads
// succeed (as under an approved lease), "team/db" is refused (no lease).
type privExecutor struct {
	reads   []*pb.ReadPrivateRegistryRequest
	listErr error
	// grants are the approved leases ListReadGrants answers.
	grants []*pb.ReadGrant
}

// ProposeReadGrant canonicalizes a lease like the executor does.
func (p *privExecutor) ProposeReadGrant(_ context.Context, in *pb.ProposeReadGrantRequest, _ ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	doc, canon, digest, err := permit.ParseReadGrant(in.GetGrantJson(), time.Unix(1_800_000_000, 0))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid document")
	}
	// The test approves every proposal at once.
	p.grants = append(p.grants, &pb.ReadGrant{GrantId: doc.ID, GrantDigest: digest, CanonicalGrant: canon,
		ApprovedBy: "cli:root", CreatedUnix: doc.CreatedUnix, ExpiryUnix: doc.ExpiryUnix})
	return &pb.ProposeReadGrantResponse{GrantDigest: digest, CanonicalGrant: canon,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY}, nil
}

func (p *privExecutor) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	return &pb.ListReadGrantsResponse{Grants: p.grants}, nil
}

// lease approves a registry read lease over the whole "corp" scope.
func (p *privExecutor) lease(t *testing.T, now time.Time) {
	t.Helper()
	req := registrymeta.LeaseRequest{ID: "00000000-0000-4000-8000-00000000d0c4", Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp"}}}
	if _, err := registrymeta.ProposeRegistryReadLease(context.Background(), p, req, now); err != nil {
		t.Fatal(err)
	}
}

func (p *privExecutor) ListPrivateRegistries(context.Context, *pb.ListPrivateRegistriesRequest, ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	if p.listErr != nil {
		return nil, p.listErr
	}
	return &pb.ListPrivateRegistriesResponse{Registries: []*pb.PrivateRegistryInfo{{
		RegistryId: "corp", RegistryOrigin: "https://registry.corp.example", Repositories: []string{"team/app", "team/db"},
		ConfigVersion: 1, CredentialVersion: 1, ConfigDigest: strings.Repeat("a", 64), CredentialId: strings.Repeat("b", 32),
	}}}, nil
}

func (p *privExecutor) ReadPrivateRegistry(_ context.Context, in *pb.ReadPrivateRegistryRequest, _ ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	p.reads = append(p.reads, in)
	if in.GetRepository() != "team/app" {
		return nil, status.Error(codes.PermissionDenied, "no lease "+privSecret)
	}
	return &pb.ReadPrivateRegistryResponse{RegistryId: in.GetRegistryId(), Repository: in.GetRepository(), Digest: privDigest}, nil
}

// TestResolvePrivateDigestsFillsOnlyPrivateUnknownImages: the server caller
// asks the executor only for images the host could not read that lie on a
// private registry; other images and statuses stay as the host reported
// them, and refusals become fixed notes without executor text.
func TestResolvePrivateDigestsFillsOnlyPrivateUnknownImages(t *testing.T) {
	in := ImageUpdates{Phase: "done", Updates: 1, Images: []ImageUpdate{
		{Image: "registry.corp.example/team/app:1.0", Status: "unknown", Note: "authentication required"},
		{Image: "registry.corp.example/team/app:1.0", Status: "unknown", Note: "authentication required"},
		{Image: "registry.corp.example/team/db:5", Status: "unknown", Note: "authentication required"},
		{Image: "registry.corp.example/team/other:1", Status: "unknown", Note: "authentication required"},
		{Image: "ghcr.io/acme/tool:2", Status: "unknown", Note: "registry not reachable"},
		{Image: "nginx:1.27", Status: "update", Remote: privDigest, Note: "local none"},
		{Image: "registry.corp.example/team/app@" + privDigest, Status: "pinned"},
	}}
	exec := &privExecutor{}
	out, err := ResolvePrivateDigests(context.Background(), in, exec)
	if err != nil {
		t.Fatal(err)
	}
	want := []ImageUpdate{
		{Image: "registry.corp.example/team/app:1.0", Status: "unknown", Remote: privDigest, Note: privateNoteRead, Private: true},
		{Image: "registry.corp.example/team/app:1.0", Status: "unknown", Remote: privDigest, Note: privateNoteRead, Private: true},
		{Image: "registry.corp.example/team/db:5", Status: "unknown", Note: privateNoteRefused, Private: true},
		{Image: "registry.corp.example/team/other:1", Status: "unknown", Note: privateNoteOutScope, Private: true},
		in.Images[4], in.Images[5], in.Images[6],
	}
	for i := range want {
		if out.Images[i] != want[i] {
			t.Errorf("image %d = %+v, want %+v", i, out.Images[i], want[i])
		}
	}
	if out.Updates != 1 || in.Images[0].Remote != "" {
		t.Fatalf("counts changed or input mutated: %+v", out)
	}
	// One read per repository and tag; none for the out-of-scope repository.
	if len(exec.reads) != 2 || exec.reads[0].GetTag() != "1.0" || exec.reads[1].GetRepository() != "team/db" {
		t.Fatalf("reads = %v", exec.reads)
	}
	for _, im := range out.Images {
		if strings.Contains(im.Note, privSecret) {
			t.Fatalf("executor text leaked: %q", im.Note)
		}
	}
}

// limitedExecutor answers every read with ResourceExhausted (budget or
// interval used up).
type limitedExecutor struct{ privExecutor }

func (l *limitedExecutor) ReadPrivateRegistry(_ context.Context, in *pb.ReadPrivateRegistryRequest, _ ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	l.reads = append(l.reads, in)
	return nil, status.Error(codes.ResourceExhausted, "read private registry: budget "+privSecret)
}

// TestResolvePrivateDigestsRateLimitedNote: a rate-limited read has its own
// note ("rate limited, retry later"), not the no-lease note.
func TestResolvePrivateDigestsRateLimitedNote(t *testing.T) {
	in := ImageUpdates{Phase: "done", Images: []ImageUpdate{{Image: "registry.corp.example/team/app:1.0", Status: "unknown"}}}
	out, err := ResolvePrivateDigests(context.Background(), in, &limitedExecutor{})
	if err != nil || out.Images[0].Note != privateNoteRateLimited || !out.Images[0].Private || out.Images[0].Remote != "" {
		t.Fatalf("out=%+v err=%v", out.Images[0], err)
	}
	if !strings.Contains(privateNoteRateLimited, "rate limited") || !strings.Contains(privateNoteRateLimited, "retry later") ||
		privateNoteRateLimited == privateNoteRefused {
		t.Fatalf("note = %q", privateNoteRateLimited)
	}
	// The executor's per-repository and the server's per-host distinct-tag
	// caps refuse as rate limits too; the note names them.
	for _, want := range []string{"distinct tags", "per repository", "per host"} {
		if !strings.Contains(privateNoteRateLimited, want) {
			t.Fatalf("note %q does not name %q", privateNoteRateLimited, want)
		}
	}
	if len(privateNoteRateLimited) > 200 {
		t.Fatalf("note is %d bytes, over the 200-byte note bound", len(privateNoteRateLimited))
	}
}

// pendingSource answers like a cache-only DigestReader render before the
// background read finished.
type pendingSource struct{}

func (pendingSource) PrivateDigests(_ context.Context, images []string) (map[string]registrymeta.PrivateDigest, map[string]error, error) {
	errs := map[string]error{}
	for _, im := range images {
		errs[im] = registrymeta.ErrPrivateReadPending
	}
	return nil, errs, nil
}

// TestResolvePrivateDigestsPendingNote: a queued background read has its
// own note, not the failure note.
func TestResolvePrivateDigestsPendingNote(t *testing.T) {
	in := ImageUpdates{Phase: "done", Images: []ImageUpdate{{Image: "registry.corp.example/team/app:1.0", Status: "unknown"}}}
	out, err := ResolvePrivateDigestsWith(context.Background(), in, pendingSource{})
	if err != nil || out.Images[0].Note != privateNotePending || !out.Images[0].Private || out.Images[0].Remote != "" ||
		out.Images[0].Status != "unknown" {
		t.Fatalf("out=%+v err=%v", out.Images[0], err)
	}
}

// TestResolvePrivateDigestsWithReaderReRender: the server's long-lived
// reader answers a re-render without moving the clock from its cache, so
// the second render shows the digest again with no new executor read.
func TestResolvePrivateDigestsWithReaderReRender(t *testing.T) {
	in := ImageUpdates{Phase: "done", Images: []ImageUpdate{
		{Image: "registry.corp.example/team/app:1.0", Status: "unknown"},
		{Image: "registry.corp.example/team/app:2.0", Status: "unknown"},
	}}
	exec := &privExecutor{}
	now := time.Unix(1_800_000_000, 0)
	exec.lease(t, now)
	r := registrymeta.NewDigestReader(exec, func() time.Time { return now })
	for i := range 2 {
		out, err := ResolvePrivateDigestsWith(context.Background(), in, r)
		if err != nil || out.Images[0].Remote != privDigest || out.Images[1].Remote != privDigest {
			t.Fatalf("render %d: %+v %v", i, out.Images, err)
		}
	}
	if len(exec.reads) != 2 {
		t.Fatalf("reads = %d, want one per tag", len(exec.reads))
	}
}

// TestResolvePrivateDigestsListFailureKeepsHostResult: without the
// executor's registry list nothing changes.
func TestResolvePrivateDigestsListFailureKeepsHostResult(t *testing.T) {
	in := ImageUpdates{Phase: "done", Images: []ImageUpdate{{Image: "registry.corp.example/team/app:1.0", Status: "unknown"}}}
	exec := &privExecutor{listErr: errors.New("down")}
	out, err := ResolvePrivateDigests(context.Background(), in, exec)
	if err == nil || out.Images[0] != in.Images[0] || len(exec.reads) != 0 {
		t.Fatalf("out=%+v err=%v reads=%d", out, err, len(exec.reads))
	}
}
