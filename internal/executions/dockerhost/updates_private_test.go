// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
