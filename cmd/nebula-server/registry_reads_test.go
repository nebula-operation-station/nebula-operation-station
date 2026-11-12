// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// The server's registry read caller is what ui.Options.RegistryReads gets,
// and the lazyExecutor is what it reads through.
var (
	_ ui.RegistryReads = (*serverRegistryReads)(nil)
	_ registryExecutor = (*lazyExecutor)(nil)
)

const (
	srvRegCfg    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	srvRegCredID = "0123456789abcdef0123456789abcdef"
	srvRegSecret = "glpat-server-test-secret"
	srvRegDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// registryExecFake is the server-role executor API: it validates proposals
// with permit's own parser, enforces approved registry leases on reads
// with the executor's per-tag interval, and records every request.
type registryExecFake struct {
	mu       sync.Mutex
	now      time.Time
	proposed map[string][]byte // canonical by digest
	approved []permit.ReadGrantDoc
	grants   []*pb.ReadGrant
	reads    []*pb.ReadPrivateRegistryRequest
	lastRead map[string]time.Time
	wire     []string
}

func newRegistryExecFake(now time.Time) *registryExecFake {
	return &registryExecFake{now: now, proposed: map[string][]byte{}, lastRead: map[string]time.Time{}}
}

func (f *registryExecFake) ListPrivateRegistries(_ context.Context, in *pb.ListPrivateRegistriesRequest, _ ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &pb.ListPrivateRegistriesResponse{Registries: []*pb.PrivateRegistryInfo{{
		RegistryId: "corp", RegistryOrigin: "https://registry.corp.example", Repositories: []string{"team/app"},
		ConfigVersion: 1, CredentialVersion: 2, ConfigDigest: srvRegCfg, CredentialId: srvRegCredID,
	}}}
	f.wire = append(f.wire, in.String(), out.String())
	return out, nil
}

func (f *registryExecFake) ProposeReadGrant(_ context.Context, in *pb.ProposeReadGrantRequest, _ ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wire = append(f.wire, string(in.GetGrantJson()))
	_, canon, digest, err := permit.ParseReadGrant(in.GetGrantJson(), f.now)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid")
	}
	f.proposed[digest] = canon
	return &pb.ProposeReadGrantResponse{GrantDigest: digest, CanonicalGrant: canon,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY}, nil
}

// approve stands in for the user's approval and the executor's registry.
func (f *registryExecFake) approve(t *testing.T, digest string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	canon := f.proposed[digest]
	doc, _, _, err := permit.ParseReadGrant(canon, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.approved = append(f.approved, doc)
	f.grants = append(f.grants, &pb.ReadGrant{GrantId: doc.ID, GrantDigest: digest, CanonicalGrant: canon, ApprovedBy: "cli:root",
		CreatedUnix: doc.CreatedUnix, ExpiryUnix: doc.ExpiryUnix})
}

func (f *registryExecFake) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.ListReadGrantsResponse{Grants: f.grants}, nil
}

func (f *registryExecFake) ReadPrivateRegistry(_ context.Context, in *pb.ReadPrivateRegistryRequest, _ ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, in)
	f.wire = append(f.wire, in.String())
	covered := slices.ContainsFunc(f.approved, func(d permit.ReadGrantDoc) bool {
		t, ok := d.RegistryTarget(in.GetRegistryId())
		return ok && t.CredentialID == srvRegCredID && t.CredentialVersion == 2 && t.AllowsRead(schedgrant.RegistryReadTagDigest, in.GetRepository())
	})
	if !covered {
		return nil, status.Error(codes.PermissionDenied, "no lease")
	}
	key := in.GetRepository() + ":" + in.GetTag()
	if last, ok := f.lastRead[key]; ok && f.now.Sub(last) < schedgrant.RegistryMinInterval {
		return nil, status.Error(codes.ResourceExhausted, "too soon")
	}
	f.lastRead[key] = f.now
	// The executor uses the credential here, and only here.
	_ = srvRegSecret
	return &pb.ReadPrivateRegistryResponse{RegistryId: in.GetRegistryId(), Repository: in.GetRepository(), Digest: srvRegDigest,
		ObservedAtUnix: f.now.Unix()}, nil
}

// TestServerRegistryReadsBuildLeaseAndResolveDigests is the production
// path of the server caller (the value cmd/nebula-server puts into
// ui.Options.RegistryReads): it builds the registry read lease under a
// fresh id from the executor's listed identity alone, proposes it through
// ProposeReadGrant, lists it as a valid registry lease once approved, and
// fills the executor-read digests of two tags of one repository into a
// check_updates result, also on a re-render without moving the clock.
func TestServerRegistryReadsBuildLeaseAndResolveDigests(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newRegistryExecFake(now)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := newServerRegistryReads(f, func() time.Time { return now }, log)
	ctx := context.Background()

	regs, err := s.PrivateRegistries(ctx)
	if err != nil || len(regs) != 1 || regs[0].ID != "corp" {
		t.Fatalf("registries = %+v, %v", regs, err)
	}
	p, err := s.ProposeRegistryLease(ctx, "alice", registrymeta.LeaseRequest{Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp"}}})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !uuidV4Re.MatchString(p.Doc.ID) || !p.CLI || p.Doc.RateProfile != schedgrant.RegistryReadProfile ||
		p.Doc.Issuer != registrymeta.LeaseIssuer || len(p.Doc.RegistryTargets) != 1 {
		t.Fatalf("proposal = %+v", p)
	}
	tg := p.Doc.RegistryTargets[0]
	if tg.ConfigDigest != srvRegCfg || tg.CredentialID != srvRegCredID || tg.CredentialVersion != 2 ||
		!slices.Equal(tg.Repositories, []string{"team/app"}) || !slices.Equal(tg.Methods, []string{schedgrant.RegistryReadTagDigest}) {
		t.Fatalf("target = %+v", tg)
	}
	p2, err := s.ProposeRegistryLease(ctx, "alice", registrymeta.LeaseRequest{Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp"}}})
	if err != nil || p2.Doc.ID == p.Doc.ID {
		t.Fatalf("second proposal reused the id: %v", err)
	}

	img1, img2 := "registry.corp.example/team/app:1.0", "registry.corp.example/team/app:2.0"
	u := dockerhost.ImageUpdates{Phase: "done", Images: []dockerhost.ImageUpdate{{Image: img1, Status: "unknown"}, {Image: img2, Status: "unknown"}}}
	if out := s.ResolveImageUpdates(ctx, u); out.Images[0].Remote != "" || !strings.Contains(out.Images[0].Note, "no approved registry read lease") {
		t.Fatalf("before approval: %+v", out.Images[0])
	}
	f.approve(t, p.Digest)
	leases, err := s.RegistryLeases(ctx)
	if err != nil || len(leases) != 1 || leases[0].State != "active" || leases[0].ID != p.Doc.ID {
		t.Fatalf("leases = %+v, %v", leases, err)
	}
	for i := range 2 { // a render and a re-render at the same instant
		out := s.ResolveImageUpdates(ctx, u)
		for j := range out.Images {
			if im := out.Images[j]; im.Remote != srvRegDigest || !im.Private || im.Status != "unknown" {
				t.Fatalf("render %d image %d = %+v", i, j, im)
			}
		}
	}
	f.mu.Lock()
	reads, wire := len(f.reads), strings.Join(f.wire, "\n")
	f.mu.Unlock()
	if reads != 4 { // two refused before approval, then one per tag
		t.Fatalf("executor reads = %d, want 4", reads)
	}
	if strings.Contains(wire, srvRegSecret) {
		t.Fatal("the credential crossed the server-role API")
	}
}

// TestServerRegistryReadsThroughRoleTable: through the real executor on a
// Unix socket, guarded by executor.MethodRoles for a server-role peer and
// reached through lazyExecutor and executorclient, the server caller lists
// the executor's private registry, builds and proposes the registry read
// lease the local admin then approves, and lists it as an active registry
// lease. A read of a repository the lease does not cover is refused by the
// executor before any registry I/O. The credential is in nothing the
// server sees.
func TestServerRegistryReadsThroughRoleTable(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	r.svc.SetVaultParams(vault.Params{Time: 1, MemoryKiB: 64, Threads: 1})
	if _, err := r.svc.InitVault(ctx, &pb.InitVaultRequest{Passphrase: slices.Clone(pass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Unlock(ctx, &pb.UnlockRequest{Passphrase: slices.Clone(pass), Scope: pb.UnlockScope_UNLOCK_SCOPE_VAULT}); err != nil {
		t.Fatal(err)
	}
	r.svc.SetRegistryReadAuthorizer(r.svc.RegistryReadGrants())
	lazy := new(lazyExecutor)
	lazy.c.Store(r.client)
	s := newServerRegistryReads(lazy, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if regs, err := s.PrivateRegistries(ctx); err != nil || len(regs) != 0 {
		t.Fatalf("registries before add = %+v, %v", regs, err)
	}
	_, err := s.ProposeRegistryLease(ctx, "alice", registrymeta.LeaseRequest{Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp"}}})
	if !errors.Is(err, registrymeta.ErrLeaseUnknownRegistry) {
		t.Fatalf("propose for an unknown registry: %v", err)
	}
	// The local admin adds the registry (admin role, in process).
	if _, err := r.svc.AddPrivateRegistry(ctx, &pb.AddPrivateRegistryRequest{RegistryId: "corp",
		RegistryOrigin: "https://registry.corp.example", AuthMode: pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_BASIC,
		Repositories: []string{"team/app", "team/db"}, Username: "ci-robot", Secret: []byte(srvRegSecret),
		CredentialExpiresUnix: time.Now().Add(30 * 24 * time.Hour).Unix()}); err != nil {
		t.Fatalf("AddPrivateRegistry: %v", err)
	}
	regs, err := s.PrivateRegistries(ctx)
	if err != nil || len(regs) != 1 || regs[0].ID != "corp" {
		t.Fatalf("registries = %+v, %v", regs, err)
	}
	p, err := s.ProposeRegistryLease(ctx, "alice", registrymeta.LeaseRequest{Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp", Repositories: []string{"team/app"}}}})
	if err != nil {
		t.Fatalf("server-built proposal through the role table: %v", err)
	}
	if !p.CLI || !uuidV4Re.MatchString(p.Doc.ID) || p.Doc.RegistryTargets[0].CredentialID != regs[0].CredentialID {
		t.Fatalf("proposal = %+v", p)
	}
	if _, err := r.svc.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: p.Digest}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	leases, err := s.RegistryLeases(ctx)
	if err != nil || len(leases) != 1 || leases[0].ID != p.Doc.ID || leases[0].State != "active" ||
		leases[0].Registries[0].RegistryID != "corp" {
		t.Fatalf("registry leases = %+v, %v", leases, err)
	}
	u := dockerhost.ImageUpdates{Phase: "done", Images: []dockerhost.ImageUpdate{{Image: "registry.corp.example/team/db:5", Status: "unknown"}}}
	if out := s.ResolveImageUpdates(ctx, u); out.Images[0].Remote != "" || !out.Images[0].Private {
		t.Fatalf("uncovered repository = %+v", out.Images[0])
	}
	doc, _ := json.Marshal(p.Doc)
	views, _ := json.Marshal(leases)
	listed, _ := json.Marshal(regs)
	for _, x := range []string{string(doc), string(views), string(listed), string(p.Options)} {
		if strings.Contains(x, srvRegSecret) || strings.Contains(x, "ci-robot") {
			t.Fatalf("the credential reached the server: %s", x)
		}
	}
	// Not connected: the pages fail closed, nothing is read.
	idle := newServerRegistryReads(new(lazyExecutor), time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := idle.PrivateRegistries(ctx); !errors.Is(err, registrymeta.ErrPrivateListFailed) {
		t.Fatalf("not connected: %v", err)
	}
	if out := idle.ResolveImageUpdates(ctx, u); out.Images[0] != u.Images[0] {
		t.Fatalf("not connected changed the result: %+v", out.Images[0])
	}
}

// TestServerRegistryLeaseApprovedInLaterSecondIsListed: the executor stamps
// an approved read grant with its approval clock, not the document's
// created_unix, so a lease proposed in one second and approved in a later
// one must still be listed as active by the next RegistryLeases call. The
// proposal clock is set two seconds back so the approval always lands in a
// later second (the CI flake hit this only when the seconds rolled over).
func TestServerRegistryLeaseApprovedInLaterSecondIsListed(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	r.svc.SetVaultParams(vault.Params{Time: 1, MemoryKiB: 64, Threads: 1})
	if _, err := r.svc.InitVault(ctx, &pb.InitVaultRequest{Passphrase: slices.Clone(pass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Unlock(ctx, &pb.UnlockRequest{Passphrase: slices.Clone(pass), Scope: pb.UnlockScope_UNLOCK_SCOPE_VAULT}); err != nil {
		t.Fatal(err)
	}
	r.svc.SetRegistryReadAuthorizer(r.svc.RegistryReadGrants())
	lazy := new(lazyExecutor)
	lazy.c.Store(r.client)
	proposed := func() time.Time { return time.Now().Add(-2 * time.Second) }
	s := newServerRegistryReads(lazy, proposed, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := r.svc.AddPrivateRegistry(ctx, &pb.AddPrivateRegistryRequest{RegistryId: "corp",
		RegistryOrigin: "https://registry.corp.example", AuthMode: pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_BASIC,
		Repositories: []string{"team/app"}, Username: "ci-robot", Secret: []byte(srvRegSecret),
		CredentialExpiresUnix: time.Now().Add(30 * 24 * time.Hour).Unix()}); err != nil {
		t.Fatalf("AddPrivateRegistry: %v", err)
	}
	p, err := s.ProposeRegistryLease(ctx, "alice", registrymeta.LeaseRequest{Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp", Repositories: []string{"team/app"}}}})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	approved, err := r.svc.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: p.Digest})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.GetGrant().GetCreatedUnix() <= p.Doc.CreatedUnix {
		t.Fatalf("approval %d not after proposal %d", approved.GetGrant().GetCreatedUnix(), p.Doc.CreatedUnix)
	}
	leases, err := s.RegistryLeases(ctx)
	if err != nil || len(leases) != 1 || leases[0].ID != p.Doc.ID || leases[0].State != "active" ||
		leases[0].Created.Unix() != approved.GetGrant().GetCreatedUnix() {
		t.Fatalf("registry leases = %+v, %v", leases, err)
	}
}
