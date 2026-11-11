// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// serverSide is what the server holds of the executor: exactly the
// server-role methods it calls for private registry reads, recorded so the
// test can check every argument and answer for the credential.
type serverSide struct {
	svc  *Service
	mu   sync.Mutex
	wire []string
}

func (s *serverSide) rec(ms ...proto.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range ms {
		if m != nil {
			b, _ := json.Marshal(m)
			s.wire = append(s.wire, string(b))
		}
	}
}

func (s *serverSide) ListPrivateRegistries(ctx context.Context, in *pb.ListPrivateRegistriesRequest, _ ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	out, err := s.svc.ListPrivateRegistries(ctx, in)
	s.rec(in, out)
	return out, err
}

func (s *serverSide) ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest, _ ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	out, err := s.svc.ReadPrivateRegistry(ctx, in)
	s.rec(in, out)
	return out, err
}

func (s *serverSide) ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, _ ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	out, err := s.svc.ListReadGrants(ctx, in)
	s.rec(in, out)
	return out, err
}

func (s *serverSide) ProposeReadGrant(ctx context.Context, in *pb.ProposeReadGrantRequest, _ ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	out, err := s.svc.ProposeReadGrant(ctx, in)
	s.rec(in, out)
	return out, err
}

func (s *serverSide) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.wire, "\n")
}

// TestServerBuiltRegistryLeaseEndToEnd is G13 end to end with the real
// executor (permit authority, executor.db, vault, TLS registry): the server
// builds a registry read lease from ListPrivateRegistries alone, proposes
// it through the executor's ProposeReadGrant, the user approves it, and the
// server's docker.check_updates caller then gets the private digest. The
// credential is in no server argument, answer, lease document, result or
// log line; an out-of-scope repository is refused before any registry I/O;
// a rotation makes the server-built lease stale until the server builds a
// new one.
func TestServerBuiltRegistryLeaseEndToEnd(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app", "team/db")
	srv := &serverSide{svc: e.svc}
	ctx := context.Background()
	host := strings.TrimPrefix(e.reg.srv.URL, "https://")
	app, db, other, app2 := host+"/team/app:1.0.0", host+"/team/db:2", host+"/team/other:1", host+"/team/app:2.0.0"
	hostResult := dockerhost.ImageUpdates{Phase: "done", Images: []dockerhost.ImageUpdate{
		{Image: app, Status: "unknown", Note: "authentication required"},
		{Image: db, Status: "unknown", Note: "authentication required"},
		{Image: other, Status: "unknown", Note: "authentication required"},
		{Image: app2, Status: "unknown", Note: "authentication required"},
	}}

	// Fail closed until a lease exists.
	before, err := dockerhost.ResolvePrivateDigests(ctx, hostResult, srv)
	if err != nil || before.Images[0].Remote != "" || !before.Images[0].Private {
		t.Fatalf("before lease: %+v, %v", before.Images[0], err)
	}
	if n := len(e.reg.requests()); n != 0 {
		t.Fatalf("registry contacted without a lease: %d", n)
	}

	// The server cannot lease a repository outside the record's scope.
	req := registrymeta.LeaseRequest{ID: "00000000-0000-4000-8000-0000000c06af", Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp", Repositories: []string{"team/other"}}}}
	if _, err := registrymeta.ProposeRegistryReadLease(ctx, srv, req, e.clock.Now()); !errors.Is(err, registrymeta.ErrOutOfScope) {
		t.Fatalf("out-of-scope lease: %v", err)
	}

	req.Registries[0].Repositories = []string{"team/app"}
	p, err := registrymeta.ProposeRegistryReadLease(ctx, srv, req, e.clock.Now())
	if err != nil {
		t.Fatalf("server proposal: %v", err)
	}
	g, err := e.svc.auth.ApproveReadGrantCLI(p.Digest, "test")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// The server's long-lived reader, as cmd/nebula-server wires it.
	reader := registrymeta.NewDigestReader(srv, e.clock.Now)
	got, err := dockerhost.ResolvePrivateDigestsWith(ctx, hostResult, reader)
	if err != nil {
		t.Fatal(err)
	}
	if im := got.Images[0]; im.Remote != regDigest || !im.Private || im.Status != "unknown" {
		t.Fatalf("leased image = %+v", im)
	}
	// A second tag of the same repository is its own read, not rate limited.
	if im := got.Images[3]; im.Remote != regDigest || !im.Private {
		t.Fatalf("second tag of the leased repository = %+v", im)
	}
	if im := got.Images[1]; im.Remote != "" || !im.Private || !strings.Contains(im.Note, "no approved registry read lease") {
		t.Fatalf("unleased repository = %+v", im)
	}
	if im := got.Images[2]; im.Remote != "" || !strings.Contains(im.Note, "outside the registry's approved scope") {
		t.Fatalf("out-of-scope repository = %+v", im)
	}
	wantReqs := []string{"HEAD /v2/team/app/manifests/1.0.0", "HEAD /v2/team/app/manifests/2.0.0"}
	if reqs := e.reg.requests(); strings.Join(reqs, "|") != strings.Join(wantReqs, "|") {
		t.Fatalf("registry requests = %q, want %q (only the leased manifest HEADs)", reqs, wantReqs)
	}
	// A re-render without moving the clock shows the same digests (no
	// ResourceExhausted, no new registry request).
	rerender, err := dockerhost.ResolvePrivateDigestsWith(ctx, hostResult, reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 3} {
		if im := rerender.Images[i]; im.Remote != regDigest || strings.Contains(im.Note, "rate limited") {
			t.Fatalf("re-render image %d = %+v", i, im)
		}
	}
	if n := len(e.reg.requests()); n != 2 {
		t.Fatalf("re-render contacted the registry: %d requests", n)
	}
	// Without the cache the executor itself refuses the repeat read as
	// rate limited, with its own note.
	direct, _ := dockerhost.ResolvePrivateDigests(ctx, hostResult, srv)
	if im := direct.Images[0]; im.Remote != "" || !strings.Contains(im.Note, "rate limited") {
		t.Fatalf("uncached repeat read = %+v", im)
	}

	// The credential stays in the executor.
	results, _ := json.Marshal(got)
	for _, s := range []string{srv.text(), string(g.Doc), string(results), allLogText(e.logs)} {
		if strings.Contains(s, regSecret) || strings.Contains(s, regUser) {
			t.Fatalf("credential left the executor: %s", s)
		}
	}
	if !strings.Contains(srv.text(), `"credentialId"`) && !strings.Contains(srv.text(), `"credential_id"`) {
		t.Fatalf("the server never saw the credential identity it leased: %s", srv.text())
	}

	// A rotation leaves the server-built lease stale; a rebuilt one works.
	e.clock.Add(16 * time.Minute)
	if _, err := e.svc.RotatePrivateRegistryCredential(ctx, &pb.RotatePrivateRegistryCredentialRequest{RegistryId: "corp",
		Username: regUser, Secret: []byte(regSecret), CredentialExpiresUnix: e.clock.Now().Add(30 * 24 * time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	stale, _ := dockerhost.ResolvePrivateDigests(ctx, hostResult, srv)
	if stale.Images[0].Remote != "" {
		t.Fatalf("stale lease still reads: %+v", stale.Images[0])
	}
	req.ID = "00000000-0000-4000-8000-0000000c06b0"
	p2, err := registrymeta.ProposeRegistryReadLease(ctx, srv, req, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveReadGrantCLI(p2.Digest, "test"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(16 * time.Minute)
	again, _ := dockerhost.ResolvePrivateDigests(ctx, hostResult, srv)
	if again.Images[0].Remote != regDigest {
		t.Fatalf("rebuilt lease: %+v", again.Images[0])
	}
}

// TestServerRoleCoversRegistryLeaseFlow: every executor method the server
// side of G13 calls is open to the server role.
func TestServerRoleCoversRegistryLeaseFlow(t *testing.T) {
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{10002: {peercred.RoleServer}}, MethodRoles())
	for _, m := range []string{
		pb.ExecutorService_ListPrivateRegistries_FullMethodName,
		pb.ExecutorService_ReadPrivateRegistry_FullMethodName,
		pb.ExecutorService_ProposeReadGrant_FullMethodName,
		pb.ExecutorService_CommitReadGrant_FullMethodName,
		pb.ExecutorService_ListReadGrants_FullMethodName,
	} {
		if _, ok := policy.Allowed(10002, m); !ok {
			t.Fatalf("server role denied %s", m)
		}
	}
}

// TestServerCacheOnlyRenderEndToEnd: with the real executor, a cache-only
// render (the inventory chart) shows nothing until the reader's background
// worker has read, then the executor-read digest from memory; after the
// lease is revoked, the next listing drops the cached digest.
func TestServerCacheOnlyRenderEndToEnd(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	srv := &serverSide{svc: e.svc}
	host := strings.TrimPrefix(e.reg.srv.URL, "https://")
	result := dockerhost.ImageUpdates{Phase: "done", Images: []dockerhost.ImageUpdate{{Image: host + "/team/app:1.0.0", Status: "unknown"}}}
	req := registrymeta.LeaseRequest{ID: "00000000-0000-4000-8000-0000000c06c0", Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp"}}}
	p, err := registrymeta.ProposeRegistryReadLease(context.Background(), srv, req, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveReadGrantCLI(p.Digest, "test"); err != nil {
		t.Fatal(err)
	}
	reader := registrymeta.NewDigestReader(srv, e.clock.Now)
	render := func() dockerhost.ImageUpdate {
		t.Helper()
		ctx := registrymeta.WithReadHost(registrymeta.WithCacheOnly(context.Background()), "web-1")
		out, err := dockerhost.ResolvePrivateDigestsWith(ctx, result, reader)
		if err != nil {
			t.Fatal(err)
		}
		return out.Images[0]
	}
	settle := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := reader.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if im := render(); im.Remote != "" {
		t.Fatalf("first render before any read: %+v", im)
	}
	settle()
	if im := render(); im.Remote != regDigest || !im.Private {
		t.Fatalf("render after the background read: %+v", im)
	}
	if n := len(e.reg.requests()); n != 1 {
		t.Fatalf("registry requests = %d, want 1", n)
	}
	if err := e.svc.auth.RevokeReadGrant(req.ID, "test"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(time.Minute) // past the reader's listing TTL
	render()
	settle()
	if im := render(); im.Remote != "" {
		t.Fatalf("revoked lease still answered from the cache: %+v", im)
	}
}
