// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

const (
	fakeSecret   = "glpat-fake-executor-secret"
	fakeUser     = "ci-robot-user"
	fakeDigest   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	fakeCfg      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fakeCredID   = "0123456789abcdef0123456789abcdef"
	fakeOrigin   = "https://registry.corp.example"
	fakeLeaseID  = "00000000-0000-4000-8000-00000000c06f"
	privateImage = "registry.corp.example/team/app:1.0.0"
)

// fakeExecutor stands in for the executor's server-role API. It holds a
// credential (as the real executor does) and enforces approved registry
// read leases like Service.RegistryReadGrants: exact record and credential
// identity, repository and method. Every request and answer is recorded so
// tests can check that the credential never crosses the API.
type fakeExecutor struct {
	mu        sync.Mutex
	now       time.Time
	infos     []*pb.PrivateRegistryInfo
	approved  []permit.ReadGrantDoc
	proposed  map[string]permit.ReadGrantDoc
	reads     []*pb.ReadPrivateRegistryRequest
	wire      []string // every request and answer, rendered
	listErr   error
	readErr   error
	tamper    func(*pb.ProposeReadGrantResponse)
	proposals int
}

func newFakeExecutor(now time.Time) *fakeExecutor {
	return &fakeExecutor{now: now, proposed: map[string]permit.ReadGrantDoc{}, infos: []*pb.PrivateRegistryInfo{{
		RegistryId: "corp", RegistryOrigin: fakeOrigin, AuthMode: pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_BASIC,
		Repositories: []string{"team/app", "team/db"}, ConfigVersion: 1, CredentialVersion: 2,
		ConfigDigest: fakeCfg, CredentialId: fakeCredID, CredentialExpiresUnix: now.Add(90 * 24 * time.Hour).Unix(),
	}}}
}

func (f *fakeExecutor) record(m interface{ String() string }) { f.wire = append(f.wire, m.String()) }

func (f *fakeExecutor) ListPrivateRegistries(_ context.Context, in *pb.ListPrivateRegistriesRequest, _ ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(in)
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := &pb.ListPrivateRegistriesResponse{Registries: f.infos}
	f.record(out)
	return out, nil
}

func (f *fakeExecutor) ProposeReadGrant(_ context.Context, in *pb.ProposeReadGrantRequest, _ ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proposals++
	f.wire = append(f.wire, string(in.GetGrantJson()))
	doc, canon, digest, err := permit.ParseReadGrant(in.GetGrantJson(), f.now)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "read grant: invalid document")
	}
	f.proposed[digest] = doc
	out := &pb.ProposeReadGrantResponse{GrantDigest: digest, CanonicalGrant: canon,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED,
		RequestOptionsJson:  []byte(`{"challenge":"x"}`), ChallengeExpiryUnix: f.now.Add(5 * time.Minute).Unix()}
	if f.tamper != nil {
		f.tamper(out)
	}
	f.record(out)
	return out, nil
}

// approve stands in for the user's WebAuthn approval (CommitReadGrant).
func (f *fakeExecutor) approve(t *testing.T, digest string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.proposed[digest]
	if !ok {
		t.Fatalf("no proposal %s", digest)
	}
	f.approved = append(f.approved, d)
}

func (f *fakeExecutor) ReadPrivateRegistry(_ context.Context, in *pb.ReadPrivateRegistryRequest, _ ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(in)
	f.reads = append(f.reads, in)
	if f.readErr != nil {
		return nil, f.readErr
	}
	k := slices.IndexFunc(f.infos, func(i *pb.PrivateRegistryInfo) bool { return i.GetRegistryId() == in.GetRegistryId() })
	if k < 0 {
		return nil, status.Error(codes.NotFound, "private registry not found")
	}
	info := f.infos[k]
	if !slices.Contains(info.GetRepositories(), in.GetRepository()) {
		return nil, status.Error(codes.PermissionDenied, "repository is outside the approved scope")
	}
	covered := false
	for _, d := range f.approved {
		tg, ok := d.RegistryTarget(in.GetRegistryId())
		if ok && f.now.Unix() < d.ExpiryUnix && tg.ConfigDigest == info.GetConfigDigest() && tg.ConfigVersion == info.GetConfigVersion() &&
			tg.CredentialID == info.GetCredentialId() && tg.CredentialVersion == info.GetCredentialVersion() &&
			tg.AllowsRead(schedgrant.RegistryReadTagDigest, in.GetRepository()) {
			covered = true
		}
	}
	if !covered {
		return nil, status.Error(codes.PermissionDenied, "read private registry: no approved registry read lease covers the registry")
	}
	// The executor uses the credential here, and only here.
	_ = fakeUser + ":" + fakeSecret
	out := &pb.ReadPrivateRegistryResponse{RegistryId: in.GetRegistryId(), Repository: in.GetRepository(),
		ObservedAtUnix: f.now.Unix(), Digest: fakeDigest, ConfigVersion: info.GetConfigVersion(), CredentialVersion: info.GetCredentialVersion()}
	f.record(out)
	return out, nil
}

func (f *fakeExecutor) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reads)
}

func (f *fakeExecutor) assertNoCredential(t *testing.T, extra ...string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range append(slices.Clone(f.wire), extra...) {
		if strings.Contains(s, fakeSecret) || strings.Contains(s, fakeUser) {
			t.Fatalf("credential crossed the executor API: %s", s)
		}
	}
}

func leaseRequest(sel ...LeaseSelection) LeaseRequest {
	return LeaseRequest{ID: fakeLeaseID, Registries: sel, Days: 7}
}

// TestServerBuiltLeaseAuthorizesPrivateDigestRead: the server builds the
// registry read lease from the executor's listed identity alone, the user
// approves it, and the private digest read then succeeds through the
// executor. No credential is in any argument, answer, lease or result.
func TestServerBuiltLeaseAuthorizesPrivateDigestRead(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	ctx := context.Background()
	if _, errs, err := PrivateDigests(ctx, f, []string{privateImage}); err != nil || !errors.Is(errs[privateImage], ErrPrivateReadRefused) {
		t.Fatalf("before the lease: errs=%v err=%v, want refused", errs, err)
	}
	p, err := ProposeRegistryReadLease(ctx, f, leaseRequest(LeaseSelection{RegistryID: "corp", Repositories: []string{"team/app"}}), now)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if p.CLI || len(p.Options) == 0 || len(p.Doc.RegistryTargets) != 1 {
		t.Fatalf("proposal = %+v", p)
	}
	tg := p.Doc.RegistryTargets[0]
	want := permit.RegistryTarget{RegistryID: "corp", ConfigDigest: fakeCfg, ConfigVersion: 1, CredentialID: fakeCredID,
		CredentialVersion: 2, Repositories: []string{"team/app"}, Methods: []string{schedgrant.RegistryReadTagDigest}}
	if !slices.Equal(tg.Repositories, want.Repositories) || !slices.Equal(tg.Methods, want.Methods) ||
		tg.ConfigDigest != want.ConfigDigest || tg.CredentialID != want.CredentialID || tg.ConfigVersion != 1 || tg.CredentialVersion != 2 {
		t.Fatalf("target = %+v, want %+v", tg, want)
	}
	if p.Doc.RateProfile != schedgrant.RegistryReadProfile || p.Doc.Trigger != permit.TriggerOnDemand || p.Doc.Issuer != LeaseIssuer ||
		p.Doc.ExpiryUnix-p.Doc.CreatedUnix != 7*24*3600 || len(p.Doc.Targets)+len(p.Doc.Credentials) != 0 {
		t.Fatalf("doc = %+v", p.Doc)
	}
	f.approve(t, p.Digest)
	images := []string{privateImage, "nginx:1.27", "docker.io/library/redis:7", "registry.corp.example/team/app@" + fakeDigest}
	got, errs, err := PrivateDigests(ctx, f, images)
	if err != nil || len(errs) != 0 || len(got) != 1 {
		t.Fatalf("got=%v errs=%v err=%v", got, errs, err)
	}
	d := got[privateImage]
	if d.Digest != fakeDigest || d.RegistryID != "corp" || d.Repository != "team/app" || d.Tag != "1.0.0" {
		t.Fatalf("digest = %+v", d)
	}
	raw, _ := json.Marshal(p.Doc)
	f.assertNoCredential(t, string(raw), string(p.Options))
}

// TestPrivateDigestOutOfScopeRepositoryRefused: a repository outside the
// record's approved scope is neither leased nor read; a repository in the
// record's scope but not in the lease is refused by the executor.
func TestPrivateDigestOutOfScopeRepositoryRefused(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	ctx := context.Background()
	_, err := ProposeRegistryReadLease(ctx, f, leaseRequest(LeaseSelection{RegistryID: "corp", Repositories: []string{"team/other"}}), now)
	if !errors.Is(err, ErrOutOfScope) || f.proposals != 0 {
		t.Fatalf("out-of-scope lease: err=%v proposals=%d", err, f.proposals)
	}
	p, err := ProposeRegistryReadLease(ctx, f, leaseRequest(LeaseSelection{RegistryID: "corp", Repositories: []string{"team/app"}}), now)
	if err != nil {
		t.Fatal(err)
	}
	f.approve(t, p.Digest)
	other := "registry.corp.example/team/other:1"
	_, errs, err := PrivateDigests(ctx, f, []string{other})
	if err != nil || !errors.Is(errs[other], ErrOutOfScope) || f.readCount() != 0 {
		t.Fatalf("out of record scope: errs=%v err=%v reads=%d", errs, err, f.readCount())
	}
	db := "registry.corp.example/team/db:5"
	_, errs, err = PrivateDigests(ctx, f, []string{db})
	if err != nil || !errors.Is(errs[db], ErrPrivateReadRefused) {
		t.Fatalf("not leased: errs=%v err=%v", errs, err)
	}
}

// TestPrivateDigestHidesExecutorText: refusals and failures map to fixed
// sentinels; the executor's message never reaches the caller.
func TestPrivateDigestHidesExecutorText(t *testing.T) {
	f := newFakeExecutor(time.Unix(1_800_000_000, 0))
	for _, c := range []struct {
		err  error
		want error
	}{
		{status.Error(codes.PermissionDenied, "leak "+fakeSecret), ErrPrivateReadRefused},
		{status.Error(codes.ResourceExhausted, "leak"), ErrPrivateReadRefused},
		{status.Error(codes.FailedPrecondition, "leak"), ErrPrivateReadRefused},
		{status.Error(codes.Unavailable, "leak "+fakeSecret), ErrPrivateReadFailed},
		{errors.New("leak"), ErrPrivateReadFailed},
	} {
		f.readErr = c.err
		_, errs, err := PrivateDigests(context.Background(), f, []string{privateImage})
		if err != nil || errs[privateImage] != c.want || strings.Contains(errs[privateImage].Error(), "leak") {
			t.Fatalf("%v: got %v, %v", c.err, errs[privateImage], err)
		}
	}
	f.listErr = status.Error(codes.Internal, "leak")
	if _, _, err := PrivateDigests(context.Background(), f, []string{privateImage}); err != ErrPrivateListFailed {
		t.Fatalf("list error = %v", err)
	}
}

// TestPrivateDigestRejectsBadExecutorAnswer: an answer that does not echo
// the request or carries no valid digest is a failure, not a digest.
func TestPrivateDigestRejectsBadExecutorAnswer(t *testing.T) {
	for name, mut := range map[string]func(*pb.ReadPrivateRegistryResponse){
		"other registry":   func(r *pb.ReadPrivateRegistryResponse) { r.RegistryId = "other" },
		"other repository": func(r *pb.ReadPrivateRegistryResponse) { r.Repository = "team/db" },
		"bad digest":       func(r *pb.ReadPrivateRegistryResponse) { r.Digest = "sha256:abc" },
		"tags":             func(r *pb.ReadPrivateRegistryResponse) { r.Tags = []string{"1"} },
	} {
		t.Run(name, func(t *testing.T) {
			e := &mutatingExecutor{fakeExecutor: newFakeExecutor(time.Unix(1_800_000_000, 0)), mut: mut}
			e.approved = []permit.ReadGrantDoc{{RegistryTargets: []permit.RegistryTarget{{RegistryID: "corp", ConfigDigest: fakeCfg,
				ConfigVersion: 1, CredentialID: fakeCredID, CredentialVersion: 2, Repositories: []string{"team/app"},
				Methods: []string{schedgrant.RegistryReadTagDigest}}}, ExpiryUnix: 1_900_000_000}}
			_, errs, err := PrivateDigests(context.Background(), e, []string{privateImage})
			if err != nil || errs[privateImage] != ErrPrivateReadFailed {
				t.Fatalf("errs=%v err=%v", errs, err)
			}
		})
	}
}

type mutatingExecutor struct {
	*fakeExecutor
	mut func(*pb.ReadPrivateRegistryResponse)
}

func (m *mutatingExecutor) ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest, opts ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	r, err := m.fakeExecutor.ReadPrivateRegistry(ctx, in, opts...)
	if err == nil {
		m.mut(r)
	}
	return r, err
}

// TestListPrivateIdentitiesSkipsInvalidEntries: an entry without a valid
// lease identity, scope or HTTPS origin cannot be leased or read and is
// left out; duplicates leave out every entry sharing the id or origin.
func TestListPrivateIdentitiesSkipsInvalidEntries(t *testing.T) {
	f := newFakeExecutor(time.Unix(1_800_000_000, 0))
	good := f.infos[0]
	mk := func(id, origin string, mut func(*pb.PrivateRegistryInfo)) *pb.PrivateRegistryInfo {
		i := &pb.PrivateRegistryInfo{RegistryId: id, RegistryOrigin: origin, Repositories: []string{"a/b"}, ConfigVersion: 1,
			CredentialVersion: 1, ConfigDigest: fakeCfg, CredentialId: fakeCredID}
		if mut != nil {
			mut(i)
		}
		return i
	}
	f.infos = []*pb.PrivateRegistryInfo{good,
		mk("nodigest", "https://a.example", func(i *pb.PrivateRegistryInfo) { i.ConfigDigest = "" }),
		mk("nocred", "https://b.example", func(i *pb.PrivateRegistryInfo) { i.CredentialId = "XYZ" }),
		mk("http", "http://c.example", nil),
		mk("v0", "https://d.example", func(i *pb.PrivateRegistryInfo) { i.CredentialVersion = 0 }),
		mk("norepo", "https://e.example", func(i *pb.PrivateRegistryInfo) { i.Repositories = nil }),
		mk("badrepo", "https://f.example", func(i *pb.PrivateRegistryInfo) { i.Repositories = []string{"A/../b"} }),
		mk("Bad_ID", "https://g.example", nil),
		mk("dup", "https://h.example", nil), mk("dup", "https://i.example", nil),
		mk("samea", "https://j.example", nil), mk("sameb", "https://j.example", nil),
		mk("ok2", "https://k.example", nil),
	}
	got, err := ListPrivateIdentities(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, g := range got {
		ids = append(ids, g.ID)
	}
	if !slices.Equal(ids, []string{"corp", "ok2"}) {
		t.Fatalf("ids = %v", ids)
	}
}

// TestMatchPrivateImage maps running references to private registries the
// way docker.check_updates splits them.
func TestMatchPrivateImage(t *testing.T) {
	regs := []PrivateIdentity{{ID: "corp", Origin: fakeOrigin, Repositories: []string{"team/app", "app"}},
		{ID: "local", Origin: "https://registry.lan:5000", Repositories: []string{"x/y"}}}
	for _, c := range []struct {
		image, reg, repo, tag string
		err                   error
	}{
		{"registry.corp.example/team/app:1.0.0", "corp", "team/app", "1.0.0", nil},
		{"registry.corp.example/team/app", "corp", "team/app", "latest", nil},
		{"Registry.Corp.Example/app:2", "corp", "app", "2", nil},
		{"registry.lan:5000/x/y:z", "local", "x/y", "z", nil},
		{"registry.lan/x/y:z", "", "", "", ErrNotPrivate},
		{"registry.corp.example/team/other:1", "", "", "", ErrOutOfScope},
		{"registry.corp.example/team/app@" + fakeDigest, "", "", "", ErrNotPrivate},
		{"https://registry.corp.example/team/app:1", "", "", "", ErrNotPrivate},
		{"nginx:1", "", "", "", ErrNotPrivate},
		{"library/nginx:1", "", "", "", ErrNotPrivate},
		{"registry.corp.example/Team/App:1", "", "", "", ErrBadRef},
		{"registry.corp.example/team/app:" + strings.Repeat("x", 200), "", "", "", ErrBadRef},
		{"", "", "", "", ErrNotPrivate},
	} {
		pi, err := matchPrivateImage(c.image, regs)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%q: err %v, want %v", c.image, err, c.err)
			}
			continue
		}
		if err != nil || pi.registry.ID != c.reg || pi.repository != c.repo || pi.tag != c.tag {
			t.Errorf("%q: got %+v, %v", c.image, pi, err)
		}
	}
}

// TestBuildRegistryReadLeaseRejections covers every refused request before
// anything reaches the executor.
func TestBuildRegistryReadLeaseRejections(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	regs := []PrivateIdentity{{ID: "corp", Origin: fakeOrigin, Repositories: []string{"team/app"}, ConfigDigest: fakeCfg,
		ConfigVersion: 1, CredentialID: fakeCredID, CredentialVersion: 1}}
	sel := LeaseSelection{RegistryID: "corp"}
	for name, c := range map[string]struct {
		req  LeaseRequest
		want error
	}{
		"zero days":     {LeaseRequest{ID: fakeLeaseID, Registries: []LeaseSelection{sel}, Days: 0}, ErrLeaseRequest},
		"eight days":    {LeaseRequest{ID: fakeLeaseID, Registries: []LeaseSelection{sel}, Days: 8}, ErrLeaseRequest},
		"no registry":   {LeaseRequest{ID: fakeLeaseID, Days: 7}, ErrLeaseRequest},
		"too many":      {LeaseRequest{ID: fakeLeaseID, Registries: slices.Repeat([]LeaseSelection{sel}, 9), Days: 7}, ErrLeaseRequest},
		"twice":         {LeaseRequest{ID: fakeLeaseID, Registries: []LeaseSelection{sel, sel}, Days: 7}, ErrLeaseRequest},
		"unknown":       {leaseRequest(LeaseSelection{RegistryID: "other"}), ErrLeaseUnknownRegistry},
		"out of scope":  {leaseRequest(LeaseSelection{RegistryID: "corp", Repositories: []string{"team/db"}}), ErrOutOfScope},
		"bad method":    {leaseRequest(LeaseSelection{RegistryID: "corp", Methods: []string{"pull"}}), ErrLeaseRequest},
		"budget":        {LeaseRequest{ID: fakeLeaseID, Registries: []LeaseSelection{sel}, Days: 7, RunBudget: 241}, ErrLeaseRequest},
		"bad id":        {LeaseRequest{ID: "not-a-uuid", Registries: []LeaseSelection{sel}, Days: 7}, ErrLeaseRequest},
		"dup method":    {leaseRequest(LeaseSelection{RegistryID: "corp", Methods: []string{"tag_digest", "tag_digest"}}), ErrLeaseRequest},
		"dup repo":      {leaseRequest(LeaseSelection{RegistryID: "corp", Repositories: []string{"team/app", "team/app"}}), ErrLeaseRequest},
		"malformed reg": {leaseRequest(LeaseSelection{RegistryID: "Corp"}), ErrLeaseUnknownRegistry},
	} {
		if _, _, err := BuildRegistryReadLease(regs, c.req, now); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", name, err, c.want)
		}
	}
	doc, raw, err := BuildRegistryReadLease(regs, leaseRequest(LeaseSelection{RegistryID: "corp",
		Methods: []string{"list_tags", "tag_digest"}}), now)
	if err != nil || len(raw) == 0 || !slices.Equal(doc.RegistryTargets[0].Methods, []string{"list_tags", "tag_digest"}) ||
		doc.RunBudget != schedgrant.RegistryDefaultRunBudget || doc.MinIntervalS != 900 {
		t.Fatalf("doc=%+v err=%v", doc, err)
	}
}

// TestProposeRegistryReadLeaseChecksExecutorAnswer: an executor answer
// that differs from the built document, or offers no user approval, is
// refused.
func TestProposeRegistryReadLeaseChecksExecutorAnswer(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for name, tamper := range map[string]func(*pb.ProposeReadGrantResponse){
		"other doc": func(r *pb.ProposeReadGrantResponse) {
			r.CanonicalGrant = []byte(strings.Replace(string(r.CanonicalGrant), `"team/app"`, `"team/db"`, 1))
		},
		"bad digest":  func(r *pb.ProposeReadGrantResponse) { r.GrantDigest = "x" },
		"no approval": func(r *pb.ProposeReadGrantResponse) { r.ApprovalRequirement = 0 },
		"no options":  func(r *pb.ProposeReadGrantResponse) { r.RequestOptionsJson = nil },
		"extra member": func(r *pb.ProposeReadGrantResponse) {
			r.CanonicalGrant = append(r.CanonicalGrant[:len(r.CanonicalGrant)-1], []byte(`,"x":1}`)...)
		},
	} {
		f := newFakeExecutor(now)
		f.tamper = tamper
		_, err := ProposeRegistryReadLease(context.Background(), f, leaseRequest(LeaseSelection{RegistryID: "corp", Repositories: []string{"team/app"}}), now)
		if !errors.Is(err, ErrLeaseProposalMismatch) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	f := newFakeExecutor(now)
	f.tamper = func(r *pb.ProposeReadGrantResponse) {
		r.ApprovalRequirement, r.RequestOptionsJson = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY, nil
	}
	p, err := ProposeRegistryReadLease(context.Background(), f, leaseRequest(LeaseSelection{RegistryID: "corp"}), now)
	if err != nil || !p.CLI || !slices.Equal(p.Doc.RegistryTargets[0].Repositories, []string{"team/app", "team/db"}) {
		t.Fatalf("cli proposal = %+v, %v", p, err)
	}
}
