// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// clientError wraps a gRPC status like the executor client's coded error
// (executorclient.Error keeps the status as its cause).
type clientError struct{ cause error }

func (e *clientError) Error() string { return "executor: limit" }
func (e *clientError) Unwrap() error { return e.cause }

// TestPrivateDigestRateLimitedIsItsOwnError: a ResourceExhausted answer
// (budget or interval) is ErrPrivateReadRateLimited, not a refusal.
func TestPrivateDigestRateLimitedIsItsOwnError(t *testing.T) {
	for _, readErr := range []error{
		status.Error(codes.ResourceExhausted, "read private registry: the same read ran less than its minimum interval ago"),
		&clientError{cause: status.Error(codes.ResourceExhausted, "budget")},
	} {
		f := newFakeExecutor(time.Unix(1_800_000_000, 0))
		f.readErr = readErr
		_, errs, err := PrivateDigests(context.Background(), f, []string{privateImage})
		if err != nil || !errors.Is(errs[privateImage], ErrPrivateReadRateLimited) || errors.Is(errs[privateImage], ErrPrivateReadRefused) {
			t.Fatalf("%v: errs=%v err=%v, want rate limited", readErr, errs, err)
		}
	}
	f := newFakeExecutor(time.Unix(1_800_000_000, 0))
	f.readErr = &clientError{cause: status.Error(codes.PermissionDenied, "no lease")}
	if _, errs, _ := PrivateDigests(context.Background(), f, []string{privateImage}); !errors.Is(errs[privateImage], ErrPrivateReadRefused) {
		t.Fatalf("wrapped PermissionDenied: %v", errs)
	}
}

// TestDigestReaderReRenderUsesCache: a re-render within the lease interval
// does not read again (the executor would answer ResourceExhausted); two
// tags of one repository are two reads; after the interval, or when the
// registry identity changes, the reader asks again.
func TestDigestReaderReRenderUsesCache(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	ctx := context.Background()
	p, err := ProposeRegistryReadLease(ctx, f, leaseRequest(LeaseSelection{RegistryID: "corp", Repositories: []string{"team/app"}}), now)
	if err != nil {
		t.Fatal(err)
	}
	f.approve(t, p.Digest)
	clock := now
	r := NewDigestReader(f, func() time.Time { return clock })
	second := "registry.corp.example/team/app:2.0.0"
	images := []string{privateImage, second}
	for i := range 2 { // first render and an immediate re-render
		got, errs, err := r.PrivateDigests(ctx, images)
		if err != nil || len(errs) != 0 || got[privateImage].Digest != fakeDigest || got[second].Digest != fakeDigest {
			t.Fatalf("render %d: got=%v errs=%v err=%v", i, got, errs, err)
		}
	}
	if n := f.readCount(); n != 2 {
		t.Fatalf("reads after two renders = %d, want 2 (one per tag)", n)
	}
	clock = clock.Add(schedgrant.RegistryMinInterval)
	if _, _, err := r.PrivateDigests(ctx, images); err != nil {
		t.Fatal(err)
	}
	if n := f.readCount(); n != 4 {
		t.Fatalf("reads after the interval = %d, want 4", n)
	}
	f.mu.Lock()
	f.infos[0].CredentialVersion = 3 // a rotation: cached digests are not reused
	f.mu.Unlock()
	if _, _, err := r.PrivateDigests(ctx, images); err != nil {
		t.Fatal(err)
	}
	if n := f.readCount(); n != 6 {
		t.Fatalf("reads after a rotation = %d, want 6", n)
	}
	f.assertNoCredential(t)
}

// TestDigestReaderCachesNoFailure: a refused or rate-limited read is not
// cached, and the cache stays bounded.
func TestDigestReaderCachesNoFailure(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	r := NewDigestReader(f, func() time.Time { return now })
	ctx := context.Background()
	for range 2 {
		if _, errs, _ := r.PrivateDigests(ctx, []string{privateImage}); !errors.Is(errs[privateImage], ErrPrivateReadRefused) {
			t.Fatalf("errs = %v", errs)
		}
	}
	if n := f.readCount(); n != 2 {
		t.Fatalf("a refusal was cached: %d reads", n)
	}
	for i := range maxCachedDigests + 10 {
		r.store(digestKey{repo: fmt.Sprintf("r%d", i)}, PrivateDigest{Digest: fakeDigest}, now)
	}
	if n := len(r.cache); n > maxCachedDigests {
		t.Fatalf("cache holds %d entries", n)
	}
}

// TestDecodeRegistryLease: an executor-held registry read lease decodes to
// its frozen registries with state active, expired or revoked; anything
// that does not verify is not a registry lease view.
func TestDecodeRegistryLease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	p, err := ProposeRegistryReadLease(context.Background(), f, leaseRequest(LeaseSelection{RegistryID: "corp"}), now)
	if err != nil {
		t.Fatal(err)
	}
	canon, _ := f.canonical(p.Digest)
	grant := func() *pb.ReadGrant {
		return &pb.ReadGrant{GrantId: fakeLeaseID, GrantDigest: p.Digest, CanonicalGrant: canon, ApprovedBy: "webauthn:abcd",
			CreatedUnix: now.Unix(), ExpiryUnix: p.Doc.ExpiryUnix}
	}
	v, ok := DecodeRegistryLease(grant(), now.Add(time.Hour))
	if !ok || v.State != "active" || len(v.Registries) != 1 || v.Registries[0].RegistryID != "corp" ||
		strings.Join(v.Registries[0].Repositories, ",") != "team/app,team/db" || v.RunBudget != schedgrant.RegistryDefaultRunBudget ||
		v.MinInterval != schedgrant.RegistryMinInterval || v.ApprovedBy != "webauthn:abcd" {
		t.Fatalf("view = %+v %v", v, ok)
	}
	if v, ok := DecodeRegistryLease(grant(), now.Add(8*24*time.Hour)); !ok || v.State != "expired" {
		t.Fatalf("expired = %+v %v", v, ok)
	}
	g := grant()
	g.RevokedUnix = now.Add(time.Minute).Unix()
	if v, ok := DecodeRegistryLease(g, now.Add(time.Hour)); !ok || v.State != "revoked" {
		t.Fatalf("revoked = %+v %v", v, ok)
	}
	for name, mutate := range map[string]func(*pb.ReadGrant){
		"digest":   func(g *pb.ReadGrant) { g.GrantDigest = strings.Repeat("0", 64) },
		"id":       func(g *pb.ReadGrant) { g.GrantId = "00000000-0000-4000-8000-000000000001" },
		"expiry":   func(g *pb.ReadGrant) { g.ExpiryUnix++ },
		"created":  func(g *pb.ReadGrant) { g.CreatedUnix = now.Unix() - 1 },
		"approver": func(g *pb.ReadGrant) { g.ApprovedBy = "x" + string(rune(0x202e)) + "y" },
		"unknown":  func(g *pb.ReadGrant) { g.CanonicalGrant = append([]byte(`{"zz":1,`), g.CanonicalGrant[1:]...) },
		"not utf8": func(g *pb.ReadGrant) { g.CanonicalGrant = append(g.CanonicalGrant, 0xff) },
		"other grant": func(g *pb.ReadGrant) {
			g.CanonicalGrant = []byte(strings.Replace(string(canon), `"registry"`, `"ordinary"`, 1))
		},
	} {
		g := grant()
		mutate(g)
		if v, ok := DecodeRegistryLease(g, now.Add(time.Hour)); ok {
			t.Fatalf("%s: decoded %+v", name, v)
		}
	}
}

// TestListRegistryLeases lists only the registry read leases.
func TestListRegistryLeases(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	p, err := ProposeRegistryReadLease(context.Background(), f, leaseRequest(LeaseSelection{RegistryID: "corp"}), now)
	if err != nil {
		t.Fatal(err)
	}
	canon, _ := f.canonical(p.Digest)
	f.grants = []*pb.ReadGrant{
		{GrantId: fakeLeaseID, GrantDigest: p.Digest, CanonicalGrant: canon, ApprovedBy: "cli:root", CreatedUnix: now.Unix(), ExpiryUnix: p.Doc.ExpiryUnix},
		{GrantId: "00000000-0000-4000-8000-000000000002", GrantDigest: strings.Repeat("1", 64), CanonicalGrant: []byte(`{}`)},
	}
	got, err := ListRegistryLeases(context.Background(), f, now)
	if err != nil || len(got) != 1 || got[0].ID != fakeLeaseID {
		t.Fatalf("got %+v, %v", got, err)
	}
	f.listGrantsErr = status.Error(codes.Unavailable, "down")
	if _, err := ListRegistryLeases(context.Background(), f, now); !errors.Is(err, ErrLeaseListFailed) {
		t.Fatalf("list failure: %v", err)
	}
}
