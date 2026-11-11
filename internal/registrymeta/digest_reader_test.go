// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// leasedReader returns a fake executor with an approved lease over the
// whole scope of "corp" (repos, when given, replace the scope first) and a
// DigestReader over it on a test clock.
func leasedReader(t *testing.T, repos ...string) (*fakeExecutor, *DigestReader, *time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	if len(repos) > 0 {
		f.infos[0].Repositories = repos
	}
	p, err := ProposeRegistryReadLease(context.Background(), f, leaseRequest(LeaseSelection{RegistryID: "corp"}), now)
	if err != nil {
		t.Fatal(err)
	}
	f.approve(t, p.Digest)
	clock := now
	return f, NewDigestReader(f, func() time.Time { return clock }), &clock
}

func drain(t *testing.T, r *DigestReader) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.Drain(ctx); err != nil {
		t.Fatalf("background worker did not finish: %v", err)
	}
}

// TestDigestReaderHostCapProtectsRegistryBudget: one host naming 50 tags of
// one repository gets MaxHostTagsPerRepository executor reads, and across
// repositories MaxHostReadsPerRegistry; the rest are rate limited without
// an executor call, and another host still gets its own reads.
func TestDigestReaderHostCapProtectsRegistryBudget(t *testing.T) {
	f, r, clock := leasedReader(t, "team/app", "team/db", "team/web")
	evil := WithReadHost(context.Background(), "evil")
	var tags []string
	for i := range MaxPrivateDigestImages {
		tags = append(tags, fmt.Sprintf("registry.corp.example/team/app:t%d", i))
	}
	got, errs, err := r.PrivateDigests(evil, tags)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxHostTagsPerRepository || f.readCount() != MaxHostTagsPerRepository {
		t.Fatalf("one repository: %d digests, %d executor reads, want %d", len(got), f.readCount(), MaxHostTagsPerRepository)
	}
	for img, e := range errs {
		if !errors.Is(e, ErrPrivateHostLimit) || !errors.Is(e, ErrPrivateReadRateLimited) {
			t.Fatalf("%s: %v, want the host limit (a rate limit)", img, e)
		}
	}
	// Across repositories the per-registry cap holds.
	var more []string
	for _, repo := range []string{"team/db", "team/web"} {
		for i := range MaxHostTagsPerRepository {
			more = append(more, fmt.Sprintf("registry.corp.example/%s:m%d", repo, i))
		}
	}
	if _, _, err := r.PrivateDigests(evil, more); err != nil {
		t.Fatal(err)
	}
	if n := f.readCount(); n != MaxHostReadsPerRegistry {
		t.Fatalf("executor reads for one host = %d, want %d", n, MaxHostReadsPerRegistry)
	}
	// Another host is not starved by the first one.
	good := WithReadHost(context.Background(), "good")
	got, errs, err = r.PrivateDigests(good, []string{"registry.corp.example/team/app:stable"})
	if err != nil || len(errs) != 0 || len(got) != 1 {
		t.Fatalf("other host: got=%v errs=%v err=%v", got, errs, err)
	}
	// A tag already counted for the host takes no new slot after its
	// interval; a new one still does not fit.
	*clock = clock.Add(schedgrant.RegistryMinInterval)
	before := f.readCount()
	got, errs, _ = r.PrivateDigests(evil, []string{tags[0], tags[MaxHostTagsPerRepository]})
	if _, ok := got[tags[0]]; !ok || !errors.Is(errs[tags[MaxHostTagsPerRepository]], ErrPrivateHostLimit) || f.readCount() != before+1 {
		t.Fatalf("re-read: got=%v errs=%v reads=%d", got, errs, f.readCount()-before)
	}
	// After the rolling hour the host has its slots again.
	*clock = clock.Add(time.Hour)
	if got, _, _ := r.PrivateDigests(evil, []string{tags[MaxHostTagsPerRepository]}); len(got) != 1 {
		t.Fatal("host slots did not roll over after an hour")
	}
}

// gatedExecutor blocks every executor call until open is closed, so a test
// can prove a call never waited on the executor.
type gatedExecutor struct {
	*fakeExecutor
	open  chan struct{}
	calls atomic.Int32
}

func (g *gatedExecutor) wait() { g.calls.Add(1); <-g.open }

func (g *gatedExecutor) ListPrivateRegistries(ctx context.Context, in *pb.ListPrivateRegistriesRequest, o ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	g.wait()
	return g.fakeExecutor.ListPrivateRegistries(ctx, in, o...)
}

func (g *gatedExecutor) ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest, o ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	g.wait()
	return g.fakeExecutor.ReadPrivateRegistry(ctx, in, o...)
}

func (g *gatedExecutor) ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, o ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	g.wait()
	return g.fakeExecutor.ListReadGrants(ctx, in, o...)
}

// TestDigestReaderCacheOnlyNeverWaitsOnExecutor: a cache-only call returns
// while the executor is blocked (it never calls it), queues the misses
// once however often the page renders, and a later render shows the
// digests the background worker read.
func TestDigestReaderCacheOnlyNeverWaitsOnExecutor(t *testing.T) {
	f, _, clock := leasedReader(t)
	g := &gatedExecutor{fakeExecutor: f, open: make(chan struct{})}
	r := NewDigestReader(g, func() time.Time { return *clock })
	ctx := WithReadHost(WithCacheOnly(context.Background()), "web-1")
	images := []string{privateImage, "registry.corp.example/team/app:2.0.0", "docker.io/library/nginx:1"}
	for i := range 5 { // five renders while the executor hangs
		done := make(chan struct{})
		var got map[string]PrivateDigest
		go func() {
			defer close(done)
			got, _, _ = r.PrivateDigests(ctx, images)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			close(g.open)
			t.Fatalf("render %d waited on the executor", i)
		}
		if len(got) != 0 {
			t.Fatalf("render %d: digests before any read: %v", i, got)
		}
	}
	close(g.open)
	drain(t, r)
	if n := f.readCount(); n != 2 {
		t.Fatalf("background reads = %d, want 2 (one per private tag, queued once)", n)
	}
	callsAfterDrain := g.calls.Load()
	got, errs, err := r.PrivateDigests(ctx, images)
	if err != nil || len(errs) != 0 || got[privateImage].Digest != fakeDigest || len(got) != 2 {
		t.Fatalf("render after the background read: got=%v errs=%v err=%v", got, errs, err)
	}
	drain(t, r)
	if g.calls.Load() != callsAfterDrain {
		t.Fatal("a cache-only render with every digest cached called the executor")
	}
}

// TestDigestReaderCacheOnlyHoldsFailures: a refused background read shows
// its reason for failureHold and is not queued again meanwhile.
func TestDigestReaderCacheOnlyHoldsFailures(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now) // no lease
	clock := now
	r := NewDigestReader(f, func() time.Time { return clock })
	ctx := WithCacheOnly(context.Background())
	if _, errs, _ := r.PrivateDigests(ctx, []string{privateImage}); len(errs) != 0 {
		t.Fatalf("without a snapshot nothing is known: %v", errs)
	}
	drain(t, r)
	for range 3 {
		_, errs, _ := r.PrivateDigests(ctx, []string{privateImage})
		if !errors.Is(errs[privateImage], ErrPrivateReadRefused) {
			t.Fatalf("held failure: %v", errs)
		}
	}
	drain(t, r)
	if n := f.readCount(); n != 1 {
		t.Fatalf("executor reads = %d, want 1 (the refusal is held)", n)
	}
	// After the hold (and with a fresh listing) the read is queued again.
	clock = clock.Add(failureHold)
	if _, _, err := r.PrivateDigests(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	_, errs, _ := r.PrivateDigests(ctx, []string{privateImage})
	if !errors.Is(errs[privateImage], ErrPrivateReadPending) {
		t.Fatalf("after the hold: %v", errs)
	}
	drain(t, r)
	if n := f.readCount(); n != 2 {
		t.Fatalf("executor reads after the hold = %d, want 2", n)
	}
}

// TestDigestReaderRevokedLeaseDropsCache: a revoked lease stops the cache
// from answering at the next listing, and an expired one at once, instead
// of serving "read by the executor" for the rest of the interval.
func TestDigestReaderRevokedLeaseDropsCache(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		f, r, clock := leasedReader(t)
		ctx := context.Background()
		if got, _, _ := r.PrivateDigests(ctx, []string{privateImage}); len(got) != 1 {
			t.Fatal("first read failed")
		}
		f.revoke(fakeLeaseID, *clock)
		*clock = clock.Add(time.Minute)
		got, errs, _ := r.PrivateDigests(ctx, []string{privateImage})
		if len(got) != 0 || !errors.Is(errs[privateImage], ErrPrivateReadRefused) {
			t.Fatalf("after revocation: got=%v errs=%v", got, errs)
		}
		r.mu.Lock()
		n := len(r.cache)
		r.mu.Unlock()
		if n != 0 {
			t.Fatalf("revoked lease left %d cache entries", n)
		}
	})
	t.Run("revoked, cache-only", func(t *testing.T) {
		f, r, clock := leasedReader(t)
		if got, _, _ := r.PrivateDigests(context.Background(), []string{privateImage}); len(got) != 1 {
			t.Fatal("first read failed")
		}
		f.revoke(fakeLeaseID, *clock)
		*clock = clock.Add(snapshotTTL)
		ctx := WithCacheOnly(context.Background())
		if got, _, _ := r.PrivateDigests(ctx, []string{privateImage}); len(got) != 0 {
			t.Fatalf("stale snapshot served a digest: %v", got)
		}
		drain(t, r)
		if got, _, _ := r.PrivateDigests(ctx, []string{privateImage}); len(got) != 0 {
			t.Fatalf("revoked lease still served from cache: %v", got)
		}
	})
	t.Run("expired", func(t *testing.T) {
		f, r, clock := leasedReader(t)
		if got, _, _ := r.PrivateDigests(context.Background(), []string{privateImage}); len(got) != 1 {
			t.Fatal("first read failed")
		}
		f.mu.Lock()
		expiry := time.Unix(f.approved[0].ExpiryUnix, 0)
		f.mu.Unlock()
		// The snapshot is fresh, the digest within its interval, but the
		// lease expired.
		*clock = expiry
		r.mu.Lock()
		r.snap.at = expiry.Add(-time.Second)
		r.cache[digestKeyFor(t, r, privateImage)] = cachedDigest{d: PrivateDigest{Digest: fakeDigest}, expires: expiry.Add(time.Minute)}
		r.mu.Unlock()
		if got, _, _ := r.PrivateDigests(WithCacheOnly(context.Background()), []string{privateImage}); len(got) != 0 {
			t.Fatalf("expired lease served from cache: %v", got)
		}
		drain(t, r)
	})
}

// digestKeyFor is the cache key of a private image under the reader's
// current snapshot.
func digestKeyFor(t *testing.T, r *DigestReader, image string) digestKey {
	t.Helper()
	pi, err := matchPrivateImage(image, r.snap.regs)
	if err != nil {
		t.Fatal(err)
	}
	return keyOf(pi)
}

// TestDigestReaderWithoutLeaseListNeverServesCache: an executor client
// that cannot list leases gets no cached answers (fail closed).
func TestDigestReaderWithoutLeaseListNeverServesCache(t *testing.T) {
	f, _, clock := leasedReader(t)
	r := NewDigestReader(struct{ ExecutorRegistry }{f}, func() time.Time { return *clock })
	for range 2 {
		if _, _, err := r.PrivateDigests(context.Background(), []string{privateImage}); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.readCount(); n != 2 {
		t.Fatalf("reads = %d, want 2 (no cache without the lease list)", n)
	}
}

// TestDigestReaderQueueAndHostBounded: the background queue and the host
// identity taken from the context are bounded.
func TestDigestReaderQueueAndHostBounded(t *testing.T) {
	f, _, clock := leasedReader(t)
	g := &gatedExecutor{fakeExecutor: f, open: make(chan struct{})}
	r := NewDigestReader(g, func() time.Time { return *clock })
	for i := range 3 * maxPendingReads {
		r.enqueue(fmt.Sprintf("h%d", i), privateImage)
	}
	r.mu.Lock()
	n := len(r.queue)
	r.mu.Unlock()
	close(g.open)
	drain(t, r)
	if n > maxPendingReads {
		t.Fatalf("queue holds %d", n)
	}
	if h := ReadHost(WithReadHost(context.Background(), strings.Repeat("h", maxReadHostLen+1))); h != "" {
		t.Fatalf("over-long host kept: %q", h)
	}
	if ReadHost(context.Background()) != "" || CacheOnly(context.Background()) {
		t.Fatal("bare context carries reader options")
	}
}
