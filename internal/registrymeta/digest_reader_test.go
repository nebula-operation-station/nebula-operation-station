// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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
		// The stale render cannot know of the revocation without an
		// executor call (stale while revalidate); it queues the listing
		// that drops the digest.
		readsBefore := f.readCount()
		r.PrivateDigests(ctx, []string{privateImage})
		drain(t, r)
		r.mu.Lock()
		n, at := len(r.cache), r.snap.at
		r.mu.Unlock()
		if n != 0 || !at.Equal(*clock) {
			t.Fatalf("stale render did not revalidate: %d cache entries, snapshot at %v", n, at)
		}
		got, errs, _ := r.PrivateDigests(ctx, []string{privateImage})
		if len(got) != 0 {
			t.Fatalf("revoked lease still served from cache: %v", got)
		}
		if _, ok := errs[privateImage]; !ok {
			t.Fatal("private image lost its Private flag after the revocation")
		}
		drain(t, r)
		if f.readCount() == readsBefore {
			t.Fatal("no background read was attempted after the revocation")
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

// switchGate is a fake executor whose calls block while block is set, so a
// test can prepare the reader with real reads and then prove a later call
// never waited on the executor.
type switchGate struct {
	*fakeExecutor
	mu    sync.Mutex
	block chan struct{} // nil: calls pass
	calls atomic.Int32
}

func (s *switchGate) wait() {
	s.calls.Add(1)
	s.mu.Lock()
	ch := s.block
	s.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

func (s *switchGate) setBlock(ch chan struct{}) { s.mu.Lock(); s.block = ch; s.mu.Unlock() }

func (s *switchGate) ListPrivateRegistries(ctx context.Context, in *pb.ListPrivateRegistriesRequest, o ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	s.wait()
	return s.fakeExecutor.ListPrivateRegistries(ctx, in, o...)
}

func (s *switchGate) ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest, o ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	s.wait()
	return s.fakeExecutor.ReadPrivateRegistry(ctx, in, o...)
}

func (s *switchGate) ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, o ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	s.wait()
	return s.fakeExecutor.ListReadGrants(ctx, in, o...)
}

// TestDigestReaderStaleSnapshotServesWhileRevalidating: a cache-only render
// whose snapshot is older than snapshotTTL still marks private images
// (cached digest for one, pending note for the other) and shows the digest
// cached within its interval, without waiting on the executor; it queues a
// background listing, after which the snapshot is fresh and the pending
// tag is read.
func TestDigestReaderStaleSnapshotServesWhileRevalidating(t *testing.T) {
	f, _, clock := leasedReader(t)
	s := &switchGate{fakeExecutor: f}
	r := NewDigestReader(s, func() time.Time { return *clock })
	const pendingImage = "registry.corp.example/team/app:2.0.0"
	const publicImage = "docker.io/library/nginx:1"
	if got, errs, err := r.PrivateDigests(context.Background(), []string{privateImage}); err != nil || len(errs) != 0 || len(got) != 1 {
		t.Fatalf("setup read: got=%v errs=%v err=%v", got, errs, err)
	}
	readsBefore := f.readCount()

	gate := make(chan struct{})
	s.setBlock(gate)
	callsBefore := s.calls.Load()
	*clock = clock.Add(snapshotTTL + time.Second) // stale, digest still in its interval
	if snapshotTTL+time.Second >= schedgrant.RegistryMinInterval {
		t.Fatal("test assumes snapshotTTL is shorter than the digest interval")
	}
	ctx := WithReadHost(WithCacheOnly(context.Background()), "web-1")
	done := make(chan struct{})
	var got map[string]PrivateDigest
	var errs map[string]error
	var err error
	go func() {
		defer close(done)
		got, errs, err = r.PrivateDigests(ctx, []string{privateImage, pendingImage, publicImage})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(gate)
		t.Fatal("a cache-only render with a stale snapshot waited on the executor")
	}
	if err != nil {
		t.Fatal(err)
	}
	if got[privateImage].Digest != fakeDigest {
		t.Fatalf("validly cached digest lost on a stale snapshot: got=%v errs=%v", got, errs)
	}
	if !errors.Is(errs[pendingImage], ErrPrivateReadPending) {
		t.Fatalf("private image lost its pending note on a stale snapshot: got=%v errs=%v", got, errs)
	}
	if _, ok := got[publicImage]; ok {
		t.Fatal("public image answered as private")
	}
	if _, ok := errs[publicImage]; ok {
		t.Fatal("public image answered as private")
	}
	if n := f.readCount(); n != readsBefore {
		t.Fatalf("stale cache-only render made %d executor reads", n-readsBefore)
	}

	// The render queued a background refresh; it lists and reads the
	// pending tag once the executor answers.
	close(gate)
	drain(t, r)
	if s.calls.Load() == callsBefore {
		t.Fatal("stale snapshot started no background refresh")
	}
	r.mu.Lock()
	at := r.snap.at
	r.mu.Unlock()
	if !at.Equal(*clock) {
		t.Fatalf("snapshot taken at %v, want the refresh at %v", at, *clock)
	}
	if n := f.readCount(); n != readsBefore+1 {
		t.Fatalf("background reads = %d, want 1 (only the pending tag)", n-readsBefore)
	}
	got, errs, _ = r.PrivateDigests(ctx, []string{privateImage, pendingImage})
	if len(got) != 2 || len(errs) != 0 {
		t.Fatalf("render after the refresh: got=%v errs=%v", got, errs)
	}
	drain(t, r)
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
