// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// DigestReader is the server's long-lived caller of private digest reads
// (cu06 part 1, G13). The executor allows one read of a tag per lease
// interval (schedgrant.RegistryMinInterval), so a page rendered twice
// within it would be refused the second time; DigestReader keeps each
// validated digest for that interval and answers re-renders from memory.
//
// Cache entries are keyed by the exact record and credential identity the
// executor lists, so a rotation, removal and re-add or record change asks
// the executor again. A cached digest is served only while the reader's
// latest list of the executor's registry read leases shows an active,
// unexpired lease covering that identity and repository; a refresh that
// no longer shows one drops the entries. An expired lease stops answering
// at once; a revoked one at the next listing, which a render with a
// snapshot older than snapshotTTL starts in the background (stale while
// revalidate, see cachedDigests), never later than the digest's interval.
// Failures are never served as digests. It holds no credential.
//
// Fairness: the reader asks the executor for at most
// MaxHostTagsPerRepository distinct tags of one repository and
// MaxHostReadsPerRegistry distinct tags of one registry on behalf of one
// managed host (WithReadHost) per rolling hour, so one host's
// docker.check_updates result cannot spend a registry's whole budget. The
// executor additionally caps distinct tags per repository.
//
// Page renders that must not wait for the executor pass WithCacheOnly:
// they get cached digests (no executor call at all) and queue the misses
// for one bounded background worker, which reads them serially.
type DigestReader struct {
	exec   ExecutorRegistry
	leases ReadGrantLister // nil: leases unknown, cached digests are never served
	now    func() time.Time

	mu      sync.Mutex
	cache   map[digestKey]cachedDigest
	failed  map[failKey]heldFailure
	snap    readerSnapshot
	hasSnap bool
	spent   map[hostRegistry][]hostRead
	queue   []pendingRead
	queued  map[pendingRead]bool
	running bool
	idle    chan struct{} // closed when the running worker stops
	closed  bool          // Close was called: nothing is queued any more

	// life is the background worker's context; Close cancels it, so a
	// shutdown stops the batch in flight instead of letting it run out
	// its timeout.
	life context.Context
	stop context.CancelFunc
}

// Limits of DigestReader.
const (
	// maxCachedDigests bounds the reader's cache (50 images per result
	// times a few hosts' worth of distinct tags).
	maxCachedDigests = 1024
	// MaxHostTagsPerRepository bounds the distinct tags of one repository
	// read for one managed host per rolling hour.
	MaxHostTagsPerRepository = 4
	// MaxHostReadsPerRegistry bounds the distinct tags of one registry read
	// for one managed host per rolling hour: a third of the default
	// per-registry budget, so one host never spends all of it.
	MaxHostReadsPerRegistry = schedgrant.RegistryDefaultRunBudget / 3
	// maxTrackedHostRegistries bounds the per-host spend table.
	maxTrackedHostRegistries = 1024
	// maxReadHostLen bounds a host identity taken from the context.
	maxReadHostLen = 128
	// snapshotTTL is how long a cache-only render trusts the listed
	// registries and leases.
	snapshotTTL = time.Minute
	// maxPendingReads bounds the background queue.
	maxPendingReads = 256
	// backgroundBatchTimeout bounds one background batch (listing and all
	// reads); backgroundReadTimeout bounds one read in it.
	backgroundBatchTimeout = 2 * time.Minute
	backgroundReadTimeout  = 10 * time.Second
	// failureHold is how long a background failure is shown and keeps the
	// same read from being queued again.
	failureHold = time.Minute
)

// Errors of DigestReader beyond those of PrivateDigests.
var (
	// ErrPrivateReadPending: a cache-only render queued the read; it runs
	// in the background and a later render shows the digest.
	ErrPrivateReadPending = errors.New("registrymeta: the private registry read is queued in the background")
	// ErrPrivateHostLimit: the host already had its distinct tags of the
	// repository or registry read this hour. It is a rate limit.
	ErrPrivateHostLimit = fmt.Errorf("%w: the host named too many distinct private tags this hour", ErrPrivateReadRateLimited)
)

type ctxKey int

const (
	cacheOnlyKey ctxKey = iota
	readHostKey
)

// WithCacheOnly marks ctx so DigestReader answers from its cache only,
// never calls the executor during the call and queues misses for its
// background worker. Page renders use it.
func WithCacheOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, cacheOnlyKey, true)
}

// CacheOnly reports whether ctx carries WithCacheOnly.
func CacheOnly(ctx context.Context) bool {
	v, _ := ctx.Value(cacheOnlyKey).(bool)
	return v
}

// WithReadHost names the managed host whose docker.check_updates result a
// DigestReader call resolves; the per-host caps count against it. Reads
// without a host share one bucket.
func WithReadHost(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, readHostKey, host)
}

// ReadHost returns the host of WithReadHost, or "" (the shared bucket)
// when none or an over-long one is set.
func ReadHost(ctx context.Context) string {
	h, _ := ctx.Value(readHostKey).(string)
	if len(h) > maxReadHostLen {
		return ""
	}
	return h
}

// digestKey is one tag of one repository under one exact registry identity.
type digestKey struct {
	registry, configDigest, credentialID string
	configVersion, credentialVersion     int64
	repo, tag                            string
}

type cachedDigest struct {
	d       PrivateDigest
	expires time.Time
}

// failKey is a failed read for one host (host caps differ per host).
type failKey struct {
	host string
	k    digestKey
}

type heldFailure struct {
	err   error
	until time.Time
}

// readerSnapshot is the executor's registries and registry read leases as
// last listed.
type readerSnapshot struct {
	regs     []PrivateIdentity
	leases   []LeaseView
	leasesOK bool
	at       time.Time
}

type hostRegistry struct{ host, registry string }

type hostRead struct {
	repo, tag string
	at        time.Time
}

type pendingRead struct{ host, image string }

// NewDigestReader returns a reader over exec; now nil uses time.Now. When
// exec also lists read grants (ReadGrantLister, as the server's executor
// client does), cached digests are served while a lease covers them;
// otherwise every call reads.
func NewDigestReader(exec ExecutorRegistry, now func() time.Time) *DigestReader {
	if now == nil {
		now = time.Now
	}
	lister, _ := exec.(ReadGrantLister)
	life, stop := context.WithCancel(context.Background())
	return &DigestReader{exec: exec, leases: lister, now: now, cache: map[digestKey]cachedDigest{},
		failed: map[failKey]heldFailure{}, spent: map[hostRegistry][]hostRead{}, queued: map[pendingRead]bool{},
		life: life, stop: stop}
}

// PrivateDigests is PrivateDigests over the reader's executor, answering
// from the cache where a covered digest of the same tag and registry
// identity was read less than the lease interval ago, and spending the
// host's caps (WithReadHost) on every new read. With WithCacheOnly it
// makes no executor call: misses are ErrPrivateReadPending (or the held
// reason of a recent background failure) and run in the background.
func (r *DigestReader) PrivateDigests(ctx context.Context, images []string) (map[string]PrivateDigest, map[string]error, error) {
	host := ReadHost(ctx)
	if CacheOnly(ctx) {
		out, errs := r.cachedDigests(host, images)
		return out, errs, nil
	}
	now := r.now()
	snap, err := r.refresh(ctx, now)
	if err != nil {
		return nil, nil, err
	}
	out, errs := resolveImages(images, snap.regs, func(_ string, pi privateRef) (PrivateDigest, error) {
		// Each read is stamped when it is made, not when the call began:
		// earlier reads of the call may have taken their full timeout.
		at := r.now()
		if d, ok := r.cached(snap, pi, at); ok {
			return d, nil
		}
		if err := r.charge(host, pi, at); err != nil {
			return PrivateDigest{}, err
		}
		d, err := readPrivateDigest(ctx, r.exec, pi)
		if err != nil {
			return PrivateDigest{}, err
		}
		r.store(keyOf(pi), d, at)
		return d, nil
	})
	return out, errs, nil
}

// cachedDigests answers images from memory only and queues the misses.
// Without any snapshot nothing is known to be private: every image is
// queued, and the background worker lists before it reads.
//
// A snapshot older than snapshotTTL is still served (stale while
// revalidate): private images keep their Private flag and pending note and
// digests still within their interval and covered by the snapshot's
// leases (expiry checked against now) are shown, and every image is queued
// so the background worker lists again before it reads. That refresh drops
// the digests of leases revoked meanwhile, so a revocation the reader has
// not listed yet is shown on renders until the next background listing,
// never longer than the digest's own interval (RegistryMinInterval); no
// executor read is made for it.
func (r *DigestReader) cachedDigests(host string, images []string) (map[string]PrivateDigest, map[string]error) {
	if len(images) > MaxPrivateDigestImages {
		images = images[:MaxPrivateDigestImages]
	}
	now := r.now()
	r.mu.Lock()
	snap, has := r.snap, r.hasSnap
	r.mu.Unlock()
	if !has {
		for _, img := range images {
			r.enqueue(host, img)
		}
		return map[string]PrivateDigest{}, map[string]error{}
	}
	if now.Before(snap.at) || now.Sub(snap.at) >= snapshotTTL {
		// Stale: revalidate in the background, answer from the snapshot.
		for _, img := range images {
			r.enqueue(host, img)
		}
	}
	return resolveImages(images, snap.regs, func(img string, pi privateRef) (PrivateDigest, error) {
		if d, ok := r.cached(snap, pi, now); ok {
			return d, nil
		}
		if f, ok := r.heldFailure(host, keyOf(pi), now); ok {
			return PrivateDigest{}, f.err
		}
		r.enqueue(host, img)
		return PrivateDigest{}, ErrPrivateReadPending
	})
}

func keyOf(pi privateRef) digestKey {
	g := pi.registry
	return digestKey{registry: g.ID, configDigest: g.ConfigDigest, credentialID: g.CredentialID,
		configVersion: g.ConfigVersion, credentialVersion: g.CredentialVersion, repo: pi.repository, tag: pi.tag}
}

// refresh lists the executor's registries (an error fails the call) and,
// when the executor lists read grants, its registry read leases (an error
// only leaves them unknown), then drops the cached digests no active
// lease covers any more.
func (r *DigestReader) refresh(ctx context.Context, now time.Time) (readerSnapshot, error) {
	regs, err := ListPrivateIdentities(ctx, r.exec)
	if err != nil {
		return readerSnapshot{}, err
	}
	s := readerSnapshot{regs: regs, at: now}
	if r.leases != nil {
		if l, err := ListRegistryLeases(ctx, r.leases, now); err == nil {
			s.leases, s.leasesOK = l, true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snap, r.hasSnap = s, true
	for k := range r.cache {
		id := PrivateIdentity{ID: k.registry, ConfigDigest: k.configDigest, ConfigVersion: k.configVersion,
			CredentialID: k.credentialID, CredentialVersion: k.credentialVersion}
		if !covered(s, id, k.repo, now) {
			delete(r.cache, k)
		}
	}
	return s, nil
}

// covered reports whether the snapshot shows an active, unexpired,
// unrevoked registry read lease whose frozen target is exactly id and
// allows tag_digest reads of repo.
func covered(s readerSnapshot, id PrivateIdentity, repo string, now time.Time) bool {
	if !s.leasesOK {
		return false
	}
	for _, l := range s.leases {
		if l.State != "active" || !l.Revoked.IsZero() || !now.Before(l.Expiry) {
			continue
		}
		for _, t := range l.Registries {
			if t.RegistryID == id.ID && t.ConfigDigest == id.ConfigDigest && t.ConfigVersion == id.ConfigVersion &&
				t.CredentialID == id.CredentialID && t.CredentialVersion == id.CredentialVersion &&
				t.AllowsRead(schedgrant.RegistryReadTagDigest, repo) {
				return true
			}
		}
	}
	return false
}

// cached returns the cached digest of pi if it is within its interval and
// a lease in snap still covers it.
func (r *DigestReader) cached(snap readerSnapshot, pi privateRef, now time.Time) (PrivateDigest, bool) {
	r.mu.Lock()
	c, ok := r.cache[keyOf(pi)]
	r.mu.Unlock()
	if !ok || !now.Before(c.expires) || now.Before(c.expires.Add(-schedgrant.RegistryMinInterval)) {
		return PrivateDigest{}, false
	}
	if !covered(snap, pi.registry, pi.repository, now) {
		return PrivateDigest{}, false
	}
	return c.d, true
}

// charge spends one of host's distinct-tag slots for pi, or refuses with
// ErrPrivateHostLimit. A tag already read for the host within the rolling
// hour takes no new slot.
func (r *DigestReader) charge(host string, pi privateRef, now time.Time) error {
	k := hostRegistry{host: host, registry: pi.registry.ID}
	cutoff := now.Add(-permit.RollingHour)
	r.mu.Lock()
	defer r.mu.Unlock()
	live := func(rs []hostRead) []hostRead {
		out := rs[:0]
		for _, x := range rs {
			// A read stamped in the future (clock rollback) still counts.
			if x.at.After(cutoff) {
				out = append(out, x)
			}
		}
		return out
	}
	reads, known := r.spent[k]
	if !known && len(r.spent) >= maxTrackedHostRegistries {
		for x, rs := range r.spent {
			if rs = live(rs); len(rs) == 0 {
				delete(r.spent, x)
			} else {
				r.spent[x] = rs
			}
		}
		if len(r.spent) >= maxTrackedHostRegistries {
			return ErrPrivateHostLimit
		}
	}
	reads = live(reads)
	inRepo := 0
	for _, x := range reads {
		if x.repo == pi.repository && x.tag == pi.tag {
			r.spent[k] = reads
			return nil
		}
		if x.repo == pi.repository {
			inRepo++
		}
	}
	if inRepo >= MaxHostTagsPerRepository || len(reads) >= MaxHostReadsPerRegistry {
		r.spent[k] = reads
		return ErrPrivateHostLimit
	}
	r.spent[k] = append(reads, hostRead{repo: pi.repository, tag: pi.tag, at: now})
	return nil
}

// store keeps d for the lease interval, dropping expired entries and, when
// full, the entry that expires first.
func (r *DigestReader) store(k digestKey, d PrivateDigest, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCachedDigests {
		var oldest digestKey
		found := false
		for x, c := range r.cache {
			if !now.Before(c.expires) {
				delete(r.cache, x)
				continue
			}
			if !found || c.expires.Before(r.cache[oldest].expires) {
				oldest, found = x, true
			}
		}
		if len(r.cache) >= maxCachedDigests && found {
			delete(r.cache, oldest)
		}
	}
	r.cache[k] = cachedDigest{d: d, expires: now.Add(schedgrant.RegistryMinInterval)}
}

// hold remembers a background failure for failureHold.
func (r *DigestReader) hold(host string, k digestKey, err error, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.failed) >= maxCachedDigests {
		for x, f := range r.failed {
			if !now.Before(f.until) {
				delete(r.failed, x)
			}
		}
		if len(r.failed) >= maxCachedDigests {
			clear(r.failed)
		}
	}
	r.failed[failKey{host: host, k: k}] = heldFailure{err: err, until: now.Add(failureHold)}
}

// heldFailure returns host's held failure of k, if one is still held.
func (r *DigestReader) heldFailure(host string, k digestKey, now time.Time) (heldFailure, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.failed[failKey{host: host, k: k}]
	if !ok || !now.Before(f.until) || now.Before(f.until.Add(-failureHold)) {
		return heldFailure{}, false
	}
	return f, true
}

// enqueue queues one image of host for the background worker and starts
// it when idle. A full queue drops the request; a later render asks again.
func (r *DigestReader) enqueue(host, image string) {
	p := pendingRead{host: host, image: image}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.queued[p] || len(r.queue) >= maxPendingReads {
		return
	}
	r.queued[p] = true
	r.queue = append(r.queue, p)
	if !r.running {
		r.running = true
		r.idle = make(chan struct{})
		go r.work(r.idle)
	}
}

// Close stops the background worker for a shutdown: nothing is queued any
// more, queued reads are dropped, the batch in flight is cancelled, and
// Close waits (Drain) until the worker has stopped or ctx ends. Cache-only
// calls still answer from memory afterwards; calls without WithCacheOnly
// still read synchronously under their own context.
func (r *DigestReader) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.queue = nil
	r.mu.Unlock()
	r.stop()
	return r.Drain(ctx)
}

// Drain blocks until the background worker is idle or ctx ends. Close
// uses it on shutdown; tests use it to wait for queued reads.
func (r *DigestReader) Drain(ctx context.Context) error {
	for {
		r.mu.Lock()
		running, idle := r.running, r.idle
		r.mu.Unlock()
		if !running {
			return nil
		}
		select {
		case <-idle:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// work runs queued batches one after another until the queue is empty.
func (r *DigestReader) work(idle chan struct{}) {
	defer close(idle)
	for {
		r.mu.Lock()
		batch := r.queue
		r.queue = nil
		if len(batch) == 0 {
			r.running = false
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
		r.runBatch(batch)
		r.mu.Lock()
		for _, p := range batch {
			delete(r.queued, p)
		}
		r.mu.Unlock()
	}
}

// runBatch lists once, then reads each queued private image serially, each
// under its own timeout and the host's caps, inside one batch deadline
// that Close cancels. Every check, charge and cache entry is stamped at
// its own read and every held failure when its read failed, not at the
// start of the batch, which may be up to backgroundBatchTimeout earlier.
func (r *DigestReader) runBatch(batch []pendingRead) {
	ctx, cancel := context.WithTimeout(r.life, backgroundBatchTimeout)
	defer cancel()
	snap, err := r.refresh(ctx, r.now())
	if err != nil {
		return
	}
	for _, p := range batch {
		if ctx.Err() != nil {
			return
		}
		pi, err := matchPrivateImage(p.image, snap.regs)
		if err != nil {
			continue // not private, or answered without I/O on render
		}
		at := r.now()
		if _, ok := r.cached(snap, pi, at); ok {
			continue
		}
		if _, ok := r.heldFailure(p.host, keyOf(pi), at); ok {
			continue
		}
		if err := r.charge(p.host, pi, at); err != nil {
			r.hold(p.host, keyOf(pi), err, at)
			continue
		}
		rctx, rcancel := context.WithTimeout(ctx, backgroundReadTimeout)
		d, err := readPrivateDigest(rctx, r.exec, pi)
		rcancel()
		if err != nil {
			if r.life.Err() != nil {
				return // shut down: not a registry failure to hold
			}
			r.hold(p.host, keyOf(pi), err, r.now())
			continue
		}
		r.store(keyOf(pi), d, at)
	}
}
