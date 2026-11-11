// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// DigestReader is the server's long-lived caller of private digest reads
// (cu06 part 1, G13). The executor allows one read of a tag per lease
// interval (schedgrant.RegistryMinInterval), so a page rendered twice
// within it would be refused the second time; DigestReader keeps each
// validated digest for that interval and answers re-renders from memory.
// Entries are keyed by the exact record and credential identity the
// executor lists, so a rotation, removal and re-add or record change asks
// the executor again. Failures are never cached. It holds no credential.
type DigestReader struct {
	exec ExecutorRegistry
	now  func() time.Time

	mu    sync.Mutex
	cache map[digestKey]cachedDigest
}

// maxCachedDigests bounds the reader's cache (50 images per result times
// a few hosts' worth of distinct tags).
const maxCachedDigests = 1024

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

// NewDigestReader returns a reader over exec; now nil uses time.Now.
func NewDigestReader(exec ExecutorRegistry, now func() time.Time) *DigestReader {
	if now == nil {
		now = time.Now
	}
	return &DigestReader{exec: exec, now: now, cache: map[digestKey]cachedDigest{}}
}

// PrivateDigests is PrivateDigests over the reader's executor, answering
// from the cache where a digest of the same tag and registry identity was
// read less than the lease interval ago.
func (r *DigestReader) PrivateDigests(ctx context.Context, images []string) (map[string]PrivateDigest, map[string]error, error) {
	return privateDigests(ctx, r.exec, images, r)
}

func keyOf(pi privateRef) digestKey {
	g := pi.registry
	return digestKey{registry: g.ID, configDigest: g.ConfigDigest, credentialID: g.CredentialID,
		configVersion: g.ConfigVersion, credentialVersion: g.CredentialVersion, repo: pi.repository, tag: pi.tag}
}

// read answers one tag from the cache or the executor.
func (r *DigestReader) read(ctx context.Context, exec ExecutorRegistry, pi privateRef) (PrivateDigest, error) {
	k := keyOf(pi)
	now := r.now()
	r.mu.Lock()
	c, ok := r.cache[k]
	r.mu.Unlock()
	if ok && now.Before(c.expires) && !now.Before(c.expires.Add(-schedgrant.RegistryMinInterval)) {
		return c.d, nil
	}
	d, err := readPrivateDigest(ctx, exec, pi)
	if err != nil {
		return PrivateDigest{}, err
	}
	r.store(k, d, now)
	return d, nil
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
