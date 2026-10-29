// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"sync"
	"time"
)

// maxCacheEntries bounds the number of cached entries. When the bound is
// reached, expired entries are dropped first; if the bound is still reached,
// the entry with the earliest expiry is evicted.
const maxCacheEntries = 1000

// cacheEntry is one cached value with its expiry.
type cacheEntry struct {
	value   any
	expires time.Time
}

// Cache is a small TTL cache with an injected clock. It is used for registry
// metadata (tag lists, digests) and for cached failures. It is safe for
// concurrent use.
type Cache struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]cacheEntry
}

// NewCache creates a Cache using now as its clock. A nil now uses time.Now.
func NewCache(now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{now: now, m: map[string]cacheEntry{}}
}

// Get returns the cached value for key if it is present and not expired.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.expires) {
		delete(c.m, key)
		return nil, false
	}
	return e.value, true
}

// Set stores value under key, valid for ttl from now.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxCacheEntries {
		c.evictLocked()
	}
	c.m[key] = cacheEntry{value: value, expires: c.now().Add(ttl)}
}

// Len returns the number of entries currently stored, including expired ones
// that have not been reaped yet. It is intended for tests.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// evictLocked drops expired entries; if the bound is still reached it drops
// the entry with the earliest expiry. Callers hold c.mu.
func (c *Cache) evictLocked() {
	now := c.now()
	for k, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, k)
		}
	}
	if len(c.m) < maxCacheEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, e := range c.m {
		if oldestKey == "" || e.expires.Before(oldest) {
			oldestKey = k
			oldest = e.expires
		}
	}
	if oldestKey != "" {
		delete(c.m, oldestKey)
	}
}
