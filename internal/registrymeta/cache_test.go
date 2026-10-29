// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock is a deterministic clock for tests. Sleep advances the clock
// instead of blocking.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func (f *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	f.Advance(d)
	return nil
}

func TestCacheGetSet(t *testing.T) {
	fc := newFakeClock()
	c := NewCache(fc.Now)

	if _, ok := c.Get("missing"); ok {
		t.Fatal("expected a miss for a missing key")
	}
	c.Set("k", "v", time.Hour)
	got, ok := c.Get("k")
	if !ok || got != "v" {
		t.Fatalf("expected v, got %v ok=%v", got, ok)
	}
}

func TestCacheExpiry(t *testing.T) {
	fc := newFakeClock()
	c := NewCache(fc.Now)
	c.Set("k", "v", time.Minute)

	fc.Advance(time.Minute - time.Nanosecond)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("entry must be valid until the TTL elapses")
	}
	fc.Advance(2 * time.Nanosecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("entry must be expired after the TTL")
	}
}

func TestCacheEvictsOldestAtBound(t *testing.T) {
	fc := newFakeClock()
	c := NewCache(fc.Now)

	for i := 0; i < maxCacheEntries; i++ {
		c.Set(fmt.Sprintf("k%04d", i), i, time.Minute)
	}
	// One more entry must evict the earliest-expiring (first set) entry.
	c.Set("newest", "last", time.Minute)
	if c.Len() > maxCacheEntries {
		t.Fatalf("cache exceeds its bound: %d", c.Len())
	}
	if _, ok := c.Get("newest"); !ok {
		t.Fatal("the newest entry must survive eviction")
	}
}

func TestCacheEvictsExpiredFirst(t *testing.T) {
	fc := newFakeClock()
	c := NewCache(fc.Now)
	for i := 0; i < maxCacheEntries; i++ {
		c.Set(fmt.Sprintf("k%04d", i), i, time.Minute)
	}
	fc.Advance(2 * time.Minute) // everything expired
	c.Set("fresh", 1, time.Minute)
	if c.Len() != 1 {
		t.Fatalf("expired entries must be dropped before eviction, len=%d", c.Len())
	}
	if v, ok := c.Get("fresh"); !ok || v != 1 {
		t.Fatalf("fresh entry lost: %v ok=%v", v, ok)
	}
}

func TestCacheConcurrent(t *testing.T) {
	fc := newFakeClock()
	c := NewCache(fc.Now)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := fmt.Sprintf("k%02d", i)
			c.Set(k, i, time.Hour)
			c.Get(k)
			c.Len()
		}(i)
	}
	wg.Wait()
}
