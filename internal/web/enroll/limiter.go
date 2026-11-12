// SPDX-License-Identifier: AGPL-3.0-or-later

package enroll

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// Per-client download limits (ADR 0013 D7): 10 per minute and 60 per hour
// per client address; IPv6 clients are bucketed per /64.
const (
	// PerMinute is the number of downloads a client may attempt per minute.
	PerMinute = 10
	// PerHour is the number of downloads a client may attempt per hour.
	PerHour = 60
	// DefaultTableSize is the maximum number of buckets kept; the least
	// recently used bucket is evicted when the table is full.
	DefaultTableSize = 4096
	// ipv6BucketBits is the prefix length IPv6 clients are bucketed by.
	ipv6BucketBits = 64
)

// Limiter is the bounded per-client rate-limit table. It never refuses a
// request because the table is full: it evicts the least recently used
// bucket instead (fail open for the evicted client). Safe for concurrent
// use.
type Limiter struct {
	mu    sync.Mutex
	now   func() time.Time
	max   int
	order *list.List // front: most recently used; values are *bucket
	table map[netip.Prefix]*list.Element
}

// bucket counts one client's attempts in a fixed minute and hour window,
// each starting with the first charge after the previous window ended.
type bucket struct {
	key         netip.Prefix
	minuteStart time.Time
	minuteCount int
	hourStart   time.Time
	hourCount   int
}

// NewLimiter returns a limiter holding at most size buckets (zero or less
// means DefaultTableSize). now is the clock; nil means time.Now.
func NewLimiter(size int, now func() time.Time) *Limiter {
	if size <= 0 {
		size = DefaultTableSize
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, max: size, order: list.New(), table: make(map[netip.Prefix]*list.Element)}
}

// bucketKey is the normalised client key: the IPv4 address itself, or the
// /64 of an IPv6 address.
func bucketKey(client netip.Addr) netip.Prefix {
	client = client.WithZone("").Unmap()
	if client.Is4() {
		return netip.PrefixFrom(client, 32)
	}
	return netip.PrefixFrom(client, ipv6BucketBits).Masked()
}

// Charge is the only charge path of the limiter: it counts one attempt of
// the already resolved client address and reports whether it is within
// the limits. A refused attempt is not counted.
func (l *Limiter) Charge(client netip.Addr) bool {
	key := bucketKey(client)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var b *bucket
	if e, ok := l.table[key]; ok {
		l.order.MoveToFront(e)
		b = e.Value.(*bucket)
	} else {
		for l.order.Len() >= l.max {
			oldest := l.order.Back()
			delete(l.table, oldest.Value.(*bucket).key)
			l.order.Remove(oldest)
		}
		b = &bucket{key: key}
		l.table[key] = l.order.PushFront(b)
	}
	if b.minuteCount == 0 || !now.Before(b.minuteStart.Add(time.Minute)) {
		b.minuteStart, b.minuteCount = now, 0
	}
	if b.hourCount == 0 || !now.Before(b.hourStart.Add(time.Hour)) {
		b.hourStart, b.hourCount = now, 0
	}
	if b.minuteCount >= PerMinute || b.hourCount >= PerHour {
		return false
	}
	b.minuteCount++
	b.hourCount++
	return true
}

// size returns the number of buckets in the table (tests).
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}
