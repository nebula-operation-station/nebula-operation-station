// SPDX-License-Identifier: AGPL-3.0-or-later

// This file holds the named limits for the public registry metadata client
// (ADR 0006, ticket P1-17). Every limit is enforced next to the code that
// checks it; the values follow the ADR: one request per second and two
// concurrent requests per registry, 1 MiB per response, 10,000 tags per scan,
// 24 h caches for tag lists and same-tag digests, 15 min failure caches,
// 7 days for immutable digest metadata, and a minimum 15 minute pause on
// 429 rate limiting.
package registrymeta

import "time"

// Response and pagination budgets.
const (
	// MaxResponseBytes is the maximum size of a single registry response
	// body (1 MiB, ADR 0006). Larger responses are rejected.
	MaxResponseBytes = 1 << 20

	// MaxTagsPerScan is the maximum number of tags collected from one tag
	// list scan (10,000, ADR 0006 registry budget). Exceeding it leaves the
	// result incomplete.
	MaxTagsPerScan = 10000

	// MaxPages is the maximum number of Link-paginated tag list pages
	// followed per scan. Exhausting it leaves the result incomplete.
	MaxPages = 100

	// MaxRedirects is the maximum number of redirects followed per request.
	MaxRedirects = 3
)

// Per-registry request budgets (ADR 0006: "cap each registry at one
// request/s, two concurrent requests").
const (
	// MinRequestInterval is the minimum time between two request starts for
	// one registry (one request per second).
	MinRequestInterval = time.Second

	// MaxConcurrentPerRegistry is the maximum number of in-flight requests
	// to one registry.
	MaxConcurrentPerRegistry = 2

	// acquirePollInterval is how long the limiter sleeps while waiting for a
	// free concurrent slot.
	acquirePollInterval = 10 * time.Millisecond
)

// Rate-limit (429) backoff. ADR 0006: pause on 429 with jittered exponential
// backoff (minimum 15 min), honor Retry-After when supplied.
const (
	// MinRateLimitPause is the first pause after a 429 (15 min).
	MinRateLimitPause = 15 * time.Minute

	// MaxBackoff caps the exponential backoff pause (24 h).
	MaxBackoff = 24 * time.Hour

	// maxBackoffShifts caps the exponent of the backoff doubling.
	maxBackoffShifts = 10
)

// Cache TTLs (ADR 0006: same-tag checks 24 h, stable tag lists 24 h,
// failures 15 min, immutable digest metadata 7 days).
const (
	// TTLTagList is the cache lifetime of a successful tag list.
	TTLTagList = 24 * time.Hour

	// TTLSameTag is the cache lifetime of a same-tag (tag -> digest) check.
	TTLSameTag = 24 * time.Hour

	// TTLFailure is the cache lifetime of a failed lookup, so a broken or
	// hostile registry is not hammered.
	TTLFailure = 15 * time.Minute

	// TTLDigest is the cache lifetime of immutable digest-pinned metadata.
	TTLDigest = 7 * 24 * time.Hour
)

// Input validation limits.
const (
	// MaxTagLen is the maximum length of a registry tag.
	MaxTagLen = 128

	// MaxRepoLen is the maximum length of a repository path.
	MaxRepoLen = 255

	// MaxImageLen is the maximum length of a full image reference.
	MaxImageLen = 512

	// MaxTokenLen is the maximum length of an anonymous bearer token.
	MaxTokenLen = 64 << 10
)

// requestTimeout bounds a single registry HTTP request.
const requestTimeout = 30 * time.Second
