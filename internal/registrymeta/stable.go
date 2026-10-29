// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registrymeta selects the "latest stable" version of a container
// image from its tag list (ADR 0006, ticket P1-31). It is pure: no network,
// no registry calls, and it never mutates its inputs.
//
// Selection applies a numeric SemVer-like ordering (never lexical order or
// creation time), keeps the current tag's variant suffix family (for example
// 1.2.3-alpine compares only against other -alpine tags), and ignores
// pre-releases, non-version tags (latest, edge, nightly, main, master),
// sha/digest tags and date tags (unless the policy allows dates). Whenever it
// cannot decide — no matching tags, an ambiguous tie between incomplete tags
// such as 1.2 and 1.2.0, or an unsupported convention — it reports "unknown"
// with a reason, never "up to date".
//
// This is stable-version selection only. Same-tag digest refresh (has the
// manifest behind a fixed tag changed?) is a separate, network-bound concern
// and is not answered here.
package registrymeta

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DefaultPolicyVersion is the selection-policy version recorded in a Result
// when the Policy does not name its own version.
const DefaultPolicyVersion = "stable-v1"

// Limits, enforced next to the code that checks them.
const (
	maxTagLen    = 128   // a tag longer than this is not a version
	maxTags      = 10000 // tags per scan (ADR 0006 registry budget)
	maxRegexes   = 50    // include/exclude patterns per policy
	maxVariant   = 32    // a variant suffix longer than this is not a variant
	maxPolicyVer = 64    // policy version string length
)

// ErrInvalidPolicy is a Policy that is not valid (an invalid or too-long
// regular expression, or a too-long policy version).
var ErrInvalidPolicy = errors.New("registrymeta: invalid policy")

func invalidPolicy(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, a...))
}

// kind classifies a parsed tag.
type kind int

const (
	kindOther   kind = iota // not a version: latest, edge, sha, digest, ...
	kindVersion             // numeric version, optional variant suffix
	kindDate                // date tag (2024-01-15, 20240115, ...)
)

// parsedTag is one tag after parsing.
type parsedTag struct {
	raw     string // the original tag
	norm    string // core without leading v and build metadata (1.2, 1.2.0)
	kind    kind
	major   int
	minor   int
	patch   int
	variant string // kindVersion: suffix (e.g. alpine); kindDate: "date"
	isPre   bool   // kindVersion: variant is a pre-release identifier
	dateKey int64  // kindDate: YYYYMMDDHHMMSS, for ordering
}

// Policy is the per-image override policy for stable-version selection.
// Every field is optional; the zero Policy is the documented default.
type Policy struct {
	// Version is the policy's own version string, recorded in the Result so a
	// later policy change is detectable. Empty means DefaultPolicyVersion.
	Version string

	// Include, when non-empty, is a list of regular expressions; a numeric
	// tag is only considered if it matches at least one. Empty means all
	// numeric tags are considered. A prefix can be expressed as an anchored
	// pattern (for example ^1\.).
	Include []string

	// Exclude is a list of regular expressions; a tag matching any is ignored.
	Exclude []string

	// MaxMajor, when > 0, caps the major version considered; a newer stable
	// with a higher major is not reported (no implicit major upgrade). Zero
	// or negative means no cap, so the zero Policy is the default.
	MaxMajor int

	// ExplicitStable, when non-empty, is the exact stable tag to treat as the
	// target; selection reports whether current is behind it.
	ExplicitStable string

	// AllowDates, when true, lets date tags be considered when the current
	// tag is also a date tag. Default false: date tags are ignored.
	AllowDates bool
}

// Status is the outcome of a stable-version selection.
type Status int

const (
	// StatusUnknown: could not decide (no matching tags, ambiguous tie,
	// unsupported convention). It is never "up to date".
	StatusUnknown Status = iota
	// StatusUpToDate: current is the latest stable, or ahead of it.
	StatusUpToDate
	// StatusNewer: a newer stable tag exists.
	StatusNewer
)

// String returns the status name.
func (s Status) String() string {
	switch s {
	case StatusUnknown:
		return "unknown"
	case StatusUpToDate:
		return "up-to-date"
	case StatusNewer:
		return "newer"
	default:
		return "invalid"
	}
}

// Result is the outcome of LatestStable.
type Result struct {
	// Status is the outcome.
	Status Status
	// Latest is the latest stable tag, when known. It may be advisory (set
	// with StatusUnknown) when the current tag is not a comparable version.
	Latest string
	// Reason explains an Unknown result, or gives a short note otherwise. It
	// never contains secrets.
	Reason string
	// PolicyVersion is the version of the selection policy that was applied.
	PolicyVersion string
}

var (
	versionRe     = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:-(.*))?$`)
	dateDashRe    = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})([T ].*)?$`)
	dateCompactRe = regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})$`)
	hexRe         = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	preReleaseRe  = regexp.MustCompile(`^(rc|beta|alpha|dev|pre|preview|canary|snapshot|snap|milestone|nightly|edge|unstable|testing|experimental)[0-9.+-]*$`)
)

// digestPrefixes are the algorithm prefixes of a digest-pinned tag.
var digestPrefixes = []string{"sha256:", "sha512:", "sha512_256:", "sha1:", "md5:"}

// LatestStable picks the latest stable version of an image from its tag list
// and compares it with the current tag. It is pure: no network, no registry
// calls, and it never mutates current or tags.
func LatestStable(current string, tags []string, policy Policy) (Result, error) {
	res := Result{Status: StatusUnknown, PolicyVersion: policyVersion(policy)}

	if err := checkPolicy(policy); err != nil {
		return res, err
	}
	if len(tags) > maxTags {
		return res, invalidPolicy("at most %d tags per scan, got %d", maxTags, len(tags))
	}
	inc, err := compileAll(policy.Include, "include")
	if err != nil {
		return res, err
	}
	exc, err := compileAll(policy.Exclude, "exclude")
	if err != nil {
		return res, err
	}

	cur := parseTag(current)

	if policy.ExplicitStable != "" {
		return explicitStable(cur, tags, policy, res)
	}

	family, ok := familyOf(cur, policy)
	if !ok {
		res.Reason = noFamilyReason(cur, policy)
		return res, nil
	}

	var cands []parsedTag
	for _, t := range tags {
		p := parseTag(t)
		if p.kind == kindOther {
			continue
		}
		if p.kind == kindDate {
			if !policy.AllowDates || cur.kind != kindDate {
				continue
			}
		} else if p.isPre {
			continue
		}
		if p.variant != family {
			continue
		}
		if !matchInclude(t, inc) {
			continue
		}
		if matchAny(t, exc) {
			continue
		}
		if policy.MaxMajor > 0 && p.kind == kindVersion && p.major > policy.MaxMajor {
			continue
		}
		cands = append(cands, p)
	}

	if len(cands) == 0 {
		res.Reason = "no matching stable tags"
		return res, nil
	}

	latest, norms, ambiguous := pickLatest(cands)
	if ambiguous {
		sort.Strings(norms)
		res.Reason = "ambiguous tie between " + strings.Join(norms, " and ")
		return res, nil
	}
	res.Latest = latest.raw

	if cur.kind != latest.kind {
		res.Status = StatusUnknown
		res.Reason = "current tag is not a comparable version; latest stable is advisory"
		return res, nil
	}
	c := compare(latest, cur)
	if c == 0 && cur.isPre {
		// A stable release of the same version is newer than a pre-release.
		c = 1
	}
	switch {
	case c > 0:
		res.Status = StatusNewer
		res.Reason = "newer stable available"
	case c == 0:
		res.Status = StatusUpToDate
		res.Reason = "current is the latest stable"
	default:
		res.Status = StatusUpToDate
		res.Reason = "current is ahead of the latest stable"
	}
	return res, nil
}

func policyVersion(p Policy) string {
	if p.Version == "" {
		return DefaultPolicyVersion
	}
	return p.Version
}

func checkPolicy(p Policy) error {
	if len(p.Version) > maxPolicyVer {
		return invalidPolicy("the policy version is at most %d characters", maxPolicyVer)
	}
	if len(p.Include) > maxRegexes {
		return invalidPolicy("at most %d include patterns", maxRegexes)
	}
	if len(p.Exclude) > maxRegexes {
		return invalidPolicy("at most %d exclude patterns", maxRegexes)
	}
	return nil
}

func compileAll(patterns []string, name string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, invalidPolicy("invalid %s pattern %q: %v", name, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func matchInclude(tag string, inc []*regexp.Regexp) bool {
	if len(inc) == 0 {
		return true
	}
	for _, re := range inc {
		if re.MatchString(tag) {
			return true
		}
	}
	return false
}

func matchAny(tag string, re []*regexp.Regexp) bool {
	for _, r := range re {
		if r.MatchString(tag) {
			return true
		}
	}
	return false
}

// familyOf returns the variant family to compare within, derived from the
// current tag. ok is false when no family applies (a date current without
// AllowDates).
func familyOf(cur parsedTag, policy Policy) (string, bool) {
	switch cur.kind {
	case kindVersion:
		if cur.isPre {
			return "", true // a pre-release current compares plain stable tags
		}
		return cur.variant, true
	case kindDate:
		if policy.AllowDates {
			return "date", true
		}
		return "", false
	case kindOther:
		return "", true // advisory: plain version tags
	}
	return "", false
}

func noFamilyReason(cur parsedTag, policy Policy) string {
	if cur.kind == kindDate {
		return "current tag is a date; date tags are ignored unless the policy allows them"
	}
	return "cannot determine the current tag's variant family"
}

// explicitStable resolves an ExplicitStable override: the named tag must be
// in the list, and the result is whether current is behind it.
func explicitStable(cur parsedTag, tags []string, policy Policy, res Result) (Result, error) {
	var found *parsedTag
	for _, t := range tags {
		if t != policy.ExplicitStable {
			continue
		}
		p := parseTag(t)
		if p.kind == kindVersion || (p.kind == kindDate && policy.AllowDates) {
			found = &p
			break
		}
	}
	if found == nil {
		res.Reason = "the explicit stable tag is not in the tag list"
		return res, nil
	}
	res.Latest = found.raw
	if cur.kind != found.kind {
		res.Status = StatusUnknown
		res.Reason = "the current tag is not comparable to the explicit stable tag"
		return res, nil
	}
	c := compare(*found, cur)
	if c == 0 && cur.isPre {
		c = 1
	}
	switch {
	case c > 0:
		res.Status = StatusNewer
		res.Reason = "current is behind the explicit stable tag"
	case c == 0:
		res.Status = StatusUpToDate
		res.Reason = "current is the explicit stable tag"
	default:
		res.Status = StatusUpToDate
		res.Reason = "current is ahead of the explicit stable tag"
	}
	return res, nil
}

// pickLatest returns the highest candidate, the set of conflicting cores when
// the top is an ambiguous tie between incomplete tags, and whether it is
// ambiguous. Among equal cores the lexicographically smallest raw tag wins,
// so the result is deterministic.
func pickLatest(cands []parsedTag) (parsedTag, []string, bool) {
	top := cands[0]
	for _, c := range cands[1:] {
		if compare(c, top) > 0 {
			top = c
		}
	}
	seen := map[string]bool{}
	var norms []string
	for _, c := range cands {
		if compare(c, top) == 0 && !seen[c.norm] {
			seen[c.norm] = true
			norms = append(norms, c.norm)
		}
	}
	if len(norms) > 1 {
		return top, norms, true
	}
	best := top
	for _, c := range cands {
		if compare(c, top) == 0 && c.norm == top.norm && c.raw < best.raw {
			best = c
		}
	}
	return best, nil, false
}

// compare orders two tags of the same kind numerically and returns -1, 0 or
// 1. Callers only compare tags of the same kind (the family filter ensures
// this); a kind mismatch yields 0.
func compare(a, b parsedTag) int {
	if a.kind != b.kind {
		return 0
	}
	switch a.kind {
	case kindVersion:
		if c := cmp(a.major, b.major); c != 0 {
			return c
		}
		if c := cmp(a.minor, b.minor); c != 0 {
			return c
		}
		return cmp(a.patch, b.patch)
	case kindDate:
		return cmpInt64(a.dateKey, b.dateKey)
	}
	return 0
}

func cmp(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// parseTag classifies and decomposes one tag. It never fails; anything that
// is not a clean numeric version (or date) is kindOther.
func parseTag(tag string) parsedTag {
	t := strings.TrimSpace(tag)
	p := parsedTag{raw: tag}
	if t == "" || len(t) > maxTagLen {
		p.kind = kindOther
		return p
	}
	if isDigest(t) {
		p.kind = kindOther
		return p
	}
	if key, ok := parseDate(t); ok {
		p.kind = kindDate
		p.norm = t
		p.variant = "date"
		p.dateKey = key
		return p
	}
	s := t
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata does not order versions
	}
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		p.kind = kindOther
		return p
	}
	if m[4] == "" && strings.HasSuffix(s, "-") {
		p.kind = kindOther // a trailing '-' is malformed
		return p
	}
	if len(m[4]) > maxVariant {
		p.kind = kindOther
		return p
	}
	p.kind = kindVersion
	p.major, _ = strconv.Atoi(m[1])
	norm := m[1]
	if m[2] != "" {
		p.minor, _ = strconv.Atoi(m[2])
		norm += "." + m[2]
	}
	if m[3] != "" {
		p.patch, _ = strconv.Atoi(m[3])
		norm += "." + m[3]
	}
	p.variant = m[4]
	p.norm = norm
	p.isPre = isPreRelease(p.variant)
	return p
}

// isDigest reports whether a tag is a digest pin or a bare sha (a git sha or
// digest short form). A pure-digit string is a version, not a sha.
func isDigest(t string) bool {
	for _, p := range digestPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	if len(t) >= 7 && len(t) <= 64 && hexRe.MatchString(t) {
		if len(t) >= 40 || hasHexLetter(t) {
			return true
		}
	}
	return false
}

func hasHexLetter(t string) bool {
	for i := 0; i < len(t); i++ {
		c := t[i]
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			return true
		}
	}
	return false
}

func isPreRelease(variant string) bool {
	if variant == "" {
		return false
	}
	return preReleaseRe.MatchString(strings.ToLower(variant))
}

// parseDate recognises YYYY-MM-DD (optionally with a time part) and YYYYMMDD
// tags and returns a comparable key. It reports false for anything that is
// not a plausible calendar date.
func parseDate(t string) (int64, bool) {
	var y, mo, d, rest string
	if m := dateDashRe.FindStringSubmatch(t); m != nil {
		y, mo, d, rest = m[1], m[2], m[3], m[4]
	} else if m := dateCompactRe.FindStringSubmatch(t); m != nil {
		y, mo, d, rest = m[1], m[2], m[3], ""
	} else {
		return 0, false
	}
	yy, _ := strconv.Atoi(y)
	mm, _ := strconv.Atoi(mo)
	dd, _ := strconv.Atoi(d)
	if !validDate(yy, mm, dd) {
		return 0, false
	}
	key := int64(yy)*1000000 + int64(mm)*10000 + int64(dd)
	hh, mi, ss := 0, 0, 0
	if r := strings.TrimPrefix(strings.TrimPrefix(rest, "T"), " "); r != "" {
		parts := strings.SplitN(r, ":", 3)
		hh, _ = strconv.Atoi(parts[0])
		if len(parts) > 1 {
			mi, _ = strconv.Atoi(parts[1])
		}
		if len(parts) > 2 {
			ss, _ = strconv.Atoi(strings.TrimSuffix(parts[2], "Z"))
		}
	}
	key = key*100 + int64(hh)
	key = key*100 + int64(mi)
	key = key*100 + int64(ss)
	return key, true
}

func validDate(y, m, d int) bool {
	return y >= 1900 && y <= 2999 && m >= 1 && m <= 12 && d >= 1 && d <= 31
}
