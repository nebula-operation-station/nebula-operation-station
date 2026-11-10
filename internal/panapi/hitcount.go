// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// MaxHitCountEntries bounds the rule entries read from one hit-count
// response (ADR 0010 D3: the security-rule limit). Entries beyond it are
// dropped and the set is marked incomplete.
const MaxHitCountEntries = netdevcontract.MaxHitCountEntries

// maxEpochSeconds is the latest accepted timestamp, 9999-12-31T23:59:59Z
// (netdevcontract.MaxObservedYear). A larger value is refused, not clamped.
const maxEpochSeconds = 253402300799

// maxDecimalDigits bounds a decimal counter or timestamp before it is
// converted: len("18446744073709551615"). Longer strings cannot be a
// uint64 and are refused without further work.
const maxDecimalDigits = 20

// hitCountBase is the only rule base NOS reads hit counts for; it matches
// the fixed command of RuleHitCountRequest.
const hitCountBase = "security"

// ErrInvalidHitCount is returned when a well-formed hit-count response
// carries content NOS refuses: a malformed or duplicated rule name, a
// missing, repeated, negative or overflowing counter, a malformed or
// out-of-range timestamp, inconsistent hit times, another vsys or rule
// base. The error never repeats device text.
var ErrInvalidHitCount = errors.New("panapi: invalid rule hit-count content")

// RuleHitCount is the hit counter of one security rule. HitCount counts
// the hits since LastReset (since rule creation if the counter was never
// reset). Every time is UTC with second precision; the zero time means
// "never" or "not reported" (PAN-OS reports 0 for a rule that never
// matched or a counter that was never reset).
type RuleHitCount struct {
	HitCount         uint64
	LastHit          time.Time
	FirstHit         time.Time
	LastReset        time.Time
	RuleCreation     time.Time
	RuleModification time.Time
}

// HitCountSet is the parsed hit-count response, keyed by rule name.
// Incomplete is set when the response held more than MaxHitCountEntries
// entries; Rules then holds the first entries in document order. A rule
// missing from an incomplete set has no known count, not a zero count.
type HitCountSet struct {
	Rules      map[string]RuleHitCount
	Incomplete bool
}

// The types below are the element allowlist for the rule-hit-count reply
// (exact form *verify* on the lab firewall, ND-03). Containers are slices
// so that a repetition is detected; every other element is dropped with
// its subtree.
type (
	xmlHCResponse struct {
		Result []xmlHCResult `xml:"result"`
	}
	xmlHCResult struct {
		RuleHitCount []xmlHCRoot `xml:"rule-hit-count"`
	}
	xmlHCRoot struct {
		Vsys []xmlList[xmlHCVsys] `xml:"vsys"`
	}
	xmlHCVsys struct {
		Name     string               `xml:"name,attr"`
		RuleBase []xmlList[xmlHCBase] `xml:"rule-base"`
	}
	xmlHCBase struct {
		Name  string                      `xml:"name,attr"`
		Rules []xmlList[xmlHitCountEntry] `xml:"rules"`
	}
	xmlHitCountEntry struct {
		Name             string   `xml:"name,attr"`
		HitCount         []string `xml:"hit-count"`
		LastHit          []string `xml:"last-hit-timestamp"`
		FirstHit         []string `xml:"first-hit-timestamp"`
		LastReset        []string `xml:"last-reset-timestamp"`
		RuleCreation     []string `xml:"rule-creation-timestamp"`
		RuleModification []string `xml:"rule-modification-timestamp"`
	}
)

// ParseRuleHitCounts parses the reply to RuleHitCountRequest (show
// rule-hit-count for the vsys1 security rule base). It performs no I/O.
// The response passes the same limit checks and strict decoding as every
// ND-09 parser. Counters are unsigned 64-bit decimals; timestamps are Unix
// epoch seconds as plain decimals. A sign, leading zero, whitespace, an
// overflowing counter or a timestamp after year 9999 is refused, never
// clamped. A missing timestamp element reads as zero (not reported); a
// missing hit-count is refused. On error the result is zero. Errors never
// contain device text.
func ParseRuleHitCounts(data []byte) (HitCountSet, error) {
	entries, err := decodeHitCounts(data)
	if err != nil {
		return HitCountSet{}, fmt.Errorf("parse rule hit counts: %w", err)
	}
	set := HitCountSet{}
	if netdevcontract.CheckCount("hit-count entries", len(entries), MaxHitCountEntries) != nil {
		entries, set.Incomplete = entries[:MaxHitCountEntries], true
	}
	set.Rules = make(map[string]RuleHitCount, len(entries))
	for i, e := range entries {
		if ValidateName(e.Name) != nil {
			return HitCountSet{}, fmt.Errorf("parse rule hit counts: entry %d: %w: invalid rule name", i, ErrInvalidHitCount)
		}
		if _, dup := set.Rules[e.Name]; dup {
			return HitCountSet{}, fmt.Errorf("parse rule hit counts: entry %d: %w: rule name duplicated", i, ErrInvalidHitCount)
		}
		h, err := parseHitCountEntry(e)
		if err != nil {
			return HitCountSet{}, fmt.Errorf("parse rule hit counts: entry %d: %w", i, err)
		}
		set.Rules[e.Name] = h
	}
	return set, nil
}

// decodeHitCounts checks and decodes the response and returns the rule
// entries of vsys1/security in document order.
func decodeHitCounts(data []byte) ([]xmlHitCountEntry, error) {
	if err := netdevcontract.CheckXML(data, MaxParseResponseBytes); err != nil {
		if errors.Is(err, netdevcontract.ErrOverLimit) {
			return nil, fmt.Errorf("%w: %w", ErrXMLLimit, err)
		}
		return nil, fmt.Errorf("%w: XML check failed", ErrMalformedResponse)
	}
	if err := checkResponse(data); err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	// Entity and CharsetReader stay nil: only the predefined entities and
	// UTF-8 are accepted.
	var resp xmlHCResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("%w: decode failed", ErrMalformedResponse)
	}
	if err := exactlyOne(len(resp.Result), "result"); err != nil {
		return nil, err
	}
	res := resp.Result[0]
	if err := exactlyOne(len(res.RuleHitCount), "rule-hit-count"); err != nil {
		return nil, err
	}
	root := res.RuleHitCount[0]
	if err := exactlyOne(len(root.Vsys), "vsys"); err != nil {
		return nil, err
	}
	vsys := root.Vsys[0].Entries
	if err := exactlyOne(len(vsys), "vsys entry"); err != nil {
		return nil, err
	}
	if vsys[0].Name != supportedVsys {
		return nil, fmt.Errorf("%w: unsupported vsys", ErrInvalidHitCount)
	}
	if err := exactlyOne(len(vsys[0].RuleBase), "rule-base"); err != nil {
		return nil, err
	}
	bases := vsys[0].RuleBase[0].Entries
	if err := exactlyOne(len(bases), "rule-base entry"); err != nil {
		return nil, err
	}
	if bases[0].Name != hitCountBase {
		return nil, fmt.Errorf("%w: unexpected rule base", ErrInvalidHitCount)
	}
	if err := exactlyOne(len(bases[0].Rules), "rules"); err != nil {
		return nil, err
	}
	return bases[0].Rules[0].Entries, nil
}

// exactlyOne checks the count of a required single container; what is a
// fixed element name, never device text.
func exactlyOne(n int, what string) error {
	switch n {
	case 0:
		return fmt.Errorf("%w: no %s element", ErrMalformedResponse, what)
	case 1:
		return nil
	}
	return fmt.Errorf("%w: %s repeated", ErrInvalidHitCount, what)
}

// parseHitCountEntry validates the counter and timestamps of one entry.
func parseHitCountEntry(e xmlHitCountEntry) (RuleHitCount, error) {
	var h RuleHitCount
	switch len(e.HitCount) {
	case 0:
		return RuleHitCount{}, fmt.Errorf("%w: hit-count missing", ErrInvalidHitCount)
	case 1:
	default:
		return RuleHitCount{}, fmt.Errorf("%w: hit-count repeated", ErrInvalidHitCount)
	}
	n, err := parseDecimal(e.HitCount[0])
	if err != nil {
		return RuleHitCount{}, fmt.Errorf("%w: hit-count: %w", ErrInvalidHitCount, err)
	}
	h.HitCount = n
	for _, f := range []struct {
		dst  *time.Time
		src  []string
		what string
	}{
		{&h.LastHit, e.LastHit, "last-hit-timestamp"},
		{&h.FirstHit, e.FirstHit, "first-hit-timestamp"},
		{&h.LastReset, e.LastReset, "last-reset-timestamp"},
		{&h.RuleCreation, e.RuleCreation, "rule-creation-timestamp"},
		{&h.RuleModification, e.RuleModification, "rule-modification-timestamp"},
	} {
		if *f.dst, err = parseEpoch(f.src); err != nil {
			return RuleHitCount{}, fmt.Errorf("%w: %s: %w", ErrInvalidHitCount, f.what, err)
		}
	}
	// the netdevcontract HitCount rules: no hit times without hits, last
	// hit not before first hit
	if h.HitCount == 0 && (!h.FirstHit.IsZero() || !h.LastHit.IsZero()) {
		return RuleHitCount{}, fmt.Errorf("%w: hit times without hits", ErrInvalidHitCount)
	}
	if !h.FirstHit.IsZero() && !h.LastHit.IsZero() && h.LastHit.Before(h.FirstHit) {
		return RuleHitCount{}, fmt.Errorf("%w: last hit before first hit", ErrInvalidHitCount)
	}
	return h, nil
}

// errDecimal is the fixed reason for a malformed decimal; it never
// contains the value.
var errDecimal = errors.New("not an unsigned decimal in range")

// parseDecimal parses a strict unsigned decimal: ASCII digits only, no
// sign, no whitespace, no leading zero (except "0" itself), at most
// math.MaxUint64.
func parseDecimal(s string) (uint64, error) {
	if s == "" || len(s) > maxDecimalDigits || (len(s) > 1 && s[0] == '0') {
		return 0, errDecimal
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errDecimal
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		// only ErrRange is possible here: a 20-digit value over 2^64-1
		return 0, errDecimal
	}
	return n, nil
}

// parseEpoch parses an optional timestamp element in Unix epoch seconds.
// Absent and "0" give the zero time; a repetition, a malformed value or a
// value after maxEpochSeconds is refused.
func parseEpoch(vs []string) (time.Time, error) {
	switch len(vs) {
	case 0:
		return time.Time{}, nil
	case 1:
	default:
		return time.Time{}, errors.New("repeated")
	}
	n, err := parseDecimal(vs[0])
	if err != nil {
		return time.Time{}, err
	}
	if n > maxEpochSeconds {
		return time.Time{}, errors.New("after year 9999")
	}
	if n == 0 {
		return time.Time{}, nil
	}
	return time.Unix(int64(n), 0).UTC(), nil
}

// UnusedRules returns the rules of rules, in rule order, that have no
// hits since the later of their counter reset time and since (ADR 0010,
// firewall view "unused-rule hint"; consumer ND-20). Per rule:
//
//   - a rule without an entry in hits has no known count and is never
//     reported (no data is no hint);
//   - with a zero count it is reported: the counter covers the time since
//     its reset (or since creation), which includes the window;
//   - if the reset is at or after since, any counted hit makes it used;
//   - otherwise it is reported only if its last hit is known and before
//     since; a non-zero count without a last-hit time is not reported.
//
// The result is a hint, never a proposal to delete. The caller checks the
// observation window (at least 30 days) and rule creation; UnusedRules
// does not.
func UnusedRules(rules []Rule, hits map[string]RuleHitCount, since time.Time) []Rule {
	var out []Rule
	for _, r := range rules {
		h, ok := hits[r.Name]
		if !ok {
			continue
		}
		if h.HitCount == 0 {
			out = append(out, r)
			continue
		}
		if !h.LastReset.Before(since) {
			continue
		}
		if !h.LastHit.IsZero() && h.LastHit.Before(since) {
			out = append(out, r)
		}
	}
	return out
}
