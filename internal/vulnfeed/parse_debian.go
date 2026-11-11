// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Limits of the Debian Security Tracker JSON export and the DSA/DLA lists
// (ADR 0011 D4).
const (
	// MaxDebianTrackerBytes caps the decompressed tracker JSON.
	MaxDebianTrackerBytes = MaxFeedBytesDefault
	// MaxDebianPackageBytes caps the JSON of one source package (the
	// largest, linux, carries thousands of issues).
	MaxDebianPackageBytes = 64 << 20
	// MaxDebianPackages caps the source packages in one export.
	MaxDebianPackages = 200_000
	// MaxDebianIssuesPerPackage caps the issues of one source package.
	MaxDebianIssuesPerPackage = 50_000
	// MaxDebianReleasesPerIssue caps the releases listed for one issue.
	MaxDebianReleasesPerIssue = 64
	// MaxDebianEntries caps the (package, issue, release) entries.
	MaxDebianEntries = 20_000_000
	// MaxDebianUrgencyBytes caps the urgency text of one entry.
	MaxDebianUrgencyBytes = 32
	// MaxDebianListBytes caps one DSA or DLA list file.
	MaxDebianListBytes = 64 << 20
	// MaxDebianListLineBytes caps one line of a DSA or DLA list.
	MaxDebianListLineBytes = 4096
	// MaxDebianListEntries caps the advisories in one list.
	MaxDebianListEntries = 200_000
)

// DebianUndetermined is the state of an entry whose tracker status is
// "undetermined". It is not in the D4 table: vulnfinding's
// MapDebianTrackerState rejects it, so it can never open or close a finding.
const DebianUndetermined vulnfinding.TrackerState = "<undetermined>"

// Debian tracker JSON status values.
const (
	debianStatusResolved     = "resolved"
	debianStatusOpen         = "open"
	debianStatusUndetermined = "undetermined"
	debianUrgencyEndOfLife   = "end-of-life"
	debianNotAffectedVersion = "0"
)

var (
	// debianPackageRe is a Debian source package name.
	debianPackageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{1,127}$`)
	// debianReleaseRe is a Debian release code name (debian:<codename>).
	debianReleaseRe = regexp.MustCompile(`^[a-z]{2,32}$`)
	// debianUrgencyRe is the tracker urgency, e.g. "low", "not yet
	// assigned", "medium**" (guessed).
	debianUrgencyRe = regexp.MustCompile(`^[a-z][a-z *-]{0,31}$`)
	// debianListHeadRe is the first line of one DSA or DLA list entry,
	// e.g. "[21 Oct 2024] DSA-5793-1 chromium - security update".
	debianListHeadRe = regexp.MustCompile(`^\[([0-9]{2} [A-Z][a-z]{2} [0-9]{4})\] (DSA|DLA)-[0-9]{1,6}(-[0-9]{1,3})?( |$)`)
)

// DebianEntry is one (source package, issue, release) state of the
// tracker JSON, mapped onto the D4 tracker states.
type DebianEntry struct {
	// Package is the source package name.
	Package string
	// IssueID is the tracker issue (CVE, or a TEMP- ID); it matches the
	// D2 vuln_id pattern.
	IssueID string
	// Release is the Debian release code name.
	Release string
	// State is one of the D4 tracker states, or DebianUndetermined.
	State vulnfinding.TrackerState
	// FixedVersion is the fixed source version; set only for TrackerFixed.
	FixedVersion string
	// Urgency is the tracker urgency text; may be empty.
	Urgency string
}

// DebianTrackerSummary counts what ParseDebianTracker delivered.
type DebianTrackerSummary struct {
	// Packages, Issues and Entries count source packages, (package,
	// issue) pairs and delivered entries.
	Packages, Issues, Entries int
	// Skipped counts the packages, issues and release entries left out
	// because they broke a field rule.
	Skipped int
}

// debianReleaseJSON is the per-release object of the tracker JSON.
// Other fields (repositories, ...) are skipped.
type debianReleaseJSON struct {
	Status       string  `json:"status"`
	FixedVersion *string `json:"fixed_version"`
	Urgency      string  `json:"urgency"`
	NoDSA        *string `json:"nodsa"`
	NoDSAReason  *string `json:"nodsa_reason"`
}

// debianIssueJSON is the per-issue object; description, scope and
// debianbug are skipped.
type debianIssueJSON struct {
	Releases map[string]debianReleaseJSON `json:"releases"`
}

// maxDebianReleaseValueBytes caps each string value of a release object
// (status, fixed_version, urgency, nodsa, nodsa_reason, ...); the field
// rules in debianEntry are stricter.
const maxDebianReleaseValueBytes = 1024

// debianIssuePaths are the per-issue limits checkJSON enforces while it
// walks, so the releases map never holds more than
// MaxDebianReleasesPerIssue entries and no release value is copied
// beyond its cap. The releases count check in parseIssue repeats the cap
// as defence in depth; it cannot fire while debianIssuePaths holds it.
var debianIssuePaths = jsonLimits{
	"releases": {Members: MaxDebianReleasesPerIssue},
	// Every direct member of every release object.
	"releases.*.*": {Bytes: maxDebianReleaseValueBytes},
}.compile()

// ParseDebianTracker streams the Debian Security Tracker JSON export
// (an object of source packages, each an object of issues with a
// "releases" object) and calls visit once per (package, issue, release)
// in package and issue order of the input and sorted release order.
// Packages and issues are decoded one at a time; every count limit is
// checked before the next package, issue or entry is decoded.
//
// A package, issue or release entry that breaks a field rule, and an
// issue that breaks a per-issue field length or count limit
// (ErrRecordLimit, e.g. more than MaxDebianReleasesPerIssue releases), is
// skipped and counted in DebianTrackerSummary.Skipped (a skipped package
// or issue counts once, not per entry inside it). A package with more than
// MaxDebianIssuesPerPackage issues breaks a per-package count limit: its
// remaining issues are consumed unread and the package is counted once in
// Skipped instead of Packages. The entries of its first
// MaxDebianIssuesPerPackage issues have been visited by then, like the
// entries of any package before a later error. An export size, package
// size, package or entry count limit, the depth limit (also inside a
// skipped package or issue), a duplicate package or issue, or a broken
// stream fails the whole export.
//
// The export is undated: its content date is the proxy date of the DSA
// and DLA lists (ParseDebianAdvisoryList), never a fetch time. On any
// error the entries already visited must be discarded by the caller.
func ParseDebianTracker(ctx context.Context, r io.Reader, visit func(DebianEntry) error) (DebianTrackerSummary, error) {
	return parseDebianTracker(ctx, r, MaxDebianEntries, visit)
}

// debianParse is the state of one ParseDebianTracker call.
type debianParse struct {
	ctx        context.Context
	dec        *json.Decoder
	br         *boundedReader
	visit      func(DebianEntry) error
	maxEntries int
	// entries counts every release entry read, skipped ones included.
	entries int
	sum     DebianTrackerSummary
}

// parseDebianTracker is ParseDebianTracker with the entry limit as a
// parameter, so tests can reach it with a small export.
func parseDebianTracker(ctx context.Context, r io.Reader, maxEntries int, visit func(DebianEntry) error) (DebianTrackerSummary, error) {
	br := newBoundedReader(r, MaxDebianTrackerBytes)
	p := &debianParse{ctx: ctx, dec: json.NewDecoder(br), br: br, visit: visit, maxEntries: maxEntries}
	err := p.run()
	return p.sum, err
}

func (p *debianParse) run() error {
	dec, br := p.dec, p.br
	if err := expectDelim(dec, br, "debian tracker top level", '{'); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	packages := 0
	for more(dec, br) {
		if err := p.ctx.Err(); err != nil {
			return fmt.Errorf("debian tracker: %w", err)
		}
		if packages >= MaxDebianPackages {
			return fmt.Errorf("debian tracker: more than %d packages: %w", MaxDebianPackages, ErrFeedLimit)
		}
		packages++
		pkg, err := nextKey(dec, br, "debian tracker package name")
		if err != nil {
			return err
		}
		valid := debianPackageRe.MatchString(pkg)
		if valid {
			if _, dup := seen[pkg]; dup {
				return fmt.Errorf("debian tracker package %s: duplicate: %w", pkg, ErrFeedMalformed)
			}
			seen[pkg] = struct{}{}
		}
		if err := p.parsePackage(pkg, valid); err != nil {
			return err
		}
	}
	if err := expectDelim(dec, br, "debian tracker end", '}'); err != nil {
		return err
	}
	return expectEOF(dec, br, "debian tracker: data after the export")
}

// parsePackage streams the issues of one source package within a window
// of MaxDebianPackageBytes. A package with an invalid name (valid false)
// or a value that is not an object is consumed and skipped.
func (p *debianParse) parsePackage(pkg string, valid bool) error {
	dec, br := p.dec, p.br
	where := "debian tracker package"
	if valid {
		where += " " + pkg
	}
	br.startWindow(dec.InputOffset(), MaxDebianPackageBytes+recordWindowSlack)
	defer br.endWindow()
	tok, err := dec.Token()
	if err != nil {
		return br.fail(where, err)
	}
	start := dec.InputOffset() - 1 // the opening brace, if tok is one
	if d, ok := tok.(json.Delim); !valid || !ok || d != '{' {
		if err := skipValueRest(dec, tok); err != nil {
			return br.fail(where, err)
		}
		if dec.InputOffset()-start > MaxDebianPackageBytes {
			return fmt.Errorf("%s: more than %d bytes: %w", where, MaxDebianPackageBytes, ErrFeedLimit)
		}
		p.sum.Skipped++
		return nil
	}
	seen := make(map[string]struct{})
	issues := 0
	for dec.More() {
		if issues >= MaxDebianIssuesPerPackage {
			// A per-package count limit: the rest of the package is
			// consumed within the package window, which keeps the size
			// and depth limits fatal, and the package is skipped.
			if err := skipValueRest(dec, json.Delim('{')); err != nil {
				return br.fail(where, err)
			}
			if dec.InputOffset()-start > MaxDebianPackageBytes {
				return fmt.Errorf("%s: more than %d bytes: %w", where, MaxDebianPackageBytes, ErrFeedLimit)
			}
			p.sum.Skipped++
			return nil
		}
		issues++
		tok, err := dec.Token()
		if err != nil {
			return br.fail(where+" issue ID", err)
		}
		id, _ := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return br.fail(where+" issue", err)
		}
		if !feedVulnIDRe.MatchString(id) {
			// The issue is skipped for its ID, but its depth limit stays
			// fatal like that of any other issue.
			if err := checkJSON(raw, MaxJSONDepth, nil); err != nil && !recordSkippable(err) {
				return fmt.Errorf("%s issue: %w", where, err)
			}
			p.sum.Skipped++
			continue
		}
		folded := strings.ToLower(id)
		if _, dup := seen[folded]; dup {
			return fmt.Errorf("%s %s: duplicate issue: %w", where, id, ErrFeedMalformed)
		}
		seen[folded] = struct{}{}
		if err := p.parseIssue(pkg, id, raw); err != nil {
			return err
		}
	}
	// The closing brace is read within the package window.
	tok, err = dec.Token()
	if err != nil {
		return br.fail(where+" end", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '}' {
		return fmt.Errorf("%s end: %w", where, ErrFeedMalformed)
	}
	if dec.InputOffset()-start > MaxDebianPackageBytes {
		return fmt.Errorf("%s: more than %d bytes: %w", where, MaxDebianPackageBytes, ErrFeedLimit)
	}
	p.sum.Packages++
	return nil
}

// parseIssue decodes one issue and visits its release entries in sorted
// release order.
func (p *debianParse) parseIssue(pkg, id string, raw []byte) error {
	var issue debianIssueJSON
	if err := decodeChecked(raw, &issue, debianIssuePaths); err != nil {
		if recordSkippable(err) {
			p.sum.Skipped++
			return nil
		}
		return fmt.Errorf("debian tracker %s %s: %w", pkg, id, err)
	}
	rels := issue.Releases
	if len(rels) > MaxDebianReleasesPerIssue { // checked during the walk already
		p.sum.Skipped++
		return nil
	}
	p.sum.Issues++
	names := make([]string, 0, len(rels))
	for name := range rels {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if p.entries >= p.maxEntries {
			return fmt.Errorf("debian tracker: more than %d entries: %w", p.maxEntries, ErrFeedLimit)
		}
		p.entries++
		if !debianReleaseRe.MatchString(name) {
			p.sum.Skipped++
			continue
		}
		e, err := debianEntry(pkg, id, name, rels[name])
		if err != nil {
			if recordSkippable(err) {
				p.sum.Skipped++
				continue
			}
			return err
		}
		if err := p.visit(e); err != nil {
			return fmt.Errorf("debian tracker %s %s %s: %w", pkg, id, name, err)
		}
		p.sum.Entries++
	}
	return nil
}

// debianEntry maps one release object onto a D4 tracker state:
//
//   - status "resolved" with fixed_version "0": <not-affected>
//   - status "resolved" with another fixed_version: fixed
//   - status "open" with urgency "end-of-life": <end-of-life>
//   - status "open" with nodsa and nodsa_reason "postponed": <postponed>
//   - status "open" with nodsa and nodsa_reason "ignored": <ignored>
//   - status "open" with nodsa and an empty nodsa_reason: <no-dsa>
//   - status "open" otherwise: unfixed
//   - status "undetermined": DebianUndetermined
//
// Any other status or nodsa_reason is rejected rather than guessed.
func debianEntry(pkg, id, rel string, j debianReleaseJSON) (DebianEntry, error) {
	where := fmt.Sprintf("debian tracker %s %s %s", pkg, id, rel)
	e := DebianEntry{Package: pkg, IssueID: id, Release: rel}
	if j.Urgency != "" {
		if len(j.Urgency) > MaxDebianUrgencyBytes || !debianUrgencyRe.MatchString(j.Urgency) {
			return e, fmt.Errorf("%s: urgency: %w", where, ErrFeedMalformed)
		}
		e.Urgency = j.Urgency
	}
	switch j.Status {
	case debianStatusResolved:
		if j.FixedVersion == nil {
			return e, fmt.Errorf("%s: resolved without fixed_version: %w", where, ErrFeedMalformed)
		}
		v := *j.FixedVersion
		if v == debianNotAffectedVersion {
			e.State = vulnfinding.TrackerNotAffected
			return e, nil
		}
		if !feedVersionRe.MatchString(v) {
			return e, fmt.Errorf("%s: fixed_version: %w", where, ErrFeedMalformed)
		}
		e.State, e.FixedVersion = vulnfinding.TrackerFixed, v
	case debianStatusOpen:
		switch {
		case j.Urgency == debianUrgencyEndOfLife:
			e.State = vulnfinding.TrackerEndOfLife
		case j.NoDSA != nil:
			reason := ""
			if j.NoDSAReason != nil {
				reason = *j.NoDSAReason
			}
			switch reason {
			case "":
				e.State = vulnfinding.TrackerNoDSA
			case "postponed":
				e.State = vulnfinding.TrackerPostponed
			case "ignored":
				e.State = vulnfinding.TrackerIgnored
			default:
				return e, fmt.Errorf("%s: nodsa_reason: %w", where, ErrFeedMalformed)
			}
		default:
			e.State = vulnfinding.TrackerUnfixed
		}
	case debianStatusUndetermined:
		e.State = DebianUndetermined
	default:
		return e, fmt.Errorf("%s: status: %w", where, ErrFeedMalformed)
	}
	return e, nil
}

// DebianAdvisoryList is the result of parsing a DSA or DLA list.
type DebianAdvisoryList struct {
	// Kind is "DSA" or "DLA"; a list mixing both is rejected.
	Kind string
	// Entries counts the advisories in the list.
	Entries int
	// Newest is the newest advisory date in the list: the content date
	// of the list and the proxy date of the tracker JSON (D4, Q5).
	Newest time.Time
	// Skipped counts lines left out because they broke the list format
	// (an unparsable entry line, a continuation line with control
	// characters).
	Skipped int
}

// ParseDebianAdvisoryList parses a Debian DSA or DLA list
// (data/DSA/list, data/DLA/list of the security tracker repository).
// Each entry starts with a line "[DD Mon YYYY] DSA-NNNN-N ..."; indented
// continuation lines are skipped. Any other line is skipped and counted.
// A list mixing DSA and DLA entries, a too long line or too many entries
// fail the list; a list without entries fails with ErrNoContentDate.
func ParseDebianAdvisoryList(ctx context.Context, r io.Reader) (DebianAdvisoryList, error) {
	var out DebianAdvisoryList
	br := newBoundedReader(r, MaxDebianListBytes)
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 4096), MaxDebianListLineBytes)
	line := 0
	for sc.Scan() {
		line++
		if line%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return DebianAdvisoryList{}, fmt.Errorf("debian advisory list: %w", err)
			}
		}
		s := strings.TrimSuffix(sc.Text(), "\r")
		if s == "" || s[0] == '\t' || s[0] == ' ' {
			if err := checkText(s, MaxDebianListLineBytes); err != nil {
				if !recordSkippable(err) {
					return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: %w", line, err)
				}
				out.Skipped++
			}
			continue
		}
		m := debianListHeadRe.FindStringSubmatch(s)
		if m == nil {
			out.Skipped++
			continue
		}
		d, err := parseFeedTime(m[1], "02 Jan 2006")
		if err != nil {
			if !recordSkippable(err) {
				return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: %w", line, err)
			}
			out.Skipped++
			continue
		}
		if out.Kind == "" {
			out.Kind = m[2]
		} else if out.Kind != m[2] {
			return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: mixed DSA and DLA: %w", line, ErrFeedMalformed)
		}
		if out.Entries++; out.Entries > MaxDebianListEntries {
			return DebianAdvisoryList{}, fmt.Errorf("debian advisory list: more than %d entries: %w", MaxDebianListEntries, ErrFeedLimit)
		}
		if d.After(out.Newest) {
			out.Newest = d
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: %w", line+1, ErrFeedLimit)
		}
		return DebianAdvisoryList{}, br.fail("debian advisory list", err)
	}
	if out.Entries == 0 {
		return DebianAdvisoryList{}, fmt.Errorf("debian advisory list: %w", ErrNoContentDate)
	}
	return out, nil
}
