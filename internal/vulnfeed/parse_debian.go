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

// ParseDebianTracker streams the Debian Security Tracker JSON export
// (an object of source packages, each an object of issues with a
// "releases" object) and calls visit once per (package, issue, release)
// in package order of the input and sorted issue and release order.
//
// The export is undated: its content date is the proxy date of the DSA
// and DLA lists (ParseDebianAdvisoryList), never a fetch time. On any
// error the entries already visited must be discarded by the caller.
func ParseDebianTracker(ctx context.Context, r io.Reader, visit func(DebianEntry) error) (DebianTrackerSummary, error) {
	var sum DebianTrackerSummary
	br := newBoundedReader(r, MaxDebianTrackerBytes)
	dec := json.NewDecoder(br)
	tok, err := dec.Token()
	if err != nil {
		return sum, br.fail("debian tracker", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return sum, fmt.Errorf("debian tracker: top level is not an object: %w", ErrFeedMalformed)
	}
	seen := make(map[string]struct{})
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return sum, fmt.Errorf("debian tracker: %w", err)
		}
		tok, err := dec.Token()
		if err != nil {
			return sum, br.fail("debian tracker package name", err)
		}
		pkg, _ := tok.(string)
		if !debianPackageRe.MatchString(pkg) {
			return sum, fmt.Errorf("debian tracker package %d: name: %w", sum.Packages, ErrFeedMalformed)
		}
		if _, dup := seen[pkg]; dup {
			return sum, fmt.Errorf("debian tracker package %s: duplicate: %w", pkg, ErrFeedMalformed)
		}
		seen[pkg] = struct{}{}
		if sum.Packages++; sum.Packages > MaxDebianPackages {
			return sum, fmt.Errorf("debian tracker: more than %d packages: %w", MaxDebianPackages, ErrFeedLimit)
		}
		br.resetWindow(MaxDebianPackageBytes)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return sum, br.fail("debian tracker package "+pkg, err)
		}
		br.resetWindow(MaxDebianTrackerBytes)
		if len(raw) > MaxDebianPackageBytes {
			return sum, fmt.Errorf("debian tracker package %s: %w", pkg, ErrFeedLimit)
		}
		if err := parseDebianPackage(pkg, raw, &sum, visit); err != nil {
			return sum, err
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return sum, br.fail("debian tracker end", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '}' {
		return sum, fmt.Errorf("debian tracker end: %w", ErrFeedMalformed)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return sum, br.fail("debian tracker: data after the export", err)
	}
	if br.exceeded {
		return sum, fmt.Errorf("debian tracker: %w", ErrFeedLimit)
	}
	return sum, nil
}

// parseDebianPackage decodes and visits the issues of one source package.
func parseDebianPackage(pkg string, raw []byte, sum *DebianTrackerSummary, visit func(DebianEntry) error) error {
	var issues map[string]debianIssueJSON
	if err := decodeChecked(raw, &issues); err != nil {
		return fmt.Errorf("debian tracker package %s: %w", pkg, err)
	}
	if issues == nil {
		return fmt.Errorf("debian tracker package %s: not an object: %w", pkg, ErrFeedMalformed)
	}
	if len(issues) > MaxDebianIssuesPerPackage {
		return fmt.Errorf("debian tracker package %s: more than %d issues: %w", pkg, MaxDebianIssuesPerPackage, ErrFeedLimit)
	}
	ids := make([]string, 0, len(issues))
	for id := range issues {
		if !feedVulnIDRe.MatchString(id) {
			return fmt.Errorf("debian tracker package %s: issue ID: %w", pkg, ErrFeedMalformed)
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		sum.Issues++
		rels := issues[id].Releases
		if len(rels) > MaxDebianReleasesPerIssue {
			return fmt.Errorf("debian tracker %s %s: more than %d releases: %w", pkg, id, MaxDebianReleasesPerIssue, ErrFeedLimit)
		}
		names := make([]string, 0, len(rels))
		for name := range rels {
			if !debianReleaseRe.MatchString(name) {
				return fmt.Errorf("debian tracker %s %s: release name: %w", pkg, id, ErrFeedMalformed)
			}
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			e, err := debianEntry(pkg, id, name, rels[name])
			if err != nil {
				return err
			}
			if sum.Entries++; sum.Entries > MaxDebianEntries {
				return fmt.Errorf("debian tracker: more than %d entries: %w", MaxDebianEntries, ErrFeedLimit)
			}
			if err := visit(e); err != nil {
				return fmt.Errorf("debian tracker %s %s %s: %w", pkg, id, name, err)
			}
		}
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
}

// ParseDebianAdvisoryList parses a Debian DSA or DLA list
// (data/DSA/list, data/DLA/list of the security tracker repository).
// Each entry starts with a line "[DD Mon YYYY] DSA-NNNN-N ..."; indented
// continuation lines are skipped. Any other non-empty line is rejected.
// A list without entries fails with ErrNoContentDate.
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
				return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: %w", line, err)
			}
			continue
		}
		m := debianListHeadRe.FindStringSubmatch(s)
		if m == nil {
			return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: %w", line, ErrFeedMalformed)
		}
		if out.Kind == "" {
			out.Kind = m[2]
		} else if out.Kind != m[2] {
			return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: mixed DSA and DLA: %w", line, ErrFeedMalformed)
		}
		d, err := parseFeedTime(m[1], "02 Jan 2006")
		if err != nil {
			return DebianAdvisoryList{}, fmt.Errorf("debian advisory list line %d: %w", line, err)
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
