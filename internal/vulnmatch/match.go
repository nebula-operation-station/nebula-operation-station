// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// MaxRecordBinaryPackages bounds the binaries listed as context in one
// record: the first ones in ascending bytewise order of name (A1.3).
const MaxRecordBinaryPackages = 6

// matcher is the state of one Match call.
type matcher struct {
	db      *DB
	opts    Options
	found   map[vulnfinding.Key]*Finding
	gaps    map[Gap]struct{}
	held    []Withheld
	feedCut int
	// vendor caches the indexed CSAF advisories per feed (vendorDocs).
	vendor map[string][]indexedAdvisory
}

// Match matches subjects against db and returns the findings in the D5
// record shape, the coverage gaps and the records withheld by validation.
// The result depends only on its inputs.
func Match(db *DB, subjects []Subject, opts Options) (Result, error) {
	if db == nil {
		return Result{}, fmt.Errorf("match: nil db: %w", ErrNoFeedSnapshot)
	}
	if len(subjects) > MaxSubjects {
		return Result{}, fmt.Errorf("match: %d subjects: %w", len(subjects), ErrLimit)
	}
	db.sortDebian()
	m := &matcher{db: db, opts: opts, found: map[vulnfinding.Key]*Finding{}, gaps: map[Gap]struct{}{}, feedCut: db.nvdCut}
	for _, s := range subjects {
		m.subject(s)
	}
	return m.result(), nil
}

func (m *matcher) gap(s Subject, pkg, id string, r GapReason) {
	m.gaps[Gap{Kind: s.Kind, Ref: s.Ref, Ecosystem: s.Ecosystem, Package: pkg, VulnID: id, Reason: r}] = struct{}{}
}

func (m *matcher) subject(s Subject) {
	if s.Incomplete {
		m.gap(s, "", "", GapInventoryIncomplete)
	}
	if s.Kind == vulnfinding.SubjectDevice {
		m.device(s)
		return
	}
	var scheme vulnver.Scheme
	var feed string
	switch {
	case debianEcoRe.MatchString(s.Ecosystem):
		scheme, feed = vulnver.SchemeDpkg, FeedDebianTracker
	case ubuntuEcoRe.MatchString(s.Ecosystem):
		scheme, feed = vulnver.SchemeDpkg, FeedOSVUbuntu
	case alpineEcoRe.MatchString(s.Ecosystem):
		scheme, feed = vulnver.SchemeAPK, FeedOSVAlpine
	default:
		m.gap(s, "", "", GapEcosystemUnknown)
		return
	}
	if _, ok := m.db.feeds[feed]; !ok {
		// A covered ecosystem without its feed snapshot is unknown, never
		// clean.
		m.gap(s, "", "", GapFeedMissing)
		return
	}
	hostKernel := s.Kind == vulnfinding.SubjectHost && scheme == vulnver.SchemeDpkg
	var kernelComps []Component
	for _, c := range s.Components {
		switch {
		case scheme == vulnver.SchemeDpkg && vulnver.NeverVersionBasis(c.SourcePackage):
			// Signed and meta kernel sources are never a basis (D4).
			continue
		case scheme == vulnver.SchemeDpkg && proxmoxPkgRe.MatchString(c.SourcePackage):
			m.gap(s, c.SourcePackage, "", GapProxmox)
			continue
		case hostKernel && vulnver.IsKernelSource(c.SourcePackage):
			kernelComps = append(kernelComps, c)
			continue
		}
		m.component(s, scheme, c, nil)
	}
	if hostKernel && (s.Kernel != nil || len(kernelComps) > 0) {
		m.kernel(s, kernelComps)
	}
}

// kernel matches a host's running kernel (D4): the basis is the running
// kernel's unsigned source package and version as NOS mapped it; installed
// kernels are context only.
func (m *matcher) kernel(s Subject, comps []Component) {
	k := s.Kernel
	if k == nil || !k.Mapped || !vulnver.IsKernelSource(k.SourcePackage) ||
		vulnver.Validate(vulnver.SchemeDpkg, k.SourceVersion) != nil {
		m.gap(s, "", "", GapKernelUnknown)
		return
	}
	run := Component{SourcePackage: k.SourcePackage, SourceVersion: k.SourceVersion}
	var installed []string
	for _, c := range comps {
		if c.SourcePackage != k.SourcePackage {
			continue // another kernel line: installed kernels never count
		}
		run.Binaries = append(run.Binaries, c.Binaries...)
		for _, b := range c.Binaries {
			if b.SourceVersion != "" {
				installed = append(installed, b.SourceVersion)
			}
		}
	}
	for i, ik := range k.Installed {
		if i >= MaxInstalledKernels {
			break
		}
		if ik.SourcePackage == k.SourcePackage {
			installed = append(installed, ik.SourceVersion)
		}
	}
	// Binaries keep their names as context; their source versions are
	// installed kernels, not the running one, so they never enter the
	// running basis.
	for i := range run.Binaries {
		run.Binaries[i].SourceVersion = ""
	}
	m.component(s, vulnver.SchemeDpkg, run, installed)
}

// basisVersion returns the D4 version basis of c: the lowest of its
// source version and every per-binary source version, via vulnver.
func basisVersion(s vulnver.Scheme, c Component) (string, error) {
	bins := []vulnver.Binary{{Name: c.SourcePackage, SourceName: c.SourcePackage, SourceVersion: c.SourceVersion}}
	for _, b := range c.Binaries {
		if b.SourceVersion != "" {
			bins = append(bins, vulnver.Binary{Name: b.Name, Version: b.Version, SourceName: c.SourcePackage, SourceVersion: b.SourceVersion})
		}
	}
	sb, err := vulnver.SourceVersionBasis(s, c.SourcePackage, bins)
	if err != nil {
		return "", fmt.Errorf("basis %s: %w", c.SourcePackage, err)
	}
	return sb.Version, nil
}

// component matches one source package of a host or image. installed are
// other installed kernels of the same source (kernel only).
func (m *matcher) component(s Subject, scheme vulnver.Scheme, c Component, installed []string) {
	basis, err := basisVersion(scheme, c)
	if err != nil {
		m.gap(s, c.SourcePackage, "", GapVersionUnknown)
		return
	}
	switch {
	case debianEcoRe.MatchString(s.Ecosystem):
		m.debian(s, c, basis, installed)
	case ubuntuEcoRe.MatchString(s.Ecosystem):
		m.osv(s, scheme, c, basis, installed, FeedOSVUbuntu, ubuntuOSVEcosystems(s.Ecosystem), vulnfinding.MatchDistroTracker)
	case alpineEcoRe.MatchString(s.Ecosystem):
		m.osv(s, scheme, c, basis, installed, FeedOSVAlpine, alpineOSVEcosystems(s.Ecosystem), vulnfinding.MatchOSVRange)
	}
}

// debian applies the Security Tracker entries of (source package, release)
// with the D4 state table. The caller has checked that the tracker
// snapshot is set.
func (m *matcher) debian(s Subject, c Component, basis string, installed []string) {
	release := debianEcoRe.FindStringSubmatch(s.Ecosystem)[1]
	for _, e := range m.db.debian[debKey{c.SourcePackage, release}] {
		mp, err := vulnfinding.MapDebianTrackerState(e.state)
		if err != nil {
			m.gap(s, c.SourcePackage, e.issue, GapTrackerState)
			continue
		}
		fix := vulnfinding.Fix{State: mp.Fix}
		state := e.state
		var notes []Note
		if e.state == vulnfinding.TrackerFixed {
			affected, err := vulnver.Affected(vulnver.SchemeDpkg, basis, e.fixed)
			if err != nil {
				m.gap(s, c.SourcePackage, e.issue, GapFixedVersionUnknown)
				continue
			}
			if !affected {
				continue // installed ≥ fixed: no record, never a claim
			}
			fix.Version = e.fixed
			if len(e.fixed) > MaxFixedVersionLen || !versionRe.MatchString(e.fixed) {
				// A1.3: fail closed; the tracker state must then be one
				// whose single target is no_fix_yet.
				fix, state = vulnfinding.Fix{State: vulnfinding.FixNoFixYet}, vulnfinding.TrackerUnfixed
				notes = append(notes, NoteFixedVersionOverBounds)
				m.feedCut++
			} else {
				notes = append(notes, rebootNote(vulnver.SchemeDpkg, installed, e.fixed)...)
			}
		}
		m.emit(s, c, basis, []string{e.issue}, fix, state, vulnfinding.MatchDistroTracker, FeedDebianTracker, notes)
	}
}

// rebootNote returns NoteFixedAfterReboot when an installed, not running
// kernel is at or after fixed.
func rebootNote(scheme vulnver.Scheme, installed []string, fixed string) []Note {
	for _, v := range installed {
		if aff, err := vulnver.Affected(scheme, v, fixed); err == nil && !aff {
			return []Note{NoteFixedAfterReboot}
		}
	}
	return nil
}

func ubuntuOSVEcosystems(eco string) []string {
	rel := ubuntuEcoRe.FindStringSubmatch(eco)[1]
	return []string{"Ubuntu:" + rel, "Ubuntu:" + rel + ":LTS"}
}

func alpineOSVEcosystems(eco string) []string {
	return []string{"Alpine:v" + alpineEcoRe.FindStringSubmatch(eco)[1]}
}

// osv evaluates the OSV records of the subject's release for c's source
// package. ESM/Pro ecosystems are never consulted (D4: they count only
// when the host has that archive enabled, which the export does not say).
// The caller has checked that the feed's snapshot is set.
func (m *matcher) osv(s Subject, scheme vulnver.Scheme, c Component, basis string, installed []string, feed string, ecos []string, mb vulnfinding.MatchBasis) {
	var hits []osvHit
	for _, eco := range ecos {
		for _, h := range m.db.osvIndex[osvKey{eco, c.SourcePackage}] {
			if m.db.osv[h.rec].feed == feed {
				hits = append(hits, h)
			}
		}
	}
	slices.SortFunc(hits, func(a, b osvHit) int {
		return cmp.Or(strings.Compare(m.db.osv[a.rec].rec.ID, m.db.osv[b.rec].rec.ID), a.rec-b.rec, a.affected-b.affected)
	})
	for _, h := range hits {
		rec := m.db.osv[h.rec].rec
		if !rec.Withdrawn.IsZero() {
			continue
		}
		aff := rec.Affected[h.affected]
		ranges, unsupported := osvRanges(aff)
		if len(ranges) == 0 {
			m.gap(s, c.SourcePackage, rec.ID, GapRangeUnknown)
			continue
		}
		affected, err := vulnver.OSVAffected(scheme, basis, ranges)
		if err != nil {
			m.gap(s, c.SourcePackage, rec.ID, GapRangeUnknown)
			continue
		}
		if !affected {
			if unsupported {
				m.gap(s, c.SourcePackage, rec.ID, GapRangeUnknown)
			}
			continue
		}
		fix := vulnfinding.Fix{State: vulnfinding.FixNoFixYet}
		var notes []Note
		if f, ok := firstFix(scheme, basis, ranges); ok {
			if len(f) > MaxFixedVersionLen || !versionRe.MatchString(f) {
				notes = append(notes, NoteFixedVersionOverBounds)
				m.feedCut++
			} else {
				fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: f}
				notes = append(notes, rebootNote(scheme, installed, f)...)
			}
		}
		ids := append([]string{rec.ID}, rec.Aliases...)
		m.emit(s, c, basis, ids, fix, "", mb, feed, notes)
	}
}

// osvRanges converts the ECOSYSTEM ranges of an affected entry; unsupported
// reports ranges left out (SEMVER, GIT, unknown types).
func osvRanges(a vulnfeed.OSVAffected) ([]vulnver.Range, bool) {
	unsupported := a.SkippedRanges > 0
	var out []vulnver.Range
	for _, r := range a.Ranges {
		if string(r.Type) != vulnver.RangeEcosystem {
			unsupported = true
			continue
		}
		vr := vulnver.Range{Type: vulnver.RangeEcosystem}
		for _, e := range r.Events {
			var k vulnver.EventKind
			switch string(e.Kind) {
			case "introduced":
				k = vulnver.EventIntroduced
			case "fixed":
				k = vulnver.EventFixed
			case "last_affected":
				k = vulnver.EventLastAffected
			case "limit":
				k = vulnver.EventLimit
			default:
				unsupported = true
				continue
			}
			vr.Events = append(vr.Events, vulnver.Event{Kind: k, Version: e.Version})
		}
		out = append(out, vr)
	}
	return out, unsupported
}

// firstFix returns the smallest "fixed" event above basis at which the
// ranges no longer affect the package; false when there is none (no fix
// yet). All comparisons go through vulnver.
func firstFix(scheme vulnver.Scheme, basis string, ranges []vulnver.Range) (string, bool) {
	var cands []string
	for _, r := range ranges {
		for _, e := range r.Events {
			if e.Kind != vulnver.EventFixed {
				continue
			}
			if aff, err := vulnver.Affected(scheme, basis, e.Version); err == nil && aff {
				cands = append(cands, e.Version)
			}
		}
	}
	var sortErr error
	slices.SortStableFunc(cands, func(a, b string) int {
		c, err := vulnver.Compare(scheme, a, b)
		if err != nil {
			sortErr = err
		}
		return c
	})
	if sortErr != nil {
		return "", false
	}
	for _, f := range cands {
		if aff, err := vulnver.OSVAffected(scheme, f, ranges); err == nil && !aff {
			return f, true
		}
	}
	return "", false
}

// emit builds one record for a host or image component and adds it.
func (m *matcher) emit(s Subject, c Component, basis string, ids []string, fix vulnfinding.Fix, state vulnfinding.TrackerState,
	mb vulnfinding.MatchBasis, feed string, notes []Note) {
	primary, aliases, cut, ok := chooseIDs(ids, s.Ecosystem, c.SourcePackage, m.opts.Anchors)
	m.feedCut += cut
	if !ok {
		m.gap(s, c.SourcePackage, "", GapNoValidID)
		return
	}
	rec := vulnfinding.Record{
		SubjectKind: s.Kind,
		SubjectRef:  s.Ref,
		Ecosystem:   s.Ecosystem,
		Component: vulnfinding.Component{
			SourcePackage: c.SourcePackage,
			SourceVersion: basis,
			Binaries:      contextBinaries(c.Binaries),
		},
		Vuln:         vulnfinding.Vuln{ID: primary, Aliases: aliases},
		Fix:          fix,
		TrackerState: state,
		MatchBasis:   mb,
	}
	m.finish(s, rec, feed, notes)
}

// finish adds scores and evidence, validates and merges the record.
func (m *matcher) finish(s Subject, rec vulnfinding.Record, feed string, notes []Note) {
	var scoreFeeds []string
	rec.Scores, scoreFeeds = m.db.scores(rec.Vuln.ID, rec.Vuln.Aliases)
	var cut int
	rec.Evidence, cut = m.db.evidence(feed, scoreFeeds)
	m.feedCut += cut
	f, err := vulnfinding.Validate(rec)
	if err != nil {
		m.held = append(m.held, Withheld{Kind: s.Kind, Ref: s.Ref, Ecosystem: s.Ecosystem, VulnID: rec.Vuln.ID, Err: err})
		return
	}
	m.merge(f.Key, Finding{Record: f.Record, Notes: notes})
}

// contextBinaries returns at most MaxRecordBinaryPackages binaries, the
// first in bytewise order of name, each name once.
func contextBinaries(bs []Binary) []vulnfinding.Binary {
	var out []vulnfinding.Binary
	seen := map[string]bool{}
	for _, b := range bs {
		if seen[b.Name] {
			continue
		}
		seen[b.Name] = true
		out = append(out, vulnfinding.Binary{Name: b.Name, Version: b.Version})
	}
	slices.SortFunc(out, func(a, b vulnfinding.Binary) int { return strings.Compare(a.Name, b.Name) })
	if len(out) > MaxRecordBinaryPackages {
		out = out[:MaxRecordBinaryPackages]
	}
	return out
}

// fixRank orders fix states for merging two records with one key: a state
// that keeps the finding open longer wins.
func fixRank(f vulnfinding.Fix) int {
	switch f.State {
	case vulnfinding.FixNoFixYet:
		return 3
	case vulnfinding.FixWontFix:
		return 2
	case vulnfinding.FixFixed:
		return 1
	default:
		return 0
	}
}

// merge combines two records with the same finding_key deterministically:
// an opening record beats not_affected; among opening records the one that
// keeps the finding open longer wins (no fix yet over a fixed version, the
// higher fixed version over the lower); aliases, basis sources and notes
// are united.
func (m *matcher) merge(k vulnfinding.Key, f Finding) {
	old, ok := m.found[k]
	if !ok {
		m.found[k] = &f
		return
	}
	keep, other := old, &f
	ro, rn := fixRank(old.Record.Fix), fixRank(f.Record.Fix)
	switch {
	case rn > ro:
		keep, other = &f, old
	case rn == ro && rn == 1:
		if scheme, err := vulnver.SchemeForEcosystem(f.Record.Ecosystem); err == nil {
			if c, err := vulnver.Compare(scheme, f.Record.Fix.Version, old.Record.Fix.Version); err == nil && c > 0 {
				keep, other = &f, old
			}
		}
	}
	out := *keep
	if fixRank(out.Record.Fix) > 0 {
		ids := append(slices.Clone(out.Record.Vuln.Aliases), other.Record.Vuln.Aliases...)
		ids = append(ids, other.Record.Vuln.ID)
		out.Record.Vuln.Aliases = mergeAliases(out.Record.Vuln.ID, ids)
		out.Record.Evidence.BasisSources = mergeBasis(out.Record.Evidence.BasisSources, other.Record.Evidence.BasisSources)
		out.Notes = append(slices.Clone(out.Notes), other.Notes...)
	}
	m.found[k] = &out
}

func mergeAliases(primary string, ids []string) []string {
	seen := map[string]bool{primary: true}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	slices.Sort(out)
	if len(out) > MaxAliases {
		out = out[:MaxAliases]
	}
	return out
}

func mergeBasis(a, b []vulnfinding.BasisSource) []vulnfinding.BasisSource {
	out := slices.Clone(a)
	seen := map[string]bool{}
	for _, x := range a {
		seen[x.SourceID] = true
	}
	for _, x := range b {
		if !seen[x.SourceID] && len(out) < MaxRecordBasisSources {
			seen[x.SourceID] = true
			out = append(out, x)
		}
	}
	return out
}

func findingOrder(a, b vulnfinding.Record) int {
	return cmp.Or(
		strings.Compare(string(a.SubjectKind), string(b.SubjectKind)),
		strings.Compare(a.SubjectRef.ID, b.SubjectRef.ID),
		strings.Compare(a.SubjectRef.ImageDigest, b.SubjectRef.ImageDigest),
		strings.Compare(a.Ecosystem, b.Ecosystem),
		strings.Compare(a.Component.SourcePackage+a.Component.Model, b.Component.SourcePackage+b.Component.Model),
		strings.Compare(a.Vuln.ID, b.Vuln.ID),
	)
}

func (m *matcher) result() Result {
	r := Result{MatcherVersion: MatcherVersion, FeedPartsCut: m.feedCut, Withheld: m.held}
	for _, f := range m.found {
		f.Notes = uniqueNotes(f.Notes)
		r.Findings = append(r.Findings, *f)
	}
	slices.SortFunc(r.Findings, func(a, b Finding) int { return findingOrder(a.Record, b.Record) })
	for g := range m.gaps {
		r.Gaps = append(r.Gaps, g)
	}
	slices.SortFunc(r.Gaps, func(a, b Gap) int {
		return cmp.Or(
			strings.Compare(string(a.Kind), string(b.Kind)),
			strings.Compare(a.Ref.ID, b.Ref.ID),
			strings.Compare(a.Ref.ImageDigest, b.Ref.ImageDigest),
			strings.Compare(a.Ecosystem, b.Ecosystem),
			strings.Compare(a.Package, b.Package),
			strings.Compare(a.VulnID, b.VulnID),
			strings.Compare(string(a.Reason), string(b.Reason)),
		)
	})
	slices.SortStableFunc(r.Withheld, func(a, b Withheld) int {
		return cmp.Or(
			strings.Compare(string(a.Kind), string(b.Kind)),
			strings.Compare(a.Ref.ID, b.Ref.ID),
			strings.Compare(a.Ref.ImageDigest, b.Ref.ImageDigest),
			strings.Compare(a.VulnID, b.VulnID),
		)
	})
	return r
}

func uniqueNotes(ns []Note) []Note {
	if len(ns) == 0 {
		return nil
	}
	out := slices.Clone(ns)
	slices.Sort(out)
	return slices.Compact(out)
}
