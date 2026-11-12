// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// snapshotView is the assessor's read-only view of the run's pinned feed
// snapshots (agent.Snapshot). It is filled while the snapshots are
// loaded and does no I/O afterwards. It keeps the NVD records, the KEV
// and EPSS data and the Debian tracker history of the source packages
// the export holds; every record carries its identity (source ID and
// position in the source's snapshot).
type snapshotView struct {
	pos map[string]int64
	nvd map[string]agent.CVERecord
	kev map[string]string
	// epss is keyed by upper-case CVE.
	epss     map[string]vulnfeed.EPSSScore
	epssDate string
	// wanted holds "release/package" of the export's Debian components.
	wanted  map[string]bool
	history map[string][]agent.PackageRecord
}

func newSnapshotView(wanted map[string]bool) *snapshotView {
	return &snapshotView{pos: map[string]int64{}, nvd: map[string]agent.CVERecord{}, kev: map[string]string{},
		epss: map[string]vulnfeed.EPSSScore{}, wanted: wanted, history: map[string][]agent.PackageRecord{}}
}

func (v *snapshotView) next(source string) int64 {
	p := v.pos[source]
	v.pos[source] = p + 1
	return p
}

func (v *snapshotView) addDebian(source string, e vulnfeed.DebianEntry) {
	v.next(source)
	k := e.Release + "/" + e.Package
	if !v.wanted[k] {
		return
	}
	v.history[k] = append(v.history[k], agent.PackageRecord{SourceID: source, RecordID: e.IssueID,
		FixedVersion: e.FixedVersion, TrackerState: string(e.State)})
}

func (v *snapshotView) addOSV(source string, _ vulnfeed.OSVRecord) {
	// OSV records are matched through the DB; the view only keeps their
	// positions so record identities stay stable.
	v.next(source)
}

func (v *snapshotView) addNVD(source string, r vulnfeed.NVDRecord) {
	pos := v.next(source)
	c := agent.CVERecord{Ref: agent.RecordRef{SourceID: source, Position: pos}, CWEs: r.CWEs,
		Description: r.Description}
	if !r.Published.IsZero() {
		c.Published = r.Published.UTC().Format("2006-01-02")
	}
	if !r.LastModified.IsZero() {
		c.Modified = r.LastModified.UTC().Format("2006-01-02")
	}
	for _, s := range r.CVSS {
		c.CVSS = append(c.CVSS, agent.CVSS{Version: s.Version, Vector: s.Vector, Score: s.BaseScore, SourceID: source})
	}
	for _, ref := range r.References {
		c.References = append(c.References, ref.URL)
	}
	v.nvd[strings.ToUpper(r.ID)] = c
}

func (v *snapshotView) addKEV(e vulnfeed.KEVEntry) {
	if e.DateAdded.IsZero() {
		return
	}
	v.kev[strings.ToUpper(e.CVE)] = e.DateAdded.UTC().Format("2006-01-02")
}

func (v *snapshotView) setEPSS(s vulnfeed.EPSSScores) {
	v.epssDate = s.Date.UTC().Format("2006-01-02")
	for _, sc := range s.Scores {
		v.epss[strings.ToUpper(sc.CVE)] = sc
	}
}

// CVERecords implements agent.Snapshot.
func (v *snapshotView) CVERecords(id string) []agent.CVERecord {
	if c, ok := v.nvd[strings.ToUpper(id)]; ok {
		return []agent.CVERecord{c}
	}
	return nil
}

// AdvisoryRecords implements agent.Snapshot. No advisory text is kept
// yet (the DSA/DLA lists only date the tracker).
func (v *snapshotView) AdvisoryRecords(string) []agent.AdvisoryRecord { return nil }

// PackageHistory implements agent.Snapshot. ecosystem is the NOS
// ecosystem ("debian:bookworm").
func (v *snapshotView) PackageHistory(ecosystem, pkg string) []agent.PackageRecord {
	rel, ok := strings.CutPrefix(ecosystem, "debian:")
	if !ok {
		return nil
	}
	return v.history[rel+"/"+pkg]
}

// KEVEPSS implements agent.Snapshot.
func (v *snapshotView) KEVEPSS(id string) (agent.KEVEPSS, bool) {
	k := strings.ToUpper(id)
	var out agent.KEVEPSS
	date, kev := v.kev[k]
	if kev {
		out.KEV, out.KEVDateAdded = true, date
	}
	sc, scored := v.epss[k]
	if scored {
		p, pc := sc.Probability, sc.Percentile
		out.EPSS, out.Percentile, out.ScoreDate = &p, &pc, v.epssDate
	}
	return out, kev || scored
}

// runView is the assessor's view of the run's own results (agent.RunView).
type runView struct {
	backport map[string]agent.Backport
	exposure map[string]agent.Exposure
}

// Backport implements agent.RunView.
func (v *runView) Backport(key string) (agent.Backport, bool) {
	b, ok := v.backport[key]
	return b, ok
}

// Exposure implements agent.RunView.
func (v *runView) Exposure(key string) (agent.Exposure, bool) {
	e, ok := v.exposure[key]
	return e, ok
}
