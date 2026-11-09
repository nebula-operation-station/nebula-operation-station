// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func TestUpsertByNOSComputedKey(t *testing.T) {
	e := newEnv(t)
	a := item(t, "web01", "CVE-2026-0001")
	r1 := e.start(t)
	if res := e.submit(t, r1, 0, nil, a); res.Opened != 1 {
		t.Fatalf("first submit: %+v", res)
	}
	e.complete(t, r1)

	// The same finding again, with other values and the CVE in lower case:
	// NOS canonicalises and computes the same key, so it updates in place.
	b := item(t, "web01", "cve-2026-0001", withFix(vulnfinding.FixFixed, "1.0-5"), withText("assessment v2"))
	if b.Finding.Key != a.Finding.Key {
		t.Fatal("fixture: keys differ")
	}
	r2 := e.start(t)
	if res := e.submit(t, r2, 0, nil, b); res.Updated != 1 || res.Opened != 0 {
		t.Fatalf("second submit: %+v", res)
	}
	f := e.get(t, a.Finding.Key)
	if f.Record.Fix.Version != "1.0-5" || f.Record.Assessment.Text != "assessment v2" || f.StateRunSeq != r2.Seq || f.Episode != 1 {
		t.Fatalf("updated finding = %+v", f)
	}
	all, err := e.st.SubjectFindings(e.ctx, hostSubj("web01"))
	if err != nil || len(all) != 1 {
		t.Fatalf("findings on web01 = %d, %v; want 1", len(all), err)
	}

	// A different vuln, package or subject is a different finding.
	r3 := e.start(t)
	res := e.submit(t, r3, 0, nil,
		item(t, "web01", "CVE-2026-0002"),
		item(t, "web01", "CVE-2026-0001", withPackage("zlib")),
		item(t, "web02", "CVE-2026-0001"))
	if res.Opened != 3 {
		t.Fatalf("distinct findings opened = %d, want 3", res.Opened)
	}
}

func TestBatchIdempotentBySeqAndHash(t *testing.T) {
	e := newEnv(t)
	r := e.start(t)
	b := batchOf(0, nil, item(t, "web01", "CVE-2026-0001"))
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, b); err != nil {
		t.Fatal(err)
	}
	res, err := e.st.SubmitBatch(e.ctx, r.ID, b)
	if err != nil || !res.Duplicate {
		t.Fatalf("repeat = %+v, %v; want duplicate no-op", res, err)
	}
	other := batchOf(0, nil, item(t, "web01", "CVE-2026-0002"))
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, other); !errors.Is(err, ErrBatchConflict) {
		t.Fatalf("repeat with other body: %v, want ErrBatchConflict", err)
	}
	if _, err := e.st.Get(e.ctx, other.Items[0].Finding.Key); !errors.Is(err, ErrFindingNotFound) {
		t.Fatal("conflicting batch was applied")
	}
}

func TestBatchLimits(t *testing.T) {
	e := newEnv(t)
	r := e.start(t)
	it := item(t, "web01", "CVE-2026-0001")
	big := Batch{Seq: 0, Items: make([]Item, MaxFindingsPerBatch+1)}
	for i := range big.Items {
		big.Items[i] = it
	}
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, big); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("oversized batch: %v", err)
	}
	if _, err := e.st.SubmitBatch(e.ctx, "nope", batchOf(0, nil, it)); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(1, []Subject{{Kind: "host", ID: "Bad/ID"}}, it)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad covered subject: %v", err)
	}
}

func TestRecordWithUnnamedBasisSourceIsRejected(t *testing.T) {
	e := newEnv(t)
	seeded := e.seed(t, "web01", 1)
	r := e.start(t, e.src("osv"))
	// Rests on nvd, which this run did not name: rejected, and it blocks
	// the key's closure in this run.
	bad := item(t, "web01", cve(0), withSources("nvd"))
	res := e.submit(t, r, 0, []Subject{hostSubj("web01")}, bad)
	if res.Rejected != 1 || res.Updated != 0 {
		t.Fatalf("result = %+v", res)
	}
	c := e.complete(t, r)
	if c.BlockedRejected != 1 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, seeded[0].Finding.Key, StateOpen, "")
}

func TestReopenStartsNewEpisodeWithRecordValues(t *testing.T) {
	e := newEnv(t)
	it := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-9"), withCVSS(8.0))
	r1 := e.start(t)
	e.submit(t, r1, 0, nil, it)
	e.complete(t, r1)
	// Closed by omission.
	r2 := e.start(t)
	e.submit(t, r2, 0, []Subject{hostSubj("web01")})
	e.complete(t, r2)
	e.wantState(t, it.Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
	// Re-opened from an undated (raise-only) source with lower values:
	// the new episode takes them as they are.
	r3 := e.start(t, RunSource{ID: "osv", SnapshotID: "s", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindNone})
	low := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-3"), withCVSS(4.0))
	if res := e.submit(t, r3, 0, nil, low); res.Reopened != 1 {
		t.Fatalf("reopen result = %+v", res)
	}
	f := e.get(t, it.Finding.Key)
	if f.State != StateOpen || f.Episode != 2 || f.EpisodeFixedVersion != "1.0-3" || f.EpisodePeakTier != TierMedium || f.Record.Scores.CVSS.BaseScore != 4.0 {
		t.Fatalf("reopened = state %s episode %d fixed %s tier %d", f.State, f.Episode, f.EpisodeFixedVersion, f.EpisodePeakTier)
	}
	if f.ClosedBy != "" || !f.ClosedAt.IsZero() {
		t.Fatal("closure fields kept after reopen")
	}
}

func TestEpisodeMarksOnlyRise(t *testing.T) {
	e := newEnv(t)
	it := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-5"), withKEV("2026-01-02"), withCVSS(9.8))
	r1 := e.start(t)
	e.submit(t, r1, 0, nil, it)
	e.complete(t, r1)
	// A fully accepted, dated record lowers the current values...
	r2 := e.start(t)
	low := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-3"), withCVSS(3.0))
	res := e.submit(t, r2, 0, nil, low)
	e.complete(t, r2)
	if res.Downgrades != 2 {
		t.Fatalf("downgrades = %d, want KEV drop and tier fall", res.Downgrades)
	}
	f := e.get(t, it.Finding.Key)
	if f.Record.Fix.Version != "1.0-3" || f.Record.Scores.KEV != nil {
		t.Fatalf("current values not as reported: %+v", f.Record.Fix)
	}
	// ...but never the episode marks.
	if f.EpisodeFixedVersion != "1.0-5" || f.EpisodeKEVDate != "2026-01-02" || f.EpisodePeakTier != TierCritical {
		t.Fatalf("marks = %s %s %d", f.EpisodeFixedVersion, f.EpisodeKEVDate, f.EpisodePeakTier)
	}
	// A higher fixed version raises the mark; an earlier KEV date wins.
	r3 := e.start(t)
	e.submit(t, r3, 0, nil, item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-10"), withKEV("2025-12-01")))
	f = e.get(t, it.Finding.Key)
	if f.EpisodeFixedVersion != "1.0-10" || f.EpisodeKEVDate != "2025-12-01" {
		t.Fatalf("marks after raise = %s %s", f.EpisodeFixedVersion, f.EpisodeKEVDate)
	}
}

func TestRaiseOnlyRecordNeverLowersValues(t *testing.T) {
	cases := map[string]RunSource{}
	e := newEnv(t)
	base := e.clk.Now()
	// Establish a high-water mark for osv at base-1h.
	cases["regressed"] = e.srcAt("osv", base.Add(-48*time.Hour))
	cases["invalid"] = e.srcAt("osv", base.Add(time.Hour))
	cases["undated"] = RunSource{ID: "osv", SnapshotID: "s", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindNone}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			it := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-5"), withKEV("2026-01-02"), withCVSS(9.8), withText("first"))
			r1 := e.start(t)
			e.submit(t, r1, 0, nil, it)
			e.complete(t, r1)

			r := e.start(t, src, e.src("kev"))
			lower := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixNoFixYet, ""), withCVSS(2.0), withText("second"))
			lower.Finding.Record.Scores.KEV = nil
			res := e.submit(t, r, 0, nil, lower)
			if res.Updated != 1 {
				t.Fatalf("raise-only record must still count as reported: %+v", res)
			}
			fields := map[string]bool{}
			for _, ig := range res.Ignored {
				fields[ig.Field] = true
			}
			for _, want := range []string{"fix", "kev", "cvss", "assessment"} {
				if !fields[want] {
					t.Errorf("ignored change %s not listed: %+v", want, res.Ignored)
				}
			}
			f := e.get(t, it.Finding.Key)
			if f.Record.Fix.Version != "1.0-5" || f.Record.Scores.KEV == nil || f.Record.Scores.CVSS.BaseScore != 9.8 || f.Record.Assessment.Text != "first" {
				t.Fatalf("raise-only record lowered values: %+v", f.Record)
			}

			// Raising values from the same source applies.
			r2 := e.start(t, src, e.src("kev"))
			higher := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-7"), withKEV("2026-01-02"), withCVSS(10.0))
			e.submit(t, r2, 0, nil, higher)
			f = e.get(t, it.Finding.Key)
			if f.Record.Fix.Version != "1.0-7" || f.Record.Scores.CVSS.BaseScore != 10.0 || f.EpisodeFixedVersion != "1.0-7" {
				t.Fatalf("raise not applied: fix %s cvss %v", f.Record.Fix.Version, f.Record.Scores.CVSS.BaseScore)
			}
		})
	}
}

func TestRaiseOnlyRecordSetsKEVOnNewFinding(t *testing.T) {
	e := newEnv(t)
	r1 := e.start(t, e.src("osv"), e.src("kev"))
	e.complete(t, r1)
	// kev regressed: a new KEV finding resting on it still opens with
	// episode KEV.
	r := e.start(t, e.src("osv"), e.srcAt("kev", e.clk.Now().Add(-72*time.Hour)))
	it := item(t, "web01", "CVE-2026-0001", withSources("osv", "kev"), withKEV("2026-03-03"))
	if res := e.submit(t, r, 0, nil, it); res.Opened != 1 {
		t.Fatalf("result = %+v", res)
	}
	if f := e.get(t, it.Finding.Key); !f.EpisodeKEV() || f.EpisodePeakTier != TierCritical {
		t.Fatal("episode KEV not set from regressed source")
	}
}

func TestMixedBasisRaiseOnlyIfAnySourceIs(t *testing.T) {
	e := newEnv(t)
	it := item(t, "web01", "CVE-2026-0001", withSources("osv", "kev"), withFix(vulnfinding.FixFixed, "1.0-5"))
	r1 := e.start(t)
	e.submit(t, r1, 0, nil, it)
	e.complete(t, r1)
	// osv fresh and accepted, kev unknown-dated: the record is raise-only.
	r := e.start(t, e.src("osv"), RunSource{ID: "kev", SnapshotID: "s", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindNone})
	e.submit(t, r, 0, nil, item(t, "web01", "CVE-2026-0001", withSources("osv", "kev"), withFix(vulnfinding.FixFixed, "1.0-2")))
	if f := e.get(t, it.Finding.Key); f.Record.Fix.Version != "1.0-5" {
		t.Fatalf("mixed-basis record lowered the fix to %s", f.Record.Fix.Version)
	}
}

func TestProxyDatedSourceLowersCurrentValuesNotMarks(t *testing.T) {
	e := newEnv(t)
	proxy := func() RunSource {
		s := e.src("debian-tracker")
		s.DateKind = "proxy:dsa"
		return s
	}
	it := item(t, "web01", "CVE-2026-0001", withSources("debian-tracker"), withFix(vulnfinding.FixFixed, "1.0-5"), withKEV("2026-01-02"))
	r1 := e.start(t, proxy(), e.src("dsa"))
	e.submit(t, r1, 0, nil, it)
	r2 := e.start(t, proxy(), e.src("dsa"))
	low := item(t, "web01", "CVE-2026-0001", withSources("debian-tracker"), withFix(vulnfinding.FixFixed, "1.0-2"))
	e.submit(t, r2, 0, nil, low)
	f := e.get(t, it.Finding.Key)
	if f.Record.Fix.Version != "1.0-2" || f.Record.Scores.KEV != nil {
		t.Fatal("proxy-dated record should lower current values (documented Q5 limit)")
	}
	if f.EpisodeFixedVersion != "1.0-5" || !f.EpisodeKEV() {
		t.Fatal("proxy-dated record lowered episode marks")
	}
}
