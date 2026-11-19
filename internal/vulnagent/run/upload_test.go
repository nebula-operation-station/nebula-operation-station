// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// packBudget is the byte budget of one batch for its records and subject
// entries together: the batch limit less the envelope (D5, upload.go).
const packBudget = nosclient.MaxBatchBytes - BatchEnvelopeMaxBytes

// filler returns a raw record of the given cost, where cost is its length
// plus the one separator byte the packer counts. The packer does not parse
// records, so filler bytes are enough for packer-level tests.
func filler(cost int) json.RawMessage {
	return json.RawMessage(strings.Repeat("x", cost-1))
}

// repeatCost returns n copies of cost.
func repeatCost(cost, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = cost
	}
	return out
}

// subjectCost is the packer's cost of a batch subject entry.
func subjectCost(t *testing.T, s nosclient.BatchSubject) int {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return len(b) + 1
}

// subjectWithCost returns a subject entry whose packer cost is exactly cost.
func subjectWithCost(t *testing.T, cost int) nosclient.BatchSubject {
	t.Helper()
	s := nosclient.BatchSubject{Kind: vulnfinding.SubjectHost, Part: 1, LastPart: true}
	base := subjectCost(t, s)
	if cost < base {
		t.Fatalf("cost %d below the minimum %d", cost, base)
	}
	s.Ref.ID = strings.Repeat("h", cost-base)
	if got := subjectCost(t, s); got != cost {
		t.Fatalf("subject cost %d, want %d", got, cost)
	}
	return s
}

// checkBatchLimits asserts the invariants every batch must keep: Seq runs
// 1, 2, … without gaps, no batch exceeds the finding or subject count, and
// no batch exceeds the byte budget.
func checkBatchLimits(t *testing.T, batches []nosclient.Batch) {
	t.Helper()
	for i, b := range batches {
		if b.Seq != int64(i+1) {
			t.Errorf("batch %d has Seq %d, want %d", i, b.Seq, i+1)
		}
		if n := len(b.Findings); n > nosclient.MaxFindingsPerBatch {
			t.Errorf("batch %d has %d findings, limit %d", b.Seq, n, nosclient.MaxFindingsPerBatch)
		}
		if n := len(b.Subjects); n > nosclient.MaxCoveredPerBatch {
			t.Errorf("batch %d has %d subjects, limit %d", b.Seq, n, nosclient.MaxCoveredPerBatch)
		}
		size := 0
		for _, f := range b.Findings {
			size += len(f) + 1
		}
		for _, s := range b.Subjects {
			size += subjectCost(t, s)
		}
		if size > packBudget {
			t.Errorf("batch %d is %d bytes, budget %d", b.Seq, size, packBudget)
		}
	}
}

// perBatch maps each batch with n and returns the results in order.
func perBatch(batches []nosclient.Batch, n func(nosclient.Batch) int) []int {
	out := make([]int, 0, len(batches))
	for _, b := range batches {
		out = append(out, n(b))
	}
	return out
}

func findingsOf(b nosclient.Batch) int { return len(b.Findings) }
func subjectsOf(b nosclient.Batch) int { return len(b.Subjects) }

func TestPackLimitsMatchD5(t *testing.T) {
	// ADR 0011 D5: 1 MiB and 1,000 findings per batch.
	if nosclient.MaxBatchBytes != 1<<20 {
		t.Errorf("MaxBatchBytes = %d, D5 says 1 MiB", nosclient.MaxBatchBytes)
	}
	if nosclient.MaxFindingsPerBatch != 1000 {
		t.Errorf("MaxFindingsPerBatch = %d, D5 says 1,000", nosclient.MaxFindingsPerBatch)
	}
}

func TestPackerFindingCountLimit(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want []int
	}{
		{"at the count limit one batch holds all", nosclient.MaxFindingsPerBatch, []int{nosclient.MaxFindingsPerBatch}},
		{"one over the count limit opens a second batch", nosclient.MaxFindingsPerBatch + 1, []int{nosclient.MaxFindingsPerBatch, 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p packer
			for range tc.n {
				p.addFinding(json.RawMessage("{}"))
			}
			p.flush()
			if got := perBatch(p.batches, findingsOf); !slices.Equal(got, tc.want) {
				t.Errorf("findings per batch = %v, want %v", got, tc.want)
			}
			checkBatchLimits(t, p.batches)
		})
	}
}

func TestPackerFindingByteLimit(t *testing.T) {
	const recMax = MaxRecordBytes // 16 KiB: 63 such records fill packBudget exactly
	tests := []struct {
		name  string
		costs []int
		want  []int
	}{
		{"63 max-size records fill the budget exactly", repeatCost(recMax, 63), []int{63}},
		{"62 max-size records and two halves sum to the budget", append(repeatCost(recMax, 62), recMax/2, recMax/2), []int{64}},
		{"62 max-size records and halves one byte over the budget", append(repeatCost(recMax, 62), recMax/2, recMax/2+1), []int{63, 1}},
		{"a record after a full budget opens a second batch", append(repeatCost(recMax, 63), 2), []int{63, 1}},
	}
	if 63*recMax != packBudget {
		t.Fatalf("test assumes 63 records of %d fill the budget %d", recMax, packBudget)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p packer
			for _, c := range tc.costs {
				p.addFinding(filler(c))
			}
			p.flush()
			if got := perBatch(p.batches, findingsOf); !slices.Equal(got, tc.want) {
				t.Errorf("findings per batch = %v, want %v", got, tc.want)
			}
			checkBatchLimits(t, p.batches)
		})
	}
}

func TestPackerSubjectCountLimit(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want []int
	}{
		{"at the count limit one batch holds all", nosclient.MaxCoveredPerBatch, []int{nosclient.MaxCoveredPerBatch}},
		{"one over the count limit opens a second batch", nosclient.MaxCoveredPerBatch + 1, []int{nosclient.MaxCoveredPerBatch, 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p packer
			s := nosclient.BatchSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Part: 1, LastPart: true}
			for range tc.n {
				if err := p.addSubject(s); err != nil {
					t.Fatal(err)
				}
			}
			p.flush()
			if got := perBatch(p.batches, subjectsOf); !slices.Equal(got, tc.want) {
				t.Errorf("subjects per batch = %v, want %v", got, tc.want)
			}
			checkBatchLimits(t, p.batches)
		})
	}
}

func TestPackerSubjectByteLimit(t *testing.T) {
	const recMax = MaxRecordBytes
	tests := []struct {
		name  string
		costs []int
		want  []int
	}{
		{"subject entries sum to the budget exactly", repeatCost(recMax, 63), []int{63}},
		{"subject entries one byte over the budget", append(repeatCost(recMax, 62), recMax/2, recMax/2+1), []int{63, 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p packer
			for _, c := range tc.costs {
				if err := p.addSubject(subjectWithCost(t, c)); err != nil {
					t.Fatal(err)
				}
			}
			p.flush()
			if got := perBatch(p.batches, subjectsOf); !slices.Equal(got, tc.want) {
				t.Errorf("subjects per batch = %v, want %v", got, tc.want)
			}
			checkBatchLimits(t, p.batches)
		})
	}
}

func TestPackerMixedByteLimit(t *testing.T) {
	const recMax = MaxRecordBytes
	tests := []struct {
		name         string
		findingCosts []int
		subjectCosts []int
		wantFindings []int
		wantSubjects []int
	}{
		{
			name:         "findings and subject entries sum to the budget exactly",
			findingCosts: repeatCost(recMax, 62),
			subjectCosts: []int{recMax / 2, recMax / 2},
			wantFindings: []int{62},
			wantSubjects: []int{2},
		},
		{
			name:         "one byte over the budget moves the last subject entry",
			findingCosts: repeatCost(recMax, 62),
			subjectCosts: []int{recMax / 2, recMax/2 + 1},
			wantFindings: []int{62, 0},
			wantSubjects: []int{1, 1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p packer
			for _, c := range tc.findingCosts {
				p.addFinding(filler(c))
			}
			for _, c := range tc.subjectCosts {
				if err := p.addSubject(subjectWithCost(t, c)); err != nil {
					t.Fatal(err)
				}
			}
			p.flush()
			if got := perBatch(p.batches, findingsOf); !slices.Equal(got, tc.wantFindings) {
				t.Errorf("findings per batch = %v, want %v", got, tc.wantFindings)
			}
			if got := perBatch(p.batches, subjectsOf); !slices.Equal(got, tc.wantSubjects) {
				t.Errorf("subjects per batch = %v, want %v", got, tc.wantSubjects)
			}
			checkBatchLimits(t, p.batches)
		})
	}
}

func TestPackerFlushEmptyMakesNoBatch(t *testing.T) {
	var p packer
	p.flush()
	p.flush()
	if len(p.batches) != 0 {
		t.Fatalf("flush on an empty packer made %d batches", len(p.batches))
	}
	p.addFinding(json.RawMessage("{}"))
	p.flush()
	p.flush()
	if len(p.batches) != 1 || p.batches[0].Seq != 1 {
		t.Fatalf("after one record and two flushes: %d batches, want one with Seq 1", len(p.batches))
	}
}

// packRecord is a record of host subject id; pack does not validate it.
func packRecord(id string) vulnfinding.Record {
	return vulnfinding.Record{
		SubjectKind: vulnfinding.SubjectHost,
		SubjectRef:  vulnfinding.SubjectRef{ID: id},
		Ecosystem:   "debian:bookworm",
	}
}

// prep wraps a record the way match does, with its subject key.
func prep(rec vulnfinding.Record) prepared {
	return prepared{rec: rec, subject: subjectKey(rec.SubjectKind, rec.SubjectRef)}
}

// hostCov is a host subject of a snapshot with parts parts.
func hostCov(id string, parts int, complete bool) nosclient.SubjectCoverage {
	return nosclient.SubjectCoverage{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: id}, Parts: parts, Complete: complete}
}

// recordCost is the packer's cost of a record: encoded length plus one.
func recordCost(t *testing.T, rec vulnfinding.Record) int {
	t.Helper()
	b, err := encodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	return len(b) + 1
}

// recordOfCost returns a record with subject id whose packer cost is cost.
// pad sets the one field whose length is varied; the cost grows by one per
// padding byte once that field is set, which the probes check.
func recordOfCost(t *testing.T, id string, cost int, pad func(*vulnfinding.Record, string)) vulnfinding.Record {
	t.Helper()
	probe := func(n int) int {
		r := packRecord(id)
		pad(&r, strings.Repeat("p", n))
		return recordCost(t, r)
	}
	if probe(2)-probe(1) != 1 {
		t.Fatal("padding does not grow the record by one byte per byte")
	}
	n := 1 + cost - probe(1)
	if n < 1 {
		t.Fatalf("cost %d below the minimum %d", cost, probe(1))
	}
	r := packRecord(id)
	pad(&r, strings.Repeat("p", n))
	if got := recordCost(t, r); got != cost {
		t.Fatalf("record cost %d, want %d", got, cost)
	}
	return r
}

func padSource(r *vulnfinding.Record, s string) { r.Component.SourcePackage = s }
func padText(r *vulnfinding.Record, s string)   { r.Assessment.Text = s }

// sentRecords decodes the findings of all batches.
func sentRecords(t *testing.T, batches []nosclient.Batch) []vulnfinding.Record {
	t.Helper()
	var out []vulnfinding.Record
	for _, b := range batches {
		for _, raw := range b.Findings {
			var rec vulnfinding.Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatalf("batch %d: finding is not a record: %v", b.Seq, err)
			}
			out = append(out, rec)
		}
	}
	return out
}

// sentSubjects returns the subject entries of all batches in order.
func sentSubjects(batches []nosclient.Batch) []nosclient.BatchSubject {
	var out []nosclient.BatchSubject
	for _, b := range batches {
		out = append(out, b.Subjects...)
	}
	return out
}

func TestPackEmptyInputSendsNothing(t *testing.T) {
	batches, withheld, covered, err := pack(&nosclient.Snapshot{}, &matched{uncovered: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 0 || withheld != 0 || covered != 0 {
		t.Fatalf("empty input: %d batches, withheld %d, covered %d; want 0, 0, 0", len(batches), withheld, covered)
	}
}

func TestPackSendsRecordsInExportOrderThenCoverage(t *testing.T) {
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 2, true), hostCov("b", 1, true)}}
	m := &matched{uncovered: map[string]bool{}, findings: []prepared{
		prep(packRecord("b")), prep(packRecord("a")), prep(packRecord("a")),
	}}
	batches, withheld, covered, err := pack(snap, m)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 0 || covered != 2 || len(batches) != 1 {
		t.Fatalf("withheld %d, covered %d, batches %d; want 0, 2, 1", withheld, covered, len(batches))
	}
	var gotRecords []string
	for _, rec := range sentRecords(t, batches) {
		gotRecords = append(gotRecords, rec.SubjectRef.ID)
	}
	if want := []string{"a", "a", "b"}; !slices.Equal(gotRecords, want) {
		t.Errorf("records sent in order %v, want %v (per subject in export order)", gotRecords, want)
	}
	want := []nosclient.BatchSubject{
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "a"}, Part: 1},
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "a"}, Part: 2, LastPart: true},
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "b"}, Part: 1, LastPart: true},
	}
	if got := sentSubjects(batches); !slices.Equal(got, want) {
		t.Errorf("coverage = %+v, want %+v", got, want)
	}
}

func TestPackWithholdsRecordAndNamesNoSubject(t *testing.T) {
	tooLarge := recordOfCost(t, "a", MaxRecordBytes+1, padSource)
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 1, true), hostCov("b", 1, true)}}
	m := &matched{uncovered: map[string]bool{}, findings: []prepared{
		prep(packRecord("a")), prep(tooLarge), prep(packRecord("b")),
	}}
	batches, withheld, covered, err := pack(snap, m)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 1 || covered != 1 {
		t.Fatalf("withheld %d, covered %d; want 1, 1", withheld, covered)
	}
	if n := len(sentRecords(t, batches)); n != 2 {
		t.Errorf("%d records sent, want 2", n)
	}
	for _, s := range sentSubjects(batches) {
		if s.Ref.ID == "a" {
			t.Errorf("subject a named as covered although one of its records was withheld")
		}
	}
	if got := sentSubjects(batches); len(got) != 1 || got[0].Ref.ID != "b" {
		t.Errorf("covered subjects %+v, want only b", got)
	}
}

func TestPackStripsAssessmentOfOversizedRecord(t *testing.T) {
	withText := recordOfCost(t, "a", MaxRecordBytes+1, padText)
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 1, true)}}
	m := &matched{uncovered: map[string]bool{}, findings: []prepared{prep(withText)}}
	batches, withheld, covered, err := pack(snap, m)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 0 || covered != 1 {
		t.Fatalf("withheld %d, covered %d; want 0, 1: the record fits without its assessment", withheld, covered)
	}
	sent := sentRecords(t, batches)
	if len(sent) != 1 {
		t.Fatalf("%d records sent, want 1", len(sent))
	}
	if sent[0].Assessment.Text != "" {
		t.Error("oversized record sent with its assessment text")
	}
	if len(sent) == 1 && sent[0].SubjectRef.ID != "a" {
		t.Errorf("sent record names subject %q", sent[0].SubjectRef.ID)
	}
}

func TestPackKeepsAssessmentAtRecordLimit(t *testing.T) {
	atLimit := recordOfCost(t, "a", MaxRecordBytes, padText)
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 1, true)}}
	m := &matched{uncovered: map[string]bool{}, findings: []prepared{prep(atLimit)}}
	batches, withheld, _, err := pack(snap, m)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 0 {
		t.Fatalf("withheld %d, want 0 at exactly MaxRecordBytes", withheld)
	}
	sent := sentRecords(t, batches)
	if len(sent) != 1 || sent[0].Assessment.Text != atLimit.Assessment.Text {
		t.Error("record at exactly MaxRecordBytes lost its assessment text")
	}
}

func TestPackIncompleteOrUncoveredSubjectNotCovered(t *testing.T) {
	tests := []struct {
		name      string
		complete  bool
		uncovered bool
	}{
		{"incomplete subject", false, false},
		{"subject the run did not see completely", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 2, tc.complete)}}
			m := &matched{uncovered: map[string]bool{}, findings: []prepared{prep(packRecord("a"))}}
			if tc.uncovered {
				m.uncovered[subjectKey(vulnfinding.SubjectHost, vulnfinding.SubjectRef{ID: "a"})] = true
			}
			batches, withheld, covered, err := pack(snap, m)
			if err != nil {
				t.Fatal(err)
			}
			checkBatchLimits(t, batches)
			if n := len(sentRecords(t, batches)); n != 1 {
				t.Errorf("%d records sent, want the record sent", n)
			}
			if s := sentSubjects(batches); len(s) != 0 {
				t.Errorf("subject named as covered: %+v", s)
			}
			if covered != 0 || withheld != 0 {
				t.Errorf("covered %d, withheld %d; want 0, 0", covered, withheld)
			}
		})
	}
}

func TestPackUnknownSubjectRecordsWithheld(t *testing.T) {
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 1, true)}}
	m := &matched{uncovered: map[string]bool{}, findings: []prepared{prep(packRecord("ghost"))}}
	batches, withheld, covered, err := pack(snap, m)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 1 || covered != 1 || len(sentRecords(t, batches)) != 0 {
		t.Errorf("withheld %d, covered %d, sent %d records; want 1, 1 (a has no records), 0",
			withheld, covered, len(sentRecords(t, batches)))
	}
	for _, s := range sentSubjects(batches) {
		if s.Ref.ID != "a" {
			t.Errorf("subject %q named as covered; only the known subject a may be", s.Ref.ID)
		}
	}
}

func TestPackRecordCountLimit(t *testing.T) {
	const n = nosclient.MaxFindingsPerBatch + 1
	m := &matched{uncovered: map[string]bool{}}
	for range n {
		m.findings = append(m.findings, prep(packRecord("a")))
	}
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 1, true)}}
	batches, withheld, covered, err := pack(snap, m)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 0 || covered != 1 {
		t.Errorf("withheld %d, covered %d; want 0, 1", withheld, covered)
	}
	if got := perBatch(batches, findingsOf); !slices.Equal(got, []int{nosclient.MaxFindingsPerBatch, 1}) {
		t.Errorf("findings per batch = %v, want [%d 1]", got, nosclient.MaxFindingsPerBatch)
	}
	if got := perBatch(batches, subjectsOf); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("subjects per batch = %v, want [0 1]: the subject follows its last record", got)
	}
}

func TestPackSubjectCountLimit(t *testing.T) {
	const parts = nosclient.MaxCoveredPerBatch + 1
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", parts, true)}}
	batches, withheld, covered, err := pack(snap, &matched{uncovered: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 0 || covered != 1 {
		t.Errorf("withheld %d, covered %d; want 0, 1", withheld, covered)
	}
	if got := perBatch(batches, subjectsOf); !slices.Equal(got, []int{nosclient.MaxCoveredPerBatch, 1}) {
		t.Errorf("subjects per batch = %v, want [%d 1]", got, nosclient.MaxCoveredPerBatch)
	}
	for i, s := range sentSubjects(batches) {
		if s.Part != i+1 || s.LastPart != (i+1 == parts) {
			t.Fatalf("entry %d: part %d last %v; want part %d, last only on the final part", i, s.Part, s.LastPart, i+1)
		}
	}
}

func TestPackRecordByteLimitFlushesBeforeCoverage(t *testing.T) {
	// 63 records at MaxRecordBytes fill the budget exactly. The subject
	// entry cannot fit and starts the next batch.
	full := &matched{uncovered: map[string]bool{}}
	for range 63 {
		full.findings = append(full.findings, prep(recordOfCost(t, "a", MaxRecordBytes, padSource)))
	}
	snap := &nosclient.Snapshot{Subjects: []nosclient.SubjectCoverage{hostCov("a", 1, true)}}
	batches, withheld, covered, err := pack(snap, full)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if withheld != 0 || covered != 1 {
		t.Fatalf("withheld %d, covered %d; want 0, 1", withheld, covered)
	}
	if got := perBatch(batches, findingsOf); !slices.Equal(got, []int{63, 0}) {
		t.Errorf("findings per batch = %v, want [63 0]", got)
	}
	if got := perBatch(batches, subjectsOf); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("subjects per batch = %v, want [0 1]", got)
	}

	// One more record at MaxRecordBytes opens a second batch for itself.
	more := &matched{uncovered: map[string]bool{}}
	for range 64 {
		more.findings = append(more.findings, prep(recordOfCost(t, "a", MaxRecordBytes, padSource)))
	}
	batches, _, _, err = pack(snap, more)
	if err != nil {
		t.Fatal(err)
	}
	checkBatchLimits(t, batches)
	if got := perBatch(batches, findingsOf); !slices.Equal(got, []int{63, 1}) {
		t.Errorf("64 max-size records: findings per batch = %v, want [63 1]", got)
	}
}
