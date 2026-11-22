// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// TestServerDigestFormatsAreAccepted uses digests as the server produces
// them: a fix group digest from opsfacts.Digest ("sha256:<hex>"), a
// question digest from opsnotes.QuestionDigest (bare hex) and a fleet
// summary digest (bare hex, internal/web/api fleetDigest; unexported, so
// the form is spelled out here).
func TestServerDigestFormatsAreAccepted(t *testing.T) {
	fix, err := opsfacts.Digest(opsfacts.LabProjection{Group: "h1/os"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fix, "sha256:") {
		t.Fatalf("opsfacts digest %q: test premise changed", fix)
	}
	q := opsnotes.QuestionDigest("Ist web-01 betroffen?")
	if strings.HasPrefix(q, "sha256:") || len(q) != 64 {
		t.Fatalf("question digest %q: test premise changed", q)
	}
	for _, c := range []struct{ kind, digest string }{
		{"fix", fix},
		{"question", q},
		{"summary", strings.Repeat("0123456789abcdef", 4)},
	} {
		if !isDigest(c.kind, c.digest) {
			t.Errorf("%s: server digest %q refused", c.kind, c.digest)
		}
	}
}

// TestFixItemWithServerDigestIsAnswered runs a fix item carrying a real
// opsfacts digest end to end: one call, one note echoing the digest.
func TestFixItemWithServerDigestIsAnswered(t *testing.T) {
	d, err := opsfacts.Digest(opsfacts.LabProjection{Group: "h1:os"})
	if err != nil {
		t.Fatal(err)
	}
	it := labItem("h1:os")
	it.Digest = d
	nos := &fakeNOS{cfg: goodSettings(), items: []nosclient.WorkItem{it}}
	h := newHarness(t, nos, &fakeChat{replies: []string{goodFix}})
	sum, err := h.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum.LLMCalls != 1 || sum.NotesWritten != 1 || len(nos.notes) != 1 || len(sum.Refusals) != 0 {
		t.Fatalf("summary %+v", sum)
	}
	if nos.notes[0].Digest != d {
		t.Errorf("note digest %q, want %q", nos.notes[0].Digest, d)
	}
}

// TestDigestFormIsBoundToItemKind: the "sha256:" prefix is accepted only
// for fix items, whose server digest carries it. A summary or question
// digest with the prefix and any digest of an unknown kind are refused, by
// isDigest and by validateItem. A bare fix digest stays accepted.
func TestDigestFormIsBoundToItemKind(t *testing.T) {
	hex64 := strings.Repeat("a", 64)
	if !isDigest("fix", hex64) {
		t.Error("bare fix digest refused")
	}
	for _, c := range []struct{ kind, digest string }{
		{"summary", "sha256:" + hex64},
		{"question", "sha256:" + hex64},
		{"", hex64},
		{"", "sha256:" + hex64},
		{"answer", hex64},
		{"FIX", "sha256:" + hex64},
	} {
		if isDigest(c.kind, c.digest) {
			t.Errorf("kind %q: digest %q accepted", c.kind, c.digest)
		}
	}

	sum := summaryItem()
	sum.Digest = "sha256:" + hex64
	q := questionItem("Ist web-01 betroffen?")
	q.Digest = "sha256:" + opsnotes.QuestionDigest("Ist web-01 betroffen?")
	for _, it := range []nosclient.WorkItem{sum, q} {
		if err := validateItem("lab", it); err == nil || err.Error() != "item digest" {
			t.Errorf("%s item with digest %q: %v, want item digest refusal", it.Kind, it.Digest, err)
		}
	}
}

// TestPrefixedSummaryDigestIsRefusedInRun: a summary item whose digest
// carries the fix prefix is refused before any LLM call and writes no note.
func TestPrefixedSummaryDigestIsRefusedInRun(t *testing.T) {
	it := summaryItem()
	it.Digest = "sha256:" + goodDigest
	nos := &fakeNOS{cfg: goodSettings(), items: []nosclient.WorkItem{it}}
	h := newHarness(t, nos, &fakeChat{replies: []string{"Zusammenfassung."}})
	sum, err := h.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum.LLMCalls != 0 || sum.NotesWritten != 0 || len(nos.notes) != 0 || len(sum.Refusals) != 1 {
		t.Fatalf("summary %+v, notes %d; want one refusal, no call, no note", sum, len(nos.notes))
	}
}

// TestMalformedDigestsAreRefused keeps the digest check exact for every
// kind: only "sha256:" followed by 64 lowercase hex (fix only) or 64
// lowercase hex alone.
func TestMalformedDigestsAreRefused(t *testing.T) {
	hex64 := strings.Repeat("a", 64)
	malformed := []string{
		"",
		"sha256:",
		hex64[:63],
		hex64 + "a",
		"sha256:" + hex64[:63],
		"sha256:" + hex64 + "a",
		"SHA256:" + hex64,
		"sha512:" + hex64,
		"md5:" + hex64,
		"sha256-" + hex64,
		":" + hex64,
		"sha256:sha256:" + hex64,
		"sha256:" + strings.Repeat("A", 64),
		strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("g", 64),
		strings.Repeat("g", 64),
		"sha256 :" + hex64,
		" sha256:" + hex64,
		" " + hex64,
		hex64 + "\n",
	}
	for _, kind := range []string{"fix", "summary", "question"} {
		for _, d := range malformed {
			if isDigest(kind, d) {
				t.Errorf("%s: digest %q accepted", kind, d)
			}
		}
	}
	it := labItem("h1:os")
	it.Digest = "sha512:" + hex64
	if err := validateItem("lab", it); err == nil {
		t.Error("fix item with a foreign digest prefix accepted")
	}
}
