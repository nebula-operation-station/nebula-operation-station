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
// them: a fix group digest from opsfacts.Digest ("sha256:<hex>") and a
// question digest from opsnotes.QuestionDigest (bare hex, also the form of
// the fleet summary digest).
func TestServerDigestFormatsAreAccepted(t *testing.T) {
	fix, err := opsfacts.Digest(opsfacts.LabProjection{Group: "h1/os"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fix, "sha256:") {
		t.Fatalf("opsfacts digest %q: test premise changed", fix)
	}
	for _, d := range []string{fix, opsnotes.QuestionDigest("Ist web-01 betroffen?")} {
		if !isDigest(d) {
			t.Errorf("server digest %q refused", d)
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

// TestMalformedDigestsAreRefused keeps the digest check exact: only
// "sha256:" followed by 64 lowercase hex, or 64 lowercase hex alone.
func TestMalformedDigestsAreRefused(t *testing.T) {
	hex64 := strings.Repeat("a", 64)
	for _, d := range []string{
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
		"sha256 :" + hex64,
		" sha256:" + hex64,
	} {
		if isDigest(d) {
			t.Errorf("digest %q accepted", d)
		}
	}
	it := labItem("h1:os")
	it.Digest = "sha512:" + hex64
	if err := validateItem("lab", it); err == nil {
		t.Error("fix item with a foreign digest prefix accepted")
	}
}
