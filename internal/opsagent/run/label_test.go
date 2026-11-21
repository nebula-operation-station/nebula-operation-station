// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/nosclient"
)

// TestCandidateWithoutLabelMakesNoCall checks ADR 0016 D4: a fix item whose
// candidate has no fixed NOS label is refused before any model call.
func TestCandidateWithoutLabelMakesNoCall(t *testing.T) {
	item := labItem("h1:os")
	item.Group.Candidates[0].Label = ""
	nos := &fakeNOS{cfg: goodSettings(), items: []nosclient.WorkItem{item}}
	h := newHarness(t, nos, &fakeChat{replies: []string{goodFix}})
	sum, err := h.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.chat.reqs) != 0 || len(nos.notes) != 0 || !slices.Contains(sum.Refusals, RefusedWork) {
		t.Errorf("calls %d notes %d refusals %v", len(h.chat.reqs), len(nos.notes), sum.Refusals)
	}
}

// TestCandidateLabelIsInPromptAndActionIDIsNot checks that the label of each
// candidate reaches the candidate line of the prompt while the action ID and
// the host ID stay out of it (ADR 0016 D4).
func TestCandidateLabelIsInPromptAndActionIDIsNot(t *testing.T) {
	item := labItem("h1:os")
	// The fixed labels of the server (opsfacts.Label), not the fixture's.
	item.Group.Candidates[0].Label = "Install security updates"
	item.Group.Candidates[1].Label = "Restart the service"
	nos := &fakeNOS{cfg: goodSettings(), items: []nosclient.WorkItem{item}}
	h := newHarness(t, nos, &fakeChat{replies: []string{goodFix}})
	if _, err := h.run(t, nil); err != nil {
		t.Fatal(err)
	}
	if len(h.chat.reqs) != 1 {
		t.Fatalf("calls %d, want 1", len(h.chat.reqs))
	}
	var prompt string
	for _, m := range h.chat.reqs[0].Messages {
		prompt += m.Content + "\n"
	}
	for _, want := range []string{"c1: Install security updates", "c2: Restart the service"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks candidate line %q", want)
		}
	}
	for _, banned := range []string{"package.install_security", "service.restart", "h1"} {
		if strings.Contains(prompt, banned) {
			t.Errorf("prompt carries %q: action and host IDs stay out of the prompt", banned)
		}
	}
}
