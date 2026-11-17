// SPDX-License-Identifier: AGPL-3.0-or-later

package fimsshd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
)

// TestIncludeGlobCostIsBudgeted matches a record path against an Include glob
// with the adversarial shape of the review finding: "*" followed by 2,000 "a"
// and a "b", against a 4,000-byte component. Without a budget the matcher
// does about 8 × 10^6 steps per component. With one, the call stops at the
// fixed budget and reports the indeterminate answer, SSHFile (fail closed).
func TestIncludeGlobCostIsBudgeted(t *testing.T) {
	glob := "*" + strings.Repeat("a", 2000) + "b"
	var b strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "Include /etc/ssh/%s%d\n", glob, i)
	}
	s := setFor(t, b.String())
	name := strings.Repeat("a", 4000)
	sc := &scratch{}
	if got := s.matchWith([]byte("/etc/ssh/"+name), sc); got != fimbaseline.SSHFile {
		t.Fatalf("hostile glob: got %v, want SSHFile (indeterminate, fail closed)", got)
	}
	if !sc.over {
		t.Fatalf("hostile glob finished without exhausting the budget (spent %d)", sc.spent)
	}
	if sc.spent > matchBudget {
		t.Fatalf("spent %d steps, above the budget %d", sc.spent, matchBudget)
	}
}

// TestUserLiteralCostIsBudgeted covers the second finding: a 2,000-byte literal
// after a %u run, checked at every live position of a 4,000-byte component.
// The matcher must stop at the budget and answer SSHFile.
func TestUserLiteralCostIsBudgeted(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxUserValues; i++ {
		fmt.Fprintf(&b, "AuthorizedKeysFile /srv/%%u%s\n", strings.Repeat("a", 2000))
	}
	s := setFor(t, b.String())
	name := strings.Repeat("a", 4000)
	sc := &scratch{}
	if got := s.matchWith([]byte("/srv/"+name), sc); got != fimbaseline.SSHFile {
		t.Fatalf("hostile user literal: got %v, want SSHFile", got)
	}
	if !sc.over {
		t.Fatalf("hostile user literal finished without exhausting the budget (spent %d)", sc.spent)
	}
	if sc.spent > matchBudget {
		t.Fatalf("spent %d steps, above the budget %d", sc.spent, matchBudget)
	}
}

// TestBudgetDoesNotChangeOrdinaryAnswers checks that a realistic set with many
// Include globs stays within the budget and keeps its exact answers: the
// budget may only turn an answer into the fail-closed one.
func TestBudgetDoesNotChangeOrdinaryAnswers(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "Include /etc/ssh/conf.d%d/*.conf\n", i)
	}
	b.WriteString("Include /etc/ssh/sshd_config.d/*.conf\n")
	s := setFor(t, b.String())
	tests := []struct {
		path string
		want fimbaseline.SSHMatch
	}{
		{"/etc/ssh/conf.d7/x.conf", fimbaseline.SSHFile},
		{"/etc/ssh/conf.d7/x.txt", fimbaseline.SSHPosition},
		{"/etc/ssh/sshd_config.d/a.conf", fimbaseline.SSHFile},
		{"/etc/motd", fimbaseline.SSHPosition},
	}
	for _, tc := range tests {
		sc := &scratch{}
		if got := s.matchWith([]byte(tc.path), sc); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.path, got, tc.want)
		}
		if sc.over {
			t.Errorf("Match(%q) exhausted the budget (spent %d)", tc.path, sc.spent)
		}
	}
}
