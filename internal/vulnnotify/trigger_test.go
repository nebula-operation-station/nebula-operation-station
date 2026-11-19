// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// triggerCount is a trigger callback that counts its calls. It reports that
// it ran, unless refuse is set (a throttle, agent-off or failed settings read).
type triggerCount struct {
	n      int
	refuse bool
}

func (c *triggerCount) touch() bool {
	c.n++
	return !c.refuse
}

// TestTriggerDeferredWhenItDoesNotRun: a trigger whose callback reports it did
// not run keeps the episode pending, and the next Flush calls it again. Once it
// ran, Flush does not call it again.
func TestTriggerDeferredWhenItDoesNotRun(t *testing.T) {
	ctx := context.Background()
	n, _, c := newTriggerTest(t)
	c.refuse = true
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, false)})
	if c.n != 1 {
		t.Fatalf("trigger called %d times, want 1", c.n)
	}
	c.refuse = false
	n.Flush(ctx)
	if c.n != 2 {
		t.Fatalf("Flush retried the trigger %d times in total, want 2", c.n)
	}
	n.Flush(ctx)
	if c.n != 2 {
		t.Fatalf("trigger called again after it ran (%d), want no retry", c.n)
	}
}

// TestTriggerDeferralKeepsEpisodeAcrossTickFindingsAndRead: the episode of a
// finding that entered high while the trigger was refused is not lost, also
// when the high read (TriggerFindings) runs on a later tick.
func TestTriggerDeferralKeepsEpisodeAcrossTickFindingsAndRead(t *testing.T) {
	ctx := context.Background()
	n, _, c := newTriggerTest(t)
	c.refuse = true
	f := finding(2, 1, vulnstore.TierCritical, false)
	n.TriggerFindings([]vulnstore.Finding{f})
	c.refuse = false
	n.TriggerFindings([]vulnstore.Finding{f}) // same episode: no new due, but pending runs
	if c.n != 2 {
		t.Fatalf("trigger called %d times, want 2 (refused, then the deferred call)", c.n)
	}
	n.Flush(ctx)
	if c.n != 2 {
		t.Fatalf("trigger called %d times after the episode was delivered, want 2", c.n)
	}
}

// TestTriggerMarksDoNotEvictVulnMarks: the trigger's episode marks have their
// own bound, so they never push out a vuln.* de-duplication mark.
func TestTriggerMarksDoNotEvictVulnMarks(t *testing.T) {
	n, _, _ := newTest(t)
	fe := findingEvent{key: finding(1, 1, vulnstore.TierHigh, true).Key, kind: KindKEVNew}
	n.markNotified(fe, 1)
	for i := 0; i < MaxTrackedTriggers+5; i++ {
		var k vulnfinding.Key
		k[0], k[1], k[2] = byte(i), byte(i>>8), byte(i>>16)
		n.markTriggered(findingEvent{key: k, kind: kindTriggerHigh}, 1)
	}
	if _, ok := n.notified[fe]; !ok {
		t.Fatal("vuln.kev_new mark evicted by trigger marks")
	}
	if len(n.triggered) > MaxTrackedTriggers {
		t.Fatalf("trigger marks %d exceed the bound %d", len(n.triggered), MaxTrackedTriggers)
	}
}

func newTriggerTest(t *testing.T) (*Notifier, *sink, *triggerCount) {
	t.Helper()
	n, s, _ := newTest(t)
	c := &triggerCount{}
	n.SetTrigger(c.touch)
	return n, s, c
}

// TestTriggerOnNewHighFinding: a finding that newly enters tier high touches
// the trigger; the vulnerability messages are unchanged (a high finding is no
// vuln.* message).
func TestTriggerOnNewHighFinding(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTriggerTest(t)
	if got := n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, false)}); got != 0 {
		t.Fatalf("high finding sent %d messages, want 0", got)
	}
	if c.n != 1 {
		t.Fatalf("trigger touched %d times, want 1", c.n)
	}
	if len(s.es) != 0 {
		t.Fatalf("messages %v, want none", s.kinds())
	}
}

// TestTriggerFindingsHighReadTouchesWithoutMessages: the high-tier read
// (TriggerFindings) touches the trigger for a new high finding and sends no
// vuln.* message; a second call for the same episode does not touch again.
func TestTriggerFindingsHighReadTouchesWithoutMessages(t *testing.T) {
	n, s, c := newTriggerTest(t)
	f := finding(1, 1, vulnstore.TierHigh, false)
	n.TriggerFindings([]vulnstore.Finding{f})
	n.TriggerFindings([]vulnstore.Finding{f})
	if c.n != 1 {
		t.Fatalf("trigger touched %d times, want 1", c.n)
	}
	if len(s.es) != 0 {
		t.Fatalf("messages %v, want none", s.kinds())
	}
}

// TestTriggerFindingsIgnoresClosedAndMedium: a closed finding and a medium
// finding never touch the trigger on the high read.
func TestTriggerFindingsIgnoresClosedAndMedium(t *testing.T) {
	n, _, c := newTriggerTest(t)
	closed := finding(1, 1, vulnstore.TierHigh, false)
	closed.State = vulnstore.StateFixed
	n.TriggerFindings([]vulnstore.Finding{closed, finding(2, 1, vulnstore.TierMedium, false)})
	if c.n != 0 {
		t.Fatalf("trigger touched %d times, want 0", c.n)
	}
}

// TestTriggerNotOnMediumOrLow: tiers below high never touch the trigger.
func TestTriggerNotOnMediumOrLow(t *testing.T) {
	ctx := context.Background()
	n, _, c := newTriggerTest(t)
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierMedium, false), finding(2, 1, vulnstore.TierLow, false)})
	if c.n != 0 {
		t.Fatalf("trigger touched %d times for medium and low, want 0", c.n)
	}
}

// TestTriggerOncePerEpisode: repeated runs of the same episode touch once; a
// re-open (new episode) touches again.
func TestTriggerOncePerEpisode(t *testing.T) {
	ctx := context.Background()
	n, _, c := newTriggerTest(t)
	f := finding(1, 1, vulnstore.TierHigh, false)
	n.Findings(ctx, []vulnstore.Finding{f})
	n.Findings(ctx, []vulnstore.Finding{f, f})
	if c.n != 1 {
		t.Fatalf("same episode: touched %d times, want 1", c.n)
	}
	closed := f
	closed.State = vulnstore.StateFixed
	n.Findings(ctx, []vulnstore.Finding{closed})
	n.Findings(ctx, []vulnstore.Finding{finding(1, 2, vulnstore.TierHigh, false)})
	if c.n != 2 {
		t.Fatalf("new episode: touched %d times, want 2", c.n)
	}
}

// TestTriggerOnEscalationToCritical: a finding escalating from high to
// critical inside its episode touches the trigger again.
func TestTriggerOnEscalationToCritical(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTriggerTest(t)
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, false)})
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierCritical, false)})
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, false)})
	if c.n != 2 {
		t.Fatalf("touched %d times, want 2 (high, then critical; falling back does not touch)", c.n)
	}
	if want := []string{KindCriticalNew}; strings.Join(s.kinds(), ",") != strings.Join(want, ",") {
		t.Fatalf("messages %v, want %v", s.kinds(), want)
	}
}

// TestTriggerNotForClosedFinding: a finding that is not open never touches
// the trigger.
func TestTriggerNotForClosedFinding(t *testing.T) {
	ctx := context.Background()
	n, _, c := newTriggerTest(t)
	f := finding(1, 1, vulnstore.TierCritical, false)
	f.State = vulnstore.StateAcceptedRisk
	n.Findings(ctx, []vulnstore.Finding{f})
	if c.n != 0 {
		t.Fatalf("closed finding touched the trigger %d times", c.n)
	}
}

// TestTriggerWithoutCallbackChangesNothing: without SetTrigger the messages
// are exactly those of the rules of ADR 0011 D9.
func TestTriggerWithoutCallbackChangesNothing(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
	if want := []string{KindKEVNew}; strings.Join(s.kinds(), ",") != strings.Join(want, ",") {
		t.Fatalf("messages %v, want %v", s.kinds(), want)
	}
}
