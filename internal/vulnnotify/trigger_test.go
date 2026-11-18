// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// triggerCount is a trigger callback that counts its calls.
type triggerCount struct{ n int }

func (c *triggerCount) touch() { c.n++ }

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
