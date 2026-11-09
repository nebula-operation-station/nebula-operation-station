// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// TestAlertSurvivesDeliveryOutage: an alert no provider accepts is not
// counted as sent, sets no de-duplication state, is retried and arrives
// exactly once after the outage.
func TestAlertSurvivesDeliveryOutage(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		raise func(ctx context.Context, n *Notifier) int
	}{
		{"kev", KindKEVNew, func(ctx context.Context, n *Notifier) int {
			return n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
		}},
		{"critical", KindCriticalNew, func(ctx context.Context, n *Notifier) int {
			return n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierCritical, false)})
		}},
		{"feed stale", KindFeedStale, func(ctx context.Context, n *Notifier) int {
			return n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true, Since: t0}})
		}},
		{"feed regressed", KindFeedRegressed, func(ctx context.Context, n *Notifier) int {
			return n.Run(ctx, vulnstore.Run{ID: "r", Sources: []vulnstore.SourceVerdict{{ID: "osv", Status: vulnstore.SourceRegressed}}})
		}},
		{"hermes stale", KindHermesStale, func(ctx context.Context, n *Notifier) int {
			return n.Hermes(ctx, t0.Add(-72*time.Hour))
		}},
		{"mark reset", KindFeedMarkReset, func(ctx context.Context, n *Notifier) int {
			return n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv", Admin: "alice"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			n, s, _ := newTest(t)
			s.setDown(true)
			if got := tc.raise(ctx, n); got != 0 {
				t.Fatalf("outage: counted %d as sent", got)
			}
			if s.attempts == 0 {
				t.Fatal("no delivery attempted")
			}
			if len(n.notified) != 0 || len(n.feedStale) != 0 || len(n.feedRegr) != 0 || !n.hermesMark.IsZero() {
				t.Fatalf("dedup state set before delivery: %d/%d/%d/%v", len(n.notified), len(n.feedStale), len(n.feedRegr), n.hermesMark)
			}
			if n.Pending() != 1 {
				t.Fatalf("pending %d, want 1", n.Pending())
			}
			// Still down: Flush retries, nothing is counted.
			if got := n.Flush(ctx); got != 0 {
				t.Fatalf("flush during outage counted %d", got)
			}
			if tc.kind != KindFeedMarkReset {
				// The same input during the outage does not queue a second copy.
				tc.raise(ctx, n)
				if n.Pending() != 1 {
					t.Fatalf("pending %d after repeat, want 1", n.Pending())
				}
			}
			s.setDown(false)
			if got := n.Flush(ctx); got != 1 {
				t.Fatalf("flush after outage sent %d, want 1", got)
			}
			if n.Pending() != 0 || n.Flush(ctx) != 0 {
				t.Fatal("alert still pending after delivery")
			}
			if tc.kind != KindFeedMarkReset {
				if got := tc.raise(ctx, n); got != 0 {
					t.Fatalf("delivered alert sent again: %d", got)
				}
			}
			if len(s.es) != 1 || s.es[0].Kind != tc.kind {
				t.Fatalf("delivered %v, want one %s", s.kinds(), tc.kind)
			}
		})
	}
}

// TestPendingAlertRetriedByNextEvent: a queued alert also goes out with the
// next event, not only on Flush.
func TestPendingAlertRetriedByNextEvent(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	s.setDown(true)
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
	s.setDown(false)
	if got := n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}}); got != 2 {
		t.Fatalf("sent %d, want 2", got)
	}
	if want := KindKEVNew + "," + KindFeedStale; strings.Join(s.kinds(), ",") != want {
		t.Fatalf("kinds %v, want %s", s.kinds(), want)
	}
}

// TestEndedEpisodeDropsPendingAlert: a feed that recovers during the outage
// does not get a stale alert later, and its next stale episode notifies.
func TestEndedEpisodeDropsPendingAlert(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	s.setDown(true)
	n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}})
	n.Run(ctx, vulnstore.Run{ID: "r", Sources: []vulnstore.SourceVerdict{{ID: "kev", Status: vulnstore.SourceRegressed}}})
	n.Hermes(ctx, t0.Add(-72*time.Hour))
	// All three conditions end while the providers are down.
	n.Feeds(ctx, []FeedStatus{{SourceID: "osv"}})
	n.Run(ctx, vulnstore.Run{ID: "a", Sources: []vulnstore.SourceVerdict{{ID: "kev", Status: vulnstore.SourceAccepted}}})
	n.Hermes(ctx, t0)
	if n.Pending() != 0 {
		t.Fatalf("pending %d, want 0", n.Pending())
	}
	s.setDown(false)
	if n.Flush(ctx) != 0 || len(s.es) != 0 {
		t.Fatalf("obsolete alerts sent: %v", s.kinds())
	}
	if got := n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}}); got != 1 {
		t.Fatalf("new stale episode sent %d, want 1", got)
	}
}

// TestReopenDuringOutageReplacesPendingAlert: a newer episode replaces the
// queued alert of the older one; a late older episode does not re-queue.
func TestReopenDuringOutageReplacesPendingAlert(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	s.setDown(true)
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
	n.Findings(ctx, []vulnstore.Finding{finding(1, 2, vulnstore.TierHigh, true)})
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
	if n.Pending() != 1 {
		t.Fatalf("pending %d, want 1", n.Pending())
	}
	s.setDown(false)
	if n.Flush(ctx) != 1 {
		t.Fatal("pending alert not delivered")
	}
	k := findingEvent{key: finding(1, 0, 0, false).Key, kind: KindKEVNew}
	if n.notified[k] != 2 {
		t.Fatalf("notified episode %d, want 2", n.notified[k])
	}
}

// TestDigestRetriedWhenSinkFails: a digest no provider accepts keeps its
// counts and is sent once, merged with later held messages, after the
// outage.
func TestDigestRetriedWhenSinkFails(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	for i := 0; i < MaxPerHour+3; i++ {
		n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"})
	}
	c.Add(RateWindow)
	s.setDown(true)
	if got := n.Flush(ctx); got != 0 {
		t.Fatalf("failed digest counted %d", got)
	}
	if got := n.Flush(ctx); got != 0 {
		t.Fatalf("second failed digest counted %d", got)
	}
	s.setDown(false)
	if got := n.Flush(ctx); got != 1 {
		t.Fatalf("digest after outage sent %d, want 1", got)
	}
	d := s.es[len(s.es)-1]
	if d.Kind != KindDigest || !strings.Contains(d.Reason, KindFeedMarkReset+": 3") {
		t.Fatalf("digest %+v", d)
	}
	if n.Flush(ctx) != 0 {
		t.Fatal("digest sent twice")
	}
}

// TestPendingQueueIsBounded: during a long outage at most MaxPending alerts
// wait; the dropped ones are reported as undelivered in the digest and the
// de-duplication state stays unset for them.
func TestPendingQueueIsBounded(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	s.setDown(true)
	total := 0
	for h := 0; total < MaxPending+15; h++ {
		var fs []vulnstore.Finding
		for i := 0; i < MaxPerHour; i++ {
			f := finding(byte(i), 1, vulnstore.TierHigh, true)
			f.Key[1], f.Key[2] = byte(h), 1
			fs = append(fs, f)
			total++
		}
		n.Findings(ctx, fs)
		if n.Pending() > MaxPending {
			t.Fatalf("pending %d exceeds %d", n.Pending(), MaxPending)
		}
		c.Add(RateWindow)
	}
	if n.Pending() != MaxPending {
		t.Fatalf("pending %d, want %d", n.Pending(), MaxPending)
	}
	if len(n.notified) != 0 {
		t.Fatalf("dedup state for undelivered alerts: %d", len(n.notified))
	}
	s.setDown(false)
	c.Add(RateWindow)
	if got := n.Flush(ctx); got != MaxPending+1 {
		t.Fatalf("sent %d, want %d alerts and one digest", got, MaxPending+1)
	}
	var digest string
	for _, e := range s.es {
		if e.Kind == KindDigest {
			digest = e.Reason
		}
	}
	if !strings.Contains(digest, KindKEVNew+" undelivered: 20") {
		t.Fatalf("digest %q", digest)
	}
}

// TestImageSubjectKeepsFullDigest: the readable part is shortened, the
// sha256 digest stays complete in the message.
func TestImageSubjectKeepsFullDigest(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	digest := "sha256:" + strings.Repeat("ab", 32)
	f := finding(1, 1, vulnstore.TierCritical, false)
	f.Subject = vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: strings.Repeat("x", 63), ImageDigest: digest}
	n.Findings(ctx, []vulnstore.Finding{f})
	if len(s.es) != 1 {
		t.Fatalf("sent %d", len(s.es))
	}
	e := s.es[0]
	if !strings.Contains(e.Reason, "/"+digest+";") {
		t.Fatalf("digest cut in reason %q", e.Reason)
	}
	if len([]rune(e.Reason)) > 300 || len([]rune(e.Host)) > 64 {
		t.Fatalf("fields exceed notify limits: reason %d, host %d runes", len([]rune(e.Reason)), len([]rune(e.Host)))
	}
}
