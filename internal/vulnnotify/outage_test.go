// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
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

// TestPendingAlertRetriedOnlyByFlush: an event call sends only its own new
// alerts; queued alerts wait for Flush, so a caller never works off the
// retry queue.
func TestPendingAlertRetriedOnlyByFlush(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	s.setDown(true)
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
	s.setDown(false)
	if got := n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}}); got != 1 {
		t.Fatalf("sent %d, want 1", got)
	}
	if n.Pending() != 1 {
		t.Fatalf("pending %d, want 1", n.Pending())
	}
	if got := n.Flush(ctx); got != 1 {
		t.Fatalf("flush sent %d, want 1", got)
	}
	if want := KindFeedStale + "," + KindKEVNew; strings.Join(s.kinds(), ",") != want {
		t.Fatalf("kinds %v, want %s", s.kinds(), want)
	}
}

// hangSink blocks every delivery until the caller's context ends, like a
// provider that accepts the connection and never answers.
type hangSink struct {
	mu       sync.Mutex
	attempts int
}

func (h *hangSink) Notify(ctx context.Context, _ notify.Event) int {
	h.mu.Lock()
	h.attempts++
	h.mu.Unlock()
	<-ctx.Done()
	return 0
}

func (h *hangSink) count() int { h.mu.Lock(); defer h.mu.Unlock(); return h.attempts }

// TestHangingSinkDoesNotBlockCaller: with a provider that never answers,
// every caller returns once its context ends; messages after the first are
// not attempted with a dead context but queued, and event calls never
// retry the queue.
func TestHangingSinkDoesNotBlockCaller(t *testing.T) {
	h := &hangSink{}
	c := &clock{t: t0}
	n, err := New(Config{Sink: h, Sources: []string{"osv", "kev"}, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	const deadline = 50 * time.Millisecond
	const limit = 2 * time.Second
	call := func(name string, f func(ctx context.Context) int) {
		t.Helper()
		before := h.count()
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		start := time.Now()
		if got := f(ctx); got != 0 {
			t.Fatalf("%s: counted %d as sent", name, got)
		}
		if el := time.Since(start); el > limit {
			t.Fatalf("%s: blocked %v with a %v context", name, el, deadline)
		}
		if a := h.count() - before; a > 1 {
			t.Fatalf("%s: %d delivery attempts after the context ended", name, a-1)
		}
	}
	var fs []vulnstore.Finding
	for i := 0; i < 5; i++ {
		fs = append(fs, finding(byte(i), 1, vulnstore.TierCritical, true))
	}
	call("findings", func(ctx context.Context) int { return n.Findings(ctx, fs) })
	if n.Pending() != 10 {
		t.Fatalf("pending %d, want 10", n.Pending())
	}
	call("feeds", func(ctx context.Context) int {
		return n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}})
	})
	call("run", func(ctx context.Context) int {
		return n.Run(ctx, vulnstore.Run{ID: "r", Sources: []vulnstore.SourceVerdict{{ID: "kev", Status: vulnstore.SourceRegressed}}})
	})
	call("hermes", func(ctx context.Context) int { return n.Hermes(ctx, t0.Add(-72*time.Hour)) })
	call("mark reset", func(ctx context.Context) int { return n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"}) })
	call("flush", n.Flush)
	if n.Pending() != 14 {
		t.Fatalf("pending %d, want 14", n.Pending())
	}
}

// TestFailedAttemptKeepsRateBudget: messages no provider accepted do not
// use up the hourly limit, so alerts raised after the outage still go out.
func TestFailedAttemptKeepsRateBudget(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	s.setDown(true)
	for i := 0; i < MaxPerHour+5; i++ {
		n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"})
	}
	if n.Pending() != MaxPerHour+5 {
		t.Fatalf("pending %d, want %d", n.Pending(), MaxPerHour+5)
	}
	s.setDown(false)
	var fs []vulnstore.Finding
	for i := 0; i < MaxPerHour; i++ {
		fs = append(fs, finding(byte(i), 1, vulnstore.TierHigh, true))
	}
	if got := n.Findings(ctx, fs); got != MaxPerHour {
		t.Fatalf("sent %d after outage, want %d", got, MaxPerHour)
	}
}

// TestRetriesObeyRateLimit: after an outage queued alerts are sent at most
// MaxPerHour per hour; the rest are folded into the digest, never sent as
// a burst.
func TestRetriesObeyRateLimit(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	s.setDown(true)
	var fs []vulnstore.Finding
	for i := 0; i < MaxPerHour+7; i++ {
		fs = append(fs, finding(byte(i), 1, vulnstore.TierHigh, true))
	}
	n.Findings(ctx, fs)
	s.setDown(false)
	// Three alerts delivered in the same hour leave room for seven retries.
	n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"})
	n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"})
	n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"})
	if got := n.Flush(ctx); got != MaxPerHour-3 {
		t.Fatalf("flush sent %d, want %d", got, MaxPerHour-3)
	}
	if n.Pending() != 0 {
		t.Fatalf("pending %d, want 0 (excess folded into the digest)", n.Pending())
	}
	if got := n.Flush(ctx); got != 0 {
		t.Fatalf("second flush in the same hour sent %d", got)
	}
	if len(s.es) != MaxPerHour {
		t.Fatalf("delivered %d in one hour, want %d", len(s.es), MaxPerHour)
	}
	c.Add(RateWindow)
	if got := n.Flush(ctx); got != 1 {
		t.Fatalf("digest flush sent %d, want 1", got)
	}
	d := s.es[len(s.es)-1]
	if d.Kind != KindDigest || !strings.Contains(d.Reason, KindKEVNew+": 10") {
		t.Fatalf("digest %+v", d)
	}
}

// hookSink delivers every event and runs hook (outside its lock) during
// the first delivery of an event of kind.
type hookSink struct {
	mu   sync.Mutex
	es   []notify.Event
	kind string
	hook func()
}

func (h *hookSink) Notify(_ context.Context, e notify.Event) int {
	h.mu.Lock()
	hook := h.hook
	if e.Kind == h.kind {
		h.hook = nil
	} else {
		hook = nil
	}
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	h.mu.Lock()
	h.es = append(h.es, e)
	h.mu.Unlock()
	return 1
}

// TestStaleDeliverySetsNoState: an alert whose episode ends or is
// superseded while its delivery runs sets no de-duplication state.
func TestStaleDeliverySetsNoState(t *testing.T) {
	ctx := context.Background()
	t.Run("feed recovers during delivery", func(t *testing.T) {
		h := &hookSink{kind: KindFeedStale}
		n, err := New(Config{Sink: h, Sources: []string{"osv"}, Now: func() time.Time { return t0 }})
		if err != nil {
			t.Fatal(err)
		}
		h.hook = func() { n.Feeds(ctx, []FeedStatus{{SourceID: "osv"}}) }
		n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}})
		if n.feedStale["osv"] {
			t.Fatal("ended episode set feed stale state")
		}
		if got := n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}}); got != 1 {
			t.Fatalf("new stale episode sent %d, want 1", got)
		}
	})
	t.Run("finding re-opens during delivery", func(t *testing.T) {
		h := &hookSink{kind: KindKEVNew}
		n, err := New(Config{Sink: h, Now: func() time.Time { return t0 }})
		if err != nil {
			t.Fatal(err)
		}
		h.hook = func() { n.Findings(ctx, []vulnstore.Finding{finding(1, 2, vulnstore.TierHigh, true)}) }
		n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
		k := findingEvent{key: finding(1, 0, 0, false).Key, kind: KindKEVNew}
		if n.notified[k] != 2 {
			t.Fatalf("notified episode %d, want 2", n.notified[k])
		}
		if len(n.inflight) != 0 || n.Pending() != 0 {
			t.Fatalf("inflight %d, pending %d", len(n.inflight), n.Pending())
		}
	})
	t.Run("hermes run completes during delivery", func(t *testing.T) {
		h := &hookSink{kind: KindHermesStale}
		n, err := New(Config{Sink: h, Now: func() time.Time { return t0 }})
		if err != nil {
			t.Fatal(err)
		}
		h.hook = func() { n.Hermes(ctx, t0) }
		n.Hermes(ctx, t0.Add(-72*time.Hour))
		if !n.hermesMark.IsZero() {
			t.Fatalf("ended offline episode set mark %v", n.hermesMark)
		}
	})
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
	// The digest of the dropped alerts plus at most MaxPerHour retries; the
	// rest of the queue is folded into the next digest.
	if got := n.Flush(ctx); got != MaxPerHour+1 {
		t.Fatalf("sent %d, want %d alerts and one digest", got, MaxPerHour+1)
	}
	if n.Pending() != 0 {
		t.Fatalf("pending %d after flush, want 0", n.Pending())
	}
	if len(n.notified) != MaxPending {
		t.Fatalf("dedup state for %d alerts, want %d (sent or in the digest)", len(n.notified), MaxPending)
	}
	if !strings.Contains(s.es[0].Reason, KindKEVNew+" undelivered: 20") || s.es[0].Kind != KindDigest {
		t.Fatalf("first message %+v, want digest with undelivered count", s.es[0])
	}
	c.Add(RateWindow)
	if got := n.Flush(ctx); got != 1 {
		t.Fatalf("second digest sent %d, want 1", got)
	}
	if d := s.es[len(s.es)-1]; !strings.Contains(d.Reason, fmt.Sprintf("%s: %d", KindKEVNew, MaxPending-MaxPerHour)) {
		t.Fatalf("second digest %q", d.Reason)
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
