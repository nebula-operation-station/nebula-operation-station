// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// sink records delivered events; while down every provider rejects.
type sink struct {
	mu       sync.Mutex
	es       []notify.Event
	down     bool
	attempts int
}

func (s *sink) Notify(_ context.Context, e notify.Event) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.down {
		return 0
	}
	s.es = append(s.es, e)
	return 1
}

func (s *sink) setDown(down bool) {
	s.mu.Lock()
	s.down = down
	s.mu.Unlock()
}

func (s *sink) kinds() []string {
	var out []string
	for _, e := range s.es {
		out = append(out, e.Kind)
	}
	return out
}

func newTest(t *testing.T) (*Notifier, *sink, *clock) {
	t.Helper()
	s, c := &sink{}, &clock{t: t0}
	n, err := New(Config{Sink: s, Sources: []string{"osv", "kev", "debian-tracker"}, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return n, s, c
}

func finding(id byte, episode int64, tier vulnstore.Tier, kev bool) vulnstore.Finding {
	f := vulnstore.Finding{State: vulnstore.StateOpen, Episode: episode, EpisodePeakTier: tier,
		Subject: vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "web1"}}
	f.Key[0] = id
	f.Record.Vuln.ID = "CVE-2026-0001"
	f.Record.Assessment.Text = "SECRET-LLM-TEXT"
	if kev {
		f.EpisodeKEVDate = "2026-11-01"
		f.Record.Scores.KEV = &vulnfinding.KEV{DateAdded: "2026-11-01"}
	}
	return f
}

func TestNewRequiresSink(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New without sink succeeded")
	}
}

func TestFindingEventsDedupePerKeyAndType(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)

	// New critical finding without KEV: critical_new only.
	f := finding(1, 1, vulnstore.TierCritical, false)
	if got := n.Findings(ctx, []vulnstore.Finding{f}); got != 1 {
		t.Fatalf("first: sent %d, want 1", got)
	}
	// Same episode again: nothing.
	if got := n.Findings(ctx, []vulnstore.Finding{f, f}); got != 0 {
		t.Fatalf("repeat: sent %d, want 0", got)
	}
	// It becomes KEV-listed: kev_new although critical_new was sent.
	f = finding(1, 1, vulnstore.TierCritical, true)
	if got := n.Findings(ctx, []vulnstore.Finding{f}); got != 1 {
		t.Fatalf("kev: sent %d, want 1", got)
	}
	if want := []string{KindCriticalNew, KindKEVNew}; strings.Join(s.kinds(), ",") != strings.Join(want, ",") {
		t.Fatalf("kinds %v, want %v", s.kinds(), want)
	}
}

func TestKEVFindingBecomingCriticalNotifiesAgain(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, true)})
	n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierCritical, true)})
	if want := []string{KindKEVNew, KindCriticalNew}; strings.Join(s.kinds(), ",") != strings.Join(want, ",") {
		t.Fatalf("kinds %v, want %v", s.kinds(), want)
	}
}

func TestReopenStartsNewEpisode(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	f := finding(1, 1, vulnstore.TierHigh, true)
	n.Findings(ctx, []vulnstore.Finding{f})
	closed := f
	closed.State = vulnstore.StateFixed
	if got := n.Findings(ctx, []vulnstore.Finding{closed}); got != 0 {
		t.Fatalf("closed finding sent %d", got)
	}
	reopened := finding(1, 2, vulnstore.TierHigh, true)
	if got := n.Findings(ctx, []vulnstore.Finding{reopened}); got != 1 {
		t.Fatalf("reopened: sent %d, want 1", got)
	}
	// An older episode seen late does not notify.
	if got := n.Findings(ctx, []vulnstore.Finding{f}); got != 0 {
		t.Fatalf("older episode: sent %d, want 0", got)
	}
	if len(s.es) != 2 {
		t.Fatalf("messages %d, want 2", len(s.es))
	}
}

func TestFlappingInsideEpisodeDoesNotRenotify(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	for i := 0; i < 5; i++ {
		// Tier falls and rises, KEV flag dropped and re-added: one episode.
		n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierCritical, i%2 == 0)})
		n.Findings(ctx, []vulnstore.Finding{finding(1, 1, vulnstore.TierHigh, false)})
	}
	if want := []string{KindKEVNew, KindCriticalNew}; strings.Join(s.kinds(), ",") != strings.Join(want, ",") {
		t.Fatalf("kinds %v, want %v", s.kinds(), want)
	}
}

func TestNonOpenFindingsDoNotNotify(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	for _, st := range []vulnstore.State{vulnstore.StateFixed, vulnstore.StateAcceptedRisk, vulnstore.StateFalsePositive} {
		f := finding(1, 1, vulnstore.TierCritical, true)
		f.State = st
		n.Findings(ctx, []vulnstore.Finding{f})
	}
	n.Findings(ctx, []vulnstore.Finding{finding(2, 1, vulnstore.TierHigh, false)})
	if len(s.es) != 0 {
		t.Fatalf("sent %v", s.kinds())
	}
}

func TestFeedStaleOncePerSourceAndEpisode(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	stale := []FeedStatus{{SourceID: "osv", Stale: true, Since: t0}, {SourceID: "kev", Stale: true}}
	if got := n.Feeds(ctx, stale); got != 2 {
		t.Fatalf("first: %d, want 2", got)
	}
	if got := n.Feeds(ctx, stale); got != 0 {
		t.Fatalf("same episode: %d, want 0", got)
	}
	// osv becomes fresh, then stale again: a new episode.
	n.Feeds(ctx, []FeedStatus{{SourceID: "osv"}})
	if got := n.Feeds(ctx, stale); got != 1 {
		t.Fatalf("new episode: %d, want 1", got)
	}
	for _, e := range s.es {
		if e.Kind != KindFeedStale {
			t.Fatalf("kind %s", e.Kind)
		}
	}
	if !strings.Contains(s.es[1].Reason, "kev") || !strings.Contains(s.es[1].Reason, "undated") {
		t.Fatalf("undated reason %q", s.es[1].Reason)
	}
}

func TestUnknownSourcesRaiseNothing(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	var st []FeedStatus
	r := vulnstore.Run{ID: "run1"}
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("unknown-%d", i)
		st = append(st, FeedStatus{SourceID: id, Stale: true})
		r.Sources = append(r.Sources, vulnstore.SourceVerdict{ID: id, Status: vulnstore.SourceRegressed})
		r.UnknownSources = append(r.UnknownSources, id)
	}
	r.UnknownCount = 50
	n.Feeds(ctx, st)
	n.Run(ctx, r)
	if len(s.es) != 0 || len(n.feedStale) != 0 || len(n.feedRegr) != 0 {
		t.Fatalf("sent %v, state %d/%d", s.kinds(), len(n.feedStale), len(n.feedRegr))
	}
}

func TestFeedRegressedOncePerAlternation(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	regr := vulnstore.Run{ID: "r", Sources: []vulnstore.SourceVerdict{{ID: "osv", Status: vulnstore.SourceRegressed}}}
	future := vulnstore.Run{ID: "f", Sources: []vulnstore.SourceVerdict{{ID: "osv", Status: vulnstore.SourceInvalid}}}
	ok := vulnstore.Run{ID: "a", Sources: []vulnstore.SourceVerdict{{ID: "osv", Status: vulnstore.SourceAccepted}}}
	undated := vulnstore.Run{ID: "u", Sources: []vulnstore.SourceVerdict{{ID: "osv", Status: vulnstore.SourceUndated, Stale: true}}}

	n.Run(ctx, regr)
	n.Run(ctx, regr)
	n.Run(ctx, future) // still the same episode
	n.Run(ctx, undated)
	n.Run(ctx, regr) // undated did not end the episode
	if len(s.es) != 1 {
		t.Fatalf("one episode sent %d", len(s.es))
	}
	n.Run(ctx, ok)
	n.Run(ctx, future)
	n.Run(ctx, ok)
	n.Run(ctx, regr)
	if len(s.es) != 3 {
		t.Fatalf("after two alternations sent %d, want 3", len(s.es))
	}
	if !strings.Contains(s.es[1].Reason, "dated in the future") || !strings.Contains(s.es[0].Reason, "high-water mark") {
		t.Fatalf("reasons %q / %q", s.es[0].Reason, s.es[1].Reason)
	}
}

func TestMarkResetEveryResetWithoutReason(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	m := vulnstore.MarkReset{SourceID: "osv", Admin: "alice", Reason: "SECRET-ADMIN-REASON", OldDate: t0, NewDate: t0.Add(-time.Hour)}
	n.MarkReset(ctx, m)
	n.MarkReset(ctx, m)
	if len(s.es) != 2 {
		t.Fatalf("sent %d, want 2", len(s.es))
	}
	if strings.Contains(s.es[0].Reason, "SECRET") {
		t.Fatalf("reason leaked: %q", s.es[0].Reason)
	}
}

func TestHermesStaleOncePerEpisode(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	last := t0.Add(-47 * time.Hour)
	if n.Hermes(ctx, last) != 0 {
		t.Fatal("fresh Hermes notified")
	}
	if n.Hermes(ctx, time.Time{}) != 0 {
		t.Fatal("never-run Hermes notified")
	}
	c.Add(2 * time.Hour)
	if n.Hermes(ctx, last) != 1 {
		t.Fatal("stale Hermes not notified")
	}
	c.Add(24 * time.Hour)
	if n.Hermes(ctx, last) != 0 {
		t.Fatal("same offline episode notified twice")
	}
	// A run completes, then Hermes goes offline again.
	newer := c.Now()
	n.Hermes(ctx, newer)
	c.Add(49 * time.Hour)
	if n.Hermes(ctx, newer) != 1 {
		t.Fatal("new offline episode not notified")
	}
	if len(s.es) != 2 || s.es[0].Kind != KindHermesStale {
		t.Fatalf("sent %v", s.kinds())
	}
}

func TestRateLimitAndDigest(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	var fs []vulnstore.Finding
	for i := 0; i < 25; i++ {
		fs = append(fs, finding(byte(i), 1, vulnstore.TierHigh, true))
	}
	if got := n.Findings(ctx, fs); got != MaxPerHour {
		t.Fatalf("sent %d, want %d", got, MaxPerHour)
	}
	// Held messages stay held, even across more events, until the hour.
	c.Add(30 * time.Minute)
	n.Feeds(ctx, []FeedStatus{{SourceID: "osv", Stale: true}})
	if n.Flush(ctx) != 0 || len(s.es) != MaxPerHour {
		t.Fatalf("early digest: %d messages", len(s.es))
	}
	c.Add(30 * time.Minute)
	if got := n.Flush(ctx); got != 1 {
		t.Fatalf("flush sent %d, want 1 digest", got)
	}
	d := s.es[len(s.es)-1]
	if d.Kind != KindDigest || !strings.Contains(d.Reason, "16 vulnerability") ||
		!strings.Contains(d.Reason, KindKEVNew+": 15") || !strings.Contains(d.Reason, KindFeedStale+": 1") {
		t.Fatalf("digest %+v", d)
	}
	// Digest is once: nothing pending now.
	if n.Flush(ctx) != 0 {
		t.Fatal("second digest")
	}
	// Held findings were counted, they do not fire later.
	if n.Findings(ctx, fs) != 0 {
		t.Fatal("held findings re-notified")
	}
	// The window slid: new events go out directly again.
	if n.Findings(ctx, []vulnstore.Finding{finding(200, 1, vulnstore.TierCritical, false)}) != 1 {
		t.Fatal("event after window not sent")
	}
}

func TestDigestFlushedByNextEvent(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	for i := 0; i < MaxPerHour+1; i++ {
		n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"})
	}
	c.Add(RateWindow)
	n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv"})
	got := s.kinds()
	if len(got) != MaxPerHour+2 || got[MaxPerHour] != KindDigest || got[MaxPerHour+1] != KindFeedMarkReset {
		t.Fatalf("kinds %v", got)
	}
}

func TestMessagesArePlainStructuredText(t *testing.T) {
	ctx := context.Background()
	n, s, _ := newTest(t)
	rlo, lri := string(rune(0x202e)), string(rune(0x2066))
	hostile := "CVE-1\n<b>x</b>" + rlo + "*[link](http://evil)*\x00\xff" + strings.Repeat("A", 500)
	f := finding(1, 1, vulnstore.TierCritical, true)
	f.Record.Vuln.ID = hostile
	f.Subject.ID = "web1\r\nInjected: header"
	n.Findings(ctx, []vulnstore.Finding{f})
	n.MarkReset(ctx, vulnstore.MarkReset{SourceID: "osv", Admin: "eve\n" + lri + "evil"})
	if len(s.es) != 3 {
		t.Fatalf("sent %d", len(s.es))
	}
	for _, e := range s.es {
		for _, field := range []string{e.Kind, e.Host, e.State, e.Reason} {
			for _, r := range field {
				if !unicode.IsPrint(r) || unicode.Is(unicode.Bidi_Control, r) {
					t.Fatalf("non-printable %U in %q", r, field)
				}
			}
			if strings.Contains(field, "SECRET-LLM-TEXT") {
				t.Fatalf("assessment text in message: %q", field)
			}
		}
		if len([]rune(e.Reason)) > 4*maxText+100 {
			t.Fatalf("reason not bounded: %d runes", len([]rune(e.Reason)))
		}
	}
	// The text stays literal: markup is not interpreted, only kept as text.
	if !strings.Contains(s.es[0].Reason, "<b>x</b>") {
		t.Fatalf("reason %q", s.es[0].Reason)
	}
}
