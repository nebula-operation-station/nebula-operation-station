// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnnotify raises the vulnerability management notifications of
// ADR 0011 D9 through the existing notification senders (internal/notify)
// and exports findings as CSV and JSON.
//
// Events: vuln.kev_new and vuln.critical_new (once per finding key, event
// type and episode), vuln.hermes_stale (once per Hermes offline episode),
// vuln.feed_stale (once per listed source and stale episode),
// vuln.feed_regressed (once per listed source and regression episode) and
// vuln.feed_mark_reset (every reset). At most MaxPerHour messages leave
// per hour; the rest are counted into one hourly digest.
//
// Every string that came from Hermes or a feed is untrusted: messages carry
// structured fields only (CVE ID, subject, tier, KEV, source ID), never the
// LLM assessment or an admin reason, and each field is reduced to bounded
// printable text before it reaches a sender. The senders send plain text
// (no Markdown, no HTML parse mode).
//
// De-duplication state is held in memory: after a restart an open
// KEV-listed or critical finding notifies once more (inside the rate
// limit). Unknown source IDs never create state, so it stays bounded by
// NOS's source list and MaxTrackedFindings.
package vulnnotify

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Event kinds (ADR 0011 D9).
const (
	KindKEVNew        = "vuln.kev_new"
	KindCriticalNew   = "vuln.critical_new"
	KindHermesStale   = "vuln.hermes_stale"
	KindFeedStale     = "vuln.feed_stale"
	KindFeedRegressed = "vuln.feed_regressed"
	KindFeedMarkReset = "vuln.feed_mark_reset"
	// KindDigest summarises the messages the hourly limit held back.
	KindDigest = "vuln.digest"
)

// Limits.
const (
	// MaxPerHour is the D9 message limit; more become one hourly digest.
	MaxPerHour = 10
	// RateWindow is the window MaxPerHour applies to and the digest period.
	RateWindow = time.Hour
	// DefaultHermesStaleAfter is the D6 Hermes offline threshold (Q5).
	DefaultHermesStaleAfter = 48 * time.Hour
	// MaxTrackedFindings bounds the per-finding de-duplication state; the
	// oldest entries are dropped first.
	MaxTrackedFindings = 100_000
	// maxText bounds one untrusted field in a message.
	maxText = 128
)

// Sink sends one notification; *notify.Notifier implements it.
type Sink interface {
	Notify(ctx context.Context, e notify.Event) int
}

// Config configures a Notifier.
type Config struct {
	// Sink receives the messages. Required.
	Sink Sink
	// Sources is NOS's fixed feed source list. Feed events for any other
	// source ID are dropped.
	Sources []string
	// HermesStaleAfter defaults to DefaultHermesStaleAfter.
	HermesStaleAfter time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

type findingEvent struct {
	key  vulnfinding.Key
	kind string
}

// Notifier decides which vulnerability events to send. It is safe for
// concurrent use; messages are sent outside its lock.
type Notifier struct {
	sink       Sink
	now        func() time.Time
	hermesMax  time.Duration
	sources    map[string]bool
	mu         sync.Mutex
	notified   map[findingEvent]int64 // episode last notified
	order      []findingEvent         // insertion order for eviction
	feedStale  map[string]bool        // source in a notified stale episode
	feedRegr   map[string]bool        // source in a notified regression episode
	hermesMark time.Time              // last complete run of the notified offline episode
	sent       []time.Time            // send times inside RateWindow
	held       map[string]int         // kind -> messages held for the digest
	heldSince  time.Time
}

// New returns a Notifier.
func New(cfg Config) (*Notifier, error) {
	if cfg.Sink == nil {
		return nil, fmt.Errorf("vulnnotify: new: sink is required")
	}
	n := &Notifier{sink: cfg.Sink, now: cfg.Now, hermesMax: cfg.HermesStaleAfter,
		sources: map[string]bool{}, notified: map[findingEvent]int64{},
		feedStale: map[string]bool{}, feedRegr: map[string]bool{}, held: map[string]int{}}
	if n.now == nil {
		n.now = time.Now
	}
	if n.hermesMax <= 0 {
		n.hermesMax = DefaultHermesStaleAfter
	}
	for _, s := range cfg.Sources {
		n.sources[s] = true
	}
	return n, nil
}

// plain reduces untrusted text to printable characters on one line, at most
// limit runes. Invalid UTF-8, control and bidi characters become '?'.
func plain(s string, limit int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if n >= limit {
			b.WriteString("…")
			break
		}
		switch {
		case r == utf8.RuneError && size <= 1:
			b.WriteByte('?')
		case !unicode.IsPrint(r) || unicode.Is(unicode.Bidi_Control, r):
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// TierName returns the D7 tier name.
func TierName(t vulnstore.Tier) string {
	switch t {
	case vulnstore.TierLow:
		return "low"
	case vulnstore.TierMedium:
		return "medium"
	case vulnstore.TierHigh:
		return "high"
	case vulnstore.TierCritical:
		return "critical"
	}
	return "unknown"
}

// kevListed: the open finding's episode is KEV-listed, or its current
// record is.
func kevListed(f vulnstore.Finding) bool {
	return f.EpisodeKEV() || f.Record.Scores.KEV != nil
}

func findingMessage(kind string, f vulnstore.Finding, at time.Time) notify.Event {
	subj := plain(f.Subject.String(), maxText)
	tier := TierName(f.EpisodePeakTier)
	kev := "no"
	if kevListed(f) {
		kev = "yes"
	}
	reason := "CVE: " + plain(f.Record.Vuln.ID, maxText) + "; subject: " + subj + "; tier: " + tier + "; KEV: " + kev
	return notify.Event{Kind: kind, Host: subj, State: tier, Reason: reason, Time: at}
}

// Findings raises vuln.kev_new and vuln.critical_new for the given
// findings (typically those a run batch or run completion touched). Only
// open findings notify; each (finding key, event type) notifies once per
// episode, so a re-open (new episode) notifies again and tier or KEV
// flapping inside an episode does not. It returns how many messages were
// sent (not held for the digest).
func (n *Notifier) Findings(ctx context.Context, fs []vulnstore.Finding) int {
	now := n.now()
	var out []notify.Event
	n.mu.Lock()
	for _, f := range fs {
		if f.State != vulnstore.StateOpen {
			continue
		}
		if kevListed(f) && n.firstInEpisode(f, KindKEVNew) {
			out = append(out, n.admit(findingMessage(KindKEVNew, f, now), now)...)
		}
		if f.EpisodePeakTier == vulnstore.TierCritical && n.firstInEpisode(f, KindCriticalNew) {
			out = append(out, n.admit(findingMessage(KindCriticalNew, f, now), now)...)
		}
	}
	n.mu.Unlock()
	return n.send(ctx, out)
}

// firstInEpisode records (key, kind) for f's episode and reports whether it
// had not been recorded yet. Caller holds n.mu.
func (n *Notifier) firstInEpisode(f vulnstore.Finding, kind string) bool {
	k := findingEvent{key: f.Key, kind: kind}
	if ep, ok := n.notified[k]; ok {
		if f.Episode <= ep {
			return false
		}
		n.notified[k] = f.Episode
		return true
	}
	for len(n.order) >= MaxTrackedFindings {
		delete(n.notified, n.order[0])
		n.order = n.order[1:]
	}
	n.notified[k] = f.Episode
	n.order = append(n.order, k)
	return true
}

// Hermes raises vuln.hermes_stale once per offline episode: when the last
// complete run is older than the threshold. A newer complete run ends the
// episode. A zero lastComplete (no complete run yet) raises nothing; the
// UI shows "not assessed".
func (n *Notifier) Hermes(ctx context.Context, lastComplete time.Time) int {
	if lastComplete.IsZero() {
		return 0
	}
	now := n.now()
	var out []notify.Event
	n.mu.Lock()
	if now.Sub(lastComplete) > n.hermesMax && !lastComplete.Equal(n.hermesMark) {
		n.hermesMark = lastComplete
		out = n.admit(notify.Event{Kind: KindHermesStale, State: "stale",
			Reason: "no complete Hermes run since " + lastComplete.UTC().Format(time.RFC3339), Time: now}, now)
	}
	n.mu.Unlock()
	return n.send(ctx, out)
}

// FeedStatus is NOS's current staleness verdict on one listed source (D4).
type FeedStatus struct {
	SourceID string
	Stale    bool
	// Since is when the source turned stale (content date plus maximum
	// age); zero for undated sources.
	Since time.Time
}

// Feeds raises vuln.feed_stale once per listed source and stale episode.
// A non-stale status ends the source's episode; unknown source IDs are
// ignored and create no state.
func (n *Notifier) Feeds(ctx context.Context, st []FeedStatus) int {
	now := n.now()
	var out []notify.Event
	n.mu.Lock()
	for _, s := range st {
		if !n.sources[s.SourceID] {
			continue
		}
		if !s.Stale {
			delete(n.feedStale, s.SourceID)
			continue
		}
		if n.feedStale[s.SourceID] {
			continue
		}
		n.feedStale[s.SourceID] = true
		reason := "feed " + plain(s.SourceID, maxText) + " stale"
		if !s.Since.IsZero() {
			reason += " since " + s.Since.UTC().Format(time.RFC3339)
		} else {
			reason += " (undated)"
		}
		out = append(out, n.admit(notify.Event{Kind: KindFeedStale, State: "stale", Reason: reason, Time: now}, now)...)
	}
	n.mu.Unlock()
	return n.send(ctx, out)
}

// Run raises vuln.feed_regressed for the listed sources a started run named
// below their high-water mark or dated in the future: once per source and
// regression episode, which ends when a run accepts the source again.
// Undated verdicts neither open nor end an episode; unknown source IDs
// raise nothing.
func (n *Notifier) Run(ctx context.Context, r vulnstore.Run) int {
	now := n.now()
	var out []notify.Event
	n.mu.Lock()
	for _, v := range r.Sources {
		if !n.sources[v.ID] {
			continue
		}
		switch v.Status {
		case vulnstore.SourceAccepted:
			delete(n.feedRegr, v.ID)
		case vulnstore.SourceRegressed, vulnstore.SourceInvalid:
			if n.feedRegr[v.ID] {
				continue
			}
			n.feedRegr[v.ID] = true
			what := "behind its high-water mark"
			if v.Status == vulnstore.SourceInvalid {
				what = "dated in the future"
			}
			out = append(out, n.admit(notify.Event{Kind: KindFeedRegressed, State: string(v.Status),
				Reason: "feed " + plain(v.ID, maxText) + " " + what + "; run " + plain(r.ID, maxText), Time: now}, now)...)
		}
	}
	n.mu.Unlock()
	return n.send(ctx, out)
}

// MarkReset raises vuln.feed_mark_reset for every applied reset. The admin
// reason is not sent.
func (n *Notifier) MarkReset(ctx context.Context, m vulnstore.MarkReset) int {
	now := n.now()
	reason := "high-water mark of feed " + plain(m.SourceID, maxText) + " reset by " + plain(m.Admin, maxText) +
		" from " + m.OldDate.UTC().Format(time.RFC3339) + " to " + m.NewDate.UTC().Format(time.RFC3339)
	n.mu.Lock()
	out := n.admit(notify.Event{Kind: KindFeedMarkReset, State: "reset", Reason: reason, Time: now}, now)
	n.mu.Unlock()
	return n.send(ctx, out)
}

// Flush sends the pending digest when a full RateWindow has passed since
// the first held message. Call it periodically (e.g. every few minutes);
// every other method also flushes when due.
func (n *Notifier) Flush(ctx context.Context) int {
	now := n.now()
	n.mu.Lock()
	out := n.digestDue(now)
	n.mu.Unlock()
	return n.send(ctx, out)
}

// admit applies the rate limit to e: it returns the messages to send now
// (a due digest, then e if it is inside the limit) and counts e into the
// digest otherwise. Caller holds n.mu.
func (n *Notifier) admit(e notify.Event, now time.Time) []notify.Event {
	out := n.digestDue(now)
	cut := 0
	for cut < len(n.sent) && now.Sub(n.sent[cut]) >= RateWindow {
		cut++
	}
	n.sent = n.sent[cut:]
	if len(n.sent) < MaxPerHour {
		n.sent = append(n.sent, now)
		return append(out, e)
	}
	if len(n.held) == 0 {
		n.heldSince = now
	}
	n.held[e.Kind]++
	return out
}

// digestDue returns the digest message when one is due and resets the
// held counts. The digest is sent at most once per RateWindow and does not
// count against MaxPerHour. Caller holds n.mu.
func (n *Notifier) digestDue(now time.Time) []notify.Event {
	if len(n.held) == 0 || now.Sub(n.heldSince) < RateWindow {
		return nil
	}
	kinds := make([]string, 0, len(n.held))
	total := 0
	for k, c := range n.held {
		kinds = append(kinds, k)
		total += c
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s: %d", k, n.held[k]))
	}
	n.held = map[string]int{}
	n.heldSince = time.Time{}
	return []notify.Event{{Kind: KindDigest, State: "digest",
		Reason: fmt.Sprintf("%d vulnerability notifications held by the hourly limit (%s)", total, strings.Join(parts, ", ")), Time: now}}
}

// send hands the messages to the sink and returns how many were sent.
func (n *Notifier) send(ctx context.Context, es []notify.Event) int {
	for _, e := range es {
		n.sink.Notify(ctx, e)
	}
	return len(es)
}
