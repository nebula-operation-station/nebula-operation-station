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
// Delivery: a message counts as sent only when at least one provider
// accepted it. De-duplication state is set only after that delivery. A
// message no provider accepts gives its rate slot back, stays queued (at
// most MaxPending) and is retried only by Flush, inside the hourly limit;
// when delivered messages use up the limit, the rest of the queue is
// folded into the digest. A queued alert whose episode ends before
// delivery is dropped. A caller is never held beyond its context: once it
// is done, no further message is attempted. When the queue overflows, the oldest
// alert is dropped and reported as undelivered in the next digest. A digest
// that fails keeps its counts for the next attempt. Messages held by the
// rate limit are accounted for by the digest, so their de-duplication
// state is set when they are held.
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
// NOS's source list, MaxTrackedFindings and MaxPending.
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
	// MaxPending bounds the messages queued for another delivery attempt
	// after no provider accepted them; the oldest are dropped first.
	MaxPending = 100
	// maxText bounds one untrusted field in a message.
	maxText = 128
	// maxSubjectID bounds the readable subject ID in a message, so that an
	// image subject keeps its full digest inside the sender's field limits.
	maxSubjectID = 40
	// maxImageDigest is the length of "sha256:" plus 64 hex digits.
	maxImageDigest = 71
	// maxVulnID bounds the CVE ID in a message.
	maxVulnID = 64
	// undeliveredSuffix marks digest counts of dropped undelivered alerts.
	undeliveredSuffix = " undelivered"
)

// Sink sends one notification and returns how many providers accepted it.
// It must return once ctx is done; *notify.Notifier implements it.
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

// alertKey identifies a de-duplicated alert: kind plus finding key or
// source ID. The episode is kept in pendingRef.
type alertKey struct {
	kind    string
	finding vulnfinding.Key
	source  string
}

// pendingRef marks an alert that is queued or being delivered.
type pendingRef struct {
	token   uint64
	episode int64
}

// outMsg is one message on its way to the sink.
type outMsg struct {
	ev    notify.Event
	keyed bool
	key   alertKey
	token uint64
	// commit sets the de-duplication state; called under n.mu after
	// delivery. Nil for messages without de-duplication.
	commit func()
	// digest holds the counts of a digest message, restored when it fails.
	digest      map[string]int
	digestSince time.Time
	// slot is the reserved MaxPerHour slot, released when the message is
	// not delivered. Zero for a digest.
	slot time.Time
}

// Notifier decides which vulnerability events to send. It is safe for
// concurrent use; messages are sent outside its lock.
type Notifier struct {
	sink       Sink
	now        func() time.Time
	hermesMax  time.Duration
	sources    map[string]bool
	mu         sync.Mutex
	notified   map[findingEvent]int64 // episode last delivered
	order      []findingEvent         // insertion order for eviction
	feedStale  map[string]bool        // source in a delivered stale episode
	feedRegr   map[string]bool        // source in a delivered regression episode
	hermesMark time.Time              // last complete run of the delivered offline episode
	inflight   map[alertKey]pendingRef
	pending    []outMsg // undelivered, waiting for the next attempt
	seq        uint64
	sent       []time.Time    // send times inside RateWindow
	held       map[string]int // kind -> messages held for the digest
	heldSince  time.Time
}

// New returns a Notifier.
func New(cfg Config) (*Notifier, error) {
	if cfg.Sink == nil {
		return nil, fmt.Errorf("vulnnotify: new: sink is required")
	}
	n := &Notifier{sink: cfg.Sink, now: cfg.Now, hermesMax: cfg.HermesStaleAfter,
		sources: map[string]bool{}, notified: map[findingEvent]int64{},
		feedStale: map[string]bool{}, feedRegr: map[string]bool{}, held: map[string]int{},
		inflight: map[alertKey]pendingRef{}}
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

// subjectText returns the readable subject (kind and shortened ID) and the
// full subject for the message reason, which keeps an image digest whole.
func subjectText(s vulnstore.Subject) (short, full string) {
	short = plain(string(s.Kind), 16) + "/" + plain(s.ID, maxSubjectID)
	full = short
	if s.Kind == vulnfinding.SubjectImage {
		full += "/" + plain(s.ImageDigest, maxImageDigest)
	}
	return short, full
}

func findingMessage(kind string, f vulnstore.Finding, at time.Time) notify.Event {
	short, full := subjectText(f.Subject)
	tier := TierName(f.EpisodePeakTier)
	kev := "no"
	if kevListed(f) {
		kev = "yes"
	}
	reason := "CVE: " + plain(f.Record.Vuln.ID, maxVulnID) + "; subject: " + full + "; tier: " + tier + "; KEV: " + kev
	return notify.Event{Kind: kind, Host: short, State: tier, Reason: reason, Time: at}
}

// Findings raises vuln.kev_new and vuln.critical_new for the given
// findings (typically those a run batch or run completion touched). Only
// open findings notify; each (finding key, event type) notifies once per
// episode, so a re-open (new episode) notifies again and tier or KEV
// flapping inside an episode does not. It returns how many messages were
// delivered, including queued ones retried now.
func (n *Notifier) Findings(ctx context.Context, fs []vulnstore.Finding) int {
	now := n.now()
	n.mu.Lock()
	var out []outMsg
	for _, f := range fs {
		if f.State != vulnstore.StateOpen {
			continue
		}
		if kevListed(f) {
			out = append(out, n.findingAlert(KindKEVNew, f, now)...)
		}
		if f.EpisodePeakTier == vulnstore.TierCritical {
			out = append(out, n.findingAlert(KindCriticalNew, f, now)...)
		}
	}
	n.mu.Unlock()
	return n.send(ctx, out)
}

// findingAlert queues (kind, f) unless its episode was delivered or is
// already queued; a queued older episode is replaced. Caller holds n.mu.
func (n *Notifier) findingAlert(kind string, f vulnstore.Finding, now time.Time) []outMsg {
	fe := findingEvent{key: f.Key, kind: kind}
	if ep, ok := n.notified[fe]; ok && f.Episode <= ep {
		return nil
	}
	k := alertKey{kind: kind, finding: f.Key}
	if ref, ok := n.inflight[k]; ok {
		if f.Episode <= ref.episode {
			return nil
		}
		n.cancel(k)
	}
	ep := f.Episode
	return n.admit(outMsg{ev: findingMessage(kind, f, now), keyed: true, key: k,
		commit: func() { n.markNotified(fe, ep) }}, ep, now)
}

// markNotified records fe's delivered episode. Caller holds n.mu.
func (n *Notifier) markNotified(fe findingEvent, ep int64) {
	if old, ok := n.notified[fe]; ok {
		if ep > old {
			n.notified[fe] = ep
		}
		return
	}
	for len(n.order) >= MaxTrackedFindings {
		delete(n.notified, n.order[0])
		n.order = n.order[1:]
	}
	n.notified[fe] = ep
	n.order = append(n.order, fe)
}

// Hermes raises vuln.hermes_stale once per offline episode: when the last
// complete run is older than the threshold. A newer complete run ends the
// episode and drops an undelivered alert of the old one. A zero
// lastComplete (no complete run yet) raises nothing; the UI shows "not
// assessed".
func (n *Notifier) Hermes(ctx context.Context, lastComplete time.Time) int {
	now := n.now()
	n.mu.Lock()
	var out []outMsg
	if !lastComplete.IsZero() {
		k := alertKey{kind: KindHermesStale}
		mark := lastComplete.UnixNano()
		if ref, ok := n.inflight[k]; ok && ref.episode != mark {
			n.cancel(k)
		}
		_, queued := n.inflight[k]
		if now.Sub(lastComplete) > n.hermesMax && !lastComplete.Equal(n.hermesMark) && !queued {
			out = append(out, n.admit(outMsg{ev: notify.Event{Kind: KindHermesStale, State: "stale",
				Reason: "no complete Hermes run since " + lastComplete.UTC().Format(time.RFC3339), Time: now},
				keyed: true, key: k, commit: func() { n.hermesMark = lastComplete }}, mark, now)...)
		}
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
// A non-stale status ends the source's episode and drops its undelivered
// alert; unknown source IDs are ignored and create no state.
func (n *Notifier) Feeds(ctx context.Context, st []FeedStatus) int {
	now := n.now()
	n.mu.Lock()
	var out []outMsg
	for _, s := range st {
		if !n.sources[s.SourceID] {
			continue
		}
		k := alertKey{kind: KindFeedStale, source: s.SourceID}
		if !s.Stale {
			delete(n.feedStale, s.SourceID)
			n.cancel(k)
			continue
		}
		if _, queued := n.inflight[k]; n.feedStale[s.SourceID] || queued {
			continue
		}
		reason := "feed " + plain(s.SourceID, maxText) + " stale"
		if !s.Since.IsZero() {
			reason += " since " + s.Since.UTC().Format(time.RFC3339)
		} else {
			reason += " (undated)"
		}
		src := s.SourceID
		out = append(out, n.admit(outMsg{ev: notify.Event{Kind: KindFeedStale, State: "stale", Reason: reason, Time: now},
			keyed: true, key: k, commit: func() { n.feedStale[src] = true }}, 0, now)...)
	}
	n.mu.Unlock()
	return n.send(ctx, out)
}

// Run raises vuln.feed_regressed for the listed sources a started run named
// below their high-water mark or dated in the future: once per source and
// regression episode, which ends when a run accepts the source again (and
// drops an undelivered alert). Undated verdicts neither open nor end an
// episode; unknown source IDs raise nothing.
func (n *Notifier) Run(ctx context.Context, r vulnstore.Run) int {
	now := n.now()
	n.mu.Lock()
	var out []outMsg
	for _, v := range r.Sources {
		if !n.sources[v.ID] {
			continue
		}
		k := alertKey{kind: KindFeedRegressed, source: v.ID}
		switch v.Status {
		case vulnstore.SourceAccepted:
			delete(n.feedRegr, v.ID)
			n.cancel(k)
		case vulnstore.SourceRegressed, vulnstore.SourceInvalid:
			if _, queued := n.inflight[k]; n.feedRegr[v.ID] || queued {
				continue
			}
			what := "behind its high-water mark"
			if v.Status == vulnstore.SourceInvalid {
				what = "dated in the future"
			}
			src := v.ID
			out = append(out, n.admit(outMsg{ev: notify.Event{Kind: KindFeedRegressed, State: string(v.Status),
				Reason: "feed " + plain(v.ID, maxText) + " " + what + "; run " + plain(r.ID, maxText), Time: now},
				keyed: true, key: k, commit: func() { n.feedRegr[src] = true }}, 0, now)...)
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
	var out []outMsg
	out = append(out, n.admit(outMsg{ev: notify.Event{Kind: KindFeedMarkReset, State: "reset", Reason: reason, Time: now}}, 0, now)...)
	n.mu.Unlock()
	return n.send(ctx, out)
}

// Flush sends the pending digest when a full RateWindow has passed since
// the first held message and retries queued undelivered messages inside the
// hourly limit. When the limit is used up by delivered messages, the rest
// of the queue is folded into the digest. Only Flush retries; call it
// periodically (e.g. every few minutes). Other methods send only their own
// new messages and a due digest. It returns how many messages were
// delivered.
func (n *Notifier) Flush(ctx context.Context) int {
	now := n.now()
	n.mu.Lock()
	out := append(n.digestDue(now), n.retries(now)...)
	n.mu.Unlock()
	sent := n.send(ctx, out)
	n.mu.Lock()
	n.foldIfFull(n.now())
	n.mu.Unlock()
	return sent
}

// Pending returns how many undelivered messages wait for another attempt.
func (n *Notifier) Pending() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.pending)
}

// retries takes as many queued messages as the hourly limit has free slots
// (oldest first) and reserves a slot for each; their keys stay in
// n.inflight, so no copy is queued meanwhile. When no slot is free the
// queue is folded into the digest. Caller holds n.mu.
func (n *Notifier) retries(now time.Time) []outMsg {
	if n.foldIfFull(now) {
		return nil
	}
	c := min(MaxPerHour-len(n.sent), len(n.pending))
	out := make([]outMsg, c)
	copy(out, n.pending[:c])
	clear(n.pending[:c])
	n.pending = n.pending[c:]
	for i := range out {
		out[i].slot = n.reserve(now)
	}
	return out
}

// foldIfFull folds the queued messages into the digest when the hourly
// limit has no free slot. A folded alert is accounted for by the digest,
// like one held by admit, so its de-duplication state is set now. Failed
// attempts release their slot, so during an outage the limit stays free
// and the queue keeps waiting for delivery. Caller holds n.mu.
func (n *Notifier) foldIfFull(now time.Time) bool {
	n.prune(now)
	if len(n.sent) < MaxPerHour {
		return false
	}
	for i, m := range n.pending {
		if m.keyed {
			delete(n.inflight, m.key)
		}
		n.hold(m.ev.Kind, 1, now)
		if m.commit != nil {
			m.commit()
		}
		n.pending[i] = outMsg{}
	}
	n.pending = n.pending[:0]
	return true
}

// prune drops send times older than RateWindow. Caller holds n.mu.
func (n *Notifier) prune(now time.Time) {
	cut := 0
	for cut < len(n.sent) && now.Sub(n.sent[cut]) >= RateWindow {
		cut++
	}
	n.sent = n.sent[cut:]
}

// reserve takes one slot of the hourly limit and returns its time; the
// caller has checked that one is free. Caller holds n.mu.
func (n *Notifier) reserve(now time.Time) time.Time {
	n.sent = append(n.sent, now)
	return now
}

// release returns the slot reserved at t after a failed or skipped
// attempt. Caller holds n.mu.
func (n *Notifier) release(t time.Time) {
	for i := len(n.sent) - 1; i >= 0; i-- {
		if n.sent[i].Equal(t) {
			n.sent = append(n.sent[:i], n.sent[i+1:]...)
			return
		}
	}
}

// cancel drops the queued or in-flight alert k: it is not retried and its
// delivery sets no state. Caller holds n.mu.
func (n *Notifier) cancel(k alertKey) {
	if _, ok := n.inflight[k]; !ok {
		return
	}
	delete(n.inflight, k)
	kept := n.pending[:0]
	for _, m := range n.pending {
		if !m.keyed || m.key != k {
			kept = append(kept, m)
		}
	}
	clear(n.pending[len(kept):])
	n.pending = kept
}

// admit applies the rate limit to m: it returns the messages to send now
// (a due digest, then m if it is inside the limit, with a reserved slot
// that send releases if no provider accepts m) and counts m into the
// digest otherwise. A held message is accounted for by the digest, so its
// de-duplication state is set now. Caller holds n.mu.
func (n *Notifier) admit(m outMsg, episode int64, now time.Time) []outMsg {
	out := n.digestDue(now)
	n.prune(now)
	if len(n.sent) < MaxPerHour {
		m.slot = n.reserve(now)
		if m.keyed {
			n.seq++
			m.token = n.seq
			n.inflight[m.key] = pendingRef{token: n.seq, episode: episode}
		}
		return append(out, m)
	}
	n.hold(m.ev.Kind, 1, now)
	if m.commit != nil {
		m.commit()
	}
	return out
}

// hold counts c messages of kind into the digest. Caller holds n.mu.
func (n *Notifier) hold(kind string, c int, now time.Time) {
	if len(n.held) == 0 {
		n.heldSince = now
	}
	n.held[kind] += c
}

// digestDue returns the digest message when one is due and resets the
// held counts. The digest is sent at most once per RateWindow and does not
// count against MaxPerHour. Caller holds n.mu.
func (n *Notifier) digestDue(now time.Time) []outMsg {
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
	m := outMsg{ev: notify.Event{Kind: KindDigest, State: "digest",
		Reason: fmt.Sprintf("%d vulnerability notifications held by the hourly limit or undelivered (%s)", total, strings.Join(parts, ", ")), Time: now},
		digest: n.held, digestSince: n.heldSince}
	n.held = map[string]int{}
	n.heldSince = time.Time{}
	return []outMsg{m}
}

// send hands the messages to the sink, one after another, and returns how
// many at least one provider accepted. Once ctx is done the remaining
// messages are not attempted; they count as undelivered. Delivered alerts
// set their de-duplication state; undelivered ones release their rate slot
// and are queued again (bounded), a failed digest returns its counts.
func (n *Notifier) send(ctx context.Context, ms []outMsg) int {
	if len(ms) == 0 {
		return 0
	}
	ok := make([]bool, len(ms))
	sent := 0
	for i, m := range ms {
		if ctx.Err() != nil {
			break
		}
		ok[i] = n.sink.Notify(ctx, m.ev) > 0
		if ok[i] {
			sent++
		}
	}
	now := n.now()
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, m := range ms {
		if !ok[i] && !m.slot.IsZero() {
			n.release(m.slot)
			m.slot = time.Time{}
		}
		live := true
		if m.keyed {
			ref, found := n.inflight[m.key]
			live = found && ref.token == m.token
		}
		switch {
		case ok[i]:
			if live && m.keyed {
				delete(n.inflight, m.key)
			}
			if live && m.commit != nil {
				m.commit()
			}
		case m.digest != nil:
			for k, c := range m.digest {
				n.hold(k, c, now)
			}
			if m.digestSince.Before(n.heldSince) {
				n.heldSince = m.digestSince
			}
		case live:
			n.requeue(m, now)
		}
	}
	return sent
}

// requeue queues an undelivered message; when the queue is full the oldest
// is dropped and counted as undelivered in the digest. Caller holds n.mu.
func (n *Notifier) requeue(m outMsg, now time.Time) {
	n.pending = append(n.pending, m)
	for len(n.pending) > MaxPending {
		old := n.pending[0]
		n.pending[0] = outMsg{}
		n.pending = n.pending[1:]
		if old.keyed {
			delete(n.inflight, old.key)
		}
		n.hold(old.ev.Kind+undeliveredSuffix, 1, now)
	}
}
