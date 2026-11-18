// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KindOpsSuggestion is the opsagent.suggestion_new event (ADR 0016 D10): a
// fix note was accepted for a group whose top tier is critical or high.
const KindOpsSuggestion = "opsagent.suggestion_new"

// Limits of the suggestion gate.
const (
	// MaxSuggestionsPerHour is the number of suggestion messages that may
	// leave in any hour; the rest are held and not sent.
	MaxSuggestionsPerHour = 10
	// SuggestionWindow is the period MaxSuggestionsPerHour applies to.
	SuggestionWindow = time.Hour
	// maxSuggestionKey bounds the group and tier key of one episode.
	maxSuggestionKey = 128
	// MaxTrackedSuggestionKeys bounds the remembered episodes; the oldest are
	// dropped first.
	MaxTrackedSuggestionKeys = 100_000
	// suggestionLinkRoute is the fixed NOS UI route of a note, relative to
	// the configured NOS base URL. The link carries no other path, query or
	// fragment.
	suggestionLinkRoute = "/assistant/ops/notes/"
)

// ErrInvalidSuggestion is returned for a suggestion whose tier is not critical
// or high, whose key or note ID is not usable. Such an event is never sent.
var ErrInvalidSuggestion = errors.New("invalid suggestion event")

// SuggestionEvent is one opsagent.suggestion_new notification. The message
// is a fixed template: the host label, the tier and the NOS link. There is no
// field for model text or note text, so none can reach a message.
type SuggestionEvent struct {
	// Key identifies the episode: the group and the tier (for example
	// "<host-id>/os|high"). It is chosen by the caller and is only compared,
	// never shown.
	Key string
	// Host is the host label as the admin set it; it is reduced to plain text
	// like every integrity label.
	Host string
	// Tier is "critical" or "high".
	Tier string
	// English selects the English template; otherwise German.
	English bool
	// NoteID is the ID of the accepted note; the link points at it.
	NoteID int64
}

// SuggestionGate sends opsagent.suggestion_new through a Notifier: once per
// episode key, inside an hourly limit. Submissions are serialised, so one
// episode is sent at most once even when two notes arrive together.
//
// Episode state is held in memory and exported with Keys; the caller keeps it
// across restarts with Restore. An over-limit suggestion is held: its episode
// is remembered (it is not sent later) and it is not reported in a digest.
type SuggestionGate struct {
	n         *Notifier
	now       func() time.Time
	linkStart string // NOS base URL plus the note route

	sendMu sync.Mutex // one Submit at a time; held across the send

	mu       sync.Mutex
	sent     []time.Time // delivery times (and reserved slots) inside the window
	notified map[string]bool
	order    []string // insertion order for eviction
}

// NewSuggestionGate returns a gate that sends through n. nosBase is the
// configured NOS base URL, for example "https://nos.example.net". now
// defaults to time.Now. The error never contains nosBase.
func NewSuggestionGate(n *Notifier, nosBase string, now func() time.Time) (*SuggestionGate, error) {
	if now == nil {
		now = time.Now
	}
	if err := checkNOSBase(nosBase); err != nil {
		return nil, err
	}
	return &SuggestionGate{
		n:         n,
		now:       now,
		linkStart: strings.TrimSuffix(nosBase, "/") + suggestionLinkRoute,
		notified:  map[string]bool{},
	}, nil
}

// Submit validates ev and, unless its episode was already sent or held, sends
// it inside the hourly limit. An episode whose send no provider accepted is
// not remembered, so a later submission may send it.
func (g *SuggestionGate) Submit(ctx context.Context, ev SuggestionEvent) (Decision, error) {
	if err := validSuggestion(ev); err != nil {
		return DecisionNone, err
	}
	g.sendMu.Lock()
	defer g.sendMu.Unlock()

	g.mu.Lock()
	if g.notified[ev.Key] {
		g.mu.Unlock()
		return DecisionDuplicate, nil
	}
	now := g.now()
	g.prune(now)
	if len(g.sent) >= MaxSuggestionsPerHour {
		g.markLocked(ev.Key)
		g.mu.Unlock()
		return DecisionHeld, nil
	}
	g.sent = append(g.sent, now)
	g.mu.Unlock()

	msg := suggestionMessage(ev, g.linkStart+strconv.FormatInt(ev.NoteID, 10), now)
	ok := len(g.n.send(ctx, msg, nil)) > 0

	g.mu.Lock()
	defer g.mu.Unlock()
	if !ok {
		g.releaseLocked(now)
		return DecisionUndelivered, nil
	}
	g.markLocked(ev.Key)
	return DecisionSent, nil
}

// Keys returns the remembered episode keys, oldest first, for the caller to
// persist.
func (g *SuggestionGate) Keys() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.order...)
}

// Restore marks the given episode keys as already handled. Keys that are not
// usable are ignored. Call it before the first Submit.
func (g *SuggestionGate) Restore(keys []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, k := range keys {
		if validSuggestionKey(k) == nil {
			g.markLocked(k)
		}
	}
}

// validSuggestion checks ev before anything is sent.
func validSuggestion(ev SuggestionEvent) error {
	if err := validSuggestionKey(ev.Key); err != nil {
		return err
	}
	if ev.Tier != "critical" && ev.Tier != "high" {
		return fmt.Errorf("%w: tier", ErrInvalidSuggestion)
	}
	if ev.NoteID <= 0 {
		return fmt.Errorf("%w: note ID", ErrInvalidSuggestion)
	}
	return nil
}

// validSuggestionKey accepts 1 to maxSuggestionKey printable ASCII bytes.
func validSuggestionKey(k string) error {
	if k == "" || len(k) > maxSuggestionKey {
		return fmt.Errorf("%w: key", ErrInvalidSuggestion)
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x21 || k[i] > 0x7e {
			return fmt.Errorf("%w: key", ErrInvalidSuggestion)
		}
	}
	return nil
}

// suggestionMessage renders ev with the fixed template of its language. The
// label is reduced by integrityLabel, the tier is validated and the link is
// built from the configured base and a note ID, so the text holds nothing else.
func suggestionMessage(ev SuggestionEvent, link string, now time.Time) Event {
	label := integrityLabel(ev.Host)
	var title string
	if ev.English {
		title = "New fix suggestion for " + label + ", tier " + ev.Tier
	} else {
		title = "Neuer Fix-Vorschlag für " + label + ", Tier " + ev.Tier
	}
	// The text is Text's default layout: title, the NOS link and the time.
	return Event{Kind: KindOpsSuggestion, title: title, link: link, Time: now}
}

// Forget removes the given episode keys, so that a later submission of the
// same key sends again. The ops agent uses it when a group leaves a tier: the
// episode ends and a later return to that tier is a new episode (ADR 0016
// D10). Keys that are not remembered are ignored.
func (g *SuggestionGate) Forget(keys []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	drop := make(map[string]bool, len(keys))
	for _, k := range keys {
		drop[k] = true
		delete(g.notified, k)
	}
	kept := g.order[:0]
	for _, k := range g.order {
		if !drop[k] {
			kept = append(kept, k)
		}
	}
	g.order = kept
}

// prune drops delivery times that left the window. Caller holds g.mu.
func (g *SuggestionGate) prune(now time.Time) {
	cut := 0
	for cut < len(g.sent) && now.Sub(g.sent[cut]) >= SuggestionWindow {
		cut++
	}
	g.sent = g.sent[cut:]
}

// releaseLocked removes the slot taken at t. Caller holds g.mu.
func (g *SuggestionGate) releaseLocked(t time.Time) {
	for i := len(g.sent) - 1; i >= 0; i-- {
		if g.sent[i].Equal(t) {
			g.sent = append(g.sent[:i], g.sent[i+1:]...)
			return
		}
	}
}

// markLocked remembers key. Caller holds g.mu.
func (g *SuggestionGate) markLocked(key string) {
	if g.notified[key] {
		return
	}
	g.notified[key] = true
	g.order = append(g.order, key)
	if len(g.order) > MaxTrackedSuggestionKeys {
		delete(g.notified, g.order[0])
		g.order = g.order[1:]
	}
}
