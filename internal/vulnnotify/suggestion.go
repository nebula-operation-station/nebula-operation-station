// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
)

// Suggestion sends e, an opsagent.suggestion_new message (ADR 0016 D10), once
// per episode key. It shares MaxPerHour and the hourly digest with every other
// message of the notifier: a suggestion over the limit is held and counted
// into the digest, and its episode is remembered, so it is not sent later. An
// undelivered suggestion waits in the queue for Flush, like any other message.
// It returns how many providers accepted the message now; a duplicate, a held
// or a queued suggestion returns 0. Only messages whose kind is
// opsagent.suggestion_new and whose key is valid are accepted.
func (n *Notifier) Suggestion(ctx context.Context, key string, e notify.Event) int {
	if e.Kind != notify.KindOpsSuggestion || !notify.ValidSuggestionKey(key) {
		return 0
	}
	now := n.now()
	n.mu.Lock()
	var out []outMsg
	k := alertKey{kind: notify.KindOpsSuggestion, source: key}
	if _, queued := n.inflight[k]; !n.suggested[key] && !queued {
		out = n.admit(outMsg{ev: e, keyed: true, key: k, commit: func() { n.markSuggested(key) }}, 0, now)
	}
	n.mu.Unlock()
	return n.send(ctx, out)
}

// SuggestionKeys returns the remembered suggestion episode keys, oldest first,
// for the caller to persist across restarts.
func (n *Notifier) SuggestionKeys() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.suggestOrder...)
}

// RestoreSuggestions marks the given episode keys as already handled. Keys
// that are not usable are ignored. Call it before the first Suggestion.
func (n *Notifier) RestoreSuggestions(keys []string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, k := range keys {
		if notify.ValidSuggestionKey(k) {
			n.markSuggested(k)
		}
	}
}

// ForgetSuggestions ends the given episodes: their remembered state and any
// queued message are dropped, so a later Suggestion for the same key sends
// again. The ops agent uses it when a group leaves a tier (ADR 0016 D10). Keys
// that are not remembered are ignored.
func (n *Notifier) ForgetSuggestions(keys []string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	drop := make(map[string]bool, len(keys))
	for _, k := range keys {
		drop[k] = true
		delete(n.suggested, k)
		n.cancel(alertKey{kind: notify.KindOpsSuggestion, source: k})
	}
	kept := n.suggestOrder[:0]
	for _, k := range n.suggestOrder {
		if !drop[k] {
			kept = append(kept, k)
		}
	}
	clear(n.suggestOrder[len(kept):])
	n.suggestOrder = kept
}

// markSuggested remembers key as handled, evicting the oldest key when the
// bound is reached. Caller holds n.mu.
func (n *Notifier) markSuggested(key string) {
	if n.suggested[key] {
		return
	}
	for len(n.suggestOrder) >= MaxTrackedSuggestionKeys {
		delete(n.suggested, n.suggestOrder[0])
		n.suggestOrder = n.suggestOrder[1:]
	}
	n.suggested[key] = true
	n.suggestOrder = append(n.suggestOrder, key)
}
