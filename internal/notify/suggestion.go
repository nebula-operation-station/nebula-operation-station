// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// KindOpsSuggestion is the opsagent.suggestion_new event (ADR 0016 D10): a
// fix note was accepted for a group whose top tier is critical or high.
const KindOpsSuggestion = "opsagent.suggestion_new"

const (
	// maxSuggestionKey bounds the group and tier key of one episode.
	maxSuggestionKey = 128
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

// SuggestionTemplate renders opsagent.suggestion_new messages with the NOS
// base URL it was built with. The message goes through the notifier's normal
// send path, which applies the shared hourly limit and digest (see
// internal/vulnnotify).
type SuggestionTemplate struct {
	linkStart string // NOS base URL plus the note route
}

// NewSuggestionTemplate returns a template whose links start with nosBase, for
// example "https://nos.example.net". The error never contains nosBase.
func NewSuggestionTemplate(nosBase string) (*SuggestionTemplate, error) {
	if err := checkNOSBase(nosBase); err != nil {
		return nil, err
	}
	return &SuggestionTemplate{linkStart: strings.TrimSuffix(nosBase, "/") + suggestionLinkRoute}, nil
}

// Event validates ev and returns its message, stamped at now. It returns an
// error wrapping ErrInvalidSuggestion for input that must never be sent.
func (t *SuggestionTemplate) Event(ev SuggestionEvent, now time.Time) (Event, error) {
	if err := validSuggestion(ev); err != nil {
		return Event{}, err
	}
	return suggestionMessage(ev, t.linkStart+strconv.FormatInt(ev.NoteID, 10), now), nil
}

// ValidSuggestionKey reports whether k can be an episode key: 1 to 128
// printable ASCII bytes.
func ValidSuggestionKey(k string) bool { return validSuggestionKey(k) == nil }

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
