// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// Ops suggestion constants.
const (
	// opsSuggestionStateFile keeps the suggestion episodes across restarts, in
	// the private notes directory.
	opsSuggestionStateFile = "suggestions.json"
	// maxOpsSuggestionState bounds reading that file.
	maxOpsSuggestionState = 16 << 20
	// opsSuggestionSendTimeout bounds one suggestion send, including retries.
	opsSuggestionSendTimeout = 2 * time.Minute
)

// opsSuggestEvents sends opsagent.suggestion_new (ADR 0016 D10) when an accepted
// fix note's group is at tier critical or high. The message is the notify
// package's fixed template; no note text reaches it.
//
// An episode is (group, tier at acceptance). It ends when an accepted note of
// the same group has a lower top tier: the episodes of the tiers above that
// one are forgotten, so a later return to such a tier is a new episode.
//
// Open: the mute per host ("Stummschaltung je Host", ADR 0016 D10) does not
// exist in this repository yet, so a suggestion is not muted per host here.
type opsSuggestEvents struct {
	gate      *notify.SuggestionGate // nil when the NOS base URL is not usable
	settings  opsSettingsReader
	statePath string
	log       *slog.Logger

	// noteMu serialises the accepted notes, so the episode bookkeeping of one
	// group is applied in order.
	noteMu sync.Mutex
	// bg tracks the background work started by NoteAccepted (tests wait on it).
	bg sync.WaitGroup
	// saveMu serialises writes of statePath.
	saveMu sync.Mutex
}

// newOpsSuggestions returns the suggestions for the server. dataDir holds the
// suggestion state (in the notes directory); publicOrigin is the NOS base URL
// that the links start with. A publicOrigin that is not usable turns the
// suggestions off with a log line.
func newOpsSuggestions(settings opsSettingsReader, dataDir, publicOrigin string, n *notify.Notifier, log *slog.Logger) *opsSuggestEvents {
	s := &opsSuggestEvents{
		settings:  settings,
		statePath: filepath.Join(dataDir, opsNotesDir, opsSuggestionStateFile),
		log:       log,
	}
	g, err := notify.NewSuggestionGate(n, publicOrigin, time.Now)
	if err != nil {
		log.Error("ops agent suggestions disabled: the NOS base URL is not usable", "error", err.Error())
		return s
	}
	s.gate = g
	s.restore()
	return s
}

// wireOpsSuggestions returns the suggestions on the server's database, reading
// the ops settings from db. Call it only when the ops token is configured.
func wireOpsSuggestions(db *sql.DB, dataDir, publicOrigin string, n *notify.Notifier, log *slog.Logger) (*opsSuggestEvents, error) {
	st, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ops agent suggestions: %w", err)
	}
	return newOpsSuggestions(st, dataDir, publicOrigin, n, log), nil
}

// acceptedHook returns the ops API's OnNoteAccepted hook, or nil when s is nil
// (no ops token): an accepted note then does nothing.
func (s *opsSuggestEvents) acceptedHook() func(opsnotes.Note) {
	if s == nil {
		return nil
	}
	return s.NoteAccepted
}

// restore reads the remembered episodes. A missing file is a first start; a
// file that cannot be read is logged and the episodes start empty.
func (s *opsSuggestEvents) restore() {
	f, err := os.Open(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.log.Error("ops agent suggestions: read state", "error", err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxOpsSuggestionState+1))
	if err == nil && len(data) > maxOpsSuggestionState {
		err = errors.New("state file too large")
	}
	var st struct {
		Keys []string `json:"keys"`
	}
	if err == nil {
		err = json.Unmarshal(data, &st)
	}
	if err != nil {
		s.log.Error("ops agent suggestions: state unusable, starting empty", "error", err)
		return
	}
	s.gate.Restore(st.Keys)
}

// save writes the remembered episodes to statePath. A failed write is logged;
// the episodes stay in memory and the next change writes them again.
func (s *opsSuggestEvents) save() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	data, err := json.Marshal(struct {
		Keys []string `json:"keys"`
	}{Keys: s.gate.Keys()})
	if err == nil {
		err = writeFileAtomic(s.statePath, data)
	}
	if err != nil {
		s.log.Error("ops agent suggestions: write state", "error", err)
	}
}

// NoteAccepted is the ops API's OnNoteAccepted hook. It runs in the background,
// so the API answer never waits for the providers. For a fix note it ends the
// episodes above the group's new top tier and, when that tier is critical or
// high, sends opsagent.suggestion_new (once per episode, inside the gate's
// limit and the normal send path).
func (s *opsSuggestEvents) NoteAccepted(n opsnotes.Note) {
	if n.Kind != opsnotes.KindFix || s.gate == nil {
		return
	}
	var p opsfacts.LabProjection
	if err := json.Unmarshal([]byte(n.Snapshot), &p); err != nil {
		s.log.Error("ops agent suggestions: note snapshot unreadable", "note", n.ID, "error", err)
		return
	}
	tier := topTier(p.Findings)
	group := groupKey(n.Ref)
	s.bg.Go(func() {
		s.noteMu.Lock()
		defer s.noteMu.Unlock()
		if ended := endedEpisodes(group, tier); len(ended) > 0 {
			s.gate.Forget(ended)
			s.save()
		}
		if tier != opsfacts.TierCritical && tier != opsfacts.TierHigh {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), opsSuggestionSendTimeout)
		defer cancel()
		row, err := s.settings.Get(ctx)
		if err != nil {
			s.log.Error("ops agent suggestions: read settings", "error", err)
			return
		}
		if !row.Enabled {
			return
		}
		ev := notify.SuggestionEvent{Key: episodeKey(group, tier), Host: p.Host.Label, Tier: string(tier),
			English: row.Language == opsconfig.LanguageEN, NoteID: n.ID}
		d, err := s.gate.Submit(ctx, ev)
		if err != nil {
			s.log.Error("ops agent suggestions: refused", "note", n.ID, "error", err)
			return
		}
		if d == notify.DecisionSent {
			s.save()
		}
	})
}

// groupKey is the hashed group reference. The hash keeps the note's group
// out of the state file and the episode keys.
func groupKey(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return hex.EncodeToString(sum[:])
}

// episodeKey is the episode key of a group at a tier.
func episodeKey(group string, tier opsfacts.Tier) string {
	return group + "|" + string(tier)
}

// endedEpisodes returns the episode keys of group above tier: an accepted note
// whose top tier is tier ends the episodes of the higher tiers.
func endedEpisodes(group string, tier opsfacts.Tier) []string {
	var out []string
	for _, t := range []opsfacts.Tier{opsfacts.TierCritical, opsfacts.TierHigh} {
		if tierRank(t) > tierRank(tier) {
			out = append(out, episodeKey(group, t))
		}
	}
	return out
}

// tierRank orders the tiers; unknown tiers rank as low.
func tierRank(t opsfacts.Tier) int {
	switch t {
	case opsfacts.TierMedium:
		return 1
	case opsfacts.TierHigh:
		return 2
	case opsfacts.TierCritical:
		return 3
	}
	return 0
}

// topTier returns the highest tier among findings; TierLow when there are none.
func topTier(fs []opsfacts.LabFinding) opsfacts.Tier {
	top := opsfacts.TierLow
	for _, f := range fs {
		if tierRank(f.Tier) > tierRank(top) {
			top = f.Tier
		}
	}
	return top
}
