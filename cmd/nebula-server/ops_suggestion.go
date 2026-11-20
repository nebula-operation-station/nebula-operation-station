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
	// opsSuggestionSendTimeout bounds the handling of one accepted note,
	// including the sends and their retries.
	opsSuggestionSendTimeout = 2 * time.Minute
	// opsSuggestionQueue bounds the accepted notes waiting for the worker. An
	// accepted note that finds the queue full is not handled (and logged).
	opsSuggestionQueue = 64
)

// opsSuggestSink is the part of the notifier the suggestions use. The messages
// go through the notifier's hourly limit and digest; *vulnnotify.Notifier
// implements it.
type opsSuggestSink interface {
	Suggestion(ctx context.Context, key string, e notify.Event) int
	SuggestionKeys() []string
	RestoreSuggestions(keys []string)
	ForgetSuggestions(keys []string)
}

// opsSuggestJob is one accepted fix note, reduced to what the worker needs.
type opsSuggestJob struct {
	noteID int64
	host   string // the host label from the note's own projection
	group  string // hashed group reference (see groupKey)
	tier   opsfacts.Tier
}

// opsSuggestEvents sends opsagent.suggestion_new (ADR 0016 D10) when an accepted
// fix note's group is at tier critical or high. The message is the notify
// package's fixed template; no note text reaches it.
//
// An episode is (group, tier at acceptance). It ends when an accepted note of
// the same group has a lower top tier: the episodes of the tiers above that
// one are forgotten, so a later return to such a tier is a new episode.
//
// Accepted notes are handled by one worker (Run), in order, from a queue of
// opsSuggestionQueue entries. The worker runs on the server's context, so
// shutdown stops it; the API hook never waits for a provider.
//
// Open: the mute per host ("Stummschaltung je Host", ADR 0016 D10) does not
// exist in this repository yet, so a suggestion is not muted per host here.
type opsSuggestEvents struct {
	tmpl      *notify.SuggestionTemplate // nil when the NOS base URL is not usable
	sink      opsSuggestSink
	settings  opsSettingsReader
	statePath string
	log       *slog.Logger
	queue     chan opsSuggestJob

	// saveMu serialises writes of statePath.
	saveMu sync.Mutex
}

// newOpsSuggestions returns the suggestions for the server. dataDir holds the
// suggestion state (in the notes directory); publicOrigin is the NOS base URL
// that the links start with; sink is the server's notifier. A publicOrigin
// that is not usable turns the suggestions off with a log line.
func newOpsSuggestions(settings opsSettingsReader, dataDir, publicOrigin string, sink opsSuggestSink, log *slog.Logger) *opsSuggestEvents {
	s := &opsSuggestEvents{
		sink:      sink,
		settings:  settings,
		statePath: filepath.Join(dataDir, opsNotesDir, opsSuggestionStateFile),
		log:       log,
		queue:     make(chan opsSuggestJob, opsSuggestionQueue),
	}
	tpl, err := notify.NewSuggestionTemplate(publicOrigin)
	if err != nil {
		log.Error("ops agent suggestions disabled: the NOS base URL is not usable", "error", err.Error())
		return s
	}
	s.tmpl = tpl
	s.restore()
	return s
}

// wireOpsSuggestions returns the suggestions on the server's database, reading
// the ops settings from db. Call it only when the ops token is configured.
func wireOpsSuggestions(db *sql.DB, dataDir, publicOrigin string, sink opsSuggestSink, log *slog.Logger) (*opsSuggestEvents, error) {
	st, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ops agent suggestions: %w", err)
	}
	return newOpsSuggestions(st, dataDir, publicOrigin, sink, log), nil
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
	s.sink.RestoreSuggestions(st.Keys)
}

// save writes the remembered episodes to statePath. A failed write is logged;
// the episodes stay in memory and the next change writes them again. Held
// episodes are part of the state too, so they are not sent after a restart.
func (s *opsSuggestEvents) save() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	data, err := json.Marshal(struct {
		Keys []string `json:"keys"`
	}{Keys: s.sink.SuggestionKeys()})
	if err == nil {
		err = writeFileAtomic(s.statePath, data)
	}
	if err != nil {
		s.log.Error("ops agent suggestions: write state", "error", err)
	}
}

// Run is the worker of the accepted notes. It handles the queued notes one at a
// time, in order, until ctx is done; notes still queued then are dropped, as
// the server is stopping. Start it once, in the server's joined goroutines.
func (s *opsSuggestEvents) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.queue:
			s.handle(ctx, j)
		}
	}
}

// NoteAccepted is the ops API's OnNoteAccepted hook. It parses the note and
// queues it for the worker without waiting; a full queue drops the note and
// logs it. For a fix note the worker ends the episodes above the group's new
// top tier and, when that tier is critical or high, sends
// opsagent.suggestion_new (once per episode, inside the notifier's limit).
func (s *opsSuggestEvents) NoteAccepted(n opsnotes.Note) {
	if n.Kind != opsnotes.KindFix || s.tmpl == nil {
		return
	}
	var p opsfacts.LabProjection
	if err := json.Unmarshal([]byte(n.Snapshot), &p); err != nil {
		s.log.Error("ops agent suggestions: note snapshot unreadable", "note", n.ID, "error", err)
		return
	}
	j := opsSuggestJob{noteID: n.ID, host: p.Host.Label, group: groupKey(n.Ref), tier: topTier(p.Findings)}
	select {
	case s.queue <- j:
	default:
		s.log.Warn("ops agent suggestions: queue full, note not handled", "note", n.ID)
	}
}

// handle applies one accepted note: the episodes above its tier end, and a
// critical or high tier sends the suggestion when the agent is on.
func (s *opsSuggestEvents) handle(ctx context.Context, j opsSuggestJob) {
	ctx, cancel := context.WithTimeout(ctx, opsSuggestionSendTimeout)
	defer cancel()
	if ended := endedEpisodes(j.group, j.tier); len(ended) > 0 {
		s.sink.ForgetSuggestions(ended)
		s.save()
	}
	if j.tier != opsfacts.TierCritical && j.tier != opsfacts.TierHigh {
		return
	}
	row, err := s.settings.Get(ctx)
	if err != nil {
		s.log.Error("ops agent suggestions: read settings", "error", err)
		return
	}
	if !row.Enabled {
		return
	}
	key := episodeKey(j.group, j.tier)
	ev, err := s.tmpl.Event(notify.SuggestionEvent{Key: key, Host: j.host, Tier: string(j.tier),
		English: row.Language == opsconfig.LanguageEN, NoteID: j.noteID}, time.Now())
	if err != nil {
		s.log.Error("ops agent suggestions: refused", "note", j.noteID, "error", err)
		return
	}
	s.sink.Suggestion(ctx, key, ev)
	s.save()
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
