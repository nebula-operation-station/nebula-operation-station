// SPDX-License-Identifier: AGPL-3.0-or-later

package turns

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxTurns is the number of turns kept per session. Appending a turn beyond it
// drops the oldest turn.
const MaxTurns = 6

// MaxAge is how long a turn stays available after it was appended.
const MaxAge = 30 * time.Minute

// MaxQuestionBytes is the largest question, in bytes, that may be stored.
const MaxQuestionBytes = 2 * 1024

// MaxAnswerBytes is the largest rendered answer, in bytes, that may be stored.
const MaxAnswerBytes = 8 * 1024

// MaxKeyBytes is the largest session key or user name, in bytes.
const MaxKeyBytes = 128

// MaxSessions is the number of sessions held at the same time. When it is
// reached, expired sessions are removed first; if none is expired the new
// session is refused.
const MaxSessions = 1024

// ErrEmptyKey reports a turn whose session key or user name is empty.
var ErrEmptyKey = errors.New("turns: empty session or user key")

// ErrEmptyTurn reports a turn without a question.
var ErrEmptyTurn = errors.New("turns: empty question")

// ErrTooLarge reports a key, question or answer over its limit.
var ErrTooLarge = errors.New("turns: value exceeds size limit")

// ErrTooManySessions reports that MaxSessions live sessions are held and the
// new session cannot be opened.
var ErrTooManySessions = errors.New("turns: too many live sessions")

// ErrSessionOwner reports a turn for a session that belongs to another user.
var ErrSessionOwner = errors.New("turns: session belongs to another user")

// ErrInvalidUTF8 reports a question or answer that is not valid UTF-8.
var ErrInvalidUTF8 = errors.New("turns: text is not valid UTF-8")

// Turn is one question and its rendered answer. Facts and chunk texts are not
// part of a Turn.
type Turn struct {
	// User is the user the panel session belongs to. It is required by Append
	// and is not rendered by String, GoString or LogValue.
	User string
	// Question is the text the user asked.
	Question string
	// Answer is the rendered answer text shown to the user.
	Answer string
}

// String renders the turn without its text: only the byte lengths.
func (t Turn) String() string {
	return fmt.Sprintf("turns.Turn{question: %d bytes, answer: %d bytes}", len(t.Question), len(t.Answer))
}

// GoString renders the turn like String, for %#v.
func (t Turn) GoString() string {
	return t.String()
}

// LogValue returns the byte lengths of the turn for structured logging.
func (t Turn) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("question_bytes", len(t.Question)),
		slog.Int("answer_bytes", len(t.Answer)),
	)
}

// timed is a stored turn with the time it was appended.
type timed struct {
	at   time.Time
	turn Turn
}

// panelSession is the state of one panel session.
type panelSession struct {
	owner string
	turns []timed
}

// Store holds the follow-up turns of all panel sessions. It is safe for
// concurrent use. The zero value is not usable; create one with New.
type Store struct {
	now      func() time.Time
	mu       sync.Mutex
	sessions map[string]*panelSession
}

// New returns an empty Store that reads the time from now. A nil now uses
// time.Now.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, sessions: make(map[string]*panelSession)}
}

// Append stores t as the newest turn of session. It returns an error wrapping
// one of the package's sentinel errors when the turn or the session cannot be
// stored; the store is then unchanged. The oldest turn is dropped when the
// session already holds MaxTurns turns.
func (s *Store) Append(session string, t Turn) error {
	if err := validate(session, t); err != nil {
		return fmt.Errorf("append turn: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.purgeLocked(session, now)
	sess, ok := s.sessions[session]
	if ok && sess.owner != t.User {
		return fmt.Errorf("append turn: %w", ErrSessionOwner)
	}
	if !ok {
		if len(s.sessions) >= MaxSessions {
			s.sweepLocked(now)
		}
		if len(s.sessions) >= MaxSessions {
			return fmt.Errorf("append turn: %w", ErrTooManySessions)
		}
		sess = &panelSession{owner: t.User}
		s.sessions[session] = sess
	}
	sess.turns = append(sess.turns, timed{at: now, turn: t})
	if over := len(sess.turns) - MaxTurns; over > 0 {
		sess.turns = append(sess.turns[:0:0], sess.turns[over:]...)
	}
	return nil
}

// History returns a copy of the live turns of session, oldest first. Expired
// turns are removed and not returned. A session with no live turns yields nil.
// Changing the returned slice does not change the store.
func (s *Store) History(session string) []Turn {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(session, s.now())
	sess, ok := s.sessions[session]
	if !ok || len(sess.turns) == 0 {
		return nil
	}
	out := make([]Turn, 0, len(sess.turns))
	for _, e := range sess.turns {
		out = append(out, e.turn)
	}
	return out
}

// Clear removes session and all its turns. Other sessions are not affected.
func (s *Store) Clear(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, session)
}

// ClearUser removes every session owned by user, for example at logout. The
// sessions of other users are not affected.
func (s *Store) ClearUser(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, sess := range s.sessions {
		if sess.owner == user {
			delete(s.sessions, key)
		}
	}
}

// validate checks the key and turn limits that do not depend on store state.
func validate(session string, t Turn) error {
	if session == "" || t.User == "" {
		return ErrEmptyKey
	}
	if len(session) > MaxKeyBytes || len(t.User) > MaxKeyBytes {
		return ErrTooLarge
	}
	if t.Question == "" {
		return ErrEmptyTurn
	}
	if len(t.Question) > MaxQuestionBytes || len(t.Answer) > MaxAnswerBytes {
		return ErrTooLarge
	}
	if !utf8.ValidString(t.Question) || !utf8.ValidString(t.Answer) {
		return ErrInvalidUTF8
	}
	return nil
}

// purgeLocked drops the expired turns of session and removes the session when
// none is left. The caller holds s.mu.
func (s *Store) purgeLocked(key string, now time.Time) {
	sess, ok := s.sessions[key]
	if !ok {
		return
	}
	sess.turns = live(sess.turns, now)
	if len(sess.turns) == 0 {
		delete(s.sessions, key)
	}
}

// sweepLocked purges every session. The caller holds s.mu.
func (s *Store) sweepLocked(now time.Time) {
	for key, sess := range s.sessions {
		sess.turns = live(sess.turns, now)
		if len(sess.turns) == 0 {
			delete(s.sessions, key)
		}
	}
}

// live returns the turns that are still available at now, in order. A turn is
// available while now is before its appended time plus MaxAge.
func live(turns []timed, now time.Time) []timed {
	kept := turns[:0]
	for _, e := range turns {
		if now.Before(e.at.Add(MaxAge)) {
			kept = append(kept, e)
		}
	}
	// Clear the tail that was filtered out, so the dropped turns no longer
	// reference their question and answer text through the backing array.
	clear(turns[len(kept):])
	return kept
}
