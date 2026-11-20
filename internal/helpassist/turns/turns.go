// SPDX-License-Identifier: AGPL-3.0-or-later

package turns

import (
	"context"
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

// MaxSessions is the number of sessions held at the same time. Expired sessions
// are removed before the limit is checked; if none is expired the new session
// is refused.
const MaxSessions = 1024

// MaxSessionsPerUser is the number of live sessions one user may hold. It stops
// a single user from taking every slot of MaxSessions and locking others out.
const MaxSessionsPerUser = 8

// SweepEvery is the interval the owner of a Store should pass to Run. Every
// Append and History also sweeps, so the interval only bounds how long the
// text of an idle session stays in memory after MaxAge.
const SweepEvery = time.Minute

// ErrBadInterval reports a non-positive sweep interval passed to Run.
var ErrBadInterval = errors.New("turns: sweep interval must be positive")

// ErrEmptyKey reports a turn whose session key or user name is empty.
var ErrEmptyKey = errors.New("turns: empty session or user key")

// ErrEmptyTurn reports a turn without a question.
var ErrEmptyTurn = errors.New("turns: empty question")

// ErrTooLarge reports a key, question or answer over its limit.
var ErrTooLarge = errors.New("turns: value exceeds size limit")

// ErrTooManySessions reports that MaxSessions live sessions are held and the
// new session cannot be opened.
var ErrTooManySessions = errors.New("turns: too many live sessions")

// ErrTooManySessionsForUser reports that the user already holds
// MaxSessionsPerUser live sessions.
var ErrTooManySessionsForUser = errors.New("turns: user holds too many live sessions")

// ErrSessionOwner reports a turn for a session that belongs to another user.
var ErrSessionOwner = errors.New("turns: session belongs to another user")

// ErrLoggedOut reports a turn whose request started before the user logged out.
// Such a turn is refused, so the text of a request that crosses logout is never
// stored.
var ErrLoggedOut = errors.New("turns: user logged out while the request was running")

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
	now       func() time.Time
	newTicker func(time.Duration) (<-chan time.Time, func())
	mu        sync.Mutex
	sessions  map[string]*panelSession
	// epochs holds, per user, the logout epoch. ClearUser increments it, so a
	// request that read the epoch before a logout cannot store a turn after it.
	// It has one entry per user that logged out while the process runs.
	epochs map[string]uint64
}

// New returns an empty Store that reads the time from now. A nil now uses
// time.Now.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		now:       now,
		newTicker: realTicker,
		sessions:  make(map[string]*panelSession),
		epochs:    make(map[string]uint64),
	}
}

// realTicker starts a time.Ticker and returns its channel and stop function.
func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Epoch returns the logout epoch of user. A request reads it before it reads the
// history and calls the language model, and passes it to Append. The value
// changes when the user logs out.
func (s *Store) Epoch(user string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epochs[user]
}

// Append stores t as the newest turn of session. epoch is the value Epoch
// returned for t.User when the request started. It returns an error wrapping
// one of the package's sentinel errors when the turn or the session cannot be
// stored; the store is then unchanged. The oldest turn is dropped when the
// session already holds MaxTurns turns. A turn whose epoch is no longer current
// (the user logged out after the request started) fails with ErrLoggedOut.
func (s *Store) Append(session string, epoch uint64, t Turn) error {
	if err := validate(session, t); err != nil {
		return fmt.Errorf("append turn: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked(now)
	if s.epochs[t.User] != epoch {
		return fmt.Errorf("append turn: %w", ErrLoggedOut)
	}
	sess, ok := s.sessions[session]
	if ok && sess.owner != t.User {
		return fmt.Errorf("append turn: %w", ErrSessionOwner)
	}
	if !ok {
		owned := 0
		for _, other := range s.sessions {
			if other.owner == t.User {
				owned++
			}
		}
		if owned >= MaxSessionsPerUser {
			return fmt.Errorf("append turn: %w", ErrTooManySessionsForUser)
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

// History returns a copy of the live turns of session, oldest first, when user
// owns session. Expired turns are removed and not returned. A session with no
// live turns, a session of another user and an empty user all yield nil.
// Changing the returned slice does not change the store.
func (s *Store) History(session, user string) []Turn {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	sess, ok := s.sessions[session]
	if !ok || sess.owner != user || len(sess.turns) == 0 {
		return nil
	}
	out := make([]Turn, 0, len(sess.turns))
	for _, e := range sess.turns {
		out = append(out, e.turn)
	}
	return out
}

// Sweep removes every expired turn of every session, including sessions that
// nobody accesses again. It is safe to call at any time.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
}

// Run calls Sweep every interval until ctx is done, then returns ctx.Err(). The
// owner of the Store starts Run in its own goroutine (with interval SweepEvery)
// so that idle sessions expire without any request. It returns ErrBadInterval
// wrapped when interval is not positive.
func (s *Store) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("run sweeper: %w", ErrBadInterval)
	}
	ticks, stop := s.newTicker(interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			s.Sweep()
		}
	}
}

// Clear removes session and all its turns. Other sessions are not affected.
func (s *Store) Clear(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, session)
}

// ClearUser removes every session owned by user, for example at logout, and
// advances the user's epoch so that requests started before the call cannot
// store a turn after it. The sessions of other users are not affected.
func (s *Store) ClearUser(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epochs[user]++
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

// sweepLocked purges the expired turns of every session and removes the
// sessions left empty. It is bounded by MaxSessions times MaxTurns. The caller
// holds s.mu.
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
