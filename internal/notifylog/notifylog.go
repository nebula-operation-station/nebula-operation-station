// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notifylog stores the notification log and inbox (ADR 0016 D10):
// one row per notification event that was sent, held back by the rate
// limit, held back by a mute, or failed to send.
//
// The log is structured data only: host label, kind, state, reason, the
// execution ID, a NOS link and counts. It never holds a provider token, a
// provider target URL or log text. Every text field is cleaned on write
// (control, bidi and zero-width runes become U+FFFD, line breaks become
// spaces) and bounded in bytes. A field over its limit is shortened and
// marked in Entry.Changed; it is never rejected, because a log must not lose
// a message. Time is injected through New, so retention is testable.
//
// The package does not send notifications and is not wired into the server
// yet; the caller appends after each decision and runs Prune periodically.
package notifylog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Retention is how long entries are kept. Prune removes older entries.
const Retention = 30 * 24 * time.Hour

// MaxEntries is the number of newest entries Prune keeps.
const MaxEntries = 5000

// MaxPage is the largest number of entries List returns in one call.
const MaxPage = 100

// Byte limits for text fields. They match the CHECK constraints in
// migration 0045_notify_log.sql.
const (
	MaxKind        = 64
	MaxHost        = 64
	MaxState       = 64
	MaxReason      = 300
	MaxExecutionID = 128
	MaxLink        = 256
	// MaxProviders is the largest provider count stored. Larger counts are
	// clamped; a count is never a message, so clamping loses nothing.
	MaxProviders = 16
)

// Outcome is what happened to one notification event.
type Outcome string

// Outcomes. The values are stored as-is and must match the CHECK constraint
// in migration 0045.
const (
	OutcomeSent          Outcome = "sent"
	OutcomeHeldRateLimit Outcome = "held_rate_limit"
	OutcomeHeldMuted     Outcome = "held_muted"
	OutcomeFailed        Outcome = "failed"
)

func (o Outcome) valid() bool {
	switch o {
	case OutcomeSent, OutcomeHeldRateLimit, OutcomeHeldMuted, OutcomeFailed:
		return true
	}
	return false
}

// Field identifies one text field of an entry. Entry.Changed is a set of
// Fields.
type Field uint8

// Fields that can be shortened or dropped on write.
const (
	FieldKind Field = 1 << iota
	FieldHost
	FieldState
	FieldReason
	FieldExecutionID
	FieldLink
)

// Has reports whether f contains x.
func (f Field) Has(x Field) bool { return f&x != 0 }

// Record is one notification event to append. Text is untrusted in the
// sense that it is cleaned and bounded before it is stored.
type Record struct {
	// Kind is the event kind, for example "execution".
	Kind string
	// Host is the host label, not an address.
	Host string
	// State is the event state, for example "FAILED".
	State string
	// Reason is a short human-readable reason.
	Reason string
	// ExecutionID is the execution the event belongs to, if any.
	ExecutionID string
	// Link is a NOS UI link (a path starting with "/"). Anything else is
	// dropped on write; see Store.Append.
	Link string
	// Outcome is what happened to the event.
	Outcome Outcome
	// Providers is the number of notification providers the event was
	// addressed to. It is clamped to 0..MaxProviders.
	Providers int
}

// Entry is a stored record with its sequence number and write time.
type Entry struct {
	Record
	// Seq is the row sequence number. It increases with every append and is
	// never reused, so it orders entries and serves as the page cursor.
	Seq int64
	// At is when the entry was appended, in UTC, at one-second resolution.
	At time.Time
	// Changed is the set of fields that were shortened or dropped on write.
	Changed Field
}

// Store is the notification log backed by the server database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a Store on db. now is the clock used to stamp appended
// entries; nil means time.Now.
func New(db *sql.DB, now func() time.Time) (*Store, error) {
	if db == nil {
		return nil, errors.New("notifylog: new store: nil database")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}, nil
}

// Append stores r and returns its sequence number. Text fields are cleaned
// and shortened as described in the package comment. A Link that is not a
// NOS path (it must start with "/", not "//", and contain neither "://" nor
// "?") is stored empty and marked as changed. Only an unknown Outcome is an
// error, because it is a caller bug and not a property of the event.
func (s *Store) Append(ctx context.Context, r Record) (int64, error) {
	if !r.Outcome.valid() {
		return 0, fmt.Errorf("notifylog: append: unknown outcome %q", r.Outcome)
	}
	var changed Field
	kind, cut := clean(r.Kind, MaxKind)
	changed = mark(changed, FieldKind, cut)
	host, cut := clean(r.Host, MaxHost)
	changed = mark(changed, FieldHost, cut)
	state, cut := clean(r.State, MaxState)
	changed = mark(changed, FieldState, cut)
	reason, cut := clean(r.Reason, MaxReason)
	changed = mark(changed, FieldReason, cut)
	execID, cut := clean(r.ExecutionID, MaxExecutionID)
	changed = mark(changed, FieldExecutionID, cut)

	var link string
	if isNOSLink(r.Link) {
		link, cut = clean(r.Link, MaxLink)
		changed = mark(changed, FieldLink, cut)
	} else {
		changed |= FieldLink
	}

	providers := min(max(r.Providers, 0), MaxProviders)

	res, err := s.db.ExecContext(ctx, `INSERT INTO notify_log
		(at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.now().UTC().Unix(), kind, host, state, reason, execID, link, string(r.Outcome), providers, int(changed))
	if err != nil {
		return 0, fmt.Errorf("notifylog: append: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("notifylog: append: last id: %w", err)
	}
	return seq, nil
}

// List returns up to limit entries, newest first. Pass afterSeq 0 for the
// newest page; for the next page pass the Seq of the last entry of the
// previous page. Entries with Seq >= afterSeq are not returned, so entries
// appended between two calls never shift a page. limit must be at least 1;
// values above MaxPage are reduced to MaxPage.
func (s *Store) List(ctx context.Context, afterSeq int64, limit int) ([]Entry, error) {
	if limit < 1 {
		return nil, fmt.Errorf("notifylog: list: limit %d must be at least 1", limit)
	}
	limit = min(limit, MaxPage)
	cursor := afterSeq
	if afterSeq <= 0 {
		cursor = math.MaxInt64
	}
	rows, err := s.db.QueryContext(ctx, `SELECT seq, at, kind, host, state, reason,
		execution_id, link, outcome, providers, changed
		FROM notify_log WHERE seq < ? ORDER BY seq DESC LIMIT ?`, cursor, limit)
	if err != nil {
		return nil, fmt.Errorf("notifylog: list: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var (
			e       Entry
			at      int64
			outcome string
			changed int
		)
		if err := rows.Scan(&e.Seq, &at, &e.Kind, &e.Host, &e.State, &e.Reason,
			&e.ExecutionID, &e.Link, &outcome, &e.Providers, &changed); err != nil {
			return nil, fmt.Errorf("notifylog: list: scan: %w", err)
		}
		e.At = time.Unix(at, 0).UTC()
		e.Outcome = Outcome(outcome)
		e.Changed = Field(changed)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notifylog: list: %w", err)
	}
	return out, nil
}

// Prune removes entries older than Retention relative to now (an entry
// written exactly Retention ago is kept), then removes the oldest entries
// beyond MaxEntries. It returns the number of entries removed.
func (s *Store) Prune(ctx context.Context, now time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("notifylog: prune: begin: %w", err)
	}
	defer tx.Rollback()

	cutoff := now.Add(-Retention).UTC().Unix()
	res, err := tx.ExecContext(ctx, `DELETE FROM notify_log WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("notifylog: prune by age: %w", err)
	}
	byAge, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("notifylog: prune by age: %w", err)
	}

	res, err = tx.ExecContext(ctx, `DELETE FROM notify_log WHERE seq IN
		(SELECT seq FROM notify_log ORDER BY seq DESC LIMIT -1 OFFSET ?)`, MaxEntries)
	if err != nil {
		return 0, fmt.Errorf("notifylog: prune by count: %w", err)
	}
	byCount, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("notifylog: prune by count: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("notifylog: prune: commit: %w", err)
	}
	return byAge + byCount, nil
}

// mark adds f to set when cut is true.
func mark(set, f Field, cut bool) Field {
	if cut {
		return set | f
	}
	return set
}

// isNOSLink reports whether s looks like a NOS UI path. It rejects absolute
// URLs, scheme-relative URLs and query strings, where provider tokens live.
func isNOSLink(s string) bool {
	return strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") &&
		!strings.Contains(s, "://") && !strings.Contains(s, "?")
}

// clean returns s with line breaks turned into spaces and every control,
// format (zero-width, soft hyphen, bidi) or otherwise non-printable rune
// replaced by U+FFFD. It keeps whole runes only, so the result is valid
// UTF-8 of at most limit bytes. cut reports whether text was dropped
// because of the limit.
func clean(s string, limit int) (out string, cut bool) {
	var b strings.Builder
	b.Grow(min(len(s), limit))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r):
			r = utf8.RuneError
		}
		if b.Len()+utf8.RuneLen(r) > limit {
			return b.String(), true
		}
		b.WriteRune(r)
	}
	return b.String(), false
}
