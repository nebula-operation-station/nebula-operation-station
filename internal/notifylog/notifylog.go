// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notifylog stores the notification log and inbox (ADR 0016 D10):
// one row per notification event that was sent, held back by the rate
// limit, held back by a mute, or failed to send.
//
// The log is structured data only: host ID, kind, state, reason, the
// execution ID, a NOS link and counts. It never holds a provider token, a
// provider target URL or log text. Kind, State, Reason and Outcome are closed
// sets. Host must be an inventory host ID (or empty, for an event with no
// host) and ExecutionID a lowercase UUIDv4 (or empty), the same forms the
// inventory and the executions package use (see validHost and
// validExecutionID). A value that does not match is refused with ErrRefused,
// and the error names the field but never the value, so a refused input
// cannot leak through an error or a log line that wraps it. The guarantee is
// the ID shape: a value that is not a valid ID is refused, and nothing more is
// claimed. A token that has the inventory shape is a valid host ID, so
// callers must never pass a secret as a host. A caller must pass the
// inventory ID, not a display name. A link that is not
// a NOS path, or is too long, is dropped and marked in Entry.Changed. Time is
// injected through New, so retention is testable.
//
// The package does not send notifications and is not wired into the server
// yet; the caller appends after each decision. Append keeps the table within
// MaxEntries itself, and Prune removes entries past Retention.
package notifylog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Retention is how long entries are kept. Prune removes older entries.
const Retention = 30 * 24 * time.Hour

// MaxEntries is the number of newest entries kept. Append trims the oldest
// rows beyond it in the same transaction as each insert, so a flood of events
// cannot grow the table between prune runs.
const MaxEntries = 5000

// ErrRefused is returned by Append when a field holds a value it may not hold:
// a value that is not a closed code, or a host ID or execution ID with the
// wrong shape. Callers branch on it with errors.Is. The error names the field;
// it never includes the value.
var ErrRefused = errors.New("notifylog: record refused")

// execIDRe is the execution ID form: a lowercase UUIDv4, as executions.newUUID
// generates it. canonical has the same pattern, but its copy is unexported.
var execIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// validHost reports whether s is empty (no host) or exactly an inventory host
// ID: canonical.ValidHostID, the pattern the inventory checks (lowercase
// letters, digits, '.', '_', '-', at most 63 bytes). Nothing stricter and
// nothing looser. There is no secret detector here: a value that does not
// have the ID shape is refused, and a value that does is a valid host ID.
func validHost(s string) bool {
	return s == "" || canonical.ValidHostID(s)
}

// validExecutionID reports whether s is empty or a lowercase UUIDv4.
func validExecutionID(s string) bool {
	return s == "" || execIDRe.MatchString(s)
}

// refused builds the error for a refused field. why names the field and the
// rule, and must never contain the input value.
func refused(why string) error {
	return fmt.Errorf("%w: append: %s", ErrRefused, why)
}

// MaxPage is the largest number of entries List returns in one call.
const MaxPage = 100

// Byte limits for the free-text fields. They match the CHECK constraints in
// migration 0045_notify_log.sql. Kind, State, Reason and Outcome are closed
// sets and have no byte limit: they are refused unless they are a code. Host
// and ExecutionID have a fixed form (see validHost and validExecutionID) and
// are refused unless they match it, so they never need cutting.
const (
	MaxHost        = 64
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

// ReasonCode says why an event was held back or failed. It is a closed set:
// free text is never stored, so a provider error text, a target URL or a
// token cannot reach the log through the reason. The values are stored as-is
// and must match the CHECK constraint in migration 0045.
type ReasonCode string

// Reason codes. ReasonNone is the empty code, for events with no reason
// (for example a sent event).
const (
	ReasonNone                ReasonCode = ""
	ReasonRateLimited         ReasonCode = "rate_limited"
	ReasonMuted               ReasonCode = "muted"
	ReasonProviderUnreachable ReasonCode = "provider_unreachable"
	ReasonProviderRejected    ReasonCode = "provider_rejected"
	ReasonTimeout             ReasonCode = "timeout"
	ReasonInternal            ReasonCode = "internal"
)

func (c ReasonCode) valid() bool {
	switch c {
	case ReasonNone, ReasonRateLimited, ReasonMuted, ReasonProviderUnreachable,
		ReasonProviderRejected, ReasonTimeout, ReasonInternal:
		return true
	}
	return false
}

// KindCode is the event kind: the notification event that was decided on. It
// is a closed set, so free text, URLs and tokens cannot be stored through it.
// The values are the event types of spec 13 (plus the digest) and must match
// the CHECK constraint in migration 0045.
type KindCode string

// Event kinds.
const (
	KindVulnKEVNew              KindCode = "vuln.kev_new"
	KindVulnCriticalNew         KindCode = "vuln.critical_new"
	KindVulnHermesStale         KindCode = "vuln.hermes_stale"
	KindVulnFeedStale           KindCode = "vuln.feed_stale"
	KindVulnFeedRegressed       KindCode = "vuln.feed_regressed"
	KindVulnFeedMarkReset       KindCode = "vuln.feed_mark_reset"
	KindIntegrityNOSMismatch    KindCode = "integrity.nos_mismatch"
	KindIntegrityHostChange     KindCode = "integrity.host_change"
	KindIntegrityScanIncomplete KindCode = "integrity.scan_incomplete"
	KindIntegrityBaselineTamper KindCode = "integrity.baseline_tamper"
	KindLeaseExpiring           KindCode = "lease.expiring"
	KindLeaseRunFailed          KindCode = "lease.run_failed"
	KindDigest                  KindCode = "digest"
	KindOpsSuggestionNew        KindCode = "opsagent.suggestion_new"
	KindOpsSettingsChanged      KindCode = "opsagent.settings_changed"
)

func (k KindCode) valid() bool {
	switch k {
	case KindVulnKEVNew, KindVulnCriticalNew, KindVulnHermesStale,
		KindVulnFeedStale, KindVulnFeedRegressed, KindVulnFeedMarkReset,
		KindIntegrityNOSMismatch, KindIntegrityHostChange, KindIntegrityScanIncomplete,
		KindIntegrityBaselineTamper, KindLeaseExpiring, KindLeaseRunFailed, KindDigest,
		KindOpsSuggestionNew, KindOpsSettingsChanged:
		return true
	}
	return false
}

// StateCode is the state an event reports, for example "expiring" or
// "mismatch". It is a closed set for the same reason as KindCode. The values
// must match the CHECK constraint in migration 0045.
type StateCode string

// Event states.
const (
	StateNew        StateCode = "new"
	StateEscalated  StateCode = "escalated"
	StateExpiring   StateCode = "expiring"
	StateFailed     StateCode = "failed"
	StateStale      StateCode = "stale"
	StateRegressed  StateCode = "regressed"
	StateMismatch   StateCode = "mismatch"
	StateIncomplete StateCode = "incomplete"
	StateTamper     StateCode = "tamper"
	StateChanged    StateCode = "changed"
	StateReset      StateCode = "reset"
	StateSummary    StateCode = "summary"
)

func (s StateCode) valid() bool {
	switch s {
	case StateNew, StateEscalated, StateExpiring, StateFailed, StateStale,
		StateRegressed, StateMismatch, StateIncomplete, StateTamper,
		StateChanged, StateReset, StateSummary:
		return true
	}
	return false
}

// ReasonForError maps an error from a notification provider to a reason
// code. It returns the code only, never err.Error(): a *url.Error carries the
// full target URL, and a Telegram URL carries the bot token in its path.
func ReasonForError(err error) ReasonCode {
	if err == nil {
		return ReasonNone
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return ReasonTimeout
		}
		return ReasonProviderUnreachable
	}
	return ReasonInternal
}

// Field identifies one text field of an entry. Entry.Changed is a set of
// Fields.
type Field uint8

// Fields that can be dropped on write. Kind, State, Reason and Outcome are
// closed sets and Host and ExecutionID are form-checked; a value that does not
// match is refused, not changed. FieldHost and FieldExecutionID are never set
// by Append now. They keep their bit values, so rows written earlier still
// decode the same way.
const (
	FieldHost Field = 1 << iota
	FieldExecutionID
	FieldLink
)

// Has reports whether f contains x.
func (f Field) Has(x Field) bool { return f&x != 0 }

// Record is one notification event to append. Text is untrusted in the
// sense that it is cleaned and bounded before it is stored.
type Record struct {
	// Kind is the event kind. Append rejects any value that is not a KindCode.
	Kind KindCode
	// Host is the inventory host ID, not a display name and not an address.
	// It must match validHost or Append refuses the record. A display name
	// (any UTF-8 text, spaces) is refused, so pass the ID.
	Host string
	// State is the event state. Append rejects any value that is not a
	// StateCode.
	State StateCode
	// Reason is a closed reason code. Append rejects any other value. Use
	// ReasonForError to map a provider error to a code.
	Reason ReasonCode
	// ExecutionID is the execution the event belongs to, if any. It must be a
	// lowercase UUIDv4 (validExecutionID) or Append refuses the record.
	ExecutionID string
	// Link is a NOS UI link (a path starting with "/", at most MaxLink bytes).
	// Anything else is dropped on write, never shortened; see Store.Append.
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
	// Changed is the set of fields that were dropped on write.
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

// Append stores r and returns its sequence number. Kind, State, Outcome and
// Reason must be codes, and Host and ExecutionID must match validHost and
// validExecutionID; otherwise Append returns an error wrapping ErrRefused that
// names the field and never the value. A Host or ExecutionID that does not
// match is refused, never cut. A Link that is not a NOS path (see
// IsNOSLink), or that is longer than MaxLink, is dropped: it is stored empty
// and marked as changed. An empty Link is no link at all and is not marked.
// In the same transaction as the insert, Append removes the oldest rows beyond
// MaxEntries, so the table stays bounded without a prune run.
func (s *Store) Append(ctx context.Context, r Record) (int64, error) {
	switch {
	case !r.Kind.valid():
		return 0, refused("kind is not an event kind")
	case !r.State.valid():
		return 0, refused("state is not a state code")
	case !r.Outcome.valid():
		return 0, refused("outcome is not an outcome code")
	case !r.Reason.valid():
		return 0, refused("reason is not a reason code")
	case !validHost(r.Host):
		return 0, refused("host is not an inventory host ID")
	case !validExecutionID(r.ExecutionID):
		return 0, refused("execution_id is not an execution ID")
	}
	var changed Field

	// IsNOSLink accepts printable ASCII only, so a valid link needs no
	// cleaning, and a link over the limit is dropped rather than cut: a cut
	// path could point at another or a nonexistent UI route.
	var link string
	switch {
	case r.Link == "":
	case IsNOSLink(r.Link):
		link = r.Link
	default:
		changed |= FieldLink
	}

	providers := min(max(r.Providers, 0), MaxProviders)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("notifylog: append: begin: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `INSERT INTO notify_log
		(at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.now().UTC().Unix(), string(r.Kind), r.Host, string(r.State), string(r.Reason), r.ExecutionID, link, string(r.Outcome), providers, int(changed))
	if err != nil {
		return 0, fmt.Errorf("notifylog: append: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("notifylog: append: last id: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_log WHERE seq IN
		(SELECT seq FROM notify_log ORDER BY seq DESC LIMIT -1 OFFSET ?)`, MaxEntries); err != nil {
		return 0, fmt.Errorf("notifylog: append: trim: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("notifylog: append: commit: %w", err)
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

// Prune removes entries older than Retention on the Store's clock (an entry
// written exactly Retention ago is kept), then removes the oldest entries
// beyond MaxEntries, which Append normally keeps within the cap already. It
// returns the number of entries removed. Prune reads the same clock as Append,
// so the retention boundary follows the injected time.
func (s *Store) Prune(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("notifylog: prune: begin: %w", err)
	}
	defer tx.Rollback()

	cutoff := s.now().Add(-Retention).UTC().Unix()
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

// IsNOSLink reports whether s is a plain NOS UI path such as
// "/executions/ex-1". It is the one link rule of the notification log: the
// store applies it on write, and the inbox page applies it again before it
// shows a link, so both checks share this code. Browsers normalize a link
// before they follow it: they turn backslashes into slashes and drop tabs and
// newlines. So the check is strict and runs before any cleaning. It rejects:
//   - anything that does not start with "/"
//   - anything longer than MaxLink bytes
//   - "//" anywhere (a scheme-relative URL, and an absolute URL such as
//     "/x://host", also after normalization)
//   - backslashes, "?" (query) and "#" (fragment), where tokens live
//   - bytes outside printable ASCII 0x21-0x7E: spaces, controls and non-ASCII
func IsNOSLink(s string) bool {
	if len(s) > MaxLink || !strings.HasPrefix(s, "/") {
		return false
	}
	if strings.Contains(s, "//") || strings.ContainsAny(s, `\?#`) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
