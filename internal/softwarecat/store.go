// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Store limits, next to the code that enforces them (ADR 0009 D7).
const (
	// MaxCatalogEntries bounds the number of catalog rows. Automatic
	// creation stops at this bound; observations of keys without an
	// entry are then refused and counted as limited.
	MaxCatalogEntries = 20_000
	// MaxQueueEntriesPerHost bounds the "observed" (unknown) catalog
	// entries one managed host may create, so one host cannot flood the
	// unknown queue or exhaust MaxCatalogEntries for everyone else.
	MaxQueueEntriesPerHost = 1_000
	// MaxObservationsPerHost bounds the observation rows of one managed
	// host (all its targets and source actions together).
	MaxObservationsPerHost = 5_000
	// MaxQueuePage bounds one page of the unknown queue, of the icon
	// history and of a host's observations.
	MaxQueuePage = 500

	// maxHostIDLen bounds a managed host ID (as in the placements
	// table).
	maxHostIDLen = 63
	// maxTargetRefLen bounds a guest reference.
	maxTargetRefLen = 128
	// maxIdentifierLen bounds the stored raw identifier.
	maxIdentifierLen = 256
	// maxVersionLen bounds a stored version.
	maxVersionLen = 128
	// maxDisplayLen bounds a display name.
	maxDisplayLen = 128
	// maxActorLen bounds an admin user name.
	maxActorLen = 64
	// maxDetailLen bounds the detail text of an audit row.
	maxDetailLen = 4096
)

// Sentinel errors callers branch on.
var (
	// ErrNotFound marks a missing catalog entry, asset, icon or history
	// row.
	ErrNotFound = errors.New("softwarecat: not found")
	// ErrInvalidInput marks a malformed argument: target, actor, display
	// name, time, icon hash or source.
	ErrInvalidInput = errors.New("softwarecat: invalid input")
	// ErrInvalidResult marks an action result that does not have the
	// expected form.
	ErrInvalidResult = errors.New("softwarecat: invalid action result")
	// ErrInvalidMerge marks a merge into itself or into an entry that is
	// itself merged.
	ErrInvalidMerge = errors.New("softwarecat: invalid merge")
	// ErrMerged marks an operation on an entry that is merged into
	// another one.
	ErrMerged = errors.New("softwarecat: entry is merged")
)

// State is the review state of a catalog entry.
type State string

// Catalog entry states.
const (
	// StateKnown is a reviewed entry: from the seed map or named by an
	// admin.
	StateKnown State = "known"
	// StateObserved is an entry created automatically from an unknown
	// identifier; unmerged observed entries form the unknown queue.
	StateObserved State = "observed"
	// StateIgnored is an entry an admin chose to ignore.
	StateIgnored State = "ignored"
)

// TargetKind is what an observation was seen on.
type TargetKind string

// Observation target kinds.
const (
	// TargetHost is the managed host itself.
	TargetHost TargetKind = "host"
	// TargetGuest is a guest identified by a server-side reference.
	TargetGuest TargetKind = "guest"
	// TargetContainer is a Docker container on the managed host,
	// identified by its full 64-digit ID.
	TargetContainer TargetKind = "container"
)

// Target names where an observation was made. HostID is the managed
// host the action ran on, from the server's own records (never from
// the result). Ref is empty for TargetHost, the full container ID for
// TargetContainer and a server-side guest reference (for example
// "<remote>/<vmid>") for TargetGuest.
type Target struct {
	Kind   TargetKind
	HostID string
	Ref    string
}

// Source actions observations are ingested from.
const (
	SourceCoreFacts   = "core.facts"
	SourceDockerList  = "docker.list"
	SourceGPUStatus   = "gpu.status"
	SourceServiceList = "service.list"
)

// Entry is one software catalog row.
type Entry struct {
	Key        Key
	Display    string
	State      State
	MergedInto Key    // "" unless merged
	IconSHA    string // "" for the generic symbol
	FirstHost  string // host whose observation created the entry, "" otherwise
	CreatedAt  time.Time
	UpdatedBy  string // "" until an admin changed the entry
	UpdatedAt  time.Time
}

// QueueEntry is an entry of the unknown queue with its observation
// summary.
type QueueEntry struct {
	Entry
	Observations int
	Hosts        int
	LastSeen     time.Time
}

// Observation is one stored observation.
type Observation struct {
	Target     Target
	Key        Key
	Identifier string // raw identifier as observed, display as text only
	Version    string
	Source     string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// IngestReport counts what one ingest call did.
type IngestReport struct {
	// Observed is the number of observations recorded or refreshed.
	Observed int
	// Created is the number of catalog entries created.
	Created int
	// Skipped is the number of identifiers that normalized to nothing.
	Skipped int
	// Limited is the number of observations refused by a cap.
	Limited int
}

// Options configures a Store.
type Options struct {
	// Now returns the current time for admin changes. Defaults to
	// time.Now.
	Now func() time.Time
}

// Store persists the software catalog, observations and icon references
// in the server database (migration 0032).
type Store struct {
	db  *sql.DB
	now func() time.Time
	// caps, defaulted from the constants above; tests may lower them.
	maxCatalog, maxQueuePerHost, maxObsPerHost int
}

// NewStore returns a Store on an open server database.
func NewStore(db *sql.DB, opts Options) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("softwarecat: nil database: %w", ErrInvalidInput)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Store{
		db: db, now: now,
		maxCatalog:      MaxCatalogEntries,
		maxQueuePerHost: MaxQueueEntriesPerHost,
		maxObsPerHost:   MaxObservationsPerHost,
	}, nil
}

// unsafeRune reports control characters (C0, DEL, C1), line and
// paragraph separators, bidirectional marks, embeddings, overrides and
// isolates, and the byte order mark (the same set as the result
// parsers in internal/executions).
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029, r == 0xfeff:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x206f:
		return true
	}
	return false
}

// printable reports whether s is 1 to limit bytes of valid UTF-8
// without unsafe characters and without leading or trailing space.
func printable(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unsafeRune(r) {
			return false
		}
	}
	return true
}

// cleanText makes untrusted host text storable: invalid UTF-8 and
// unsafe characters become U+FFFD, and the result is clipped to limit
// bytes at a rune boundary. Input beyond 4*limit bytes is cut first so
// the work stays bounded.
func cleanText(s string, limit int) string {
	if len(s) > 4*limit {
		s = s[:4*limit]
	}
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return utf8.RuneError
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= limit {
		return s
	}
	n := limit
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// validID reports whether s is a 1..limit byte identifier of ASCII
// letters, digits and ".:_/-" (host IDs, asset IDs, guest references).
func validID(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == ':' || c == '_' || c == '/' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// validHex64 reports whether s is 64 lowercase hex digits.
func validHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validate checks a target.
func (t Target) validate() error {
	if !validID(t.HostID, maxHostIDLen) {
		return fmt.Errorf("target host ID: %w", ErrInvalidInput)
	}
	switch t.Kind {
	case TargetHost:
		if t.Ref != "" {
			return fmt.Errorf("host target with a reference: %w", ErrInvalidInput)
		}
	case TargetGuest:
		if !validID(t.Ref, maxTargetRefLen) {
			return fmt.Errorf("guest reference: %w", ErrInvalidInput)
		}
	case TargetContainer:
		if !validHex64(t.Ref) {
			return fmt.Errorf("container reference is not a full container ID: %w", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("target kind %q: %w", t.Kind, ErrInvalidInput)
	}
	return nil
}

func validActor(actor string) error {
	if !printable(actor, maxActorLen) {
		return fmt.Errorf("actor: %w", ErrInvalidInput)
	}
	return nil
}

func validSource(src string) bool {
	switch src {
	case SourceCoreFacts, SourceDockerList, SourceGPUStatus, SourceServiceList:
		return true
	}
	return false
}

// beginWrite starts a write transaction and takes the write lock first,
// so caps read inside it cannot change underneath.
func (s *Store) beginWrite(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE software_catalog_lock SET n = n + 1 WHERE id = 1`); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("lock: %w", err)
	}
	return tx, nil
}

// audit appends an admin change to software_catalog_audit inside tx.
func audit(ctx context.Context, tx *sql.Tx, at time.Time, actor, action, subject, detail string) error {
	if len(detail) > maxDetailLen {
		detail = cleanText(detail, maxDetailLen)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO software_catalog_audit (at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)`,
		at.UnixNano(), actor, action, subject, detail); err != nil {
		return fmt.Errorf("audit %s %s: %w", action, subject, err)
	}
	return nil
}

// item is one normalized observation ready for the database.
type item struct {
	target     Target
	res        Result
	identifier string
	version    string
	source     string
}

// observe records items observed at at in one transaction. Unknown
// keys create observed entries; nothing else (placements, assets,
// hosts) is ever written.
func (s *Store) observe(ctx context.Context, items []item, at time.Time) (IngestReport, error) {
	var rep IngestReport
	if at.IsZero() {
		return rep, fmt.Errorf("observation time: %w", ErrInvalidInput)
	}
	for _, it := range items {
		if err := it.target.validate(); err != nil {
			return rep, err
		}
		if !validSource(it.source) {
			return rep, fmt.Errorf("source action %q: %w", it.source, ErrInvalidInput)
		}
	}
	if len(items) == 0 {
		return rep, nil
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return rep, fmt.Errorf("record observations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ts := at.UnixNano()
	for _, it := range items {
		if it.res.Key == unknownKey {
			rep.Skipped++
			continue
		}
		if _, err := NewKey(string(it.res.Key)); err != nil {
			rep.Skipped++
			continue
		}
		created, ok, err := s.ensureEntry(ctx, tx, it, ts)
		if err != nil {
			return IngestReport{}, err
		}
		if !ok {
			rep.Limited++
			continue
		}
		if created {
			rep.Created++
		}
		ok, err = s.upsertObservation(ctx, tx, it, ts)
		if err != nil {
			return IngestReport{}, err
		}
		if !ok {
			rep.Limited++
			continue
		}
		rep.Observed++
	}
	if err := tx.Commit(); err != nil {
		return IngestReport{}, fmt.Errorf("record observations: commit: %w", err)
	}
	return rep, nil
}

// ensureEntry makes sure the item's key has a catalog entry. It reports
// whether it created one and whether the key may be observed (false when
// a cap refused the creation).
func (s *Store) ensureEntry(ctx context.Context, tx *sql.Tx, it item, ts int64) (created, ok bool, err error) {
	key := string(it.res.Key)
	var state, updatedBy string
	err = tx.QueryRowContext(ctx, `SELECT state, updated_by FROM software_catalog WHERE key = ?`, key).Scan(&state, &updatedBy)
	switch {
	case err == nil:
		// A key that became known through a seed map update is
		// promoted, unless an admin already decided about it.
		if it.res.Known && State(state) == StateObserved && updatedBy == "" {
			if _, err := tx.ExecContext(ctx,
				`UPDATE software_catalog SET state = 'known', display = ?, updated_at = ? WHERE key = ?`,
				it.res.Display, ts, key); err != nil {
				return false, false, fmt.Errorf("promote catalog entry %s: %w", key, err)
			}
		}
		return false, true, nil
	case !errors.Is(err, sql.ErrNoRows):
		return false, false, fmt.Errorf("read catalog entry %s: %w", key, err)
	}
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM software_catalog`).Scan(&total); err != nil {
		return false, false, fmt.Errorf("count catalog: %w", err)
	}
	if total >= s.maxCatalog {
		return false, false, nil
	}
	state, display := string(StateKnown), it.res.Display
	if !it.res.Known {
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM software_catalog WHERE first_host = ? AND state = 'observed'`,
			it.target.HostID).Scan(&n); err != nil {
			return false, false, fmt.Errorf("count queue entries of host %s: %w", it.target.HostID, err)
		}
		if n >= s.maxQueuePerHost {
			return false, false, nil
		}
		state, display = string(StateObserved), ""
	}
	if len(display) > maxDisplayLen {
		display = cleanText(display, maxDisplayLen)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO software_catalog (key, display, state, first_host, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		key, display, state, it.target.HostID, ts, ts); err != nil {
		return false, false, fmt.Errorf("create catalog entry %s: %w", key, err)
	}
	return true, true, nil
}

// upsertObservation inserts or refreshes one observation. It reports
// false when the host's observation cap refused a new row.
func (s *Store) upsertObservation(ctx context.Context, tx *sql.Tx, it item, ts int64) (bool, error) {
	ident := cleanText(it.identifier, maxIdentifierLen)
	version := cleanText(it.version, maxVersionLen)
	t := it.target
	var id, last int64
	err := tx.QueryRowContext(ctx,
		`SELECT id, last_seen FROM software_observations
		 WHERE host_id = ? AND target_kind = ? AND target_ref = ? AND source_action = ? AND key = ?`,
		t.HostID, string(t.Kind), t.Ref, it.source, string(it.res.Key)).Scan(&id, &last)
	switch {
	case err == nil:
		if ts < last {
			// An older result never overwrites a newer one.
			return true, nil
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE software_observations SET identifier = ?, version = ?, last_seen = ? WHERE id = ?`,
			ident, version, ts, id); err != nil {
			return false, fmt.Errorf("refresh observation %d: %w", id, err)
		}
		return true, nil
	case !errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("read observation: %w", err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM software_observations WHERE host_id = ?`, t.HostID).Scan(&n); err != nil {
		return false, fmt.Errorf("count observations of host %s: %w", t.HostID, err)
	}
	if n >= s.maxObsPerHost {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO software_observations
		 (host_id, target_kind, target_ref, key, identifier, version, source_action, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.HostID, string(t.Kind), t.Ref, string(it.res.Key), ident, version, it.source, ts, ts); err != nil {
		return false, fmt.Errorf("insert observation: %w", err)
	}
	return true, nil
}

const entryColumns = `key, display, state, merged_into, COALESCE(icon_sha, ''), first_host, created_at, updated_by, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanEntry(r rowScanner, extra ...any) (Entry, error) {
	var e Entry
	var key, state, merged string
	var created, updated int64
	dest := append([]any{&key, &e.Display, &state, &merged, &e.IconSHA, &e.FirstHost, &created, &e.UpdatedBy, &updated}, extra...)
	if err := r.Scan(dest...); err != nil {
		return Entry{}, err
	}
	e.Key, e.State, e.MergedInto = Key(key), State(state), Key(merged)
	e.CreatedAt, e.UpdatedAt = time.Unix(0, created), time.Unix(0, updated)
	return e, nil
}

func getEntry(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key Key) (Entry, error) {
	e, err := scanEntry(q.QueryRowContext(ctx, `SELECT `+entryColumns+` FROM software_catalog WHERE key = ?`, string(key)))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, fmt.Errorf("catalog entry %s: %w", key, ErrNotFound)
	}
	if err != nil {
		return Entry{}, fmt.Errorf("read catalog entry %s: %w", key, err)
	}
	return e, nil
}

// Entry returns the catalog entry for key.
func (s *Store) Entry(ctx context.Context, key Key) (Entry, error) {
	if _, err := NewKey(string(key)); err != nil {
		return Entry{}, err
	}
	return getEntry(ctx, s.db, key)
}

// Resolve returns the effective entry for key: the merge target if key
// is merged, the entry itself otherwise. Merges are one level deep.
func (s *Store) Resolve(ctx context.Context, key Key) (Entry, error) {
	e, err := s.Entry(ctx, key)
	if err != nil || e.MergedInto == "" {
		return e, err
	}
	return getEntry(ctx, s.db, e.MergedInto)
}

// UnknownQueue returns up to limit (at most MaxQueuePage) observed,
// unmerged entries with their observation counts, most recently seen
// first.
func (s *Store) UnknownQueue(ctx context.Context, limit int) ([]QueueEntry, error) {
	if limit <= 0 || limit > MaxQueuePage {
		limit = MaxQueuePage
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+entryColumns+`,
		       (SELECT COUNT(*) FROM software_observations o WHERE o.key = c.key),
		       (SELECT COUNT(DISTINCT host_id) FROM software_observations o WHERE o.key = c.key),
		       COALESCE((SELECT MAX(last_seen) FROM software_observations o WHERE o.key = c.key), 0)
		FROM software_catalog c
		WHERE c.state = 'observed' AND c.merged_into = ''
		ORDER BY 12 DESC, c.key
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("read unknown queue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []QueueEntry
	for rows.Next() {
		var q QueueEntry
		var last int64
		e, err := scanEntry(rows, &q.Observations, &q.Hosts, &last)
		if err != nil {
			return nil, fmt.Errorf("read unknown queue: %w", err)
		}
		q.Entry = e
		if last > 0 {
			q.LastSeen = time.Unix(0, last)
		}
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read unknown queue: %w", err)
	}
	return out, nil
}

// Observations returns the observations of one managed host (at most
// MaxObservationsPerHost rows), ordered by target, source and key.
func (s *Store) Observations(ctx context.Context, hostID string) ([]Observation, error) {
	if !validID(hostID, maxHostIDLen) {
		return nil, fmt.Errorf("host ID: %w", ErrInvalidInput)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT target_kind, target_ref, key, identifier, version, source_action, first_seen, last_seen
		FROM software_observations WHERE host_id = ?
		ORDER BY target_kind, target_ref, source_action, key
		LIMIT ?`, hostID, MaxObservationsPerHost)
	if err != nil {
		return nil, fmt.Errorf("read observations of host %s: %w", hostID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []Observation
	for rows.Next() {
		o := Observation{Target: Target{HostID: hostID}}
		var kind, key string
		var first, last int64
		if err := rows.Scan(&kind, &o.Target.Ref, &key, &o.Identifier, &o.Version, &o.Source, &first, &last); err != nil {
			return nil, fmt.Errorf("read observations of host %s: %w", hostID, err)
		}
		o.Target.Kind, o.Key = TargetKind(kind), Key(key)
		o.FirstSeen, o.LastSeen = time.Unix(0, first), time.Unix(0, last)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read observations of host %s: %w", hostID, err)
	}
	return out, nil
}

// PruneObservations removes observations last seen before cutoff (for
// example containers that no longer exist). Catalog entries stay.
func (s *Store) PruneObservations(ctx context.Context, cutoff time.Time) (int64, error) {
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return 0, fmt.Errorf("prune observations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM software_observations WHERE last_seen < ?`, cutoff.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("prune observations: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune observations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("prune observations: commit: %w", err)
	}
	return n, nil
}

// Rename sets the display name of key. Naming an entry is an admin
// decision about it, so the entry becomes known (it leaves the unknown
// queue, or stops being ignored). A merged entry cannot be renamed.
func (s *Store) Rename(ctx context.Context, actor string, key Key, display string) error {
	if err := validActor(actor); err != nil {
		return err
	}
	if _, err := NewKey(string(key)); err != nil {
		return err
	}
	if !printable(display, maxDisplayLen) {
		return fmt.Errorf("display name: %w", ErrInvalidInput)
	}
	return s.adminChange(ctx, func(tx *sql.Tx, now time.Time) error {
		e, err := getEntry(ctx, tx, key)
		if err != nil {
			return err
		}
		if e.MergedInto != "" {
			return fmt.Errorf("rename %s (merged into %s): %w", key, e.MergedInto, ErrMerged)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE software_catalog SET display = ?, state = 'known', updated_by = ?, updated_at = ? WHERE key = ?`,
			display, actor, now.UnixNano(), string(key)); err != nil {
			return fmt.Errorf("rename %s: %w", key, err)
		}
		return audit(ctx, tx, now, actor, "rename", string(key),
			fmt.Sprintf("display %q (was %q), state known (was %s)", display, e.Display, e.State))
	})
}

// Merge merges key from into key into: from resolves to into from now
// on, and entries already merged into from are re-pointed to into, so
// merges stay one level deep. into must exist and must not be merged
// itself.
func (s *Store) Merge(ctx context.Context, actor string, from, into Key) error {
	if err := validActor(actor); err != nil {
		return err
	}
	if _, err := NewKey(string(from)); err != nil {
		return err
	}
	if _, err := NewKey(string(into)); err != nil {
		return err
	}
	if from == into {
		return fmt.Errorf("merge %s into itself: %w", from, ErrInvalidMerge)
	}
	return s.adminChange(ctx, func(tx *sql.Tx, now time.Time) error {
		src, err := getEntry(ctx, tx, from)
		if err != nil {
			return err
		}
		dst, err := getEntry(ctx, tx, into)
		if err != nil {
			return err
		}
		if dst.MergedInto != "" {
			return fmt.Errorf("merge %s into %s (merged into %s): %w", from, into, dst.MergedInto, ErrInvalidMerge)
		}
		ts := now.UnixNano()
		if _, err := tx.ExecContext(ctx,
			`UPDATE software_catalog SET merged_into = ?, updated_by = ?, updated_at = ? WHERE key = ?`,
			string(into), actor, ts, string(from)); err != nil {
			return fmt.Errorf("merge %s into %s: %w", from, into, err)
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE software_catalog SET merged_into = ?, updated_by = ?, updated_at = ? WHERE merged_into = ?`,
			string(into), actor, ts, string(from))
		if err != nil {
			return fmt.Errorf("re-point merges of %s: %w", from, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("re-point merges of %s: %w", from, err)
		}
		return audit(ctx, tx, now, actor, "merge", string(from),
			fmt.Sprintf("into %s (was %q), re-pointed %d", into, src.MergedInto, n))
	})
}

// Ignore marks key as ignored: it leaves the unknown queue and later
// observations do not bring it back. Observations are still recorded.
func (s *Store) Ignore(ctx context.Context, actor string, key Key) error {
	if err := validActor(actor); err != nil {
		return err
	}
	if _, err := NewKey(string(key)); err != nil {
		return err
	}
	return s.adminChange(ctx, func(tx *sql.Tx, now time.Time) error {
		e, err := getEntry(ctx, tx, key)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE software_catalog SET state = 'ignored', updated_by = ?, updated_at = ? WHERE key = ?`,
			actor, now.UnixNano(), string(key)); err != nil {
			return fmt.Errorf("ignore %s: %w", key, err)
		}
		return audit(ctx, tx, now, actor, "ignore", string(key), fmt.Sprintf("was %s", e.State))
	})
}

// adminChange runs fn in a write transaction with the store's clock and
// commits it. fn writes the change and its audit row, so both commit or
// neither does.
func (s *Store) adminChange(ctx context.Context, fn func(tx *sql.Tx, now time.Time) error) error {
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return fmt.Errorf("softwarecat: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx, s.now()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("softwarecat: commit: %w", err)
	}
	return nil
}

// AuditRecord is one row of the catalog's audit trail.
type AuditRecord struct {
	ID      int64
	At      time.Time
	Actor   string
	Action  string
	Subject string
	Detail  string
}

// AuditTrail returns up to limit (at most MaxQueuePage) audit rows,
// newest first.
func (s *Store) AuditTrail(ctx context.Context, limit int) ([]AuditRecord, error) {
	if limit <= 0 || limit > MaxQueuePage {
		limit = MaxQueuePage
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, subject, detail FROM software_catalog_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("read catalog audit: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRecord
	for rows.Next() {
		var a AuditRecord
		var at int64
		if err := rows.Scan(&a.ID, &at, &a.Actor, &a.Action, &a.Subject, &a.Detail); err != nil {
			return nil, fmt.Errorf("read catalog audit: %w", err)
		}
		a.At = time.Unix(0, at)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read catalog audit: %w", err)
	}
	return out, nil
}
