// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// busyTimeoutMS is how long a statement waits for a lock before it fails.
const busyTimeoutMS = 5000

// Store is the notes store. It is safe for concurrent use: the database
// holds one connection, so writes are serialised.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Note is a stored note.
type Note struct {
	ID         int64
	Kind       Kind
	Ref        string
	Digest     string
	Body       Body
	Snapshot   string
	CreatedAt  time.Time
	Superseded bool
	Dismissed  bool
}

// queryer is the subset of *sql.DB and *sql.Tx the store uses.
type queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Open opens or creates the notes database at path and applies pending
// migrations. The caller chooses path; it must not be inside the server
// backup set. now is the injected clock; nil means time.Now.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)&_journal_mode=WAL&_synchronous=FULL",
		path, busyTimeoutMS)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opsnotes: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, now: now}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("opsnotes: close: %w", err)
	}
	return nil
}

// migrate applies the embedded migrations in file-name order. The schema
// version is kept in user_version; migration n is the n-th file.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("opsnotes: read schema version: %w", err)
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("opsnotes: list migrations: %w", err)
	}
	for i, e := range entries {
		v := i + 1
		if v <= version {
			continue
		}
		script, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("opsnotes: read migration %s: %w", e.Name(), err)
		}
		if err := applyMigration(db, v, string(script)); err != nil {
			return fmt.Errorf("opsnotes: migration %s: %w", e.Name(), err)
		}
	}
	return nil
}

func applyMigration(db *sql.DB, version int, script string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(script); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return err
	}
	return tx.Commit()
}

// Put validates d against r and stores it with the caller's facts snapshot.
//
// Idempotent by (kind, ref, digest): the same body returns the stored note
// with created false and writes nothing; a different body returns
// ErrConflict. A stored note is pruned first (retention), then the daily
// limit is checked, then older notes of the same ref are marked superseded.
func (s *Store) Put(ctx context.Context, r Resolver, d Draft, snapshot string) (Note, bool, error) {
	if len(snapshot) > MaxSnapshotBytes {
		return Note{}, false, fmt.Errorf("snapshot: %d bytes, max %d: %w", len(snapshot), MaxSnapshotBytes, ErrLimit)
	}
	if !utf8.ValidString(snapshot) || !json.Valid([]byte(snapshot)) {
		return Note{}, false, fmt.Errorf("snapshot: %w", ErrInvalidSnapshot)
	}
	steps, err := Validate(d, r)
	if err != nil {
		return Note{}, false, err
	}
	body, err := json.Marshal(d.Body)
	if err != nil {
		return Note{}, false, fmt.Errorf("opsnotes: encode body: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Note{}, false, fmt.Errorf("opsnotes: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existingID int64
	var existingBody string
	err = tx.QueryRowContext(ctx,
		`SELECT id, body FROM notes WHERE kind = ? AND ref = ? AND digest = ?`,
		string(d.Kind), d.Ref, d.Digest).Scan(&existingID, &existingBody)
	switch {
	case err == nil:
		if existingBody != string(body) {
			return Note{}, false, fmt.Errorf("ref %s digest %s: %w", d.Ref, d.Digest, ErrConflict)
		}
		n, err := getNote(ctx, tx, existingID)
		if err != nil {
			return Note{}, false, err
		}
		return n, false, nil
	case errors.Is(err, sql.ErrNoRows):
	default:
		return Note{}, false, fmt.Errorf("opsnotes: lookup: %w", err)
	}

	now := s.now().UTC()
	// Make room first: the new note must leave the store within MaxNotes.
	if _, err := pruneTx(ctx, tx, now, MaxNotes-1); err != nil {
		return Note{}, false, err
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var today int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notes WHERE created_at >= ?`, dayStart.UnixNano()).Scan(&today); err != nil {
		return Note{}, false, fmt.Errorf("opsnotes: count today: %w", err)
	}
	if today >= MaxNotesPerDay {
		return Note{}, false, fmt.Errorf("day %s: %w", dayStart.Format(time.DateOnly), ErrDailyLimit)
	}
	// Supersession is scoped like idempotency and CurrentDigest: per kind and
	// ref, so a summary or answer never supersedes a fix note.
	if _, err := tx.ExecContext(ctx,
		`UPDATE notes SET superseded = 1 WHERE kind = ? AND ref = ? AND superseded = 0`,
		string(d.Kind), d.Ref); err != nil {
		return Note{}, false, fmt.Errorf("opsnotes: supersede: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO notes (kind, ref, digest, body, snapshot, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		string(d.Kind), d.Ref, d.Digest, string(body), snapshot, now.UnixNano())
	if err != nil {
		return Note{}, false, fmt.Errorf("opsnotes: insert note: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Note{}, false, fmt.Errorf("opsnotes: note ID: %w", err)
	}
	for _, st := range steps {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO steps (note_id, idx, action_id, family, host_id, why) VALUES (?, ?, ?, ?, ?, ?)`,
			id, st.Index, st.ActionID, st.Family, st.HostID, st.Why); err != nil {
			return Note{}, false, fmt.Errorf("opsnotes: insert step %d: %w", st.Index, err)
		}
	}
	n, err := getNote(ctx, tx, id)
	if err != nil {
		return Note{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Note{}, false, fmt.Errorf("opsnotes: commit: %w", err)
	}
	return n, true, nil
}

// Get returns a stored note, including dismissed and superseded ones.
func (s *Store) Get(ctx context.Context, id int64) (Note, error) {
	return getNote(ctx, s.db, id)
}

// List returns all stored notes, newest first, including dismissed and
// superseded ones; the caller decides what to show.
func (s *Store) List(ctx context.Context) ([]Note, error) {
	rows, err := s.db.QueryContext(ctx, noteColumns+` ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("opsnotes: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Note
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("opsnotes: list: %w", err)
	}
	return out, nil
}

// Dismiss hides a note from the cards. It changes nothing else: steps stay
// indexed for MatchStep and Step (ADR 0016 D8, D9).
func (s *Store) Dismiss(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE notes SET dismissed = 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("opsnotes: dismiss %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("opsnotes: dismiss %d: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("note %d: %w", id, ErrNotFound)
	}
	return nil
}

// Prune deletes notes older than Retention at now, then the oldest notes
// beyond MaxNotes. It returns the number of notes deleted; their steps go
// with them.
func (s *Store) Prune(ctx context.Context, now time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("opsnotes: begin prune: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	n, err := pruneTx(ctx, tx, now.UTC(), MaxNotes)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("opsnotes: commit prune: %w", err)
	}
	return n, nil
}

// pruneTx deletes notes older than Retention and all but the newest keep
// notes. Steps are removed by the foreign key cascade.
func pruneTx(ctx context.Context, q queryer, now time.Time, keep int) (int64, error) {
	cutoff := now.Add(-Retention).UnixNano()
	res, err := q.ExecContext(ctx, `DELETE FROM notes WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("opsnotes: prune by age: %w", err)
	}
	byAge, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("opsnotes: prune by age: %w", err)
	}
	res, err = q.ExecContext(ctx,
		`DELETE FROM notes WHERE id NOT IN (SELECT id FROM notes ORDER BY id DESC LIMIT ?)`, keep)
	if err != nil {
		return 0, fmt.Errorf("opsnotes: prune by count: %w", err)
	}
	byCount, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("opsnotes: prune by count: %w", err)
	}
	return byAge + byCount, nil
}

// MatchStep returns the newest stored step with the given action family on
// the given host (ADR 0016 D9, match rule). Dismissed and superseded notes
// count; deleted notes do not.
func (s *Store) MatchStep(ctx context.Context, family, hostID string) (Step, bool, error) {
	row := s.db.QueryRowContext(ctx, stepColumns+
		` WHERE family = ? AND host_id = ? ORDER BY note_id DESC, idx ASC LIMIT 1`, family, hostID)
	st, err := scanStep(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Step{}, false, nil
	}
	if err != nil {
		return Step{}, false, err
	}
	return st, true, nil
}

// Step returns step index of note noteID (ADR 0016 D9, reference rule).
// Dismissed and superseded notes count; deleted notes do not.
func (s *Store) Step(ctx context.Context, noteID int64, index int) (Step, bool, error) {
	row := s.db.QueryRowContext(ctx, stepColumns+` WHERE note_id = ? AND idx = ?`, noteID, index)
	st, err := scanStep(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Step{}, false, nil
	}
	if err != nil {
		return Step{}, false, err
	}
	return st, true, nil
}

const noteColumns = `SELECT id, kind, ref, digest, body, snapshot, created_at, superseded, dismissed FROM notes`

const stepColumns = `SELECT note_id, idx, action_id, host_id, family, why FROM steps`

func getNote(ctx context.Context, q queryer, id int64) (Note, error) {
	row := q.QueryRowContext(ctx, noteColumns+` WHERE id = ?`, id)
	n, err := scanNote(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Note{}, fmt.Errorf("note %d: %w", id, ErrNotFound)
	}
	return n, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanNote(sc scanner) (Note, error) {
	var (
		n                   Note
		kind, body          string
		createdNS           int64
		superseded, dismiss int
	)
	if err := sc.Scan(&n.ID, &kind, &n.Ref, &n.Digest, &body, &n.Snapshot, &createdNS, &superseded, &dismiss); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Note{}, err
		}
		return Note{}, fmt.Errorf("opsnotes: scan note: %w", err)
	}
	if err := json.Unmarshal([]byte(body), &n.Body); err != nil {
		return Note{}, fmt.Errorf("opsnotes: stored body of note %d: %w", n.ID, err)
	}
	n.Kind = Kind(kind)
	n.CreatedAt = time.Unix(0, createdNS).UTC()
	n.Superseded = superseded == 1
	n.Dismissed = dismiss == 1
	return n, nil
}

func scanStep(sc scanner) (Step, error) {
	var st Step
	if err := sc.Scan(&st.NoteID, &st.Index, &st.ActionID, &st.HostID, &st.Family, &st.Why); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Step{}, err
		}
		return Step{}, fmt.Errorf("opsnotes: scan step: %w", err)
	}
	return st, nil
}
