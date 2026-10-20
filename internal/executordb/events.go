// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
)

// ErrEventNotFound is returned by EventAt for an unknown sequence number.
var ErrEventNotFound = errors.New("executordb: event not found")

// LastEvent returns the sequence number and hash of the newest event
// (0 and nil when there is none).
func (db *DB) LastEvent() (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := db.sql.QueryRow(`SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, fmt.Errorf("executordb: last event: %w", err)
	}
	return seq, hash, nil
}

// InsertEvent appends one event; its sequence number must be the next one.
func (db *DB) InsertEvent(r events.Record) error {
	res, err := db.sql.Exec(`INSERT INTO events (seq, body, prev_hash, hash, sig)
		SELECT ?, ?, ?, ?, ? WHERE ? = coalesce((SELECT max(seq) FROM events), 0) + 1`,
		r.Seq, r.Body, r.PrevHash, r.Hash, r.Sig, r.Seq)
	if err != nil {
		return fmt.Errorf("executordb: insert event: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("executordb: insert event: not the next sequence number")
	}
	return nil
}

// Events returns up to limit events after seq, oldest first.
func (db *DB) Events(after int64, limit int) ([]events.Record, error) {
	rows, err := db.sql.Query(`SELECT seq, body, prev_hash, hash, sig FROM events WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("executordb: list events: %w", err)
	}
	defer rows.Close()
	var out []events.Record
	for rows.Next() {
		var r events.Record
		if err := rows.Scan(&r.Seq, &r.Body, &r.PrevHash, &r.Hash, &r.Sig); err != nil {
			return nil, fmt.Errorf("executordb: list events: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EventAt returns the event with sequence number seq.
func (db *DB) EventAt(seq int64) (events.Record, error) {
	var r events.Record
	err := db.sql.QueryRow(`SELECT seq, body, prev_hash, hash, sig FROM events WHERE seq = ?`, seq).Scan(&r.Seq, &r.Body, &r.PrevHash, &r.Hash, &r.Sig)
	if errors.Is(err, sql.ErrNoRows) {
		return events.Record{}, ErrEventNotFound
	}
	if err != nil {
		return events.Record{}, fmt.Errorf("executordb: event: %w", err)
	}
	return r, nil
}

// EventKeys returns the keys that signed the chain, by first sequence
// number.
func (db *DB) EventKeys() ([]events.Key, error) {
	rows, err := db.sql.Query(`SELECT first_seq, public_key FROM event_keys ORDER BY first_seq`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list event keys: %w", err)
	}
	defer rows.Close()
	var out []events.Key
	for rows.Next() {
		var k events.Key
		if err := rows.Scan(&k.FirstSeq, &k.PublicKey); err != nil {
			return nil, fmt.Errorf("executordb: list event keys: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RegisterEventKey records pub as the key from the next event on, unless
// it is recorded already. It returns whether it was added and the key it
// replaces (nil for the first key). The first key of a chain that already
// has events (an install from before the key history) starts at event 1.
func (db *DB) RegisterEventKey(pub []byte) (bool, []byte, error) {
	if len(pub) != 32 {
		return false, nil, fmt.Errorf("executordb: %w: event key", ErrInvalid)
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return false, nil, fmt.Errorf("executordb: register event key: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM event_keys WHERE public_key = ?`, pub).Scan(&n); err != nil {
		return false, nil, fmt.Errorf("executordb: register event key: %w", err)
	}
	if n > 0 {
		return false, nil, nil
	}
	var prev []byte
	err = tx.QueryRow(`SELECT public_key FROM event_keys ORDER BY first_seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, nil, fmt.Errorf("executordb: register event key: %w", err)
	}
	first := int64(1)
	if prev != nil {
		if err := tx.QueryRow(`SELECT coalesce(max(seq), 0) + 1 FROM events`).Scan(&first); err != nil {
			return false, nil, fmt.Errorf("executordb: register event key: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO event_keys (first_seq, public_key, added_at) VALUES (?, ?, ?)`, first, pub, db.now().Unix()); err != nil {
		return false, nil, fmt.Errorf("executordb: register event key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("executordb: register event key: %w", err)
	}
	return true, prev, nil
}
