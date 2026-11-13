// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

var t0 = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

// clock is an injected test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestStore opens a fresh serverdb with the real migrations and a store
// on it, driven by clk.
func newTestStore(t *testing.T, clk *clock) (*Store, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "nebula.db"))
	if err != nil {
		t.Fatalf("open serverdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db, Config{Now: clk.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, db
}

func mustHost(t *testing.T, id string) Subject {
	t.Helper()
	s, err := HostSubject(id)
	if err != nil {
		t.Fatalf("HostSubject(%q): %v", id, err)
	}
	return s
}

func mustBegin(t *testing.T, s *Store, subj Subject) Run {
	t.Helper()
	r, err := s.BeginRun(t.Context(), subj)
	if err != nil {
		t.Fatalf("BeginRun(%s): %v", subj, err)
	}
	return r
}

// obs returns a changed-file observation for path with a fixed new record.
func obs(class Class, path string) Observation {
	return Observation{Class: class, Path: []byte(path), NewRecord: "sha256=aa owner=root mode=0644"}
}

// keyOf returns the finding key of an observation for subj.
func keyOf(subj Subject, o Observation) Key {
	return Key{Subject: subj, Class: o.Class, Path: o.Path}
}

// finishComplete finishes a run as complete and fails the test on error.
func finishComplete(t *testing.T, s *Store, runID string) FinishResult {
	t.Helper()
	res, err := s.Finish(t.Context(), runID, true)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return res
}

// rowCount counts integrity_findings rows of a subject.
func rowCount(t *testing.T, db *sql.DB, subj Subject) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM integrity_findings WHERE subject = ?`, string(subj)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// sizedPath returns a path of exactly n bytes that is unique per i.
func sizedPath(i, n int) []byte {
	head := "/etc/f" + strconv.Itoa(i) + "-"
	return []byte(head + strings.Repeat("x", n-len(head)))
}
