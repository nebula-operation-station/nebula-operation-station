// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auditlog keeps the server's audit lines in server.db (M10-1):
// every log record with the message "audit" is also stored, so the History
// page can show who did what. An optional hash chain links each line to
// the one before (decision 2 of the M10 plan); unlike the executor's
// events it is not signed, because the server cannot sign in a way a
// compromised server could not repeat.
package auditlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Limits.
const (
	MaxAttrs     = 32
	MaxAttrValue = 1024
	MaxKind      = 64
	MaxPage      = 500
)

// Entry is one stored audit line.
type Entry struct {
	Seq   int64
	At    time.Time
	Kind  string
	User  string
	Attrs map[string]string
	// Chained is true when the line carries a hash.
	Chained bool
}

// Store appends and lists audit lines.
type Store struct {
	db    *sql.DB
	chain bool
	mu    sync.Mutex
	now   func() time.Time
}

// New returns a store; chain turns on the hash chain for new lines.
func New(db *sql.DB, chain bool) *Store { return &Store{db: db, chain: chain, now: time.Now} }

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// attrKey is the stored key for k: clipped to MaxKind, and made unique when
// two keys clip to the same prefix or a key is the reserved "_truncated"
// (review m101, F2), so that two different lines never store the same body.
func attrKey(k string, taken map[string]string) string {
	c := clip(k, MaxKind)
	if _, dup := taken[c]; !dup && c != "_truncated" {
		return c
	}
	// A crafted key can equal another key's suffixed form: try further
	// suffixes until one is free (review fx2, note 3). The first suffix is
	// the hash of the key alone, so existing bodies keep their keys.
	for i := 0; ; i++ {
		in := k
		if i > 0 {
			in = k + "#" + strconv.Itoa(i)
		}
		sum := sha256.Sum256([]byte(in))
		cand := clip(k, MaxKind-9) + "#" + hex.EncodeToString(sum[:4])
		if _, dup := taken[cand]; !dup {
			return cand
		}
	}
}

// Append stores one line.
func (s *Store) Append(ctx context.Context, kind string, attrs map[string]string) error {
	kind, user, body, err := line(kind, attrs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.insert(ctx, s.db, kind, user, body)
}

// WithTx runs fn in a write transaction on the store's database and
// commits it, so the lines fn appends through appendLine commit together
// with fn's other writes or not at all: when fn or the commit fails, the
// transaction is rolled back and the error returned. The store's lock,
// which orders the hash chain, is taken before the transaction begins
// (the same order as Append) and held until it ended; fn must not log
// audit lines through the store's Handler, and appendLine is valid only
// during fn.
func (s *Store) WithTx(ctx context.Context, fn func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error) error {
	if fn == nil {
		return errors.New("auditlog: with tx: function is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("auditlog: begin: %w", err)
	}
	defer tx.Rollback()
	appendLine := func(kind string, attrs map[string]string) error {
		kind, user, body, err := line(kind, attrs)
		if err != nil {
			return err
		}
		return s.insert(ctx, tx, kind, user, body)
	}
	if err := fn(tx, appendLine); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("auditlog: commit: %w", err)
	}
	return nil
}

// execQuerier is *sql.DB or *sql.Tx.
type execQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// line cleans kind and attrs and returns the stored kind, user and body.
func line(kind string, attrs map[string]string) (string, string, []byte, error) {
	if kind == "" {
		kind = "unknown"
	}
	kind = clip(kind, MaxKind)
	clean := map[string]string{}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == MaxAttrs {
			clean["_truncated"] = "true"
			break
		}
		clean[attrKey(k, clean)] = clip(attrs[k], MaxAttrValue)
	}
	user := clip(clean["user"], 64)
	body, err := json.Marshal(clean) // map keys are sorted: deterministic
	if err != nil {
		return "", "", nil, err
	}
	return kind, user, body, nil
}

// insert writes one cleaned line through q; the caller holds s.mu.
func (s *Store) insert(ctx context.Context, q execQuerier, kind, user string, body []byte) error {
	at := s.now().UnixNano()
	if !s.chain {
		_, err := q.ExecContext(ctx, `INSERT INTO audit_log (at, kind, user_name, body) VALUES (?, ?, ?, ?)`, at, kind, user, string(body))
		return err
	}
	var prev []byte
	err := q.QueryRowContext(ctx, `SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) || prev == nil {
		prev = make([]byte, sha256.Size)
	} else if err != nil {
		return err
	}
	h := sha256.Sum256(append(append([]byte{}, prev...), lineBytes(at, kind, user, body)...))
	_, err = q.ExecContext(ctx, `INSERT INTO audit_log (at, kind, user_name, body, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)`,
		at, kind, user, string(body), prev, h[:])
	return err
}

// lineBytes is what the chain hashes for one line.
func lineBytes(at int64, kind, user string, body []byte) []byte {
	b, _ := json.Marshal([]any{at, kind, user, json.RawMessage(body)})
	return b
}

// List returns up to limit lines before seq (0: the newest), newest first,
// optionally only of one kind.
func (s *Store) List(ctx context.Context, before int64, limit int, kind string) ([]Entry, error) {
	if limit < 1 || limit > MaxPage {
		limit = 100
	}
	q := `SELECT seq, at, kind, user_name, body, hash IS NOT NULL FROM audit_log WHERE (? = 0 OR seq < ?) AND (? = '' OR kind = ?) ORDER BY seq DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, before, before, kind, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var at int64
		var body string
		if err := rows.Scan(&e.Seq, &at, &e.Kind, &e.User, &body, &e.Chained); err != nil {
			return nil, err
		}
		e.At = time.Unix(0, at)
		_ = json.Unmarshal([]byte(body), &e.Attrs)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrChainBroken says a chained line does not match the one before.
var ErrChainBroken = errors.New("auditlog: the hash chain is broken")

// Verify checks every chained line against the one before it and returns
// how many chained lines it checked.
func (s *Store) Verify(ctx context.Context) (int, error) {
	n, _, err := s.VerifyHead(ctx)
	return n, err
}

// VerifyHead is Verify that also returns the hash of the newest chained
// line, for the operator to note down elsewhere: a chain rewritten from
// the start is only detectable against an earlier head.
func (s *Store) VerifyHead(ctx context.Context) (int, []byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, at, kind, user_name, body, prev_hash, hash FROM audit_log WHERE hash IS NOT NULL ORDER BY seq`)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	n := 0
	var last []byte
	for rows.Next() {
		var seq, at int64
		var kind, user, body string
		var prev, hash []byte
		if err := rows.Scan(&seq, &at, &kind, &user, &body, &prev, &hash); err != nil {
			return n, nil, err
		}
		h := sha256.Sum256(append(append([]byte{}, prev...), lineBytes(at, kind, user, []byte(body))...))
		// The first chained line starts from zeros: a chain whose first
		// lines were deleted does not (review m101, F1).
		want := last
		if want == nil {
			want = make([]byte, sha256.Size)
		}
		if !bytes.Equal(h[:], hash) || !bytes.Equal(prev, want) {
			return n, nil, fmt.Errorf("%w at line %d", ErrChainBroken, seq)
		}
		last = hash
		n++
	}
	return n, last, rows.Err()
}

// Handler passes records to next and stores the "audit" ones.
type Handler struct {
	next  slog.Handler
	store *Store
	pre   []slog.Attr
}

// NewHandler wraps next.
func NewHandler(next slog.Handler, store *Store) *Handler { return &Handler{next: next, store: store} }

// Enabled implements slog.Handler. Audit lines are logged at Info or
// above and are kept even when the log level hides them from next.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelInfo || h.next.Enabled(ctx, l)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.next = h.next.WithAttrs(as)
	c.pre = append(append([]slog.Attr{}, h.pre...), as...)
	return &c
}

// WithGroup implements slog.Handler (groups are not kept in stored lines).
func (h *Handler) WithGroup(name string) slog.Handler {
	c := *h
	c.next = h.next.WithGroup(name)
	return &c
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "audit" && h.store != nil {
		attrs := map[string]string{}
		kind := ""
		add := func(a slog.Attr) bool {
			v := a.Value.Resolve()
			if a.Key == "kind" {
				kind = v.String()
				return true
			}
			if v.Kind() == slog.KindTime {
				attrs[a.Key] = v.Time().UTC().Format(time.RFC3339Nano)
			} else {
				attrs[a.Key] = v.String()
			}
			return true
		}
		for _, a := range h.pre {
			add(a)
		}
		r.Attrs(add)
		// The request context may be cancelled already; the line must still land.
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		err := h.store.Append(sctx, kind, attrs)
		cancel()
		if err != nil {
			e := slog.NewRecord(time.Now(), slog.LevelError, "audit log: append failed", 0)
			e.AddAttrs(slog.String("kind", kind), slog.String("error", err.Error()))
			_ = h.next.Handle(ctx, e)
		}
	}
	if !h.next.Enabled(ctx, r.Level) {
		return nil
	}
	return h.next.Handle(ctx, r)
}
