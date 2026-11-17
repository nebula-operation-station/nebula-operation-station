// SPDX-License-Identifier: AGPL-3.0-or-later

package auditlog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func TestAuditLog(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	plain := New(db, false)
	var out bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&out, nil), plain))
	log.Info("started")
	log.Info("audit", "kind", "host_created", "host", "web", "user", "axel")
	chained := New(db, true)
	clog := slog.New(NewHandler(slog.NewJSONHandler(&out, nil), chained)).With("component", "ui")
	for i := 0; i < 3; i++ {
		clog.Info("audit", "kind", "asset_saved", "asset", "nas", "user", "axel", "at", time.Unix(0, 0))
	}
	log.Info("audit", "kind", "network_saved", "user", "bob")
	clog.Info("audit", "kind", "asset_deleted", "user", strings.Repeat("u", 100))
	list, err := plain.List(ctx, 0, 10, "")
	if err != nil || len(list) != 6 || list[0].Kind != "asset_deleted" || len(list[0].User) != 64 || list[5].Attrs["host"] != "web" {
		t.Fatalf("%+v %v", list, err)
	}
	if only, _ := plain.List(ctx, 0, 10, "asset_saved"); len(only) != 3 || !only[0].Chained || only[0].Attrs["component"] != "ui" || only[0].Attrs["at"] != "1970-01-01T00:00:00Z" {
		t.Fatalf("%+v", only)
	}
	if page, _ := plain.List(ctx, list[2].Seq, 10, ""); len(page) != 3 {
		t.Fatalf("%d", len(page))
	}
	n, err := chained.Verify(ctx)
	if err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if _, err := db.Exec(`UPDATE audit_log SET body = '{}' WHERE seq = 3`); err == nil {
		t.Fatal("audit line updated")
	}
	if _, err := db.Exec(`DELETE FROM audit_log WHERE seq = 1`); err == nil {
		t.Fatal("audit line deleted")
	}
	// Deleting the first chained lines offline (trigger dropped) breaks
	// the chain too: the new first line does not start from zeros.
	if _, err := db.Exec(`DROP TRIGGER audit_log_no_delete`); err != nil {
		t.Fatal(err)
	}
	first, _, _ := chained.VerifyHead(ctx)
	if _, err := db.Exec(`DELETE FROM audit_log WHERE seq = (SELECT min(seq) FROM audit_log WHERE hash IS NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if n, _, err := chained.VerifyHead(ctx); !errors.Is(err, ErrChainBroken) {
		t.Fatal("prefix deletion not detected", first, n, err)
	}
	// An offline edit (trigger dropped) breaks the chain.
	if _, err := db.Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE audit_log SET user_name = 'mallory' WHERE seq = 4`); err != nil {
		t.Fatal(err)
	}
	if _, err := chained.Verify(ctx); !errors.Is(err, ErrChainBroken) {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 7 {
		t.Fatal(out.String())
	}
}

// The server audit log's copy of attrKey keeps crafted keys distinct like
// the events copy (review fx3, note 2).
func TestAttrKeySuffixCollision(t *testing.T) {
	long := strings.Repeat("k", MaxKind)
	first := attrKey(long+"a", map[string]string{clip(long+"a", MaxKind): "x"})
	taken := map[string]string{clip(long+"a", MaxKind): "1", first: "2"}
	if got := attrKey(long+"a", taken); got == first || len(got) > MaxKind {
		t.Fatalf("%q reused or too long", got)
	}
	if got := attrKey("_truncated", map[string]string{}); got == "_truncated" {
		t.Fatal("the reserved key was handed out")
	}
}

// The user column survives the attribute bound even when "user" sorts
// after the MaxAttrs-th key: it is read before the truncation (review
// tw05), and the body keeps the user attribute among the kept keys.
func TestUserSurvivesAttrBound(t *testing.T) {
	attrs := map[string]string{"user": "axel"}
	for i := 0; i < 40; i++ {
		attrs["a"+strconv.Itoa(100+i)] = "v"
	}
	kind, user, body, err := line("audit_test", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "audit_test" || user != "axel" {
		t.Fatalf("kind %q user %q", kind, user)
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m["user"] != "axel" || m["_truncated"] != "true" || len(m) != MaxAttrs+1 {
		t.Fatalf("%d keys, user %q, truncated %q", len(m), m["user"], m["_truncated"])
	}
}

// line keeps the bounds: attribute count, value size, kind size, the
// "unknown" kind and invalid UTF-8 in keys and values.
func TestLineBounds(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < MaxAttrs+5; i++ {
		many["k"+strconv.Itoa(1000+i)] = "v"
	}
	tests := []struct {
		name      string
		kind      string
		attrs     map[string]string
		wantKind  string
		wantKeys  int
		wantTrunc bool
	}{
		{"too many attrs", "x", many, "x", MaxAttrs + 1, true},
		{"empty kind", "", map[string]string{"a": "1"}, "unknown", 1, false},
		{"long kind", strings.Repeat("k", 200), nil, strings.Repeat("k", MaxKind), 0, false},
		{"invalid utf-8 kind", "a\xffb", nil, "a?b", 0, false},
		{"invalid utf-8 key", "x", map[string]string{"a\xff": "1"}, "x", 1, false},
		{"invalid utf-8 value", "x", map[string]string{"a": "b\xffc"}, "x", 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, _, body, err := line(tc.kind, tc.attrs)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]string
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			if kind != tc.wantKind || len(m) != tc.wantKeys || (m["_truncated"] == "true") != tc.wantTrunc {
				t.Fatalf("kind %q keys %d truncated %v: %s", kind, len(m), tc.wantTrunc, body)
			}
			for k, v := range m {
				if len(v) > MaxAttrValue || !utf8.ValidString(v) || !utf8.ValidString(k) {
					t.Fatalf("%q: %d bytes or invalid UTF-8", k, len(v))
				}
			}
		})
	}
}

// FuzzLine checks the invariants of a stored line for any input: valid
// JSON with at most MaxAttrs+1 keys (the reserved _truncated included),
// bounded valid UTF-8 values, a user column of at most 64 bytes that is a
// prefix of the stored user attribute, and the same body for the same
// input.
func FuzzLine(f *testing.F) {
	f.Add("kind", "user", "axel", 3)
	f.Add("", "a\xff", "b\xff", 40)
	f.Add(strings.Repeat("k", 100), "user", strings.Repeat("é", 2000), 33)
	f.Fuzz(func(t *testing.T, kind, key, val string, n int) {
		// Inputs are kept small: line cleans every byte it is given, so
		// multi-megabyte mutations only slow the fuzzer down.
		const fuzzInput = 4 * MaxAttrValue
		kind, key, val = kind[:min(len(kind), fuzzInput)], key[:min(len(key), fuzzInput)], val[:min(len(val), fuzzInput)]
		if n < 0 {
			n = -n
		}
		n %= MaxAttrs + 10
		attrs := map[string]string{"user": val}
		for i := 0; i < n; i++ {
			attrs[key+strconv.Itoa(i)] = val
		}
		gotKind, user, body, err := line(kind, attrs)
		if err != nil {
			t.Fatal(err)
		}
		if gotKind == "" || len(gotKind) > MaxKind || !utf8.ValidString(gotKind) {
			t.Fatalf("kind %q", gotKind)
		}
		var m map[string]string
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("body is not a JSON object of strings: %v", err)
		}
		if len(m) > MaxAttrs+1 {
			t.Fatalf("%d keys", len(m))
		}
		for k, v := range m {
			if !utf8.ValidString(k) || !utf8.ValidString(v) || len(v) > MaxAttrValue {
				t.Fatalf("%q: %d bytes or invalid UTF-8", k, len(v))
			}
		}
		if len(user) > 64 || !utf8.ValidString(user) {
			t.Fatalf("user %q", user)
		}
		if _, ok := m["user"]; ok && !strings.HasPrefix(m["user"], user) {
			t.Fatalf("user column %q is not a prefix of the attribute %q", user, m["user"])
		}
		if _, ok := attrs["user"]; ok && len(attrs) > MaxAttrs && !strings.HasPrefix(val, user) && utf8.ValidString(val) {
			t.Fatalf("user column %q lost the input user %q", user, val)
		}
		_, _, again, err := line(kind, attrs)
		if err != nil || string(again) != string(body) {
			t.Fatalf("same input, different body: %s vs %s", body, again)
		}
	})
}

// AppendFunc is the appendLine parameter of WithTx's function.
type AppendFunc = func(kind string, attrs map[string]string) error

// WithTx writes the lines through its transaction: a failing function or
// commit leaves no line, a committed transaction keeps the line in the
// hash chain.
func TestWithTxCommitsAndRollsBackTheLines(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	s := New(db, true)
	if err := s.Append(ctx, "before", map[string]string{"user": "axel"}); err != nil {
		t.Fatal(err)
	}

	// fn fails after appending: nothing is stored.
	boom := errors.New("change refused")
	err = s.WithTx(ctx, func(tx *sql.Tx, appendLine AppendFunc) error {
		if err := appendLine("rolled_back", map[string]string{"user": "axel"}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx = %v, want fn's error", err)
	}
	// The commit fails (context cancelled after the append): nothing is
	// stored.
	cctx, cancel := context.WithCancel(ctx)
	err = s.WithTx(cctx, func(tx *sql.Tx, appendLine AppendFunc) error {
		err := appendLine("commit_failed", map[string]string{"user": "axel"})
		cancel()
		return err
	})
	if err == nil {
		t.Fatal("WithTx with a cancelled commit succeeded")
	}
	for _, kind := range []string{"rolled_back", "commit_failed"} {
		if got, err := s.List(ctx, 0, 10, kind); err != nil || len(got) != 0 {
			t.Fatalf("%s line stored: %+v %v", kind, got, err)
		}
	}

	// A committed transaction keeps the line and fn's own write; a plain
	// Append meanwhile waits for the transaction, so the chain stays
	// intact.
	appended := make(chan error, 1)
	err = s.WithTx(ctx, func(tx *sql.Tx, appendLine AppendFunc) error {
		if err := appendLine("committed", map[string]string{"user": "axel"}); err != nil {
			return err
		}
		go func() { appended <- s.Append(ctx, "after", map[string]string{"user": "bob"}) }()
		select {
		case err := <-appended:
			return fmt.Errorf("plain Append did not wait for the transaction: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-appended; err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx, 0, 10, "")
	if err != nil || len(list) != 3 || list[0].Kind != "after" || list[1].Kind != "committed" || !list[1].Chained {
		t.Fatalf("lines %+v %v", list, err)
	}
	if n, err := s.Verify(ctx); err != nil || n != 3 {
		t.Fatalf("chain verify: %d %v", n, err)
	}
}

func TestWithTxNeedsFunction(t *testing.T) {
	s := New(nil, false)
	if err := s.WithTx(context.Background(), nil); err == nil {
		t.Fatal("nil function accepted")
	}
}
