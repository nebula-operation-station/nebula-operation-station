// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconfig

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// fakeAuditor runs a change in a transaction on db and records the audit
// entries; appendErr makes the audit write fail.
type fakeAuditor struct {
	db        *sql.DB
	kinds     []string
	attrs     []map[string]string
	appendErr error
}

func (f *fakeAuditor) WithTx(ctx context.Context, fn func(*sql.Tx, func(string, map[string]string) error) error) error {
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = fn(tx, func(kind string, attrs map[string]string) error {
		if f.appendErr != nil {
			return f.appendErr
		}
		f.kinds = append(f.kinds, kind)
		f.attrs = append(f.attrs, attrs)
		return nil
	})
	if err != nil {
		return err
	}
	return tx.Commit()
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open serverdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newTestStore(t *testing.T) (*Store, *sql.DB, *fakeAuditor) {
	t.Helper()
	db := openTestDB(t)
	s, err := NewStore(db, func() time.Time { return time.Unix(1_800_000_000, 0).UTC() })
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, db, &fakeAuditor{db: db}
}

func TestFreshStoreServesDisabledDefaults(t *testing.T) {
	s, _, _ := newTestStore(t)
	row, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row.Enabled || row.Version != 0 {
		t.Fatalf("fresh row = %+v, want disabled at version 0", row)
	}
	if row.DataClass != DataClassLab || row.Language != LanguageDE {
		t.Fatalf("fresh row = %+v, want lab class and de", row)
	}
}

func TestSaveStoresValidatedRowAndAudits(t *testing.T) {
	s, _, aud := newTestStore(t)
	ctx := context.Background()
	next := validSettings()
	row, err := s.Save(ctx, "admin", next, 0, aud)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if row.Version != 1 || row.UpdatedBy != "admin" || row.BaseURL != next.BaseURL || row.DataClass != DataClassLab {
		t.Fatalf("saved row = %+v", row)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Settings != next || got.Version != 1 {
		t.Fatalf("stored row = %+v, want %+v at version 1", got, next)
	}
	if len(aud.kinds) != 1 || aud.kinds[0] != AuditOpsAgentSettingsChanged {
		t.Fatalf("audit kinds = %v", aud.kinds)
	}
	if aud.attrs[0]["actor"] != "admin" || aud.attrs[0]["new_version"] != "1" || aud.attrs[0]["old_version"] != "0" {
		t.Fatalf("audit attrs = %v", aud.attrs[0])
	}
}

func TestSaveRejectsInvalidSettingsWithoutWriting(t *testing.T) {
	s, _, aud := newTestStore(t)
	ctx := context.Background()
	bad := validSettings()
	bad.DataClass = "public"
	if _, err := s.Save(ctx, "admin", bad, 0, aud); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Save = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Save(ctx, "", validSettings(), 0, aud); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Save without actor = %v, want ErrInvalidInput", err)
	}
	row, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row.Version != 0 || row.Enabled {
		t.Fatalf("rejected save changed the row: %+v", row)
	}
	if len(aud.kinds) != 0 {
		t.Fatalf("rejected save was audited: %v", aud.kinds)
	}
}

func TestSaveWithStaleBaseVersionIsRefused(t *testing.T) {
	s, _, aud := newTestStore(t)
	ctx := context.Background()
	first := validSettings()
	if _, err := s.Save(ctx, "admin", first, 0, aud); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// A second admin who loaded the defaults (version 0) must not overwrite.
	second := validSettings()
	second.Model = "other-model"
	if _, err := s.Save(ctx, "admin2", second, 0, aud); !errors.Is(err, ErrStale) {
		t.Fatalf("stale save = %v, want ErrStale", err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Model != first.Model || got.Version != 1 || got.UpdatedBy != "admin" {
		t.Fatalf("stale save changed the row: %+v", got)
	}
	if len(aud.kinds) != 1 {
		t.Fatalf("stale save was audited: %v", aud.kinds)
	}
	// Re-loading at version 1 succeeds.
	if _, err := s.Save(ctx, "admin2", second, 1, aud); err != nil {
		t.Fatalf("save at current version: %v", err)
	}
	if _, err := s.Save(ctx, "admin2", second, 1, aud); !errors.Is(err, ErrStale) {
		t.Fatalf("replayed base version = %v, want ErrStale", err)
	}
}

func TestSaveRollsBackWhenAuditFails(t *testing.T) {
	s, _, aud := newTestStore(t)
	ctx := context.Background()
	aud.appendErr = errors.New("audit disk full")
	if _, err := s.Save(ctx, "admin", validSettings(), 0, aud); err == nil {
		t.Fatal("Save succeeded although the audit entry failed")
	}
	row, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row.Version != 0 || row.Enabled {
		t.Fatalf("change committed without its audit entry: %+v", row)
	}
}

func TestSaveRequiresAuditor(t *testing.T) {
	s, _, _ := newTestStore(t)
	if _, err := s.Save(context.Background(), "admin", validSettings(), 0, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Save without auditor = %v, want ErrInvalidInput", err)
	}
}

func mustDigest(t *testing.T, s Settings, baseVersion int64) [32]byte {
	t.Helper()
	d, err := ChangeDigest(s, baseVersion)
	if err != nil {
		t.Fatalf("ChangeDigest: %v", err)
	}
	return d
}

func TestChangeDigestChangesWithEveryField(t *testing.T) {
	base := validSettings()
	const baseVersion = 3
	want := mustDigest(t, base, baseVersion)
	mutators := map[string]func(*Settings){
		"enabled":          func(s *Settings) { s.Enabled = !s.Enabled },
		"base url":         func(s *Settings) { s.BaseURL = "http://10.0.0.6:11434/v1" },
		"model":            func(s *Settings) { s.Model = "other" },
		"allow plain http": func(s *Settings) { s.AllowPlainHTTP = !s.AllowPlainHTTP },
		"data class":       func(s *Settings) { s.DataClass = DataClassExternal },
		"instructions":     func(s *Settings) { s.Instructions = "anders" },
		"language":         func(s *Settings) { s.Language = LanguageEN },
	}
	for name, mut := range mutators {
		t.Run(name, func(t *testing.T) {
			s := base
			mut(&s)
			if mustDigest(t, s, baseVersion) == want {
				t.Fatalf("digest did not change with %s", name)
			}
		})
	}
	if mustDigest(t, base, baseVersion+1) == want {
		t.Fatal("digest did not change with the base version")
	}
	if mustDigest(t, base, baseVersion) != want {
		t.Fatal("digest is not deterministic")
	}
}

func TestChangeDigestFieldBoundaryCannotMove(t *testing.T) {
	// Moving a byte from one text field to the next must change the digest:
	// the JSON keeps the fields apart.
	a := validSettings()
	a.Model = "ab"
	a.Instructions = ""
	b := validSettings()
	b.Model = "a"
	b.Instructions = "b"
	if mustDigest(t, a, 1) == mustDigest(t, b, 1) {
		t.Fatal("digest does not separate fields")
	}
}

func TestChangeDigestUsesDomainSeparator(t *testing.T) {
	if DigestDomain != "nebula-opsagent-settings-v1" {
		t.Fatalf("DigestDomain = %q", DigestDomain)
	}
}

func TestDiffCarriesFullURLAndNeverInstructionText(t *testing.T) {
	old := validSettings()
	old.Instructions = "geheime Anweisung ABC"
	next := old
	next.Enabled = false
	next.BaseURL = "http://10.0.0.9:11434/v2"
	next.Model = "new-model"
	next.DataClass = DataClassExternal
	next.Instructions = "andere Anweisung XYZ"
	d := Diff(old, next)
	checks := map[string]string{
		"old_base_url":   old.BaseURL,
		"new_base_url":   next.BaseURL,
		"old_model":      old.Model,
		"new_model":      next.Model,
		"old_data_class": DataClassLab,
		"new_data_class": DataClassExternal,
		"old_enabled":    "true",
		"new_enabled":    "false",
	}
	for k, want := range checks {
		if d[k] != want {
			t.Errorf("Diff[%s] = %q, want %q", k, d[k], want)
		}
	}
	if d["operator_instructions_changed"] != "true" {
		t.Errorf("instructions change not flagged: %v", d)
	}
	for k, v := range d {
		if strings.Contains(v, "geheime") || strings.Contains(v, "XYZ") || strings.Contains(v, "ABC") {
			t.Fatalf("Diff[%s] carries instruction text: %q", k, v)
		}
	}
	if d["old_operator_instructions_bytes"] != "21" {
		t.Errorf("old instruction length = %q", d["old_operator_instructions_bytes"])
	}
	if len(d["old_operator_instructions_sha256"]) != 64 || len(d["new_operator_instructions_sha256"]) != 64 {
		t.Errorf("instruction digests missing: %v", d)
	}
}

func TestDiffUnchangedFieldsAreNotFlagged(t *testing.T) {
	s := validSettings()
	d := Diff(s, s)
	for _, k := range []string{"operator_instructions_changed", "base_url_changed", "model_changed", "data_class_changed"} {
		if d[k] != "false" {
			t.Errorf("Diff[%s] = %q, want false", k, d[k])
		}
	}
}

func TestSchemaHasNoCredentialColumn(t *testing.T) {
	db := openTestDB(t)
	rows, err := db.Query(`SELECT name FROM pragma_table_info('ops_agent_config')`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	want := map[string]bool{
		"id": true, "enabled": true, "base_url": true, "model": true, "allow_plain_http": true,
		"data_class": true, "operator_instructions": true, "language": true,
		"updated_by": true, "updated_at": true, "version": true,
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[name] = true
		if !want[name] {
			t.Errorf("unexpected column %q", name)
		}
		for _, bad := range []string{"key", "secret", "token", "password", "credential"} {
			if strings.Contains(strings.ToLower(name), bad) {
				t.Errorf("column %q looks like a credential", name)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	for c := range want {
		if !seen[c] {
			t.Errorf("missing column %q", c)
		}
	}
}

func TestSchemaRefusesInvalidRowsBelowTheStore(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	stmts := []string{
		`UPDATE ops_agent_config SET data_class = 'public' WHERE id = 1`,
		`UPDATE ops_agent_config SET language = 'fr' WHERE id = 1`,
		`UPDATE ops_agent_config SET enabled = 2 WHERE id = 1`,
		`UPDATE ops_agent_config SET operator_instructions = ? WHERE id = 1`,
	}
	for _, q := range stmts {
		var args []any
		if strings.Contains(q, "?") {
			args = append(args, strings.Repeat("a", MaxInstructions+1))
		}
		if _, err := db.ExecContext(ctx, q, args...); err == nil {
			t.Errorf("CHECK accepted %q", q)
		}
	}
}
