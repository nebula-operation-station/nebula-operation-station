// SPDX-License-Identifier: AGPL-3.0-or-later

package deployprofile

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func store(t *testing.T) *Store {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func TestStoreEditingCreatesNewVersion(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	v1, err := s.Save(ctx, "admin", profile())
	if err != nil || v1.Version != 1 {
		t.Fatalf("save 1: %+v %v", v1, err)
	}
	p := profile()
	p.Title = "Web server, M (v2)"
	p.Runbooks[0].Version = 4
	v2, err := s.Save(ctx, "admin", p)
	if err != nil || v2.Version != 2 {
		t.Fatalf("save 2: %+v %v", v2, err)
	}
	// Latest is the new version; the old one is still there unchanged.
	got, err := s.Get(ctx, "web_m", 0)
	if err != nil || got.Version != 2 || got.Profile.Title != "Web server, M (v2)" {
		t.Fatalf("latest: %+v %v", got, err)
	}
	old, err := s.Get(ctx, "web_m", 1)
	if err != nil || old.Profile.Title != "Web server, M" || old.Profile.Runbooks[0].Version != 3 {
		t.Fatalf("v1: %+v %v", old, err)
	}
	all, err := s.Versions(ctx, "web_m")
	if err != nil || len(all) != 2 || all[0].Version != 2 || all[1].Version != 1 {
		t.Fatalf("versions: %+v %v", all, err)
	}
	latest, err := s.Latest(ctx)
	if err != nil || len(latest) != 1 || latest[0].Version != 2 {
		t.Fatalf("latest list: %+v %v", latest, err)
	}
}

func TestStoreSaveRejectsInvalid(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	p := profile()
	p.Bootstrap[0].Params = map[string]string{"password": "hunter2"}
	if _, err := s.Save(ctx, "admin", p); err == nil {
		t.Fatal("secret parameter must be rejected")
	}
	if _, err := s.Get(ctx, "web_m", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected profile must not be stored, got %v", err)
	}
	if _, err := s.Save(ctx, "bad\x00user", profile()); err == nil {
		t.Fatal("invalid user must be rejected")
	}
}

func TestStoreGetMissing(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	if _, err := s.Get(ctx, "nope", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	if _, err := s.Get(ctx, "nope", 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestStoreVersionsImmutable(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	if _, err := s.Save(ctx, "admin", profile()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE deploy_profile_versions SET title = 'x' WHERE slug = 'web_m' AND version = 1`); err == nil {
		t.Fatal("updating a stored version must be refused")
	}
	if _, err := s.db.Exec(`DELETE FROM deploy_profile_versions WHERE slug = 'web_m' AND version = 1`); err == nil {
		t.Fatal("deleting a stored version must be refused")
	}
}

func TestStoreVersionIntegrity(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	if _, err := s.Save(ctx, "admin", profile()); err != nil {
		t.Fatal(err)
	}
	// A row whose document does not match its digest must not be
	// returned as a version.
	if _, err := s.db.Exec(`INSERT INTO deploy_profile_versions
		(slug, version, title, description, doc, doc_sha256, created_by, created_at)
		VALUES ('web_m', 7, 'x', '', '{"slug":"web_m"}', '` + strings.Repeat("0", 64) + `', 'admin', 0)`); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get(ctx, "web_m", 7)
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("tampered version: got %v, want verification failure", err)
	}
}
