// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

func TestParseSuggestionRefAcceptsOnlyPositivePairs(t *testing.T) {
	tests := []struct {
		ref string
		ok  bool
		id  int64
		idx int
	}{
		{"3.1", true, 3, 1},
		{"120.6", true, 120, 6},
		{"0.1", false, 0, 0},
		{"3.0", false, 0, 0},
		{"3.01", false, 0, 0},
		{"03.1", false, 0, 0},
		{"+3.1", false, 0, 0},
		{"3.-1", false, 0, 0},
		{"3.", false, 0, 0},
		{".1", false, 0, 0},
		{"x.1", false, 0, 0},
		{"31", false, 0, 0},
		{"", false, 0, 0},
		{"3.1.2", false, 0, 0},
	}
	for _, tc := range tests {
		id, idx, ok := parseSuggestionRef(tc.ref)
		if ok != tc.ok || id != tc.id || idx != tc.idx {
			t.Errorf("parseSuggestionRef(%q) = %d, %d, %v; want %d, %d, %v", tc.ref, id, idx, ok, tc.id, tc.idx, tc.ok)
		}
	}
}

func TestOpsNotesFileIsPrivateAndUnknownRefsAreNotSuggestions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := newOpsNotes(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	fi, err := os.Stat(filepath.Join(dir, opsNotesDir, opsNotesFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("notes file mode %v, want private (0600)", fi.Mode().Perm())
	}
	idx := opsSuggestions{notes: st}
	if _, _, _, ok := idx.Step("999.1"); ok {
		t.Error("an unknown note resolved as a suggestion")
	}
	if _, ok := idx.Match("os-update", "h-web01"); ok {
		t.Error("an empty store matched a suggestion")
	}
	if fam, ok := idx.Family("package.install_security"); !ok || fam != "os-update" {
		t.Errorf("Family of an allowlisted action: %q, %v", fam, ok)
	}
	if _, ok := idx.Family("shell.exec"); ok {
		t.Error("a non-allowlisted action has a family")
	}
}

func TestNoOpsTokenMeansNoOpsAPI(t *testing.T) {
	cfg := serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{
		{Name: "reader", SHA256: "00", Scopes: []string{serverconfig.ScopeInventoryRead}}}}
	h, err := newOpsAPI(cfg, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		t.Error("an ops API without an ops token")
	}
}
