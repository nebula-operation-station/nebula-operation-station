// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"strconv"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// nosSourceListFile holds NOS's fixed feed source list (vulnSources). It is
// package main, so the test reads its source instead of importing it.
const nosSourceListFile = "../../cmd/nebula-server/vuln.go"

// nosSourceIDs parses the ID fields of the vulnSources literal.
func nosSourceIDs(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, nosSourceListFile, nil, 0)
	if err != nil {
		t.Fatalf("parse NOS source list: %v", err)
	}
	ids := map[string]bool{}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "vulnSources" || len(vs.Values) != 1 {
			return true
		}
		found = true
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatalf("vulnSources is not a composite literal")
		}
		for _, el := range lit.Elts {
			cl, ok := el.(*ast.CompositeLit)
			if !ok {
				t.Fatalf("vulnSources entry is not a composite literal")
			}
			for _, kv := range cl.Elts {
				kve, ok := kv.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kve.Key.(*ast.Ident); ok && k.Name == "ID" {
					bl, ok := kve.Value.(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						t.Fatalf("vulnSources ID is not a string literal")
					}
					s, err := strconv.Unquote(bl.Value)
					if err != nil {
						t.Fatalf("unquote ID: %v", err)
					}
					ids[s] = true
				}
			}
		}
		return false
	})
	if !found || len(ids) == 0 {
		t.Fatalf("vulnSources not found in %s", nosSourceListFile)
	}
	return ids
}

func TestFeedSourceIDsMatchNOSSourceList(t *testing.T) {
	nos := nosSourceIDs(t)
	covered := map[string]bool{}
	for _, f := range Feeds() {
		if !nos[f.SourceID] {
			t.Errorf("feed %s: source ID %q is not in NOS's fixed source list", f.Name, f.SourceID)
		}
		covered[f.SourceID] = true
	}
	for id := range nos {
		if !covered[id] {
			t.Errorf("NOS source %q has no feed", id)
		}
	}
}

func TestFeedTableIsValid(t *testing.T) {
	names := map[string]bool{}
	for _, f := range Feeds() {
		if err := f.validate(); err != nil {
			t.Errorf("feed %s: %v", f.Name, err)
		}
		if names[f.Name] {
			t.Errorf("duplicate feed name %s", f.Name)
		}
		names[f.Name] = true
		u, err := url.Parse(f.URL)
		if err != nil || u.Scheme != "https" {
			t.Errorf("feed %s: URL must be https: %q", f.Name, f.URL)
		}
		if f.MaxBytes <= 0 || f.MaxBytes > MaxFeedBytesNVD {
			t.Errorf("feed %s: max bytes %d out of range", f.Name, f.MaxBytes)
		}
	}
	for _, f := range Feeds() {
		for _, c := range f.ProxyCompanions {
			cf, ok := FeedByName(c)
			if !ok {
				t.Errorf("feed %s: unknown proxy companion %s", f.Name, c)
				continue
			}
			if cf.DateKind != DateKindDated {
				t.Errorf("feed %s: proxy companion %s is not dated", f.Name, c)
			}
		}
	}
}

func TestFeedTableModes(t *testing.T) {
	want := map[string]struct {
		mode vulnfinding.IntegrityMode
		kind DateKind
	}{
		"debian-tracker": {vulnfinding.IntegrityNone, DateKindProxy},
		"debian-dsa":     {vulnfinding.IntegrityNone, DateKindDated},
		"debian-dla":     {vulnfinding.IntegrityNone, DateKindDated},
		"osv-debian":     {vulnfinding.IntegrityNone, DateKindDated},
		"osv-ubuntu":     {vulnfinding.IntegrityNone, DateKindDated},
		"osv-alpine":     {vulnfinding.IntegrityNone, DateKindDated},
		"osv-go":         {vulnfinding.IntegrityNone, DateKindDated},
		"nvd-modified":   {vulnfinding.IntegrityNone, DateKindDated},
		"cisa-kev":       {vulnfinding.IntegrityNone, DateKindDated},
		"first-epss":     {vulnfinding.IntegrityNone, DateKindDated},
		"cisco-csaf":     {vulnfinding.IntegritySigned, DateKindDated},
		"paloalto-csaf":  {vulnfinding.IntegritySigned, DateKindDated},
	}
	if len(Feeds()) != len(want) {
		t.Fatalf("feed table has %d entries, want %d", len(Feeds()), len(want))
	}
	for name, w := range want {
		f, ok := FeedByName(name)
		if !ok {
			t.Errorf("feed %s missing", name)
			continue
		}
		if f.Integrity != w.mode || f.DateKind != w.kind {
			t.Errorf("feed %s: mode %s kind %s, want %s %s", name, f.Integrity, f.DateKind, w.mode, w.kind)
		}
	}
	nvd, _ := FeedByName("nvd-modified")
	if nvd.MaxBytes != MaxFeedBytesNVD {
		t.Errorf("nvd max bytes %d, want %d", nvd.MaxBytes, MaxFeedBytesNVD)
	}
}

func TestFeedsReturnsCopy(t *testing.T) {
	a := Feeds()
	a[0].URL = "https://evil.example/"
	a[0].ProxyCompanions = append(a[0].ProxyCompanions, "x")
	b := Feeds()
	if b[0].URL == "https://evil.example/" {
		t.Fatal("Feeds exposes the fixed table")
	}
	for _, f := range b {
		for _, c := range f.ProxyCompanions {
			if c == "x" {
				t.Fatal("Feeds exposes companion slices")
			}
		}
	}
}

func TestDefaultOriginsCoverEveryFeed(t *testing.T) {
	al, err := NewAllowlist(DefaultOrigins())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Feeds() {
		u, _ := url.Parse(f.URL)
		if !al.Allows(u) {
			t.Errorf("feed %s origin not allowlisted", f.Name)
		}
	}
}
