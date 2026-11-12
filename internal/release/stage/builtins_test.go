// SPDX-License-Identifier: AGPL-3.0-or-later

package stage

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

func TestBuiltinsPassBundleVerification(t *testing.T) {
	b, err := BuildBuiltins(repoModules)
	if err != nil {
		t.Fatal(err)
	}
	locks := repoLocks(t)
	if len(b.Modules) != len(locks) {
		t.Fatalf("built %d modules, want %d", len(b.Modules), len(locks))
	}
	// The manifest the offline recipe would write for this bundle,
	// unsigned: VerifyBundle checks everything but the signature.
	m := b.manifest(testVersion)
	mods, err := release.VerifyBundle(m, b.Tar)
	if err != nil {
		t.Fatal(err)
	}
	for i, mb := range mods {
		if mb.Module.Name != sortedKeys(locks)[i] || mb.Lock.Version != locks[mb.Module.Name] {
			t.Errorf("module %d = %s %s", i, mb.Module.Name, mb.Lock.Version)
		}
		if len(mb.Actions) == 0 {
			t.Errorf("%s has no actions", mb.Module.Name)
		}
		if _, err := release.ParseModuleTar(m.Modules[i], b.Modules[i].Tar); err != nil {
			t.Errorf("ParseModuleTar %s: %v", mb.Module.Name, err)
		}
	}
}

func TestBuiltinsHeadersAreFixed(t *testing.T) {
	b, err := BuildBuiltins(repoModules)
	if err != nil {
		t.Fatal(err)
	}
	check := func(where string, es []entry) {
		var names []string
		for _, e := range es {
			h := e.hdr
			if h.Format != tar.FormatUSTAR || h.Typeflag != tar.TypeReg || h.Mode != 0o644 ||
				!h.ModTime.Equal(epoch) || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
				t.Errorf("%s %s: header %+v", where, e.name, h)
			}
			names = append(names, e.name)
		}
		if !slices.IsSorted(names) {
			t.Errorf("%s entries are not sorted: %v", where, names)
		}
	}
	outer := outerEntries(t, b.Tar)
	check("builtins.tar", outer)
	for _, e := range outer {
		check(e.name, outerEntries(t, e.data))
	}
	if len(b.Tar)%512 != 0 {
		t.Error("builtins.tar is not block aligned")
	}
}

// copyModule copies one repository module into a temporary modules tree.
func copyModule(t *testing.T, dst, name string) string {
	t.Helper()
	src := filepath.Join(repoModules, "bootstrap", name)
	to := filepath.Join(dst, "bootstrap", name)
	if err := os.CopyFS(to, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	return to
}

func TestBuiltinsIgnoreFilesTheLockDoesNotReference(t *testing.T) {
	dst := t.TempDir()
	m := copyModule(t, dst, "timezone")
	if err := os.WriteFile(filepath.Join(m, "actions", "stray.sh"), []byte("echo hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := BuildBuiltins(dst)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := BuildBuiltins(repoModules)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(ref.Modules, func(m ModuleTar) bool { return m.Name == "timezone" })
	if len(b.Modules) != 1 || !bytes.Equal(b.Modules[0].Tar, ref.Modules[i].Tar) {
		t.Fatal("module tar includes unreferenced files or depends on the source location")
	}
}

func TestBuiltinsRejectBadModules(t *testing.T) {
	cases := map[string]func(t *testing.T, dst string){
		"script hash mismatch": func(t *testing.T, dst string) {
			m := copyModule(t, dst, "timezone")
			if err := os.WriteFile(filepath.Join(m, "actions", "install.sh"), []byte("tampered\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"missing script": func(t *testing.T, dst string) {
			m := copyModule(t, dst, "timezone")
			if err := os.Remove(filepath.Join(m, "actions", "verify.sh")); err != nil {
				t.Fatal(err)
			}
		},
		"script symlink": func(t *testing.T, dst string) {
			m := copyModule(t, dst, "timezone")
			p := filepath.Join(m, "actions", "verify.sh")
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("verify.sh.real", p); err != nil {
				t.Fatal(err)
			}
		},
		"lock symlink": func(t *testing.T, dst string) {
			m := copyModule(t, dst, "timezone")
			p := filepath.Join(m, "module.lock.json")
			if err := os.Rename(p, filepath.Join(m, "real.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.json", p); err != nil {
				t.Fatal(err)
			}
		},
		"malformed lock": func(t *testing.T, dst string) {
			m := copyModule(t, dst, "timezone")
			if err := os.WriteFile(filepath.Join(m, "module.lock.json"), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"duplicate name": func(t *testing.T, dst string) {
			copyModule(t, dst, "timezone")
			if err := os.CopyFS(filepath.Join(dst, "other", "timezone"), os.DirFS(filepath.Join(repoModules, "bootstrap", "timezone"))); err != nil {
				t.Fatal(err)
			}
		},
		"no modules": func(t *testing.T, dst string) {},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dst := t.TempDir()
			setup(t, dst)
			if _, err := BuildBuiltins(dst); !errors.Is(err, ErrModules) {
				t.Fatalf("err = %v, want ErrModules", err)
			}
		})
	}
}
