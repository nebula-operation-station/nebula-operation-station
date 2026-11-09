// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// package.list_installed output comes from a managed host: the parser never
// panics, keeps its output bounded, and never maps a kernel to a signed or
// meta source.
func FuzzParseInstalled(f *testing.F) {
	for _, n := range []string{"debian12.txt", "ubuntu2404.txt", "malformed.txt"} {
		b, err := os.ReadFile(filepath.Join("testdata", "installed", n))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, 0, false)
	}
	f.Add([]byte(InstalledFormat+"\nEND\t0\n"), 0, false)
	f.Add([]byte(""), 1, true)
	f.Fuzz(func(t *testing.T, b []byte, exit int, truncated bool) {
		inv := ParseInstalled(b, ReadStatus{ExitCode: exit, Truncated: truncated})
		if len(inv.Packages) > MaxPackages || len(inv.InstalledKernels) > len(inv.Packages) {
			t.Fatalf("unbounded output: %d packages, %d kernels", len(inv.Packages), len(inv.InstalledKernels))
		}
		if inv.Complete && (inv.Reason != "" || exit != 0 || truncated || inv.Dropped != 0) {
			t.Fatalf("partial read claims complete: %+v", inv)
		}
		if !inv.Complete && inv.Reason == "" {
			t.Fatal("partial read without reason")
		}
		for _, p := range inv.Packages {
			for _, s := range []string{p.Name, p.Arch, p.Version, p.Source, p.SourceVersion} {
				if s == "" || len(s) > maxFieldLen+11 || !utf8.ValidString(s) {
					t.Fatalf("bad field %q", s)
				}
			}
			if len(p.BuiltUsing) > maxBuiltUsingLen {
				t.Fatalf("Built-Using too long")
			}
		}
		k := inv.RunningKernel
		if len(k.Release) > maxReleaseLen || len(k.Build) > maxBuildLen {
			t.Fatal("kernel fields unbounded")
		}
		if k.State == KernelMapped && (k.Source == "" || k.Version == "" || !isKernelSource(k.Source)) {
			t.Fatalf("mapped kernel without unsigned source: %+v", k)
		}
		if k.State != KernelMapped && (k.Source != "" || k.Version != "") {
			t.Fatalf("unknown kernel with version basis: %+v", k)
		}
	})
}
