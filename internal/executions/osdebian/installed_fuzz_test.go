// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// package.list_installed output comes from a managed host: the parser never
// panics, keeps its output bounded, never maps a kernel to a signed or meta
// source, and always reaches the same kernel verdict as vulnver.
func FuzzParseInstalled(f *testing.F) {
	for _, n := range []string{"debian12.txt", "ubuntu2404.txt", "malformed.txt"} {
		b, err := os.ReadFile(filepath.Join("testdata", "installed", n))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, 0, false, int(vulnver.DistroDebian))
		f.Add(b, 0, false, int(vulnver.DistroUbuntu))
	}
	for _, src := range []string{"linux-latest", "linux-x", "linux-signed-amd64", "linux-meta", "linux-hwe-6.8"} {
		f.Add([]byte(InstalledFormat+"\n"+
			"P\tinstalled\tlinux-image-6.1.0-26-amd64\tamd64\t6.1.112-1\tlinux-signed-amd64\t6.1.112+1\t"+src+" (= 6.1.112-1)\t.\n"+
			"K\t6.1.0-26-amd64\t#1 SMP Debian 6.1.112-1\nEND\t1\n"), 0, false, int(vulnver.DistroDebian))
	}
	f.Add([]byte(InstalledFormat+"\n"+
		"P\thalf-installed\tlinux-image-6.1.0-26-amd64\tamd64\t6.1.112-1\tlinux\t6.1.112-1\t\t.\n"+
		"K\t6.1.0-26-amd64\t\nEND\t1\n"), 0, false, int(vulnver.DistroDebian))
	f.Add([]byte(InstalledFormat+"\nEND\t0\n"), 0, false, 0)
	f.Add([]byte(""), 1, true, 0)
	f.Fuzz(func(t *testing.T, b []byte, exit int, truncated bool, d int) {
		distro := vulnver.Distro(d)
		inv := ParseInstalled(b, ReadStatus{ExitCode: exit, Truncated: truncated}, distro)
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
			if inv.Complete && unfinishedStatus[p.Status] {
				t.Fatalf("complete read with %s package", p.Status)
			}
		}
		k := inv.RunningKernel
		if len(k.Release) > maxReleaseLen || len(k.Build) > maxBuildLen {
			t.Fatal("kernel fields unbounded")
		}
		if k.State == KernelMapped {
			if !vulnver.IsKernelSource(k.Source) || vulnver.NeverVersionBasis(k.Source) || strings.HasPrefix(k.Source, "linux-meta") {
				t.Fatalf("mapped to a source that is no kernel version basis: %+v", k)
			}
			if k.Build == "" {
				t.Fatalf("mapped with an empty build string: %+v", k)
			}
		}
		if k.State != KernelMapped && (k.Source != "" || k.Version != "") {
			t.Fatalf("unknown kernel with version basis: %+v", k)
		}
		assertKernelAgreesWithVulnver(t, inv, distro)
	})
}
