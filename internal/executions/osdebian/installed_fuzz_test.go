// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"os"
	"path/filepath"
	"strings"
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
	for _, src := range []string{"linux-latest", "linux-x", "linux-signed-amd64", "linux-meta", "linux-hwe-6.8"} {
		f.Add([]byte(InstalledFormat+"\n"+
			"P\tinstalled\tlinux-image-6.1.0-26-amd64\tamd64\t6.1.112-1\tlinux-signed-amd64\t6.1.112+1\t"+src+" (= 6.1.112-1)\t.\n"+
			"K\t6.1.0-26-amd64\t#1 SMP\nEND\t1\n"), 0, false)
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
		if k.State == KernelMapped {
			if why := kernelOracle(inv, k); why != "" {
				t.Fatalf("mapped kernel %+v: %s", k, why)
			}
		}
		if k.State != KernelMapped && (k.Source != "" || k.Version != "") {
			t.Fatalf("unknown kernel with version basis: %+v", k)
		}
	})
}

// oracleFlavours is written out by hand, apart from kernelSourceRe.
var oracleFlavours = map[string]bool{
	"aws": true, "azure": true, "gcp": true, "gke": true, "gkeop": true, "ibm": true,
	"kvm": true, "lowlatency": true, "nvidia": true, "oem": true, "oracle": true,
	"raspi": true, "realtime": true,
}

// oracleKernelSource decides by string surgery, not by the production
// regexp, whether a source is an unsigned kernel source: "linux",
// "linux-<x.y>", "linux-hwe-<x.y>", "linux-<flavour>[-hwe][-<x.y>]".
func oracleKernelSource(src string) bool {
	for _, bad := range []string{"linux-signed", "linux-meta", "linux-restricted", "linux-firmware", "linux-base", "linux-latest", "linux-image", "linux-headers"} {
		if strings.HasPrefix(src, bad) {
			return false
		}
	}
	if src == "linux" {
		return true
	}
	rest, ok := strings.CutPrefix(src, "linux-")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "-")
	hasSeries := isSeries(parts[len(parts)-1])
	if hasSeries {
		parts = parts[:len(parts)-1]
	}
	switch {
	case len(parts) == 0:
		return hasSeries // linux-<x.y>
	case len(parts) == 1 && parts[0] == "hwe":
		return hasSeries // linux-hwe-<x.y>
	case len(parts) == 1:
		return oracleFlavours[parts[0]]
	case len(parts) == 2 && parts[1] == "hwe":
		return oracleFlavours[parts[0]]
	}
	return false
}

func isSeries(s string) bool {
	major, minor, ok := strings.Cut(s, ".")
	return ok && len(major) <= 2 && len(minor) <= 3 && allDigits(major) && allDigits(minor)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// kernelOracle re-derives the mapping from the inventory: the mapped
// source and version come from the running release's image, either
// directly (unsigned source) or from a "<src> (= <ver>)" entry in its
// Built-Using (signed source), and the source is never signed or meta.
func kernelOracle(inv InstalledInventory, k RunningKernel) string {
	if k.Source == "" || k.Version == "" || !oracleKernelSource(k.Source) {
		return "not an unsigned kernel source"
	}
	for _, p := range inv.Packages {
		if p.Name != k.ImagePackage {
			continue
		}
		if !strings.HasPrefix(p.Name, "linux-image-") || !strings.Contains(p.Name, k.Release) {
			return "image package does not match the running release"
		}
		if p.Source == k.Source && p.SourceVersion == k.Version {
			return ""
		}
		if strings.HasPrefix(p.Source, "linux-signed") {
			for _, e := range strings.Split(p.BuiltUsing, ",") {
				if strings.TrimSpace(e) == k.Source+" (= "+k.Version+")" {
					return ""
				}
			}
		}
		return "source and version not taken from the image"
	}
	return "image package not in inventory"
}
