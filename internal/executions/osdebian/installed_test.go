// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

func readInstalledFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "installed", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func findPkg(t *testing.T, inv InstalledInventory, name, arch string) InstalledPackage {
	t.Helper()
	for _, p := range inv.Packages {
		if p.Name == name && p.Arch == arch {
			return p
		}
	}
	t.Fatalf("package %s:%s not in inventory", name, arch)
	return InstalledPackage{}
}

func hasPkg(inv InstalledInventory, name string) bool {
	for _, p := range inv.Packages {
		if p.Name == name {
			return true
		}
	}
	return false
}

// installedDoc builds a well-formed document around the given P lines.
func installedDoc(kernel string, pLines ...string) string {
	var b strings.Builder
	b.WriteString(InstalledFormat + "\n")
	for _, l := range pLines {
		b.WriteString(l + "\n")
	}
	if kernel != "" {
		b.WriteString(kernel + "\n")
	}
	fmt.Fprintf(&b, "END\t%d\n", len(pLines))
	return b.String()
}

func pLine(status, name, arch, ver, src, srcVer, builtUsing string) string {
	return strings.Join([]string{"P", status, name, arch, ver, src, srcVer, builtUsing, "."}, "\t")
}

var okRead = ReadStatus{ExitCode: 0}

const (
	deb12 = vulnver.DistroDebian
	ubu   = vulnver.DistroUbuntu
)

// assertKernelAgreesWithVulnver checks the review rule that the parser and
// vulnver can never reach different kernel verdicts for the same host.
func assertKernelAgreesWithVulnver(t *testing.T, inv InstalledInventory, distro vulnver.Distro) {
	t.Helper()
	k := inv.RunningKernel
	kb, err := vulnver.RunningKernel(vulnver.KernelFacts{
		Distro: distro, Release: k.Release, BuildVersion: k.Build, Installed: binaries(inv.Packages),
	})
	switch {
	case k.State == KernelMapped && err != nil:
		t.Fatalf("parser mapped %s %s, vulnver: %v", k.Source, k.Version, err)
	case k.State != KernelMapped && err == nil && k.Release != "":
		t.Fatalf("parser says unknown (%s), vulnver maps %+v", k.Reason, kb)
	case k.State == KernelMapped && (kb.SourceName != k.Source || kb.Version != k.Version || kb.ImageBinary != k.ImagePackage):
		t.Fatalf("parser %s %s from %s, vulnver %+v", k.Source, k.Version, k.ImagePackage, kb)
	}
}

func TestInstalledDebian12UsesSourceVersionNeverBinaryVersion(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "debian12.txt"), okRead, deb12)
	if !inv.Complete || inv.Reason != "" {
		t.Fatalf("complete=%v reason=%q, want complete", inv.Complete, inv.Reason)
	}
	cases := []struct {
		name, arch, ver, src, srcVer string
	}{
		{"base-files", "amd64", "12.4+deb12u7", "base-files", "12.4+deb12u7"},
		// binNMU: binary 2.14-2+b1, source 2.14-2.
		{"libjansson4", "amd64", "2.14-2+b1", "jansson", "2.14-2"},
		// binary named apart from its source.
		{"libgcc-s1", "amd64", "12.2.0-14", "gcc-12", "12.2.0-14"},
		// binary versioned apart from its source.
		{"cpp", "amd64", "4:12.2.0-3", "gcc-defaults", "1.203"},
		{"libc6", "amd64", "2.36-9+deb12u8", "glibc", "2.36-9+deb12u8"},
		{"libc6", "i386", "2.36-9+deb12u8", "glibc", "2.36-9+deb12u8"},
		// signed image: dpkg's source:Version stays as reported.
		{"linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1"},
	}
	for _, c := range cases {
		p := findPkg(t, inv, c.name, c.arch)
		if p.Version != c.ver || p.Source != c.src || p.SourceVersion != c.srcVer {
			t.Errorf("%s:%s = (%s, %s, %s), want (%s, %s, %s)", c.name, c.arch,
				p.Version, p.Source, p.SourceVersion, c.ver, c.src, c.srcVer)
		}
	}
	if hasPkg(inv, "oldpkg") {
		t.Error("config-files package must not be in the installed inventory")
	}
	if len(inv.Packages) != 10 {
		t.Errorf("packages = %d, want 10", len(inv.Packages))
	}
}

func TestInstalledBuiltUsingKeptOnlyForKernelImages(t *testing.T) {
	doc := installedDoc("K\t6.1.0-26-amd64\t#1 SMP Debian 6.1.112-1",
		pLine("installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)"),
		pLine("installed", "some-tool", "amd64", "1.0-1", "some-tool", "1.0-1", "golang-1.19 (= 1.19.8-2)"),
	)
	inv := ParseInstalled([]byte(doc), okRead, deb12)
	if !inv.Complete {
		t.Fatalf("incomplete: %s", inv.Reason)
	}
	if p := findPkg(t, inv, "linux-image-6.1.0-26-amd64", "amd64"); p.BuiltUsing != "linux (= 6.1.112-1)" {
		t.Errorf("kernel BuiltUsing = %q", p.BuiltUsing)
	}
	if p := findPkg(t, inv, "some-tool", "amd64"); p.BuiltUsing != "" {
		t.Errorf("non-kernel BuiltUsing = %q, want empty", p.BuiltUsing)
	}
}

// Go and Rust packages such as docker.io carry Built-Using lists far beyond
// the field and line limits; for non-kernel binaries the field is dropped
// before any limit applies, so such hosts still get a complete read.
func TestInstalledLongNonKernelBuiltUsingDroppedBeforeLimits(t *testing.T) {
	var entries []string
	for i := 0; len(strings.Join(entries, ", ")) <= 2*maxInstalledLine; i++ {
		entries = append(entries, fmt.Sprintf("golang-github-example-module%d (= 0.0~git20240101.%d-1)", i, i))
	}
	long := strings.Join(entries, ", ")
	doc := installedDoc("K\t6.1.0-26-amd64\t#1 SMP",
		pLine("installed", "docker.io", "amd64", "20.10.24+dfsg1-1+b3", "docker.io", "20.10.24+dfsg1-1", long),
		pLine("installed", "base-files", "amd64", "12.4", "base-files", "12.4", ""),
	)
	inv := ParseInstalled([]byte(doc), okRead, deb12)
	if !inv.Complete || inv.Dropped != 0 {
		t.Fatalf("complete=%v dropped=%d reason=%q, want complete", inv.Complete, inv.Dropped, inv.Reason)
	}
	p := findPkg(t, inv, "docker.io", "amd64")
	if p.BuiltUsing != "" || p.SourceVersion != "20.10.24+dfsg1-1" {
		t.Errorf("docker.io = %+v, want no Built-Using and source version 20.10.24+dfsg1-1", p)
	}
	// The same list on a kernel image is still over the limit.
	doc = installedDoc("K\t6.1.0-26-amd64\t#1 SMP",
		pLine("installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", long),
	)
	if inv := ParseInstalled([]byte(doc), okRead, deb12); inv.Complete || !strings.HasPrefix(inv.Reason, ReasonMalformed) {
		t.Errorf("kernel image with overlong Built-Using: complete=%v reason=%q", inv.Complete, inv.Reason)
	}
}

// The kernel source classification is vulnver.IsKernelSource, reached
// through the parser: an image from an unsigned kernel source maps, a
// signed, meta or non-kernel source never does.
func TestKernelImageSourceUsesVulnverClassification(t *testing.T) {
	cases := map[string]bool{
		"linux":                    true,
		"linux-5.10":               true, // Debian LTS kernel source
		"linux-hwe-6.8":            true,
		"linux-aws":                true,
		"linux-aws-6.8":            true,
		"linux-azure":              true,
		"linux-gcp":                true,
		"linux-oracle":             true,
		"linux-lowlatency":         true,
		"linux-lowlatency-hwe-6.8": true,
		"linux-oem-6.8":            true,
		"linux-raspi":              true,
		"linux-ibm":                true,
		"linux-kvm":                true,
		"linux-nvidia":             true,
		"linux-signed":             false,
		"linux-signed-amd64":       false,
		"linux-signed-hwe-6.8":     false,
		"linux-meta":               false,
		"linux-meta-hwe-6.8":       false,
		"linux-restricted-modules": false,
		"linux-firmware":           false,
		"linux-base":               false,
		"linux-latest":             false,
		"linuxx":                   false,
		"custom-kernel":            false,
		"proxmox-kernel-signed":    false,
	}
	const kern = "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
	for src, want := range cases {
		t.Run(src, func(t *testing.T) {
			if got := vulnver.IsKernelSource(src); got != want {
				t.Errorf("vulnver.IsKernelSource(%q) = %v, want %v", src, got, want)
			}
			doc := installedDoc(kern, pLine("installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", src, "6.1.112-1", ""))
			inv := ParseInstalled([]byte(doc), okRead, deb12)
			assertKernelAgreesWithVulnver(t, inv, deb12)
			if got := inv.RunningKernel.State == KernelMapped; got != want {
				t.Errorf("image from %q: mapped = %v, want %v", src, got, want)
			}
			// Built-Using of a signed image follows the same rule.
			doc = installedDoc(kern, pLine("installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", src+" (= 6.1.112-1)"))
			inv = ParseInstalled([]byte(doc), okRead, deb12)
			assertKernelAgreesWithVulnver(t, inv, deb12)
			if got := inv.RunningKernel.State == KernelMapped; got != want {
				t.Errorf("Built-Using %q: mapped = %v, want %v", src, got, want)
			}
		})
	}
}

func TestInstalledRecordOrderEnforced(t *testing.T) {
	good := pLine("installed", "base-files", "amd64", "12.4", "base-files", "12.4", "")
	other := pLine("installed", "openssl", "amd64", "3.0.13-1", "openssl", "3.0.13-1", "")
	kern := "K\t6.1.0-26-amd64\t#1 SMP"
	cases := []struct {
		name string
		doc  string
		pkgs int
	}{
		{"K before P lines", InstalledFormat + "\n" + kern + "\n" + good + "\n" + other + "\nEND\t2\n", 0},
		{"K between P lines", InstalledFormat + "\n" + good + "\n" + kern + "\n" + other + "\nEND\t2\n", 1},
		{"END before K", InstalledFormat + "\n" + good + "\n" + other + "\nEND\t2\n" + kern + "\n", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := ParseInstalled([]byte(c.doc), okRead, deb12)
			if inv.Complete || !strings.HasPrefix(inv.Reason, ReasonMalformed) {
				t.Fatalf("complete=%v reason=%q, want malformed", inv.Complete, inv.Reason)
			}
			if len(inv.Packages) != c.pkgs {
				t.Errorf("packages = %d, want %d", len(inv.Packages), c.pkgs)
			}
		})
	}
}

// A read that lists no installed package can never prove that every
// package was removed.
func TestInstalledReadWithoutPackagesIsPartial(t *testing.T) {
	kern := "K\t6.1.0-26-amd64\t#1 SMP"
	cases := map[string]string{
		"no P lines":        installedDoc(kern),
		"only config-files": installedDoc(kern, pLine("config-files", "oldpkg", "amd64", "1.0-1", "oldpkg", "1.0-1", "")),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			inv := ParseInstalled([]byte(doc), okRead, deb12)
			if inv.Complete || inv.Reason != ReasonNoPackages {
				t.Fatalf("complete=%v reason=%q, want %q", inv.Complete, inv.Reason, ReasonNoPackages)
			}
		})
	}
}

// dpkg-query always fills source:Package and source:Version (falling back
// to the binary name and version itself), so an empty field is anomalous
// input: the line is malformed and the read partial, never filled in from
// the binary fields.
func TestInstalledEmptySourceFieldMakesLineMalformed(t *testing.T) {
	both := pLine("installed", "both", "amd64", "1.0-1+b2", "upstream", "1.0-1", "")
	cases := []struct {
		name, src, srcVer string
	}{
		{"empty source:Version", "upstream", ""},
		{"empty source:Package", "", "1.0-1"},
		{"both empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := pLine("installed", "anomalous", "amd64", "1.0-1+b2", c.src, c.srcVer, "")
			inv := ParseInstalled([]byte(installedDoc("K\t6.1.0-26-amd64\t#1 SMP", both, bad)), okRead, deb12)
			if inv.Complete {
				t.Fatal("read with an empty source field claims complete")
			}
			if inv.Reason != ReasonMalformed+" 3" {
				t.Errorf("reason = %q, want %q", inv.Reason, ReasonMalformed+" 3")
			}
			if inv.Dropped != 1 {
				t.Errorf("dropped = %d, want 1", inv.Dropped)
			}
			if hasPkg(inv, "anomalous") {
				t.Error("line with an empty source field is in the inventory")
			}
			// The well-formed line keeps dpkg's source version, not the
			// binNMU binary version.
			if p := findPkg(t, inv, "both", "amd64"); p.Source != "upstream" || p.SourceVersion != "1.0-1" {
				t.Errorf("both: source=(%s, %s), want (upstream, 1.0-1)", p.Source, p.SourceVersion)
			}
		})
	}
}

func TestRunningKernelDebian12SignedMapsViaBuiltUsing(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "debian12.txt"), okRead, deb12)
	assertKernelAgreesWithVulnver(t, inv, deb12)
	k := inv.RunningKernel
	if k.State != KernelMapped {
		t.Fatalf("state = %s (%s), want mapped", k.State, k.Reason)
	}
	if k.Release != "6.1.0-26-amd64" || k.ImagePackage != "linux-image-6.1.0-26-amd64" {
		t.Errorf("release/image = %s/%s", k.Release, k.ImagePackage)
	}
	if k.Source != "linux" || k.Version != "6.1.112-1" {
		t.Errorf("kernel source = %s %s, want linux 6.1.112-1", k.Source, k.Version)
	}
	if k.Build != "#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)" {
		t.Errorf("build = %q", k.Build)
	}
}

func TestRunningKernelUbuntu2404SignedMapsViaBuiltUsing(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "ubuntu2404.txt"), okRead, ubu)
	if !inv.Complete {
		t.Fatalf("incomplete: %s", inv.Reason)
	}
	assertKernelAgreesWithVulnver(t, inv, ubu)
	k := inv.RunningKernel
	if k.State != KernelMapped {
		t.Fatalf("state = %s (%s), want mapped", k.State, k.Reason)
	}
	if k.Source != "linux" || k.Version != "6.8.0-45.45" || k.ImagePackage != "linux-image-6.8.0-45-generic" {
		t.Errorf("kernel = %s %s from %s", k.Source, k.Version, k.ImagePackage)
	}
}

func TestInstalledKernelsListedWithRunningMarked(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "debian12.txt"), okRead, deb12)
	want := map[string]struct {
		src, ver string
		running  bool
	}{
		"linux-image-6.1.0-25-amd64": {"linux", "6.1.106-3", false},
		"linux-image-6.1.0-26-amd64": {"linux", "6.1.112-1", true},
	}
	if len(inv.InstalledKernels) != len(want) {
		t.Fatalf("installed kernels = %+v", inv.InstalledKernels)
	}
	for _, k := range inv.InstalledKernels {
		w, ok := want[k.Package]
		if !ok {
			t.Errorf("unexpected installed kernel %s (meta packages are not kernels)", k.Package)
			continue
		}
		if k.Source != w.src || k.SourceVersion != w.ver || k.Running != w.running || !k.Mapped {
			t.Errorf("%s = %+v, want %+v", k.Package, k, w)
		}
	}
}

func TestRunningKernelUnmappableIsVersionUnknown(t *testing.T) {
	img := func(name, src, srcVer, bu string) string {
		return pLine("installed", name, "amd64", "6.1.112-1", src, srcVer, bu)
	}
	const deb = "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
	signed := img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)")
	ubuImg := pLine("installed", "linux-image-6.8.0-45-generic", "amd64", "6.8.0-45.45", "linux-signed", "6.8.0-45.45", "linux (= 6.8.0-45.45)")
	cases := []struct {
		name   string
		kernel string
		lines  []string
		distro vulnver.Distro // default Debian
	}{
		// ADR 0011 D4 and vulnver checkBuildString: the build string must
		// carry the version; empty or unrecognised is never mapped.
		{"empty build string", "K\t6.1.0-26-amd64\t", []string{signed}, 0},
		{"build string without version", "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC", []string{signed}, 0},
		{"build string with two Debian versions", "K\t6.1.0-26-amd64\t#1 SMP Debian 6.1.112-1 Debian 6.1.112-1", []string{signed}, 0},
		{"Debian build string on Ubuntu", "K\t6.8.0-45-generic\t#1 SMP PREEMPT_DYNAMIC Debian 6.8.0-45.45", []string{ubuImg}, ubu},
		{"Ubuntu empty build string", "K\t6.8.0-45-generic\t", []string{ubuImg}, ubu},
		{"Ubuntu build string without marker", "K\t6.8.0-45-generic\tSMP PREEMPT_DYNAMIC #45", []string{ubuImg}, ubu},
		{"Ubuntu marker on Debian", "K\t6.8.0-45-generic\t#45-Ubuntu SMP PREEMPT_DYNAMIC", []string{ubuImg}, 0},
		{"unknown distribution", deb, []string{signed}, -1},
		// vulnver maps linux-image-<release> only (ADR 0011 D4).
		{"Ubuntu linux-image-unsigned only", "K\t6.8.0-45-generic\t#45-Ubuntu SMP PREEMPT_DYNAMIC",
			[]string{pLine("installed", "linux-image-unsigned-6.8.0-45-generic", "amd64", "6.8.0-45.45", "linux", "6.8.0-45.45", "")}, ubu},
		{"image for two architectures", deb,
			[]string{signed, strings.Replace(signed, "\tamd64\t", "\ti386\t", 1)}, 0},
		{"no image for running release", deb,
			[]string{img("linux-image-6.1.0-25-amd64", "linux-signed-amd64", "6.1.106+3", "linux (= 6.1.106-3)")}, 0},
		{"signed without Built-Using", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "")}, 0},
		{"Built-Using without kernel source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "shim (= 15.8-1)")}, 0},
		{"Built-Using with two kernel sources", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1), linux-hwe-6.1 (= 6.1.112-1)")}, 0},
		{"Built-Using names a signed source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux-signed-amd64 (= 6.1.112+1)")}, 0},
		{"Built-Using names a meta source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux-meta (= 6.1.112)")}, 0},
		{"Built-Using unparseable", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (>= 6.1.112-1)")}, 0},
		{"Built-Using one entry unparseable", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1), garbage")}, 0},
		{"image from meta source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-meta", "6.1.112", "linux (= 6.1.112-1)")}, 0},
		{"image from unrelated source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "custom-kernel", "6.1.112-1", "")}, 0},
		{"Debian build string mismatch", "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.106-3 (2024-08-26)",
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)")}, 0},
		{"Ubuntu upload mismatch", "K\t6.8.0-45-generic\t#44-Ubuntu SMP PREEMPT_DYNAMIC", []string{ubuImg}, ubu},
		{"Ubuntu HWE upload mismatch", "K\t6.8.0-45-generic\t#45~20.04.1-Ubuntu SMP PREEMPT_DYNAMIC",
			[]string{pLine("installed", "linux-image-6.8.0-45-generic", "amd64", "6.8.0-45.45~22.04.1", "linux-signed-hwe-6.8", "6.8.0-45.45~22.04.1", "linux-hwe-6.8 (= 6.8.0-45.45~22.04.1)")}, ubu},
		{"Proxmox kernel", "K\t6.8.12-4-pve\t#1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4",
			[]string{pLine("installed", "proxmox-kernel-6.8.12-4-pve-signed", "amd64", "6.8.12-4", "proxmox-kernel-signed", "6.8.12-4", "")}, 0},
		{"missing kernel record", "",
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)")}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			distro := c.distro
			switch {
			case distro == 0:
				distro = deb12
			case distro < 0:
				distro = 0
			}
			inv := ParseInstalled([]byte(installedDoc(c.kernel, c.lines...)), okRead, distro)
			assertKernelAgreesWithVulnver(t, inv, distro)
			k := inv.RunningKernel
			if k.State != KernelVersionUnknown {
				t.Fatalf("state = %s (source %s %s), want kernel version unknown", k.State, k.Source, k.Version)
			}
			if k.Source != "" || k.Version != "" {
				t.Errorf("unknown kernel carries version basis %s %s", k.Source, k.Version)
			}
			if k.Reason == "" {
				t.Error("unknown kernel without reason")
			}
		})
	}
}

func TestRunningKernelMapsWithoutSignedImage(t *testing.T) {
	cases := []struct {
		name, kernel string
		lines        []string
		distro       vulnver.Distro
		src, ver     string
	}{
		{"Debian unsigned image", "K\t6.1.0-26-cloud-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)",
			[]string{pLine("installed", "linux-image-6.1.0-26-cloud-amd64", "amd64", "6.1.112-1", "linux", "6.1.112-1", "")},
			deb12, "linux", "6.1.112-1"},
		{"Ubuntu unsigned source", "K\t6.8.0-45-generic\t#45-Ubuntu SMP PREEMPT_DYNAMIC",
			[]string{pLine("installed", "linux-image-6.8.0-45-generic", "amd64", "6.8.0-45.45", "linux", "6.8.0-45.45", "")},
			ubu, "linux", "6.8.0-45.45"},
		{"Ubuntu HWE signed", "K\t6.8.0-45-generic\t#45~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC",
			[]string{pLine("installed", "linux-image-6.8.0-45-generic", "amd64", "6.8.0-45.45~22.04.1", "linux-signed-hwe-6.8", "6.8.0-45.45~22.04.1", "linux-hwe-6.8 (= 6.8.0-45.45~22.04.1)")},
			ubu, "linux-hwe-6.8", "6.8.0-45.45~22.04.1"},
		// Only linux-image-<release> is the running image (vulnver, ADR
		// 0011 D4); a linux-image-<release>-unsigned binary is a different
		// package and the build string confirms the signed one.
		{"unsigned variant beside the signed image", "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)",
			[]string{
				pLine("installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)"),
				pLine("installed", "linux-image-6.1.0-26-amd64-unsigned", "amd64", "6.1.106-3", "linux", "6.1.106-3", ""),
			},
			deb12, "linux", "6.1.112-1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := ParseInstalled([]byte(installedDoc(c.kernel, c.lines...)), okRead, c.distro)
			assertKernelAgreesWithVulnver(t, inv, c.distro)
			k := inv.RunningKernel
			if k.State != KernelMapped || k.Source != c.src || k.Version != c.ver {
				t.Fatalf("kernel = %s %s %s (%s), want mapped %s %s", k.State, k.Source, k.Version, k.Reason, c.src, c.ver)
			}
		})
	}
}

func TestInstalledMalformedLinesMarkPartial(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "malformed.txt"), okRead, deb12)
	if inv.Complete {
		t.Fatal("read with malformed lines claims complete")
	}
	if !strings.HasPrefix(inv.Reason, ReasonMalformed) {
		t.Errorf("reason = %q", inv.Reason)
	}
	if len(inv.Packages) != 2 || !hasPkg(inv, "good-pkg") || !hasPkg(inv, "other-good") {
		t.Errorf("packages = %+v, want good-pkg and other-good", inv.Packages)
	}
	if inv.Dropped != 8 {
		t.Errorf("dropped = %d, want 8", inv.Dropped)
	}
	if strings.Contains(inv.Reason, "Bad_Name") {
		t.Error("reason echoes host content")
	}
}

func TestInstalledCompletenessNeverClaimedOnPartialRead(t *testing.T) {
	good := pLine("installed", "base-files", "amd64", "12.4", "base-files", "12.4", "")
	kern := "K\t6.1.0-26-amd64\t#1 SMP"
	full := installedDoc(kern, good)
	cases := []struct {
		name   string
		doc    string
		rs     ReadStatus
		reason string
		pkgs   int
	}{
		{"nonzero exit", full, ReadStatus{ExitCode: 1}, ReasonReadFailed, 1},
		{"output truncated by executor", full, ReadStatus{Truncated: true}, ReasonTruncated, 1},
		{"missing END", strings.TrimSuffix(full, "END\t1\n"), okRead, ReasonNoEnd, 1},
		{"END count mismatch", strings.Replace(full, "END\t1", "END\t2", 1), okRead, ReasonCountMismatch, 1},
		{"END count garbage", strings.Replace(full, "END\t1", "END\tx", 1), okRead, ReasonMalformed, 1},
		{"END count with sign", strings.Replace(full, "END\t1", "END\t+1", 1), okRead, ReasonMalformed, 1},
		{"END count with leading zero", strings.Replace(full, "END\t1", "END\t01", 1), okRead, ReasonMalformed, 1},
		{"END count with extra field", strings.Replace(full, "END\t1", "END\t1\t1", 1), okRead, ReasonMalformed, 1},
		{"line after END", full + good + "\n", okRead, ReasonMalformed, 1},
		{"last line without newline", strings.TrimSuffix(full, "\n"), okRead, ReasonTruncated, 1},
		{"cut mid-line", full[:len(InstalledFormat)+1+len(good)-3], okRead, ReasonTruncated, 0},
		{"missing header", strings.TrimPrefix(full, InstalledFormat+"\n"), okRead, ReasonFormat, 0},
		{"wrong header", strings.Replace(full, InstalledFormat, "nos-installed-v2", 1), okRead, ReasonFormat, 0},
		{"empty output", "", okRead, ReasonFormat, 0},
		{"missing kernel record", installedDoc("", good), okRead, ReasonNoKernel, 1},
		{"two kernel records", strings.Replace(full, kern, kern+"\n"+kern, 1), okRead, ReasonMalformed, 1},
		{"invalid UTF-8", strings.Replace(full, "#1 SMP", "#1 \xff SMP", 1), okRead, ReasonMalformed, 1},
		{"control character", strings.Replace(full, "#1 SMP", "#1 \x1b[31m SMP", 1), okRead, ReasonMalformed, 1},
		{"carriage return", strings.Replace(full, "\t.\n", "\t.\r\n", 1), okRead, ReasonMalformed, 0},
		{"overlong line", installedDoc(kern, good, pLine("installed", "x"+strings.Repeat("a", maxInstalledLine), "amd64", "1", "x", "1", "")), okRead, ReasonMalformed, 1},
		{"overlong name", installedDoc(kern, good, pLine("installed", "a"+strings.Repeat("b", maxFieldLen), "amd64", "1", "x", "1", "")), okRead, ReasonMalformed, 1},
		{"overlong Built-Using", installedDoc(kern, good, pLine("installed", "linux-image-x", "amd64", "1", "linux-signed", "1", strings.Repeat("a", maxBuiltUsingLen+1))), okRead, ReasonMalformed, 1},
		{"duplicate package", installedDoc(kern, good, good), okRead, ReasonMalformed, 1},
		{"unknown status", installedDoc(kern, pLine("bogus", "a1", "amd64", "1", "a1", "1", "")), okRead, ReasonMalformed, 0},
		{"bad source version", installedDoc(kern, pLine("installed", "a1", "amd64", "1", "a1", "1 2", "")), okRead, ReasonMalformed, 0},
		{"bad release", strings.Replace(full, "6.1.0-26-amd64", "6.1.0 26", 1), okRead, ReasonMalformed, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := ParseInstalled([]byte(c.doc), c.rs, deb12)
			if inv.Complete {
				t.Fatal("partial read claims complete")
			}
			if !strings.HasPrefix(inv.Reason, c.reason) {
				t.Errorf("reason = %q, want prefix %q", inv.Reason, c.reason)
			}
			if len(inv.Packages) != c.pkgs {
				t.Errorf("packages = %d, want %d", len(inv.Packages), c.pkgs)
			}
		})
	}
	// Control: the same document read cleanly is complete.
	if inv := ParseInstalled([]byte(full), okRead, deb12); !inv.Complete || inv.Reason != "" {
		t.Fatalf("clean read: complete=%v reason=%q", inv.Complete, inv.Reason)
	}
}

func TestInstalledFirstReasonWins(t *testing.T) {
	doc := installedDoc("K\t6.1.0-26-amd64\t#1 SMP", "P\tgarbage")
	inv := ParseInstalled([]byte(doc), ReadStatus{ExitCode: 2}, deb12)
	if inv.Complete || !strings.HasPrefix(inv.Reason, ReasonReadFailed) {
		t.Fatalf("complete=%v reason=%q", inv.Complete, inv.Reason)
	}
}

// half-installed and half-configured are left by a failed or interrupted
// dpkg run: files of two versions may be on disk, so the source version is
// no sure basis and the read can never be complete. The package is still
// inventory (its files are on disk).
func TestInstalledUnfinishedDpkgStateMakesReadPartial(t *testing.T) {
	good := pLine("installed", "base-files", "amd64", "12.4", "base-files", "12.4", "")
	kern := "K\t6.1.0-26-amd64\t#1 SMP"
	for _, status := range []string{"half-installed", "half-configured"} {
		t.Run(status, func(t *testing.T) {
			doc := installedDoc(kern, good, pLine(status, "openssl", "amd64", "3.0.15-1~deb12u1", "openssl", "3.0.15-1~deb12u1", ""))
			inv := ParseInstalled([]byte(doc), okRead, deb12)
			if inv.Complete {
				t.Fatalf("read with a %s package claims complete", status)
			}
			if inv.Reason != ReasonUnfinished+" 3" {
				t.Errorf("reason = %q, want %q", inv.Reason, ReasonUnfinished+" 3")
			}
			if p := findPkg(t, inv, "openssl", "amd64"); p.Status != status {
				t.Errorf("status = %q, want %q", p.Status, status)
			}
			if inv.Dropped != 0 {
				t.Errorf("dropped = %d, want 0", inv.Dropped)
			}
		})
	}
	// Settled states keep the read complete.
	for _, status := range []string{"installed", "unpacked", "triggers-awaited", "triggers-pending"} {
		t.Run(status, func(t *testing.T) {
			doc := installedDoc(kern, good, pLine(status, "openssl", "amd64", "3.0.15-1", "openssl", "3.0.15-1", ""))
			if inv := ParseInstalled([]byte(doc), okRead, deb12); !inv.Complete {
				t.Fatalf("%s: incomplete: %s", status, inv.Reason)
			}
		})
	}
}

// An empty or unrecognised build string is a well-formed record: the read
// stays complete, only the kernel is "kernel version unknown".
func TestInstalledUnknownKernelBuildKeepsReadComplete(t *testing.T) {
	img := pLine("installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)")
	for _, build := range []string{"", "#1 SMP PREEMPT_DYNAMIC", "custom build 6.1.112-1"} {
		t.Run(build, func(t *testing.T) {
			inv := ParseInstalled([]byte(installedDoc("K\t6.1.0-26-amd64\t"+build, img)), okRead, deb12)
			if !inv.Complete {
				t.Fatalf("incomplete: %s", inv.Reason)
			}
			k := inv.RunningKernel
			if k.State != KernelVersionUnknown || k.Reason != KernelReasonUnmapped || k.Source != "" || k.Version != "" {
				t.Fatalf("kernel = %+v, want kernel version unknown", k)
			}
			if k.Release != "6.1.0-26-amd64" || k.Build != build {
				t.Errorf("release/build = %q/%q", k.Release, k.Build)
			}
			// The installed image is still listed as context.
			if len(inv.InstalledKernels) != 1 || !inv.InstalledKernels[0].Running || !inv.InstalledKernels[0].Mapped {
				t.Errorf("installed kernels = %+v", inv.InstalledKernels)
			}
		})
	}
}

func TestInstalledPackageLimit(t *testing.T) {
	gen := func(n int) string {
		lines := make([]string, n)
		for i := range lines {
			lines[i] = pLine("installed", fmt.Sprintf("pkg%d", i), "amd64", "1.0-1", fmt.Sprintf("src%d", i), "1.0-1", "")
		}
		return installedDoc("K\t6.1.0-26-amd64\t#1 SMP", lines...)
	}
	cases := []struct {
		n        int
		complete bool
		kept     int
	}{
		{MaxPackages - 1, true, MaxPackages - 1},
		{MaxPackages, false, MaxPackages},
		{MaxPackages + 1, false, MaxPackages},
		{MaxPackages + 500, false, MaxPackages},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.n), func(t *testing.T) {
			inv := ParseInstalled([]byte(gen(c.n)), okRead, deb12)
			if inv.Complete != c.complete || len(inv.Packages) != c.kept {
				t.Fatalf("complete=%v kept=%d reason=%q, want complete=%v kept=%d", inv.Complete, len(inv.Packages), inv.Reason, c.complete, c.kept)
			}
			if !c.complete && !strings.HasPrefix(inv.Reason, ReasonLimit) {
				t.Errorf("reason = %q", inv.Reason)
			}
		})
	}
}

func TestInstalledOversizedOutputIsPartial(t *testing.T) {
	line := pLine("installed", "p", "amd64", "1", "p", "1", "")
	var b strings.Builder
	b.WriteString(InstalledFormat + "\n")
	for i := 0; b.Len() <= MaxInstalledOutput; i++ {
		b.WriteString(strings.Replace(line, "\tp\t", fmt.Sprintf("\tp%d\t", i), 1) + "\n")
	}
	inv := ParseInstalled([]byte(b.String()), okRead, deb12)
	if inv.Complete || !strings.HasPrefix(inv.Reason, ReasonTruncated) {
		t.Fatalf("complete=%v reason=%q", inv.Complete, inv.Reason)
	}
	if len(inv.Packages) > MaxPackages {
		t.Fatalf("kept %d packages", len(inv.Packages))
	}
}
