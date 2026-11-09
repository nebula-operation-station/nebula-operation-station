// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"errors"
	"strings"
	"testing"
)

// The fixture versions below follow the shapes of real Debian 12 and
// Ubuntu 24.04/22.04 packages. ADR 0011 D4 marks the concrete pairs as
// *verify*; the rules tested do not depend on the exact numbers.

func TestBinNMUComparedOnSourceVersion(t *testing.T) {
	// Binary 1.2-3+b1 is a binNMU of source 1.2-3. The tracker's fixed
	// version is the source version 1.2-3+deb12u1. Compared on the binary
	// version the host would look fixed or not depending on the +bN
	// suffix; compared on source it is affected.
	installed := []Binary{
		{Name: "libfoo1", Version: "1.2-3+b1", SourceName: "foo", SourceVersion: "1.2-3"},
	}
	basis, err := SourceVersionBasis(SchemeDpkg, "foo", installed)
	if err != nil {
		t.Fatalf("SourceVersionBasis: %v", err)
	}
	if basis.Version != "1.2-3" {
		t.Fatalf("basis = %q, want source version 1.2-3 (never the binary version)", basis.Version)
	}
	affected, err := Affected(SchemeDpkg, basis.Version, "1.2-3+deb12u1")
	if err != nil || !affected {
		t.Fatalf("Affected(source 1.2-3, fixed 1.2-3+deb12u1) = %v, %v; want true", affected, err)
	}

	// Source fixed in 1.2-3: the binNMU binary of exactly that source is
	// fixed, and so is the source itself.
	affected, err = Affected(SchemeDpkg, basis.Version, "1.2-3")
	if err != nil || affected {
		t.Fatalf("Affected(source 1.2-3, fixed 1.2-3) = %v, %v; want false", affected, err)
	}

	// The binNMU's binary version 1.2-3+b1 would wrongly compare as newer
	// than a fixed 1.2-3+a0 style upload; on source it does not.
	binaryGreater, _ := CompareDpkg("1.2-3+b1", "1.2-3+a1")
	if binaryGreater <= 0 {
		t.Fatal("precondition: binary version sorts after 1.2-3+a1")
	}
	affected, err = Affected(SchemeDpkg, basis.Version, "1.2-3+a1")
	if err != nil || !affected {
		t.Fatalf("source 1.2-3 vs fixed 1.2-3+a1 = %v, %v; want affected", affected, err)
	}
}

func TestBinaryVersionedApartFromSource(t *testing.T) {
	// libgcc-s1 carries its own version line but is built from gcc-12.
	installed := []Binary{
		{Name: "libgcc-s1", Version: "12.2.0-14", SourceName: "gcc-12", SourceVersion: "12.2.0-14"},
		{Name: "cpp-12", Version: "12.2.0-14", SourceName: "gcc-12", SourceVersion: "12.2.0-14"},
		// A binary named like the source but from another source package
		// must not be mixed in.
		{Name: "gcc-12", Version: "99", SourceName: "gcc-12-cross", SourceVersion: "1"},
		// Separately versioned binary: binary 1:2.0 from source 3.1-1.
		{Name: "libbar0", Version: "1:2.0", SourceName: "bar", SourceVersion: "3.1-1"},
	}
	basis, err := SourceVersionBasis(SchemeDpkg, "gcc-12", installed)
	if err != nil {
		t.Fatalf("gcc-12: %v", err)
	}
	if basis.Version != "12.2.0-14" || len(basis.Binaries) != 2 {
		t.Fatalf("gcc-12 basis = %+v", basis)
	}
	basis, err = SourceVersionBasis(SchemeDpkg, "bar", installed)
	if err != nil {
		t.Fatalf("bar: %v", err)
	}
	if basis.Version != "3.1-1" {
		t.Fatalf("bar basis = %q, want source version 3.1-1, not binary 1:2.0", basis.Version)
	}
}

func TestMixedSourceVersionsLowestWins(t *testing.T) {
	installed := []Binary{
		{Name: "libssl3", Version: "3.0.15-1~deb12u1", SourceName: "openssl", SourceVersion: "3.0.15-1~deb12u1"},
		{Name: "openssl", Version: "3.0.14-1~deb12u2", SourceName: "openssl", SourceVersion: "3.0.14-1~deb12u2"},
		{Name: "libssl-dev", Version: "3.0.15-1~deb12u1+b1", SourceName: "openssl", SourceVersion: "3.0.15-1~deb12u1"},
	}
	basis, err := SourceVersionBasis(SchemeDpkg, "openssl", installed)
	if err != nil {
		t.Fatalf("SourceVersionBasis: %v", err)
	}
	if basis.Version != "3.0.14-1~deb12u2" {
		t.Fatalf("basis = %q, want the lowest 3.0.14-1~deb12u2", basis.Version)
	}
	if len(basis.Binaries) != 3 {
		t.Fatalf("basis lists %d binaries, want all 3", len(basis.Binaries))
	}
	affected, err := Affected(SchemeDpkg, basis.Version, "3.0.15-1~deb12u1")
	if err != nil || !affected {
		t.Fatalf("partial upgrade must stay affected: %v, %v", affected, err)
	}

	// Alpine: origin package and its version.
	apk := []Binary{
		{Name: "libcrypto3", Version: "3.3.2-r1", SourceName: "openssl", SourceVersion: "3.3.2-r1"},
		{Name: "libssl3", Version: "3.3.2-r0", SourceName: "openssl", SourceVersion: "3.3.2-r0"},
	}
	basis, err = SourceVersionBasis(SchemeAPK, "openssl", apk)
	if err != nil || basis.Version != "3.3.2-r0" {
		t.Fatalf("apk basis = %+v, %v; want 3.3.2-r0", basis, err)
	}
}

func TestSourceVersionBasisRejections(t *testing.T) {
	ok := Binary{Name: "a", Version: "1.0-1", SourceName: "foo", SourceVersion: "1.0-1"}
	cases := []struct {
		name      string
		scheme    Scheme
		source    string
		installed []Binary
		want      error
	}{
		{"no binary of source", SchemeDpkg, "bar", []Binary{ok}, ErrNoBasis},
		{"empty list", SchemeDpkg, "foo", nil, ErrNoBasis},
		{"empty source version", SchemeDpkg, "foo", []Binary{ok, {Name: "b", Version: "1.0-1", SourceName: "foo"}}, ErrInvalidVersion},
		{"invalid source version", SchemeDpkg, "foo", []Binary{ok, {Name: "b", SourceName: "foo", SourceVersion: "x"}}, ErrNoBasis},
		{"apk version in dpkg", SchemeAPK, "foo", []Binary{ok}, ErrInvalidVersion},
		{"empty source name", SchemeDpkg, "", []Binary{ok}, ErrNoBasis},
		{"debian signed kernel", SchemeDpkg, "linux-signed-amd64", []Binary{{Name: "linux-image-6.1.0-26-amd64", SourceName: "linux-signed-amd64", SourceVersion: "6.1.112+1"}}, ErrNotVersionBasis},
		{"ubuntu signed kernel", SchemeDpkg, "linux-signed", []Binary{{Name: "linux-image-6.8.0-45-generic", SourceName: "linux-signed", SourceVersion: "6.8.0-45.45"}}, ErrNotVersionBasis},
		{"ubuntu meta", SchemeDpkg, "linux-meta", []Binary{{Name: "linux-image-generic", SourceName: "linux-meta", SourceVersion: "6.8.0.45.45"}}, ErrNotVersionBasis},
		{"ubuntu hwe meta", SchemeDpkg, "linux-meta-hwe-6.8", []Binary{{Name: "linux-image-generic-hwe-22.04", SourceName: "linux-meta-hwe-6.8", SourceVersion: "6.8.0.45.45~22.04.1"}}, ErrNotVersionBasis},
		{"unknown scheme", Scheme(0), "foo", []Binary{ok}, ErrUnsupportedEcosystem},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SourceVersionBasis(tc.scheme, tc.source, tc.installed)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	big := make([]Binary, MaxInstalledBinaries+1)
	for i := range big {
		big[i] = ok
	}
	if _, err := SourceVersionBasis(SchemeDpkg, "foo", big); !errors.Is(err, ErrNoBasis) {
		t.Fatalf("over limit err = %v, want ErrNoBasis", err)
	}
}

func TestKernelSourceClassification(t *testing.T) {
	kernel := []string{"linux", "linux-hwe-6.8", "linux-aws", "linux-raspi", "linux-oem-6.8", "linux-lowlatency", "linux-5.10"}
	for _, s := range kernel {
		if !IsKernelSource(s) {
			t.Errorf("IsKernelSource(%q) = false", s)
		}
		if NeverVersionBasis(s) {
			t.Errorf("NeverVersionBasis(%q) = true", s)
		}
	}
	never := []string{"linux-signed-amd64", "linux-signed-arm64", "linux-signed", "linux-signed-hwe-6.8", "linux-meta", "linux-meta-hwe-6.8", "linux-meta-aws", "linux-latest"}
	for _, s := range never {
		if IsKernelSource(s) {
			t.Errorf("IsKernelSource(%q) = true", s)
		}
		if !NeverVersionBasis(s) {
			t.Errorf("NeverVersionBasis(%q) = false", s)
		}
	}
	for _, s := range []string{"", "linuxx", "linux-", "linux-firmware", "linux-base", "linux-restricted-modules", "Linux", "proxmox-kernel-6.8", "pve-kernel-6.2", "openssl", "linux-HWE"} {
		if IsKernelSource(s) {
			t.Errorf("IsKernelSource(%q) = true", s)
		}
	}
}

// Kernel fixtures.
var (
	// Debian 12, signed amd64 image: source linux-signed-amd64 6.1.112+1,
	// built from linux 6.1.112-1.
	debSigned = Binary{
		Name: "linux-image-6.1.0-26-amd64", Version: "6.1.112-1",
		SourceName: "linux-signed-amd64", SourceVersion: "6.1.112+1",
		BuiltUsing: "linux (= 6.1.112-1)",
	}
	debSignedNewer = Binary{
		Name: "linux-image-6.1.0-27-amd64", Version: "6.1.115-1",
		SourceName: "linux-signed-amd64", SourceVersion: "6.1.115+1",
		BuiltUsing: "linux (= 6.1.115-1)",
	}
	// Debian meta package: same signed source, no Built-Using.
	debMeta = Binary{
		Name: "linux-image-amd64", Version: "6.1.115-1",
		SourceName: "linux-signed-amd64", SourceVersion: "6.1.115+1",
	}
	debFacts = KernelFacts{
		Distro:       DistroDebian,
		Release:      "6.1.0-26-amd64",
		BuildVersion: "#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)",
		Installed:    []Binary{debMeta, debSignedNewer, debSigned},
	}

	// Debian armmp: unsigned image, built directly from linux.
	debUnsigned = Binary{
		Name: "linux-image-6.1.0-26-armmp", Version: "6.1.112-1",
		SourceName: "linux", SourceVersion: "6.1.112-1",
	}
	debUnsignedFacts = KernelFacts{
		Distro:       DistroDebian,
		Release:      "6.1.0-26-armmp",
		BuildVersion: "#1 SMP Debian 6.1.112-1 (2024-09-30)",
		Installed:    []Binary{debUnsigned},
	}

	// Ubuntu 24.04 signed generic image.
	ubuSigned = Binary{
		Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45",
		SourceName: "linux-signed", SourceVersion: "6.8.0-45.45",
		BuiltUsing: "linux (= 6.8.0-45.45)",
	}
	ubuMeta = Binary{
		Name: "linux-image-generic", Version: "6.8.0.45.45",
		SourceName: "linux-meta", SourceVersion: "6.8.0.45.45",
	}
	ubuFacts = KernelFacts{
		Distro:       DistroUbuntu,
		Release:      "6.8.0-45-generic",
		BuildVersion: "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024",
		Installed:    []Binary{ubuMeta, ubuSigned},
	}

	// Ubuntu 22.04 HWE signed image.
	ubuHWE = Binary{
		Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45~22.04.1",
		SourceName: "linux-signed-hwe-6.8", SourceVersion: "6.8.0-45.45~22.04.1",
		BuiltUsing: "linux-hwe-6.8 (= 6.8.0-45.45~22.04.1)",
	}
	ubuHWEFacts = KernelFacts{
		Distro:       DistroUbuntu,
		Release:      "6.8.0-45-generic",
		BuildVersion: "#45~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Aug 29 10:20:26 UTC 2",
		Installed:    []Binary{ubuHWE},
	}

	// Ubuntu raspi: unsigned flavour source.
	ubuRaspi = Binary{
		Name: "linux-image-6.8.0-1010-raspi", Version: "6.8.0-1010.11",
		SourceName: "linux-raspi", SourceVersion: "6.8.0-1010.11",
	}
	ubuRaspiFacts = KernelFacts{
		Distro:       DistroUbuntu,
		Release:      "6.8.0-1010-raspi",
		BuildVersion: "#11-Ubuntu SMP PREEMPT_DYNAMIC Thu Aug  8 23:22:48 UTC 2024",
		Installed:    []Binary{ubuRaspi},
	}
)

func TestRunningKernelBasis(t *testing.T) {
	cases := []struct {
		name        string
		facts       KernelFacts
		source, ver string
		image       string
	}{
		{"debian signed via Built-Using", debFacts, "linux", "6.1.112-1", "linux-image-6.1.0-26-amd64"},
		{"debian unsigned source:Version", debUnsignedFacts, "linux", "6.1.112-1", "linux-image-6.1.0-26-armmp"},
		{"ubuntu signed via Built-Using", ubuFacts, "linux", "6.8.0-45.45", "linux-image-6.8.0-45-generic"},
		{"ubuntu hwe signed", ubuHWEFacts, "linux-hwe-6.8", "6.8.0-45.45~22.04.1", "linux-image-6.8.0-45-generic"},
		{"ubuntu raspi unsigned", ubuRaspiFacts, "linux-raspi", "6.8.0-1010.11", "linux-image-6.8.0-1010-raspi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := RunningKernel(tc.facts)
			if err != nil {
				t.Fatalf("RunningKernel: %v", err)
			}
			if b.SourceName != tc.source || b.Version != tc.ver || b.ImageBinary != tc.image {
				t.Fatalf("RunningKernel = %+v, want %s %s from %s", b, tc.source, tc.ver, tc.image)
			}
			// The signed (6.1.112+1) and meta (6.8.0.45.45) versions are
			// never the basis.
			if b.Version == "6.1.112+1" || b.Version == "6.8.0.45.45" {
				t.Fatalf("signed or meta version used as basis: %q", b.Version)
			}
		})
	}
}

func TestRunningKernelUnknown(t *testing.T) {
	with := func(f KernelFacts, mut func(*KernelFacts)) KernelFacts {
		f.Installed = append([]Binary(nil), f.Installed...)
		mut(&f)
		return f
	}
	signedWith := func(bu string) func(*KernelFacts) {
		return func(f *KernelFacts) {
			b := debSigned
			b.BuiltUsing = bu
			f.Installed = []Binary{b}
		}
	}
	cases := map[string]KernelFacts{
		"no distro":            with(debFacts, func(f *KernelFacts) { f.Distro = 0 }),
		"empty release":        with(debFacts, func(f *KernelFacts) { f.Release = "" }),
		"release with slash":   with(debFacts, func(f *KernelFacts) { f.Release = "../6.1.0-26-amd64" }),
		"release too long":     with(debFacts, func(f *KernelFacts) { f.Release = strings.Repeat("1", 200) }),
		"no image for release": with(debFacts, func(f *KernelFacts) { f.Release = "6.1.0-28-amd64" }),
		"only unsigned-named image": with(debFacts, func(f *KernelFacts) {
			f.Installed = []Binary{{Name: "linux-image-6.1.0-26-amd64-unsigned", SourceName: "linux", SourceVersion: "6.1.112-1"}}
		}),
		"two images for release":         with(debFacts, func(f *KernelFacts) { f.Installed = append(f.Installed, debSigned) }),
		"signed missing Built-Using":     with(debFacts, signedWith("")),
		"Built-Using names no kernel":    with(debFacts, signedWith("gcc-12 (= 12.2.0-14)")),
		"Built-Using two kernels":        with(debFacts, signedWith("linux (= 6.1.112-1), linux (= 6.1.115-1)")),
		"Built-Using two kernel sources": with(debFacts, signedWith("linux (= 6.1.112-1), linux-5.10 (= 5.10.226-1)")),
		"Built-Using unparseable":        with(debFacts, signedWith("linux 6.1.112-1")),
		"Built-Using wrong relation":     with(debFacts, signedWith("linux (>= 6.1.112-1)")),
		"Built-Using bad version":        with(debFacts, signedWith("linux (= x)")),
		"Built-Using one bad entry":      with(debFacts, signedWith("linux (= 6.1.112-1), gcc-12 (12.2.0-14)")),
		"Built-Using names signed":       with(debFacts, signedWith("linux-signed-amd64 (= 6.1.112+1)")),
		"Built-Using empty entry":        with(debFacts, signedWith("linux (= 6.1.112-1),")),
		"Built-Using too long":           with(debFacts, signedWith("linux (= 6.1.112-1)"+strings.Repeat(", gcc-12 (= 1)", 400))),
		"image from meta source": with(ubuFacts, func(f *KernelFacts) {
			f.Release = "generic"
			f.Installed = []Binary{{Name: "linux-image-generic", SourceName: "linux-meta", SourceVersion: "6.8.0.45.45"}}
		}),
		"image from foreign source": with(debFacts, func(f *KernelFacts) {
			f.Installed = []Binary{{Name: "linux-image-6.1.0-26-amd64", SourceName: "custom-kernel", SourceVersion: "1"}}
		}),
		"proxmox kernel": with(debFacts, func(f *KernelFacts) {
			f.Release = "6.8.12-2-pve"
			f.Installed = []Binary{{Name: "proxmox-kernel-6.8.12-2-pve-signed", SourceName: "proxmox-kernel-6.8", SourceVersion: "6.8.12-2"}}
		}),
		"unsigned bad source version":  with(debUnsignedFacts, func(f *KernelFacts) { f.Installed[0].SourceVersion = "" }),
		"debian uname -v mismatch":     with(debFacts, func(f *KernelFacts) { f.BuildVersion = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.115-1 (2024-11-01)" }),
		"debian uname -v no version":   with(debFacts, func(f *KernelFacts) { f.BuildVersion = "#1 SMP PREEMPT_DYNAMIC" }),
		"debian uname -v two versions": with(debFacts, func(f *KernelFacts) { f.BuildVersion = "#1 SMP Debian 6.1.112-1 Debian 6.1.112-1" }),
		"debian uname -v bad version":  with(debFacts, func(f *KernelFacts) { f.BuildVersion = "#1 SMP Debian x (2024-09-30)" }),
		"debian uname -v empty":        with(debFacts, func(f *KernelFacts) { f.BuildVersion = "" }),
		"ubuntu uname -v mismatch":     with(ubuFacts, func(f *KernelFacts) { f.BuildVersion = "#47-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 27 21:40:26 UTC 2024" }),
		"ubuntu uname -v no marker":    with(ubuFacts, func(f *KernelFacts) { f.BuildVersion = "#45 SMP PREEMPT_DYNAMIC" }),
		"ubuntu uname -v empty upload": with(ubuFacts, func(f *KernelFacts) { f.BuildVersion = "#-Ubuntu SMP" }),
		"ubuntu hwe uname -v plain":    with(ubuHWEFacts, func(f *KernelFacts) { f.BuildVersion = "#45-Ubuntu SMP" }),
		"ubuntu revision without dot":  with(ubuFacts, func(f *KernelFacts) { b := ubuSigned; b.BuiltUsing = "linux (= 6.8.0-45)"; f.Installed = []Binary{b} }),
		"uname -v too long":            with(debFacts, func(f *KernelFacts) { f.BuildVersion = "#1 SMP Debian 6.1.112-1 " + strings.Repeat("x", 300) }),
		"uname -v invalid utf-8":       with(debFacts, func(f *KernelFacts) { f.BuildVersion = "#1 SMP Debian 6.1.112-1 \xff" }),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			b, err := RunningKernel(f)
			if !errors.Is(err, ErrKernelUnknown) {
				t.Fatalf("RunningKernel = %+v, %v; want ErrKernelUnknown", b, err)
			}
		})
	}
	big := debFacts
	big.Installed = make([]Binary, MaxInstalledBinaries+1)
	if _, err := RunningKernel(big); !errors.Is(err, ErrKernelUnknown) {
		t.Fatalf("over limit err = %v, want ErrKernelUnknown", err)
	}
}

func TestKernelStatus(t *testing.T) {
	cases := []struct {
		name      string
		facts     KernelFacts
		fixed     string
		want      KernelState
		installed int
	}{
		// Running 6.1.112-1; 6.1.115-1 is installed but not booted.
		{"fixed kernel installed but not booted stays open", debFacts, "6.1.115-1", KernelAffectedFixedAfterReboot, 2},
		{"no fixed kernel installed", debFacts, "6.1.119-1", KernelAffected, 2},
		{"running kernel fixed", debFacts, "6.1.112-1", KernelNotAffected, 2},
		{"running kernel newer than fix", debFacts, "6.1.106-3", KernelNotAffected, 2},
		{"signed version never compared", debFacts, "6.1.112+1", KernelAffectedFixedAfterReboot, 2},
		{"ubuntu running fixed", ubuFacts, "6.8.0-45.45", KernelNotAffected, 1},
		{"ubuntu running affected", ubuFacts, "6.8.0-47.47", KernelAffected, 1},
		{"ubuntu meta version ignored", ubuFacts, "6.8.0-45.46", KernelAffected, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := KernelStatus(tc.facts, tc.fixed)
			if err != nil {
				t.Fatalf("KernelStatus: %v", err)
			}
			if r.State != tc.want {
				t.Fatalf("State = %v, want %v", r.State, tc.want)
			}
			if len(r.Installed) != tc.installed {
				t.Fatalf("Installed = %+v, want %d kernels", r.Installed, tc.installed)
			}
		})
	}

	// Another kernel source line (HWE vs generic) never counts as the fix.
	mixed := ubuFacts
	newerOther := Binary{
		Name: "linux-image-6.8.0-50-lowlatency", Version: "6.8.0-50.51",
		SourceName: "linux-signed-lowlatency", SourceVersion: "6.8.0-50.51",
		BuiltUsing: "linux-lowlatency (= 6.8.0-50.51)",
	}
	mixed.Installed = append([]Binary{newerOther}, ubuFacts.Installed...)
	r, err := KernelStatus(mixed, "6.8.0-47.47")
	if err != nil || r.State != KernelAffected {
		t.Fatalf("other source line counted as fix: %+v, %v", r, err)
	}

	// An installed kernel that cannot be resolved is skipped, not an error.
	broken := debFacts
	broken.Installed = append([]Binary{{Name: "linux-image-6.1.0-30-amd64", SourceName: "linux-signed-amd64", SourceVersion: "6.1.124+1"}}, debFacts.Installed...)
	r, err = KernelStatus(broken, "6.1.124-1")
	if err != nil || r.State != KernelAffected {
		t.Fatalf("unresolvable kernel used: %+v, %v", r, err)
	}

	if _, err := KernelStatus(debFacts, "x"); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("invalid fixed err = %v, want ErrInvalidVersion", err)
	}
	unknown := debFacts
	unknown.BuildVersion = ""
	if r, err := KernelStatus(unknown, "6.1.115-1"); !errors.Is(err, ErrKernelUnknown) || r.State != KernelUnknown {
		t.Fatalf("unknown running kernel = %+v, %v; want KernelUnknown", r, err)
	}
}

func TestKernelStateString(t *testing.T) {
	for s, want := range map[KernelState]string{
		KernelUnknown:                  "unknown",
		KernelAffected:                 "affected",
		KernelAffectedFixedAfterReboot: "affected, fixed after reboot",
		KernelNotAffected:              "not affected",
		KernelState(42):                "unknown",
	} {
		if s.String() != want {
			t.Errorf("%d.String() = %q, want %q", int(s), s.String(), want)
		}
	}
}

// ImageBasis is the per-image rule RunningKernel and KernelStatus use; the
// osdebian parser lists installed kernels with it so that there is one
// kernel mapping rule only.
func TestImageBasisUsesTheRunningKernelRule(t *testing.T) {
	cases := []struct {
		name    string
		b       Binary
		src     string
		ver     string
		unknown bool
	}{
		{"unsigned source", Binary{Name: "linux-image-6.1.0-26-cloud-amd64", SourceName: "linux", SourceVersion: "6.1.112-1"}, "linux", "6.1.112-1", false},
		{"signed via Built-Using", Binary{Name: "linux-image-6.1.0-26-amd64", SourceName: "linux-signed-amd64", SourceVersion: "6.1.112+1", BuiltUsing: "linux (= 6.1.112-1)"}, "linux", "6.1.112-1", false},
		{"signed without Built-Using", Binary{Name: "linux-image-6.1.0-26-amd64", SourceName: "linux-signed-amd64", SourceVersion: "6.1.112+1"}, "", "", true},
		{"two kernel sources", Binary{Name: "linux-image-6.1.0-26-amd64", SourceName: "linux-signed-amd64", SourceVersion: "6.1.112+1", BuiltUsing: "linux (= 6.1.112-1), linux-hwe-6.1 (= 6.1.112-1)"}, "", "", true},
		{"meta source", Binary{Name: "linux-image-generic", SourceName: "linux-meta", SourceVersion: "6.8.0.45.45"}, "", "", true},
		{"unrelated source", Binary{Name: "linux-image-x", SourceName: "custom-kernel", SourceVersion: "1"}, "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kb, err := ImageBasis(c.b)
			if c.unknown {
				if err == nil || kb != (KernelBasis{}) {
					t.Fatalf("ImageBasis = %+v, %v; want no basis", kb, err)
				}
				return
			}
			if err != nil || kb.SourceName != c.src || kb.Version != c.ver || kb.ImageBinary != c.b.Name {
				t.Fatalf("ImageBasis = %+v, %v; want %s %s", kb, err, c.src, c.ver)
			}
		})
	}
}
