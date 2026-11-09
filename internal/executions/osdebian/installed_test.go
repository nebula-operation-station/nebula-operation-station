// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestInstalledDebian12UsesSourceVersionNeverBinaryVersion(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "debian12.txt"), okRead)
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
	inv := ParseInstalled([]byte(doc), okRead)
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
			inv := ParseInstalled([]byte(installedDoc("K\t6.1.0-26-amd64\t#1 SMP", both, bad)), okRead)
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
	inv := ParseInstalled(readInstalledFixture(t, "debian12.txt"), okRead)
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
	inv := ParseInstalled(readInstalledFixture(t, "ubuntu2404.txt"), okRead)
	if !inv.Complete {
		t.Fatalf("incomplete: %s", inv.Reason)
	}
	k := inv.RunningKernel
	if k.State != KernelMapped {
		t.Fatalf("state = %s (%s), want mapped", k.State, k.Reason)
	}
	if k.Source != "linux" || k.Version != "6.8.0-45.45" || k.ImagePackage != "linux-image-6.8.0-45-generic" {
		t.Errorf("kernel = %s %s from %s", k.Source, k.Version, k.ImagePackage)
	}
}

func TestInstalledKernelsListedWithRunningMarked(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "debian12.txt"), okRead)
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
	cases := []struct {
		name   string
		kernel string
		lines  []string
	}{
		{"no image for running release", deb,
			[]string{img("linux-image-6.1.0-25-amd64", "linux-signed-amd64", "6.1.106+3", "linux (= 6.1.106-3)")}},
		{"signed without Built-Using", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "")}},
		{"Built-Using without kernel source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "shim (= 15.8-1)")}},
		{"Built-Using with two kernel sources", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1), linux-hwe-6.1 (= 6.1.112-1)")}},
		{"Built-Using names a signed source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux-signed-amd64 (= 6.1.112+1)")}},
		{"Built-Using names a meta source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux-meta (= 6.1.112)")}},
		{"Built-Using unparseable", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (>= 6.1.112-1)")}},
		{"Built-Using one entry unparseable", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1), garbage")}},
		{"image from meta source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "linux-meta", "6.1.112", "linux (= 6.1.112-1)")}},
		{"image from unrelated source", deb,
			[]string{img("linux-image-6.1.0-26-amd64", "custom-kernel", "6.1.112-1", "")}},
		{"Debian build string mismatch", "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.106-3 (2024-08-26)",
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)")}},
		{"Ubuntu upload mismatch", "K\t6.8.0-45-generic\t#44-Ubuntu SMP PREEMPT_DYNAMIC",
			[]string{pLine("installed", "linux-image-6.8.0-45-generic", "amd64", "6.8.0-45.45", "linux-signed", "6.8.0-45.45", "linux (= 6.8.0-45.45)")}},
		{"Proxmox kernel", "K\t6.8.12-4-pve\t#1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4",
			[]string{pLine("installed", "proxmox-kernel-6.8.12-4-pve-signed", "amd64", "6.8.12-4", "proxmox-kernel-signed", "6.8.12-4", "")}},
		{"signed and unsigned image disagree", deb,
			[]string{
				img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)"),
				pLine("installed", "linux-image-6.1.0-26-amd64-unsigned", "amd64", "6.1.106-3", "linux", "6.1.106-3", ""),
			}},
		{"missing kernel record", "",
			[]string{img("linux-image-6.1.0-26-amd64", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := ParseInstalled([]byte(installedDoc(c.kernel, c.lines...)), okRead)
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
		name, kernel, line, src, ver string
	}{
		{"Debian unsigned image", "K\t6.1.0-26-cloud-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)",
			pLine("installed", "linux-image-6.1.0-26-cloud-amd64", "amd64", "6.1.112-1", "linux", "6.1.112-1", ""),
			"linux", "6.1.112-1"},
		{"Ubuntu unsigned image", "K\t6.8.0-45-generic\t#45-Ubuntu SMP PREEMPT_DYNAMIC",
			pLine("installed", "linux-image-unsigned-6.8.0-45-generic", "amd64", "6.8.0-45.45", "linux", "6.8.0-45.45", ""),
			"linux", "6.8.0-45.45"},
		{"Ubuntu HWE signed", "K\t6.8.0-45-generic\t#45~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC",
			pLine("installed", "linux-image-6.8.0-45-generic", "amd64", "6.8.0-45.45~22.04.1", "linux-signed-hwe-6.8", "6.8.0-45.45~22.04.1", "linux-hwe-6.8 (= 6.8.0-45.45~22.04.1)"),
			"linux-hwe-6.8", "6.8.0-45.45~22.04.1"},
		{"build string without version", "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC",
			pLine("installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)"),
			"linux", "6.1.112-1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := ParseInstalled([]byte(installedDoc(c.kernel, c.line)), okRead)
			k := inv.RunningKernel
			if k.State != KernelMapped || k.Source != c.src || k.Version != c.ver {
				t.Fatalf("kernel = %s %s %s (%s), want mapped %s %s", k.State, k.Source, k.Version, k.Reason, c.src, c.ver)
			}
		})
	}
}

func TestInstalledMalformedLinesMarkPartial(t *testing.T) {
	inv := ParseInstalled(readInstalledFixture(t, "malformed.txt"), okRead)
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
			inv := ParseInstalled([]byte(c.doc), c.rs)
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
	if inv := ParseInstalled([]byte(full), okRead); !inv.Complete || inv.Reason != "" {
		t.Fatalf("clean read: complete=%v reason=%q", inv.Complete, inv.Reason)
	}
}

func TestInstalledFirstReasonWins(t *testing.T) {
	doc := installedDoc("K\t6.1.0-26-amd64\t#1 SMP", "P\tgarbage")
	inv := ParseInstalled([]byte(doc), ReadStatus{ExitCode: 2})
	if inv.Complete || !strings.HasPrefix(inv.Reason, ReasonReadFailed) {
		t.Fatalf("complete=%v reason=%q", inv.Complete, inv.Reason)
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
			inv := ParseInstalled([]byte(gen(c.n)), okRead)
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
	inv := ParseInstalled([]byte(b.String()), okRead)
	if inv.Complete || !strings.HasPrefix(inv.Reason, ReasonTruncated) {
		t.Fatalf("complete=%v reason=%q", inv.Complete, inv.Reason)
	}
	if len(inv.Packages) > MaxPackages {
		t.Fatalf("kept %d packages", len(inv.Packages))
	}
}
