// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"fmt"
	"strings"
)

// Limits for the version basis.
const (
	// MaxInstalledBinaries is the most installed binaries considered, the
	// package.list_installed limit (VU-05).
	MaxInstalledBinaries = 20000
	// MaxBuiltUsingLen is the longest Built-Using field accepted, in bytes.
	MaxBuiltUsingLen = 4096
	// MaxBuiltUsingEntries is the most entries in one Built-Using field.
	MaxBuiltUsingEntries = 64
	// MaxKernelReleaseLen is the longest `uname -r` accepted, in bytes.
	MaxKernelReleaseLen = 128
	// MaxKernelBuildLen is the longest `uname -v` accepted, in bytes.
	MaxKernelBuildLen = 256
	// maxPackageNameLen bounds a package name.
	maxPackageNameLen = 128
)

// Binary is one installed binary package as reported by the inventory
// (package.list_installed or image.packages).
type Binary struct {
	// Name is the binary package name.
	Name string
	// Version is the binary version. It is context only and never a
	// comparison basis (ADR 0011 D4).
	Version string
	// SourceName is the source package (dpkg source:Package, apk origin).
	SourceName string
	// SourceVersion is the source version (dpkg source:Version, apk
	// version of the origin package).
	SourceVersion string
	// BuiltUsing is the raw dpkg Built-Using field; empty when absent.
	BuiltUsing string
}

// SourceBasis is the version basis for one source package.
type SourceBasis struct {
	// SourceName is the source package.
	SourceName string
	// Version is the lowest source version among its installed binaries.
	Version string
	// Binaries lists every installed binary of the source package, as
	// context for the finding.
	Binaries []Binary
}

// SourceVersionBasis returns the version basis for source package source:
// the lowest SourceVersion among the installed binaries built from it
// (ADR 0011 D4; a partial upgrade leaves the host as exposed as its oldest
// binary). Binary versions are never used. Any binary of the source with an
// invalid source version makes the basis unknown (ErrNoBasis), since the
// lowest version can then not be known. Signed and meta kernel sources are
// never a basis (ErrNotVersionBasis).
func SourceVersionBasis(s Scheme, source string, installed []Binary) (SourceBasis, error) {
	basis := SourceBasis{SourceName: source}
	if s != SchemeDpkg && s != SchemeAPK {
		return basis, fmt.Errorf("source basis: scheme %d: %w", int(s), ErrUnsupportedEcosystem)
	}
	if source == "" {
		return basis, fmt.Errorf("source basis: empty source package: %w", ErrNoBasis)
	}
	if s == SchemeDpkg && NeverVersionBasis(source) {
		return basis, fmt.Errorf("source basis %s: %w", quote(source), ErrNotVersionBasis)
	}
	if len(installed) > MaxInstalledBinaries {
		return basis, fmt.Errorf("source basis: %d binaries exceed %d: %w", len(installed), MaxInstalledBinaries, ErrNoBasis)
	}
	for _, b := range installed {
		if b.SourceName != source {
			continue
		}
		if err := Validate(s, b.SourceVersion); err != nil {
			return SourceBasis{SourceName: source}, fmt.Errorf("source basis %s: binary %s: %w: %w", quote(source), quote(b.Name), ErrNoBasis, err)
		}
		if basis.Version == "" {
			basis.Version = b.SourceVersion
		} else if c, _ := Compare(s, b.SourceVersion, basis.Version); c < 0 {
			basis.Version = b.SourceVersion
		}
		basis.Binaries = append(basis.Binaries, b)
	}
	if len(basis.Binaries) == 0 {
		return basis, fmt.Errorf("source basis %s: no installed binary: %w", quote(source), ErrNoBasis)
	}
	return basis, nil
}

// neverBasisPrefixes are kernel-related source packages whose versions
// never compare with the security trackers' fixed versions: signed
// wrappers and meta packages (Debian linux-signed-<arch>, linux-latest;
// Ubuntu linux-signed*, linux-meta*).
var neverBasisPrefixes = []string{"linux-signed", "linux-meta", "linux-latest"}

// notKernelPrefixes are linux-* source packages that are not kernels.
var notKernelPrefixes = []string{"linux-firmware", "linux-base", "linux-restricted-modules", "linux-atm", "linux-tools", "linux-libc-dev"}

// NeverVersionBasis reports whether source is a signed or meta kernel
// source package, whose version is never a version basis (ADR 0011 D4). A
// kernel finding naming such a source package must be rejected.
func NeverVersionBasis(source string) bool {
	for _, p := range neverBasisPrefixes {
		if source == p || strings.HasPrefix(source, p+"-") {
			return true
		}
	}
	return false
}

// IsKernelSource reports whether source is an unsigned kernel source
// package that the security trackers key kernel CVEs on: Debian "linux"
// (and versioned lines such as "linux-5.10"), Ubuntu "linux" and its
// flavour sources ("linux-hwe-6.8", "linux-aws", …). Signed, meta and
// non-kernel linux-* sources are excluded. It is only meant for the
// source of a linux-image-* binary and for Built-Using entries.
func IsKernelSource(source string) bool {
	if !validPackageName(source) {
		return false
	}
	if source == "linux" {
		return true
	}
	flavour, ok := strings.CutPrefix(source, "linux-")
	if !ok || flavour == "" || !isAlnum(flavour[0]) || NeverVersionBasis(source) {
		return false
	}
	for _, p := range notKernelPrefixes {
		if source == p || strings.HasPrefix(source, p+"-") {
			return false
		}
	}
	return true
}

// validPackageName checks Debian Policy §5.6.1: lowercase letters, digits,
// '+', '-', '.'; at least two characters; starts alphanumeric.
func validPackageName(name string) bool {
	if len(name) < 2 || len(name) > maxPackageNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		lowerOrDigit := isDigit(c) || (c >= 'a' && c <= 'z')
		if i == 0 && !lowerOrDigit {
			return false
		}
		if !lowerOrDigit && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// builtUsingEntry is one "name (= version)" entry of a Built-Using field.
type builtUsingEntry struct {
	name, version string
}

// parseBuiltUsing parses a Built-Using field strictly. Policy §7.8 allows
// only exact "(= version)" relations; anything else is an error.
func parseBuiltUsing(field string) ([]builtUsingEntry, error) {
	if len(field) > MaxBuiltUsingLen {
		return nil, fmt.Errorf("built-using: %d bytes exceed %d", len(field), MaxBuiltUsingLen)
	}
	if strings.TrimSpace(field) == "" {
		return nil, nil
	}
	parts := strings.Split(field, ",")
	if len(parts) > MaxBuiltUsingEntries {
		return nil, fmt.Errorf("built-using: %d entries exceed %d", len(parts), MaxBuiltUsingEntries)
	}
	entries := make([]builtUsingEntry, 0, len(parts))
	for i, p := range parts {
		p = strings.Trim(p, " \t")
		name, rest, ok := strings.Cut(p, "(")
		name = strings.TrimRight(name, " \t")
		rest, closed := strings.CutSuffix(rest, ")")
		if !ok || !closed || !validPackageName(name) {
			return nil, fmt.Errorf("built-using entry %d: malformed", i)
		}
		rest = strings.Trim(rest, " \t")
		ver, isEq := strings.CutPrefix(rest, "=")
		if !isEq || strings.HasPrefix(ver, "=") {
			return nil, fmt.Errorf("built-using entry %d: relation is not \"=\"", i)
		}
		ver = strings.Trim(ver, " \t")
		if _, err := ParseDpkg(ver); err != nil {
			return nil, fmt.Errorf("built-using entry %d: %w", i, err)
		}
		entries = append(entries, builtUsingEntry{name: name, version: ver})
	}
	return entries, nil
}

// Distro is the distribution family of a host, for the kernel rules.
type Distro int

// Supported distributions.
const (
	// DistroDebian is Debian.
	DistroDebian Distro = iota + 1
	// DistroUbuntu is Ubuntu.
	DistroUbuntu
)

// KernelFacts are the inventory facts about a host's kernels (D3).
type KernelFacts struct {
	// Distro is the host's distribution.
	Distro Distro
	// Release is the running kernel release (`uname -r`).
	Release string
	// BuildVersion is the running kernel build string (`uname -v`).
	BuildVersion string
	// Installed are the installed binary packages.
	Installed []Binary
}

// KernelBasis is a kernel's version basis: its unsigned kernel source
// package and that package's version.
type KernelBasis struct {
	// SourceName is the unsigned kernel source package, for example
	// "linux" or "linux-hwe-6.8".
	SourceName string
	// Version is that source package's version.
	Version string
	// ImageBinary is the linux-image-* binary the basis was read from.
	ImageBinary string
}

// RunningKernel returns the running kernel's version basis (ADR 0011 D4):
//
//   - the running release maps to the single installed binary
//     "linux-image-<release>";
//   - if its source is an unsigned kernel source, its source version is
//     the basis;
//   - if its source is signed (linux-signed*), the basis is the single
//     unsigned kernel source entry of its Built-Using field;
//   - the `uname -v` build string must agree (Debian: "Debian <version>";
//     Ubuntu: "#<upload>-Ubuntu", see ubuntuUpload).
//
// Every other case wraps ErrKernelUnknown; signed and meta versions are
// never returned.
func RunningKernel(f KernelFacts) (KernelBasis, error) {
	if f.Distro != DistroDebian && f.Distro != DistroUbuntu {
		return KernelBasis{}, fmt.Errorf("running kernel: unsupported distribution: %w", ErrKernelUnknown)
	}
	if !validRelease(f.Release) {
		return KernelBasis{}, fmt.Errorf("running kernel: invalid release %s: %w", quote(f.Release), ErrKernelUnknown)
	}
	if len(f.Installed) > MaxInstalledBinaries {
		return KernelBasis{}, fmt.Errorf("running kernel: %d binaries exceed %d: %w", len(f.Installed), MaxInstalledBinaries, ErrKernelUnknown)
	}
	image := "linux-image-" + f.Release
	var found []Binary
	for _, b := range f.Installed {
		if b.Name == image {
			found = append(found, b)
		}
	}
	if len(found) != 1 {
		return KernelBasis{}, fmt.Errorf("running kernel: %d installed %s binaries: %w", len(found), quote(image), ErrKernelUnknown)
	}
	basis, err := kernelBasisOf(found[0])
	if err != nil {
		return KernelBasis{}, fmt.Errorf("running kernel: %w: %w", err, ErrKernelUnknown)
	}
	if err := checkBuildString(f.Distro, f.BuildVersion, basis.Version); err != nil {
		return KernelBasis{}, fmt.Errorf("running kernel: %w: %w", err, ErrKernelUnknown)
	}
	return basis, nil
}

// kernelBasisOf resolves one linux-image-* binary to its kernel basis.
func kernelBasisOf(b Binary) (KernelBasis, error) {
	switch {
	case IsKernelSource(b.SourceName):
		if _, err := ParseDpkg(b.SourceVersion); err != nil {
			return KernelBasis{}, fmt.Errorf("image %s: source version: %w", quote(b.Name), err)
		}
		return KernelBasis{SourceName: b.SourceName, Version: b.SourceVersion, ImageBinary: b.Name}, nil
	case b.SourceName == "linux-signed" || strings.HasPrefix(b.SourceName, "linux-signed-"):
		entries, err := parseBuiltUsing(b.BuiltUsing)
		if err != nil {
			return KernelBasis{}, fmt.Errorf("image %s: %w", quote(b.Name), err)
		}
		var kernels []builtUsingEntry
		for _, e := range entries {
			if IsKernelSource(e.name) {
				kernels = append(kernels, e)
			}
		}
		if len(kernels) != 1 {
			return KernelBasis{}, fmt.Errorf("image %s: %d kernel sources in Built-Using", quote(b.Name), len(kernels))
		}
		return KernelBasis{SourceName: kernels[0].name, Version: kernels[0].version, ImageBinary: b.Name}, nil
	default:
		return KernelBasis{}, fmt.Errorf("image %s: source %s is not a kernel source", quote(b.Name), quote(b.SourceName))
	}
}

// validRelease checks a `uname -r` value: non-empty, bounded, starting
// alphanumeric, characters [A-Za-z0-9._+~-].
func validRelease(r string) bool {
	if r == "" || len(r) > MaxKernelReleaseLen || !isAlnum(r[0]) {
		return false
	}
	for i := 0; i < len(r); i++ {
		c := r[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '+' && c != '~' && c != '-' {
			return false
		}
	}
	return true
}

// checkBuildString cross-checks `uname -v` against the basis version.
func checkBuildString(d Distro, build, version string) error {
	if build == "" || len(build) > MaxKernelBuildLen {
		return fmt.Errorf("uname -v: empty or longer than %d bytes", MaxKernelBuildLen)
	}
	for i := 0; i < len(build); i++ {
		if build[i] < 0x20 || build[i] > 0x7e {
			return fmt.Errorf("uname -v: not printable ASCII")
		}
	}
	fields := strings.Fields(build)
	switch d {
	case DistroDebian:
		var got []string
		for i, f := range fields {
			if f == "Debian" && i+1 < len(fields) {
				got = append(got, fields[i+1])
			}
		}
		if len(got) != 1 {
			return fmt.Errorf("uname -v: %d Debian versions", len(got))
		}
		c, err := CompareDpkg(got[0], version)
		if err != nil {
			return fmt.Errorf("uname -v: %w", err)
		}
		if c != 0 {
			return fmt.Errorf("uname -v: version %s does not match kernel source version %s", quote(got[0]), quote(version))
		}
		return nil
	case DistroUbuntu:
		want, err := ubuntuUpload(version)
		if err != nil {
			return err
		}
		if len(fields) == 0 {
			return fmt.Errorf("uname -v: empty")
		}
		upload, ok := strings.CutPrefix(fields[0], "#")
		if ok {
			upload, ok = strings.CutSuffix(upload, "-Ubuntu")
		}
		if !ok || upload == "" {
			return fmt.Errorf("uname -v: no \"#<upload>-Ubuntu\" marker")
		}
		if upload != want {
			return fmt.Errorf("uname -v: upload %s does not match kernel source version %s", quote(upload), quote(version))
		}
		return nil
	default:
		return fmt.Errorf("uname -v: unsupported distribution")
	}
}

// ubuntuUpload returns the upload part of an Ubuntu kernel source version
// as it appears in `uname -v`: the Debian revision after its first '.'.
// "6.8.0-45.45" gives "45" (matching "#45-Ubuntu") and the HWE form
// "6.8.0-45.45~22.04.1" gives "45~22.04.1" (matching "#45~22.04.1-Ubuntu").
// For plain versions this equals ADR 0011 D4's "part after the last '.'".
func ubuntuUpload(version string) (string, error) {
	v, err := ParseDpkg(version)
	if err != nil {
		return "", fmt.Errorf("ubuntu upload: %w", err)
	}
	_, upload, ok := strings.Cut(v.Revision, ".")
	if !ok || upload == "" {
		return "", fmt.Errorf("ubuntu upload: revision %s has no upload number", quote(v.Revision))
	}
	return upload, nil
}

// KernelState is the result of comparing the running kernel with a fixed
// version.
type KernelState int

// Kernel states.
const (
	// KernelUnknown means the running kernel's version is unknown; the
	// finding is not checkable and never clean.
	KernelUnknown KernelState = iota
	// KernelAffected means the running kernel is older than the fix and no
	// installed kernel of the same source carries it.
	KernelAffected
	// KernelAffectedFixedAfterReboot means the running kernel is older
	// than the fix but an installed, not running kernel of the same source
	// is fixed. The finding stays open ("fixed after reboot").
	KernelAffectedFixedAfterReboot
	// KernelNotAffected means the running kernel is at or after the fix.
	KernelNotAffected
)

// String returns a short label.
func (k KernelState) String() string {
	switch k {
	case KernelAffected:
		return "affected"
	case KernelAffectedFixedAfterReboot:
		return "affected, fixed after reboot"
	case KernelNotAffected:
		return "not affected"
	default:
		return "unknown"
	}
}

// KernelResult is the outcome of KernelStatus.
type KernelResult struct {
	// State is the comparison result.
	State KernelState
	// Running is the running kernel's basis.
	Running KernelBasis
	// Installed lists the installed kernels of the running kernel's source
	// package (including the running one) as context for the finding.
	Installed []KernelBasis
}

// KernelStatus compares the running kernel with fixed, a source version of
// the running kernel's unsigned source package. Only the running kernel
// decides: an installed but not booted fixed kernel leaves the finding
// open (KernelAffectedFixedAfterReboot). Installed kernels that cannot be
// resolved are left out of the context. An unknown running kernel returns
// KernelUnknown with an error wrapping ErrKernelUnknown.
func KernelStatus(f KernelFacts, fixed string) (KernelResult, error) {
	if _, err := ParseDpkg(fixed); err != nil {
		return KernelResult{}, fmt.Errorf("kernel status: fixed version: %w", err)
	}
	running, err := RunningKernel(f)
	if err != nil {
		return KernelResult{}, fmt.Errorf("kernel status: %w", err)
	}
	res := KernelResult{Running: running}
	fixedElsewhere := false
	for _, b := range f.Installed {
		if !strings.HasPrefix(b.Name, "linux-image-") {
			continue
		}
		kb, err := kernelBasisOf(b)
		if err != nil || kb.SourceName != running.SourceName {
			continue
		}
		res.Installed = append(res.Installed, kb)
		if b.Name == running.ImageBinary {
			continue
		}
		if c, _ := CompareDpkg(kb.Version, fixed); c >= 0 {
			fixedElsewhere = true
		}
	}
	c, _ := CompareDpkg(running.Version, fixed)
	switch {
	case c >= 0:
		res.State = KernelNotAffected
	case fixedElsewhere:
		res.State = KernelAffectedFixedAfterReboot
	default:
		res.State = KernelAffected
	}
	return res, nil
}
