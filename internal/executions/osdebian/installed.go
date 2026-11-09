// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// InstalledFormat is the first line of a package.list_installed result.
//
// The result is line based; every line ends with "\n" and fields are
// separated by a single TAB. After the header line come, in this order:
//
//	P <status> <binary> <arch> <binary version> <source package> <source version> <Built-Using> .
//	K <uname -r> <uname -v>
//	END <number of P lines>
//
// P lines are the dpkg-query -W fields db:Status-Status, Package,
// Architecture, Version, source:Package, source:Version and Built-Using,
// followed by a literal "." field so that an empty Built-Using never ends
// a line (Built-Using is kept for linux-image-* binaries only). Status
// config-files and not-installed lines are counted but not inventory.
// Exactly one K line carries the running kernel release and build string.
// The END line is written only after dpkg-query exited successfully and
// counts every P line written, so a missing or wrong END line reveals a
// truncated or failed read.
const InstalledFormat = "nos-installed-v1"

// Limits for package.list_installed results. The kernel and Built-Using
// bounds are the vulnver ones (spec 09), so that a value vulnver accepts
// never makes the read partial.
const (
	// MaxInstalledOutput bounds the bytes read from a result; anything
	// beyond is ignored and the read is partial.
	MaxInstalledOutput = 8 << 20
	maxFieldLen        = 128
	maxBuiltUsingLen   = vulnver.MaxBuiltUsingLen
	maxReleaseLen      = vulnver.MaxKernelReleaseLen
	maxBuildLen        = vulnver.MaxKernelBuildLen
	// maxInstalledLine leaves room for a full Built-Using field next to
	// the other, much shorter fields.
	maxInstalledLine = maxBuiltUsingLen + 1024
)

// Reasons for a partial read. Reason strings name the line number at most,
// never host content.
const (
	ReasonReadFailed    = "read failed"
	ReasonTruncated     = "output truncated"
	ReasonFormat        = "not a package.list_installed result"
	ReasonMalformed     = "malformed line"
	ReasonLimit         = "package limit reached"
	ReasonNoEnd         = "end record missing"
	ReasonCountMismatch = "record count mismatch"
	ReasonNoKernel      = "kernel record missing"
	ReasonNoPackages    = "no installed packages"
	// ReasonUnfinished: a package is half-installed or half-configured
	// (failed or interrupted dpkg run), so its files may not match its
	// source version.
	ReasonUnfinished = "package in an unfinished dpkg state"
)

// Reasons the running kernel has no version basis. Like the partial-read
// reasons they never carry host content.
const (
	// KernelReasonUnmapped: vulnver.RunningKernel found no basis (no or
	// several images for the release, no unsigned kernel source, build
	// string empty, unrecognised or not matching).
	KernelReasonUnmapped = "running kernel not mappable to a kernel source version"
	// KernelReasonDistro: the host's distribution is not Debian or Ubuntu.
	KernelReasonDistro = "distribution not supported for kernel mapping"
)

// KernelState says whether the running kernel maps to a version basis.
type KernelState string

// Kernel states.
const (
	// KernelMapped: Source and Version are the unsigned kernel source
	// package and its version for the running kernel.
	KernelMapped KernelState = "mapped"
	// KernelVersionUnknown: the running kernel has no version basis
	// ("kernel coverage unknown", never clean).
	KernelVersionUnknown KernelState = "kernel_version_unknown"
)

// ReadStatus is what the executor reports about the read besides its
// output.
type ReadStatus struct {
	ExitCode  int
	Truncated bool // output cut by the executor
}

// InstalledPackage is one installed binary package. Source and
// SourceVersion are the version basis for matching (source:Version), never
// Version.
type InstalledPackage struct {
	Name          string
	Arch          string
	Version       string // binary version, context only
	Source        string
	SourceVersion string
	Status        string // dpkg db:Status-Status
	BuiltUsing    string // linux-image-* binaries only
}

// RunningKernel is the running kernel and, if mappable, its unsigned
// kernel source package and version.
type RunningKernel struct {
	Release      string // uname -r
	Build        string // uname -v
	State        KernelState
	Reason       string // why the version is unknown
	ImagePackage string
	Source       string // unsigned kernel source, empty unless mapped
	Version      string // its version, empty unless mapped
}

// InstalledKernel is an installed linux-image-<release> binary (context:
// several kernels may be installed, only the running one is the basis).
type InstalledKernel struct {
	Package       string
	Version       string // binary version
	Release       string
	Source        string // unsigned kernel source, empty unless Mapped
	SourceVersion string
	Mapped        bool
	Running       bool
}

// InstalledInventory is a parsed package.list_installed result. Complete
// is true only for a read that exited successfully, was not truncated,
// parsed every line, had no package in an unfinished dpkg state, and
// stayed below MaxPackages; a partial read can add inventory but never
// prove a removal.
type InstalledInventory struct {
	Packages         []InstalledPackage
	RunningKernel    RunningKernel
	InstalledKernels []InstalledKernel
	Complete         bool
	Reason           string // first reason the read is partial
	Dropped          int    // lines that could not be used
}

var (
	debNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{1,127}$`)
	debArchRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,31}$`)
	debVersionRe = regexp.MustCompile(`^(?:[0-9]{1,10}:)?[0-9A-Za-z][0-9A-Za-z.+~\-]{0,127}$`)
	releaseRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~\-]{0,127}$`)
	endCountRe   = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,8})$`)
)

// dpkg db:Status-Status values. included: the package's files are on disk.
var dpkgStatus = map[string]bool{
	"installed":        true,
	"half-installed":   true,
	"unpacked":         true,
	"half-configured":  true,
	"triggers-awaited": true,
	"triggers-pending": true,
	"config-files":     false,
	"not-installed":    false,
}

// unfinishedStatus are included states left by a failed or interrupted
// dpkg run: files of the old and the new version may both be on disk, so
// the source version is not a sure basis and the read is partial.
var unfinishedStatus = map[string]bool{
	"half-installed":  true,
	"half-configured": true,
}

type installedParser struct {
	inv     InstalledInventory
	seen    map[string]bool
	pLines  int
	kernels int
	endSeen bool
	kernel  bool
}

func (p *installedParser) partial(reason string) {
	p.inv.Complete = false
	if p.inv.Reason == "" {
		p.inv.Reason = reason
	}
}

func (p *installedParser) malformed(n int) {
	p.inv.Dropped++
	p.partial(fmt.Sprintf("%s %d", ReasonMalformed, n))
}

// ParseInstalled reads a package.list_installed result (InstalledFormat)
// from a host of distribution distro (from os.detect). It never fails:
// whatever cannot be used makes the inventory partial. The running kernel
// is mapped by vulnver.RunningKernel only, so the parser and the matcher
// cannot reach different kernel verdicts for the same host.
func ParseInstalled(out []byte, rs ReadStatus, distro vulnver.Distro) InstalledInventory {
	p := &installedParser{seen: map[string]bool{}}
	p.inv.Complete = true
	p.inv.RunningKernel = RunningKernel{State: KernelVersionUnknown, Reason: ReasonNoKernel}
	if rs.ExitCode != 0 {
		p.partial(ReasonReadFailed)
	}
	if rs.Truncated {
		p.partial(ReasonTruncated)
	}
	if len(out) > MaxInstalledOutput {
		out = out[:MaxInstalledOutput]
		p.partial(ReasonTruncated)
	}
	header := []byte(InstalledFormat + "\n")
	if !bytes.HasPrefix(out, header) {
		p.partial(ReasonFormat)
		p.inv.Complete = false
		return p.inv
	}
	rest := out[len(header):]
	n := 1
	for len(rest) > 0 {
		n++
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			// Last line without newline: the output was cut.
			p.inv.Dropped++
			p.partial(ReasonTruncated)
			break
		}
		line := rest[:i]
		rest = rest[i+1:]
		p.line(n, line)
	}
	if !p.kernel {
		p.partial(ReasonNoKernel)
	}
	if !p.endSeen {
		p.partial(ReasonNoEnd)
	}
	if len(p.inv.Packages) >= MaxPackages {
		p.partial(ReasonLimit)
	}
	if len(p.inv.Packages) == 0 {
		// An empty inventory would read as "every package removed".
		p.partial(ReasonNoPackages)
	}
	p.mapKernels(distro)
	return p.inv
}

func (p *installedParser) line(n int, line []byte) {
	isP := bytes.HasPrefix(line, []byte("P\t"))
	if isP {
		p.pLines++
	}
	if p.endSeen {
		p.malformed(n)
		return
	}
	f := strings.Split(string(line), "\t")
	size := len(line)
	if isP && len(f) == 9 && !strings.HasPrefix(f[2], "linux-image-") {
		// Built-Using is used for kernel images only; drop it for every
		// other binary before the limits apply (Go and Rust packages carry
		// long lists).
		size -= len(f[7])
		f[7] = ""
	}
	if size > maxInstalledLine || !validUTF8(f) {
		p.malformed(n)
		return
	}
	switch f[0] {
	case "P":
		if p.kernels > 0 {
			// Record order is P lines, then K, then END.
			p.malformed(n)
			return
		}
		p.pkg(n, f)
	case "K":
		p.kernelRecord(n, f)
	case "END":
		p.endSeen = true
		if len(f) != 2 || !endCountRe.MatchString(f[1]) {
			p.malformed(n)
			return
		}
		if c, err := strconv.Atoi(f[1]); err != nil || c != p.pLines {
			p.partial(ReasonCountMismatch)
		}
	default:
		p.malformed(n)
	}
}

func (p *installedParser) pkg(n int, f []string) {
	if len(f) != 9 || f[8] != "." {
		p.malformed(n)
		return
	}
	status, name, arch, ver, src, srcVer, bu := f[1], f[2], f[3], f[4], f[5], f[6], f[7]
	include, known := dpkgStatus[status]
	if !known || !debNameRe.MatchString(name) || !debArchRe.MatchString(arch) ||
		!debVersionRe.MatchString(ver) ||
		!debNameRe.MatchString(src) || !debVersionRe.MatchString(srcVer) ||
		!validBuiltUsing(bu) {
		p.malformed(n)
		return
	}
	if !include {
		return
	}
	key := name + ":" + arch
	if p.seen[key] {
		p.malformed(n)
		return
	}
	if len(p.inv.Packages) >= MaxPackages {
		p.inv.Dropped++
		p.partial(ReasonLimit)
		return
	}
	if unfinishedStatus[status] {
		// The files are on disk, so the package stays inventory, but the
		// read can no longer prove a fix or a removal.
		p.partial(fmt.Sprintf("%s %d", ReasonUnfinished, n))
	}
	p.seen[key] = true
	p.inv.Packages = append(p.inv.Packages, InstalledPackage{
		Name: name, Arch: arch, Version: ver, Source: src, SourceVersion: srcVer,
		Status: status, BuiltUsing: bu,
	})
}

func validUTF8(f []string) bool {
	for _, s := range f {
		if !utf8.ValidString(s) {
			return false
		}
	}
	return true
}

func validBuiltUsing(s string) bool {
	if len(s) > maxBuiltUsingLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func (p *installedParser) kernelRecord(n int, f []string) {
	p.kernels++
	if p.kernels > 1 {
		// A second record makes the running kernel ambiguous.
		p.inv.RunningKernel = RunningKernel{State: KernelVersionUnknown, Reason: "several kernel records"}
		p.malformed(n)
		return
	}
	p.kernel = true
	if len(f) != 3 || len(f[1]) > maxReleaseLen || !releaseRe.MatchString(f[1]) || !validText(f[2], maxBuildLen) {
		p.inv.RunningKernel = RunningKernel{State: KernelVersionUnknown, Reason: "malformed kernel record"}
		p.malformed(n)
		return
	}
	// An empty or unrecognised build string is a well-formed record; it is
	// vulnver.RunningKernel that turns it into "kernel version unknown".
	p.inv.RunningKernel = RunningKernel{Release: f[1], Build: f[2], State: KernelVersionUnknown}
}

func validText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// kernelImageRelease returns the release of a linux-image-<release>
// binary, or "" for meta (linux-image-amd64, linux-image-generic) and debug
// packages. It only selects what is listed as an installed kernel; the
// running kernel's image is chosen by vulnver.RunningKernel.
func kernelImageRelease(name string) string {
	rel, ok := strings.CutPrefix(name, "linux-image-")
	if !ok || rel == "" || rel[0] < '0' || rel[0] > '9' ||
		strings.HasSuffix(rel, "-dbg") || strings.HasSuffix(rel, "-dbgsym") {
		return ""
	}
	return rel
}

// binaries converts the inventory for vulnver.
func binaries(pkgs []InstalledPackage) []vulnver.Binary {
	out := make([]vulnver.Binary, len(pkgs))
	for i, pkg := range pkgs {
		out[i] = vulnver.Binary{
			Name: pkg.Name, Version: pkg.Version,
			SourceName: pkg.Source, SourceVersion: pkg.SourceVersion,
			BuiltUsing: pkg.BuiltUsing,
		}
	}
	return out
}

// mapKernels sets the running kernel's basis with vulnver.RunningKernel and
// lists installed kernel images with vulnver.ImageBasis. There is no local
// kernel rule.
func (p *installedParser) mapKernels(distro vulnver.Distro) {
	rk := &p.inv.RunningKernel
	running := ""
	if rk.Release != "" {
		running = "linux-image-" + rk.Release
	}
	bins := binaries(p.inv.Packages)
	for _, b := range bins {
		rel := kernelImageRelease(b.Name)
		if rel == "" {
			continue
		}
		k := InstalledKernel{Package: b.Name, Version: b.Version, Release: rel, Running: b.Name == running}
		if kb, err := vulnver.ImageBasis(b); err == nil {
			k.Source, k.SourceVersion, k.Mapped = kb.SourceName, kb.Version, true
		}
		p.inv.InstalledKernels = append(p.inv.InstalledKernels, k)
	}
	if running == "" {
		return // no usable kernel record; Reason is already set
	}
	if distro != vulnver.DistroDebian && distro != vulnver.DistroUbuntu {
		rk.Reason = KernelReasonDistro
		return
	}
	kb, err := vulnver.RunningKernel(vulnver.KernelFacts{
		Distro: distro, Release: rk.Release, BuildVersion: rk.Build, Installed: bins,
	})
	if err != nil {
		// vulnver errors quote host content; the reason stays fixed text.
		rk.Reason = KernelReasonUnmapped
		return
	}
	rk.State, rk.Reason, rk.ImagePackage, rk.Source, rk.Version = KernelMapped, "", kb.ImageBinary, kb.SourceName, kb.Version
}
