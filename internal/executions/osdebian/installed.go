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

// Limits for package.list_installed results.
const (
	// MaxInstalledOutput bounds the bytes read from a result; anything
	// beyond is ignored and the read is partial.
	MaxInstalledOutput = 8 << 20
	maxInstalledLine   = 4096
	maxFieldLen        = 128
	maxBuiltUsingLen   = 1024
	maxReleaseLen      = 64
	maxBuildLen        = 256
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
// parsed every line, and stayed below MaxPackages; a partial read can add
// inventory but never prove a removal.
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
	releaseRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~\-]{0,63}$`)
	builtUsingRe = regexp.MustCompile(`^([a-z0-9][a-z0-9+.\-]{1,127}) \(= ((?:[0-9]{1,10}:)?[0-9A-Za-z][0-9A-Za-z.+~\-]{0,127})\)$`)
	debBuildRe   = regexp.MustCompile(`\bDebian ([0-9][0-9A-Za-z.+~:\-]*)`)
	ubuBuildRe   = regexp.MustCompile(`^#([0-9]+)(?:~[0-9A-Za-z.+]+)?-Ubuntu\b`)
	imageRe      = regexp.MustCompile(`^linux-image-(?:unsigned-)?([0-9][A-Za-z0-9._+~\-]*?)(?:-unsigned)?$`)
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

// ParseInstalled reads a package.list_installed result (InstalledFormat).
// It never fails: whatever cannot be used makes the inventory partial.
func ParseInstalled(out []byte, rs ReadStatus) InstalledInventory {
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
	p.mapKernels()
	return p.inv
}

func (p *installedParser) line(n int, line []byte) {
	if bytes.HasPrefix(line, []byte("P\t")) {
		p.pLines++
	}
	if p.endSeen || len(line) > maxInstalledLine || !utf8.Valid(line) {
		p.malformed(n)
		return
	}
	f := strings.Split(string(line), "\t")
	switch f[0] {
	case "P":
		p.pkg(n, f)
	case "K":
		p.kernelRecord(n, f)
	case "END":
		p.endSeen = true
		c, err := strconv.Atoi(f[len(f)-1])
		if len(f) != 2 || err != nil || c < 0 {
			p.malformed(n)
			return
		}
		if c != p.pLines {
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
	p.seen[key] = true
	if !strings.HasPrefix(name, "linux-image-") {
		bu = ""
	}
	p.inv.Packages = append(p.inv.Packages, InstalledPackage{
		Name: name, Arch: arch, Version: ver, Source: src, SourceVersion: srcVer,
		Status: status, BuiltUsing: bu,
	})
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

// isKernelSource reports whether a source package is an unsigned kernel
// source the trackers key on (Debian linux, Ubuntu linux and its flavour
// sources such as linux-hwe-6.8 or linux-aws). Signed and meta sources
// carry version lines that never compare with tracker fixed versions.
func isKernelSource(src string) bool {
	if src == "linux" {
		return true
	}
	if !strings.HasPrefix(src, "linux-") {
		return false
	}
	for _, x := range []string{"linux-signed", "linux-meta", "linux-restricted-", "linux-firmware", "linux-base"} {
		if strings.HasPrefix(src, x) {
			return false
		}
	}
	return true
}

// mapImage returns the unsigned kernel source and version of a kernel
// image binary, or a reason it cannot be mapped.
func mapImage(pkg InstalledPackage) (src, ver, reason string) {
	if isKernelSource(pkg.Source) {
		return pkg.Source, pkg.SourceVersion, ""
	}
	if !strings.HasPrefix(pkg.Source, "linux-signed") {
		return "", "", "kernel image not built from a kernel source"
	}
	if pkg.BuiltUsing == "" {
		return "", "", "signed kernel image without Built-Using"
	}
	found := 0
	for _, e := range strings.Split(pkg.BuiltUsing, ",") {
		m := builtUsingRe.FindStringSubmatch(strings.TrimSpace(e))
		if m == nil {
			return "", "", "unparseable Built-Using"
		}
		name := m[1]
		switch {
		case isKernelSource(name):
			src, ver = name, m[2]
			found++
		case strings.HasPrefix(name, "linux-signed"), strings.HasPrefix(name, "linux-meta"):
			return "", "", "Built-Using names a signed or meta source"
		}
	}
	if found != 1 {
		return "", "", "Built-Using without exactly one kernel source"
	}
	return src, ver, ""
}

// imageRelease returns the kernel release of a linux-image-<release>
// binary (also linux-image-unsigned-<release> and
// linux-image-<release>-unsigned), or "" for meta and debug packages.
func imageRelease(name string) string {
	if strings.HasSuffix(name, "-dbg") || strings.HasSuffix(name, "-dbgsym") {
		return ""
	}
	m := imageRe.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1]
}

// ubuntuUpload returns the ABI upload number of an Ubuntu kernel version
// (6.8.0-45.45 and 6.8.0-45.45~22.04.1 -> 45).
func ubuntuUpload(ver string) string {
	if i := strings.IndexByte(ver, '~'); i >= 0 {
		ver = ver[:i]
	}
	if i := strings.LastIndexByte(ver, '.'); i >= 0 {
		return ver[i+1:]
	}
	return ""
}

func (p *installedParser) mapKernels() {
	rk := &p.inv.RunningKernel
	running := ""
	if rk.Release != "" {
		running = rk.Release
		rk.Reason = "no installed kernel image for the running release"
	}
	var src, ver, image string
	candidates, failed := 0, false
	for _, pkg := range p.inv.Packages {
		rel := imageRelease(pkg.Name)
		if rel == "" {
			continue
		}
		s, v, why := mapImage(pkg)
		k := InstalledKernel{Package: pkg.Name, Version: pkg.Version, Release: rel, Running: rel == running}
		if why == "" {
			k.Source, k.SourceVersion, k.Mapped = s, v, true
		}
		p.inv.InstalledKernels = append(p.inv.InstalledKernels, k)
		if !k.Running {
			continue
		}
		candidates++
		switch {
		case why != "":
			failed = true
			rk.Reason = why
		case candidates == 1:
			src, ver, image = s, v, pkg.Name
		case s != src || v != ver:
			failed = true
			rk.Reason = "installed images of the running release disagree"
		}
	}
	if running == "" || candidates == 0 || failed {
		return
	}
	if m := debBuildRe.FindStringSubmatch(rk.Build); m != nil && m[1] != ver {
		rk.Reason = "build string does not match the kernel version"
		return
	}
	if m := ubuBuildRe.FindStringSubmatch(rk.Build); m != nil && m[1] != ubuntuUpload(ver) {
		rk.Reason = "build string does not match the kernel upload"
		return
	}
	rk.State, rk.Reason, rk.ImagePackage, rk.Source, rk.Version = KernelMapped, "", image, src, ver
}
