// SPDX-License-Identifier: AGPL-3.0-or-later
// Package hostmetrics parses the bounded, base64-encoded machine and
// filesystem telemetry that the built-in host.metrics and filesystem.list
// actions collect over SSH.
//
// The values are untrusted input from a managed host (spec 09): every field
// is validated against explicit size and numeric limits, virtual kernel
// filesystems are dropped by an explicit list rather than a heuristic, and a
// missing reading is reported as unavailable rather than as a successful
// zero. Unknown formats and malformed numbers are rejected, never guessed.
package hostmetrics

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits for host telemetry (ADR 0006 P1-22, spec 09).
const (
	// maxRawSize bounds the decoded size of a single response value.
	maxRawSize = 1 << 20
	// maxMounts bounds the number of real mounts in a filesystem.list result.
	maxMounts = 256
	// maxMountLen bounds a mount point in bytes.
	maxMountLen = 512
	// maxFSTypeLen bounds a filesystem type in bytes.
	maxFSTypeLen = 32
	// maxReasonLen bounds a precheck reason in bytes.
	maxReasonLen = 300
	// maxBytes bounds any byte count (4 EiB) so a host cannot claim an
	// absurd amount of storage.
	maxBytes = 1 << 62
	// maxLoad bounds a single load-average value.
	maxLoad = 1 << 20
)

// pseudoFilesystems are the virtual kernel filesystems that are not real disk
// storage. They are excluded from filesystem.list and from the
// fullest-filesystem computation (ADR 0006 P1-22). The list is explicit, not
// a heuristic: an fstype is virtual if and only if it appears here.
var pseudoFilesystems = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"cgroup": true, "cgroup2": true, "pstore": true, "securityfs": true,
	"debugfs": true, "tracefs": true, "fusectl": true, "configfs": true,
	"mqueue": true, "hugetlbfs": true, "bpf": true, "autofs": true,
	"binfmt_misc": true, "rpc_pipefs": true, "nsfs": true, "selinuxfs": true,
	"efivarfs": true, "ramfs": true, "tmpfs": true, "swap": true, "shm": true,
}

// Metrics is the parsed result of a host.metrics action.
type Metrics struct {
	// Phase is "done" or "precheck".
	Phase string
	// Reason is a printable precheck reason; empty on done.
	Reason string
	// CPU is the usage over the short sample.
	CPU CPUStat
	// Load is the 1/5/15-minute load average.
	Load LoadStat
	// Mem is RAM used/total in bytes.
	Mem MemStat
	// Disk is the fullest real filesystem.
	Disk DiskStat
}

// CPUStat is the CPU usage over the short sample.
type CPUStat struct {
	// Available reports whether the reading succeeded. A real 0.0 is
	// available; an unreadable counter is not.
	Available bool
	// Percent is 0-100; only meaningful when Available.
	Percent float64
}

// LoadStat is the 1/5/15-minute load average.
type LoadStat struct {
	Available bool
	Min1      float64
	Min5      float64
	Min15     float64
}

// MemStat is RAM used/total in bytes.
type MemStat struct {
	// Available reports whether the reading succeeded. A real used of 0 is
	// available; an unreadable /proc/meminfo is not.
	Available  bool
	UsedBytes  uint64
	TotalBytes uint64
}

// Percent returns the RAM usage percentage, or 0 when unavailable.
func (m MemStat) Percent() float64 {
	if !m.Available || m.TotalBytes == 0 {
		return 0
	}
	return 100 * float64(m.UsedBytes) / float64(m.TotalBytes)
}

// DiskStat is one filesystem.
type DiskStat struct {
	// Available reports whether a real filesystem was found. A host with no
	// real (non-virtual) mounts is unavailable, distinct from a real
	// filesystem that happens to be empty.
	Available  bool
	Mount      string
	UsedBytes  uint64
	TotalBytes uint64
	// Percent is 0-100, computed from UsedBytes/TotalBytes; only meaningful
	// when Available.
	Percent float64
}

// Filesystems is the parsed result of a filesystem.list action.
type Filesystems struct {
	// Phase is "done" or "precheck".
	Phase string
	// Reason is a printable precheck reason; empty on done.
	Reason string
	// Available reports whether the host produced a mount listing at all.
	// It is distinct from an empty Mounts slice, which means the host has
	// no real (non-virtual) mounts.
	Available bool
	// Mounts holds the real filesystems, in the order the host reported them.
	Mounts []Mount
}

// Mount is one real filesystem.
type Mount struct {
	FSType    string
	Mount     string
	SizeBytes uint64
	UsedBytes uint64
	// Percent is 0-100, computed from UsedBytes/SizeBytes.
	Percent float64
}

// Fullest returns the mount with the highest usage percentage, or ok=false
// when there are no mounts.
func (f Filesystems) Fullest() (Mount, bool) {
	if len(f.Mounts) == 0 {
		return Mount{}, false
	}
	best := f.Mounts[0]
	for _, m := range f.Mounts[1:] {
		if m.Percent > best.Percent {
			best = m
		}
	}
	return best, true
}

// ParseMetrics parses a host.metrics result document.
func ParseMetrics(result []byte) (Metrics, error) {
	var doc struct {
		Format string `json:"format"`
		Phase  string `json:"phase"`
		Reason string `json:"reason"`
		CPU    string `json:"cpu"`
		Load   string `json:"load"`
		Mem    string `json:"mem"`
		Disk   string `json:"disk"`
	}
	if err := json.Unmarshal(result, &doc); err != nil {
		return Metrics{}, fmt.Errorf("parse host metrics: %w", err)
	}
	if doc.Format != "host-metrics-v1" {
		return Metrics{}, errors.New("host metrics: unknown format")
	}
	if err := validatePhase(doc.Phase); err != nil {
		return Metrics{}, err
	}
	m := Metrics{Phase: doc.Phase}
	reason, err := decodeText(doc.Reason, maxReasonLen)
	if err != nil {
		return Metrics{}, err
	}
	m.Reason = reason
	cpu, err := decodeText(doc.CPU, maxRawSize)
	if err != nil {
		return Metrics{}, err
	}
	m.CPU = parseCPU(cpu)
	load, err := decodeText(doc.Load, maxRawSize)
	if err != nil {
		return Metrics{}, err
	}
	m.Load = parseLoad(load)
	mem, err := decodeText(doc.Mem, maxRawSize)
	if err != nil {
		return Metrics{}, err
	}
	m.Mem = parseMem(mem)
	disk, err := decodeText(doc.Disk, maxRawSize)
	if err != nil {
		return Metrics{}, err
	}
	m.Disk = parseDisk(disk)
	return m, nil
}

// ParseFilesystems parses a filesystem.list result document.
func ParseFilesystems(result []byte) (Filesystems, error) {
	var doc struct {
		Format string `json:"format"`
		Phase  string `json:"phase"`
		Reason string `json:"reason"`
		Mounts string `json:"mounts"`
	}
	if err := json.Unmarshal(result, &doc); err != nil {
		return Filesystems{}, fmt.Errorf("parse filesystem list: %w", err)
	}
	if doc.Format != "fs-list-v1" {
		return Filesystems{}, errors.New("filesystem list: unknown format")
	}
	if err := validatePhase(doc.Phase); err != nil {
		return Filesystems{}, err
	}
	fs := Filesystems{Phase: doc.Phase}
	reason, err := decodeText(doc.Reason, maxReasonLen)
	if err != nil {
		return Filesystems{}, err
	}
	fs.Reason = reason
	mounts, err := decodeText(doc.Mounts, maxRawSize)
	if err != nil {
		return Filesystems{}, err
	}
	// Available is true once the host produced any mount line, which is
	// distinct from a list that is empty after dropping virtual filesystems.
	for _, line := range strings.Split(mounts, "\n") {
		if line == "" {
			continue
		}
		fs.Available = true
		m, ok := parseMountLine(line)
		if !ok {
			continue
		}
		if len(fs.Mounts) >= maxMounts {
			return Filesystems{}, fmt.Errorf("filesystem list exceeds %d mounts", maxMounts)
		}
		fs.Mounts = append(fs.Mounts, m)
	}
	return fs, nil
}

// parseCPU parses a "percent" value. Empty means unavailable; a valid
// percentage in [0,100] is available (including a real 0.0). A non-empty
// malformed value is unavailable, never an error, so one bad field cannot
// discard the rest of the document.
func parseCPU(s string) CPUStat {
	if s == "" {
		return CPUStat{}
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 100 {
		return CPUStat{}
	}
	return CPUStat{Available: true, Percent: v}
}

// parseLoad parses "m1 m5 m15" load averages. Empty means unavailable.
func parseLoad(s string) LoadStat {
	if s == "" {
		return LoadStat{}
	}
	f := strings.Fields(s)
	if len(f) != 3 {
		return LoadStat{}
	}
	vals := make([]float64, 3)
	for i, tok := range f {
		v, err := strconv.ParseFloat(tok, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > maxLoad {
			return LoadStat{}
		}
		vals[i] = v
	}
	return LoadStat{Available: true, Min1: vals[0], Min5: vals[1], Min15: vals[2]}
}

// parseMem parses "used total" byte counts. Empty means unavailable. total
// must be > 0 and used must be within [0, total].
func parseMem(s string) MemStat {
	if s == "" {
		return MemStat{}
	}
	f := strings.Fields(s)
	if len(f) != 2 {
		return MemStat{}
	}
	used, err1 := strconv.ParseUint(f[0], 10, 64)
	total, err2 := strconv.ParseUint(f[1], 10, 64)
	if err1 != nil || err2 != nil || total == 0 || total > maxBytes || used > total {
		return MemStat{}
	}
	return MemStat{Available: true, UsedBytes: used, TotalBytes: total}
}

// parseDisk parses "mount\tused\ttotal". Empty means unavailable. The
// percentage is computed from used/total so a host cannot report a false one.
func parseDisk(s string) DiskStat {
	if s == "" {
		return DiskStat{}
	}
	f := strings.Split(s, "\t")
	if len(f) != 3 {
		return DiskStat{}
	}
	mount := f[0]
	if !printable(mount, maxMountLen) {
		return DiskStat{}
	}
	used, err1 := strconv.ParseUint(f[1], 10, 64)
	total, err2 := strconv.ParseUint(f[2], 10, 64)
	if err1 != nil || err2 != nil || total == 0 || total > maxBytes || used > total {
		return DiskStat{}
	}
	return DiskStat{
		Available:  true,
		Mount:      mount,
		UsedBytes:  used,
		TotalBytes: total,
		Percent:    100 * float64(used) / float64(total),
	}
}

// parseMountLine parses one "fstype\tmount\tsize\tused" line. It returns
// ok=false for malformed lines and for virtual kernel filesystems, which are
// excluded by the explicit pseudoFilesystems list.
func parseMountLine(line string) (Mount, bool) {
	f := strings.Split(line, "\t")
	if len(f) != 4 {
		return Mount{}, false
	}
	fstype, mount, sizeStr, usedStr := f[0], f[1], f[2], f[3]
	if !printable(fstype, maxFSTypeLen) || !printable(mount, maxMountLen) {
		return Mount{}, false
	}
	if pseudoFilesystems[fstype] {
		return Mount{}, false
	}
	size, err1 := strconv.ParseUint(sizeStr, 10, 64)
	used, err2 := strconv.ParseUint(usedStr, 10, 64)
	if err1 != nil || err2 != nil || size == 0 || size > maxBytes || used > size {
		return Mount{}, false
	}
	pct := 100 * float64(used) / float64(size)
	if pct > 100 {
		pct = 100
	}
	return Mount{FSType: fstype, Mount: mount, SizeBytes: size, UsedBytes: used, Percent: pct}, true
}

// decodeText base64-decodes a field and validates it is UTF-8 text within
// limit bytes. An empty field decodes to an empty string (the "unavailable"
// signal), never an error.
func decodeText(field string, limit int) (string, error) {
	if field == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return "", fmt.Errorf("decode host metric: %w", err)
	}
	if len(raw) > limit {
		return "", fmt.Errorf("host metric value exceeds %d bytes", limit)
	}
	if !utf8.Valid(raw) {
		return "", errors.New("host metric value is not valid UTF-8")
	}
	return string(raw), nil
}

// validatePhase accepts only the known phases; anything else is rejected
// rather than guessed.
func validatePhase(phase string) error {
	if phase != "done" && phase != "precheck" {
		return fmt.Errorf("host telemetry: unknown phase %q", phase)
	}
	return nil
}

// printable reports whether s is non-empty printable text within limit bytes.
func printable(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for _, r := range s {
		if unsafeRune(r) {
			return false
		}
	}
	return true
}

// unsafeRune reports whether r must not appear in host-provided text.
func unsafeRune(r rune) bool {
	switch {
	case r == '\n' || r == '\r' || r == '\t':
		return true
	case r < 0x20 || r == 0x7f:
		return true
	case !utf8.ValidRune(r):
		return true
	}
	return false
}
