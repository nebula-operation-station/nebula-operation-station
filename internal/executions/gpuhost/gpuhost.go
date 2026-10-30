// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gpuhost reads the results of the built-in PCI/GPU actions
// (spec 10, v23-10-03). Everything in a result comes from the host and
// is untrusted: fields are checked, cut and dropped, never interpreted.
package gpuhost

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrPCIFormat means the result is not a pci.inventory result.
var ErrPCIFormat = errors.New("gpuhost: not a pci.inventory result")

// ErrGPUFormat means the result is not a gpu.status result.
var ErrGPUFormat = errors.New("gpuhost: not a gpu.status result")

const (
	maxDocumentSize = 2 << 20                  // 2 MiB JSON, checked before unmarshalling
	maxEncodedSize  = (maxRawSize + 2) / 3 * 4 // base64, checked before decoding
	maxRawSize      = 1 << 20                  // 1 MiB decoded
	maxDevices      = 512                      // PCI devices per host
	maxGPUs         = 64                       // GPUs per host
	maxNameLen      = 100                      // a device or GPU name
	maxReasonLen    = 300                      // a precheck reason

	maxIndex     = 255     // nvidia-smi GPU index
	maxUtil      = 100     // percent
	maxMemoryMiB = 4 << 20 // 4 TiB
	maxTempC     = 150     // degrees Celsius
	maxPowerW    = 10000.0 // watts
	maxDomain    = 0xffff  // PCI domain
)

// PCIDevice is one line of a pci.inventory result: an NVIDIA display or
// 3D controller as lspci reports it.
type PCIDevice struct {
	Slot   string // 0000:65:00.0
	Class  string // 3D controller or VGA compatible controller
	Vendor string // NVIDIA Corporation [10de]
	Device string // GA102 [RTX A6000] [10de:2216]
}

// PCIInventory is a parsed pci.inventory result. Present is false when
// the host has no lspci; an empty Devices with Present true is a host
// without an NVIDIA device, which is not the same thing.
type PCIInventory struct {
	Phase   string // done or precheck
	Reason  string
	Present bool
	Devices []PCIDevice
}

// GPU is one line of a gpu.status result. A nil metric is unavailable
// (nvidia-smi reported [N/A]); it is not zero.
type GPU struct {
	Index          int
	UUID           string // GPU-...
	PCIBusID       string // 00000000:65:00.0
	Name           string // NVIDIA RTX A6000
	UtilPercent    *int
	MemoryUsedMiB  *int
	MemoryTotalMiB *int
	TemperatureC   *int
	PowerW         *float64
}

// GPUStatus is a parsed gpu.status result. Present is false when the
// host has no nvidia-smi; a precheck phase means the driver is missing
// or the query failed, with the reason.
type GPUStatus struct {
	Phase   string // done or precheck
	Reason  string
	Present bool
	GPUs    []GPU
}

var (
	// slotRe is an lspci slot with domain, e.g. 0000:65:00.0.
	slotRe = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)
	// uuidRe is an NVIDIA GPU UUID.
	uuidRe = regexp.MustCompile(`^GPU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// nvidiaBusRe is nvidia-smi's pci.bus_id with a 32-bit domain.
	nvidiaBusRe = regexp.MustCompile(`^[0-9a-f]{8}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)
)

// unsafeRune reports control characters (C0, DEL, C1), line and
// paragraph separators, bidirectional marks, embeddings, overrides and
// isolates, and the byte order mark: characters that can make a value
// look different from what it is.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029, r == 0xfeff:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x206f:
		return true
	}
	return false
}

// printable is at most limit bytes, valid UTF-8, without unsafe
// characters.
func printable(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unsafeRune(r) {
			return false
		}
	}
	return true
}

func decode(s string) (string, bool) {
	if len(s) > maxEncodedSize {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) > maxRawSize || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

// isGPUClass reports whether the lspci class is an NVIDIA display or 3D
// controller.
func isGPUClass(class string) bool {
	return class == "3D controller" || class == "VGA compatible controller"
}

// isNVIDIA reports whether the lspci vendor field identifies NVIDIA:
// the name from the pci.ids database or the numeric vendor ID.
func isNVIDIA(vendor string) bool {
	return strings.HasPrefix(vendor, "NVIDIA Corporation") || strings.Contains(vendor, "[10de]")
}

// intMetric parses an integer metric: a number in [0, hi], or "[N/A]"
// (unavailable). Anything else is invalid.
func intMetric(s string, hi int) (v int, avail, valid bool) {
	if s == "[N/A]" {
		return 0, false, true
	}
	i, err := strconv.Atoi(s)
	if err != nil || i < 0 || i > hi {
		return 0, false, false
	}
	return i, true, true
}

// floatMetric parses a float metric: a number in [0, hi], or "[N/A]"
// (unavailable). Anything else is invalid.
func floatMetric(s string, hi float64) (v float64, avail, valid bool) {
	if s == "[N/A]" {
		return 0, false, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > hi {
		return 0, false, false
	}
	return f, true, true
}

// ParsePCIInventory reads a pci.inventory result. Lines that are not an
// NVIDIA display or 3D controller are left out.
func ParsePCIInventory(result []byte) (PCIInventory, error) {
	if len(result) > maxDocumentSize {
		return PCIInventory{}, ErrPCIFormat
	}
	var doc struct {
		Format  string `json:"format"`
		Phase   string `json:"phase"`
		Reason  string `json:"reason"`
		Present bool   `json:"present"`
		Devices string `json:"devices"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "pci-inventory-v1" || len(doc.Devices) > maxEncodedSize || (doc.Phase != "done" && doc.Phase != "precheck") {
		return PCIInventory{}, ErrPCIFormat
	}
	inv := PCIInventory{Phase: doc.Phase, Present: doc.Present}
	if doc.Phase == "precheck" {
		if printable(doc.Reason, maxReasonLen) {
			inv.Reason = doc.Reason
		}
		return inv, nil
	}
	if !doc.Present {
		return inv, nil
	}
	text, ok := decode(doc.Devices)
	if !ok {
		return PCIInventory{}, ErrPCIFormat
	}
	for _, line := range strings.Split(text, "\n") {
		if len(inv.Devices) >= maxDevices {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			continue
		}
		slot, class, vendor, device := f[0], f[1], f[2], f[3]
		if !slotRe.MatchString(slot) || !isGPUClass(class) || !isNVIDIA(vendor) {
			continue
		}
		if !printable(vendor, maxNameLen) || !printable(device, maxNameLen) {
			continue
		}
		inv.Devices = append(inv.Devices, PCIDevice{Slot: slot, Class: class, Vendor: vendor, Device: device})
	}
	return inv, nil
}

// parseGPULine reads one nvidia-smi CSV line of the fixed query.
func parseGPULine(f []string) (GPU, bool) {
	idx, err := strconv.Atoi(strings.TrimSpace(f[0]))
	if err != nil || idx < 0 || idx > maxIndex {
		return GPU{}, false
	}
	uuid := strings.TrimSpace(f[1])
	bus := strings.TrimSpace(f[2])
	if !uuidRe.MatchString(uuid) || !nvidiaBusRe.MatchString(bus) {
		return GPU{}, false
	}
	name := strings.TrimSpace(f[3])
	if !printable(name, maxNameLen) {
		return GPU{}, false
	}
	util, okUtil, valid := intMetric(strings.TrimSpace(f[4]), maxUtil)
	memUsed, okUsed, validUsed := intMetric(strings.TrimSpace(f[5]), maxMemoryMiB)
	memTotal, okTotal, validTotal := intMetric(strings.TrimSpace(f[6]), maxMemoryMiB)
	temp, okTemp, validTemp := intMetric(strings.TrimSpace(f[7]), maxTempC)
	power, okPower, validPower := floatMetric(strings.TrimSpace(f[8]), maxPowerW)
	if !valid || !validUsed || !validTotal || !validTemp || !validPower {
		return GPU{}, false
	}
	g := GPU{Index: idx, UUID: uuid, PCIBusID: bus, Name: name}
	if okUtil {
		g.UtilPercent = &util
	}
	if okUsed {
		g.MemoryUsedMiB = &memUsed
	}
	if okTotal {
		g.MemoryTotalMiB = &memTotal
	}
	if okTemp {
		g.TemperatureC = &temp
	}
	if okPower {
		g.PowerW = &power
	}
	return g, true
}

// ParseGPUStatus reads a gpu.status result. Lines that do not fit the
// fixed 9-field schema are left out.
func ParseGPUStatus(result []byte) (GPUStatus, error) {
	if len(result) > maxDocumentSize {
		return GPUStatus{}, ErrGPUFormat
	}
	var doc struct {
		Format  string `json:"format"`
		Phase   string `json:"phase"`
		Reason  string `json:"reason"`
		Present bool   `json:"present"`
		GPUs    string `json:"gpus"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "gpu-status-v1" || len(doc.GPUs) > maxEncodedSize || (doc.Phase != "done" && doc.Phase != "precheck") {
		return GPUStatus{}, ErrGPUFormat
	}
	st := GPUStatus{Phase: doc.Phase, Present: doc.Present}
	if doc.Phase == "precheck" {
		if printable(doc.Reason, maxReasonLen) {
			st.Reason = doc.Reason
		}
		return st, nil
	}
	if !doc.Present {
		return st, nil
	}
	text, ok := decode(doc.GPUs)
	if !ok {
		return GPUStatus{}, ErrGPUFormat
	}
	for _, line := range strings.Split(text, "\n") {
		if len(st.GPUs) >= maxGPUs {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) != 9 {
			continue
		}
		if g, ok := parseGPULine(f); ok {
			st.GPUs = append(st.GPUs, g)
		}
	}
	return st, nil
}
