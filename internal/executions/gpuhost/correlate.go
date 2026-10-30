// SPDX-License-Identifier: AGPL-3.0-or-later

package gpuhost

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// ErrBusID means the value is not a PCI bus ID.
var ErrBusID = errors.New("gpuhost: not a PCI bus ID")

// ErrHostPCITarget means the value is not a PVE hostpci target.
var ErrHostPCITarget = errors.New("gpuhost: not a hostpci target")

// BusID is a normalized PCI bus ID. The domain is 4 hex digits; the
// function is -1 when the ID names the whole device.
type BusID struct {
	Domain   string
	Bus      string
	Device   string
	Function int
}

// String is the canonical form, e.g. 0000:65:00.0 or 0000:65:00.
func (b BusID) String() string {
	if b.Function < 0 {
		return b.Domain + ":" + b.Bus + ":" + b.Device
	}
	return b.Domain + ":" + b.Bus + ":" + b.Device + "." + strconv.Itoa(b.Function)
}

var (
	// busIDRe is a PCI bus ID with an optional 4- or 8-digit domain and
	// an optional function.
	busIDRe = regexp.MustCompile(`^(?:(?:[0-9a-f]{4}|[0-9a-f]{8}):)?([0-9a-f]{2}):([0-9a-f]{2})(?:\.([0-7]))?$`)
	// hostPCIPrefixRe is the multi-host or pcieRoot prefix of a hostpci
	// target.
	hostPCIPrefixRe = regexp.MustCompile(`^(?:host[0-9]+|pcieRoot[0-9]+):`)
)

// ParseBusID parses a PCI bus ID in the lspci ("0000:65:00.0"),
// nvidia-smi ("00000000:65:00.0") or short ("65:00") form. Without a
// domain, domain 0000 is assumed; without a function, the ID names the
// whole device.
func ParseBusID(s string) (BusID, error) {
	m := busIDRe.FindStringSubmatch(s)
	if m == nil {
		return BusID{}, ErrBusID
	}
	domain := "0000"
	if strings.Count(s, ":") == 2 {
		// With a domain, it is the part before the first colon; the
		// 8-digit nvidia-smi form normalizes to the 4-digit lspci form.
		d, err := strconv.ParseUint(s[:strings.IndexByte(s, ':')], 16, 32)
		if err != nil || d > maxDomain {
			return BusID{}, ErrBusID
		}
		domain = strconv.FormatUint(d, 16)
		for len(domain) < 4 {
			domain = "0" + domain
		}
	}
	b := BusID{Domain: domain, Bus: m[1], Device: m[2], Function: -1}
	if m[3] != "" {
		fn, _ := strconv.Atoi(m[3])
		b.Function = fn
	}
	return b, nil
}

// HostPCITarget is one PVE hostpci value: a PCI bus ID, optionally with
// a hostN:/pcieRootN: prefix, optionally a range of functions.
type HostPCITarget struct {
	Domain     string
	Bus        string
	Device     string
	FnLo, FnHi int // -1: the target names no function (the whole device)
}

// ParseHostPCITarget parses one PVE hostpci target: "0000:65:00",
// "0000:65:00.0", "65:00", "65:00.0", "host0:0000:65:00",
// "pcieRoot1:0000:65:00", a function range "0000:65:00.0-0000:65:00.1",
// with or without trailing options after a comma.
func ParseHostPCITarget(s string) (HostPCITarget, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	s = hostPCIPrefixRe.ReplaceAllString(s, "")
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, err := ParseBusID(s[:i])
		if err != nil {
			return HostPCITarget{}, ErrHostPCITarget
		}
		hi, err := ParseBusID(s[i+1:])
		if err != nil || lo.Domain != hi.Domain || lo.Bus != hi.Bus || lo.Device != hi.Device {
			return HostPCITarget{}, ErrHostPCITarget
		}
		if lo.Function < 0 || hi.Function < 0 || lo.Function > hi.Function {
			return HostPCITarget{}, ErrHostPCITarget
		}
		return HostPCITarget{Domain: lo.Domain, Bus: lo.Bus, Device: lo.Device, FnLo: lo.Function, FnHi: hi.Function}, nil
	}
	b, err := ParseBusID(s)
	if err != nil {
		return HostPCITarget{}, ErrHostPCITarget
	}
	return HostPCITarget{Domain: b.Domain, Bus: b.Bus, Device: b.Device, FnLo: b.Function, FnHi: b.Function}, nil
}

// Matches reports whether the target refers to the device with the bus
// ID d, as reported by lspci (with a function).
func (t HostPCITarget) Matches(d BusID) bool {
	if t.Domain != d.Domain || t.Bus != d.Bus || t.Device != d.Device {
		return false
	}
	if t.FnLo < 0 {
		return true
	}
	return d.Function >= t.FnLo && d.Function <= t.FnHi
}

// GPUForSlot returns the GPU whose PCI bus ID is the lspci slot. The
// domain is 4 hex digits in lspci and 8 in nvidia-smi; both forms
// normalize to the same BusID.
func (s GPUStatus) GPUForSlot(slot string) (GPU, bool) {
	bid, err := ParseBusID(slot)
	if err != nil {
		return GPU{}, false
	}
	for _, g := range s.GPUs {
		if gid, err := ParseBusID(g.PCIBusID); err == nil && gid == bid {
			return g, true
		}
	}
	return GPU{}, false
}

// GPUsForTarget returns the GPUs a guest's hostpci target refers to:
// the target's PCI devices that nvidia-smi reports as GPUs. An empty
// result means the target is not a GPU, has no driver telemetry, or is
// invalid; it is not an error.
func GPUsForTarget(inv PCIInventory, st GPUStatus, target string) []GPU {
	t, err := ParseHostPCITarget(target)
	if err != nil {
		return nil
	}
	var out []GPU
	for _, d := range inv.Devices {
		bid, err := ParseBusID(d.Slot)
		if err != nil || !t.Matches(bid) {
			continue
		}
		if g, ok := st.GPUForSlot(d.Slot); ok {
			out = append(out, g)
		}
	}
	return out
}
