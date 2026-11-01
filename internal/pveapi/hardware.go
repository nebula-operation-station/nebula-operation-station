// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// maxPCIDevices bounds the entries of one node's PCI device list.
const maxPCIDevices = 1024

var (
	// pciAddressRe is a full PCI address with domain (dddd:bb:ss.f).
	pciAddressRe = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)
	// pciIDRe is a PCI vendor or device ID as PVE renders it (0xhhhh).
	pciIDRe = regexp.MustCompile(`^0x[0-9a-f]{4}$`)
)

// PCIDevice is the identity of one node PCI function from GET
// /nodes/{node}/hardware/pci: only its address and vendor/device IDs are
// kept (names, IOMMU groups and subsystem IDs are discarded).
type PCIDevice struct {
	// Address is the lowercase full PCI address, e.g. "0000:01:00.0".
	Address string
	// Vendor and Device are four lowercase hex digits without "0x".
	Vendor string
	Device string
}

// PCIDevices is a node's PCI device list.
type PCIDevices struct {
	// Available reports whether the list could be read.
	Available bool
	// Reason explains an unavailable result.
	Reason string
	// Devices are the listed functions in response order.
	Devices []PCIDevice
}

type pciDeviceRaw struct {
	ID     string `json:"id"`
	Vendor string `json:"vendor"`
	Device string `json:"device"`
}

// NodePCIDevices reads GET /nodes/{node}/hardware/pci with PVE's default
// class filter. A denied or missing list is Available=false, never empty.
func (c *Client) NodePCIDevices(ctx context.Context, node string) (PCIDevices, error) {
	if !nodeNameRe.MatchString(node) {
		return PCIDevices{}, fmt.Errorf("pveapi: invalid node name")
	}
	body, reason, err := c.clusterGet(ctx, "/nodes/"+url.PathEscape(node)+"/hardware/pci")
	if err != nil {
		return PCIDevices{}, err
	}
	if body == nil {
		return PCIDevices{Reason: reason}, nil
	}
	entries, err := decodeData[[]pciDeviceRaw](body)
	if err != nil {
		return PCIDevices{}, err
	}
	if len(*entries) > maxPCIDevices {
		return PCIDevices{}, fmt.Errorf("%w: pci list exceeds %d entries", ErrMalformed, maxPCIDevices)
	}
	out := PCIDevices{Available: true, Devices: make([]PCIDevice, 0, len(*entries))}
	seen := map[string]bool{}
	for _, e := range *entries {
		addr, vendor, device := strings.ToLower(e.ID), strings.ToLower(e.Vendor), strings.ToLower(e.Device)
		if !pciAddressRe.MatchString(addr) || !pciIDRe.MatchString(vendor) || !pciIDRe.MatchString(device) {
			return PCIDevices{}, fmt.Errorf("%w: invalid pci device entry", ErrMalformed)
		}
		if seen[addr] {
			return PCIDevices{}, fmt.Errorf("%w: duplicate pci address", ErrMalformed)
		}
		seen[addr] = true
		out.Devices = append(out.Devices, PCIDevice{Address: addr, Vendor: vendor[2:], Device: device[2:]})
	}
	return out, nil
}

// NormalizePCIAddress returns the full lowercase address (domain 0000 when
// omitted) of one exact PCI function as a hostpci value names it, or false
// for anything else (all functions "01:00", lists "01:00.0;02:00.0",
// resource mappings, garbage).
func NormalizePCIAddress(s string) (string, bool) {
	s = strings.ToLower(s)
	if strings.Count(s, ":") == 1 {
		s = "0000:" + s
	}
	return s, pciAddressRe.MatchString(s)
}
