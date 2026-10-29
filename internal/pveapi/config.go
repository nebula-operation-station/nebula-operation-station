// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// secretKeyPattern matches config keys whose values are secrets and must
// never be kept (ADR 0006: Cloud-Init passwords, storage credentials).
var secretKeyPattern = regexp.MustCompile(`(?i)(password|secret|token)`)

// configDropKeys are fields discarded before spooling: raw arguments
// may contain inline credentials, snippet files may hold secrets, and
// free-form descriptions are excluded by policy.
var configDropKeys = map[string]bool{
	"args":        true,
	"snippets":    true,
	"description": true,
}

// macPattern is a canonical Ethernet MAC address.
var macPattern = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

// diskDevicePattern matches QEMU disk and cdrom device names.
var diskDevicePattern = regexp.MustCompile(`^(scsi|virtio|ide|sata)\d+$`)

// mountDevicePattern matches LXC mount point names.
var mountDevicePattern = regexp.MustCompile(`^mp\d+$`)

// nicDevicePattern matches QEMU and LXC network device names.
var nicDevicePattern = regexp.MustCompile(`^net\d+$`)

// hostpciDevicePattern matches QEMU PCI passthrough device names.
var hostpciDevicePattern = regexp.MustCompile(`^hostpci\d+$`)

// ipconfigDevicePattern matches cloud-init IP configuration entries.
var ipconfigDevicePattern = regexp.MustCompile(`^ipconfig\d+$`)

// Disk is one guest disk or cdrom entry.
type Disk struct {
	Device  string // "scsi0", "rootfs"
	Volume  string // "local-lvm:vm-100-disk-0"
	Storage string // "local-lvm"
	Format  string // "raw", "qcow2", "iso", ...
	Size    int64  // bytes, 0 = unknown
}

// NIC is one guest network interface.
type NIC struct {
	Device string // "net0"
	Bridge string
	VLAN   int // 0 = none
	MAC    string
}

// HostPCI is one PCI passthrough device mapping.
type HostPCI struct {
	Device     string // "hostpci0"
	PCIAddress string // "0000:01:00.0"
	Mapping    string // explicit mapping= target, "" = none
	Extras     map[string]string
}

// Mount is one LXC mount point (mp0, mp1, ...).
type Mount struct {
	Device string // "mp0"
	Volume string
	Mount  string // mountpoint inside the container
	Size   int64  // bytes, 0 = unknown
}

// GuestConfig is a sanitized QEMU or LXC guest configuration. Secret keys
// are dropped (counted in DroppedSecrets), sshkeys is reduced to a line
// count, and remaining non-secret keys are kept in Extras up to
// MaxConfigExtras. All text values are sanitized and bounded.
type GuestConfig struct {
	Node           string
	Kind           GuestKind
	VMID           int
	Name           string
	CPUs           int
	Memory         int64 // bytes, 0 = unknown
	Balloon        int64 // QEMU dynamic memory, bytes, 0 = unset
	Swap           int64 // LXC swap, bytes, 0 = unset
	Boot           string
	Tags           []string
	Pool           string
	OSType         string
	Hostname       string
	CloudInitIP    []string // nonsecret ipconfigN values
	Disks          []Disk
	Mounts         []Mount
	NICs           []NIC
	HostPCI        []HostPCI
	Features       map[string]string // LXC features
	SSHKeyCount    int
	Ctime          *time.Time
	UUID           string
	DroppedSecrets int
	Truncated      bool
	Extras         map[string]string
}

// GetQemuConfig returns the sanitized configuration of QEMU guest vmid on
// node.
func (c *Client) GetQemuConfig(ctx context.Context, node string, vmid int) (*GuestConfig, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	if err := validateVMID(vmid); err != nil {
		return nil, err
	}
	data, err := c.do(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/config", node, vmid))
	if err != nil {
		return nil, err
	}
	cfg, err := parseGuestConfig(data, node, vmid, KindQemu)
	if err != nil {
		return nil, fmt.Errorf("pveapi: qemu %s/%d: %w", node, vmid, err)
	}
	return cfg, nil
}

// GetLxcConfig returns the sanitized configuration of LXC container vmid
// on node.
func (c *Client) GetLxcConfig(ctx context.Context, node string, vmid int) (*GuestConfig, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	if err := validateVMID(vmid); err != nil {
		return nil, err
	}
	data, err := c.do(ctx, fmt.Sprintf("/nodes/%s/lxc/%d/config", node, vmid))
	if err != nil {
		return nil, err
	}
	cfg, err := parseGuestConfig(data, node, vmid, KindLxc)
	if err != nil {
		return nil, fmt.Errorf("pveapi: lxc %s/%d: %w", node, vmid, err)
	}
	return cfg, nil
}

// parseGuestConfig decodes a flat PVE guest config map of strings and
// schema-defined numbers into a GuestConfig, dropping secrets. Keys are
// processed in sorted order so the result is deterministic. PVE 8 and
// PVE 9 configs use the same flat shape; unknown keys land in Extras.
func parseGuestConfig(data json.RawMessage, node string, vmid int, kind GuestKind) (*GuestConfig, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode guest config: %w", err)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	cfg := &GuestConfig{
		Node:     node,
		Kind:     kind,
		VMID:     vmid,
		Features: map[string]string{},
		Extras:   map[string]string{},
	}
	cores, sockets := 0, 0
	for _, key := range keys {
		val, ok := raw[key].(string)
		if !ok {
			switch key {
			case "cores", "cpus", "sockets", "memory", "balloon", "swap", "onboot", "ctime":
				n, ok := raw[key].(json.Number)
				if !ok {
					return nil, fmt.Errorf("bad %s: expected string or number", key)
				}
				// Preserve the number exactly; the field parsers enforce
				// integer syntax, bounds and conversion overflow checks.
				val = n.String()
			default:
				continue
			}
		}
		switch {
		case key == "sshkeys" || key == "sshkey":
			// Counted before sanitizing: sanitizeText strips newlines.
			cfg.SSHKeyCount += countLines(val)
			continue
		case secretKeyPattern.MatchString(key):
			cfg.DroppedSecrets++
			continue
		case configDropKeys[key]:
			// dropped by policy
			continue
		}
		val = sanitizeText(val, MaxTextFieldBytes)
		switch {
		case key == "name":
			cfg.Name = val
		case key == "cores" || (key == "cpus" && cores == 0):
			n, err := parseBoundedInt(val, 1, 4096)
			if err != nil {
				return nil, fmt.Errorf("bad %s %q", key, val)
			}
			cores = n
		case key == "sockets":
			n, err := parseBoundedInt(val, 1, 64)
			if err != nil {
				return nil, fmt.Errorf("bad %s %q", key, val)
			}
			sockets = n
		case key == "memory":
			n, err := parseSizeBytes(val, 1<<20)
			if err != nil {
				return nil, fmt.Errorf("bad memory %q", val)
			}
			cfg.Memory = n
		case key == "balloon":
			n, err := parseSizeBytes(val, 1<<20)
			if err != nil {
				return nil, fmt.Errorf("bad balloon %q", val)
			}
			cfg.Balloon = n
		case key == "swap":
			n, err := parseSizeBytes(val, 1<<20)
			if err != nil {
				return nil, fmt.Errorf("bad swap %q", val)
			}
			cfg.Swap = n
		case key == "boot":
			cfg.Boot = val
		case key == "tags":
			cfg.Tags = parseTags(val)
		case key == "pool":
			cfg.Pool = val
		case key == "ostype":
			cfg.OSType = val
		case key == "hostname":
			cfg.Hostname = val
		case key == "onboot":
			if val == "1" {
				cfg.Extras["onboot"] = "1"
			}
		case key == "ctime":
			n, err := parseBoundedInt(val, 0, 1<<32)
			if err != nil {
				return nil, fmt.Errorf("bad ctime %q", val)
			}
			t := time.Unix(int64(n), 0)
			cfg.Ctime = &t
		case key == "uuid":
			cfg.UUID = val
		case key == "rootfs":
			d, err := parseDisk("rootfs", val)
			if err != nil {
				return nil, err
			}
			cfg.Disks = append(cfg.Disks, d)
		case mountDevicePattern.MatchString(key):
			m, err := parseMount(key, val)
			if err != nil {
				return nil, err
			}
			cfg.Mounts = append(cfg.Mounts, m)
		case diskDevicePattern.MatchString(key):
			d, err := parseDisk(key, val)
			if err != nil {
				return nil, err
			}
			cfg.Disks = append(cfg.Disks, d)
		case nicDevicePattern.MatchString(key):
			nic, err := parseNIC(key, val)
			if err != nil {
				return nil, err
			}
			cfg.NICs = append(cfg.NICs, nic)
		case hostpciDevicePattern.MatchString(key):
			hp, err := parseHostPCI(key, val)
			if err != nil {
				return nil, err
			}
			cfg.HostPCI = append(cfg.HostPCI, hp)
		case ipconfigDevicePattern.MatchString(key):
			if len(cfg.CloudInitIP) < 16 {
				cfg.CloudInitIP = append(cfg.CloudInitIP, val)
			}
		case key == "features":
			for k, v := range parseFeatureList(val) {
				cfg.Features[k] = v
			}
		default:
			if len(cfg.Extras) >= MaxConfigExtras {
				cfg.Truncated = true
				continue
			}
			cfg.Extras[key] = val
		}
	}
	if cores == 0 {
		cores = 1
	}
	if sockets == 0 {
		sockets = 1
	}
	cfg.CPUs = cores * sockets
	return cfg, nil
}

// countLines counts the non-empty lines of a multi-line value (used to
// reduce sshkeys to a count).
func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// parseBoundedInt parses a non-negative integer within [lo, hi].
func parseBoundedInt(s string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, errors.New("out of range")
	}
	return n, nil
}

// parseSizeBytes parses PVE size values: a plain number (multiplied by
// plainUnit, e.g. 1<<20 for MiB-based memory) or a number with a binary
// K/M/G/T suffix (which already encodes the unit).
func parseSizeBytes(s string, plainUnit int64) (int64, error) {
	if s == "" {
		return 0, nil
	}
	mult := int64(1)
	num := s
	if r := s[len(s)-1]; (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
		switch strings.ToUpper(s[len(s)-1:]) {
		case "K":
			mult = 1 << 10
		case "M":
			mult = 1 << 20
		case "G":
			mult = 1 << 30
		case "T":
			mult = 1 << 40
		default:
			return 0, errors.New("bad size suffix")
		}
		num = s[:len(s)-1]
		plainUnit = 1
	}
	n, err := strconv.ParseInt(num, 10, 63)
	if err != nil || n < 0 {
		return 0, errors.New("bad size")
	}
	if plainUnit > 0 && n > (1<<63-1)/(mult*plainUnit) {
		return 0, errors.New("size overflow")
	}
	return n * mult * plainUnit, nil
}

// parseTags splits a comma-separated tag list into bounded, sanitized
// tags.
func parseTags(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	tags := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(tags) >= 32 {
			break
		}
		tags = append(tags, sanitizeText(p, 64))
	}
	return tags
}

// parseKVList splits "a=b,c=d" into an ordered key/value list. PVE config
// values containing commas are quoted; quoted values are kept as-is.
func parseKVList(s string) [][2]string {
	var out [][2]string
	for _, part := range splitTopLevel(s) {
		if part == "" {
			continue
		}
		i := strings.Index(part, "=")
		if i <= 0 {
			out = append(out, [2]string{part, ""})
			continue
		}
		out = append(out, [2]string{part[:i], strings.Trim(part[i+1:], `"`)})
	}
	return out
}

// splitTopLevel splits on commas that are not inside double quotes.
func splitTopLevel(s string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	out = append(out, b.String())
	return out
}

// parseDisk decodes "storage:volume[,size=..][,format=..]" into a Disk.
func parseDisk(device, val string) (Disk, error) {
	d := Disk{Device: device}
	kvs := parseKVList(val)
	if len(kvs) == 0 {
		return d, nil
	}
	d.Volume = kvs[0][0]
	if i := strings.LastIndex(d.Volume, ":"); i > 0 {
		d.Storage = d.Volume[:i]
	}
	for _, kv := range kvs[1:] {
		switch kv[0] {
		case "size":
			n, err := parseSizeBytes(kv[1], 1)
			if err != nil {
				return d, fmt.Errorf("bad size for %s: %w", device, err)
			}
			d.Size = n
		case "format":
			d.Format = sanitizeText(kv[1], 32)
		}
	}
	return d, nil
}

// parseMount decodes an LXC mpN value "volume[,mp=/path][,size=..]".
func parseMount(device, val string) (Mount, error) {
	m := Mount{Device: device}
	kvs := parseKVList(val)
	if len(kvs) == 0 {
		return m, nil
	}
	m.Volume = kvs[0][0]
	for _, kv := range kvs[1:] {
		switch kv[0] {
		case "mp":
			m.Mount = sanitizeText(kv[1], 255)
		case "size":
			n, err := parseSizeBytes(kv[1], 1)
			if err != nil {
				return m, fmt.Errorf("bad size for %s: %w", device, err)
			}
			m.Size = n
		}
	}
	return m, nil
}

// parseNIC decodes a netN value. QEMU uses model=MAC or macaddr=MAC;
// LXC uses hwaddr=MAC. Both use tag= for the VLAN ID.
func parseNIC(device, val string) (NIC, error) {
	nic := NIC{Device: device}
	for _, kv := range parseKVList(val) {
		switch kv[0] {
		case "bridge":
			nic.Bridge = sanitizeText(kv[1], 64)
		case "tag", "vlan":
			n, err := parseBoundedInt(kv[1], 0, 4094)
			if err != nil {
				return nic, fmt.Errorf("bad vlan for %s: %w", device, err)
			}
			nic.VLAN = n
		case "macaddr", "hwaddr", "virtio", "e1000", "e1000-82540em", "e1000-82544gc", "e1000-82545em",
			"e1000e", "i82551", "i82557b", "i82559er", "ne2k_isa", "ne2k_pci", "pcnet", "rtl8139", "vmxnet3":
			if macPattern.MatchString(kv[1]) {
				nic.MAC = strings.ToLower(kv[1])
			}
		}
	}
	return nic, nil
}

// parseHostPCI decodes a hostpciN value: the first part is the PCI
// address, the rest are options (mapping, legacy, rom, ...).
func parseHostPCI(device, val string) (HostPCI, error) {
	hp := HostPCI{Device: device, Extras: map[string]string{}}
	kvs := parseKVList(val)
	if len(kvs) == 0 {
		return hp, nil
	}
	hp.PCIAddress = sanitizeText(kvs[0][0], 32)
	for _, kv := range kvs[1:] {
		if kv[0] == "mapping" {
			hp.Mapping = sanitizeText(kv[1], 64)
			continue
		}
		if len(hp.Extras) < 16 {
			hp.Extras[kv[0]] = sanitizeText(kv[1], 64)
		}
	}
	return hp, nil
}

// parseFeatureList decodes an LXC features value "k1=1,k2=0".
func parseFeatureList(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range parseKVList(s) {
		if len(kv) == 2 && kv[0] != "" && len(kv[0]) <= 64 {
			out[kv[0]] = sanitizeText(kv[1], 16)
		}
		if len(out) >= 64 {
			break
		}
	}
	return out
}
