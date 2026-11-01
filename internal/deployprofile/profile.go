// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deployprofile implements the versioned, secret-free deploy
// profiles of ADR 0008 section 1 (PV-04): the server model, the S/M/L/XL
// size presets with bounded custom sizes, the ordered bootstrap selection,
// the ordered runbook references and the executor vault references.
//
// A profile never contains a secret value: secret material is referenced
// through VaultRefs by vault entry ID, and parameter names that would hold
// secret material are rejected by Validate.
package deployprofile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
)

// Named limits of the profile model.
const (
	MaxSlug          = 40
	MaxTitle         = 100
	MaxDescription   = 2000
	MaxImageRef      = 64
	MaxStorageClass  = 64
	MaxBridge        = 64
	MaxVLAN          = 4094
	MaxIPAMPool      = 64
	MaxNameservers   = 4
	MaxSearchDomain  = 253
	MaxBootstrap     = 10
	MaxModuleParams  = 8
	MaxRunbookRefs   = 10
	MaxRunbookParams = 10
	MaxVaultRefs     = 8
	MaxParamName     = 32
	MaxParamValue    = 200
	MaxDoc           = 16000

	MinVCPUs   = 1
	MaxVCPUs   = 32
	MinRAMGiB  = 1
	MaxRAMGiB  = 64
	MinDiskGiB = 1
	MaxDiskGiB = 1024
)

var (
	slugRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,39}$`)
	imageRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	storageRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	bridgeRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	domainRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	paramNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	vaultIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	secretNameRe = regexp.MustCompile(`(?i)(password|passwd|passphrase|token|secret|credential|api[_-]?key|setup[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?key|passkey)`)
)

// Size is the guest size: one of the named presets or a custom value
// bounded by the named limits.
type Size struct {
	Preset  string `json:"preset"`
	VCPU    int    `json:"vcpu"`
	RAMGiB  int    `json:"ram_gib"`
	DiskGiB int    `json:"disk_gib"`
}

// Presets are the fixed size presets of ADR 0008 section 1:
// S = 1 vCPU / 1 GiB / 16 GiB, M = 2 / 4 / 32, L = 4 / 8 / 64,
// XL = 8 / 16 / 128.
var Presets = map[string]Size{
	"S":  {Preset: "S", VCPU: 1, RAMGiB: 1, DiskGiB: 16},
	"M":  {Preset: "M", VCPU: 2, RAMGiB: 4, DiskGiB: 32},
	"L":  {Preset: "L", VCPU: 4, RAMGiB: 8, DiskGiB: 64},
	"XL": {Preset: "XL", VCPU: 8, RAMGiB: 16, DiskGiB: 128},
}

// Resolve returns the size with the preset values filled in. A preset
// entry must not carry values that differ from the preset.
func (s Size) Resolve() (Size, error) {
	if s.Preset == "" {
		return s, nil
	}
	p, ok := Presets[s.Preset]
	if !ok {
		return s, fmt.Errorf("unknown size preset %q", s.Preset)
	}
	if (s.VCPU != 0 && s.VCPU != p.VCPU) || (s.RAMGiB != 0 && s.RAMGiB != p.RAMGiB) || (s.DiskGiB != 0 && s.DiskGiB != p.DiskGiB) {
		return s, fmt.Errorf("size values do not match preset %s", s.Preset)
	}
	return p, nil
}

// Network is the guest network: a bridge plus either an IPAM pool or DHCP.
type Network struct {
	Bridge   string `json:"bridge"`
	VLAN     int    `json:"vlan"`
	IPAMPool string `json:"ipam_pool,omitempty"`
	DHCP     bool   `json:"dhcp"`
}

// DNS is the guest DNS configuration.
type DNS struct {
	Nameservers  []string `json:"nameservers"`
	SearchDomain string   `json:"search_domain,omitempty"`
}

// BootstrapModule is one selected bootstrap module with its plain-text
// parameters. Secret material never goes here; it is referenced through
// VaultRefs by slot name.
type BootstrapModule struct {
	Name   string            `json:"name"`
	Params map[string]string `json:"params,omitempty"`
}

// RunbookRef references one exact runbook version and its plain-text
// parameters.
type RunbookRef struct {
	Slug    string            `json:"slug"`
	Version int               `json:"version"`
	Params  map[string]string `json:"params,omitempty"`
}

// VaultRef references one executor vault entry by ID. It is the only place
// a profile may point at secret material; the value itself never appears
// in a profile.
type VaultRef struct {
	Slot    string `json:"slot"`
	VaultID string `json:"vault_id"`
}

// Profile is one versioned, secret-free deploy profile (ADR 0008 section
// 1). It has no field that can hold a secret value.
type Profile struct {
	Slug         string            `json:"slug"`
	Title        string            `json:"title"`
	Description  string            `json:"description,omitempty"`
	Image        string            `json:"image"`
	Size         Size              `json:"size"`
	StorageClass string            `json:"storage_class"`
	Network      Network           `json:"network"`
	DNS          DNS               `json:"dns"`
	Bootstrap    []BootstrapModule `json:"bootstrap"`
	Runbooks     []RunbookRef      `json:"runbooks"`
	VaultRefs    []VaultRef        `json:"vault_refs"`
}

// BootstrapModules are the bootstrap modules a profile may select, in the
// documented execution order of ADR 0008 section 5.
var BootstrapModules = []string{
	"user", "ssh-hardening", "timezone", "packages", "qemu-guest-agent",
	"docker", "netbird", "firewall", "telegraf", "pkg-report",
}

// InvalidError reports a profile that violates the model.
type InvalidError struct{ Err error }

// Error implements error.
func (e *InvalidError) Error() string { return e.Err.Error() }

// Unwrap implements error.
func (e *InvalidError) Unwrap() error { return e.Err }

// Validate checks the profile against every field and limit of ADR 0008
// section 1. It returns an *InvalidError on the first violation.
func Validate(p Profile) error {
	if err := validate(p); err != nil {
		return &InvalidError{Err: err}
	}
	return nil
}

func validate(p Profile) error {
	if !slugRe.MatchString(p.Slug) {
		return fmt.Errorf("slug is 1 to %d lowercase letters, digits or _, starting with a letter or digit", MaxSlug)
	}
	if p.Slug == "new" {
		return fmt.Errorf("slug %q is reserved", p.Slug)
	}
	if !prelude.Clean(p.Title, false) || len(p.Title) < 1 || len(p.Title) > MaxTitle {
		return fmt.Errorf("title is plain text of 1 to %d characters", MaxTitle)
	}
	if !prelude.Clean(p.Description, true) || len(p.Description) > MaxDescription {
		return fmt.Errorf("description is plain text of at most %d characters", MaxDescription)
	}
	if !imageRe.MatchString(p.Image) {
		return fmt.Errorf("image is an image catalog reference of 1 to %d characters", MaxImageRef)
	}
	size, err := p.Size.Resolve()
	if err != nil {
		return err
	}
	if size.Preset == "" {
		if size.VCPU < MinVCPUs || size.VCPU > MaxVCPUs {
			return fmt.Errorf("custom vCPU count is %d to %d", MinVCPUs, MaxVCPUs)
		}
		if size.RAMGiB < MinRAMGiB || size.RAMGiB > MaxRAMGiB {
			return fmt.Errorf("custom RAM is %d to %d GiB", MinRAMGiB, MaxRAMGiB)
		}
		if size.DiskGiB < MinDiskGiB || size.DiskGiB > MaxDiskGiB {
			return fmt.Errorf("custom disk is %d to %d GiB", MinDiskGiB, MaxDiskGiB)
		}
	}
	if !storageRe.MatchString(p.StorageClass) {
		return fmt.Errorf("storage class is a PVE storage name of 1 to %d characters", MaxStorageClass)
	}
	if !bridgeRe.MatchString(p.Network.Bridge) {
		return fmt.Errorf("bridge is a PVE bridge name of 1 to %d characters", MaxBridge)
	}
	if p.Network.VLAN < 0 || p.Network.VLAN > MaxVLAN {
		return fmt.Errorf("VLAN is 0 (none) to %d", MaxVLAN)
	}
	if p.Network.DHCP != (p.Network.IPAMPool == "") {
		return fmt.Errorf("network uses exactly one of an IPAM pool or DHCP")
	}
	if p.Network.IPAMPool != "" && (!prelude.Clean(p.Network.IPAMPool, false) || len(p.Network.IPAMPool) > MaxIPAMPool) {
		return fmt.Errorf("IPAM pool is plain text of 1 to %d characters", MaxIPAMPool)
	}
	if len(p.DNS.Nameservers) > MaxNameservers {
		return fmt.Errorf("at most %d nameservers", MaxNameservers)
	}
	seenNS := map[string]bool{}
	for _, ns := range p.DNS.Nameservers {
		// Canonical form only: no IPv6 zone (free text that would reach
		// cloud-init), no IPv4-mapped IPv6, no case variants, so the
		// duplicate check below compares like with like.
		if a, err := netip.ParseAddr(ns); err != nil || a.Zone() != "" || a.Is4In6() || a.String() != ns {
			return fmt.Errorf("nameservers are canonical IP literals without zone")
		}
		if seenNS[ns] {
			return fmt.Errorf("nameserver %q is listed twice", ns)
		}
		seenNS[ns] = true
	}
	if p.DNS.SearchDomain != "" && (!domainRe.MatchString(p.DNS.SearchDomain) || len(p.DNS.SearchDomain) > MaxSearchDomain) {
		return fmt.Errorf("search domain is a DNS domain of at most %d characters", MaxSearchDomain)
	}
	if err := validateBootstrap(p); err != nil {
		return err
	}
	if err := validateRunbooks(p); err != nil {
		return err
	}
	return validateVaultRefs(p)
}

func validateBootstrap(p Profile) error {
	if len(p.Bootstrap) > MaxBootstrap {
		return fmt.Errorf("at most %d bootstrap modules", MaxBootstrap)
	}
	slots := map[string]bool{}
	for _, v := range p.VaultRefs {
		slots[v.Slot] = true
	}
	known := map[string]int{}
	for i, m := range BootstrapModules {
		known[m] = i
	}
	last := -1
	seen := map[string]bool{}
	for _, m := range p.Bootstrap {
		idx, ok := known[m.Name]
		if !ok {
			return fmt.Errorf("unknown bootstrap module %q", m.Name)
		}
		if seen[m.Name] {
			return fmt.Errorf("bootstrap module %q is selected twice", m.Name)
		}
		if idx <= last {
			return fmt.Errorf("bootstrap module %q: the selection follows the documented execution order", m.Name)
		}
		last = idx
		seen[m.Name] = true
		if err := validateParams(m.Params, MaxModuleParams, slots); err != nil {
			return fmt.Errorf("module %s: %w", m.Name, err)
		}
	}
	return nil
}

func validateRunbooks(p Profile) error {
	if len(p.Runbooks) > MaxRunbookRefs {
		return fmt.Errorf("at most %d runbook references", MaxRunbookRefs)
	}
	slots := map[string]bool{}
	for _, v := range p.VaultRefs {
		slots[v.Slot] = true
	}
	seen := map[string]bool{}
	for _, r := range p.Runbooks {
		if !slugRe.MatchString(r.Slug) {
			return fmt.Errorf("runbook %q: slug is 1 to %d lowercase letters, digits or _, starting with a letter or digit", r.Slug, MaxSlug)
		}
		if r.Version < 1 {
			return fmt.Errorf("runbook %s: references an exact version of at least 1", r.Slug)
		}
		key := fmt.Sprintf("%s@%d", r.Slug, r.Version)
		if seen[key] {
			return fmt.Errorf("runbook %s is referenced twice", key)
		}
		seen[key] = true
		if err := validateParams(r.Params, MaxRunbookParams, slots); err != nil {
			return fmt.Errorf("runbook %s: %w", r.Slug, err)
		}
	}
	return nil
}

func validateVaultRefs(p Profile) error {
	if len(p.VaultRefs) > MaxVaultRefs {
		return fmt.Errorf("at most %d vault references", MaxVaultRefs)
	}
	seen := map[string]bool{}
	for _, v := range p.VaultRefs {
		if !paramNameRe.MatchString(v.Slot) {
			return fmt.Errorf("vault slot %q: slots are 1 to %d lowercase letters, digits or _, starting with a letter", v.Slot, MaxParamName)
		}
		if seen[v.Slot] {
			return fmt.Errorf("vault slot %q is referenced twice", v.Slot)
		}
		seen[v.Slot] = true
		if !vaultIDRe.MatchString(v.VaultID) {
			return fmt.Errorf("vault entry %q: IDs are 1 to 64 characters of a-z, 0-9, ., _ or -, starting with a letter or digit", v.VaultID)
		}
	}
	return nil
}

// validateParams checks the plain-text parameters of one module or runbook
// reference. Secret values never go into a profile: a parameter name that
// would hold secret material, or a name that is a vault slot, is rejected.
func validateParams(params map[string]string, max int, slots map[string]bool) error {
	if len(params) > max {
		return fmt.Errorf("at most %d parameters", max)
	}
	for name, value := range params {
		if secretNameRe.MatchString(name) {
			return fmt.Errorf("parameter %q: secret values never go into a profile; reference a vault entry", name)
		}
		if !paramNameRe.MatchString(name) {
			return fmt.Errorf("parameter %q: names are 1 to %d lowercase letters, digits or _, starting with a letter", name, MaxParamName)
		}
		if slots[name] {
			return fmt.Errorf("parameter %q: this name is a vault slot; the value comes from the vault", name)
		}
		if !prelude.Clean(value, false) || len(value) > MaxParamValue {
			return fmt.Errorf("parameter %q: values are plain text of at most %d characters", name, MaxParamValue)
		}
	}
	return nil
}

// Doc returns the canonical JSON document of the profile: struct fields in
// declaration order and map keys sorted, so the document and its digest
// are deterministic.
func (p Profile) Doc() ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxDoc {
		return nil, &InvalidError{Err: fmt.Errorf("profile document is at most %d bytes", MaxDoc)}
	}
	return b, nil
}
