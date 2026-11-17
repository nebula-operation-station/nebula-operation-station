// SPDX-License-Identifier: AGPL-3.0-or-later

package deployprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// filler returns n copies of the byte c.
func filler(c byte, n int) string { return strings.Repeat(string(c), n) }

// numberedParams returns n plain-text parameters named p00, p01, ... that
// all carry value. Names never match the secret-name rule.
func numberedParams(n int, value string) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("p%02d", i)] = value
	}
	return out
}

// numberedRunbooks returns n runbook references rb00, rb01, ... at version.
func numberedRunbooks(n, version int) []RunbookRef {
	out := make([]RunbookRef, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, RunbookRef{Slug: fmt.Sprintf("rb%02d", i), Version: version})
	}
	return out
}

// numberedVaultRefs returns n vault references s00/v00, s01/v01, ...
func numberedVaultRefs(n int) []VaultRef {
	out := make([]VaultRef, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, VaultRef{Slot: fmt.Sprintf("s%02d", i), VaultID: fmt.Sprintf("v%02d", i)})
	}
	return out
}

// allModules selects every bootstrap module once, in execution order: the
// largest accepted bootstrap selection.
func allModules() []BootstrapModule {
	out := make([]BootstrapModule, 0, len(BootstrapModules))
	for _, m := range BootstrapModules {
		out = append(out, BootstrapModule{Name: m})
	}
	return out
}

// domainOfLen returns a DNS name of exactly n characters made of valid
// labels (each at most 63 characters). It needs 192 <= n <= 255.
func domainOfLen(n int) string {
	label := filler('a', 63)
	return strings.Join([]string{label, label, label, filler('a', n-192)}, ".")
}

// TestCountLimitOneOverRejected pins every named limit one step above its
// edge: one entry more than allowed, a name one character too long, a value
// one character too long. Each must fail with *InvalidError.
func TestCountLimitOneOverRejected(t *testing.T) {
	for name, mut := range map[string]func(*Profile){
		"slug 41 characters":          func(p *Profile) { p.Slug = filler('a', MaxSlug+1) },
		"title 101 characters":        func(p *Profile) { p.Title = filler('t', MaxTitle+1) },
		"description 2001 characters": func(p *Profile) { p.Description = filler('d', MaxDescription+1) },
		"image 65 characters":         func(p *Profile) { p.Image = filler('a', MaxImageRef+1) },
		"storage class 65 characters": func(p *Profile) { p.StorageClass = filler('a', MaxStorageClass+1) },
		"bridge 65 characters":        func(p *Profile) { p.Network.Bridge = filler('a', MaxBridge+1) },
		"VLAN 4095":                   func(p *Profile) { p.Network.VLAN = MaxVLAN + 1 },
		"IPAM pool 65 characters":     func(p *Profile) { p.Network.IPAMPool = filler('p', MaxIPAMPool+1) },
		"nameservers 5 of 4": func(p *Profile) {
			p.DNS.Nameservers = []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
		},
		"search domain 254 characters":        func(p *Profile) { p.DNS.SearchDomain = domainOfLen(MaxSearchDomain + 1) },
		"bootstrap 11 of 10":                  func(p *Profile) { p.Bootstrap = append(allModules(), BootstrapModule{Name: "user"}) },
		"module parameters 9 of 8":            func(p *Profile) { p.Bootstrap[0].Params = numberedParams(MaxModuleParams+1, "v") },
		"runbook refs 11 of 10":               func(p *Profile) { p.Runbooks = numberedRunbooks(MaxRunbookRefs+1, 1) },
		"runbook parameters 11 of 10":         func(p *Profile) { p.Runbooks[0].Params = numberedParams(MaxRunbookParams+1, "v") },
		"vault refs 9 of 8":                   func(p *Profile) { p.VaultRefs = numberedVaultRefs(MaxVaultRefs + 1) },
		"parameter name 33 of 32 characters":  func(p *Profile) { p.Bootstrap[0].Params = map[string]string{filler('a', MaxParamName+1): "v"} },
		"parameter value 201 of 200":          func(p *Profile) { p.Bootstrap[0].Params = map[string]string{"username": filler('v', MaxParamValue+1)} },
		"runbook parameter value 201 of 200":  func(p *Profile) { p.Runbooks[0].Params = map[string]string{"port": filler('v', MaxParamValue+1)} },
		"vault slot name 33 of 32 characters": func(p *Profile) { p.VaultRefs[0].Slot = filler('s', MaxParamName+1) },
		"custom vCPU 33 of 32":                func(p *Profile) { p.Size = Size{VCPU: MaxVCPUs + 1, RAMGiB: 4, DiskGiB: 32} },
		"custom vCPU 0 of 1":                  func(p *Profile) { p.Size = Size{VCPU: MinVCPUs - 1, RAMGiB: 4, DiskGiB: 32} },
		"custom RAM 65 of 64":                 func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: MaxRAMGiB + 1, DiskGiB: 32} },
		"custom RAM 0 of 1":                   func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: MinRAMGiB - 1, DiskGiB: 32} },
		"custom disk 1025 of 1024":            func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: 4, DiskGiB: MaxDiskGiB + 1} },
		"custom disk 0 of 1":                  func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: 4, DiskGiB: MinDiskGiB - 1} },
	} {
		t.Run(name, func(t *testing.T) {
			p := profile()
			mut(&p)
			var ie *InvalidError
			if err := Validate(p); !errors.As(err, &ie) {
				t.Fatalf("got %v, want *InvalidError", err)
			}
		})
	}
}

// TestLimitAtEdgeAccepted pins every named Max and Min constant of the
// package: the value at the edge is accepted.
func TestLimitAtEdgeAccepted(t *testing.T) {
	for name, mut := range map[string]func(*Profile){
		"slug 1 character":               func(p *Profile) { p.Slug = "a" },
		"slug 40 characters":             func(p *Profile) { p.Slug = filler('a', MaxSlug) },
		"title 1 character":              func(p *Profile) { p.Title = "t" },
		"title 100 characters":           func(p *Profile) { p.Title = filler('t', MaxTitle) },
		"description empty":              func(p *Profile) { p.Description = "" },
		"description 2000 characters":    func(p *Profile) { p.Description = filler('d', MaxDescription) },
		"image 64 characters":            func(p *Profile) { p.Image = filler('a', MaxImageRef) },
		"storage class 64 characters":    func(p *Profile) { p.StorageClass = filler('a', MaxStorageClass) },
		"bridge 64 characters":           func(p *Profile) { p.Network.Bridge = filler('a', MaxBridge) },
		"VLAN 0 (none)":                  func(p *Profile) { p.Network.VLAN = 0 },
		"VLAN 4094":                      func(p *Profile) { p.Network.VLAN = MaxVLAN },
		"IPAM pool 64 characters":        func(p *Profile) { p.Network.IPAMPool = filler('p', MaxIPAMPool) },
		"nameservers 4":                  func(p *Profile) { p.DNS.Nameservers = []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} },
		"search domain 253 characters":   func(p *Profile) { p.DNS.SearchDomain = domainOfLen(MaxSearchDomain) },
		"bootstrap 10 of 10 in order":    func(p *Profile) { p.Bootstrap = allModules() },
		"module parameters 8 of 8":       func(p *Profile) { p.Bootstrap[0].Params = numberedParams(MaxModuleParams, "v") },
		"runbook refs 10 of 10":          func(p *Profile) { p.Runbooks = numberedRunbooks(MaxRunbookRefs, 1) },
		"runbook parameters 10 of 10":    func(p *Profile) { p.Runbooks[0].Params = numberedParams(MaxRunbookParams, "v") },
		"vault refs 8 of 8":              func(p *Profile) { p.VaultRefs = numberedVaultRefs(MaxVaultRefs) },
		"parameter name 32 characters":   func(p *Profile) { p.Bootstrap[0].Params = map[string]string{filler('a', MaxParamName): "v"} },
		"parameter value 200 characters": func(p *Profile) { p.Bootstrap[0].Params = map[string]string{"username": filler('v', MaxParamValue)} },
		"runbook parameter value 200":    func(p *Profile) { p.Runbooks[0].Params = map[string]string{"port": filler('v', MaxParamValue)} },
		"custom vCPU minimum 1":          func(p *Profile) { p.Size = Size{VCPU: MinVCPUs, RAMGiB: 4, DiskGiB: 32} },
		"custom vCPU maximum 32":         func(p *Profile) { p.Size = Size{VCPU: MaxVCPUs, RAMGiB: 4, DiskGiB: 32} },
		"custom RAM minimum 1 GiB":       func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: MinRAMGiB, DiskGiB: 32} },
		"custom RAM maximum 64 GiB":      func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: MaxRAMGiB, DiskGiB: 32} },
		"custom disk minimum 1 GiB":      func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: 4, DiskGiB: MinDiskGiB} },
		"custom disk maximum 1024 GiB":   func(p *Profile) { p.Size = Size{VCPU: 2, RAMGiB: 4, DiskGiB: MaxDiskGiB} },
		"custom all minima":              func(p *Profile) { p.Size = Size{VCPU: MinVCPUs, RAMGiB: MinRAMGiB, DiskGiB: MinDiskGiB} },
		"custom all maxima":              func(p *Profile) { p.Size = Size{VCPU: MaxVCPUs, RAMGiB: MaxRAMGiB, DiskGiB: MaxDiskGiB} },
	} {
		t.Run(name, func(t *testing.T) {
			p := profile()
			mut(&p)
			if err := Validate(p); err != nil {
				t.Fatalf("at the edge: %v", err)
			}
		})
	}
}

// TestBootstrapLimitPrecedesModuleChecks records which check fires first
// when the bootstrap selection is over its count limit or breaks another
// rule. The count is checked before any module; per module the order is
// unknown name, duplicate, execution order, then parameters. The behaviour
// is pinned, not changed.
func TestBootstrapLimitPrecedesModuleChecks(t *testing.T) {
	ten := allModules()
	withLast := func(name string) []BootstrapModule {
		s := allModules()
		s[len(s)-1] = BootstrapModule{Name: name}
		return s
	}
	for name, tc := range map[string]struct {
		modules []BootstrapModule
		want    string // substring of the error; "" means accepted
	}{
		"ten modules in order are accepted":  {modules: ten},
		"eleven, last unknown: count wins":   {modules: append(allModules(), BootstrapModule{Name: "ansible"}), want: "at most 10 bootstrap modules"},
		"eleven, last duplicate: count wins": {modules: append(allModules(), BootstrapModule{Name: "user"}), want: "at most 10 bootstrap modules"},
		"ten, last unknown":                  {modules: withLast("ansible"), want: `unknown bootstrap module "ansible"`},
		"ten, duplicate before order check":  {modules: append([]BootstrapModule{{Name: "user"}}, allModules()[:9]...), want: `bootstrap module "user" is selected twice`},
		"two, out of order":                  {modules: []BootstrapModule{{Name: "netbird"}, {Name: "user"}}, want: "execution order"},
		"unknown before order: unknown wins": {modules: []BootstrapModule{{Name: "netbird"}, {Name: "ansible"}}, want: `unknown bootstrap module "ansible"`},
	} {
		t.Run(name, func(t *testing.T) {
			p := profile()
			p.Bootstrap = tc.modules
			err := Validate(p)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("got %v, want accepted", err)
				}
				return
			}
			var ie *InvalidError
			if !errors.As(err, &ie) {
				t.Fatalf("got %v, want *InvalidError", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// docLimitProfile returns a profile whose canonical document is exactly
// size bytes. It fills the runbook parameters, 200 characters each, from the
// front and pads one parameter to the exact length. Validate accepts it, so
// the document limit is the only rule it can break.
func docLimitProfile(t testing.TB, size int) Profile {
	t.Helper()
	slots := MaxRunbookRefs * MaxRunbookParams
	build := func(full, rest int) Profile {
		p := profile()
		p.Runbooks = numberedRunbooks(MaxRunbookRefs, 1)
		slot := 0
		for r := range p.Runbooks {
			params := make(map[string]string, MaxRunbookParams)
			for i := 0; i < MaxRunbookParams; i++ {
				v := ""
				switch {
				case slot < full:
					v = filler('x', MaxParamValue)
				case slot == full:
					v = filler('x', rest)
				}
				params[fmt.Sprintf("p%02d", i)] = v
				slot++
			}
			p.Runbooks[r].Params = params
		}
		return p
	}
	for full := 0; full < slots; full++ {
		base, err := json.Marshal(build(full, 0))
		if err != nil {
			t.Fatal(err)
		}
		if len(base) > size {
			t.Fatalf("cannot reach %d bytes: base is already %d", size, len(base))
		}
		if gap := size - len(base); gap <= MaxParamValue {
			return build(full, gap)
		}
	}
	t.Fatalf("cannot reach %d bytes", size)
	return Profile{}
}

// TestDocLimitEdge pins MaxDoc: a canonical document of exactly MaxDoc bytes
// is accepted and stable; one byte more is refused with *InvalidError.
func TestDocLimitEdge(t *testing.T) {
	at := docLimitProfile(t, MaxDoc)
	if err := Validate(at); err != nil {
		t.Fatalf("profile at the document limit: %v", err)
	}
	doc, err := at.Doc()
	if err != nil {
		t.Fatalf("document at MaxDoc: %v", err)
	}
	if len(doc) != MaxDoc {
		t.Fatalf("document length %d, want %d", len(doc), MaxDoc)
	}
	again, err := at.Doc()
	if err != nil || string(again) != string(doc) {
		t.Fatalf("Doc is not stable at the limit: %v", err)
	}

	over := docLimitProfile(t, MaxDoc+1)
	var ie *InvalidError
	if _, err := over.Doc(); !errors.As(err, &ie) {
		t.Fatalf("document at MaxDoc+1: got %v, want *InvalidError", err)
	}
}
