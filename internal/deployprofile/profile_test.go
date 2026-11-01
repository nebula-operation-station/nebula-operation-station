// SPDX-License-Identifier: AGPL-3.0-or-later

package deployprofile

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func profile() Profile {
	return Profile{
		Slug:         "web_m",
		Title:        "Web server, M",
		Description:  "Standard web server on the M preset.",
		Image:        "ubuntu-24.04-amd64",
		Size:         Size{Preset: "M"},
		StorageClass: "local-lvm",
		Network:      Network{Bridge: "vmbr0", IPAMPool: "lab"},
		DNS:          DNS{Nameservers: []string{"10.0.0.2"}, SearchDomain: "lab.example.org"},
		Bootstrap: []BootstrapModule{
			{Name: "user", Params: map[string]string{"username": "svc"}},
			{Name: "netbird", Params: map[string]string{"server": "nb.lab.example.org"}},
		},
		Runbooks: []RunbookRef{
			{Slug: "install_web", Version: 3, Params: map[string]string{"port": "8443"}},
		},
		VaultRefs: []VaultRef{
			{Slot: "netbird_key", VaultID: "netbird-setup-key"},
		},
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(profile()); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Profile){
		"slug empty":     func(p *Profile) { p.Slug = "" },
		"slug upper":     func(p *Profile) { p.Slug = "Web_M" },
		"slug dot":       func(p *Profile) { p.Slug = "web.m" },
		"slug new":       func(p *Profile) { p.Slug = "new" },
		"slug long":      func(p *Profile) { p.Slug = strings.Repeat("a", MaxSlug+1) },
		"title empty":    func(p *Profile) { p.Title = "" },
		"title long":     func(p *Profile) { p.Title = strings.Repeat("t", MaxTitle+1) },
		"title bidi":     func(p *Profile) { p.Title = "a\u202eb" },
		"title newline":  func(p *Profile) { p.Title = "a\nb" },
		"desc long":      func(p *Profile) { p.Description = strings.Repeat("d", MaxDescription+1) },
		"desc control":   func(p *Profile) { p.Description = "a\x1b[2J" },
		"image empty":    func(p *Profile) { p.Image = "" },
		"image upper":    func(p *Profile) { p.Image = "Ubuntu-24.04" },
		"image long":     func(p *Profile) { p.Image = strings.Repeat("a", MaxImageRef+1) },
		"storage empty":  func(p *Profile) { p.StorageClass = "" },
		"storage bad":    func(p *Profile) { p.StorageClass = "local lvm" },
		"bridge empty":   func(p *Profile) { p.Network.Bridge = "" },
		"bridge bad":     func(p *Profile) { p.Network.Bridge = "vm br0" },
		"vlan negative":  func(p *Profile) { p.Network.VLAN = -1 },
		"vlan high":      func(p *Profile) { p.Network.VLAN = MaxVLAN + 1 },
		"both pool dhcp": func(p *Profile) { p.Network.DHCP = true },
		"neither pool":   func(p *Profile) { p.Network.IPAMPool = "" },
		"pool long":      func(p *Profile) { p.Network.IPAMPool = strings.Repeat("p", MaxIPAMPool+1) },
		"pool control":   func(p *Profile) { p.Network.IPAMPool = "a\x00b" },
		"ns not ip":      func(p *Profile) { p.DNS.Nameservers = []string{"resolver1"} },
		"ns too many": func(p *Profile) {
			p.DNS.Nameservers = []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
		},
		"ns duplicate": func(p *Profile) { p.DNS.Nameservers = []string{"10.0.0.2", "10.0.0.2"} },
		"domain long": func(p *Profile) {
			p.DNS.SearchDomain = strings.Repeat(strings.Repeat("a", 63)+".", 5) + strings.Repeat("a", 63)
		},
		"domain bad":        func(p *Profile) { p.DNS.SearchDomain = "-bad." },
		"module unknown":    func(p *Profile) { p.Bootstrap[0].Name = "ansible" },
		"module dup":        func(p *Profile) { p.Bootstrap[1].Name = "user" },
		"module order":      func(p *Profile) { p.Bootstrap[0], p.Bootstrap[1] = p.Bootstrap[1], p.Bootstrap[0] },
		"module param":      func(p *Profile) { p.Bootstrap[0].Params["User"] = "svc" },
		"module param val":  func(p *Profile) { p.Bootstrap[0].Params["username"] = strings.Repeat("x", MaxParamValue+1) },
		"module param ctl":  func(p *Profile) { p.Bootstrap[0].Params["username"] = "a\x00b" },
		"module param slot": func(p *Profile) { p.Bootstrap[0].Params["netbird_key"] = "x" },
		"rb slug":           func(p *Profile) { p.Runbooks[0].Slug = "Install Web" },
		"rb version 0":      func(p *Profile) { p.Runbooks[0].Version = 0 },
		"rb dup":            func(p *Profile) { p.Runbooks = append(p.Runbooks, p.Runbooks[0]) },
		"rb param":          func(p *Profile) { p.Runbooks[0].Params["Port"] = "8443" },
		"rb param slot":     func(p *Profile) { p.Runbooks[0].Params["netbird_key"] = "x" },
		"slot upper":        func(p *Profile) { p.VaultRefs[0].Slot = "NetbirdKey" },
		"slot dup":          func(p *Profile) { p.VaultRefs = append(p.VaultRefs, p.VaultRefs[0]) },
		"vault id upper":    func(p *Profile) { p.VaultRefs[0].VaultID = "NetbirdSetupKey" },
		"vault id dash":     func(p *Profile) { p.VaultRefs[0].VaultID = "-netbird" },
		"vault id long":     func(p *Profile) { p.VaultRefs[0].VaultID = strings.Repeat("a", 65) },
		"vault id empty":    func(p *Profile) { p.VaultRefs[0].VaultID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			p := profile()
			p.Bootstrap = append([]BootstrapModule(nil), p.Bootstrap...)
			p.Runbooks = append([]RunbookRef(nil), p.Runbooks...)
			p.VaultRefs = append([]VaultRef(nil), p.VaultRefs...)
			mut(&p)
			var ie *InvalidError
			if err := Validate(p); !errors.As(err, &ie) {
				t.Fatalf("got %v, want *InvalidError", err)
			}
		})
	}
}

func TestSecretValuesRejected(t *testing.T) {
	for _, name := range []string{
		"password", "passwd", "passphrase", "token", "secret", "credential",
		"api_key", "apikey", "setup_key", "private_key", "access_key",
		"auth_key", "passkey", "db_password", "NETBIRD_TOKEN",
	} {
		p := profile()
		p.Bootstrap[0].Params = map[string]string{name: "hunter2"}
		err := Validate(p)
		var ie *InvalidError
		if !errors.As(err, &ie) {
			t.Fatalf("param %q: got %v, want *InvalidError", name, err)
		}
		if !strings.Contains(err.Error(), "vault") {
			t.Errorf("param %q: error %q does not point at vault references", name, err)
		}
	}
	// The same rule applies to runbook parameters.
	p := profile()
	p.Runbooks[0].Params = map[string]string{"token": "abc"}
	if err := Validate(p); err == nil {
		t.Fatal("runbook param token: want rejection")
	}
}

func TestPresets(t *testing.T) {
	for name, want := range map[string]Size{
		"S":  {Preset: "S", VCPU: 1, RAMGiB: 1, DiskGiB: 16},
		"M":  {Preset: "M", VCPU: 2, RAMGiB: 4, DiskGiB: 32},
		"L":  {Preset: "L", VCPU: 4, RAMGiB: 8, DiskGiB: 64},
		"XL": {Preset: "XL", VCPU: 8, RAMGiB: 16, DiskGiB: 128},
	} {
		got, err := Presets[name].Resolve()
		if err != nil || got != want {
			t.Errorf("preset %s: %+v %v", name, got, err)
		}
		p := profile()
		p.Size = Presets[name]
		if err := Validate(p); err != nil {
			t.Errorf("preset %s: %v", name, err)
		}
	}
}

func TestPresetMismatchRejected(t *testing.T) {
	p := profile()
	p.Size = Size{Preset: "S", VCPU: 4}
	var ie *InvalidError
	if err := Validate(p); !errors.As(err, &ie) {
		t.Fatalf("got %v, want *InvalidError", err)
	}
	p.Size = Size{Preset: "XL", RAMGiB: 8}
	if err := Validate(p); err == nil {
		t.Fatal("preset with a differing RAM value must be rejected")
	}
}

func TestCustomSizeBounds(t *testing.T) {
	for name, size := range map[string]Size{
		"min":    {VCPU: MinVCPUs, RAMGiB: MinRAMGiB, DiskGiB: MinDiskGiB},
		"max":    {VCPU: MaxVCPUs, RAMGiB: MaxRAMGiB, DiskGiB: MaxDiskGiB},
		"middle": {VCPU: 3, RAMGiB: 6, DiskGiB: 48},
	} {
		p := profile()
		p.Size = size
		if err := Validate(p); err != nil {
			t.Errorf("custom %s: %v", name, err)
		}
	}
	for name, mut := range map[string]func(*Size){
		"vcpu 0":   func(s *Size) { s.VCPU = 0 },
		"vcpu max": func(s *Size) { s.VCPU = MaxVCPUs + 1 },
		"ram 0":    func(s *Size) { s.RAMGiB = 0 },
		"ram max":  func(s *Size) { s.RAMGiB = MaxRAMGiB + 1 },
		"disk 0":   func(s *Size) { s.DiskGiB = 0 },
		"disk max": func(s *Size) { s.DiskGiB = MaxDiskGiB + 1 },
	} {
		p := profile()
		p.Size = Size{VCPU: 2, RAMGiB: 4, DiskGiB: 32}
		mut(&p.Size)
		var ie *InvalidError
		if err := Validate(p); !errors.As(err, &ie) {
			t.Errorf("custom %s: got %v, want *InvalidError", name, err)
		}
	}
}

func TestDocIsDeterministic(t *testing.T) {
	a, err := profile().Doc()
	if err != nil {
		t.Fatal(err)
	}
	b, err := profile().Doc()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("canonical document is not deterministic")
	}
	p := profile()
	p.Bootstrap[0].Params = map[string]string{"zeta": "1", "alpha": "2"}
	c, err := p.Doc()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(c), `"alpha":"2","zeta":"1"`) {
		t.Errorf("map keys are not sorted in the document: %s", c)
	}
}

func TestDocLimit(t *testing.T) {
	// Every field at its individual maximum: ten modules with eight
	// max-length parameters each push the canonical document past MaxDoc.
	p := profile()
	modules := make([]BootstrapModule, 0, MaxBootstrap)
	for _, name := range BootstrapModules {
		params := make(map[string]string, MaxModuleParams)
		for i := 0; i < MaxModuleParams; i++ {
			params[fmt.Sprintf("p%02d", i)] = strings.Repeat("x", MaxParamValue)
		}
		modules = append(modules, BootstrapModule{Name: name, Params: params})
	}
	p.Bootstrap = modules
	if _, err := p.Doc(); err == nil {
		t.Fatal("document over the limit must be rejected")
	}
}
