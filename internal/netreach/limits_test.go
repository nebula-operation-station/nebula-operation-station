// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// TestCheckLimitsAtLimitAndOver checks every snapshot count limit at the
// limit (accepted) and one over (ErrLimitReached, never a panic).
func TestCheckLimitsAtLimitAndOver(t *testing.T) {
	tests := []struct {
		name string
		max  int
		fill func(s *Snapshot, n int)
	}{
		{"security rules", MaxSecurityRules, func(s *Snapshot, n int) {
			s.SecurityRules = make([]SecurityRule, n)
			for i := range s.SecurityRules {
				s.SecurityRules[i].Name = fmt.Sprint("r", i)
			}
		}},
		{"NAT rules", MaxNATRules, func(s *Snapshot, n int) {
			s.NATRules = make([]NATRule, n)
			for i := range s.NATRules {
				s.NATRules[i].Name = fmt.Sprint("n", i)
			}
		}},
		{"address objects", MaxAddressObjects, func(s *Snapshot, n int) {
			s.Addresses = make([]AddressObject, n)
			for i := range s.Addresses {
				s.Addresses[i].Name = fmt.Sprint("a", i)
			}
		}},
		{"service objects", MaxServiceObjects, func(s *Snapshot, n int) {
			s.Services = make([]ServiceObject, n)
			for i := range s.Services {
				s.Services[i].Name = fmt.Sprint("s", i)
			}
		}},
		{"address groups", MaxAddressGroups, func(s *Snapshot, n int) {
			s.AddressGroups = make([]Group, n)
			for i := range s.AddressGroups {
				s.AddressGroups[i].Name = fmt.Sprint("g", i)
			}
		}},
		{"service groups", MaxServiceGroups, func(s *Snapshot, n int) {
			s.ServiceGroups = make([]Group, n)
			for i := range s.ServiceGroups {
				s.ServiceGroups[i].Name = fmt.Sprint("g", i)
			}
		}},
		{"zones", MaxZones, func(s *Snapshot, n int) {
			s.Zones = make([]Zone, n)
			for i := range s.Zones {
				s.Zones[i].Name = fmt.Sprint("z", i)
			}
		}},
		{"interfaces", MaxInterfaces, func(s *Snapshot, n int) {
			s.Interfaces = make([]Interface, n)
			for i := range s.Interfaces {
				s.Interfaces[i].Name = fmt.Sprint("ethernet1/", i)
			}
		}},
		{"subnets", MaxSubnets, func(s *Snapshot, n int) {
			s.Subnets = make([]Subnet, n)
			for i := range s.Subnets {
				s.Subnets[i] = Subnet{ID: fmt.Sprint("sn", i), Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)}
			}
		}},
		{"routes", MaxRoutes, func(s *Snapshot, n int) {
			s.Routes = make([]Route, n)
			for i := range s.Routes {
				s.Routes[i] = Route{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0}), 24), Zone: "wan"}
			}
		}},
		{"prefixes per interface", MaxPrefixesPerInterface, func(s *Snapshot, n int) {
			in := Interface{Name: "ethernet1/9"}
			for i := range n {
				in.Prefixes = append(in.Prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{12, 0, byte(i), 0}), 24))
			}
			s.Interfaces = []Interface{in}
		}},
		{"group members", MaxGroupMembers, func(s *Snapshot, n int) {
			s.AddressGroups = []Group{{Name: "g", Static: make([]string, n)}}
			for i := range n {
				s.AddressGroups[0].Static[i] = "x"
			}
		}},
		{"rule members", MaxRuleMembers, func(s *Snapshot, n int) {
			r := SecurityRule{Name: "r", Source: Collected(make([]string, n))}
			for i := range n {
				r.Source.Value[i] = "x"
			}
			s.SecurityRules = []SecurityRule{r}
		}},
		{"markers", MaxMarkers, func(s *Snapshot, n int) {
			r := NATRule{Name: "n", Dropped: make([]string, n)}
			for i := range n {
				r.Dropped[i] = "<dropped:x>"
			}
			s.NATRules = []NATRule{r}
		}},
		{"name bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.Zones = []Zone{{Name: strings.Repeat("z", n)}}
		}},
		{"value bytes", MaxValueBytes, func(s *Snapshot, n int) {
			s.Addresses = []AddressObject{{Name: "a", Type: AddressFQDN, Value: strings.Repeat("v", n)}}
		}},
		{"address type bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.Addresses = []AddressObject{{Name: "a", Type: AddressType(strings.Repeat("t", n))}}
		}},
		{"rule type bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.SecurityRules = []SecurityRule{{Name: "r", Type: Collected(RuleType(strings.Repeat("t", n)))}}
		}},
		{"rule action bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.SecurityRules = []SecurityRule{{Name: "r", Action: Action(strings.Repeat("a", n))}}
		}},
		{"default intrazone action bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.DefaultRules = Collected(DefaultRules{Intrazone: Action(strings.Repeat("a", n))})
		}},
		{"default interzone action bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.DefaultRules = Collected(DefaultRules{Interzone: Action(strings.Repeat("a", n))})
		}},
		{"default rules outside allowlist", MaxMarkers, func(s *Snapshot, n int) {
			s.DefaultRules = Collected(DefaultRules{OutsideAllowlist: make([]string, n)})
			for i := range n {
				s.DefaultRules.Value.OutsideAllowlist[i] = "f"
			}
		}},
		{"dataset id bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.Inputs = map[InputKind]Input{InputZones: {State: InputFresh, DatasetID: strings.Repeat("d", n)}}
		}},
		{"redacted digest bytes", MaxNameBytes, func(s *Snapshot, n int) {
			s.Inputs = map[InputKind]Input{InputZones: {State: InputFresh, RedactedDigest: strings.Repeat("d", n)}}
		}},
		{"inputs", MaxInputs, func(s *Snapshot, n int) {
			s.Inputs = map[InputKind]Input{}
			for i := range n {
				s.Inputs[InputKind(fmt.Sprint("k", i))] = Input{}
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Snapshot{}
			tc.fill(s, tc.max)
			if err := CheckLimits(s); err != nil {
				t.Fatalf("at limit %d: %v", tc.max, err)
			}
			s = &Snapshot{}
			tc.fill(s, tc.max+1)
			err := CheckLimits(s)
			if !errors.Is(err, ErrLimitReached) {
				t.Fatalf("over limit: err = %v, want ErrLimitReached", err)
			}
			if _, err := NewIndex(s); !errors.Is(err, ErrLimitReached) {
				t.Fatalf("NewIndex over limit: err = %v", err)
			}
		})
	}
}

func TestCheckLimitsRejectsMalformedText(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Snapshot)
	}{
		{"invalid utf-8 rule name", func(s *Snapshot) { s.SecurityRules[0].Name = "r\xff" }},
		{"control char in member", func(s *Snapshot) { s.SecurityRules[0].Source = list("a\nb") }},
		{"empty rule name", func(s *Snapshot) { s.SecurityRules[0].Name = "" }},
		{"empty zone name", func(s *Snapshot) { s.Zones[0].Name = "" }},
		{"empty interface name", func(s *Snapshot) { s.Interfaces[0].Name = "" }},
		{"invalid utf-8 address value", func(s *Snapshot) { s.Addresses[0].Value = "\xc3" }},
		{"invalid utf-8 marker", func(s *Snapshot) { s.Addresses[0].Dropped = []string{"<dropped:\xff>"} }},
		{"del in NAT service", func(s *Snapshot) { s.NATRules[0].Service = Collected("svc\x7f") }},
		{"invalid subnet prefix", func(s *Snapshot) { s.Subnets[0].Prefix = netip.Prefix{} }},
		{"subnet host bits", func(s *Snapshot) { s.Subnets[0].Prefix = netip.MustParsePrefix("10.0.1.1/24") }},
		{"mapped interface prefix", func(s *Snapshot) {
			s.Interfaces[0].Prefixes = []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/120")}
		}},
		{"invalid route prefix", func(s *Snapshot) { s.Routes[0].Prefix = netip.Prefix{} }},
		{"invalid utf-8 address type", func(s *Snapshot) { s.Addresses[4].Type = "fq\xffdn" }},
		{"control char in address type", func(s *Snapshot) { s.Addresses[4].Type = "fqdn\x1b[2J" }},
		{"invalid utf-8 rule type", func(s *Snapshot) { s.SecurityRules[0].Type = Collected(RuleType("uni\xff")) }},
		{"control char in rule action", func(s *Snapshot) { s.SecurityRules[0].Action = "allow\n" }},
		{"invalid utf-8 default action", func(s *Snapshot) { s.DefaultRules.Value.Interzone = "deny\xc3" }},
		{"control char in default rules outside allowlist", func(s *Snapshot) {
			s.DefaultRules.Value.OutsideAllowlist = []string{"a\tb"}
		}},
		{"invalid utf-8 dataset id", func(s *Snapshot) { s.Inputs[InputZones] = Input{State: InputFresh, DatasetID: "ds\xff"} }},
		{"control char in digest", func(s *Snapshot) { s.Inputs[InputRoutes] = Input{State: InputFresh, RedactedDigest: "ab\x00"} }},
		{"invalid utf-8 input kind", func(s *Snapshot) { s.Inputs[InputKind("z\xff")] = Input{} }},
		{"c1 control in interface name", func(s *Snapshot) { s.Interfaces[0].Name = "eth\u0085x" }},
		{"c1 csi in zone name", func(s *Snapshot) { s.Zones[0].Name = "wan\u009b31m" }},
		// Bidi formatting characters, built from code points so the source
		// carries none: RLO, LRI/PDI, RLM, ALM, LRE.
		{"bidi override in rule name", func(s *Snapshot) { s.SecurityRules[0].Name = "allow" + string(rune(0x202e)) + "gnp.exe" }},
		{"bidi isolate in interface name", func(s *Snapshot) {
			s.Interfaces[0].Name = "eth" + string(rune(0x2066)) + "x" + string(rune(0x2069))
		}},
		{"bidi mark in address name", func(s *Snapshot) { s.Addresses[0].Name = "a" + string(rune(0x200f)) + "b" }},
		{"arabic letter mark in subnet id", func(s *Snapshot) { s.Subnets[0].ID = "lan" + string(rune(0x061c)) }},
		{"bidi embedding in route zone", func(s *Snapshot) { s.Routes[0].Zone = string(rune(0x202a)) + "wan" }},
		{"negative vsys", func(s *Snapshot) { s.Vsys = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(s)
			if err := CheckLimits(s); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("err = %v, want ErrInvalidSnapshot", err)
			}
			if _, err := NewPlacer(s); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("NewPlacer err = %v", err)
			}
		})
	}
	if err := CheckLimits(nil); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("nil snapshot: %v", err)
	}
}

// TestZeroSnapshotIsFailSafe: an empty snapshot is never complete and
// places nothing.
func TestZeroSnapshotIsFailSafe(t *testing.T) {
	x, err := NewIndex(&Snapshot{})
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	c := x.PathCompleteness("a", "b")
	if c.Complete || len(c.Reasons) < len(RequiredInputs) {
		t.Fatalf("completeness %+v", c)
	}
	for _, a := range []string{"10.0.0.1", "8.8.8.8", "2a00::1"} {
		if p := x.Placer().Place(netip.MustParseAddr(a)); !p.Unknown || p.Zone != "" {
			t.Errorf("%s: %+v", a, p)
		}
	}
	if d := x.DefaultRule(false); d.Evaluable() {
		t.Error("default rule evaluable without data")
	}
}
