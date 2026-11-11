// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import "net/netip"

// fixtures for the netreach tests: a small lab with a WAN, LAN, DMZ and
// management zone on one firewall, an IPAM subnet that no firewall
// interface owns, and every Q11 field collected (the "after NS-04" case).
// Fail-safe tests start from it and remove or change one thing.

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func list(s ...string) Field[[]string] { return Collected(s) }

func allFresh() map[InputKind]Input {
	m := map[InputKind]Input{}
	for _, k := range RequiredInputs {
		m[k] = Input{State: InputFresh, DatasetID: "ds-" + string(k)}
	}
	return m
}

// evaluableRule returns an enabled universal rule with every field
// collected.
func evaluableRule(name string, action Action, from, to, src, dst, svc []string) SecurityRule {
	return SecurityRule{
		Name:              name,
		Disabled:          Collected(false),
		Action:            action,
		From:              Collected(from),
		To:                Collected(to),
		Source:            Collected(src),
		Destination:       Collected(dst),
		NegateSource:      Collected(false),
		NegateDestination: Collected(false),
		Type:              Collected(RuleTypeUniversal),
		SourceHIP:         list("any"),
		DestinationHIP:    list("any"),
		SourceUser:        list("any"),
		Application:       list("any"),
		Service:           Collected(svc),
		Category:          list("any"),
		Schedule:          Collected(""),
	}
}

func evaluableNAT(name string) NATRule {
	return NATRule{
		Name:        name,
		Disabled:    Collected(false),
		From:        list("wan"),
		To:          Collected("wan"),
		Source:      list("any"),
		Destination: list("wan-ip"),
		Service:     Collected("svc-https"),
		DestinationTranslation: Collected(&DestinationTranslation{
			Address: "web-server",
			Port:    8443,
		}),
	}
}

func labSnapshot() *Snapshot {
	return &Snapshot{
		Inputs: allFresh(),
		Vsys:   1,
		Zones:  []Zone{{Name: "wan"}, {Name: "lan"}, {Name: "dmz"}, {Name: "mgmt"}, {Name: "vpn"}},
		Interfaces: []Interface{
			{Name: "ethernet1/1", Zone: "wan", Prefixes: []netip.Prefix{pfx("203.0.113.0/29")}},
			{Name: "ethernet1/2", Zone: "lan", Prefixes: []netip.Prefix{pfx("10.0.0.0/16"), pfx("fd00:10::/64")}},
			{Name: "ethernet1/2.20", Zone: "dmz", VLAN: Collected(uint16(20)), Prefixes: []netip.Prefix{pfx("10.20.0.0/24"), pfx("2001:db8:20::/64")}},
			{Name: "ethernet1/3", Zone: "mgmt", Prefixes: []netip.Prefix{pfx("192.168.99.0/24")}},
			{Name: "tunnel.1", Zone: "vpn"},
		},
		Subnets: []Subnet{
			{ID: "lan-a", Prefix: pfx("10.0.1.0/24"), VLAN: Collected(uint16(11))},
			{ID: "lan-b", Prefix: pfx("10.0.2.0/24"), VLAN: Collected(uint16(12))},
			{ID: "lan-b2", Prefix: pfx("10.0.3.0/24"), VLAN: Collected(uint16(12))},
			{ID: "dmz", Prefix: pfx("10.20.0.0/24")},
			{ID: "dmz6", Prefix: pfx("2001:db8:20::/64")},
			{ID: "lab-behind-host", Prefix: pfx("172.30.0.0/24")},
		},
		Routes: []Route{
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1", Zone: "wan"},
			{Prefix: pfx("::/0"), Interface: "ethernet1/1"},
			{Prefix: pfx("100.64.0.0/10"), Interface: "tunnel.1"},
			{Prefix: pfx("198.51.100.0/24"), Zone: "vpn"},
		},
		Addresses: []AddressObject{
			{Name: "wan-ip", Type: AddressNetmask, Value: "203.0.113.2/32"},
			{Name: "web-server", Type: AddressNetmask, Value: "10.20.0.10"},
			{Name: "lan-net", Type: AddressNetmask, Value: "10.0.0.0/16"},
			{Name: "pool", Type: AddressRange, Value: "10.0.1.10-10.0.1.20"},
			{Name: "cloud", Type: AddressFQDN, Value: "example.org"},
		},
		AddressGroups: []Group{
			{Name: "servers", Static: []string{"web-server", "pool", "10.0.9.9"}},
			{Name: "nested", Static: []string{"servers", "lan-net"}},
			{Name: "dyn", Dynamic: true},
		},
		Services: []ServiceObject{
			{Name: "svc-https", Protocol: "tcp", Ports: "443", SourcePorts: Collected("")},
			{Name: "svc-dns", Protocol: "udp", Ports: "53", SourcePorts: Collected("")},
			{Name: "svc-high", Protocol: "tcp", Ports: "8000-8080,9000", SourcePorts: Collected("")},
		},
		ServiceGroups: []Group{
			{Name: "web", Static: []string{"svc-https", "svc-high"}},
		},
		SecurityRules: []SecurityRule{
			evaluableRule("allow-web", ActionAllow, []string{"wan"}, []string{"dmz"}, []string{"any"}, []string{"wan-ip"}, []string{"web"}),
			evaluableRule("deny-lan-mgmt", ActionDeny, []string{"lan"}, []string{"mgmt"}, []string{"lan-net"}, []string{"any"}, []string{"any"}),
		},
		NATRules: []NATRule{evaluableNAT("fwd-https")},
		DefaultRules: Collected(DefaultRules{
			Intrazone: ActionAllow,
			Interzone: ActionDeny,
		}),
	}
}
