// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"net/netip"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// Fixtures: a small lab with every Q11 field collected (the "after NS-04"
// case). Fail-safe tests start from it and remove or change one thing,
// the same way the netreach fail-safe fixtures do.

func list(s ...string) nr.Field[[]string] { return nr.Collected(s) }

func allFresh() map[nr.InputKind]nr.Input {
	m := map[nr.InputKind]nr.Input{}
	for _, k := range nr.RequiredInputs {
		m[k] = nr.Input{State: nr.InputFresh, DatasetID: "ds-" + string(k)}
	}
	return m
}

// rule returns an enabled universal rule with every field collected and
// no conditions.
func rule(name string, action nr.Action, from, to, src, dst, svc []string) nr.SecurityRule {
	return nr.SecurityRule{
		Name:              name,
		UUID:              "uuid-" + name,
		Disabled:          nr.Collected(false),
		Action:            action,
		From:              nr.Collected(from),
		To:                nr.Collected(to),
		Source:            nr.Collected(src),
		Destination:       nr.Collected(dst),
		NegateSource:      nr.Collected(false),
		NegateDestination: nr.Collected(false),
		Type:              nr.Collected(nr.RuleTypeUniversal),
		SourceHIP:         list("any"),
		DestinationHIP:    list("any"),
		SourceUser:        list("any"),
		Application:       list("any"),
		Service:           nr.Collected(svc),
		Category:          list("any"),
		Schedule:          nr.Collected(""),
	}
}

func s(v ...string) []string { return v }

func labSnapshot(rules ...nr.SecurityRule) *nr.Snapshot {
	pfx := netip.MustParsePrefix
	return &nr.Snapshot{
		Inputs: allFresh(),
		Vsys:   1,
		Zones:  []nr.Zone{{Name: "wan"}, {Name: "lan"}, {Name: "dmz"}, {Name: "mgmt"}, {Name: "guest"}},
		Interfaces: []nr.Interface{
			{Name: "ethernet1/1", Zone: "wan", Prefixes: []netip.Prefix{pfx("203.0.113.0/29")}},
			{Name: "ethernet1/2", Zone: "lan", Prefixes: []netip.Prefix{pfx("10.0.0.0/16")}},
			{Name: "ethernet1/3", Zone: "dmz", Prefixes: []netip.Prefix{pfx("10.20.0.0/24")}},
			{Name: "ethernet1/4", Zone: "mgmt", Prefixes: []netip.Prefix{pfx("192.168.99.0/24")}},
			{Name: "ethernet1/5", Zone: "guest", Prefixes: []netip.Prefix{pfx("10.50.0.0/24")}},
		},
		Subnets: []nr.Subnet{
			{ID: "lan", Prefix: pfx("10.0.0.0/16")},
			{ID: "dmz", Prefix: pfx("10.20.0.0/24")},
		},
		Routes: []nr.Route{{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1", Zone: "wan"}},
		Addresses: []nr.AddressObject{
			{Name: "lan-net", Type: nr.AddressNetmask, Value: "10.0.0.0/16"},
			{Name: "lan-low", Type: nr.AddressNetmask, Value: "10.0.0.0/17"},
			{Name: "lan-high", Type: nr.AddressNetmask, Value: "10.0.128.0/17"},
			{Name: "web-server", Type: nr.AddressNetmask, Value: "10.20.0.10"},
			{Name: "dmz-net", Type: nr.AddressNetmask, Value: "10.20.0.0/24"},
			{Name: "pool", Type: nr.AddressRange, Value: "10.20.0.5-10.20.0.15"},
			{Name: "cloud", Type: nr.AddressFQDN, Value: "example.org"},
			{Name: "dropped-obj", Type: nr.AddressNetmask, Value: "10.20.0.0/24", Dropped: []string{"<dropped:ip-netmask>"}},
		},
		AddressGroups: []nr.Group{
			{Name: "lan-halves", Static: []string{"lan-low", "lan-high"}},
			{Name: "dyn", Dynamic: true},
		},
		Services: []nr.ServiceObject{
			{Name: "svc-https", Protocol: "tcp", Ports: "443", SourcePorts: nr.Collected("")},
			{Name: "svc-http", Protocol: "tcp", Ports: "80", SourcePorts: nr.Collected("")},
			{Name: "svc-web", Protocol: "tcp", Ports: "80,443", SourcePorts: nr.Collected("")},
			{Name: "svc-dns", Protocol: "udp", Ports: "53", SourcePorts: nr.Collected("")},
			{Name: "svc-high", Protocol: "tcp", Ports: "1024-65535", SourcePorts: nr.Collected("")},
			{Name: "svc-low", Protocol: "tcp", Ports: "1-1023", SourcePorts: nr.Collected("")},
		},
		SecurityRules: rules,
		DefaultRules:  nr.Collected(nr.DefaultRules{Intrazone: nr.ActionAllow, Interzone: nr.ActionDeny}),
	}
}

var labClasses = map[string]TrustClass{
	"wan":   TrustUntrusted,
	"lan":   TrustInternal,
	"dmz":   TrustInternal,
	"mgmt":  TrustManagement,
	"guest": TrustGuest,
}

func newInput(t *testing.T, snap *nr.Snapshot, profiles nr.Field[map[string]ProfileSetting]) *Input {
	t.Helper()
	in, err := NewInput(snap, labClasses, profiles)
	if err != nil {
		t.Fatalf("NewInput: %v", err)
	}
	return in
}

// byRule returns the finding of check id for the rule at index i.
func byRule(t *testing.T, r Report, id string, i int) Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.CheckID == id && f.RuleIndex == i {
			return f
		}
	}
	t.Fatalf("no %s finding for rule %d in %+v", id, i, r.Findings)
	return Finding{}
}
