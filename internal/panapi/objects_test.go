// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// validatePolicy runs the netdevcontract validator over fp so the parser
// output is known to be acceptable as an observation.
func validatePolicy(t *testing.T, fp netdevcontract.FirewallPolicy) {
	t.Helper()
	o := netdevcontract.Observation{
		DeviceID:        "fw-1",
		Family:          netdevcontract.FamilyPANOS,
		TrustGeneration: 1,
		ObservedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		FirewallPolicy:  netdevcontract.AvailableDataset(fp),
	}
	if _, err := netdevcontract.ValidateObservation(o); err != nil {
		t.Fatalf("parser output fails the contract: %v", err)
	}
}

func objectsBody(inner string) []byte {
	return wrapResult(`<vsys><entry name="vsys1">` + inner + `</entry></vsys>`)
}

func addrNames(as []netdevcontract.AddressObject) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.Name)
	}
	return out
}

func TestParseObjectsFixture(t *testing.T) {
	got, err := ParseObjects(readFixture(t, "objects.xml"))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	wantAddr := []netdevcontract.AddressObject{
		{Name: "web-1", Type: netdevcontract.AddressNetmask, Value: "192.0.2.10", Description: "example web server", Tags: []string{"web", "prod"}},
		{Name: "web-2", Type: netdevcontract.AddressNetmask, Value: "192.0.2.11/32", Tags: []string{"web"}},
		{Name: "lab-net", Type: netdevcontract.AddressNetmask, Value: "198.51.100.0/24"},
		{Name: "v6-net", Type: netdevcontract.AddressNetmask, Value: "2001:db8::/32"},
		{Name: "dhcp-pool", Type: netdevcontract.AddressRange, Value: "192.0.2.100-192.0.2.150"},
		{Name: "wild", Type: netdevcontract.AddressWildcard, Value: "198.51.100.0/0.0.0.255"},
		{Name: "updates.example.com", Type: netdevcontract.AddressFQDN, Value: "updates.example.com"},
	}
	wantAG := []netdevcontract.Group{
		{Name: "web-servers", Static: []string{"web-1", "web-2"}, Description: "both web servers"},
		{Name: "all-internal", Static: []string{"web-servers", "lab-net", "web-1"}, Tags: []string{"prod"}},
		{Name: "dyn-prod-web", DynamicFilter: "'prod' and 'web'"},
		{Name: "with-dynamic", Static: []string{"dyn-prod-web"}},
	}
	wantSvc := []netdevcontract.ServiceObject{
		{Name: "svc-http-alt", Protocol: "tcp", Port: "8080,8443"},
		{Name: "svc-dns", Protocol: "udp", Port: "53", SourcePort: "1024-65535", Description: "example dns"},
		{Name: "svc-sctp", Protocol: "sctp", Port: "2905"},
	}
	wantSG := []netdevcontract.Group{
		{Name: "web-services", Static: []string{"svc-http-alt"}},
		{Name: "all-services", Static: []string{"web-services", "svc-dns", "svc-sctp"}},
	}
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"addresses", got.Addresses, wantAddr},
		{"address groups", got.AddressGroups, wantAG},
		{"services", got.Services, wantSvc},
		{"service groups", got.ServiceGroups, wantSG},
		{"tags", got.Tags, []string{"prod", "web"}},
		{"incomplete", got.Incomplete, false},
	} {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s =\n%+v\nwant\n%+v", c.name, c.got, c.want)
		}
	}
	validatePolicy(t, got.Policy())
}

func TestParseObjectsDropsUnknownElements(t *testing.T) {
	got, err := ParseObjects(readFixture(t, "objects.xml"))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	s := fmt.Sprintf("%#v", got)
	for _, leaked := range []string{"should-be-dropped", "not a real key", "allow-web", "example-av", "color1", "example tag", "00000000-0000"} {
		if strings.Contains(s, leaked) {
			t.Errorf("non-allowlisted content %q reached the result", leaked)
		}
	}
	// an unknown element inside an allowed entry is dropped, not an error
	got, err = ParseObjects(objectsBody(`<address><entry name="a" extra="x"><ip-netmask>192.0.2.1</ip-netmask><new-field><deep>v</deep></new-field></entry></address>`))
	if err != nil || len(got.Addresses) != 1 || got.Addresses[0].Value != "192.0.2.1" {
		t.Fatalf("ParseObjects = %+v, %v", got, err)
	}
}

func TestParseObjectsRefusesStatusError(t *testing.T) {
	_, err := ParseObjects(readFixture(t, "status-error.xml"))
	if !errors.Is(err, ErrAPIStatus) || strings.Contains(err.Error(), "example-secret-body-text") {
		t.Fatalf("err = %v, want ErrAPIStatus without body text", err)
	}
}

func TestParseObjectsRefusesEntityExpansion(t *testing.T) {
	in := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">` +
		`<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>` +
		`<response status="success"><result><address><entry name="a"><description>&lol3;</description><ip-netmask>192.0.2.1</ip-netmask></entry></address></result></response>`
	if _, err := ParseObjects([]byte(in)); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}

func TestParseObjectsRefusesDeepNesting(t *testing.T) {
	n := netdevcontract.MaxXMLDepth
	in := objectsBody(`<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask>` +
		strings.Repeat("<x>", n) + strings.Repeat("</x>", n) + `</entry></address>`)
	if _, err := ParseObjects(in); !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("err = %v, want ErrXMLLimit", err)
	}
}

func TestParseObjectsRejectsInvalidContent(t *testing.T) {
	cases := map[string]string{
		"address without value":        `<address><entry name="a"/></address>`,
		"address two value kinds":      `<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask><fqdn>a.example.com</fqdn></entry></address>`,
		"address value repeated":       `<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask><ip-netmask>192.0.2.2</ip-netmask></entry></address>`,
		"address bad netmask":          `<address><entry name="a"><ip-netmask>192.0.2.0/33</ip-netmask></entry></address>`,
		"address netmask with zone":    `<address><entry name="a"><ip-netmask>fe80::1%eth0</ip-netmask></entry></address>`,
		"address netmask with space":   `<address><entry name="a"><ip-netmask> 192.0.2.1</ip-netmask></entry></address>`,
		"address range reversed":       `<address><entry name="a"><ip-range>192.0.2.9-192.0.2.1</ip-range></entry></address>`,
		"address range mixed family":   `<address><entry name="a"><ip-range>192.0.2.1-2001:db8::1</ip-range></entry></address>`,
		"address range one end":        `<address><entry name="a"><ip-range>192.0.2.1</ip-range></entry></address>`,
		"address wildcard bad":         `<address><entry name="a"><ip-wildcard>192.0.2.0</ip-wildcard></entry></address>`,
		"address fqdn non-ascii":       `<address><entry name="a"><fqdn>exämple.com</fqdn></entry></address>`,
		"address fqdn bad label":       `<address><entry name="a"><fqdn>-bad.example.com</fqdn></entry></address>`,
		"address fqdn empty":           `<address><entry name="a"><fqdn></fqdn></entry></address>`,
		"address name invalid":         `<address><entry name="a/b"><ip-netmask>192.0.2.1</ip-netmask></entry></address>`,
		"address duplicate":            `<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask></entry><entry name="a"><ip-netmask>192.0.2.2</ip-netmask></entry></address>`,
		"address description control":  "<address><entry name=\"a\"><ip-netmask>192.0.2.1</ip-netmask><description>x‮y</description></entry></address>",
		"address description too long": `<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask><description>` + strings.Repeat("d", netdevcontract.MaxDescriptionBytes+1) + `</description></entry></address>`,
		"address tag invalid":          `<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask><tag><member>x&amp;y</member></tag></entry></address>`,
		"address tag duplicated":       `<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask><tag><member>t</member><member>t</member></tag></entry></address>`,
		"group shares address name":    `<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask></entry></address><address-group><entry name="a"><static><member>a</member></static></entry></address-group>`,
		"group static and dynamic":     `<address-group><entry name="g"><static><member>a</member></static><dynamic><filter>'t'</filter></dynamic></entry></address-group>`,
		"group dynamic without filter": `<address-group><entry name="g"><dynamic/></entry></address-group>`,
		"group dynamic filter control": "<address-group><entry name=\"g\"><dynamic><filter>'t'\u0085</filter></dynamic></entry></address-group>",
		"group filter too long":        `<address-group><entry name="g"><dynamic><filter>` + strings.Repeat("f", netdevcontract.MaxFilterBytes+1) + `</filter></dynamic></entry></address-group>`,
		"group member invalid":         `<address-group><entry name="g"><static><member>a'b</member></static></entry></address-group>`,
		"group member duplicated":      `<address-group><entry name="g"><static><member>a</member><member>a</member></static></entry></address-group>`,
		"group static repeated":        `<address-group><entry name="g"><static><member>a</member></static><static><member>b</member></static></entry></address-group>`,
		"group duplicate":              `<address-group><entry name="g"/><entry name="g"/></address-group>`,
		"service without protocol":     `<service><entry name="s"/></service>`,
		"service two protocols":        `<service><entry name="s"><protocol><tcp><port>1</port></tcp><udp><port>1</port></udp></protocol></entry></service>`,
		"service without port":         `<service><entry name="s"><protocol><tcp/></protocol></entry></service>`,
		"service port out of range":    `<service><entry name="s"><protocol><tcp><port>70000</port></tcp></protocol></entry></service>`,
		"service port range reversed":  `<service><entry name="s"><protocol><tcp><port>90-80</port></tcp></protocol></entry></service>`,
		"service port garbage":         `<service><entry name="s"><protocol><tcp><port>80;rm</port></tcp></protocol></entry></service>`,
		"service bad source port":      `<service><entry name="s"><protocol><udp><port>53</port><source-port>x</source-port></udp></protocol></entry></service>`,
		"service duplicate":            `<service><entry name="s"><protocol><tcp><port>1</port></tcp></protocol></entry><entry name="s"><protocol><tcp><port>2</port></tcp></protocol></entry></service>`,
		"service group shares name":    `<service><entry name="s"><protocol><tcp><port>1</port></tcp></protocol></entry></service><service-group><entry name="s"/></service-group>`,
		"service group member invalid": `<service-group><entry name="g"><members><member>a"b</member></members></entry></service-group>`,
		"tag name invalid":             `<tag><entry name="a/b"/></tag>`,
		"tag duplicate":                `<tag><entry name="t"/><entry name="t"/></tag>`,
	}
	for name, inner := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseObjects(objectsBody(inner))
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestParseObjectsOversizeCountsAreIncomplete(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<address>`)
	for i := range netdevcontract.MaxAddressObjects + 1 {
		fmt.Fprintf(&b, `<entry name="a%d"><ip-netmask>192.0.2.1</ip-netmask></entry>`, i)
	}
	b.WriteString(`</address><address-group><entry name="g"><static><member>a20000</member></static></entry></address-group>`)
	got, err := ParseObjects(objectsBody(b.String()))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if !got.Incomplete || len(got.Addresses) != netdevcontract.MaxAddressObjects {
		t.Fatalf("got %d addresses, incomplete %v", len(got.Addresses), got.Incomplete)
	}
	// a member that may have been cut away is not "unknown" but incomplete
	if _, err := got.ResolveGroup("g"); !errors.Is(err, ErrGroupIncomplete) {
		t.Fatalf("ResolveGroup err = %v, want ErrGroupIncomplete", err)
	}

	b.Reset()
	b.WriteString(`<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask></entry></address><address-group><entry name="big"><static>`)
	for i := range netdevcontract.MaxGroupMembers + 1 {
		fmt.Fprintf(&b, `<member>m%d</member>`, i)
	}
	b.WriteString(`</static></entry><entry name="small"><static><member>a</member></static></entry></address-group>`)
	got, err = ParseObjects(objectsBody(b.String()))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if !got.Incomplete || len(got.AddressGroups[0].Static) != netdevcontract.MaxGroupMembers {
		t.Fatalf("got %d members, incomplete %v", len(got.AddressGroups[0].Static), got.Incomplete)
	}
	if _, err := got.ResolveGroup("big"); !errors.Is(err, ErrGroupIncomplete) {
		t.Fatalf("ResolveGroup(big) err = %v, want ErrGroupIncomplete", err)
	}
	if r, err := got.ResolveGroup("small"); err != nil || len(r) != 1 {
		t.Fatalf("ResolveGroup(small) = %v, %v", r, err)
	}

	b.Reset()
	b.WriteString(`<address-group>`)
	for i := range netdevcontract.MaxAddressGroups + 1 {
		fmt.Fprintf(&b, `<entry name="g%d"/>`, i)
	}
	b.WriteString(`</address-group><service-group>`)
	for i := range netdevcontract.MaxServiceGroups + 1 {
		fmt.Fprintf(&b, `<entry name="s%d"/>`, i)
	}
	b.WriteString(`</service-group>`)
	got, err = ParseObjects(objectsBody(b.String()))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if !got.Incomplete || len(got.AddressGroups) != netdevcontract.MaxAddressGroups || len(got.ServiceGroups) != netdevcontract.MaxServiceGroups {
		t.Fatalf("got %d/%d groups, incomplete %v", len(got.AddressGroups), len(got.ServiceGroups), got.Incomplete)
	}

	b.Reset()
	b.WriteString(`<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask><tag>`)
	for i := range netdevcontract.MaxTagsPerObject + 1 {
		fmt.Fprintf(&b, `<member>t%d</member>`, i)
	}
	b.WriteString(`</tag></entry></address>`)
	got, err = ParseObjects(objectsBody(b.String()))
	if err != nil || !got.Incomplete || len(got.Addresses[0].Tags) != netdevcontract.MaxTagsPerObject {
		t.Fatalf("tags over limit: %+v, %v", got.Incomplete, err)
	}
}

func TestResolveGroupFixture(t *testing.T) {
	o, err := ParseObjects(readFixture(t, "objects.xml"))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	got, err := o.ResolveGroup("all-internal")
	if err != nil {
		t.Fatalf("ResolveGroup: %v", err)
	}
	if names := addrNames(got); !reflect.DeepEqual(names, []string{"web-1", "web-2", "lab-net"}) {
		t.Fatalf("ResolveGroup = %v", names)
	}
	for _, name := range []string{"dyn-prod-web", "with-dynamic"} {
		if _, err := o.ResolveGroup(name); !errors.Is(err, ErrDynamicGroup) {
			t.Fatalf("ResolveGroup(%s) err = %v, want ErrDynamicGroup", name, err)
		}
	}
	if _, err := o.ResolveGroup("web-1"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("ResolveGroup(address) err = %v, want ErrGroupNotFound", err)
	}
	svcs, err := o.ResolveServiceGroup("all-services")
	if err != nil {
		t.Fatalf("ResolveServiceGroup: %v", err)
	}
	var names []string
	for _, s := range svcs {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"svc-http-alt", "svc-dns", "svc-sctp"}) {
		t.Fatalf("ResolveServiceGroup = %v", names)
	}
}

// groupChain builds address groups g1 -> g2 -> ... -> gN -> address a.
func groupChain(n int) string {
	var b strings.Builder
	b.WriteString(`<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask></entry></address><address-group>`)
	for i := 1; i <= n; i++ {
		next := fmt.Sprintf("g%d", i+1)
		if i == n {
			next = "a"
		}
		fmt.Fprintf(&b, `<entry name="g%d"><static><member>%s</member></static></entry>`, i, next)
	}
	b.WriteString(`</address-group>`)
	return b.String()
}

func TestResolveGroupDepthLimit(t *testing.T) {
	o, err := ParseObjects(objectsBody(groupChain(MaxGroupResolveDepth)))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if got, err := o.ResolveGroup("g1"); err != nil || len(got) != 1 {
		t.Fatalf("depth %d: %v, %v", MaxGroupResolveDepth, got, err)
	}

	o, err = ParseObjects(objectsBody(groupChain(MaxGroupResolveDepth + 1)))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if _, err := o.ResolveGroup("g1"); !errors.Is(err, ErrGroupDepth) {
		t.Fatalf("depth %d: err = %v, want ErrGroupDepth", MaxGroupResolveDepth+1, err)
	}
	// the inner groups are within the limit
	if _, err := o.ResolveGroup("g2"); err != nil {
		t.Fatalf("ResolveGroup(g2): %v", err)
	}
}

func TestResolveGroupDepthThroughSharedSubgroup(t *testing.T) {
	// g1 reaches the shared chain s1..s7 twice: once directly and once
	// one level deeper. The memoized height must still count the deeper
	// path: g1 -> h -> s1 -> ... -> s7 -> a is 9 levels.
	var b strings.Builder
	b.WriteString(`<address><entry name="a"><ip-netmask>192.0.2.1</ip-netmask></entry></address><address-group>`)
	b.WriteString(`<entry name="g1"><static><member>s1</member><member>h</member></static></entry>`)
	b.WriteString(`<entry name="h"><static><member>s1</member></static></entry>`)
	for i := 1; i <= 7; i++ {
		next := fmt.Sprintf("s%d", i+1)
		if i == 7 {
			next = "a"
		}
		fmt.Fprintf(&b, `<entry name="s%d"><static><member>%s</member></static></entry>`, i, next)
	}
	b.WriteString(`</address-group>`)
	o, err := ParseObjects(objectsBody(b.String()))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if _, err := o.ResolveGroup("g1"); !errors.Is(err, ErrGroupDepth) {
		t.Fatalf("err = %v, want ErrGroupDepth", err)
	}
	if _, err := o.ResolveGroup("h"); err != nil {
		t.Fatalf("ResolveGroup(h): %v", err)
	}
}

func TestResolveGroupCycles(t *testing.T) {
	cases := map[string]string{
		"self":  `<address-group><entry name="a"><static><member>a</member></static></entry></address-group>`,
		"pair":  `<address-group><entry name="a"><static><member>b</member></static></entry><entry name="b"><static><member>a</member></static></entry></address-group>`,
		"three": `<address-group><entry name="a"><static><member>b</member></static></entry><entry name="b"><static><member>c</member></static></entry><entry name="c"><static><member>a</member></static></entry></address-group>`,
	}
	for name, inner := range cases {
		t.Run(name, func(t *testing.T) {
			o, err := ParseObjects(objectsBody(inner))
			if err != nil {
				t.Fatalf("ParseObjects: %v", err)
			}
			if _, err := o.ResolveGroup("a"); !errors.Is(err, ErrGroupCycle) {
				t.Fatalf("err = %v, want ErrGroupCycle", err)
			}
		})
	}
	o, err := ParseObjects(objectsBody(`<service-group><entry name="x"><members><member>y</member></members></entry><entry name="y"><members><member>x</member></members></entry></service-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if _, err := o.ResolveServiceGroup("x"); !errors.Is(err, ErrGroupCycle) {
		t.Fatalf("service group err = %v, want ErrGroupCycle", err)
	}
}

func TestResolveGroupUnresolvedMember(t *testing.T) {
	o, err := ParseObjects(objectsBody(`<address-group><entry name="g"><static><member>shared-object</member></static></entry></address-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if _, err := o.ResolveGroup("g"); !errors.Is(err, ErrUnresolvedMember) {
		t.Fatalf("err = %v, want ErrUnresolvedMember", err)
	}
}

func TestResolveGroupWideDiamondIsBounded(t *testing.T) {
	// Every group of level i contains every group of level i+1. Without
	// memoization the expansion would visit width^levels groups.
	const width, levels = 40, MaxGroupResolveDepth
	var b strings.Builder
	b.WriteString(`<address>`)
	for j := range width {
		fmt.Fprintf(&b, `<entry name="a%d"><ip-netmask>192.0.2.%d</ip-netmask></entry>`, j, j)
	}
	b.WriteString(`</address><address-group><entry name="root"><static>`)
	for j := range width {
		fmt.Fprintf(&b, `<member>l1-%d</member>`, j)
	}
	b.WriteString(`</static></entry>`)
	for i := 1; i < levels; i++ {
		for j := range width {
			fmt.Fprintf(&b, `<entry name="l%d-%d"><static>`, i, j)
			for k := range width {
				if i == levels-1 {
					fmt.Fprintf(&b, `<member>a%d</member>`, k)
				} else {
					fmt.Fprintf(&b, `<member>l%d-%d</member>`, i+1, k)
				}
			}
			b.WriteString(`</static></entry>`)
		}
	}
	b.WriteString(`</address-group>`)
	o, err := ParseObjects(objectsBody(b.String()))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	got, err := o.ResolveGroup("root")
	if err != nil || len(got) != width {
		t.Fatalf("ResolveGroup = %d objects, %v; want %d", len(got), err, width)
	}
}
