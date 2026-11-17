// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ipList returns n distinct IPv4 management addresses.
func ipList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.%d.1", i)
	}
	return out
}

// prefixList returns n distinct IPv4 host prefixes.
func prefixList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.%d.1/32", i)
	}
	return out
}

// ifaceNames returns n distinct PAN-OS interface names.
func ifaceNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("ethernet1/%d", i+1)
	}
	return out
}

// memberLimitCases covers the list limits that TestParseLimitsAtLimitAndOver
// does not reach: rule member lists, tags, management addresses, zone
// interfaces and interface addresses. Each row is accepted with exactly
// limit entries and rejected with ErrOverLimit at limit+1.
func memberLimitCases() []limitCase {
	type securityField struct {
		name   string
		prefix string
		set    func(r *SecurityRule, v []string)
	}
	securityFields := []securityField{
		{"from", "z", func(r *SecurityRule, v []string) { r.From = v }},
		{"to", "z", func(r *SecurityRule, v []string) { r.To = v }},
		{"source", "m", func(r *SecurityRule, v []string) { r.Source = v }},
		{"destination", "m", func(r *SecurityRule, v []string) { r.Destination = v }},
		{"source_user", "m", func(r *SecurityRule, v []string) { r.SourceUser = v }},
		{"application", "m", func(r *SecurityRule, v []string) { r.Application = v }},
		{"service", "m", func(r *SecurityRule, v []string) { r.Service = v }},
		{"category", "m", func(r *SecurityRule, v []string) { r.Category = v }},
	}
	type natField struct {
		name   string
		prefix string
		set    func(r *NATRule, v []string)
	}
	natFields := []natField{
		{"from", "z", func(r *NATRule, v []string) { r.From = v }},
		{"to", "z", func(r *NATRule, v []string) { r.To = v }},
		{"source", "m", func(r *NATRule, v []string) { r.Source = v }},
		{"destination", "m", func(r *NATRule, v []string) { r.Destination = v }},
	}

	var cases []limitCase
	for _, f := range securityFields {
		cases = append(cases, limitCase{"security rule " + f.name + " members", MaxRuleMembers, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				r := SecurityRule{Name: "r", Action: ActionAllow}
				f.set(&r, names(f.prefix, n))
				fp.SecurityRules = []SecurityRule{r}
			})
		}})
	}
	for _, f := range natFields {
		cases = append(cases, limitCase{"NAT rule " + f.name + " members", MaxRuleMembers, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				r := NATRule{Name: "n"}
				f.set(&r, names(f.prefix, n))
				fp.NATRules = []NATRule{r}
			})
		}})
	}
	return append(cases,
		limitCase{"security rule tags", MaxTagsPerObject, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				fp.SecurityRules = []SecurityRule{{Name: "r", Action: ActionAllow, Tags: names("t", n)}}
			})
		}},
		limitCase{"address object tags", MaxTagsPerObject, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				fp.Addresses = []AddressObject{{Name: "a", Type: AddressNetmask, Value: "10.0.0.1", Tags: names("t", n)}}
			})
		}},
		limitCase{"management addresses per device", MaxManagementAddresses, func(n int) Observation {
			return cbsWith(func(o *Observation) {
				o.Facts = AvailableDataset(Facts{Model: "CBS350-24T-4G", FirmwareVersion: "3.x", ManagementAddresses: ipList(n)})
			})
		}},
		limitCase{"zone interfaces", MaxFirewallInterfaces, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				fp.Zones = []Zone{{Name: "trust", Interfaces: ifaceNames(n)}}
			})
		}},
		limitCase{"addresses per interface (PAN-OS)", MaxAddressesPerInterface, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				fp.Interfaces = []FirewallInterface{{Name: "ethernet1/1", Addresses: prefixList(n)}}
			})
		}},
	)
}

// TestMemberLimitsAtLimitAndOver checks each list limit of memberLimitCases
// with exactly limit entries (accepted) and limit+1 (ErrOverLimit and
// ErrInvalid).
func TestMemberLimitsAtLimitAndOver(t *testing.T) {
	for _, c := range memberLimitCases() {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ValidateObservation(c.build(c.limit)); err != nil {
				t.Fatalf("at limit %d: %v", c.limit, err)
			}
			_, err := ValidateObservation(c.build(c.limit + 1))
			if !errors.Is(err, ErrOverLimit) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("limit+1: got %v, want ErrOverLimit and ErrInvalid", err)
			}
		})
	}
}

// TestMemberLimitsRejectedWhenDecoding decodes a document at each list limit
// (accepted) and one entry over it (rejected with ErrOverLimit). Marshal
// refuses the over-limit observation, so the document is built directly.
func TestMemberLimitsRejectedWhenDecoding(t *testing.T) {
	for _, c := range memberLimitCases() {
		t.Run(c.name, func(t *testing.T) {
			at, err := MarshalObservation(c.build(c.limit))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeObservation(at); err != nil {
				t.Fatalf("at limit: %v", err)
			}
			raw, err := json.Marshal(c.build(c.limit + 1))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeObservation(raw); !errors.Is(err, ErrOverLimit) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("limit+1: got %v, want ErrOverLimit and ErrInvalid", err)
			}
		})
	}
}

// TestLLDPCapabilityCountLimit checks MaxLLDPCapabilities. The protocol has
// only eight capability values and the validator rejects duplicates, so a
// neighbor with exactly 16 capabilities cannot be valid: at the limit it is
// rejected for the duplicates, not for the count. The count limit is
// reached at 17, and the 17-entry case is also rejected for the duplicates.
func TestLLDPCapabilityCountLimit(t *testing.T) {
	known := []LLDPCapability{CapOther, CapRepeater, CapBridge, CapWLANAP, CapRouter, CapTelephone, CapDOCSIS, CapStationOnly}
	neighbor := func(caps []LLDPCapability) Observation {
		return cbsWith(func(o *Observation) {
			o.LLDPNeighbors = AvailableDataset([]LLDPNeighbor{{
				LocalPort: "gi1/0/1", ChassisID: "02:00:00:00:00:01", PortID: "p", Capabilities: caps,
			}})
		})
	}
	withRepeats := func(n int) []LLDPCapability {
		out := make([]LLDPCapability, n)
		for i := range out {
			out[i] = known[i%len(known)]
		}
		return out
	}

	if _, err := ValidateObservation(neighbor(known)); err != nil {
		t.Fatalf("all eight capabilities once: %v", err)
	}

	_, err := ValidateObservation(neighbor(withRepeats(MaxLLDPCapabilities)))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("at limit with duplicates: got %v, want ErrInvalid", err)
	}
	if errors.Is(err, ErrOverLimit) {
		t.Fatalf("at limit: count limit reported as exceeded: %v", err)
	}

	_, err = ValidateObservation(neighbor(withRepeats(MaxLLDPCapabilities + 1)))
	if !errors.Is(err, ErrOverLimit) || !errors.Is(err, ErrInvalid) {
		t.Fatalf("limit+1: got %v, want ErrOverLimit and ErrInvalid", err)
	}

	raw, err := json.Marshal(neighbor(withRepeats(MaxLLDPCapabilities + 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeObservation(raw); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("decode limit+1: got %v, want ErrOverLimit", err)
	}
}

// TestFilterBytesLimit checks MaxFilterBytes on a dynamic address group filter.
// The limit counts bytes, not runes: 1024 two-byte runes are exactly the limit.
func TestFilterBytesLimit(t *testing.T) {
	filter := func(s string) Observation {
		return panosWith(func(fp *FirewallPolicy) {
			fp.AddressGroups = []Group{{Name: "dyn", DynamicFilter: s}}
		})
	}
	ascii := func(n int) string { return strings.Repeat("a", n) }
	twoByte := func(runes int) string { return strings.Repeat("ä", runes) }

	if _, err := ValidateObservation(filter(ascii(MaxFilterBytes))); err != nil {
		t.Fatalf("filter at %d bytes: %v", MaxFilterBytes, err)
	}
	if _, err := ValidateObservation(filter(twoByte(MaxFilterBytes / 2))); err != nil {
		t.Fatalf("filter of %d runes (%d bytes): %v", MaxFilterBytes/2, MaxFilterBytes, err)
	}
	if _, err := ValidateObservation(filter(ascii(MaxFilterBytes + 1))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("filter at %d bytes: got %v, want ErrInvalid", MaxFilterBytes+1, err)
	}
	if _, err := ValidateObservation(filter(twoByte(MaxFilterBytes/2) + "a")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("filter of %d bytes: got %v, want ErrInvalid", MaxFilterBytes+1, err)
	}
}

// TestObservedAtYearLimits checks the accepted UTC years MinObservedYear and
// MaxObservedYear, and the zero time. The year is taken in UTC.
func TestObservedAtYearLimits(t *testing.T) {
	cases := []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"zero time", time.Time{}, false},
		{"first year, one nanosecond after zero time", time.Date(MinObservedYear, 1, 1, 0, 0, 0, 1, time.UTC), true},
		{"year before the first", time.Date(MinObservedYear-1, 12, 31, 23, 59, 59, 999999999, time.UTC), false},
		{"first year by local time, year 0 in UTC", time.Date(MinObservedYear, 1, 1, 0, 0, 0, 1, time.FixedZone("east", 2*3600)), false},
		{"last year", time.Date(MaxObservedYear, 12, 31, 23, 59, 59, 0, time.UTC), true},
		{"year after the last", time.Date(MaxObservedYear+1, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"last year by local time, year 10000 in UTC", time.Date(MaxObservedYear, 12, 31, 23, 0, 0, 0, time.FixedZone("west", -5*3600)), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := baseCBSObservation()
			o.ObservedAt = c.at
			_, err := ValidateObservation(o)
			if c.ok && err != nil {
				t.Fatalf("observed_at %v rejected: %v", c.at, err)
			}
			if !c.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("observed_at %v: got %v, want ErrInvalid", c.at, err)
			}
		})
	}
}
