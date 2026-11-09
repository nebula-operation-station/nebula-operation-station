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

var observedAt = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func config(lines ...string) ConfigSnapshot {
	return ConfigSnapshot{
		Lines:          lines,
		RawDigest:      strings.Repeat("ab", 32),
		RedactedDigest: RedactedDigestOf(lines),
	}
}

func baseCBSObservation() Observation {
	return Observation{
		DeviceID:        "sw-core-1",
		Family:          FamilyCBS,
		TrustGeneration: 1,
		ObservedAt:      observedAt,
		Facts: AvailableDataset(Facts{
			Model: "CBS350-24T-4G", FirmwareVersion: "3.x", Serial: "SERIAL",
			Hostname: "sw-core-1", UptimeSeconds: ptr(uint64(3600)),
			ManagementAddresses: []string{"10.0.0.2"},
		}),
		RunningConfig: AvailableDataset(config("hostname sw-core-1", "username admin password <redacted:0a1b2c3d>")),
		StartupConfig: UnavailableDataset[ConfigSnapshot](ReasonTimeout),
		Ports: AvailableDataset([]Port{
			{Name: "gi1/0/1", AdminState: LinkUp, OperState: LinkUp, SpeedMbps: ptr(uint64(1000)), Mode: ModeAccess, AccessVLAN: ptr(uint16(10)), Description: "pve-1 <eno1>"},
			{Name: "gi1/0/24", AdminState: LinkUp, OperState: LinkDown, Mode: ModeTrunk, NativeVLAN: ptr(uint16(1)), AllowedVLANs: []uint16{1, 10, 20}},
		}),
		VLANs:    AvailableDataset([]VLAN{{ID: 1, Name: "default"}, {ID: 10, Name: "lab"}}),
		MACTable: AvailableDataset([]MACEntry{{VLAN: 10, MAC: "02:00:00:00:00:01", Port: "gi1/0/1", Type: MACDynamic}}),
		LLDPNeighbors: AvailableDataset([]LLDPNeighbor{{
			LocalPort: "gi1/0/1", ChassisID: "02:00:00:00:00:01", PortID: "eno1",
			SystemName: "pve-1", ManagementAddress: "10.0.0.10", Capabilities: []LLDPCapability{CapBridge, CapRouter},
		}}),
	}
}

func basePolicy() FirewallPolicy {
	return FirewallPolicy{
		SecurityRules: []SecurityRule{{
			Name: "allow lab-web", UUID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
			From: []string{"trust"}, To: []string{"untrust"}, Source: []string{"lab-net"},
			Destination: []string{"any"}, Application: []string{"web-browsing"}, Service: []string{"application-default"},
			Action: ActionAllow, Description: "web <out>", Tags: []string{"lab"},
		}},
		NATRules:      []NATRule{{Name: "outbound", From: []string{"trust"}, To: []string{"untrust"}, Source: []string{"lab-net"}, Destination: []string{"any"}, Service: "any", SourceTranslation: "dynamic-ip-and-port interface ethernet1/1"}},
		Addresses:     []AddressObject{{Name: "lab-net", Type: AddressNetmask, Value: "10.0.0.0/24"}, {Name: "range", Type: AddressRange, Value: "10.0.0.10-10.0.0.20"}, {Name: "dns", Type: AddressFQDN, Value: "dns.example.org"}},
		AddressGroups: []Group{{Name: "lab-all", Static: []string{"lab-net", "range"}}, {Name: "tagged", DynamicFilter: "'lab' and 'web'"}},
		Services:      []ServiceObject{{Name: "svc-web", Protocol: "tcp", Port: "80,443,8000-8080"}},
		ServiceGroups: []Group{{Name: "svc-all", Static: []string{"svc-web"}}},
		Zones:         []Zone{{Name: "trust", Interfaces: []string{"ethernet1/2"}}, {Name: "untrust", Interfaces: []string{"ethernet1/1"}}},
		Interfaces:    []FirewallInterface{{Name: "ethernet1/1", Addresses: []string{"192.0.2.2/30"}, Zone: "untrust"}, {Name: "ethernet1/2.10", VLANTag: ptr(uint16(10)), Addresses: []string{"10.0.0.1/24"}, Zone: "trust"}},
	}
}

func basePANOSObservation() Observation {
	first := observedAt.Add(-48 * time.Hour)
	return Observation{
		DeviceID:        "fw-1",
		Family:          FamilyPANOS,
		TrustGeneration: 2,
		ObservedAt:      observedAt,
		Facts:           AvailableDataset(Facts{Model: "PA-440", FirmwareVersion: "11.1.x"}),
		RunningConfig:   AvailableDataset(config("<config>", "<devices/>", "</config>")),
		FirewallPolicy:  AvailableDataset(basePolicy()),
		HitCounts: AvailableDataset([]HitCount{
			{RuleName: "allow lab-web", Hits: 42, FirstHit: &first, LastHit: ptr(observedAt), ResetAt: ptr(first.Add(-time.Hour))},
			{RuleName: "unused", Hits: 0},
		}),
	}
}

func mustValid(t *testing.T, o Observation) {
	t.Helper()
	if _, err := ValidateObservation(o); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
}

func mustInvalid(t *testing.T, o Observation) error {
	t.Helper()
	_, err := ValidateObservation(o)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
	if _, merr := MarshalObservation(o); merr == nil {
		t.Fatal("marshal accepted an invalid observation")
	}
	return err
}

func TestValidObservationsRoundTrip(t *testing.T) {
	for _, o := range []Observation{baseCBSObservation(), basePANOSObservation()} {
		raw, err := MarshalObservation(o)
		if err != nil {
			t.Fatalf("marshal %s: %v", o.DeviceID, err)
		}
		if strings.Contains(string(raw), "\\"+"u003c") || !strings.Contains(string(raw), "<") {
			t.Fatalf("encoding escapes HTML: %s", raw)
		}
		got, err := DecodeObservation(raw)
		if err != nil {
			t.Fatalf("decode %s: %v\n%s", o.DeviceID, err, raw)
		}
		again, err := MarshalObservation(got)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(raw) {
			t.Fatalf("round trip differs:\n%s\n%s", raw, again)
		}
	}
}

func TestUnavailableIsDistinctFromEmpty(t *testing.T) {
	o := baseCBSObservation()
	o.MACTable = AvailableDataset([]MACEntry(nil)) // empty, complete
	o.LLDPNeighbors = UnavailableDataset[[]LLDPNeighbor](ReasonUnexpectedPrompt)
	o.VLANs = nil // not part of this read
	raw, err := MarshalObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"mac_table":{"state":"available","value":[]}`) {
		t.Fatalf("empty dataset not encoded as available []: %s", s)
	}
	if !strings.Contains(s, `"lldp_neighbors":{"state":"unavailable","reason":"unexpected_prompt"}`) {
		t.Fatalf("unavailable dataset encoded wrongly: %s", s)
	}
	if strings.Contains(s, `"vlans"`) {
		t.Fatalf("absent dataset encoded: %s", s)
	}
	got, err := DecodeObservation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.MACTable.State != Available || got.MACTable.Value == nil || len(got.MACTable.Value) != 0 {
		t.Fatalf("empty dataset decoded as %+v", got.MACTable)
	}
	if got.LLDPNeighbors.State != Unavailable || got.LLDPNeighbors.Reason != ReasonUnexpectedPrompt || got.LLDPNeighbors.Value != nil {
		t.Fatalf("unavailable dataset decoded as %+v", got.LLDPNeighbors)
	}
	if got.VLANs != nil {
		t.Fatalf("absent dataset decoded as %+v", got.VLANs)
	}
}

func TestDatasetShapeRejected(t *testing.T) {
	cases := map[string]string{
		"available without value":    `{"state":"available"}`,
		"available with reason":      `{"state":"available","value":[],"reason":"timeout"}`,
		"unavailable with value":     `{"state":"unavailable","reason":"timeout","value":[]}`,
		"unavailable without reason": `{"state":"unavailable"}`,
		"unknown reason":             `{"state":"unavailable","reason":"device said: secret"}`,
		"incomplete without reason":  `{"state":"incomplete","value":[]}`,
		"incomplete other reason":    `{"state":"incomplete","value":[],"reason":"timeout"}`,
		"unknown state":              `{"state":"partial","value":[]}`,
		"missing state":              `{"value":[]}`,
		"unknown key":                `{"state":"available","value":[],"extra":1}`,
		"null value":                 `{"state":"available","value":null}`,
		"not an object":              `[]`,
	}
	for name, ds := range cases {
		t.Run(name, func(t *testing.T) {
			raw := `{"device_id":"sw-1","family":"cbs","trust_generation":1,"observed_at":"2026-11-09T12:00:00Z","vlans":` + ds + `}`
			if _, err := DecodeObservation([]byte(raw)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
	ok := `{"device_id":"sw-1","family":"cbs","trust_generation":1,"observed_at":"2026-11-09T12:00:00Z","vlans":{"state":"incomplete","value":[{"id":1}],"reason":"over_limit"}}`
	if _, err := DecodeObservation([]byte(ok)); err != nil {
		t.Fatalf("incomplete list rejected: %v", err)
	}
}

func TestIncompleteOnlyForLists(t *testing.T) {
	o := baseCBSObservation()
	o.RunningConfig = IncompleteDataset(config("hostname x"))
	mustInvalid(t, o)
	o = baseCBSObservation()
	o.Facts = IncompleteDataset(Facts{Model: "m", FirmwareVersion: "v"})
	mustInvalid(t, o)
	o = basePANOSObservation()
	o.FirewallPolicy = IncompleteDataset(basePolicy())
	o.HitCounts = IncompleteDataset([]HitCount{{RuleName: "r", Hits: 1}})
	mustValid(t, o)
}

func TestDecodeObservationRejectsUnknownFields(t *testing.T) {
	good, err := MarshalObservation(baseCBSObservation())
	if err != nil {
		t.Fatal(err)
	}
	pgood, err := MarshalObservation(basePANOSObservation())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"top level":      strings.Replace(string(good), `"device_id"`, `"raw_config":"x","device_id"`, 1),
		"facts value":    strings.Replace(string(good), `"model"`, `"password":"x","model"`, 1),
		"port":           strings.Replace(string(good), `"admin_state"`, `"vlan_raw":"x","admin_state"`, 1),
		"config":         strings.Replace(string(good), `"raw_digest"`, `"raw":"x","raw_digest"`, 1),
		"security rule":  strings.Replace(string(pgood), `"action"`, `"xpath":"/config","action"`, 1),
		"hit count":      strings.Replace(string(pgood), `"hits":42`, `"hits":42,"x":1`, 1),
		"policy":         strings.Replace(string(pgood), `"security_rules"`, `"mgt_config":[],"security_rules"`, 1),
		"family dataset": strings.Replace(string(good), `"device_id"`, `"hit_counts":{"state":"available","value":[]},"device_id"`, 1),
		// encoding/json matches field names case-insensitively; keys that
		// differ only in case must not smuggle a second value
		"case duplicate device_id":  strings.Replace(string(good), `"device_id"`, `"DEVICE_ID":"other","device_id"`, 1),
		"case duplicate trailing":   strings.Replace(string(good), `"device_id":"`, `"DEVICE_ID":"other","device_id":"`, 1),
		"upper-case only key":       strings.Replace(string(good), `"device_id"`, `"Device_ID"`, 1),
		"case duplicate facts":      strings.Replace(string(good), `"facts"`, `"Facts":{"state":"unavailable","reason":"not_supported"},"facts"`, 1),
		"case duplicate generation": strings.Replace(string(good), `"trust_generation"`, `"Trust_Generation":2,"trust_generation"`, 1),
		"case dataset state":        strings.Replace(string(good), `"state"`, `"STATE"`, 1),
		"long s folds to s":         strings.Replace(string(good), `"state"`, `"`+string(rune(0x017F))+`tate"`, 1),
		"case duplicate rule":       strings.Replace(string(pgood), `"action"`, `"ACTION":"deny","action"`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == string(good) || raw == string(pgood) {
				t.Fatal("test case did not modify the document")
			}
			if _, err := DecodeObservation([]byte(raw)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestDecodeObservationRejectsBadText(t *testing.T) {
	good, err := MarshalObservation(baseCBSObservation())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"invalid utf8":       strings.Replace(string(good), "pve-1 <eno1>", "pve-1 \xff", 1),
		"escaped control":    strings.Replace(string(good), "pve-1 <eno1>", `pve-1\u001b[31m`, 1),
		"lone surrogate":     strings.Replace(string(good), "pve-1 <eno1>", `pve-1\udc00`, 1),
		"newline in label":   strings.Replace(string(good), "pve-1 <eno1>", `a\nb`, 1),
		"oversize string":    strings.Replace(string(good), "pve-1 <eno1>", strings.Repeat("d", MaxJSONStringBytes+1), 1),
		"oversize label":     strings.Replace(string(good), "pve-1 <eno1>", strings.Repeat("d", MaxLabelBytes+1), 1),
		"null field":         strings.Replace(string(good), `"serial":"SERIAL"`, `"serial":null`, 1),
		"duplicate key":      strings.Replace(string(good), `"model"`, `"model":"a","model"`, 1),
		"bad time":           strings.Replace(string(good), `2026-11-09T12:00:00Z`, `yesterday`, 1),
		"vlan out of uint16": strings.Replace(string(good), `"access_vlan":10`, `"access_vlan":65536`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == string(good) {
				t.Fatal("test case did not modify the document")
			}
			if _, err := DecodeObservation([]byte(raw)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestObservationRejectsMalformedValues(t *testing.T) {
	cbs := map[string]func(*Observation){
		"device_id":       func(o *Observation) { o.DeviceID = "SW 1" },
		"empty device_id": func(o *Observation) { o.DeviceID = "" },
		"unknown family":  func(o *Observation) { o.Family = "pfsense" },
		"zero generation": func(o *Observation) { o.TrustGeneration = 0 },
		"zero time":       func(o *Observation) { o.ObservedAt = time.Time{} },
		"no datasets": func(o *Observation) {
			*o = Observation{DeviceID: "a", Family: FamilyCBS, TrustGeneration: 1, ObservedAt: observedAt}
		},
		"panos dataset on cbs":  func(o *Observation) { o.HitCounts = AvailableDataset([]HitCount{}) },
		"facts without model":   func(o *Observation) { o.Facts.Value.Model = "" },
		"facts bad address":     func(o *Observation) { o.Facts.Value.ManagementAddresses = []string{"switch.lab"} },
		"port name":             func(o *Observation) { o.Ports.Value[0].Name = "gi1/0/1; reload" },
		"duplicate port":        func(o *Observation) { o.Ports.Value[1].Name = o.Ports.Value[0].Name },
		"port mode":             func(o *Observation) { o.Ports.Value[0].Mode = "hybrid" },
		"access with trunk":     func(o *Observation) { o.Ports.Value[0].AllowedVLANs = []uint16{2} },
		"trunk with access":     func(o *Observation) { o.Ports.Value[1].AccessVLAN = ptr(uint16(2)) },
		"vlan 0":                func(o *Observation) { o.Ports.Value[0].AccessVLAN = ptr(uint16(0)) },
		"vlan 4095":             func(o *Observation) { o.VLANs.Value[0].ID = 4095 },
		"duplicate vlan":        func(o *Observation) { o.VLANs.Value[1].ID = 1 },
		"duplicate allowed":     func(o *Observation) { o.Ports.Value[1].AllowedVLANs = []uint16{10, 10} },
		"speed":                 func(o *Observation) { o.Ports.Value[0].SpeedMbps = ptr(uint64(MaxSpeedMbps + 1)) },
		"port description":      func(o *Observation) { o.Ports.Value[0].Description = "a\x00b" },
		"mac upper":             func(o *Observation) { o.MACTable.Value[0].MAC = "02:00:00:00:00:AB" },
		"mac dashes":            func(o *Observation) { o.MACTable.Value[0].MAC = "02-00-00-00-00-01" },
		"mac type":              func(o *Observation) { o.MACTable.Value[0].Type = "learned" },
		"duplicate mac":         func(o *Observation) { o.MACTable.Value = append(o.MACTable.Value, o.MACTable.Value[0]) },
		"lldp empty chassis":    func(o *Observation) { o.LLDPNeighbors.Value[0].ChassisID = "" },
		"lldp control":          func(o *Observation) { o.LLDPNeighbors.Value[0].SystemName = "evil\x1b]0;x\x07" },
		"lldp capability":       func(o *Observation) { o.LLDPNeighbors.Value[0].Capabilities = []LLDPCapability{"root"} },
		"lldp mgmt address":     func(o *Observation) { o.LLDPNeighbors.Value[0].ManagementAddress = "10.0.0.010" },
		"config digest":         func(o *Observation) { o.RunningConfig.Value.RedactedDigest = strings.Repeat("0", 64) },
		"config raw digest":     func(o *Observation) { o.RunningConfig.Value.RawDigest = "sha256:abc" },
		"config no lines":       func(o *Observation) { o.RunningConfig = AvailableDataset(config()) },
		"config control":        func(o *Observation) { o.RunningConfig = AvailableDataset(config("a\rb")) },
		"unavailable no reason": func(o *Observation) { o.Ports = &Dataset[[]Port]{State: Unavailable} },
		"unavailable value":     func(o *Observation) { o.Ports.State, o.Ports.Reason = Unavailable, ReasonTimeout },
	}
	for name, mutate := range cbs {
		t.Run("cbs/"+name, func(t *testing.T) {
			o := baseCBSObservation()
			mutate(&o)
			mustInvalid(t, o)
		})
	}
	panos := map[string]func(*Observation){
		"cbs dataset on panos": func(o *Observation) { o.Ports = AvailableDataset([]Port{}) },
		"startup on panos":     func(o *Observation) { o.StartupConfig = AvailableDataset(config("x")) },
		"rule name chars":      func(o *Observation) { o.FirewallPolicy.Value.SecurityRules[0].Name = "a'];<x" },
		"rule name length": func(o *Observation) {
			o.FirewallPolicy.Value.SecurityRules[0].Name = strings.Repeat("r", MaxPANOSNameBytes+1)
		},
		"rule uuid":         func(o *Observation) { o.FirewallPolicy.Value.SecurityRules[0].UUID = "NOT-A-UUID" },
		"rule action":       func(o *Observation) { o.FirewallPolicy.Value.SecurityRules[0].Action = "permit" },
		"rule zone":         func(o *Observation) { o.FirewallPolicy.Value.SecurityRules[0].From = []string{"tr/ust"} },
		"rule member empty": func(o *Observation) { o.FirewallPolicy.Value.SecurityRules[0].Source = []string{""} },
		"rule description": func(o *Observation) {
			o.FirewallPolicy.Value.SecurityRules[0].Description = strings.Repeat("d", MaxDescriptionBytes+1)
		},
		"duplicate rule": func(o *Observation) {
			p := &o.FirewallPolicy.Value
			p.SecurityRules = append(p.SecurityRules, p.SecurityRules[0])
		},
		"address value":         func(o *Observation) { o.FirewallPolicy.Value.Addresses[0].Value = "10.0.0.0/33" },
		"address range order":   func(o *Observation) { o.FirewallPolicy.Value.Addresses[1].Value = "10.0.0.20-10.0.0.10" },
		"address type":          func(o *Observation) { o.FirewallPolicy.Value.Addresses[0].Type = "ip" },
		"address group clash":   func(o *Observation) { o.FirewallPolicy.Value.AddressGroups[0].Name = "lab-net" },
		"static and dynamic":    func(o *Observation) { o.FirewallPolicy.Value.AddressGroups[1].Static = []string{"lab-net"} },
		"service dynamic":       func(o *Observation) { o.FirewallPolicy.Value.ServiceGroups[0].DynamicFilter = "'x'" },
		"service port":          func(o *Observation) { o.FirewallPolicy.Value.Services[0].Port = "70000" },
		"service port range":    func(o *Observation) { o.FirewallPolicy.Value.Services[0].Port = "90-80" },
		"service protocol":      func(o *Observation) { o.FirewallPolicy.Value.Services[0].Protocol = "icmp" },
		"group cycle":           func(o *Observation) { o.FirewallPolicy.Value.AddressGroups[0].Static = []string{"lab-all"} },
		"interface name":        func(o *Observation) { o.FirewallPolicy.Value.Interfaces[0].Name = "eth 1" },
		"interface address":     func(o *Observation) { o.FirewallPolicy.Value.Interfaces[0].Addresses = []string{"10.0.0.1/24 "} },
		"interface vlan":        func(o *Observation) { o.FirewallPolicy.Value.Interfaces[1].VLANTag = ptr(uint16(5000)) },
		"hit rule name":         func(o *Observation) { o.HitCounts.Value[0].RuleName = "" },
		"duplicate hit":         func(o *Observation) { o.HitCounts.Value[1].RuleName = o.HitCounts.Value[0].RuleName },
		"hit order":             func(o *Observation) { o.HitCounts.Value[0].LastHit = ptr(observedAt.Add(-72 * time.Hour)) },
		"hit times without hit": func(o *Observation) { o.HitCounts.Value[1].LastHit = ptr(observedAt) },
		"hit time range":        func(o *Observation) { o.HitCounts.Value[0].ResetAt = ptr(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)) },
	}
	for name, mutate := range panos {
		t.Run("panos/"+name, func(t *testing.T) {
			o := basePANOSObservation()
			fp := basePolicy()
			o.FirewallPolicy = AvailableDataset(fp)
			mutate(&o)
			mustInvalid(t, o)
		})
	}
}

func TestObservationErrorsDoNotEchoDeviceText(t *testing.T) {
	o := baseCBSObservation()
	o.Ports.Value[0].Name = "SECRET-community-string"
	o.LLDPNeighbors.Value[0].SystemName = "SECRET\x1b"
	o.RunningConfig = AvailableDataset(config("snmp-server community SECRET\x00"))
	_, err := ValidateObservation(o)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error echoes device text: %v", err)
	}
}

// limitCase builds an observation with n entries of one list.
type limitCase struct {
	name  string
	limit int
	build func(n int) Observation
}

func cbsWith(mutate func(*Observation)) Observation {
	o := Observation{DeviceID: "sw-1", Family: FamilyCBS, TrustGeneration: 1, ObservedAt: observedAt}
	mutate(&o)
	return o
}

func panosWith(mutate func(*FirewallPolicy)) Observation {
	var fp FirewallPolicy
	mutate(&fp)
	return Observation{DeviceID: "fw-1", Family: FamilyPANOS, TrustGeneration: 1, ObservedAt: observedAt, FirewallPolicy: AvailableDataset(fp)}
}

func names(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}

func groupChain(depth int) []Group {
	gs := make([]Group, depth)
	for i := range gs {
		member := "leaf"
		if i+1 < depth {
			member = fmt.Sprintf("g%d", i+1)
		}
		gs[i] = Group{Name: fmt.Sprintf("g%d", i), Static: []string{member}}
	}
	return gs
}

func limitCases() []limitCase {
	return []limitCase{
		{"interfaces per device (CBS ports)", MaxInterfacesPerDevice, func(n int) Observation {
			return cbsWith(func(o *Observation) {
				ps := make([]Port, n)
				for i := range ps {
					ps[i] = Port{Name: fmt.Sprintf("gi%d/0/%d", i/64+1, i%64+1), AdminState: LinkUp, OperState: LinkUp, Mode: ModeUnknown}
				}
				o.Ports = AvailableDataset(ps)
			})
		}},
		{"VLANs per device", MaxVLANsPerDevice, func(n int) Observation {
			return cbsWith(func(o *Observation) {
				vs := make([]VLAN, n)
				for i := range vs {
					vs[i] = VLAN{ID: uint16(i%MaxVLANID + 1)}
				}
				o.VLANs = AvailableDataset(vs)
			})
		}},
		{"allowed VLANs per port", MaxVLANsPerDevice, func(n int) Observation {
			return cbsWith(func(o *Observation) {
				vs := make([]uint16, n)
				for i := range vs {
					vs[i] = uint16(i%MaxVLANID + 1)
				}
				o.Ports = AvailableDataset([]Port{{Name: "gi1/0/1", AdminState: LinkUp, OperState: LinkUp, Mode: ModeTrunk, AllowedVLANs: vs}})
			})
		}},
		{"MAC entries per device", MaxMACEntriesPerDevice, func(n int) Observation {
			return cbsWith(func(o *Observation) {
				es := make([]MACEntry, n)
				for i := range es {
					es[i] = MACEntry{VLAN: 1, MAC: fmt.Sprintf("02:00:00:%02x:%02x:%02x", i>>16&0xff, i>>8&0xff, i&0xff), Type: MACDynamic}
				}
				o.MACTable = AvailableDataset(es)
			})
		}},
		{"LLDP neighbors per device", MaxLLDPNeighborsPerDevice, func(n int) Observation {
			return cbsWith(func(o *Observation) {
				ns := make([]LLDPNeighbor, n)
				for i := range ns {
					ns[i] = LLDPNeighbor{LocalPort: fmt.Sprintf("gi1/0/%d", i/MaxLLDPNeighborsPerPort), ChassisID: fmt.Sprint(i), PortID: "p"}
				}
				o.LLDPNeighbors = AvailableDataset(ns)
			})
		}},
		{"LLDP neighbors per port", MaxLLDPNeighborsPerPort, func(n int) Observation {
			return cbsWith(func(o *Observation) {
				ns := make([]LLDPNeighbor, n)
				for i := range ns {
					ns[i] = LLDPNeighbor{LocalPort: "gi1/0/1", ChassisID: fmt.Sprint(i), PortID: "p"}
				}
				o.LLDPNeighbors = AvailableDataset(ns)
			})
		}},
		{"CBS config lines", MaxConfigLines, func(n int) Observation {
			return cbsWith(func(o *Observation) { o.RunningConfig = AvailableDataset(config(names("l", n)...)) })
		}},
		{"PAN-OS config lines (XML elements)", MaxXMLElements, func(n int) Observation {
			o := panosWith(func(*FirewallPolicy) {})
			o.FirewallPolicy = nil
			o.RunningConfig = AvailableDataset(config(names("<e/>", n)...))
			return o
		}},
		{"security rules", MaxSecurityRules, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for _, nm := range names("r", n) {
					fp.SecurityRules = append(fp.SecurityRules, SecurityRule{Name: nm, Action: ActionAllow})
				}
			})
		}},
		{"NAT rules", MaxNATRules, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for _, nm := range names("n", n) {
					fp.NATRules = append(fp.NATRules, NATRule{Name: nm})
				}
			})
		}},
		{"address objects", MaxAddressObjects, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for _, nm := range names("a", n) {
					fp.Addresses = append(fp.Addresses, AddressObject{Name: nm, Type: AddressNetmask, Value: "10.0.0.1"})
				}
			})
		}},
		{"service objects", MaxServiceObjects, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for _, nm := range names("s", n) {
					fp.Services = append(fp.Services, ServiceObject{Name: nm, Protocol: "tcp", Port: "443"})
				}
			})
		}},
		{"address groups", MaxAddressGroups, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for _, nm := range names("ag", n) {
					fp.AddressGroups = append(fp.AddressGroups, Group{Name: nm, Static: []string{"x"}})
				}
			})
		}},
		{"service groups", MaxServiceGroups, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for _, nm := range names("sg", n) {
					fp.ServiceGroups = append(fp.ServiceGroups, Group{Name: nm, Static: []string{"x"}})
				}
			})
		}},
		{"members per group", MaxGroupMembers, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				fp.AddressGroups = []Group{{Name: "big", Static: names("m", n)}}
			})
		}},
		{"address group nesting depth", MaxGroupNestingDepth, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) { fp.AddressGroups = groupChain(n) })
		}},
		{"service group nesting depth", MaxGroupNestingDepth, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) { fp.ServiceGroups = groupChain(n) })
		}},
		{"zones", MaxZones, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for _, nm := range names("z", n) {
					fp.Zones = append(fp.Zones, Zone{Name: nm})
				}
			})
		}},
		{"interfaces (PAN-OS)", MaxFirewallInterfaces, func(n int) Observation {
			return panosWith(func(fp *FirewallPolicy) {
				for i := range n {
					fp.Interfaces = append(fp.Interfaces, FirewallInterface{Name: fmt.Sprintf("ethernet1/%d", i+1)})
				}
			})
		}},
		{"hit-count entries", MaxHitCountEntries, func(n int) Observation {
			o := panosWith(func(*FirewallPolicy) {})
			hs := make([]HitCount, n)
			for i, nm := range names("r", n) {
				hs[i] = HitCount{RuleName: nm, Hits: uint64(i)}
			}
			o.HitCounts = AvailableDataset(hs)
			return o
		}},
	}
}

// TestParseLimitsAtLimitAndOver checks every count limit enforced by the
// observation contract with exactly limit entries (accepted) and limit+1
// (rejected with ErrOverLimit).
// TestNameLengthLimitsFollowConstants ties each name rule to its named
// constant at the limit and one byte over.
func TestNameLengthLimitsFollowConstants(t *testing.T) {
	cases := []struct {
		name  string
		valid func(string) bool
		at    string
	}{
		{"PAN-OS name", ValidPANOSName, strings.Repeat("r", MaxPANOSNameBytes)},
		{"interface name", ValidInterfaceName, "e" + strings.Repeat("1", MaxInterfaceNameBytes-1)},
		{"device id", ValidDeviceID, strings.Repeat("d", MaxDeviceIDBytes)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !c.valid(c.at) {
				t.Fatalf("%d bytes rejected", len(c.at))
			}
			if c.valid(c.at + c.at[len(c.at)-1:]) {
				t.Fatalf("%d bytes accepted", len(c.at)+1)
			}
		})
	}
	if ValidPANOSName("") {
		t.Fatal("empty PAN-OS name accepted")
	}
}

func TestParseLimitsAtLimitAndOver(t *testing.T) {
	for _, c := range limitCases() {
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

func TestOverLimitRejectedWhenDecoding(t *testing.T) {
	for _, c := range limitCases() {
		if c.name != "MAC entries per device" && c.name != "security rules" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			at, err := MarshalObservation(c.build(c.limit))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeObservation(at); err != nil {
				t.Fatalf("at limit: %v", err)
			}
			// Build the limit+1 document by hand: Marshal refuses it.
			over := c.build(c.limit + 1)
			raw, err := json.Marshal(struct {
				Observation
				MACTable       any `json:"mac_table,omitempty"`
				FirewallPolicy any `json:"firewall_policy,omitempty"`
			}{over, rawDataset(over.MACTable), rawDataset(over.FirewallPolicy)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeObservation(raw); !errors.Is(err, ErrOverLimit) {
				t.Fatalf("limit+1: got %v, want ErrOverLimit", err)
			}
		})
	}
}

// rawDataset renders an available dataset without validation.
func rawDataset[T any](d *Dataset[T]) any {
	if d == nil {
		return nil
	}
	return struct {
		State Availability `json:"state"`
		Value T            `json:"value"`
	}{d.State, d.Value}
}

func TestIncompleteListWithinLimitAccepted(t *testing.T) {
	o := limitCases()[3].build(MaxMACEntriesPerDevice)
	o.MACTable.State, o.MACTable.Reason = Incomplete, ReasonOverLimit
	raw, err := MarshalObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeObservation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.MACTable.State != Incomplete || len(got.MACTable.Value) != MaxMACEntriesPerDevice {
		t.Fatalf("incomplete dataset decoded as %s with %d entries", got.MACTable.State, len(got.MACTable.Value))
	}
}

func TestConfigLineLength(t *testing.T) {
	at := cbsWith(func(o *Observation) {
		o.RunningConfig = AvailableDataset(config(strings.Repeat("a", MaxLineBytes)))
	})
	if _, err := ValidateObservation(at); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	over := cbsWith(func(o *Observation) {
		o.RunningConfig = AvailableDataset(config(strings.Repeat("a", MaxLineBytes+1)))
	})
	if _, err := ValidateObservation(over); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("limit+1: got %v, want ErrOverLimit", err)
	}
}

func TestRedactedConfigBytesLimit(t *testing.T) {
	// build returns lines of at most 4000 bytes whose joined text is
	// exactly total bytes, so only the byte limit can trip.
	build := func(total int) Observation {
		line := strings.Repeat("a", 4000)
		var lines []string
		for remaining := total; ; remaining -= len(line) + 1 {
			if remaining <= len(line) {
				lines = append(lines, line[:remaining])
				break
			}
			lines = append(lines, line)
		}
		if got := len(strings.Join(lines, "\n")); got != total {
			t.Fatalf("built %d bytes, want %d", got, total)
		}
		return Observation{DeviceID: "fw-1", Family: FamilyPANOS, TrustGeneration: 1, ObservedAt: observedAt, RunningConfig: AvailableDataset(config(lines...))}
	}
	if _, err := ValidateObservation(build(MaxRedactedConfigBytes)); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	_, err := ValidateObservation(build(MaxRedactedConfigBytes + 1))
	if !errors.Is(err, ErrOverLimit) || !strings.Contains(err.Error(), "bytes exceed") {
		t.Fatalf("limit+1: got %v, want the byte limit", err)
	}
}
