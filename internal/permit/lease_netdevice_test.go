// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

const (
	netdevPinA = "3333333333333333333333333333333333333333333333333333333333333333"
	netdevPinB = "4444444444444444444444444444444444444444444444444444444444444444"
)

func netDeviceDocAt(now time.Time, lifetime time.Duration) ReadGrantDoc {
	return ReadGrantDoc{
		Grant: ReadGrantFormat, ID: rgID, Issuer: "root",
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(lifetime).Unix(),
		Trigger: TriggerBoth, MinIntervalS: 900, RunBudget: schedgrant.NetDeviceDefaultRunBudget,
		RateProfile: schedgrant.NetDeviceReadProfile,
		NetDeviceTargets: []NetDeviceTarget{
			{DeviceID: "sw-core-1", TrustPin: netdevPinA, TrustGeneration: 1, CredentialVersion: 1,
				Reads: []string{"cbs_version", "cbs_vlans", "cbs_interfaces", "cbs_mac_table", "cbs_lldp"}},
			{DeviceID: "fw-1", TrustPin: netdevPinB, TrustGeneration: 3, CredentialVersion: 2,
				Reads: []string{"panos_zones", "panos_rule_hit_counts"}},
		},
	}
}

// cloneNetDeviceDoc deep-copies the targets so table cases cannot leak.
func cloneNetDeviceDoc(d ReadGrantDoc) ReadGrantDoc {
	ts := make([]NetDeviceTarget, len(d.NetDeviceTargets))
	for i, t := range d.NetDeviceTargets {
		t.Reads = append([]string(nil), t.Reads...)
		ts[i] = t
	}
	d.NetDeviceTargets = ts
	return d
}

func TestNetDeviceGrantParses(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, lifetime := range []time.Duration{DefaultReadGrantLifetime, ReadGrantMaxLifetime} {
		d := netDeviceDocAt(now, lifetime)
		doc, canon, digest, err := ParseReadGrant(readGrantRaw(t, d), now)
		if err != nil {
			t.Fatalf("valid netdevice grant (%v) rejected: %v", lifetime, err)
		}
		if len(canon) == 0 || len(digest) != 64 || len(doc.NetDeviceTargets) != 2 {
			t.Fatalf("unexpected parse result %+v %q", doc, digest)
		}
		if !bytes.Contains(canon, []byte(`"netdevice_targets":[{"credential_version":1,"device_id":"sw-core-1"`)) {
			t.Fatalf("canonical form lacks the bound device: %s", canon)
		}
	}
	// Every trigger is allowed: configuration reads run on demand (ADR 0010 D4).
	for _, trig := range []string{TriggerScheduled, TriggerOnDemand, TriggerBoth} {
		d := netDeviceDocAt(now, DefaultReadGrantLifetime)
		d.Trigger = trig
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
			t.Fatalf("trigger %s rejected: %v", trig, err)
		}
	}
	// Boundaries that must still be accepted.
	d := netDeviceDocAt(now, DefaultReadGrantLifetime)
	d.RunBudget = schedgrant.NetDeviceMaxRunBudget
	d.NetDeviceTargets[0].TrustGeneration = 1 << 48
	d.NetDeviceTargets[0].CredentialVersion = 1<<53 - 1
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("boundary netdevice grant rejected: %v", err)
	}
}

func TestNetDeviceGrantRejectsInvalidFields(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	ordinary := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	provider := providerDocAt(now, rgID, 240)
	cases := map[string]func(d *ReadGrantDoc){
		"ssh action":             func(d *ReadGrantDoc) { d.Actions = ordinary.Actions },
		"ssh target":             func(d *ReadGrantDoc) { d.Targets = ordinary.Targets },
		"ssh credential":         func(d *ReadGrantDoc) { d.Credentials = ordinary.Credentials },
		"provider target":        func(d *ReadGrantDoc) { d.ProviderTargets = provider.ProviderTargets },
		"interval below floor":   func(d *ReadGrantDoc) { d.MinIntervalS = 899 },
		"interval above max":     func(d *ReadGrantDoc) { d.MinIntervalS = int64(schedgrant.MaxInterval/time.Second) + 1 },
		"budget zero":            func(d *ReadGrantDoc) { d.RunBudget = 0 },
		"budget above max":       func(d *ReadGrantDoc) { d.RunBudget = schedgrant.NetDeviceMaxRunBudget + 1 },
		"validity 31 days":       func(d *ReadGrantDoc) { d.ExpiryUnix = d.CreatedUnix + int64(31*24*time.Hour/time.Second) },
		"validity under an hour": func(d *ReadGrantDoc) { d.ExpiryUnix = d.CreatedUnix + 3599 },
		"no devices":             func(d *ReadGrantDoc) { d.NetDeviceTargets = nil },
		"empty device id":        func(d *ReadGrantDoc) { d.NetDeviceTargets[0].DeviceID = "" },
		"uppercase device id":    func(d *ReadGrantDoc) { d.NetDeviceTargets[0].DeviceID = "SW-1" },
		"device id with space":   func(d *ReadGrantDoc) { d.NetDeviceTargets[0].DeviceID = "sw 1" },
		"device id too long":     func(d *ReadGrantDoc) { d.NetDeviceTargets[0].DeviceID = strings.Repeat("a", 65) },
		"empty pin":              func(d *ReadGrantDoc) { d.NetDeviceTargets[0].TrustPin = "" },
		"short pin":              func(d *ReadGrantDoc) { d.NetDeviceTargets[0].TrustPin = "abc" },
		"uppercase pin":          func(d *ReadGrantDoc) { d.NetDeviceTargets[0].TrustPin = strings.ToUpper(strings.Repeat("ab", 32)) },
		"generation zero":        func(d *ReadGrantDoc) { d.NetDeviceTargets[0].TrustGeneration = 0 },
		"generation too large":   func(d *ReadGrantDoc) { d.NetDeviceTargets[0].TrustGeneration = 1<<48 + 1 },
		"credential version 0":   func(d *ReadGrantDoc) { d.NetDeviceTargets[0].CredentialVersion = 0 },
		"credential version <0":  func(d *ReadGrantDoc) { d.NetDeviceTargets[0].CredentialVersion = -1 },
		"credential version big": func(d *ReadGrantDoc) { d.NetDeviceTargets[0].CredentialVersion = 1 << 53 },
		"no reads":               func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = nil },
		"empty reads":            func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{} },
		"unknown read":           func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{"cbs_show_tech"} },
		"enum spelling":          func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{"CBS_VERSION"} },
		"unspecified read":       func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{"unspecified"} },
		"change method cbs":      func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{"cbs_set_vlan"} },
		"change method panos":    func(d *ReadGrantDoc) { d.NetDeviceTargets[1].Reads = []string{"panos_commit"} },
		"provider method":        func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{ProviderMethodNodes} },
		"ssh action as read":     func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{"core.facts"} },
		"duplicate read":         func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{"cbs_lldp", "cbs_lldp"} },
		"mixed families":         func(d *ReadGrantDoc) { d.NetDeviceTargets[0].Reads = []string{"cbs_lldp", "panos_zones"} },
		"duplicate device": func(d *ReadGrantDoc) {
			d.NetDeviceTargets = append(d.NetDeviceTargets, d.NetDeviceTargets[0])
		},
		"too many devices": func(d *ReadGrantDoc) {
			for i := 0; i < MaxNetDeviceTargets; i++ {
				t := d.NetDeviceTargets[0]
				t.DeviceID = "sw-x" + strings.Repeat("a", i+1)
				d.NetDeviceTargets = append(d.NetDeviceTargets, t)
			}
		},
		"legacy v1 format": func(d *ReadGrantDoc) { d.Grant = "read-grant-v1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := cloneNetDeviceDoc(netDeviceDocAt(now, DefaultReadGrantLifetime))
			mutate(&d)
			if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
				t.Fatal("malformed netdevice grant accepted")
			}
		})
	}
}

func TestOtherProfilesRefuseNetDeviceTargets(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	dev := netDeviceDocAt(now, DefaultReadGrantLifetime).NetDeviceTargets
	for _, profile := range []string{schedgrant.OrdinaryReadProfile, schedgrant.TelemetryReadProfile} {
		d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
		d.RateProfile = profile
		if profile == schedgrant.TelemetryReadProfile {
			d.Actions[0].ActionID = "host.metrics"
		}
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
			t.Fatalf("%s baseline rejected: %v", profile, err)
		}
		d.NetDeviceTargets = dev
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
			t.Fatalf("%s grant accepted netdevice targets", profile)
		}
	}
	for _, profile := range []string{ProviderReadProfile, ProviderTelemetryProfile} {
		d := providerDocAt(now, rgID, 240)
		d.RateProfile = profile
		d.NetDeviceTargets = dev
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
			t.Fatalf("%s grant accepted netdevice targets", profile)
		}
	}
	// A netdevice grant with an unknown or empty profile is not a netdevice grant.
	for _, profile := range []string{"", "NetDevice", "netdevices"} {
		d := netDeviceDocAt(now, DefaultReadGrantLifetime)
		d.RateProfile = profile
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
			t.Fatalf("profile %q accepted with netdevice targets", profile)
		}
	}
}

func TestNetDeviceGrantStrictJSON(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	good := string(readGrantRaw(t, netDeviceDocAt(now, DefaultReadGrantLifetime)))
	if _, _, _, err := ParseReadGrant([]byte(good), now); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	mutations := map[string]string{
		"duplicate top-level key": strings.Replace(good, `"rate_profile":"netdevice"`, `"rate_profile":"netdevice","rate_profile":"netdevice"`, 1),
		"duplicate target key":    strings.Replace(good, `"device_id":"sw-core-1"`, `"device_id":"sw-core-1","device_id":"sw-core-1"`, 1),
		"duplicate key overrides": strings.Replace(good, `"device_id":"sw-core-1"`, `"device_id":"sw-core-1","device_id":"sw-core-2"`, 1),
		"unknown target field":    strings.Replace(good, `"device_id":"sw-core-1"`, `"device_id":"sw-core-1","change":true`, 1),
		"unknown methods field":   strings.Replace(good, `"device_id":"sw-core-1"`, `"device_id":"sw-core-1","methods":["cbs_set_vlan"]`, 1),
		"case-folded member":      strings.Replace(good, `"device_id":"sw-core-1"`, `"Device_ID":"sw-core-1"`, 1),
		"nested too deep":         strings.Replace(good, `"device_id":"sw-core-1"`, `"device_id":"sw-core-1","x":`+strings.Repeat("[", 40)+strings.Repeat("]", 40), 1),
		"read as object":          strings.Replace(good, `"reads":["cbs_version"`, `"reads":[{"name":"cbs_version"}`, 1),
		"trailing data":           good + `{}`,
	}
	for name, raw := range mutations {
		t.Run(name, func(t *testing.T) {
			if raw == good {
				t.Fatal("mutation did not apply")
			}
			if _, _, _, err := ParseReadGrant([]byte(raw), now); err == nil {
				t.Fatal("malformed netdevice grant accepted")
			}
		})
	}
}

func TestNetDeviceTargetLookup(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	doc, _, _, err := ParseReadGrant(readGrantRaw(t, netDeviceDocAt(now, DefaultReadGrantLifetime)), now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := doc.NetDeviceTarget("fw-1")
	if !ok || got.TrustPin != netdevPinB || got.TrustGeneration != 3 || got.CredentialVersion != 2 || len(got.Reads) != 2 {
		t.Fatalf("NetDeviceTarget(fw-1) = %+v, %v", got, ok)
	}
	for _, id := range []string{"", "fw-2", "FW-1", "sw-core"} {
		if _, ok := doc.NetDeviceTarget(id); ok {
			t.Fatalf("NetDeviceTarget(%q) found a target", id)
		}
	}
	if !got.AllowsRead("panos_rule_hit_counts") || got.AllowsRead("panos_nat_rules") || got.AllowsRead("cbs_lldp") {
		t.Fatalf("AllowsRead does not follow the bound reads: %v", got.Reads)
	}
}

func TestNetDeviceGrantCloneIsDeep(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	doc := netDeviceDocAt(now, DefaultReadGrantLifetime)
	c := cloneReadGrantDoc(doc)
	c.NetDeviceTargets[0].Reads[0] = "panos_commit"
	c.NetDeviceTargets[1].DeviceID = "other"
	if doc.NetDeviceTargets[0].Reads[0] != "cbs_version" || doc.NetDeviceTargets[1].DeviceID != "fw-1" {
		t.Fatal("cloneReadGrantDoc shares netdevice targets")
	}
}
