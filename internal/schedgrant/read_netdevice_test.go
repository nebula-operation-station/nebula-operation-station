// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import (
	"slices"
	"testing"
	"time"
)

func TestNetDeviceReadsAreTheClosedND12Set(t *testing.T) {
	want := []string{
		"cbs_version", "cbs_vlans", "cbs_interfaces", "cbs_mac_table", "cbs_lldp",
		"panos_zones", "panos_objects", "panos_security_rules", "panos_nat_rules", "panos_rule_hit_counts",
	}
	if got := NetDeviceReads(); !slices.Equal(got, want) {
		t.Fatalf("NetDeviceReads() = %v, want %v", got, want)
	}
	for _, r := range want {
		if !IsNetDeviceRead(r) {
			t.Errorf("%s not accepted", r)
		}
	}
	for _, r := range []string{"", "CBS_VERSION", "cbs_version ", "unspecified", "cbs_set_vlan", "panos_commit",
		"cbs_write_memory", "cbs_copy_running_startup", "panos_config_set", "nodes", "core.facts"} {
		if IsNetDeviceRead(r) {
			t.Errorf("%q accepted", r)
		}
	}
	// The returned slice is a copy: callers cannot widen the closed set.
	got := NetDeviceReads()
	got[0] = "panos_commit"
	if IsNetDeviceRead("panos_commit") {
		t.Fatal("closed set mutated through NetDeviceReads")
	}
}

func TestNetDeviceProfileLimitsMatchOrdinary(t *testing.T) {
	if NetDeviceReadProfile != "netdevice" {
		t.Fatalf("profile %q", NetDeviceReadProfile)
	}
	if NetDeviceMinInterval != 15*time.Minute {
		t.Fatalf("floor %v", NetDeviceMinInterval)
	}
	if NetDeviceDefaultRunBudget != 24 || NetDeviceMaxRunBudget != 240 {
		t.Fatalf("budgets %d/%d", NetDeviceDefaultRunBudget, NetDeviceMaxRunBudget)
	}
}

func TestNetDeviceReadFamily(t *testing.T) {
	for r, fam := range map[string]string{"cbs_lldp": "cbs", "panos_zones": "panos", "nope": "", "cbs_set_vlan": ""} {
		if got := NetDeviceReadFamily(r); got != fam {
			t.Errorf("NetDeviceReadFamily(%q) = %q, want %q", r, got, fam)
		}
	}
}
