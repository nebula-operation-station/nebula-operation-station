// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import "time"

// ReadFormat identifies read grants with approval-bound rate profile
// and SSH credential versions. It never identifies a legacy schedule grant.
const ReadFormat = "read-grant-v2"

// OrdinaryReadProfile retains the 15-minute action floor and 24/240 run budgets.
const OrdinaryReadProfile = "ordinary"

// TelemetryReadProfile permits only the reviewed SSH telemetry observations.
// Scheduled runs collect history; on-demand runs collect live observations.
const TelemetryReadProfile = "telemetry"

// Telemetry profile limits are enforced in addition to the approved interval
// and aggregate host budget. Longer approved intervals always take precedence.
const (
	// TelemetryLiveInterval is the minimum interval for on-demand live reads.
	TelemetryLiveInterval = 10 * time.Second
	// TelemetryHistoryInterval is the minimum interval for scheduled history.
	TelemetryHistoryInterval = 5 * time.Minute
	// MaxTelemetryRunBudget caps the aggregate runs per host per rolling hour.
	MaxTelemetryRunBudget = 4096
)

// IsTelemetryAction reports whether actionID has a reviewed fast-read contract.
// Scans, logs, mutations and arbitrary commands never gain telemetry authority.
func IsTelemetryAction(actionID string) bool {
	switch actionID {
	case "host.metrics", "filesystem.list", "pci.inventory", "gpu.status", "docker.stats":
		return true
	default:
		return false
	}
}

// ReadCredential binds one frozen target to its SSH credential reference and
// version. CredentialVersion is the SHA-256 SSH public-key fingerprint: key
// replacement under the same reference requires a newly approved grant.
type ReadCredential struct {
	// HostID names one host in the grant's frozen target list.
	HostID string `json:"host_id"`
	// CredentialRef names the executor's SSH credential for this host.
	CredentialRef string `json:"credential_ref"`
	// CredentialVersion is the exact SSH public-key SHA-256 fingerprint.
	CredentialVersion string `json:"credential_version"`
}

// NetDeviceReadProfile is the read-grant-v2 rate profile of a device read
// lease (ADR 0010 D4, ND-13): typed reads of exact network devices under
// the ADR 0007 read-grant mechanism. It binds no SSH actions, hosts or
// provider remotes, and it never authorizes a change.
const NetDeviceReadProfile = "netdevice"

// Device read lease limits (ADR 0010 D4): the ADR 0007 ordinary floor and
// budgets apply unchanged. The budget counts reads per device per rolling
// hour across all reads.
const (
	// NetDeviceMinInterval is the 15-minute floor between two reads of one
	// typed read on one device.
	NetDeviceMinInterval = MinInterval
	// NetDeviceDefaultRunBudget is the default per-device rolling-hour budget.
	NetDeviceDefaultRunBudget = 24
	// NetDeviceMaxRunBudget bounds the per-device rolling-hour budget.
	NetDeviceMaxRunBudget = 240
)

// Typed network device reads (ADR 0010 D4). The names are the lowercase
// suffixes of the executor's NetDeviceRead enum (ND-12), one to one; the
// prefix names the device family. The set is closed and read-only: no
// name here maps to a configuration change, commit or save.
const (
	NetDeviceReadCBSVersion         = "cbs_version"
	NetDeviceReadCBSVLANs           = "cbs_vlans"
	NetDeviceReadCBSInterfaces      = "cbs_interfaces"
	NetDeviceReadCBSMACTable        = "cbs_mac_table"
	NetDeviceReadCBSLLDP            = "cbs_lldp"
	NetDeviceReadPANOSZones         = "panos_zones"
	NetDeviceReadPANOSObjects       = "panos_objects"
	NetDeviceReadPANOSSecurityRules = "panos_security_rules"
	NetDeviceReadPANOSNATRules      = "panos_nat_rules"
	NetDeviceReadPANOSRuleHitCounts = "panos_rule_hit_counts"
	netDeviceFamilyCBS              = "cbs"
	netDeviceFamilyPANOS            = "panos"
)

var netDeviceReads = []struct{ name, family string }{
	{NetDeviceReadCBSVersion, netDeviceFamilyCBS},
	{NetDeviceReadCBSVLANs, netDeviceFamilyCBS},
	{NetDeviceReadCBSInterfaces, netDeviceFamilyCBS},
	{NetDeviceReadCBSMACTable, netDeviceFamilyCBS},
	{NetDeviceReadCBSLLDP, netDeviceFamilyCBS},
	{NetDeviceReadPANOSZones, netDeviceFamilyPANOS},
	{NetDeviceReadPANOSObjects, netDeviceFamilyPANOS},
	{NetDeviceReadPANOSSecurityRules, netDeviceFamilyPANOS},
	{NetDeviceReadPANOSNATRules, netDeviceFamilyPANOS},
	{NetDeviceReadPANOSRuleHitCounts, netDeviceFamilyPANOS},
}

// NetDeviceReads returns a copy of the closed list of typed device reads.
func NetDeviceReads() []string {
	out := make([]string, 0, len(netDeviceReads))
	for _, r := range netDeviceReads {
		out = append(out, r.name)
	}
	return out
}

// IsNetDeviceRead reports whether name is one of the typed device reads.
func IsNetDeviceRead(name string) bool { return NetDeviceReadFamily(name) != "" }

// NetDeviceReadFamily returns the device family ("cbs" or "panos") of a
// typed device read, or "" if name is not one.
func NetDeviceReadFamily(name string) string {
	for _, r := range netDeviceReads {
		if r.name == name {
			return r.family
		}
	}
	return ""
}
