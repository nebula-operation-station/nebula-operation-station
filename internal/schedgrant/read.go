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
