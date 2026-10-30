// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

// ReadFormat identifies ordinary read grants with approval-bound rate profile
// and SSH credential versions. It never identifies a legacy schedule grant.
const ReadFormat = "read-grant-v2"

// OrdinaryReadProfile retains the 15-minute action floor and 24/240 run budgets.
const OrdinaryReadProfile = "ordinary"

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
