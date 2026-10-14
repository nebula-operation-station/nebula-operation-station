// SPDX-License-Identifier: AGPL-3.0-or-later

// Package actions is the server's catalog of built-in actions. Their
// scripts are embedded in the binary; the executor sees only their bytes
// and hashes them itself. Built-in scripts are not executor-trusted unless
// the admin trusts them (`nebula artifact trust`), so the executor's
// minimum risk for them is usually HIGH (spec 10).
package actions

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Action is one runnable action.
type Action struct {
	ID          string
	Version     string
	Title       string
	Description string
	// Risk is the declared risk; the executor may require more.
	Risk     pb.RiskClass
	Durable  bool
	Timeout  time.Duration
	ReadOnly bool
	Script   []byte
}

// SHA256 is the hex digest of the script.
func (a Action) SHA256() string {
	s := sha256.Sum256(a.Script)
	return hex.EncodeToString(s[:])
}

//go:embed scripts/core_facts.sh
var coreFacts []byte

//go:embed scripts/package_list_updates.sh
var packageListUpdates []byte

//go:embed scripts/package_refresh.sh
var packageRefresh []byte

//go:embed scripts/package_install.sh.tmpl
var packageInstallTemplate string

// installScript renders the install template for one mode.
func installScript(mode string) []byte {
	return []byte(strings.ReplaceAll(packageInstallTemplate, "@MODE@", mode))
}

// Builtin lists the built-in actions in display order.
var Builtin = []Action{
	{
		ID: "core.facts", Version: "1.0.0", Title: "Collect facts",
		Description: "Reads /etc/os-release, kernel, hostname, uptime and whether the host is a Proxmox VE node. Read-only.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: 30 * time.Second, ReadOnly: true, Script: coreFacts,
	},
	{
		ID: "package.list_updates", Version: "1.0.0", Title: "Check updates",
		Description: "Lists pending package updates (security, other, kernel) and whether a reboot is required, from the host's current package lists. Read-only (apt simulation, no root).",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: 2 * time.Minute, ReadOnly: true, Script: packageListUpdates,
	},
	{
		ID: "package.refresh", Version: "1.0.0", Title: "Refresh package lists",
		Description: "Runs apt-get update (with sudo). Changes only the package lists; waits up to 8 minutes for the apt lock.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: 10 * time.Minute, Script: packageRefresh,
	},
	{
		ID: "package.install_security", Version: "1.0.0", Title: "Install security updates",
		Description: "Installs the packages whose new version comes from the security archive (apt-get install --only-upgrade), as a durable job. Prechecks: free space, dpkg state, writable disk; postchecks: dpkg state, reboot required, newly failed units. No reboot.",
		Risk:        pb.RiskClass_RISK_CLASS_MEDIUM, Durable: true, Timeout: time.Hour, Script: installScript("install_security"),
	},
	{
		ID: "package.install_all", Version: "1.0.0", Title: "Install all updates",
		Description: "apt-get upgrade (full-upgrade on Proxmox VE), as a durable job, with the same pre- and postchecks. No reboot.",
		Risk:        pb.RiskClass_RISK_CLASS_MEDIUM, Durable: true, Timeout: 2 * time.Hour, Script: installScript("install_all"),
	},
}

// Lookup returns the built-in action id.
func Lookup(id string) (Action, bool) {
	for _, a := range Builtin {
		if a.ID == id {
			return a, true
		}
	}
	return Action{}, false
}
