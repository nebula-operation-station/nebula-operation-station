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
	"fmt"
	"regexp"
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
	// Params are the action's parameters, all required.
	Params []Param
	// Retry is the spec 07 retry class.
	Retry RetryClass
}

// RetryClass says what may happen after a host run that did not finish
// (spec 07).
type RetryClass string

// Retry classes.
const (
	// RetrySafe: idempotent reads; a run that never reached the host is
	// retried automatically with the same permit.
	RetrySafe RetryClass = "safe"
	// RetryReconcileFirst: the outcome is reconciled from the host (durable
	// jobs) before anything runs again; never retried automatically.
	RetryReconcileFirst RetryClass = "reconcile-first"
	// RetryNever: never retried automatically; plan a new operation.
	RetryNever RetryClass = "never"
)

// Param is one string parameter with a strict pattern (scripts read it
// from the canonical JSON with an equally strict pattern).
type Param struct {
	Name    string
	Label   string
	Pattern *regexp.Regexp
}

// unitRe is a systemd unit name: no leading '-' (option injection), no
// spaces, quotes or slashes.
var unitRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,199}$`)

var unitParam = []Param{{Name: "unit", Label: "Unit (e.g. nginx.service)", Pattern: unitRe}}

// containerRe is a Docker container name or ID: no leading '-', no
// spaces, quotes or slashes.
var containerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

var containerParam = []Param{{Name: "container", Label: "Container (name or ID)", Pattern: containerRe}}

// ValidParams checks params against the action's parameters.
func (a Action) ValidParams(params map[string]string) error {
	if len(params) != len(a.Params) {
		return fmt.Errorf("%s takes %d parameters", a.ID, len(a.Params))
	}
	for _, p := range a.Params {
		v, ok := params[p.Name]
		if !ok {
			return fmt.Errorf("parameter %s is required", p.Name)
		}
		if !p.Pattern.MatchString(v) {
			return fmt.Errorf("parameter %s is not valid", p.Name)
		}
	}
	return nil
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

//go:embed scripts/system_reboot.sh
var systemReboot []byte

//go:embed scripts/service_list.sh
var serviceList []byte

//go:embed scripts/service_status.sh
var serviceStatus []byte

//go:embed scripts/docker_list.sh
var dockerList []byte

//go:embed scripts/docker_logs.sh
var dockerLogs []byte

//go:embed scripts/docker_inspect.sh
var dockerInspect []byte

//go:embed scripts/service_control.sh.tmpl
var serviceControlTemplate string

func serviceScript(verb string) []byte {
	return []byte(strings.ReplaceAll(serviceControlTemplate, "@VERB@", verb))
}

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
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: 30 * time.Second, ReadOnly: true, Script: coreFacts, Retry: RetrySafe,
	},
	{
		ID: "package.list_updates", Version: "1.0.0", Title: "Check updates",
		Description: "Lists pending package updates (security, other, kernel) and whether a reboot is required, from the host's current package lists. Read-only (apt simulation, no root).",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: 2 * time.Minute, ReadOnly: true, Script: packageListUpdates, Retry: RetrySafe,
	},
	{
		ID: "package.refresh", Version: "1.0.0", Title: "Refresh package lists",
		Description: "Runs apt-get update (with sudo). Changes only the package lists; waits up to 8 minutes for the apt lock.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: 10 * time.Minute, Script: packageRefresh, Retry: RetrySafe,
	},
	{
		ID: "package.install_security", Version: "1.0.0", Title: "Install security updates",
		Description: "Installs the packages whose new version comes from the security archive (apt-get install --only-upgrade), as a durable job. Prechecks: free space, dpkg state, writable disk; postchecks: dpkg state, reboot required, newly failed units. No reboot.",
		Risk:        pb.RiskClass_RISK_CLASS_MEDIUM, Durable: true, Timeout: time.Hour, Script: installScript("install_security"), Retry: RetryReconcileFirst,
	},
	{
		ID: "package.install_all", Version: "1.0.0", Title: "Install all updates",
		Description: "apt-get upgrade (full-upgrade on Proxmox VE), as a durable job, with the same pre- and postchecks. No reboot.",
		Risk:        pb.RiskClass_RISK_CLASS_MEDIUM, Durable: true, Timeout: 2 * time.Hour, Script: installScript("install_all"), Retry: RetryReconcileFirst,
	},
	{
		ID: "system.reboot", Version: "1.0.0", Title: "Reboot",
		Description: "Reboots the host (15 seconds after the job is stored) and waits until it is back with a new boot ID; after 20 minutes the result is host_not_returned.",
		Risk:        pb.RiskClass_RISK_CLASS_HIGH, Durable: true, Timeout: 20 * time.Minute, Script: systemReboot, Retry: RetryReconcileFirst,
	},
	{
		ID: "service.list", Version: "1.0.0", Title: "List services",
		Description: "Lists the systemd service units and their state. Read-only.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: time.Minute, ReadOnly: true, Script: serviceList, Retry: RetrySafe,
	},
	{
		ID: "service.status", Version: "1.0.0", Title: "Service status",
		Description: "State of one unit and its last 50 journal lines (journal via sudo when needed). Read-only.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: time.Minute, ReadOnly: true, Script: serviceStatus, Params: unitParam, Retry: RetrySafe,
	},
	{
		ID: "service.restart", Version: "1.0.0", Title: "Restart service", Description: "systemctl restart of one unit (sudo).",
		Risk: pb.RiskClass_RISK_CLASS_MEDIUM, Timeout: 3 * time.Minute, Script: serviceScript("restart"), Params: unitParam, Retry: RetryNever,
	},
	{
		ID: "service.start", Version: "1.0.0", Title: "Start service", Description: "systemctl start of one unit (sudo).",
		Risk: pb.RiskClass_RISK_CLASS_MEDIUM, Timeout: 3 * time.Minute, Script: serviceScript("start"), Params: unitParam, Retry: RetryNever,
	},
	{
		ID: "service.stop", Version: "1.0.0", Title: "Stop service", Description: "systemctl stop of one unit (sudo).",
		Risk: pb.RiskClass_RISK_CLASS_MEDIUM, Timeout: 3 * time.Minute, Script: serviceScript("stop"), Params: unitParam, Retry: RetryNever,
	},
	{
		ID: "service.reload", Version: "1.0.0", Title: "Reload service", Description: "systemctl reload of one unit (sudo).",
		Risk: pb.RiskClass_RISK_CLASS_MEDIUM, Timeout: 3 * time.Minute, Script: serviceScript("reload"), Params: unitParam, Retry: RetryNever,
	},
	{
		ID: "docker.list", Version: "1.0.0", Title: "List containers",
		Description: "Lists all Docker containers with image, state, health, published ports and Compose project (docker group or sudo). A host without Docker reports that. Read-only.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: time.Minute, ReadOnly: true, Script: dockerList, Retry: RetrySafe,
	},
	{
		ID: "docker.logs", Version: "1.0.0", Title: "Container logs",
		Description: "State and the last 100 log lines (stdout and stderr, with timestamps) of one container. Read-only.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: time.Minute, ReadOnly: true, Script: dockerLogs, Params: containerParam, Retry: RetrySafe,
	},
	{
		ID: "docker.inspect", Version: "1.0.0", Title: "Container details",
		Description: "Image and digest, state, restart policy, health, mounts, published ports and networks of one container. Environment, command line and labels are not read. Read-only.",
		Risk:        pb.RiskClass_RISK_CLASS_LOW, Timeout: time.Minute, ReadOnly: true, Script: dockerInspect, Params: containerParam, Retry: RetrySafe,
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
