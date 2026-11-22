// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

// Suggestion families (ADR 0016 D4). A family groups the actions the ops
// agent may suggest; read-only actions belong to no family.
const (
	FamilyOSUpdate         = "os-update"
	FamilyReboot           = "reboot"
	FamilyServiceRestart   = "service-restart"
	FamilyContainerUpdate  = "container-update"
	FamilyContainerRestart = "container-restart"
)

// suggestionAllowlist maps each action the agent may suggest to its family.
// It is code, not configuration: adding an action is a reviewed change. An
// action that is not in the NOS catalog at projection time is dropped.
var suggestionAllowlist = map[string]string{
	"package.install_security": FamilyOSUpdate,
	"package.install_all":      FamilyOSUpdate,
	"system.reboot":            FamilyReboot,
	"service.restart":          FamilyServiceRestart,
	"docker.compose_update":    FamilyContainerUpdate,
	"docker.update":            FamilyContainerUpdate,
	"docker.restart":           FamilyContainerRestart,
}

// MaxCandidateLabelBytes bounds a fixed label. It mirrors
// prompt.MaxCandidateLabelBytes, which the agent enforces; a test in
// internal/web/api checks that every label fits it.
const MaxCandidateLabelBytes = 200

// suggestionLabels is the fixed NOS label of each allowlisted action: the
// text the agent shows the model next to the candidate key (ADR 0016 D4). It
// is code, never input data, and it is plain text without a URL. It has one
// entry per allowlisted action and nothing else.
var suggestionLabels = map[string]string{
	"package.install_security": "Install security updates",
	"package.install_all":      "Install all updates",
	"system.reboot":            "Reboot the host",
	"service.restart":          "Restart the service",
	"docker.compose_update":    "Update the Compose project",
	"docker.update":            "Update the standalone container",
	"docker.restart":           "Restart the container",
}

// Families returns the family of a suggestable action. ok is false for an
// action that is not on the allowlist, including every read-only action.
// The validator of a suggestion uses it to check that an action belongs to
// the family the candidate was offered under.
func Families(action string) (family string, ok bool) {
	family, ok = suggestionAllowlist[action]
	return family, ok
}

// Label returns the fixed NOS label of a suggestable action. ok is false for
// an action without a label; such an action never becomes a candidate.
func Label(action string) (label string, ok bool) {
	label, ok = suggestionLabels[action]
	return label, ok
}
