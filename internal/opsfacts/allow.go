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

// Families returns the family of a suggestable action. ok is false for an
// action that is not on the allowlist, including every read-only action.
// The validator of a suggestion uses it to check that an action belongs to
// the family the candidate was offered under.
func Families(action string) (family string, ok bool) {
	family, ok = suggestionAllowlist[action]
	return family, ok
}
