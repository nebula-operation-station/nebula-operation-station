// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Container update binding limits (container update plan, cu01). A plan over
// any of them is refused; the operator splits it into more batches.
const (
	maxContainerUpdateImages     = 20
	maxContainerUpdateContainers = 50 // targets and dependency containers together
	maxContainerUpdateOldDigests = 8
	maxContainerUpdateDeps       = maxContainerUpdateContainers
)

// Container update kinds and forms. Both are fixed by the action ID.
const (
	ContainerUpdateKindUpdate   = "update"
	ContainerUpdateKindRollback = "rollback"
	ContainerUpdateFormCompose  = "compose"
	ContainerUpdateFormAlone    = "standalone"
)

// Dependency relations of a Compose service outside the recreated set.
const (
	ContainerDependencyRequires   = "requires"
	ContainerDependencyRequiredBy = "required_by"
)

// containerUpdateActions is the fixed action table: each of these actions
// must carry exactly this kind and form, and no other action may carry a
// container update binding.
var containerUpdateActions = map[string]struct{ kind, form string }{
	"docker.compose_update":   {ContainerUpdateKindUpdate, ContainerUpdateFormCompose},
	"docker.compose_rollback": {ContainerUpdateKindRollback, ContainerUpdateFormCompose},
	"docker.update":           {ContainerUpdateKindUpdate, ContainerUpdateFormAlone},
	"docker.rollback":         {ContainerUpdateKindRollback, ContainerUpdateFormAlone},
}

// batchOnlyContainerActions are container mutations that run only as batch
// members. docker.compose_update joins in cu02, together with the change that
// replaces its classic version 1.0.0.
var batchOnlyContainerActions = map[string]bool{
	"docker.update":           true,
	"docker.rollback":         true,
	"docker.compose_rollback": true,
}

// IsBatchOnlyContainerAction reports whether actionID is a container mutation
// that classic (non-batch) permits, schedules and grants must refuse. The rule
// keys on the action ID, so a module cannot choose a name to avoid it.
func IsBatchOnlyContainerAction(actionID string) bool { return batchOnlyContainerActions[actionID] }

// IsContainerUpdateAction reports whether actionID requires a container
// update binding in a batch member.
func IsContainerUpdateAction(actionID string) bool {
	_, ok := containerUpdateActions[actionID]
	return ok
}

var (
	composeServiceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	composeProjectRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	containerNameRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	platformRe       = regexp.MustCompile(`^[a-z0-9]{1,16}/[a-z0-9_]{1,16}(/[a-z0-9]{1,16})?$`)
	policyVersionRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// BatchContainerUpdate binds one atomic recreate unit (one standalone
// container, or one Compose project with its frozen service set) for a
// container update or rollback (ADR 0006 P2-03, R5). Host, host key, SSH
// credential version and stage plan are bound by the member itself. The
// parameter document is rendered from this binding (ContainerUpdateParameters),
// so what was reviewed and what runs cannot differ.
type BatchContainerUpdate struct {
	Kind         string                      `json:"kind"`
	Form         string                      `json:"form"`
	Images       []ContainerUpdateImage      `json:"images"`
	Targets      []ContainerUpdateTarget     `json:"targets"`
	Dependencies []ContainerUpdateDependency `json:"dependencies"`
	// Compose only: what the operator's files render to at preview time
	// (keyed host-side digest, Q5), project name, and hashes of the working
	// directory and of the operator's config file paths without the NOS override.
	SourceDigest    string `json:"source_digest,omitempty"`
	Project         string `json:"project,omitempty"`
	WorkingDirHash  string `json:"working_dir_hash,omitempty"`
	ConfigFilesHash string `json:"config_files_hash,omitempty"`
	// Registry is absent for public images (private transfer: cu06).
	Registry *ContainerUpdateRegistry `json:"registry,omitempty"`
	// Standalone only (cu05): the immutable operator definition.
	DefinitionID      string `json:"definition_id,omitempty"`
	DefinitionVersion uint64 `json:"definition_version,omitempty"`
	// Rollback only (cu03): the recorded update execution and recovery plan.
	RollbackOf         string `json:"rollback_of,omitempty"`
	RecoveryPlanDigest string `json:"recovery_plan_digest,omitempty"`
}

// ContainerUpdateImage is the image transition of one recreated service
// (standalone: one entry with an empty Service). Digests and image IDs are
// "sha256:<64 hex>".
type ContainerUpdateImage struct {
	Service    string `json:"service"`
	Repository string `json:"repository"`
	Platform   string `json:"platform"`
	OldTag     string `json:"old_tag"`
	NewTag     string `json:"new_tag"`
	// OldDigests are the digests the local image lists for Repository (Q17).
	OldDigests []string `json:"old_digests"`
	// Update only.
	NewIndexDigest    string `json:"new_index_digest,omitempty"`
	NewPlatformDigest string `json:"new_platform_digest,omitempty"`
	OldImageID        string `json:"old_image_id,omitempty"`
	// Required exactly when the tags differ (R8).
	PolicyVersion string `json:"policy_version,omitempty"`
	PolicyDigest  string `json:"policy_digest,omitempty"`
	MajorChange   bool   `json:"major_change,omitempty"`
	// Rollback only: what the rollback returns to, copied from the row (cu03).
	Rollback *ContainerRollbackImage `json:"rollback,omitempty"`
}

// ContainerRollbackImage is the retained prior image of a rollback entry.
type ContainerRollbackImage struct {
	PriorImageID      string `json:"prior_image_id"`
	RetainedTag       string `json:"retained_tag"`
	RetainedReference string `json:"retained_reference"`
}

// ContainerUpdateTarget is one exact container incarnation that is recreated.
// RunningReference is the container's Config.Image, byte for byte.
// ConfigurationDigest is the host-side keyed digest of that incarnation (Q5).
type ContainerUpdateTarget struct {
	Service             string `json:"service"`
	ContainerID         string `json:"container_id"`
	ContainerName       string `json:"container_name"`
	ImageID             string `json:"image_id"`
	RunningReference    string `json:"running_reference"`
	ConfigurationDigest string `json:"configuration_digest"`
}

// ContainerUpdateDependency is a Compose service outside the recreated set
// that is connected to it (Q12). Targets and dependencies together are the
// exact affected set.
type ContainerUpdateDependency struct {
	Service         string                      `json:"service"`
	Relation        string                      `json:"relation"`
	RestartOnUpdate bool                        `json:"restart_on_update"`
	Containers      []ContainerDependencyMember `json:"containers"`
}

// ContainerDependencyMember is one frozen container of a dependency service.
type ContainerDependencyMember struct {
	ContainerID         string `json:"container_id"`
	ContainerName       string `json:"container_name"`
	ConfigurationDigest string `json:"configuration_digest"`
}

// ContainerUpdateRegistry binds the private registry record and credential
// version used for the transfer (cu06).
type ContainerUpdateRegistry struct {
	RegistryID        string `json:"registry_id"`
	RecordDigest      string `json:"record_digest"`
	CredentialID      string `json:"credential_id"`
	CredentialVersion uint64 `json:"credential_version"`
}

func cuError(format string, args ...any) error {
	return batchError("container update: "+format, args...)
}

// ContainerUpdateFloor is the risk floor a container update binding implies:
// MEDIUM when every entry keeps its tag, otherwise HIGH (R8). It trusts the
// binding's tags; cu02's phase 1 proves old_tag against the running container.
func ContainerUpdateFloor(u BatchContainerUpdate) Risk {
	for _, img := range u.Images {
		if img.OldTag != img.NewTag {
			return RiskHigh
		}
	}
	return RiskMedium
}

// ContainerUpdateParameters renders the parameter document of a container
// update member from its binding (Decision 3). Every value a script needs is a
// binding field; the member's ParametersHash must be the hash of these bytes.
func ContainerUpdateParameters(u BatchContainerUpdate) ([]byte, string, error) {
	raw, err := json.Marshal(struct {
		ContainerUpdate BatchContainerUpdate `json:"container_update"`
	}{u})
	if err != nil {
		return nil, "", fmt.Errorf("marshal container update parameters: %w", err)
	}
	return CanonicalParameters(raw)
}

func validContainerTag(s string) bool { return imageTagRe.MatchString(s) }

// normalizeContainerUpdate validates a binding for actionID and returns a
// deep copy. It is the contract half of R2, R5 and R6.
func normalizeContainerUpdate(actionID string, in BatchContainerUpdate) (BatchContainerUpdate, error) {
	want, ok := containerUpdateActions[actionID]
	if !ok {
		return BatchContainerUpdate{}, cuError("binding is not allowed on this action")
	}
	u := in
	if u.Kind != want.kind || u.Form != want.form {
		return BatchContainerUpdate{}, cuError("kind or form does not match the action")
	}
	update := u.Kind == ContainerUpdateKindUpdate
	compose := u.Form == ContainerUpdateFormCompose
	if len(u.Images) < 1 || len(u.Images) > maxContainerUpdateImages {
		return BatchContainerUpdate{}, cuError("image count must be 1..%d", maxContainerUpdateImages)
	}
	if len(u.Dependencies) > maxContainerUpdateDeps {
		return BatchContainerUpdate{}, cuError("too many dependencies")
	}
	if len(u.Targets) < 1 {
		return BatchContainerUpdate{}, cuError("no target container")
	}
	containers := len(u.Targets)
	for _, d := range u.Dependencies {
		containers += len(d.Containers)
	}
	if containers > maxContainerUpdateContainers {
		return BatchContainerUpdate{}, cuError("more than %d containers", maxContainerUpdateContainers)
	}

	// Form-specific unit identity.
	if compose {
		if !hex64.MatchString(u.SourceDigest) || !composeProjectRe.MatchString(u.Project) || !hex64.MatchString(u.WorkingDirHash) || !hex64.MatchString(u.ConfigFilesHash) {
			return BatchContainerUpdate{}, cuError("malformed compose identity")
		}
		if u.DefinitionID != "" || u.DefinitionVersion != 0 {
			return BatchContainerUpdate{}, cuError("definition binding on a compose member")
		}
	} else {
		if u.SourceDigest != "" || u.Project != "" || u.WorkingDirHash != "" || u.ConfigFilesHash != "" {
			return BatchContainerUpdate{}, cuError("compose identity on a standalone member")
		}
		if !uuidRe.MatchString(u.DefinitionID) || u.DefinitionVersion == 0 || u.DefinitionVersion > maxBatchExactInteger {
			return BatchContainerUpdate{}, cuError("standalone member needs its definition ID and version")
		}
		if len(u.Images) != 1 || u.Images[0].Service != "" || len(u.Targets) != 1 || len(u.Dependencies) != 0 {
			return BatchContainerUpdate{}, cuError("standalone member is exactly one image and one container")
		}
	}
	if update {
		if u.RollbackOf != "" || u.RecoveryPlanDigest != "" {
			return BatchContainerUpdate{}, cuError("rollback binding on an update")
		}
	} else if !uuidRe.MatchString(u.RollbackOf) || !hex64.MatchString(u.RecoveryPlanDigest) {
		return BatchContainerUpdate{}, cuError("rollback needs rollback_of and recovery_plan_digest")
	}
	if r := u.Registry; r != nil {
		if !hostIDRe.MatchString(r.RegistryID) || !hex64.MatchString(r.RecordDigest) || !credRefRe.MatchString(r.CredentialID) || r.CredentialVersion == 0 || r.CredentialVersion > maxBatchExactInteger {
			return BatchContainerUpdate{}, cuError("malformed registry binding")
		}
		reg := *r
		u.Registry = &reg
	}

	// Images: sorted by service, one entry per service.
	images := make(map[string]ContainerUpdateImage, len(u.Images))
	u.Images = slices.Clone(u.Images)
	for i, img := range u.Images {
		if compose && !composeServiceRe.MatchString(img.Service) {
			return BatchContainerUpdate{}, cuError("malformed service name")
		}
		if i > 0 && u.Images[i-1].Service >= img.Service {
			return BatchContainerUpdate{}, cuError("images must be sorted by service, one entry per service")
		}
		if err := validateContainerImage(img, update); err != nil {
			return BatchContainerUpdate{}, err
		}
		img.OldDigests = slices.Clone(img.OldDigests)
		if img.Rollback != nil {
			rb := *img.Rollback
			img.Rollback = &rb
		}
		u.Images[i] = img
		images[img.Service] = img
	}

	// Targets: sorted by (service, container_id), each with an image entry.
	ids := make(map[string]bool)
	names := make(map[string]bool)
	claim := func(id, name string) error {
		if !hex64.MatchString(id) || !containerNameRe.MatchString(name) {
			return cuError("malformed container ID or name")
		}
		if ids[id] || names[name] {
			return cuError("container appears more than once")
		}
		ids[id], names[name] = true, true
		return nil
	}
	targeted := make(map[string]bool)
	u.Targets = slices.Clone(u.Targets)
	for i, t := range u.Targets {
		if i > 0 {
			p := u.Targets[i-1]
			if p.Service > t.Service || (p.Service == t.Service && p.ContainerID >= t.ContainerID) {
				return BatchContainerUpdate{}, cuError("targets must be sorted by service and container ID")
			}
		}
		img, ok := images[t.Service]
		if !ok {
			return BatchContainerUpdate{}, cuError("target service has no image entry")
		}
		if err := claim(t.ContainerID, t.ContainerName); err != nil {
			return BatchContainerUpdate{}, err
		}
		if !validImageDigest(t.ImageID) || !hex64.MatchString(t.ConfigurationDigest) {
			return BatchContainerUpdate{}, cuError("malformed target image ID or configuration digest")
		}
		ref, err := ParseImageReference(t.RunningReference)
		if err != nil || ref.Repository != img.Repository {
			return BatchContainerUpdate{}, cuError("running reference does not name the entry's repository")
		}
		if update {
			if t.ImageID != img.OldImageID {
				return BatchContainerUpdate{}, cuError("mixed_images: target image differs from the entry's old image")
			}
			if ref.Tag != img.OldTag {
				return BatchContainerUpdate{}, cuError("running reference does not carry the entry's old tag")
			}
		}
		targeted[t.Service] = true
	}
	// On a rollback an entry may have no target: cu03 allows that only when the
	// row records every container of that service as missing.
	if update {
		for _, img := range u.Images {
			if !targeted[img.Service] {
				return BatchContainerUpdate{}, cuError("update entry has no target")
			}
		}
	}

	// Dependencies: compose only, sorted by service, outside images. An empty
	// list is explicit: no dependencies.
	u.Dependencies = slices.Clone(u.Dependencies)
	if u.Dependencies == nil {
		u.Dependencies = []ContainerUpdateDependency{}
	}
	for i, d := range u.Dependencies {
		if !composeServiceRe.MatchString(d.Service) {
			return BatchContainerUpdate{}, cuError("malformed dependency service")
		}
		if i > 0 && u.Dependencies[i-1].Service >= d.Service {
			return BatchContainerUpdate{}, cuError("dependencies must be sorted by service, one entry per service")
		}
		if _, ok := images[d.Service]; ok {
			return BatchContainerUpdate{}, cuError("service is both recreated and a dependency")
		}
		if d.Relation != ContainerDependencyRequires && d.Relation != ContainerDependencyRequiredBy {
			return BatchContainerUpdate{}, cuError("unknown dependency relation")
		}
		// A dependency without a container would be created by `up`, outside
		// the bound set; the unit is unavailable instead.
		if len(d.Containers) < 1 {
			return BatchContainerUpdate{}, cuError("dependency without containers")
		}
		d.Containers = slices.Clone(d.Containers)
		for j, c := range d.Containers {
			if j > 0 && d.Containers[j-1].ContainerID >= c.ContainerID {
				return BatchContainerUpdate{}, cuError("dependency containers must be sorted by container ID")
			}
			if err := claim(c.ContainerID, c.ContainerName); err != nil {
				return BatchContainerUpdate{}, err
			}
			if !hex64.MatchString(c.ConfigurationDigest) {
				return BatchContainerUpdate{}, cuError("malformed dependency configuration digest")
			}
		}
		u.Dependencies[i] = d
	}
	return u, nil
}

func validateContainerImage(img ContainerUpdateImage, update bool) error {
	if !validCanonicalRepository(img.Repository) {
		return cuError("repository is not in canonical form")
	}
	if !platformRe.MatchString(img.Platform) || !validContainerTag(img.OldTag) || !validContainerTag(img.NewTag) {
		return cuError("malformed platform or tag")
	}
	if len(img.OldDigests) < 1 || len(img.OldDigests) > maxContainerUpdateOldDigests {
		return cuError("old_digests must list 1..%d digests", maxContainerUpdateOldDigests)
	}
	for i, d := range img.OldDigests {
		if !validImageDigest(d) || (i > 0 && img.OldDigests[i-1] >= d) {
			return cuError("old_digests must be sorted, unique sha256 digests")
		}
	}
	sameTag := img.OldTag == img.NewTag
	if sameTag {
		if img.PolicyVersion != "" || img.PolicyDigest != "" || img.MajorChange {
			return cuError("tag policy on a same-tag entry")
		}
	} else if !policyVersionRe.MatchString(img.PolicyVersion) || !hex64.MatchString(img.PolicyDigest) {
		return cuError("tag change needs policy_version and policy_digest")
	}
	if update {
		if img.Rollback != nil {
			return cuError("rollback block on an update")
		}
		if !validImageDigest(img.NewPlatformDigest) || !validImageDigest(img.OldImageID) {
			return cuError("update needs new_platform_digest and old_image_id")
		}
		if img.NewIndexDigest != "" && (!validImageDigest(img.NewIndexDigest) || img.NewIndexDigest == img.NewPlatformDigest) {
			return cuError("malformed new_index_digest")
		}
		// An equal tag whose new digest the host already lists would recreate
		// for nothing.
		if sameTag && (slices.Contains(img.OldDigests, img.NewPlatformDigest) || (img.NewIndexDigest != "" && slices.Contains(img.OldDigests, img.NewIndexDigest))) {
			return cuError("same-tag entry does not change the image")
		}
		return nil
	}
	if img.NewIndexDigest != "" || img.NewPlatformDigest != "" || img.OldImageID != "" {
		return cuError("rollback pulls nothing: new digests and old_image_id must be empty")
	}
	rb := img.Rollback
	if rb == nil || !validImageDigest(rb.PriorImageID) || !validContainerTag(rb.RetainedTag) {
		return cuError("rollback needs prior_image_id and retained_tag")
	}
	ref, err := ParseImageReference(rb.RetainedReference)
	if err != nil || ref.Repository != img.Repository || strings.ContainsAny(rb.RetainedReference, " \t") {
		return cuError("retained_reference does not name the entry's repository")
	}
	return nil
}
