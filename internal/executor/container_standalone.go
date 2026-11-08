// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/containerdef"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Standalone container members (ADR 0006 P2-03, container update plan cu05,
// execution part).
//
// A standalone member's binding names the operator's stored definition by
// definition_id and definition_version; the definition itself holds env
// values and never leaves the executor except to the member's host, as the
// run secret "definition" over the existing tmpfs secret channel
// (hostrun.Secret). The planner sees no secret slot (the catalog entries
// have none), so batches stay possible (G8): the executor alone derives the
// slot from the binding, here.
//
// The definition is read and its shape checked (containerdef.Decode, the
// same check as at storage: newline, carriage return or NUL in an env
// value, Docker-chosen host ports, env or image flags, another container)
// before the member is claimed, and read and checked again immediately
// before the job is handed to the host, where it must be byte for byte
// the definition read at the claim. Every version is a write-once vault
// secret, so a definition changed after approval is a new version, which
// the bound one is not: a binding whose version was removed, replaced or
// re-created under another definition ID is refused, never redirected.
//
// The run records the slot's vault secret ID (run.SecretRefs), so the
// durable output is redacted with the whole definition, or withheld or
// left on the host like every durable run's when the vault is locked or
// the secret gone (redactDurable). Individual env values are not redaction
// entries (Q26): silent command output and env-free snapshots protect them.

// definitionSlot is the run secret slot of a standalone member's
// definition ($NEBULA_SECRETS_DIR/definition on the host).
const definitionSlot = "definition"

var (
	// errDefinitionUnavailable: no stored definition with the bound ID and
	// version for the bound host and container.
	errDefinitionUnavailable = errors.New("container definition unavailable: no stored definition with the bound ID and version for this host and container")
	// errDefinitionChanged: the bound definition is not the one read at
	// the claim, or its vault secret was replaced.
	errDefinitionChanged = errors.New("container definition changed after approval")
	// errDefinitionVaultLocked: the vault is locked, so the definition
	// cannot be read.
	errDefinitionVaultLocked = errors.New("vault_locked: the standalone member's container definition is in the executor vault; run `nebula unlock` on the executor host")
	// errDefinitionShape: the stored definition fails the shape check.
	errDefinitionShape = errors.New("container definition refused")
)

// isStandaloneMember reports whether u binds a standalone container.
func isStandaloneMember(u *canonical.BatchContainerUpdate) bool {
	return u != nil && u.Form == canonical.ContainerUpdateFormAlone
}

// standaloneSecretRefs is the run's slot -> vault secret ID mapping derived
// from a standalone binding: slot definition to ctrdef.<id>.<version>.
// Nil for any other binding.
func standaloneSecretRefs(u *canonical.BatchContainerUpdate) map[string]string {
	if !isStandaloneMember(u) {
		return nil
	}
	return map[string]string{definitionSlot: executordb.ContainerDefinitionSecretID(u.DefinitionID, u.DefinitionVersion)}
}

// standaloneDefinition reads the definition a standalone binding names for
// hostID and checks it: the metadata row of exactly that host, container
// name, definition ID and version exists, its vault secret is the
// write-once first version, and the content passes the shape check for
// the bound container. It returns the run secret. Errors name no content.
func (s *Service) standaloneDefinition(u canonical.BatchContainerUpdate, hostID string) (hostrun.Secret, error) {
	if !isStandaloneMember(&u) || len(u.Targets) != 1 || !executordb.ValidContainerDefinitionID(u.DefinitionID) ||
		u.DefinitionVersion == 0 || u.DefinitionVersion > executordb.MaxContainerDefinitionVersion {
		return hostrun.Secret{}, errDefinitionUnavailable
	}
	name := u.Targets[0].ContainerName
	versions, err := s.db.ContainerDefinitionVersions(hostID, name)
	if err != nil {
		if !errors.Is(err, executordb.ErrNoContainerDefinition) {
			s.log.Error("audit", "kind", "store_error", "op", "container_definition_versions", "host", hostID, "detail", err.Error())
		}
		return hostrun.Secret{}, errDefinitionUnavailable
	}
	secretID := executordb.ContainerDefinitionSecretID(u.DefinitionID, u.DefinitionVersion)
	found := false
	for _, d := range versions {
		if d.DefinitionID == u.DefinitionID && d.Version == u.DefinitionVersion && d.VaultSecretID == secretID {
			found = true
		}
	}
	if !found {
		return hostrun.Secret{}, errDefinitionUnavailable
	}
	raw, version, err := s.vault.OpenVersion(secretID)
	switch {
	case errors.Is(err, vault.ErrLocked):
		return hostrun.Secret{}, errDefinitionVaultLocked
	case errors.Is(err, vault.ErrNotFound):
		return hostrun.Secret{}, errDefinitionUnavailable
	case err != nil:
		s.log.Error("audit", "kind", "store_error", "op", "open_container_definition", "host", hostID, "definition_id", u.DefinitionID,
			"version", u.DefinitionVersion, "detail", err.Error())
		return hostrun.Secret{}, errDefinitionUnavailable
	case version != 1:
		// Definition secrets are written once; a later version is a
		// replacement nobody approved.
		clear(raw)
		return hostrun.Secret{}, errDefinitionChanged
	}
	// The shape errors name positions and flags, never a value.
	if _, err := containerdef.Decode(raw, name); err != nil {
		clear(raw)
		return hostrun.Secret{}, fmt.Errorf("%w: %w", errDefinitionShape, err)
	}
	return hostrun.Secret{Slot: definitionSlot, Value: raw}, nil
}

// standaloneMemberSecrets is what a container member gets before its
// claim: for a standalone member its definition run secret and the run's
// secret refs derived from the binding; nothing for any other member.
func (s *Service) standaloneMemberSecrets(m canonical.BatchMember, hostID string) ([]hostrun.Secret, map[string]string, error) {
	if !isStandaloneMember(m.ContainerUpdate) {
		return nil, nil, nil
	}
	def, err := s.standaloneDefinition(*m.ContainerUpdate, hostID)
	if err != nil {
		return nil, nil, err
	}
	return []hostrun.Secret{def}, standaloneSecretRefs(m.ContainerUpdate), nil
}

// recheckStandaloneDefinition reads the member's definition again right
// before dispatch: it must still pass every check and be byte for byte
// the definition read at the claim (held). Non-standalone members pass.
func (s *Service) recheckStandaloneDefinition(u *canonical.BatchContainerUpdate, hostID string, held []hostrun.Secret) error {
	if !isStandaloneMember(u) {
		return nil
	}
	sec, err := s.standaloneDefinition(*u, hostID)
	if err != nil {
		return err
	}
	defer clear(sec.Value)
	if len(held) != 1 || held[0].Slot != definitionSlot || !bytes.Equal(held[0].Value, sec.Value) {
		return errDefinitionChanged
	}
	return nil
}
