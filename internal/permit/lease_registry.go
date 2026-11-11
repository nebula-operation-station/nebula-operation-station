// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Private registry read leases (ADR 0006, cu06 part 1, G13): read-grant-v2
// documents of rate profile schedgrant.RegistryReadProfile. A lease binds
// exact private registry records of the executor vault by record digest
// and version and by credential identity and version, plus an explicit
// repository list and method list per registry. It never binds a
// credential value: the credential stays in the executor vault.

// Registry read lease limits beyond the schedgrant profile.
const (
	// MaxRegistryTargets bounds the registries one lease names.
	MaxRegistryTargets = 8
	// MaxRegistryRepositories bounds the repositories per registry; it
	// equals the record's own scope limit (registrymeta.MaxPrivateRepositories).
	MaxRegistryRepositories = 64
	// maxRegistryVersion keeps vault versions exact in JSON numbers.
	maxRegistryVersion = int64(1)<<53 - 1
)

var (
	registryConfigDigestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	registryCredentialIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// RegistryTarget is one private registry in a registry read lease's frozen
// scope. Any change of the stored record (digest or version) or of the
// credential (random identity or version, i.e. a rotation, removal or
// re-add) leaves the lease without effect for that registry.
type RegistryTarget struct {
	RegistryID        string   `json:"registry_id"`
	ConfigDigest      string   `json:"config_digest"`
	ConfigVersion     int64    `json:"config_version"`
	CredentialID      string   `json:"credential_id"`
	CredentialVersion int64    `json:"credential_version"`
	Repositories      []string `json:"repositories"`
	Methods           []string `json:"methods"`
}

// RegistryTarget returns the frozen registry target for registryID.
func (d ReadGrantDoc) RegistryTarget(registryID string) (RegistryTarget, bool) {
	for _, t := range d.RegistryTargets {
		if t.RegistryID == registryID {
			return t, true
		}
	}
	return RegistryTarget{}, false
}

// AllowsRead reports whether the target binds the method on exactly this
// repository.
func (t RegistryTarget) AllowsRead(method, repository string) bool {
	return slices.Contains(t.Methods, method) && slices.Contains(t.Repositories, repository)
}

// validateRegistryGrant checks a v2 grant whose rate profile is
// schedgrant.RegistryReadProfile.
func validateRegistryGrant(d ReadGrantDoc) error {
	maxInterval := int64(schedgrant.MaxInterval / time.Second)
	switch {
	case len(d.Actions) != 0 || len(d.Targets) != 0 || len(d.Credentials) != 0 || len(d.ProviderTargets) != 0 ||
		len(d.NetDeviceTargets) != 0:
		return errors.New("a registry read lease binds no SSH actions, hosts, credentials, provider remotes or network devices")
	case d.Trigger != TriggerOnDemand:
		return errors.New("a registry read lease is on_demand only")
	case d.ExpiryUnix-d.CreatedUnix > int64(schedgrant.RegistryReadMaxLifetime/time.Second):
		return fmt.Errorf("a registry read lease lives at most %s", schedgrant.RegistryReadMaxLifetime)
	case d.MinIntervalS < int64(schedgrant.RegistryMinInterval/time.Second) || d.MinIntervalS > maxInterval:
		return fmt.Errorf("min_interval_s must be %d to %d", int64(schedgrant.RegistryMinInterval/time.Second), maxInterval)
	case d.RunBudget < 1 || d.RunBudget > schedgrant.RegistryMaxRunBudget:
		return fmt.Errorf("run_budget must be 1 to %d", schedgrant.RegistryMaxRunBudget)
	case len(d.RegistryTargets) == 0 || len(d.RegistryTargets) > MaxRegistryTargets:
		return fmt.Errorf("a registry read lease has 1 to %d registries", MaxRegistryTargets)
	}
	seen := map[string]bool{}
	for _, t := range d.RegistryTargets {
		switch {
		case !schedgrant.ValidRegistryID(t.RegistryID):
			return errors.New("a registry id is malformed")
		case seen[t.RegistryID]:
			return fmt.Errorf("registry %s listed twice", t.RegistryID)
		case !registryConfigDigestRe.MatchString(t.ConfigDigest) || !registryCredentialIDRe.MatchString(t.CredentialID):
			return fmt.Errorf("registry %s: record digest or credential identity is malformed", t.RegistryID)
		case t.ConfigVersion < 1 || t.ConfigVersion > maxRegistryVersion ||
			t.CredentialVersion < 1 || t.CredentialVersion > maxRegistryVersion:
			return fmt.Errorf("registry %s: version out of range", t.RegistryID)
		case len(t.Repositories) == 0 || len(t.Repositories) > MaxRegistryRepositories:
			return fmt.Errorf("registry %s: 1 to %d repositories", t.RegistryID, MaxRegistryRepositories)
		case len(t.Methods) == 0 || len(t.Methods) > len(schedgrant.RegistryReadMethods()):
			return fmt.Errorf("registry %s: 1 to %d methods", t.RegistryID, len(schedgrant.RegistryReadMethods()))
		}
		seen[t.RegistryID] = true
		repos := map[string]bool{}
		for _, r := range t.Repositories {
			if !schedgrant.ValidRegistryRepository(r) || repos[r] {
				return fmt.Errorf("registry %s: a repository is malformed or listed twice", t.RegistryID)
			}
			repos[r] = true
		}
		methods := map[string]bool{}
		for _, m := range t.Methods {
			if !schedgrant.IsRegistryReadMethod(m) || methods[m] {
				return fmt.Errorf("registry %s: a method is unknown or listed twice", t.RegistryID)
			}
			methods[m] = true
		}
	}
	return nil
}
