// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"errors"
	"fmt"
	"strings"
)

// ErrArtifactTrust is a review that does not yield well-formed exact
// artifact trust tuples; nothing may be trusted from it.
var ErrArtifactTrust = errors.New("trust: review does not yield exact artifact trust")

// ArtifactTuple is one exact artifact trust tuple: the executor trusts the
// artifact with this SHA-256 for exactly this action and module version at
// the declared risk, as `nebula artifact trust` does.
type ArtifactTuple struct {
	// ActionID is <family>.<action>.
	ActionID string
	// ModuleVersion is the built-in module version.
	ModuleVersion string
	// SHA256 is the lowercase hex digest of the artifact that runs.
	SHA256 string
	// Risk is the declared risk (LOW, MEDIUM, HIGH or CRITICAL).
	Risk string
}

// VersionRef names one version of a built-in module family.
type VersionRef struct {
	// Module is the module family.
	Module string
	// Version is the module version.
	Version string
}

// ArtifactTrust is the execution authority a committed review implies
// (ADR 0007 E16). Retention in the store confers none; these tuples are
// what the executor's risk policy honours.
type ArtifactTrust struct {
	// Trust are the tuples of every action of every newly committed
	// version (new, changed or reactivated modules).
	Trust []ArtifactTuple
	// Retire are the old versions the admin retired; their trust is
	// revoked, never retargeted to the new bytes.
	Retire []VersionRef
}

// ArtifactTrustFor derives the artifact trust of review r committed with
// the retired old versions (name@version). Unchanged modules add nothing
// (their trust was recorded when they were committed), removed actions and
// modules add nothing, and retained old versions keep their trust. Every
// action must belong to its own module family and carry its exact artifact
// hash and module version; otherwise nothing is trusted.
func ArtifactTrustFor(r Review, retired []string) (ArtifactTrust, error) {
	var out ArtifactTrust
	for _, m := range r.Modules {
		switch m.Status {
		case StatusNew, StatusChanged, StatusReactivated:
		default:
			continue
		}
		if m.Name == "" || m.NewVersion == "" {
			return ArtifactTrust{}, fmt.Errorf("%w: module %q has no new version", ErrArtifactTrust, m.Name)
		}
		for _, a := range m.Actions {
			if a.Status == StatusRemoved {
				continue
			}
			if !strings.HasPrefix(a.ActionID, m.Name+".") {
				return ArtifactTrust{}, fmt.Errorf("%w: action %q is not in module family %s", ErrArtifactTrust, a.ActionID, m.Name)
			}
			if a.NewArtifactSHA256 == "" || a.NewRisk == "" {
				return ArtifactTrust{}, fmt.Errorf("%w: action %s@%s has no artifact hash or risk", ErrArtifactTrust, a.ActionID, m.NewVersion)
			}
			out.Trust = append(out.Trust, ArtifactTuple{ActionID: a.ActionID, ModuleVersion: m.NewVersion,
				SHA256: a.NewArtifactSHA256, Risk: a.NewRisk})
		}
	}
	for _, v := range retired {
		name, version, ok := strings.Cut(v, "@")
		if !ok || name == "" || version == "" {
			return ArtifactTrust{}, fmt.Errorf("%w: retired version %q is not name@version", ErrArtifactTrust, v)
		}
		out.Retire = append(out.Retire, VersionRef{Module: name, Version: version})
	}
	return out, nil
}
