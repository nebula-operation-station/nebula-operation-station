// SPDX-License-Identifier: AGPL-3.0-or-later

// Package riskpolicy derives the minimum risk class the executor accepts
// for an execution request from data the executor holds itself (H01).
//
// The server proposes risk_class. A compromised server could label a
// dangerous action LOW and have it auto-approved inside a privileged
// session, so the executor never lowers its own floor to the proposal: a
// proposal below the floor is rejected, one above it is kept (the server
// may always ask for stronger approval).
//
// Rules (docs/spec/10-modules.md: effective risk = max(declared, scanner,
// trust floor); docs/spec/12-inventory.md: host criticality):
//
//  1. Action floor: the risk the admin declared when trusting this artifact
//     on the executor host. It counts only if the artifact is trusted for
//     exactly this (action_id, module_version); its value is the highest
//     risk the same bytes are trusted at under any action, because the
//     server chooses which action_id it presents. An artifact the executor
//     does not trust has the floor HIGH, the spec's floor for unverified
//     scripts running as root (the executor cannot know whether a script
//     runs as root, so it assumes it does).
//  2. Host floor, per target. A host record counts only if both host_id and
//     the pinned key fingerprint match it (host_id alone is a name the
//     server chooses). For actions above LOW the host floor is the recorded
//     criticality, or HIGH without a matching record; a record sharing only
//     the host ID or only the key can raise that (never lower it). LOW actions are
//     read-only by declaration: they stay LOW on recorded LOW to HIGH hosts
//     and need MEDIUM (a WebAuthn tap) on CRITICAL or unrecorded hosts.
//
// The floor is the maximum of both. The Safety Scanner and signed manifests
// (Milestone 7) will add further sources; they can only raise the floor.
package riskpolicy

import (
	"errors"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// UntrustedFloor is the floor of an artifact the executor does not trust.
const UntrustedFloor = canonical.RiskHigh

// UnknownHostFloor is the host floor of a target without a matching record,
// for actions above LOW.
const UnknownHostFloor = canonical.RiskHigh

// Source is the executor-held data (internal/executordb implements it).
type Source interface {
	ArtifactRisk(sha256Hex, actionID, moduleVersion string) (canonical.Risk, bool, error)
	// HostCriticality returns the criticality recorded for exactly this
	// host ID and key (exact true), or else the highest criticality of any
	// record sharing the host ID or the key ("" if none).
	HostCriticality(hostID, fingerprint string) (c canonical.Risk, exact bool, err error)
}

// Policy implements permit.RiskPolicy.
type Policy struct {
	src Source
}

// New returns a policy over src.
func New(src Source) (*Policy, error) {
	if src == nil {
		return nil, errors.New("riskpolicy: a source is required")
	}
	return &Policy{src: src}, nil
}

// MinimumRisk returns the lowest risk class the executor accepts for
// running r on targets (Propose passes every target, AuthorizeRun the one
// host being run) and the reason for it. The reason may name hosts and
// trust entries; it belongs in the executor's audit log, not in replies to
// the server. An error means the floor could not be determined; callers
// must fail closed.
func (p *Policy) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	var floor canonical.Risk
	var reason string
	declared, trusted, err := p.src.ArtifactRisk(r.ArtifactSHA256, r.ActionID, r.ModuleVersion)
	if err != nil {
		return "", "", err
	}
	if trusted {
		floor, reason = declared, fmt.Sprintf("%s@%s is trusted as %s", r.ActionID, r.ModuleVersion, declared)
	} else {
		floor, reason = UntrustedFloor, "artifact is not trusted on the executor for this action and version"
	}
	readOnly := floor == canonical.RiskLow

	// The first host that raises the floor to its final value is named.
	for _, t := range targets {
		if floor == canonical.RiskCritical {
			break
		}
		c, exact, err := p.src.HostCriticality(t.HostID, t.HostKeyFingerprint)
		if err != nil {
			return "", "", err
		}
		hf, why := hostFloor(c, exact, readOnly)
		if hf.Rank() > floor.Rank() {
			floor, reason = hf, fmt.Sprintf("host %s (%s) %s", t.HostID, t.HostKeyFingerprint, why)
		}
	}
	return floor, reason, nil
}

// hostFloor: only an exact record can lower a host below the unrecorded
// floor. A record that shares only the host ID or only the key can raise it
// (a CRITICAL host presented under another key stays CRITICAL).
func hostFloor(c canonical.Risk, exact, readOnly bool) (canonical.Risk, string) {
	switch {
	case !exact && readOnly:
		return canonical.RiskMedium, "has no matching criticality record; read-only actions need MEDIUM there"
	case !exact && c.Rank() > UnknownHostFloor.Rank():
		return c, "has no matching criticality record, but its host ID or key is recorded as " + string(c)
	case !exact:
		return UnknownHostFloor, "has no matching criticality record"
	case readOnly && c == canonical.RiskCritical:
		return canonical.RiskMedium, "is CRITICAL; read-only actions need MEDIUM there"
	case readOnly:
		return canonical.RiskLow, ""
	default:
		return c, "is " + string(c)
	}
}
