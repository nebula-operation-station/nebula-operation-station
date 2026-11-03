// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Risk of pve.guest.provision (ADR 0008 section 3 and decision 2 of
// 2026-11-02): base MEDIUM, never LOW (LOW stays read-only, spec 11). ADR
// 0008 adds no automatic raise of its own: a production profile, PCI
// passthrough and memory or storage over-commit do not raise it. The
// general rule of spec 11 ("PVE action profiles and risks") still applies:
// the floor is the maximum of MEDIUM, the criticality of the remote and the
// node and the floors of affected linked hosts; unknown criticality is
// HIGH. The guest being created does not exist yet, so it has no
// criticality and is not scored (it does not count as unknown).
//
// Criticality is the executor's own host criticality record of the
// synthetic risk targets: the node target the permit binds
// (permit.ProviderMutationTarget.RiskTarget) and the remote target
// (PveRemoteRiskTarget), each with its own synthetic fingerprint. The
// executor's risk policy (riskpolicy) gives an unrecorded target HIGH.

// PveGuestProvisionAction is the action ID of guest provisioning.
const PveGuestProvisionAction = "pve.guest.provision"

// pveProvisionBaseRisk is the base risk of pve.guest.provision.
const pveProvisionBaseRisk = canonical.RiskMedium

// PveProvisionCapacity is what the executor observed about the node's
// capacity for one provisioning. It is information for the reviewer only
// (a warning in the frozen plan), never a risk input. It is bound into the
// approved parameters and rebuilt before the run, so a warning that
// appears or disappears after approval refuses the run instead of running
// on a plan the reviewer did not see.
type PveProvisionCapacity struct {
	// MemoryOvercommit is set when the configured memory of every guest of
	// the node plus the new guest exceeds the node's memory, or the node's
	// memory is not known.
	MemoryOvercommit bool `json:"memory_overcommit"`
	// StorageOvercommit is set when the new disk does not fit into the
	// target storage's free space, or the free space is not known.
	StorageOvercommit bool `json:"storage_overcommit"`
}

// Warnings names the set facts, for display.
func (f PveProvisionCapacity) Warnings() []string {
	var out []string
	if f.MemoryOvercommit {
		out = append(out, "node RAM over-committed or unknown")
	}
	if f.StorageOvercommit {
		out = append(out, "storage over-committed or unknown")
	}
	return out
}

// pveCapacityFacts derives the over-commit facts from a complete cluster
// inventory and the target storage. All inputs are untrusted remote data:
// a missing or duplicated node, an unknown capacity or an arithmetic
// overflow counts as over-commit (fail closed).
func pveCapacityFacts(inv pveapi.ClusterInventory, st pveapi.Storage, node string, memoryMiB int, diskGiB int64) (memory, storage bool) {
	memory = true
	var nodeMem uint64
	seen := 0
	for _, n := range inv.Nodes {
		if n.Name == node {
			seen++
			nodeMem = n.MaxMemory
		}
	}
	if seen == 1 && nodeMem != 0 && memoryMiB > 0 {
		committed := uint64(memoryMiB) << 20
		overflow := false
		for _, g := range inv.Guests {
			if g.Node != node || g.MaxMemory <= 0 {
				continue
			}
			if committed+uint64(g.MaxMemory) < committed {
				overflow = true
				break
			}
			committed += uint64(g.MaxMemory)
		}
		memory = overflow || committed > nodeMem
	}
	storage = true
	if st.CapacityKnown && st.Active && st.UsedBytes <= st.TotalBytes && diskGiB > 0 {
		storage = uint64(diskGiB)<<30 > st.TotalBytes-st.UsedBytes
	}
	return memory, storage
}

// pveRemoteRiskDomain separates the remote risk target's fingerprint from
// the node and guest fingerprints (permit.ProviderRiskFingerprint).
const pveRemoteRiskDomain = "nebula-pve-remote-risk-target-v1\x00"

// PveRemoteRiskTarget returns the synthetic risk target of a whole PVE
// remote, by its trust pin (hex SHA-256). An executor host criticality
// record of this target sets the remote's criticality; without one the
// remote counts as HIGH. Its fingerprint is a domain-separated digest of
// the pin, distinct from the fingerprints of the remote's node and guest
// targets, so all of them can carry exact records at the same time. The
// host ID is unchanged from the earlier scheme (which used the bare pin as
// fingerprint), so an old record still raises the target but no longer
// matches exactly. Both follow the pin: a re-pinned remote needs its
// record again (fail closed).
func PveRemoteRiskTarget(trustPin string) (canonical.Target, error) {
	if !pvecontract.ValidTrustPin(trustPin) {
		return canonical.Target{}, ErrPveRemoteChanged
	}
	pin, err := hex.DecodeString(trustPin)
	if err != nil || len(pin) != sha256.Size {
		return canonical.Target{}, ErrPveRemoteChanged
	}
	id := sha256.Sum256([]byte("pve-remote\x00SHA256:" + base64.RawStdEncoding.EncodeToString(pin)))
	fp := sha256.Sum256(append([]byte(pveRemoteRiskDomain), pin...))
	return canonical.Target{
		HostID:             "pvr-" + hex.EncodeToString(id[:16]),
		HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(fp[:]),
	}, nil
}

// PveLinkedHosts returns the managed hosts linked to a PVE node (a node
// that is also an enrolled host). They are affected by provisioning, since
// the guest is created on them, so their criticality counts (spec 11). An
// error fails closed.
type PveLinkedHosts func(r canonical.Request, node canonical.Target) ([]canonical.Target, error)

// PveRemoteOf returns the trust pin of the registered remote a node risk
// target belongs to, ok false if it belongs to none. An error fails
// closed.
type PveRemoteOf func(node canonical.Target) (trustPin string, ok bool, err error)

// PveRemoteLister is the part of the executor registry PveRegistryRemoteOf
// reads (executordb implements it).
type PveRemoteLister interface {
	ListRemotes() ([]executordb.PveRemote, error)
}

// PveRegistryRemoteOf returns the executor's production PveRemoteOf: the
// registered remote (tombstones included; their actions fail elsewhere)
// whose trust pin the node target's fingerprint was made with
// (permit.ProviderRiskFingerprint). Pins are unique in the registry, so at
// most one remote matches. A nil registry resolves nothing.
func PveRegistryRemoteOf(reg PveRemoteLister) PveRemoteOf {
	return func(node canonical.Target) (string, bool, error) {
		if reg == nil {
			return "", false, nil
		}
		rms, err := reg.ListRemotes()
		if err != nil {
			return "", false, fmt.Errorf("pve remote of risk target: %w", err)
		}
		for _, rm := range rms {
			fp, err := permit.ProviderRiskFingerprint(rm.TrustPin, node.HostID)
			if err == nil && fp == node.HostKeyFingerprint {
				return rm.TrustPin, true, nil
			}
		}
		return "", false, nil
	}
}

// GuestProvisionRiskFloor wraps the executor's risk policy for
// pve.guest.provision requests, whoever builds them. The authority
// enforces it when proposing and again when authorizing the run. For a
// provisioning request the floor is the maximum of:
//
//   - MEDIUM (base, ADR 0008);
//   - Next for the bound node target, the remote's risk target and the
//     hosts Linked returns for the node, so unknown criticality is HIGH
//     and a recorded HIGH or CRITICAL node, remote or linked host raises
//     the floor to it; without Next or without Linked, HIGH (a node that
//     is also an enrolled host defaults to HIGH, spec 11, so an unknown
//     set of linked hosts must not be read as "none");
//   - HIGH if the remote of a node target cannot be established: no
//     Remote, a node of no known remote, or a node whose fingerprint was
//     not made with the pin Remote names.
//
// Nothing else raises it: no capacity, PCI or profile fact. Other requests
// get Next's floor unchanged, or HIGH without Next.
type GuestProvisionRiskFloor struct {
	Next permit.RiskPolicy
	// Linked names the managed hosts linked to the node (an empty result
	// means none). Without it the floor is HIGH: fail closed.
	Linked PveLinkedHosts
	// Remote names the remote of a node target, whose risk target is
	// scored with the node. Without it the floor is HIGH: fail closed.
	Remote PveRemoteOf
}

// MinimumRisk implements permit.RiskPolicy.
func (p GuestProvisionRiskFloor) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	if r.ActionID != PveGuestProvisionAction {
		if p.Next == nil {
			// No risk policy to defer to: fail closed.
			return canonical.RiskHigh, "no risk policy configured", nil
		}
		return p.Next.MinimumRisk(r, targets)
	}
	risk, reasons := pveProvisionBaseRisk, []string{"pve.guest.provision is MEDIUM (ADR 0008)"}
	if p.Next == nil {
		return canonical.RiskHigh, strings.Join(append(reasons, "no criticality source: unknown criticality is HIGH"), "; "), nil
	}
	if p.Linked == nil {
		return canonical.RiskHigh, strings.Join(append(reasons, "no linked-host source: unknown criticality is HIGH"), "; "), nil
	}
	if p.Remote == nil {
		return canonical.RiskHigh, strings.Join(append(reasons, "no remote source: unknown criticality is HIGH"), "; "), nil
	}
	if len(targets) == 0 {
		// No node target: its criticality is unknown.
		return canonical.RiskHigh, strings.Join(append(reasons, "no node target: unknown criticality is HIGH"), "; "), nil
	}
	ext := append([]canonical.Target(nil), targets...)
	seen := map[string]bool{}
	for _, t := range targets {
		pin, ok, err := p.Remote(t)
		if err != nil {
			return "", "", fmt.Errorf("provision risk floor: remote: %w", err)
		}
		if fp, ferr := permit.ProviderRiskFingerprint(pin, t.HostID); !ok || ferr != nil || fp != t.HostKeyFingerprint {
			// Unknown remote: HIGH is a floor, but the known targets are
			// still scored so a CRITICAL node or linked host stays CRITICAL.
			risk = canonical.RiskHigh
			reasons = append(reasons, "remote of node target "+t.HostID+" unknown: unknown criticality is HIGH")
		} else if !seen[pin] {
			seen[pin] = true
			remote, err := PveRemoteRiskTarget(pin)
			if err != nil {
				risk = canonical.RiskHigh
				reasons = append(reasons, "remote of node target "+t.HostID+" unknown: unknown criticality is HIGH")
			} else {
				ext = append(ext, remote)
			}
		}
		hosts, err := p.Linked(r, t)
		if err != nil {
			return "", "", fmt.Errorf("provision risk floor: linked hosts: %w", err)
		}
		ext = append(ext, hosts...)
	}
	nr, why, err := p.Next.MinimumRisk(r, ext)
	if err != nil {
		return "", "", fmt.Errorf("provision risk floor: %w", err)
	}
	if nr.Rank() > risk.Rank() {
		risk = nr
		if why != "" {
			reasons = append(reasons, why)
		}
	}
	return risk, strings.Join(reasons, "; "), nil
}
