// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Risk of pve.guest.provision (ADR 0008 section 3): base MEDIUM, because
// it creates and destroys nothing. HIGH when the node or remote
// criticality is high, when PCI passthrough is requested, or when the plan
// over-commits node RAM or storage. Unknown criticality is HIGH, as in
// ADR 0006. A production profile is not forced to HIGH beyond these rules
// (ADR 0008 open question 2, draft default).
//
// Criticality is the executor's own host criticality record of the
// synthetic risk targets: the node target the permit binds
// (permit.ProviderMutationTarget.RiskTarget) and the remote target
// (PveRemoteRiskTarget). The executor's risk policy (riskpolicy) gives an
// unrecorded target HIGH. Capacity and PCI are facts the executor reads
// itself when it builds the proposal and again before it runs it.

// PveGuestProvisionAction is the action ID of guest provisioning.
const PveGuestProvisionAction = "pve.guest.provision"

// pveProvisionBaseRisk is the base risk of pve.guest.provision.
const pveProvisionBaseRisk = canonical.RiskMedium

// Risk floor registry limits.
const (
	// maxPveProvisionFloors bounds the proposals whose floor is kept.
	maxPveProvisionFloors = 1024
)

// ErrPveProvisionFloors is returned when no more provisioning floors can be
// recorded; the proposal is refused.
var ErrPveProvisionFloors = errors.New("executor: too many open provisioning proposals")

// PveProvisionRiskFacts are the risk-relevant facts of one provisioning
// that the executor observed. They are bound into the approved parameters,
// so a change before the run (a guest added to the node, storage filled)
// refuses the run and needs a new approval.
type PveProvisionRiskFacts struct {
	// PCIPassthrough is set when the plan requests PCI passthrough.
	PCIPassthrough bool `json:"pci_passthrough"`
	// MemoryOvercommit is set when the configured memory of every guest of
	// the node plus the new guest exceeds the node's memory, or the node's
	// memory is not known.
	MemoryOvercommit bool `json:"memory_overcommit"`
	// StorageOvercommit is set when the new disk does not fit into the
	// target storage's free space, or the free space is not known.
	StorageOvercommit bool `json:"storage_overcommit"`
}

// Risk is the floor the facts set: MEDIUM, or HIGH if any fact is set.
func (f PveProvisionRiskFacts) Risk() canonical.Risk {
	if f.PCIPassthrough || f.MemoryOvercommit || f.StorageOvercommit {
		return canonical.RiskHigh
	}
	return pveProvisionBaseRisk
}

// reasons names the set facts.
func (f PveProvisionRiskFacts) reasons() []string {
	var out []string
	if f.PCIPassthrough {
		out = append(out, "PCI passthrough requested")
	}
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
// a missing node, an unknown capacity or an arithmetic overflow counts as
// over-commit (fail closed).
func pveCapacityFacts(inv pveapi.ClusterInventory, st pveapi.Storage, node string, memoryMiB int, diskGiB int64) (memory, storage bool) {
	memory = true
	for _, n := range inv.Nodes {
		if n.Name != node || n.MaxMemory == 0 {
			continue
		}
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
		memory = overflow || committed > n.MaxMemory
	}
	storage = true
	if st.CapacityKnown && st.Active && st.UsedBytes <= st.TotalBytes && diskGiB > 0 {
		storage = uint64(diskGiB)<<30 > st.TotalBytes-st.UsedBytes
	}
	return memory, storage
}

// PveRemoteRiskTarget returns the synthetic risk target of a whole PVE
// remote, by its trust pin (hex SHA-256). An executor host criticality
// record of this target sets the remote's criticality for provisioning;
// without one the remote counts as HIGH. The ID follows the pin, so a
// re-pinned remote needs its record again (fail closed).
func PveRemoteRiskTarget(trustPin string) (canonical.Target, error) {
	if !pvecontract.ValidTrustPin(trustPin) {
		return canonical.Target{}, ErrPveRemoteChanged
	}
	pin, err := hex.DecodeString(trustPin)
	if err != nil || len(pin) != sha256.Size {
		return canonical.Target{}, ErrPveRemoteChanged
	}
	return remoteRiskTarget("SHA256:" + base64.RawStdEncoding.EncodeToString(pin)), nil
}

func remoteRiskTarget(fingerprint string) canonical.Target {
	sum := sha256.Sum256([]byte("pve-remote\x00" + fingerprint))
	return canonical.Target{HostID: "pvr-" + hex.EncodeToString(sum[:16]), HostKeyFingerprint: fingerprint}
}

// PveProvisionRiskFloors keeps the floor the executor computed for each
// provisioning proposal it built, by parameters hash, until the
// proposal's expiry. GuestProvisionRiskFloor enforces it, so a proposal
// the executor did not build (or one presented with a lower risk class)
// cannot get below the facts the executor observed. It is safe for
// concurrent use; like permits it does not survive a restart.
type PveProvisionRiskFloors struct {
	// Now is the clock. Default: time.Now.
	Now func() time.Time

	mu sync.Mutex
	m  map[string]pveFloor
}

type pveFloor struct {
	risk    canonical.Risk
	why     string
	expires int64
}

func (f *PveProvisionRiskFloors) now() time.Time {
	if f.Now == nil {
		return time.Now()
	}
	return f.Now()
}

// record keeps risk as the floor of r's parameters.
func (f *PveProvisionRiskFloors) record(r canonical.Request, risk canonical.Risk, why string) error {
	if !canonical.ValidSHA256Hex(r.ParametersHash) {
		return ErrPveMutationPlan
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now().Unix()
	if f.m == nil {
		f.m = make(map[string]pveFloor)
	}
	if _, ok := f.m[r.ParametersHash]; !ok && len(f.m) >= maxPveProvisionFloors {
		for k, v := range f.m {
			if v.expires <= now {
				delete(f.m, k)
			}
		}
		if len(f.m) >= maxPveProvisionFloors {
			return ErrPveProvisionFloors
		}
	}
	prev, ok := f.m[r.ParametersHash]
	if ok && prev.risk.Rank() > risk.Rank() {
		risk, why = prev.risk, prev.why
	}
	f.m[r.ParametersHash] = pveFloor{risk: risk, why: why, expires: max(r.ExpiryUnix, prev.expires)}
	return nil
}

// floor returns the recorded floor of r's parameters, if it is in force.
func (f *PveProvisionRiskFloors) floor(r canonical.Request) (canonical.Risk, string, bool) {
	if f == nil {
		return "", "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[r.ParametersHash]
	if !ok || e.expires <= f.now().Unix() {
		return "", "", false
	}
	return e.risk, e.why, true
}

// GuestProvisionRiskFloor wraps the executor's risk policy for
// pve.guest.provision requests, whoever builds them. The authority
// enforces it when proposing and again when authorizing the run. For a
// provisioning request the floor is the maximum of:
//
//   - MEDIUM (base);
//   - Next for the bound node target and the remote's risk target, so
//     unknown criticality is HIGH and a recorded HIGH or CRITICAL node or
//     remote raises the floor to it; without Next, HIGH;
//   - the floor PveProvisioner recorded for these exact parameters from
//     its own capacity and PCI facts; without a record, HIGH.
//
// Other requests get Next's floor unchanged.
type GuestProvisionRiskFloor struct {
	Next   permit.RiskPolicy
	Floors *PveProvisionRiskFloors
}

// MinimumRisk implements permit.RiskPolicy.
func (p GuestProvisionRiskFloor) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	if r.ActionID != PveGuestProvisionAction {
		if p.Next == nil {
			return canonical.RiskLow, "", nil
		}
		return p.Next.MinimumRisk(r, targets)
	}
	risk, reasons := pveProvisionBaseRisk, []string{"pve.guest.provision is MEDIUM (ADR 0008)"}
	raise := func(to canonical.Risk, why string) {
		if to.Rank() > risk.Rank() {
			risk = to
		}
		if why != "" && to.Rank() > pveProvisionBaseRisk.Rank() {
			reasons = append(reasons, why)
		}
	}
	if p.Next == nil {
		raise(canonical.RiskHigh, "no criticality source: unknown criticality is HIGH")
	} else {
		ext := append([]canonical.Target(nil), targets...)
		seen := map[string]bool{}
		for _, t := range targets {
			if !seen[t.HostKeyFingerprint] {
				seen[t.HostKeyFingerprint] = true
				ext = append(ext, remoteRiskTarget(t.HostKeyFingerprint))
			}
		}
		nr, why, err := p.Next.MinimumRisk(r, ext)
		if err != nil {
			return "", "", fmt.Errorf("provision risk floor: %w", err)
		}
		raise(nr, why)
	}
	if fr, why, ok := p.Floors.floor(r); ok {
		raise(fr, why)
	} else {
		raise(canonical.RiskHigh, "provisioning facts not observed by the executor for these parameters")
	}
	return risk, strings.Join(reasons, "; "), nil
}
