// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Org-chart read model (ADR 0006, P1-15). BuildTree is a pure function
// that turns stored observations — PVE remotes/nodes/guests, managed
// hosts with their SSH-observed containers and services, and reviewed
// (remote, vmid, generation) -> host links — into the nested tree the
// /inventory/chart page renders: PVE node -> VM/LXC -> Compose project
// -> Docker container -> service, with bare-metal managed hosts as
// roots.
//
// The model is display-only:
//   - A reviewed link attaches a managed host's SSH observations to a
//     guest box. It is authoritative for display only and never proves
//     SSH identity: nothing in this package infers an endpoint or
//     authority from PVE data, and a guest without a link carries no
//     host observations.
//   - A linked host is not rendered as a second box, so its state and
//     children are counted exactly once.
//   - Container identity is (host, container ID); the ID is the full
//     container ID carried by the observation (docker.list currently
//     carries the 12-character prefix until P1-16 extends it). Names
//     and Compose labels are display hints, never identity.
//   - Unknown or stale observations get an explicit state and never
//     become ok or off.

package pveinventory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Input limits for the org-chart read model.
const (
	// MaxTreeRemotes bounds the number of PVE remotes in one tree.
	MaxTreeRemotes = 64
	// MaxTreeNodesPerRemote bounds node boxes per remote (input plus
	// implicit nodes for orphan guests).
	MaxTreeNodesPerRemote = 128
	// MaxTreeGuestsPerRemote bounds guest boxes per remote.
	MaxTreeGuestsPerRemote = 1000
	// MaxTreeHosts bounds managed hosts in one tree.
	MaxTreeHosts = 256
	// MaxTreeContainers bounds Docker containers per host.
	MaxTreeContainers = 2000
	// MaxTreeServices bounds systemd units per host.
	MaxTreeServices = 1000
	// MaxTreeLinks bounds reviewed host links in one tree.
	MaxTreeLinks = 1000
	// MaxTreeStoragesPerRemote bounds per-node storage reports per remote;
	// shared storages collapse to one box.
	MaxTreeStoragesPerRemote = pvecontract.MaxStorageReportsPerRemote
	// DefaultStaleAfter marks a PVE observation stale after three
	// missed 60-second inventory intervals.
	DefaultStaleAfter = 3 * time.Minute
)

// Storage fill thresholds for the org chart.
const (
	// StorageWarnPercent marks a storage warning at 70 percent full.
	StorageWarnPercent = 70
	// StorageCritPercent marks a storage critical at 90 percent full.
	StorageCritPercent = 90
	// StorageStaleAfter marks a storage observation stale after three
	// missed five-minute storage refresh intervals. Storage is refreshed
	// on a five-minute cadence (spec 12), so the default three-minute
	// node window would expire a valid observation before its next
	// refresh.
	StorageStaleAfter = 15 * time.Minute
)

// BoxKind identifies one org-chart box.
type BoxKind string

// Box kinds.
const (
	KindPVENode   BoxKind = "pve-node"
	KindGuest     BoxKind = "guest"
	KindHost      BoxKind = "host"
	KindCompose   BoxKind = "compose"
	KindContainer BoxKind = "container"
	KindService   BoxKind = "service"
	KindStorage   BoxKind = "storage"
)

// BoxState is the state of one box.
type BoxState string

// Box states.
const (
	// StateOK is healthy and fresh.
	StateOK BoxState = "ok"
	// StateWarning is degraded: pending updates, reboot required,
	// paused, maintenance-like.
	StateWarning BoxState = "warning"
	// StateCritical is unreachable, failed or unhealthy.
	StateCritical BoxState = "critical"
	// StateOff is expected off: stopped, exited, inactive.
	StateOff BoxState = "off"
	// StateUnknown is explicit: never observed, stale, or unavailable.
	// It never becomes ok or off.
	StateUnknown BoxState = "unknown"
)

// StateRank orders states from best (0) to worst. Higher is worse for
// aggregate worst-state computation.
func StateRank(s BoxState) int {
	switch s {
	case StateCritical:
		return 4
	case StateWarning:
		return 3
	case StateUnknown:
		return 2
	case StateOff:
		return 1
	default:
		return 0
	}
}

// Container is one Docker container observation. Identity is
// (host, ID); Name and Project are display hints.
type Container struct {
	// ID is the full container ID from the observation.
	ID string
	// Name is the container name label.
	Name string
	// Image is the image reference.
	Image string
	// State is the Docker state (running, exited, ...).
	State string
	// Health is the Docker health (healthy, unhealthy, ...).
	Health string
	// Project is the Compose project hint; "" means standalone.
	Project string
}

// Service is one systemd unit observation. Identity is (host, Name).
type Service struct {
	// Name is the unit name.
	Name string
	// Active is the unit active state (active, failed, ...).
	Active string
}

// HostInput is one managed host with its latest SSH observations. The
// observations belong to the host because the host is enrolled, never
// because of any PVE data.
type HostInput struct {
	// ID is the inventory host ID.
	ID string
	// DisplayName is the host display name (untrusted text).
	DisplayName string
	// OS is the host OS label.
	OS string
	// OpsState is the host ops state (executions state); "" means not
	// checked.
	OpsState string
	// KeyBlocked is true when the host key pin is blocked.
	KeyBlocked bool
	// UpdatesTotal is the pending package update count; negative means
	// unknown.
	UpdatesTotal int
	// RebootRequired comes from the same observation.
	RebootRequired bool
	// Stale is set by the caller when the host's last read is older
	// than the host stale threshold.
	Stale bool
	// Containers are the latest docker.list containers, in stored
	// order.
	Containers []Container
	// Services are the latest service.list units, in stored order.
	Services []Service
}

// NodeInput is one PVE node observation.
type NodeInput struct {
	// Node is the node name.
	Node string
	// Status is the node status (online, offline, ...).
	Status string
	// State is the node dataset availability.
	State DatasetState
	// Reason explains an unavailable dataset.
	Reason string
	// ObservedAt is when the observation was taken.
	ObservedAt time.Time
}

// GuestInput is one active guest incarnation.
type GuestInput struct {
	// VMID is the guest VMID within its remote.
	VMID uint64
	// Generation is the incarnation generation.
	Generation uint64
	// Kind is the guest kind (qemu, lxc).
	Kind string
	// Node is the node the guest runs on.
	Node string
	// Name is the guest name (untrusted text).
	Name string
	// Status is the guest status (running, stopped, ...).
	Status string
	// State is the guest dataset availability.
	State DatasetState
	// Reason explains an unavailable dataset.
	Reason string
	// ObservedAt is when the observation was taken.
	ObservedAt time.Time
}

// StorageInput is one PVE storage (datastore) observation on one
// node.
type StorageInput struct {
	// Node is the node the storage is reported on.
	Node string
	// ID is the storage ID (untrusted text).
	ID string
	// Type is the storage type (dir, lvmthin, zfspool, nfs, cifs,
	// pbs, ...).
	Type string
	// Active is the storage active flag.
	Active bool
	// Shared is the storage shared flag.
	Shared bool
	// UsedBytes is the used capacity in bytes.
	UsedBytes uint64
	// TotalBytes is the total capacity in bytes.
	TotalBytes uint64
	// CapacityKnown is false when the observation carried no usable
	// used/total pair.
	CapacityKnown bool
	// StoredState is the stored dataset availability state
	// (available, unavailable, partial); empty means derive it from
	// the observation fields.
	StoredState DatasetState
	// StoredReason is the stored dataset reason (untrusted text).
	StoredReason string
	// Stale is set by the caller when the observation is older than
	// the stale threshold.
	Stale bool
}

// RemoteInput is one PVE remote with its node and guest observations.
type RemoteInput struct {
	// RemoteID is the remote identity.
	RemoteID string
	// Name is the remote display name (untrusted text).
	Name string
	// Nodes are the node observations, in stored order.
	Nodes []NodeInput
	// Guests are the active guest incarnations, in stored order.
	Guests []GuestInput
	// Storages are the storage observations, in stored order.
	Storages []StorageInput
}

// HostLink is one reviewed (remote, vmid, generation) -> host link. It
// is authoritative for display only; it never proves SSH identity.
type HostLink struct {
	// RemoteID is the remote the guest belongs to.
	RemoteID string
	// VMID is the guest VMID.
	VMID uint64
	// Generation is the incarnation generation.
	Generation uint64
	// HostID is the managed host whose observations attach to the
	// guest box.
	HostID string
}

// TreeInput is everything the org-chart read model needs.
type TreeInput struct {
	// Now is the reference time for staleness; zero uses time.Now().
	Now time.Time
	// StaleAfter marks PVE observations older than this stale; zero
	// uses DefaultStaleAfter.
	StaleAfter time.Duration
	// Remotes are the PVE remotes with their observations.
	Remotes []RemoteInput
	// Hosts are the managed hosts with their SSH observations.
	Hosts []HostInput
	// Links are the reviewed host links.
	Links []HostLink
}

// Box is one org-chart box.
type Box struct {
	// Kind is the box kind.
	Kind BoxKind
	// ID is the stable box identity.
	ID string
	// Name is the display label (untrusted text; render as text only).
	Name string
	// RemoteID and RemoteName identify the remote of a PVE node box.
	RemoteID   string
	RemoteName string
	// VMID and Generation identify a guest box.
	VMID       uint64
	Generation uint64
	// HostID identifies a host box, or — on a guest box — the managed
	// host whose observations are attached via a reviewed link. It is
	// display information, never SSH authority.
	HostID string
	// Image is the container image reference (container boxes).
	Image string
	// Unit is the systemd unit name (service boxes).
	Unit string
	// StorageType is the storage type (storage boxes).
	StorageType string
	// StorageUsedBytes and StorageTotalBytes are the storage
	// capacities in bytes (storage boxes).
	StorageUsedBytes  uint64
	StorageTotalBytes uint64
	// StorageFillPercent is the used percentage, clamped to [0, 100]
	// (storage boxes with known capacity).
	StorageFillPercent int
	// StorageShared marks a storage that is shared across the
	// cluster (storage boxes).
	StorageShared bool
	// StorageBackup marks a Proxmox Backup Server datastore (storage
	// boxes).
	StorageBackup bool
	// State is the box's own state; StateReason explains it.
	State       BoxState
	StateReason string
	// Stale marks an observation older than the stale threshold.
	Stale bool
	// Worst is the worst of the box's own state and its descendants.
	Worst BoxState
	// Counts is the number of direct children per kind.
	Counts map[BoxKind]int
	// Children are the direct children.
	Children []Box
}

// Tree is the org-chart read model.
type Tree struct {
	// Roots are the top-level boxes: PVE nodes first (remote input
	// order, then node order), then bare-metal managed hosts (input
	// order).
	Roots []Box
}

// BuildTree builds the org-chart read model from stored observations.
// It is pure: it only reads its input and never performs I/O. It
// returns an error when the input exceeds the named limits or carries
// duplicate identities.
func BuildTree(in TreeInput) (Tree, error) {
	staleAfter := in.StaleAfter
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	if len(in.Remotes) > MaxTreeRemotes {
		return Tree{}, fmt.Errorf("chart tree: %d remotes exceed limit %d", len(in.Remotes), MaxTreeRemotes)
	}
	if len(in.Hosts) > MaxTreeHosts {
		return Tree{}, fmt.Errorf("chart tree: %d hosts exceed limit %d", len(in.Hosts), MaxTreeHosts)
	}
	if len(in.Links) > MaxTreeLinks {
		return Tree{}, fmt.Errorf("chart tree: %d links exceed limit %d", len(in.Links), MaxTreeLinks)
	}

	// Validate hosts: unique IDs, bounded and unique containers and
	// services per host.
	hosts := make(map[string]HostInput, len(in.Hosts))
	for _, h := range in.Hosts {
		if h.ID == "" {
			return Tree{}, errors.New("chart tree: host with empty id")
		}
		if _, dup := hosts[h.ID]; dup {
			return Tree{}, fmt.Errorf("chart tree: duplicate host id %q", h.ID)
		}
		if len(h.Containers) > MaxTreeContainers {
			return Tree{}, fmt.Errorf("chart tree: host %s has %d containers, limit %d", h.ID, len(h.Containers), MaxTreeContainers)
		}
		if len(h.Services) > MaxTreeServices {
			return Tree{}, fmt.Errorf("chart tree: host %s has %d services, limit %d", h.ID, len(h.Services), MaxTreeServices)
		}
		seenC := make(map[string]bool, len(h.Containers))
		for _, c := range h.Containers {
			if c.ID == "" {
				return Tree{}, fmt.Errorf("chart tree: host %s has a container with empty id", h.ID)
			}
			if seenC[c.ID] {
				return Tree{}, fmt.Errorf("chart tree: host %s has duplicate container id %q", h.ID, c.ID)
			}
			seenC[c.ID] = true
		}
		seenS := make(map[string]bool, len(h.Services))
		for _, sv := range h.Services {
			if sv.Name == "" {
				return Tree{}, fmt.Errorf("chart tree: host %s has a service with empty name", h.ID)
			}
			if seenS[sv.Name] {
				return Tree{}, fmt.Errorf("chart tree: host %s has duplicate service name %q", h.ID, sv.Name)
			}
			seenS[sv.Name] = true
		}
		hosts[h.ID] = h
	}

	// Validate remotes: unique remote IDs, unique node names and guest
	// incarnations per remote, bounded sizes.
	guests := make(map[guestKey]bool)
	seenRemotes := make(map[string]bool, len(in.Remotes))
	for _, r := range in.Remotes {
		if r.RemoteID == "" {
			return Tree{}, errors.New("chart tree: remote with empty id")
		}
		if seenRemotes[r.RemoteID] {
			return Tree{}, fmt.Errorf("chart tree: duplicate remote id %q", r.RemoteID)
		}
		seenRemotes[r.RemoteID] = true
		if len(r.Nodes) > MaxTreeNodesPerRemote {
			return Tree{}, fmt.Errorf("chart tree: remote %s has %d nodes, limit %d", r.RemoteID, len(r.Nodes), MaxTreeNodesPerRemote)
		}
		if len(r.Guests) > MaxTreeGuestsPerRemote {
			return Tree{}, fmt.Errorf("chart tree: remote %s has %d guests, limit %d", r.RemoteID, len(r.Guests), MaxTreeGuestsPerRemote)
		}
		if len(r.Storages) > MaxTreeStoragesPerRemote {
			return Tree{}, fmt.Errorf("chart tree: remote %s has %d storages, limit %d", r.RemoteID, len(r.Storages), MaxTreeStoragesPerRemote)
		}
		seenNodes := make(map[string]bool, len(r.Nodes))
		for _, n := range r.Nodes {
			if n.Node == "" {
				return Tree{}, fmt.Errorf("chart tree: remote %s has a node with empty name", r.RemoteID)
			}
			if seenNodes[n.Node] {
				return Tree{}, fmt.Errorf("chart tree: remote %s has duplicate node %q", r.RemoteID, n.Node)
			}
			seenNodes[n.Node] = true
		}
		for _, g := range r.Guests {
			k := guestKey{r.RemoteID, g.VMID, g.Generation}
			if _, dup := guests[k]; dup {
				return Tree{}, fmt.Errorf("chart tree: remote %s has duplicate guest vmid %d generation %d", r.RemoteID, g.VMID, g.Generation)
			}
			guests[k] = true
		}
		seenStorages := make(map[string]bool, len(r.Storages))
		for _, s := range r.Storages {
			if s.Node == "" {
				return Tree{}, fmt.Errorf("chart tree: remote %s has a storage without node", r.RemoteID)
			}
			if s.ID == "" {
				return Tree{}, fmt.Errorf("chart tree: remote %s has a storage without id", r.RemoteID)
			}
			k := s.Node + "\x00" + s.ID
			if seenStorages[k] {
				return Tree{}, fmt.Errorf("chart tree: remote %s has duplicate storage %q on node %q", r.RemoteID, s.ID, s.Node)
			}
			seenStorages[k] = true
		}
	}

	// Validate links: unique (remote, vmid, generation).
	seenLinks := make(map[guestKey]bool, len(in.Links))
	for _, l := range in.Links {
		k := guestKey{l.RemoteID, l.VMID, l.Generation}
		if seenLinks[k] {
			return Tree{}, fmt.Errorf("chart tree: duplicate link for %s vmid %d generation %d", l.RemoteID, l.VMID, l.Generation)
		}
		seenLinks[k] = true
	}

	// Resolve links against known guests and hosts. Links to unknown
	// targets are ignored: the host stays a bare-metal root and the
	// guest carries no observations.
	linkByGuest := make(map[guestKey]string, len(in.Links))
	linkedHosts := make(map[string]int)
	for _, l := range in.Links {
		if _, ok := hosts[l.HostID]; !ok {
			continue
		}
		k := guestKey{l.RemoteID, l.VMID, l.Generation}
		if !guests[k] {
			continue
		}
		linkByGuest[k] = l.HostID
		linkedHosts[l.HostID]++
	}
	for h, n := range linkedHosts {
		if n > 1 {
			return Tree{}, fmt.Errorf("chart tree: host %s is linked to %d guests", h, n)
		}
	}

	tree := Tree{}
	for _, r := range in.Remotes {
		roots, err := buildRemoteBranch(r, now, staleAfter, hosts, linkByGuest)
		if err != nil {
			return Tree{}, err
		}
		tree.Roots = append(tree.Roots, roots...)
	}
	for _, h := range in.Hosts {
		if linkedHosts[h.ID] > 0 {
			continue // attached to its guest box; not a separate box
		}
		tree.Roots = append(tree.Roots, buildHostBox(h))
	}
	for i := range tree.Roots {
		finalize(&tree.Roots[i])
	}
	return tree, nil
}

// buildRemoteBranch builds the node boxes of one remote, with their
// guest children.
func buildRemoteBranch(r RemoteInput, now time.Time, staleAfter time.Duration, hosts map[string]HostInput, linkByGuest map[guestKey]string) ([]Box, error) {
	// Group guests by node, ordered by (vmid, generation).
	sorted := make([]GuestInput, len(r.Guests))
	copy(sorted, r.Guests)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].VMID != sorted[j].VMID {
			return sorted[i].VMID < sorted[j].VMID
		}
		return sorted[i].Generation < sorted[j].Generation
	})
	byNode := make(map[string][]GuestInput)
	nodeOrder := make([]string, 0, len(sorted))
	for _, g := range sorted {
		if _, ok := byNode[g.Node]; !ok {
			nodeOrder = append(nodeOrder, g.Node)
		}
		byNode[g.Node] = append(byNode[g.Node], g)
	}

	// Node boxes from the input, in input order.
	nodes := make(map[string]Box, len(r.Nodes))
	order := make([]string, 0, len(r.Nodes)+len(nodeOrder))
	for _, n := range r.Nodes {
		stale := n.ObservedAt.IsZero() || now.Sub(n.ObservedAt) > staleAfter
		b := Box{
			Kind:       KindPVENode,
			ID:         "node/" + r.RemoteID + "/" + n.Node,
			Name:       n.Node,
			RemoteID:   r.RemoteID,
			RemoteName: r.Name,
			Stale:      stale,
		}
		b.State, b.StateReason = nodeState(n, stale)
		nodes[n.Node] = b
		order = append(order, n.Node)
	}
	// Implicit node boxes for guests whose node was not observed.
	for _, name := range nodeOrder {
		if _, ok := nodes[name]; ok {
			continue
		}
		nodes[name] = Box{
			Kind:        KindPVENode,
			ID:          "node/" + r.RemoteID + "/" + name,
			Name:        name,
			RemoteID:    r.RemoteID,
			RemoteName:  r.Name,
			State:       StateUnknown,
			StateReason: "no node observation",
		}
		order = append(order, name)
	}

	// Storage boxes: one per (node, id), sorted by id, after the
	// guests. Only explicitly shared storages are deduplicated: a shared
	// storage reported by several nodes appears once per cluster, under
	// the first node (input order) that reports it. Node-local storages
	// are kept per node, even when two nodes happen to use the same
	// storage id, so an independent local store is never hidden.
	firstSharedNode := make(map[string]string, len(r.Storages))
	for _, s := range r.Storages {
		if s.Shared {
			if _, ok := firstSharedNode[s.ID]; !ok {
				firstSharedNode[s.ID] = s.Node
			}
		}
	}
	storagesByNode := make(map[string][]StorageInput)
	storageNodeOrder := make([]string, 0, len(r.Storages))
	for _, s := range r.Storages {
		if s.Shared && firstSharedNode[s.ID] != s.Node {
			continue // shared storage placed under the first node; not double-counted
		}
		if _, ok := storagesByNode[s.Node]; !ok {
			storageNodeOrder = append(storageNodeOrder, s.Node)
		}
		storagesByNode[s.Node] = append(storagesByNode[s.Node], s)
	}
	// Implicit node boxes for storages whose node was not observed.
	for _, name := range storageNodeOrder {
		if _, ok := nodes[name]; ok {
			continue
		}
		nodes[name] = Box{
			Kind:        KindPVENode,
			ID:          "node/" + r.RemoteID + "/" + name,
			Name:        name,
			RemoteID:    r.RemoteID,
			RemoteName:  r.Name,
			State:       StateUnknown,
			StateReason: "no node observation",
		}
		order = append(order, name)
	}
	if len(order) > MaxTreeNodesPerRemote {
		// The input node limit bounds r.Nodes; implicit nodes for
		// orphan guests can push the total over it. Fail closed.
		return nil, fmt.Errorf("chart tree: remote %s has %d node boxes, limit %d", r.RemoteID, len(order), MaxTreeNodesPerRemote)
	}

	out := make([]Box, 0, len(order))
	for _, name := range order {
		b := nodes[name]
		for _, g := range byNode[name] {
			k := guestKey{r.RemoteID, g.VMID, g.Generation}
			hostID, linked := linkByGuest[k]
			b.Children = append(b.Children, buildGuestBox(r.RemoteID, g, now, staleAfter, hosts, hostID, linked))
		}
		if sts := storagesByNode[name]; len(sts) > 0 {
			sort.Slice(sts, func(i, j int) bool { return sts[i].ID < sts[j].ID })
			for _, s := range sts {
				b.Children = append(b.Children, buildStorageBox(r.RemoteID, s))
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// buildStorageBox builds one storage (datastore) box under a PVE node.
// The shared flag is taken from the input; it is never derived from how
// many nodes report the storage.
func buildStorageBox(remoteID string, s StorageInput) Box {
	b := Box{
		Kind:              KindStorage,
		ID:                "storage/" + remoteID + "/" + s.ID,
		Name:              s.ID,
		StorageType:       s.Type,
		StorageUsedBytes:  s.UsedBytes,
		StorageTotalBytes: s.TotalBytes,
		StorageShared:     s.Shared,
		StorageBackup:     s.Type == "pbs",
		Stale:             s.Stale,
	}
	b.State, b.StateReason = storageState(s)
	if b.State != StateUnknown {
		b.StorageFillPercent = storageFillPercent(s)
	}
	return b
}

// storageState derives the state of a storage box. Inactive, stale
// and capacity-unknown storages are unknown, never 0 percent. The
// stored availability is preserved: an unavailable observation is
// never a healthy fill, and a partial one is a warning.
func storageState(s StorageInput) (BoxState, string) {
	if !s.Active {
		return StateUnknown, "inactive"
	}
	if s.Stale {
		return StateUnknown, "stale"
	}
	switch s.StoredState {
	case StateUnavailable:
		return StateUnknown, storedDatasetReason(s, "unavailable")
	case StatePartial:
		return StateWarning, storedDatasetReason(s, "partial")
	}
	if !s.CapacityKnown || s.TotalBytes == 0 {
		return StateUnknown, "capacity unknown"
	}
	pct := storageFillPercent(s)
	if pct >= StorageCritPercent {
		return StateCritical, fmt.Sprintf("%d%% full", pct)
	}
	if pct >= StorageWarnPercent {
		return StateWarning, fmt.Sprintf("%d%% full", pct)
	}
	return StateOK, ""
}

// storedDatasetReason returns the stored dataset reason for a
// non-available state, falling back to a default when the stored
// reason is empty.
func storedDatasetReason(s StorageInput, fallback string) string {
	if s.StoredReason != "" {
		return s.StoredReason
	}
	return fallback
}

// storageFillPercent is the used percentage of a storage, clamped to
// [0, 100]. It is only called for storages with total > 0. The
// multiplication is overflow-safe: a hostile used near 2^64 falls back
// to arbitrary-precision arithmetic so the percentage cannot wrap to
// zero and suppress the critical threshold.
func storageFillPercent(s StorageInput) int {
	if s.UsedBytes >= s.TotalBytes {
		return 100
	}
	// used < total, so the percentage is in [0, 100). The fast path
	// is safe when used*100 cannot overflow uint64; a hostile used
	// above that bound falls back to big.Int.
	if s.UsedBytes <= math.MaxUint64/100 {
		return int(s.UsedBytes * 100 / s.TotalBytes)
	}
	num := new(big.Int).SetUint64(s.UsedBytes)
	num.Mul(num, big.NewInt(100))
	den := new(big.Int).SetUint64(s.TotalBytes)
	return int(new(big.Int).Quo(num, den).Int64())
}

// buildGuestBox builds one guest box, attaching the linked host's SSH
// observations when a reviewed link resolves.
func buildGuestBox(remoteID string, g GuestInput, now time.Time, staleAfter time.Duration, hosts map[string]HostInput, hostID string, linked bool) Box {
	stale := g.ObservedAt.IsZero() || now.Sub(g.ObservedAt) > staleAfter
	b := Box{
		Kind:       KindGuest,
		ID:         fmt.Sprintf("guest/%s/%d/%d", remoteID, g.VMID, g.Generation),
		Name:       g.Name,
		VMID:       g.VMID,
		Generation: g.Generation,
		Stale:      stale,
	}
	b.State, b.StateReason = guestState(g, stale)
	if !linked {
		return b
	}
	h := hosts[hostID]
	b.HostID = hostID
	b.Stale = b.Stale || h.Stale
	hs, hr := hostState(h)
	b.State, b.StateReason = maxState(b.State, b.StateReason, hs, hr)
	b.Children = hostChildren(h)
	return b
}

// buildHostBox builds one bare-metal host root box.
func buildHostBox(h HostInput) Box {
	b := Box{
		Kind:   KindHost,
		ID:     "host/" + h.ID,
		Name:   h.DisplayName,
		HostID: h.ID,
		Stale:  h.Stale,
	}
	b.State, b.StateReason = hostState(h)
	b.Children = hostChildren(h)
	return b
}

// hostChildren builds the compose groups (first-seen order), standalone
// containers (input order) and services (input order) of one host.
func hostChildren(h HostInput) []Box {
	var out []Box
	groups := make(map[string]int) // project -> index in out
	for _, c := range h.Containers {
		cb := Box{
			Kind:  KindContainer,
			ID:    "container/" + h.ID + "/" + c.ID,
			Name:  c.Name,
			Image: c.Image,
			Stale: h.Stale,
		}
		cb.State, cb.StateReason = containerState(c)
		if h.Stale {
			cb.State, cb.StateReason = maxState(cb.State, cb.StateReason, StateUnknown, "stale")
		}
		if c.Project == "" {
			out = append(out, cb)
			continue
		}
		idx, ok := groups[c.Project]
		if !ok {
			gb := Box{
				Kind:  KindCompose,
				ID:    "compose/" + h.ID + "/" + c.Project,
				Name:  c.Project,
				State: StateOK,
				Stale: h.Stale,
			}
			if h.Stale {
				gb.State, gb.StateReason = StateUnknown, "stale"
			}
			groups[c.Project] = len(out)
			out = append(out, gb)
			idx = len(out) - 1
		}
		out[idx].Children = append(out[idx].Children, cb)
	}
	for _, sv := range h.Services {
		sb := Box{
			Kind:  KindService,
			ID:    "service/" + h.ID + "/" + sv.Name,
			Name:  sv.Name,
			Unit:  sv.Name,
			Stale: h.Stale,
		}
		sb.State, sb.StateReason = serviceState(sv)
		if h.Stale {
			sb.State, sb.StateReason = maxState(sb.State, sb.StateReason, StateUnknown, "stale")
		}
		out = append(out, sb)
	}
	return out
}

// finalize sets the direct child counts and the aggregate worst state
// of a box and its descendants.
func finalize(b *Box) {
	b.Counts = make(map[BoxKind]int, len(b.Children))
	worst := b.State
	for i := range b.Children {
		finalize(&b.Children[i])
		b.Counts[b.Children[i].Kind]++
		if StateRank(b.Children[i].Worst) > StateRank(worst) {
			worst = b.Children[i].Worst
		}
	}
	b.Worst = worst
}

// maxState returns the worse of two (state, reason) pairs.
func maxState(cur BoxState, curReason string, cand BoxState, candReason string) (BoxState, string) {
	if StateRank(cand) > StateRank(cur) {
		return cand, candReason
	}
	return cur, curReason
}

// hostState derives the state of a managed host from its ops state and
// observations.
func hostState(h HostInput) (BoxState, string) {
	var st BoxState
	var reason string
	switch h.OpsState {
	case executions.StateReady:
		st, reason = StateOK, ""
	case executions.StateWarning:
		st, reason = StateWarning, "warning"
	case executions.StateUnreachable:
		st, reason = StateCritical, "unreachable"
	default:
		st, reason = StateUnknown, "not checked"
	}
	if h.KeyBlocked {
		st, reason = maxState(st, reason, StateCritical, "blocked")
	}
	if h.UpdatesTotal > 0 {
		st, reason = maxState(st, reason, StateWarning, "updates pending")
	}
	if h.RebootRequired {
		st, reason = maxState(st, reason, StateWarning, "reboot required")
	}
	if h.Stale {
		st, reason = maxState(st, reason, StateUnknown, "stale")
	}
	return st, reason
}

// nodeState derives the state of a PVE node box.
func nodeState(n NodeInput, stale bool) (BoxState, string) {
	var st BoxState
	var reason string
	switch n.State {
	case StateAvailable:
		st, reason = StateOK, ""
	default:
		st, reason = StateUnknown, datasetReason(n.Reason)
	}
	switch n.Status {
	case string(pvecontract.NodeOnline):
		// ok
	case string(pvecontract.NodeOffline):
		st, reason = maxState(st, reason, StateOff, "")
	default:
		st, reason = maxState(st, reason, StateUnknown, "status "+n.Status)
	}
	if stale {
		st, reason = maxState(st, reason, StateUnknown, "stale")
	}
	return st, reason
}

// guestState derives the state of a guest box from its PVE observation
// only. The linked host's state is combined by the caller.
func guestState(g GuestInput, stale bool) (BoxState, string) {
	var st BoxState
	var reason string
	switch g.State {
	case StateAvailable:
		st, reason = StateOK, ""
	default:
		st, reason = StateUnknown, datasetReason(g.Reason)
	}
	switch g.Status {
	case string(pvecontract.GuestRunning):
		// ok
	case string(pvecontract.GuestStopped):
		st, reason = maxState(st, reason, StateOff, "")
	case string(pvecontract.GuestPaused):
		st, reason = maxState(st, reason, StateWarning, "paused")
	default:
		st, reason = maxState(st, reason, StateUnknown, "status "+g.Status)
	}
	if stale {
		st, reason = maxState(st, reason, StateUnknown, "stale")
	}
	return st, reason
}

// containerState derives the state of a container box.
func containerState(c Container) (BoxState, string) {
	var st BoxState
	var reason string
	switch c.State {
	case "running":
		st, reason = StateOK, ""
	case "exited", "dead", "created":
		st, reason = StateOff, ""
	case "paused", "restarting", "removing":
		st, reason = StateWarning, c.State
	default:
		st, reason = StateUnknown, "state "+c.State
	}
	if c.Health == "unhealthy" {
		st, reason = maxState(st, reason, StateCritical, "unhealthy")
	}
	return st, reason
}

// serviceState derives the state of a service box.
func serviceState(s Service) (BoxState, string) {
	switch s.Active {
	case "active":
		return StateOK, ""
	case "failed":
		return StateCritical, "failed"
	case "inactive":
		return StateOff, ""
	default:
		return StateUnknown, "state " + s.Active
	}
}

// datasetReason returns the dataset reason, with a default when empty.
func datasetReason(reason string) string {
	if reason == "" {
		return "dataset unavailable"
	}
	return reason
}

// guestKey identifies one guest incarnation within one remote.
type guestKey struct {
	remote string
	vmid   uint64
	gen    uint64
}

// ChartQuery selects the stored observations for the org chart.
type ChartQuery struct {
	// RemoteID restricts the query to one remote; "" means all
	// remotes.
	RemoteID string
	// MaxRemotes, MaxNodes, MaxGuests and MaxStorages bound the
	// queries. Non-positive values use the defaults; values above the
	// defaults are an error.
	MaxRemotes  int
	MaxNodes    int
	MaxGuests   int
	MaxStorages int
}

// ChartData is the stored PVE side of a TreeInput.
type ChartData struct {
	// Remotes are the stored remotes, ordered by remote_id.
	Remotes []Remote
	// Nodes maps remote_id to its nodes, ordered by node name.
	Nodes map[string][]Node
	// Guests maps remote_id to its active guest incarnations, ordered
	// by vmid.
	Guests map[string][]Guest
	// Storages maps remote_id to its storages, ordered by storage
	// name.
	Storages map[string][]Storage
}

// ChartData returns the stored PVE observations needed to build the
// org chart, using bounded queries. Remotes are read with
// MaxRemotes, then nodes, guests and storages per remote with
// MaxNodes, MaxGuests and MaxStorages. Only active guest
// incarnations are returned.
func (s *Store) ChartData(ctx context.Context, q ChartQuery) (ChartData, error) {
	remotesLimit, err := checkLimit(q.MaxRemotes, MaxTreeRemotes)
	if err != nil {
		return ChartData{}, err
	}
	nodesLimit, err := checkLimit(q.MaxNodes, MaxTreeNodesPerRemote)
	if err != nil {
		return ChartData{}, err
	}
	guestsLimit, err := checkLimit(q.MaxGuests, MaxTreeGuestsPerRemote)
	if err != nil {
		return ChartData{}, err
	}
	storagesLimit, err := checkLimit(q.MaxStorages, MaxStoragesQuery)
	if err != nil {
		return ChartData{}, err
	}

	data := ChartData{
		Nodes:    make(map[string][]Node),
		Guests:   make(map[string][]Guest),
		Storages: make(map[string][]Storage),
	}

	query := `SELECT remote_id, name, kind, trust_generation,
	         first_observed_at, last_observed_at, last_source,
	         last_collection_generation FROM pve_remotes`
	args := []any{}
	if q.RemoteID != "" {
		query += ` WHERE remote_id = ?`
		args = append(args, q.RemoteID)
	}
	query += ` ORDER BY remote_id LIMIT ?`
	args = append(args, remotesLimit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ChartData{}, fmt.Errorf("pveinventory: chart data: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r Remote
		var first, last string
		if err := rows.Scan(&r.RemoteID, &r.Name, &r.Kind, &r.TrustGeneration,
			&first, &last, &r.LastSource, &r.LastCollectionGeneration); err != nil {
			return ChartData{}, fmt.Errorf("pveinventory: chart data: %w", err)
		}
		r.FirstObservedAt, _ = time.Parse(time.RFC3339, first)
		r.LastObservedAt, _ = time.Parse(time.RFC3339, last)
		data.Remotes = append(data.Remotes, r)
	}
	if err := rows.Err(); err != nil {
		return ChartData{}, fmt.Errorf("pveinventory: chart data: %w", err)
	}
	if q.RemoteID != "" && len(data.Remotes) == 0 {
		return ChartData{}, fmt.Errorf("chart data: %w", ErrRemoteNotFound)
	}

	for _, r := range data.Remotes {
		nodes, err := s.ListNodes(ctx, r.RemoteID, nodesLimit)
		if err != nil {
			return ChartData{}, err
		}
		data.Nodes[r.RemoteID] = nodes
		guests, err := s.ListGuests(ctx, r.RemoteID, GuestFilter{}, guestsLimit)
		if err != nil {
			return ChartData{}, err
		}
		data.Guests[r.RemoteID] = guests
		storages, err := s.ListStorages(ctx, r.RemoteID, storagesLimit)
		if err != nil {
			return ChartData{}, err
		}
		data.Storages[r.RemoteID] = storages
	}
	return data, nil
}

// TreeInput converts the stored chart data into a TreeInput for
// BuildTree, passing hosts and links through unchanged.
//
// Storage observations are stored per reporting node with PVE's
// authoritative shared flag (vorher: attributed to the first node and
// shared guessed from the storage type). BuildTree places a shared
// storage once, under the first node that reports it. Reports without a
// node (older sources) are placed under the remote's first node, falling
// back to the first guest's node, for display only. Storages of a remote
// without any node or guest are dropped, because they would have no
// parent node box.
func (d ChartData) TreeInput(now time.Time, staleAfter time.Duration, hosts []HostInput, links []HostLink) TreeInput {
	if now.IsZero() {
		now = time.Now()
	}
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	in := TreeInput{Now: now, StaleAfter: staleAfter, Hosts: hosts, Links: links}
	for _, r := range d.Remotes {
		ri := RemoteInput{RemoteID: r.RemoteID, Name: r.Name}
		nodes := d.Nodes[r.RemoteID]
		for _, n := range nodes {
			ri.Nodes = append(ri.Nodes, NodeInput{
				Node: n.Node, Status: n.Status, State: n.State,
				Reason: n.Reason, ObservedAt: n.ObservedAt,
			})
		}
		guests := d.Guests[r.RemoteID]
		for _, g := range guests {
			ri.Guests = append(ri.Guests, GuestInput{
				VMID: g.VMID, Generation: g.Generation, Kind: g.Kind,
				Node: g.Node, Name: g.Name, Status: g.Status,
				State: g.State, Reason: g.Reason, ObservedAt: g.ObservedAt,
			})
		}
		anchor := ""
		if len(nodes) > 0 {
			anchor = nodes[0].Node
		} else {
			for _, g := range guests {
				if g.Node != "" {
					anchor = g.Node
					break
				}
			}
		}
		if anchor == "" {
			// No node box could host the storages; drop them.
			in.Remotes = append(in.Remotes, ri)
			continue
		}
		for _, st := range d.Storages[r.RemoteID] {
			// A capacity pair is only usable when the total is
			// positive and the free amount does not exceed it; a
			// malformed pair (free > total) is capacity-unknown, not
			// a healthy zero fill.
			capacityKnown := st.Active && st.SizeBytes > 0 && st.FreeBytes <= st.SizeBytes
			var used uint64
			if capacityKnown {
				used = st.SizeBytes - st.FreeBytes
			}
			node := st.Node
			if node == "" {
				node = anchor
			}
			ri.Storages = append(ri.Storages, StorageInput{
				Node:          node,
				ID:            st.Name,
				Type:          st.Type,
				Active:        st.Active,
				Shared:        st.Shared,
				UsedBytes:     used,
				TotalBytes:    st.SizeBytes,
				CapacityKnown: capacityKnown,
				StoredState:   st.State,
				StoredReason:  st.Reason,
				Stale:         now.Sub(st.ObservedAt) > StorageStaleAfter,
			})
		}
		in.Remotes = append(in.Remotes, ri)
	}
	return in
}

// ChartTree builds the PVE side of the org chart from the stored
// observations at now: node boxes with their guest and storage (datastore)
// children. Managed SSH hosts are rendered by the chart page itself, so
// none are passed here.
func (s *Store) ChartTree(ctx context.Context, now time.Time) (Tree, error) {
	data, err := s.ChartData(ctx, ChartQuery{})
	if err != nil {
		return Tree{}, err
	}
	return BuildTree(data.TreeInput(now, 0, nil, nil))
}
