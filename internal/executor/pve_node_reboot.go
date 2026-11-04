// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Typed node reboot (ADR 0006 "Phase 2 actions, permits and
// reconciliation", P2-01 node-reboot profile): pve.node.reboot, HIGH for a
// standalone node and CRITICAL for a node in a cluster (CRITICAL approval
// needs user verification plus the typed target count).
//
// The approval binds the exact node, a snapshot of the cluster membership
// (name, members, corosync votes, the HA shutdown policy and the node's HA
// maintenance flag) and every guest on the node (kind, VMID, power status,
// whether HA evacuates it, whether the request accepts its downtime). The
// request names every running guest on the node explicitly, either as
// accepted downtime or as a guest HA is to evacuate, and the permit's
// targets are the node plus each of those guests: the typed count of a
// CRITICAL approval is 1 + the number of guests the reboot takes down or
// moves, and the parameters list each target's synthetic host ID with its
// kind, VMID and effect. The action refuses:
//
//   - a read-only remote (no action credential) with ErrPveReadOnly, and a
//     remote whose admin-set site marker is offsite (ErrPveRebootOffsite;
//     ADR 0006: an offsite node reboot is CRITICAL, manual and needs an
//     agreed recovery path, which NOS does not offer) or not set
//     (ErrPveRebootSite: unknown never lowers the risk), before anything
//     is read;
//   - a node that is not listed online exactly once;
//   - in a cluster: a cluster without quorum; any other member offline or
//     booted less than pveRebootSettle ago (it is rebooting or settling);
//     an open pve.node.reboot step or a running reboot on the same remote,
//     or an unknown one whose node was not seen back yet (at most one node
//     at a time); remaining corosync votes that are not a strict majority
//     of all configured votes; a configured or unknown QDevice (its votes
//     are not modelled); unknown HA state;
//   - a cluster remote whose cluster status cannot be read, a standalone
//     remote that does not list exactly one node, and a remote registered
//     standalone that reports a cluster (the one-node-at-a-time lock is
//     per remote, and a cluster is registered once, by its CA pin);
//   - any running guest on the node the request does not list, a listed
//     guest that is not on the node, an accepted entry for a stopped
//     guest, and an HA-evacuation entry for a guest that is not provably
//     movable (ErrPveRebootNotEvacuable; such a guest must be listed as
//     accepted downtime). A guest is provably movable only while the node
//     is in HA maintenance mode (HA moves guests off before the reboot;
//     under shutdown_policy=migrate the move would happen only after the
//     reboot was sent, so nothing could be checked first), the guest is
//     HA-managed with requested state "started" and running, its
//     configuration has no passthrough or local device (hostpci, usb,
//     virtiofs, ivshmem, a serial port other than socket, a parallel port,
//     LXC dev) and no disk, unused volume or attached CD image on storage
//     that is not shared, its HA group and HA node-affinity rules (PVE 9) allow another online member (any other
//     HA rule is not modelled and counts as not movable), and that member
//     has free memory for it (first fit over all evacuating guests).
//
// Before anything is authorized, a Run with HA-evacuation entries waits
// (bounded by RebootEvacuationWait) until every one of them has left the
// node and HA reports it started on another online member; the cluster
// gates (quorum, votes, QDevice, members) are evaluated again on those
// fresh facts, and the dispatcher repeats the same post-evacuation check
// right before sending. HA not finishing the evacuation refuses the Run
// with ErrPveRebootEvacuation; nothing is sent.
//
// The bound facts are read again before authorization, immediately before
// the step's intent is recorded, and by the dispatcher right before the
// reboot is sent (the step carries the hash of the bound facts). Any drift
// sends nothing.
//
// PVE answers a node reboot without a task (pveapi.Writer.RebootNode), so
// the step is never matched to a UPID. Completion is observed instead: the
// step succeeds once the node is listed online again with an uptime that
// places its boot after the step's durable intent (and, for a cluster
// remote, the cluster is quorate with the node online again). It is then
// recorded with a NOS observation record in the UPID column (task type
// pveNodeRebootTaskType, process fields zero; PVE never creates such a
// task). A node that does not return within RebootMaxWait leaves the step
// unknown; an unknown step keeps blocking further reboots of the remote
// until its node is seen with a boot after the step's intent, or for
// pveRebootUnknownHold. A lost response is never sent again: it is
// observed the same way, and Reconcile does so after a restart.

// PveNodeRebootAction is the action ID of the node reboot.
const PveNodeRebootAction = "pve.node.reboot"

// Node reboot limits and fixed values.
const (
	// pveNodeRebootVersion is the module version of the reboot artifact.
	pveNodeRebootVersion = "1.0.0"
	// pveNodeRebootMethod is the only step method of the reboot.
	pveNodeRebootMethod = "node.reboot"
	// pveNodeRebootTaskType marks the job of a reboot step; PVE creates no
	// task for a node reboot and no PVE task has this type.
	pveNodeRebootTaskType = "nosnodereboot"
	// maxPveRebootGuests bounds the guests on the node a reboot binds; a
	// node with more is refused.
	maxPveRebootGuests = 128
	// maxPveRebootAccepted bounds the accepted-downtime and HA-evacuation
	// lists together.
	maxPveRebootAccepted = 128
	// maxPveRebootStepArgs bounds the arguments of the reboot step.
	maxPveRebootStepArgs = 8 << 10
	// pveRebootSettle is how long another cluster member must have been up
	// before a node may reboot: a member that booted more recently is
	// still rebooting or settling (one node at a time, quorum checked after
	// the return).
	pveRebootSettle = 5 * time.Minute
	// pveNodeRebootPollInterval is the default interval between node
	// reads while waiting for the node to return.
	pveNodeRebootPollInterval = 10 * time.Second
	// pveNodeRebootMaxWait bounds the wait for the node to return; after
	// it the outcome is unknown.
	pveNodeRebootMaxWait = 20 * time.Minute
	// maxPveNodeUptime bounds a reported uptime (about 100 years).
	maxPveNodeUptime = 100 * 366 * 24 * 3600
	// pveNodeRebootEvacuationWait is the default bound of a Run's wait for
	// HA to move the listed guests off the node.
	pveNodeRebootEvacuationWait = 15 * time.Minute
	// pveRebootUnknownHold is how long an unknown reboot step whose node
	// was never seen back blocks further reboots of the remote.
	pveRebootUnknownHold = 24 * time.Hour
	// maxPveHARules bounds the HA groups and rules a reboot reads.
	maxPveHARules = 256
)

// Effects of a reboot target, as listed in the parameters.
const (
	pveRebootEffectReboot     = "reboot"
	pveRebootEffectDowntime   = "downtime"
	pveRebootEffectEvacuation = "ha_evacuation"
	// pveRebootHAMoveRestart marks a guest HA moves by restart migration
	// (a container): it is stopped, moved and started again, so its
	// effect is downtime.
	pveRebootHAMoveRestart = "restart_migration"
)

// HA shutdown policies (datacenter option ha: shutdown_policy=...).
const (
	pveHAPolicyConditional = "conditional"
	pveHAPolicyMigrate     = "migrate"
)

var (
	// ErrPveRebootRequest is returned for a malformed node or
	// accepted-downtime list. Nothing is read or sent.
	ErrPveRebootRequest = errors.New("executor: unsupported pve node reboot request")
	// ErrPveRebootQuorum is returned when the remaining nodes would not keep
	// quorum, or the votes or QDevice state cannot be established. Nothing
	// is sent.
	ErrPveRebootQuorum = errors.New("executor: the cluster would lose quorum without the node, or its votes are unknown")
	// ErrPveRebootBusy is returned when another node of the cluster is
	// offline, rebooting or settling, or another node reboot of the remote
	// is open or running (at most one node at a time). Nothing is sent.
	ErrPveRebootBusy = errors.New("executor: another node of the cluster is offline, rebooting or settling")
	// ErrPveRebootGuests is returned when a running guest on the node is
	// neither evacuated by HA nor listed as accepted downtime, or an
	// accepted entry names no running guest of the node. Nothing is sent.
	ErrPveRebootGuests = errors.New("executor: a running guest on the node is neither HA-evacuated nor accepted downtime")
	// ErrPveRebootState is returned when the node is not online or the
	// node, cluster, HA or guest state could not be read completely.
	// Nothing is sent.
	ErrPveRebootState = errors.New("executor: pve node state does not allow the reboot")
	// ErrPveRebootChanged is returned when facts bound in the approval
	// changed. Nothing is sent.
	ErrPveRebootChanged = errors.New("executor: pve node, cluster or guests changed; the reboot needs a new approval")
	// ErrPveRebootUnavailable is returned when the engine's client has no
	// node reboot surface (PveNodeRebootClient).
	ErrPveRebootUnavailable = errors.New("executor: pve node reboot is not available")
	// ErrPveRebootRisk is returned when the risk floor could not be
	// established.
	ErrPveRebootRisk = errors.New("executor: pve node reboot risk could not be established")
	// ErrPveRebootNotEvacuable is returned when a guest the request lists
	// for HA evacuation is not provably movable by HA; it must be listed as
	// accepted downtime instead. Nothing is sent.
	ErrPveRebootNotEvacuable = errors.New("executor: a guest listed for HA evacuation is not provably movable; list it as accepted downtime")
	// ErrPveRebootEvacuation is returned when HA did not move every guest
	// listed for evacuation off the node (started on another online
	// member) in time, or one came back. Nothing is sent.
	ErrPveRebootEvacuation = errors.New("executor: HA did not finish evacuating the listed guests")
	// ErrPveRebootOffsite is returned for a remote the admin marked
	// offsite: NOS does not offer an offsite node reboot (ADR 0006).
	ErrPveRebootOffsite = errors.New("executor: pve node reboot of an offsite remote is not offered")
	// ErrPveRebootSite is returned for a remote whose site marker is not
	// set (nebula pve remote set-site): unknown is treated as offsite.
	ErrPveRebootSite = errors.New("executor: pve remote site is not set; node reboot needs it set to onsite")

	// errPveRebootEvacuating is returned by the post-evacuation check while
	// a listed guest is still on the node or not yet started elsewhere.
	errPveRebootEvacuating = fmt.Errorf("%w: still evacuating", ErrPveRebootEvacuation)
)

func pveNodeRebootArtifact() []byte {
	return []byte(PveNodeRebootAction + " " + pveNodeRebootVersion + "\n" +
		"Reboot the exact node of an onsite remote; in a cluster only while the remaining nodes keep quorum, no other node is offline or rebooting, and every running guest is accepted downtime or was moved off by HA before the reboot is sent.\n")
}

var pveNodeRebootStagePlan = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"pve-node-reboot-v1"}`))
	return s
}()

// NodeRebootStepTaskType returns the job task type of the reboot step
// method (no PVE task exists for it).
func NodeRebootStepTaskType(method string) (string, bool) {
	if method != pveNodeRebootMethod {
		return "", false
	}
	return pveNodeRebootTaskType, true
}

// PveQDevice is the QDevice state of a cluster.
type PveQDevice struct {
	// Known is true when the QDevice state was read.
	Known bool
	// Configured is true when the cluster has a QDevice.
	Configured bool
}

// PveNodeRebootFacts are the live facts a reboot binds, read with the read
// token (untrusted; validated by the action).
type PveNodeRebootFacts struct {
	// Nodes is the remote's node list (status and uptime).
	Nodes []pveapi.Node
	// Cluster is the cluster status; unavailable on a standalone node.
	Cluster pveapi.ClusterStatus
	// Votes, QDevice, HA and HAShutdownPolicy are read only for a cluster.
	Votes   pveapi.NodeVotes
	QDevice PveQDevice
	HA      pveapi.HAStatus
	// HAShutdownPolicy is the datacenter HA shutdown_policy ("conditional"
	// when not set).
	HAShutdownPolicy string
	// Guests are the QEMU and LXC guests on the node.
	Guests []pveapi.Guest
	// Placement holds what limits HA in moving each HA-managed guest on the
	// node with requested state "started" (read only for a cluster with
	// HA); a guest without an entry is not provably movable.
	Placement map[PveRebootGuestRef]PveRebootPlacement
}

// PveRebootPlacement is what limits HA in moving one guest off the node.
type PveRebootPlacement struct {
	// Known is set when the configuration, the node's storages and every
	// HA group and rule naming the guest were read and are modelled.
	Known bool
	// LocalResources is set when the guest has a passthrough or local
	// device, or a volume on storage that is not shared.
	LocalResources bool
	// Restricted is set when HA may place the guest only on AllowedNodes.
	Restricted   bool
	AllowedNodes []string
}

// PveNodeBoot is the observed state of a node after a reboot was sent.
type PveNodeBoot struct {
	// Online reports the node listed online exactly once.
	Online bool
	// UptimeSeconds is the node's reported uptime; 0 is not reported.
	UptimeSeconds uint64
	// Cluster is the cluster status read with it.
	Cluster pveapi.ClusterStatus
}

// PveNodeRebootClient is the node reboot surface of a PveMutationClient.
// The engine routes the reboot step only to a client implementing it.
type PveNodeRebootClient interface {
	// NodeRebootFacts reads the facts of a reboot of node with the read
	// token; cluster facts are read when the remote reports a cluster.
	NodeRebootFacts(ctx context.Context, rm executordb.PveRemote, node string, read pveapi.TokenSupplier) (PveNodeRebootFacts, error)
	// NodeBoot reads the node list and cluster status with the read token.
	NodeBoot(ctx context.Context, rm executordb.PveRemote, node string, read pveapi.TokenSupplier) (PveNodeBoot, error)
	// DispatchNodeReboot sends the reboot step with the action token after
	// rechecking every bound fact with the read token (see
	// DispatchNodeRebootStep). It returns no UPID. An error wrapping
	// ErrPveRejected means nothing was sent or the remote refused it.
	DispatchNodeReboot(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action, read pveapi.TokenSupplier) error
}

// PveRebootGuestRef names one guest by kind and VMID.
type PveRebootGuestRef struct {
	Kind string `json:"kind"`
	VMID uint64 `json:"vmid"`
}

// PveNodeRebootRequest names one reboot of one exact node.
type PveNodeRebootRequest struct {
	// Digest is the approved permit (Run only).
	Digest   canonical.Digest
	RemoteID string
	Node     string
	// AcceptedDowntime lists the running guests on the node whose downtime
	// the approval accepts. An entry for a guest that is not running on
	// the node is refused.
	AcceptedDowntime []PveRebootGuestRef
	// HAEvacuate lists the running guests on the node the approval expects
	// HA to move off before the reboot (the node in HA maintenance mode).
	// Each must be provably movable when proposed, and must have left the
	// node, started elsewhere, before the reboot is sent. Every running
	// guest on the node is in exactly one of the two lists.
	HAEvacuate []PveRebootGuestRef
}

func (r PveNodeRebootRequest) validate() error {
	if !permit.ValidPveNodeName(r.Node) || len(r.AcceptedDowntime)+len(r.HAEvacuate) > maxPveRebootAccepted {
		return ErrPveRebootRequest
	}
	seen := map[PveRebootGuestRef]bool{}
	for _, g := range slices.Concat(r.AcceptedDowntime, r.HAEvacuate) {
		if (g.Kind != permit.ProviderKindQemu && g.Kind != permit.ProviderKindLXC) || !validVMID(g.VMID) || seen[g] {
			return ErrPveRebootRequest
		}
		seen[g] = true
	}
	return nil
}

// accepted returns the accepted-downtime list sorted by kind and VMID.
func (r PveNodeRebootRequest) accepted() []PveRebootGuestRef {
	return sortedGuestRefs(r.AcceptedDowntime)
}

// evacuate returns the HA-evacuation list sorted by kind and VMID.
func (r PveNodeRebootRequest) evacuate() []PveRebootGuestRef { return sortedGuestRefs(r.HAEvacuate) }

func sortedGuestRefs(in []PveRebootGuestRef) []PveRebootGuestRef {
	out := slices.Clone(in)
	if out == nil {
		out = []PveRebootGuestRef{}
	}
	slices.SortFunc(out, cmpGuestRef)
	return out
}

func cmpGuestRef(a, b PveRebootGuestRef) int {
	if c := strings.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	switch {
	case a.VMID < b.VMID:
		return -1
	case a.VMID > b.VMID:
		return 1
	}
	return 0
}

// PveRebootMember is one bound cluster member.
type PveRebootMember struct {
	Name  string `json:"name"`
	Votes int    `json:"votes"`
}

// PveRebootGuest is one bound guest on the node.
type PveRebootGuest struct {
	Kind   string `json:"kind"`
	VMID   uint64 `json:"vmid"`
	Status string `json:"status"`
	// HAEvacuates is set when HA moves the guest off the node.
	HAEvacuates bool `json:"ha_evacuates"`
	// AcceptedDowntime is set when the request accepts its downtime.
	AcceptedDowntime bool `json:"accepted_downtime"`
}

// pveRebootBound are the live facts a reboot binds.
type pveRebootBound struct {
	Clustered        bool              `json:"clustered"`
	Cluster          string            `json:"cluster"`
	Members          []PveRebootMember `json:"members"`
	TotalVotes       int               `json:"total_votes"`
	RemainingVotes   int               `json:"remaining_votes"`
	HAShutdownPolicy string            `json:"ha_shutdown_policy"`
	Maintenance      bool              `json:"maintenance"`
	Guests           []PveRebootGuest  `json:"guests"`
}

// PveRebootTarget is one target of the reboot permit as listed in its
// parameters: the synthetic host ID and fingerprint the permit binds, the
// object it stands for and what the reboot does to it.
type PveRebootTarget struct {
	HostID      string `json:"host_id"`
	Fingerprint string `json:"host_key_fingerprint"`
	Kind        string `json:"kind"`
	Node        string `json:"node"`
	VMID        uint64 `json:"vmid,omitempty"`
	Effect      string `json:"effect"`
	// HAMove is set for a guest HA evacuates with downtime: how HA moves
	// it (pveRebootHAMoveRestart for a container).
	HAMove string `json:"ha_move,omitempty"`
}

// pveRebootParams are the action parameters bound in the approval.
type pveRebootParams struct {
	Node             string              `json:"node"`
	Risk             canonical.Risk      `json:"risk"`
	AcceptedDowntime []PveRebootGuestRef `json:"accepted_downtime"`
	HAEvacuate       []PveRebootGuestRef `json:"ha_evacuate"`
	// Targets are the permit's targets (the typed count of a CRITICAL
	// approval): the node, then every guest it takes down or HA moves.
	Targets []PveRebootTarget `json:"targets"`
	Bound   pveRebootBound    `json:"bound"`
	Steps   []PveMutationStep `json:"steps"`
}

// pveRebootStepArgs are the arguments of the reboot step: what the
// dispatcher needs to bind the facts again and compare them.
type pveRebootStepArgs struct {
	Node        string              `json:"node"`
	Clustered   bool                `json:"clustered"`
	Accepted    []PveRebootGuestRef `json:"accepted_downtime"`
	Evacuate    []PveRebootGuestRef `json:"ha_evacuate"`
	BoundSHA256 string              `json:"bound_sha256"`
}

// rebootPhase selects how bindNodeReboot treats the HA-evacuation list.
type rebootPhase int

const (
	// rebootPropose: every guest listed for evacuation is still on the node
	// and provably movable.
	rebootPropose rebootPhase = iota
	// rebootSend (post-evacuation, before authorization and sending):
	// every guest listed for evacuation has left the node and HA reports
	// it started on another online member.
	rebootSend
)

// bindNodeReboot derives the bound facts of a reboot of node with the
// accepted and HA-evacuation lists from live facts, refusing whatever the
// reboot does not allow in phase. remoteKind is the registered kind of the
// remote. Both phases bind the same facts for the same reboot.
func bindNodeReboot(node string, accepted, evacuate []PveRebootGuestRef, remoteKind pvecontract.Kind, f PveNodeRebootFacts, phase rebootPhase) (pveRebootBound, error) {
	self, ok := uniqueNode(f.Nodes, node)
	if !ok || self.Status != "online" {
		return pveRebootBound{}, ErrPveRebootState
	}
	b := pveRebootBound{Clustered: f.Cluster.Available, Members: []PveRebootMember{}, Guests: []PveRebootGuest{}}
	if !b.Clustered {
		// A cluster remote that does not show its cluster is unknown, never
		// standalone; a standalone remote lists only its own node.
		if remoteKind != pvecontract.KindStandalone || len(f.Nodes) != 1 {
			return pveRebootBound{}, ErrPveRebootState
		}
	} else if remoteKind != pvecontract.KindCluster {
		// A remote registered standalone that is in a cluster: the reboot
		// lock is per remote, so the cluster's other remotes would not see
		// it. It must be registered as the cluster.
		return pveRebootBound{}, ErrPveRebootState
	} else if err := bindRebootCluster(node, f, &b); err != nil {
		return pveRebootBound{}, err
	}
	guests, err := bindRebootGuests(node, accepted, evacuate, f, b, phase)
	if err != nil {
		return pveRebootBound{}, err
	}
	b.Guests = guests
	return b, nil
}

// uniqueNode returns the entry of node if the list names it exactly once.
func uniqueNode(nodes []pveapi.Node, node string) (pveapi.Node, bool) {
	var out pveapi.Node
	n := 0
	for _, x := range nodes {
		if x.Name == node {
			out = x
			n++
		}
	}
	return out, n == 1
}

// bindRebootCluster applies the cluster gates: quorum, every other member
// online and settled, votes and QDevice, HA state.
func bindRebootCluster(node string, f PveNodeRebootFacts, b *pveRebootBound) error {
	c := f.Cluster
	if !c.Quorum || c.Name == "" || len(c.Members) < 1 || c.NodesTotal != len(c.Members) {
		return ErrPveRebootQuorum
	}
	names := map[string]bool{}
	for _, m := range c.Members {
		if names[m.Name] || !permit.ValidPveNodeName(m.Name) {
			return ErrPveRebootState
		}
		names[m.Name] = true
		if !m.Online {
			// Another node offline (or this one not seen by corosync): one
			// node at a time, and quorum must be checked after its return.
			return ErrPveRebootBusy
		}
		n, ok := uniqueNode(f.Nodes, m.Name)
		if !ok {
			return ErrPveRebootState
		}
		if m.Name == node {
			continue
		}
		if n.Status != "online" || n.UptimeSeconds == 0 || n.UptimeSeconds > maxPveNodeUptime ||
			time.Duration(n.UptimeSeconds)*time.Second < pveRebootSettle {
			return ErrPveRebootBusy
		}
	}
	if !names[node] || c.NodesOnline != len(c.Members) || len(f.Nodes) != len(c.Members) {
		return ErrPveRebootState
	}
	if !f.Votes.Available || len(f.Votes.Votes) != len(names) {
		return ErrPveRebootQuorum
	}
	total := 0
	for name, v := range f.Votes.Votes {
		if !names[name] || v < 0 {
			return ErrPveRebootQuorum
		}
		total += v
		b.Members = append(b.Members, PveRebootMember{Name: name, Votes: v})
	}
	slices.SortFunc(b.Members, func(x, y PveRebootMember) int { return strings.Compare(x.Name, y.Name) })
	remaining := total - f.Votes.Votes[node]
	if total < 1 || 2*remaining <= total {
		return ErrPveRebootQuorum
	}
	if !f.QDevice.Known || f.QDevice.Configured {
		// QDevice votes are not modelled: its state is unknown here.
		return ErrPveRebootQuorum
	}
	if !f.HA.Available && !f.HA.NotConfigured {
		return ErrPveRebootState
	}
	if !validHAPolicy(f.HAShutdownPolicy) {
		return ErrPveRebootState
	}
	b.Cluster, b.TotalVotes, b.RemainingVotes, b.HAShutdownPolicy = c.Name, total, remaining, f.HAShutdownPolicy
	b.Maintenance = f.HA.Available && f.HA.Maintenance[node]
	return nil
}

// bindRebootGuests binds every guest on the node: each running guest is
// accepted downtime or listed for HA evacuation, every listed guest exists
// as phase requires. A guest HA evacuates is bound with status "running"
// whether it is still on the node (propose) or already moved (send).
func bindRebootGuests(node string, accepted, evacuate []PveRebootGuestRef, f PveNodeRebootFacts, b pveRebootBound, phase rebootPhase) ([]PveRebootGuest, error) {
	if len(f.Guests) > maxPveRebootGuests {
		return nil, ErrPveRebootState
	}
	acc, evac := map[PveRebootGuestRef]bool{}, map[PveRebootGuestRef]bool{}
	for _, a := range accepted {
		acc[a] = true
	}
	for _, e := range evacuate {
		if acc[e] {
			return nil, ErrPveRebootRequest
		}
		evac[e] = true
	}
	var evacuable map[PveRebootGuestRef]bool
	if phase == rebootPropose {
		evacuable = rebootEvacuable(node, evacuate, f, b)
	}
	present := map[PveRebootGuestRef]bool{}
	seen := map[uint64]bool{}
	out := make([]PveRebootGuest, 0, len(f.Guests)+len(evacuate))
	for _, g := range f.Guests {
		kind := string(g.Kind)
		if g.Node != node || (kind != permit.ProviderKindQemu && kind != permit.ProviderKindLXC) || g.VMID <= 0 ||
			!validVMID(uint64(g.VMID)) || seen[uint64(g.VMID)] || !validPveStatus(g.Status) {
			return nil, ErrPveRebootState
		}
		vmid := uint64(g.VMID)
		seen[vmid] = true
		ref := PveRebootGuestRef{Kind: kind, VMID: vmid}
		present[ref] = true
		switch {
		case evac[ref]:
			if phase == rebootSend {
				return nil, errPveRebootEvacuating
			}
			if !evacuable[ref] {
				return nil, ErrPveRebootNotEvacuable
			}
			out = append(out, PveRebootGuest{Kind: kind, VMID: vmid, Status: "running", HAEvacuates: true})
		case acc[ref]:
			if g.Status == "stopped" {
				// The approval would accept downtime of a guest that is
				// not running: it would not describe the reboot.
				return nil, ErrPveRebootGuests
			}
			out = append(out, PveRebootGuest{Kind: kind, VMID: vmid, Status: g.Status, AcceptedDowntime: true})
		case g.Status != "stopped":
			return nil, ErrPveRebootGuests
		default:
			out = append(out, PveRebootGuest{Kind: kind, VMID: vmid, Status: g.Status})
		}
	}
	for _, a := range accepted {
		if !present[a] {
			return nil, ErrPveRebootGuests
		}
	}
	for _, e := range evacuate {
		if present[e] {
			continue
		}
		if phase == rebootPropose {
			// Not on the node: the reboot does not impact it.
			return nil, ErrPveRebootGuests
		}
		if !haStartedElsewhere(f.HA, e, node, b) {
			return nil, errPveRebootEvacuating
		}
		out = append(out, PveRebootGuest{Kind: e.Kind, VMID: e.VMID, Status: "running", HAEvacuates: true})
	}
	slices.SortFunc(out, func(x, y PveRebootGuest) int {
		return cmpGuestRef(PveRebootGuestRef{Kind: x.Kind, VMID: x.VMID}, PveRebootGuestRef{Kind: y.Kind, VMID: y.VMID})
	})
	return out, nil
}

// haSIDType is the HA resource type of a guest kind.
func haSIDType(kind string) string {
	if kind == permit.ProviderKindLXC {
		return "ct"
	}
	return "vm"
}

// haResourceOf returns the HA resource of ref, if HA manages it.
func haResourceOf(ha pveapi.HAStatus, ref PveRebootGuestRef) (pveapi.HAResource, bool) {
	if !ha.Available {
		return pveapi.HAResource{}, false
	}
	for _, r := range ha.Resources {
		if r.VMID > 0 && uint64(r.VMID) == ref.VMID && r.Type == haSIDType(ref.Kind) && r.Managed {
			return r, true
		}
	}
	return pveapi.HAResource{}, false
}

// haStartedElsewhere reports whether HA reports ref started on another
// member of the bound cluster (every member is online, bindRebootCluster).
func haStartedElsewhere(ha pveapi.HAStatus, ref PveRebootGuestRef, node string, b pveRebootBound) bool {
	r, ok := haResourceOf(ha, ref)
	if !ok || r.DesiredState != "started" || r.State != "started" || r.Node == node {
		return false
	}
	return slices.ContainsFunc(b.Members, func(m PveRebootMember) bool { return m.Name == r.Node })
}

// rebootEvacuable returns the guests of evacuate that HA provably moves
// off node before the reboot: the node is in HA maintenance mode, and each
// such guest is running on the node, HA-managed with requested state
// "started", its placement is known without local resources, and a member
// HA may place it on has free memory for it (first fit, in list order, so
// the evacuating guests together fit).
func rebootEvacuable(node string, evacuate []PveRebootGuestRef, f PveNodeRebootFacts, b pveRebootBound) map[PveRebootGuestRef]bool {
	out := map[PveRebootGuestRef]bool{}
	if !b.Clustered || !b.Maintenance || len(evacuate) == 0 {
		return out
	}
	free := map[string]uint64{}
	var names []string
	for _, m := range b.Members {
		n, ok := uniqueNode(f.Nodes, m.Name)
		if m.Name == node || !ok || n.Status != "online" || n.MaxMemory == 0 || n.Memory > n.MaxMemory {
			continue
		}
		free[m.Name] = n.MaxMemory - n.Memory
		names = append(names, m.Name)
	}
	slices.Sort(names)
	guests := map[PveRebootGuestRef]pveapi.Guest{}
	for _, g := range f.Guests {
		if g.Node == node && g.VMID > 0 {
			guests[PveRebootGuestRef{Kind: string(g.Kind), VMID: uint64(g.VMID)}] = g
		}
	}
	for _, e := range evacuate {
		g, ok := guests[e]
		if !ok || g.Status != "running" || g.MaxMemory <= 0 {
			continue
		}
		if r, ok := haResourceOf(f.HA, e); !ok || r.DesiredState != "started" {
			continue
		}
		p, ok := f.Placement[e]
		if !ok || !p.Known || p.LocalResources {
			continue
		}
		need := uint64(g.MaxMemory)
		for _, name := range names {
			if (p.Restricted && !slices.Contains(p.AllowedNodes, name)) || free[name] < need {
				continue
			}
			free[name] -= need
			out[e] = true
			break
		}
	}
	return out
}

func pveRebootBoundHash(b pveRebootBound) (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", ErrPveMutationPlan
	}
	h, err := canonical.HashParameters(raw)
	if err != nil {
		return "", ErrPveMutationPlan
	}
	return h, nil
}

// PveNodeReboot proposes and runs node reboots on the executor's single
// PVE mutation engine.
type PveNodeReboot struct {
	Mutations *PveMutations
	// Criticality, if set, raises the risk to the executor criticality
	// records of the node, the remote and every guest on the node (an
	// unknown record counts HIGH, below both bases).
	Criticality PveCriticality
	// Floor, if set, is evaluated by Propose and raises the proposed risk
	// to it; it can only raise the risk.
	Floor permit.RiskPolicy
}

func (g *PveNodeReboot) client() (PveNodeRebootClient, error) {
	if g.Mutations == nil {
		return nil, errors.New("executor: pve node reboot: Mutations is required")
	}
	if err := g.Mutations.checkDeps(); err != nil {
		return nil, err
	}
	rc, ok := g.Mutations.Client.(PveNodeRebootClient)
	if !ok {
		return nil, ErrPveRebootUnavailable
	}
	return rc, nil
}

// risk is the reboot's base (HIGH standalone, CRITICAL cluster) raised by
// the criticality records of the node, the remote and the bound guests.
func (g *PveNodeReboot) risk(rm executordb.PveRemote, node string, b pveRebootBound) (canonical.Risk, error) {
	risk := canonical.RiskHigh
	if b.Clustered {
		risk = canonical.RiskCritical
	}
	if g.Criticality == nil {
		return risk, nil
	}
	nt, err := (permit.ProviderMutationTarget{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, Kind: permit.ProviderKindNode, Node: node}).RiskTarget()
	if err != nil {
		return "", ErrPveRebootRisk
	}
	remote, err := PveRemoteRiskTarget(rm.TrustPin)
	if err != nil {
		return "", ErrPveRebootRisk
	}
	targets := []canonical.Target{nt, remote}
	for _, gu := range b.Guests {
		gt, err := (permit.ProviderMutationTarget{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, Kind: gu.Kind, Node: node, VMID: gu.VMID}).RiskTarget()
		if err != nil {
			return "", ErrPveRebootRisk
		}
		targets = append(targets, gt)
	}
	for _, t := range targets {
		c, _, err := g.Criticality.HostCriticality(t.HostID, t.HostKeyFingerprint)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrPveRebootRisk, err)
		}
		if c.Rank() > risk.Rank() {
			risk = c
		}
	}
	return risk, nil
}

// checkRebootSite refuses a remote that is not marked onsite: offsite is
// never offered, an unset marker is unknown and treated alike.
func checkRebootSite(rm executordb.PveRemote) error {
	switch rm.Site {
	case executordb.SiteOnsite:
		return nil
	case executordb.SiteOffsite:
		return ErrPveRebootOffsite
	}
	return ErrPveRebootSite
}

// rebootRemote returns the active remote with an action credential that
// is marked onsite.
func (m *PveMutations) rebootRemote(remoteID string) (executordb.PveRemote, error) {
	rm, err := m.activeRemote(remoteID)
	if err != nil {
		return executordb.PveRemote{}, err
	}
	if err := checkRebootSite(rm); err != nil {
		return executordb.PveRemote{}, err
	}
	return rm, nil
}

// rebootTargets returns the permit targets of a reboot of node with the
// bound facts b: the node, then every guest it takes down or HA moves, in
// bound order. An LXC guest listed for HA evacuation is listed with effect
// downtime and HAMove pveRebootHAMoveRestart.
func rebootTargets(rm executordb.PveRemote, node string, b pveRebootBound) ([]canonical.Target, []PveRebootTarget, error) {
	add := func(ts []canonical.Target, ls []PveRebootTarget, kind string, vmid uint64, effect string) ([]canonical.Target, []PveRebootTarget, error) {
		t, err := (permit.ProviderMutationTarget{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, Kind: kind, Node: node, VMID: vmid}).RiskTarget()
		if err != nil {
			return nil, nil, ErrPveMutationPlan
		}
		return append(ts, t), append(ls, PveRebootTarget{HostID: t.HostID, Fingerprint: t.HostKeyFingerprint, Kind: kind, Node: node, VMID: vmid, Effect: effect}), nil
	}
	ts, ls, err := add(nil, nil, permit.ProviderKindNode, 0, pveRebootEffectReboot)
	if err != nil {
		return nil, nil, err
	}
	for _, g := range b.Guests {
		effect, move := "", ""
		switch {
		case g.HAEvacuates && g.Kind == permit.ProviderKindLXC:
			// HA moves a container by restart migration: downtime.
			effect, move = pveRebootEffectDowntime, pveRebootHAMoveRestart
		case g.HAEvacuates:
			effect = pveRebootEffectEvacuation
		case g.AcceptedDowntime:
			effect = pveRebootEffectDowntime
		default:
			continue
		}
		if ts, ls, err = add(ts, ls, g.Kind, g.VMID, effect); err != nil {
			return nil, nil, err
		}
		ls[len(ls)-1].HAMove = move
	}
	return ts, ls, nil
}

func (g *PveNodeReboot) prepare(ctx context.Context, rc PveNodeRebootClient, req PveNodeRebootRequest, phase rebootPhase) (PveMutationRequest, error) {
	m := g.Mutations
	rm, err := m.rebootRemote(req.RemoteID)
	if err != nil {
		return PveMutationRequest{}, err
	}
	base := PveMutationRequest{RemoteID: req.RemoteID, Kind: permit.ProviderKindNode, Node: req.Node}
	if _, _, err := m.targetLive(ctx, rm, base); err != nil {
		return PveMutationRequest{}, err
	}
	read, err := m.readToken(rm)
	if err != nil {
		return PveMutationRequest{}, err
	}
	f, err := rc.NodeRebootFacts(ctx, rm, req.Node, read)
	if err != nil {
		return PveMutationRequest{}, ErrPveRebootState
	}
	// One node at a time first: an open or unknown reboot of the remote
	// refuses whatever the guests look like.
	if err := m.openNodeReboot(rm.RemoteID, f); err != nil {
		return PveMutationRequest{}, err
	}
	accepted, evacuate := req.accepted(), req.evacuate()
	b, err := bindNodeReboot(req.Node, accepted, evacuate, rm.Kind, f, phase)
	if err != nil {
		return PveMutationRequest{}, err
	}
	risk, err := g.risk(rm, req.Node, b)
	if err != nil {
		return PveMutationRequest{}, err
	}
	hash, err := pveRebootBoundHash(b)
	if err != nil {
		return PveMutationRequest{}, err
	}
	_, targets, err := rebootTargets(rm, req.Node, b)
	if err != nil {
		return PveMutationRequest{}, err
	}
	rawArgs, err := json.Marshal(pveRebootStepArgs{Node: req.Node, Clustered: b.Clustered, Accepted: accepted, Evacuate: evacuate, BoundSHA256: hash})
	if err != nil || len(rawArgs) > maxPveRebootStepArgs {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	params, err := json.Marshal(pveRebootParams{Node: req.Node, Risk: risk, AcceptedDowntime: accepted, HAEvacuate: evacuate,
		Targets: targets, Bound: b, Steps: []PveMutationStep{{Method: pveNodeRebootMethod, Args: rawArgs}}})
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	base.Digest, base.ActionID, base.ModuleVersion, base.Artifact, base.Parameters = req.Digest, PveNodeRebootAction, pveNodeRebootVersion, pveNodeRebootArtifact(), params
	base.liveCheck = func(ctx context.Context, rm executordb.PveRemote, live PveTargetState, read pveapi.TokenSupplier) error {
		if err := checkRebootSite(rm); err != nil {
			return err
		}
		if live.Node != req.Node {
			return ErrPveTargetChanged
		}
		f, err := rc.NodeRebootFacts(ctx, rm, req.Node, read)
		if err != nil {
			return ErrPveRebootState
		}
		// One node at a time, also across restarts: no reboot step of the
		// remote may still be open or unknown with its node not seen back.
		if err := m.openNodeReboot(rm.RemoteID, f); err != nil {
			return err
		}
		again, err := bindNodeReboot(req.Node, accepted, evacuate, rm.Kind, f, phase)
		if err != nil {
			return err
		}
		if h, err := pveRebootBoundHash(again); err != nil || h != hash {
			return ErrPveRebootChanged
		}
		return nil
	}
	return base, nil
}

// Propose proposes req for the exact node, binding the cluster membership
// snapshot and every guest on the node. The risk is HIGH for a standalone
// node and CRITICAL in a cluster, raised by Criticality and Floor. The
// permit's targets are the node and every guest the reboot takes down or
// HA moves, so a CRITICAL approval types their number.
func (g *PveNodeReboot) Propose(ctx context.Context, req PveNodeRebootRequest, executionID string, expiry time.Time) (permit.Permit, error) {
	if err := req.validate(); err != nil {
		return permit.Permit{}, err
	}
	rc, err := g.client()
	if err != nil {
		return permit.Permit{}, err
	}
	m := g.Mutations
	if m.nodeRebootRunning(req.RemoteID) {
		return permit.Permit{}, ErrPveRebootBusy
	}
	mreq, err := g.prepare(ctx, rc, req, rebootPropose)
	if err != nil {
		return permit.Permit{}, err
	}
	var doc pveRebootParams
	if err := json.Unmarshal(mreq.Parameters, &doc); err != nil {
		return permit.Permit{}, ErrPveMutationPlan
	}
	rq, params, err := m.ProposalRequest(ctx, mreq, executionID, doc.Risk, pveNodeRebootStagePlan, expiry)
	if err != nil {
		return permit.Permit{}, err
	}
	if len(rq.ResolvedTargets) != 1 || len(doc.Targets) == 0 ||
		rq.ResolvedTargets[0] != (canonical.Target{HostID: doc.Targets[0].HostID, HostKeyFingerprint: doc.Targets[0].Fingerprint}) {
		return permit.Permit{}, ErrPveMutationPlan
	}
	rq.ResolvedTargets = make([]canonical.Target, 0, len(doc.Targets))
	for _, t := range doc.Targets {
		rq.ResolvedTargets = append(rq.ResolvedTargets, canonical.Target{HostID: t.HostID, HostKeyFingerprint: t.Fingerprint})
	}
	if g.Floor != nil {
		f, _, err := g.Floor.MinimumRisk(rq, rq.ResolvedTargets)
		if err != nil {
			return permit.Permit{}, fmt.Errorf("%w: %w", ErrPveRebootRisk, err)
		}
		if f.Rank() > rq.RiskClass.Rank() {
			rq.RiskClass = f
		}
	}
	res, err := m.Auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return permit.Permit{}, err
	}
	m.log().Info("audit", "kind", "pve_node_reboot_proposed", "remote", req.RemoteID, "node", req.Node,
		"guests", len(doc.Bound.Guests), "targets", len(doc.Targets), "risk", string(res.Permit.Request.RiskClass), "execution", executionID)
	return res.Permit, nil
}

// Run runs the approved reboot req.Digest. At most one reboot per remote
// runs at a time. With HA-evacuation entries it first waits, bounded by
// RebootEvacuationWait, until HA moved every listed guest off the node
// (post-evacuation check, nothing authorized yet). Every bound fact is
// read again before authorization, immediately before the step's intent
// and by the dispatcher before the reboot is sent; the risk is derived
// again and is part of the bound parameters. Run then waits (bounded) for
// the node to return.
func (g *PveNodeReboot) Run(ctx context.Context, req PveNodeRebootRequest) (PveMutationResult, error) {
	if err := req.validate(); err != nil {
		return PveMutationResult{}, err
	}
	rc, err := g.client()
	if err != nil {
		return PveMutationResult{}, err
	}
	release, ok := g.Mutations.lockNodeReboot(req.RemoteID)
	if !ok {
		return PveMutationResult{}, ErrPveRebootBusy
	}
	defer release()
	if len(req.HAEvacuate) > 0 {
		if err := g.awaitEvacuation(ctx, rc, req); err != nil {
			return PveMutationResult{}, err
		}
	}
	mreq, err := g.prepare(ctx, rc, req, rebootSend)
	if err != nil {
		return PveMutationResult{}, err
	}
	return g.Mutations.Run(ctx, mreq)
}

func (m *PveMutations) rebootEvacuationWait() time.Duration {
	if m.RebootEvacuationWait > 0 {
		return m.RebootEvacuationWait
	}
	return pveNodeRebootEvacuationWait
}

func (m *PveMutations) rebootPollInterval() time.Duration {
	if m.RebootPollInterval > 0 {
		return m.RebootPollInterval
	}
	return pveNodeRebootPollInterval
}

// awaitEvacuation polls the facts until the post-evacuation check of req
// passes: every listed guest left the node and runs started on another
// online member, with all cluster gates met. Any other refusal ends the
// wait at once; unreadable facts and guests still moving keep waiting
// until RebootEvacuationWait passed (ErrPveRebootEvacuation).
func (g *PveNodeReboot) awaitEvacuation(ctx context.Context, rc PveNodeRebootClient, req PveNodeRebootRequest) error {
	m := g.Mutations
	rm, err := m.rebootRemote(req.RemoteID)
	if err != nil {
		return err
	}
	read, err := m.readToken(rm)
	if err != nil {
		return err
	}
	accepted, evacuate := req.accepted(), req.evacuate()
	deadline := m.now().Add(m.rebootEvacuationWait())
	for {
		f, err := rc.NodeRebootFacts(ctx, rm, req.Node, read)
		if err == nil {
			_, err = bindNodeReboot(req.Node, accepted, evacuate, rm.Kind, f, rebootSend)
			if err == nil {
				return nil
			}
			if !errors.Is(err, errPveRebootEvacuating) {
				return err
			}
		}
		if !m.now().Before(deadline) {
			m.log().Warn("audit", "kind", "pve_node_reboot_refused", "remote", req.RemoteID, "node", req.Node, "reason", "HA evacuation not finished")
			return ErrPveRebootEvacuation
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrPveRebootEvacuation, ctx.Err())
		case <-time.After(m.rebootPollInterval()):
		}
	}
}

// PveNodeRebootWriter is the part of pveapi.Writer the reboot step uses
// (action token).
type PveNodeRebootWriter interface {
	RebootNode(ctx context.Context, node string) error
}

// PveNodeRebootReader reads the facts of a reboot right before sending
// (read token).
type PveNodeRebootReader interface {
	NodeRebootFacts(ctx context.Context, node string) (PveNodeRebootFacts, error)
}

// DispatchNodeRebootStep decodes the reboot step strictly, reads the facts
// again with rd, binds them as the approval did and sends the reboot with w
// only if the hash of the bound facts is the approved one. Any refusal
// before sending, or by PVE, wraps ErrPveRejected; a reboot whose answer
// was lost returns another error (it may have been sent).
func DispatchNodeRebootStep(ctx context.Context, w PveNodeRebootWriter, rd PveNodeRebootReader, remoteKind pvecontract.Kind, node string, step PveMutationStep) error {
	if step.Method != pveNodeRebootMethod || w == nil || rd == nil {
		return fmt.Errorf("dispatch node reboot: %w", ErrPveRejected)
	}
	var a pveRebootStepArgs
	if err := decodeStepArgsMax(step.Args, &a, maxPveRebootStepArgs); err != nil {
		return err
	}
	reject := func(why string) error {
		return fmt.Errorf("dispatch %s: %s: %w", step.Method, why, ErrPveRejected)
	}
	req := PveNodeRebootRequest{Node: a.Node, AcceptedDowntime: a.Accepted, HAEvacuate: a.Evacuate}
	if a.Node != node || req.validate() != nil || !slices.IsSortedFunc(a.Accepted, cmpGuestRef) || !slices.IsSortedFunc(a.Evacuate, cmpGuestRef) {
		return reject("arguments")
	}
	f, err := rd.NodeRebootFacts(ctx, node)
	if err != nil {
		return reject("facts")
	}
	// Post-evacuation check: every guest listed for HA evacuation has left
	// the node, started elsewhere, and the cluster gates hold without it.
	b, err := bindNodeReboot(node, a.Accepted, a.Evacuate, remoteKind, f, rebootSend)
	if err != nil {
		return reject("gates")
	}
	if h, err := pveRebootBoundHash(b); err != nil || h != a.BoundSHA256 || b.Clustered != a.Clustered {
		return reject("bound facts changed")
	}
	_, err = pveWriteResult(step.Method, "", w.RebootNode(ctx, node))
	return err
}

// pveNodeRebootRecord is the observation record stored in a reboot step's
// UPID column once the node is seen back: a UPID-shaped string with zero
// process fields, the observed boot time, the NOS-only task type, the
// permit digest as ID and the action token user. PVE never creates it.
func pveNodeRebootRecord(job executordb.PveJob, bootAt time.Time) string {
	id := job.Digest
	if len(id) > 32 {
		id = id[:32]
	}
	return fmt.Sprintf("UPID:%s:00000000:00000000:%08X:%s:%s:%s:", job.Node, bootAt.Unix(), pveNodeRebootTaskType, id, job.TaskUser)
}

var _ PveNodeRebootClient = (*pveMutationClient)(nil)

// NodeRebootFacts implements PveNodeRebootClient with the read token over
// the remote's pinned transport.
func (c *pveMutationClient) NodeRebootFacts(ctx context.Context, rm executordb.PveRemote, node string, read pveapi.TokenSupplier) (PveNodeRebootFacts, error) {
	if !permit.ValidPveNodeName(node) || read == nil {
		return PveNodeRebootFacts{}, ErrPveMutationRequest
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return PveNodeRebootFacts{}, err
	}
	f, err := pveNodeRebootFacts(ctx, hc, base, read, node)
	if err = c.checkTrust(rm, watch, err); err != nil {
		return PveNodeRebootFacts{}, err
	}
	return f, nil
}

// pveRebootInventory returns the pveapi client for the node and guest
// lists (ListNodes, ListQemu, ListLxc add the API root themselves) and the
// one for the storage list (relative to the API root).
func pveRebootInventory(hc *http.Client, base string, read pveapi.TokenSupplier) (inv, pc *pveapi.Client, err error) {
	if inv, err = pveapi.New(base, hc, read, pveapi.WithTimeout(pveMutationRequestTimeout)); err != nil {
		return nil, nil, errPveMutationRead
	}
	if pc, err = pveapi.NewClient(hc, base+"/api2/json", read); err != nil {
		return nil, nil, errPveMutationRead
	}
	return inv, pc, nil
}

func pveNodeRebootFacts(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, node string) (PveNodeRebootFacts, error) {
	inv, pc, err := pveRebootInventory(hc, base, read)
	if err != nil {
		return PveNodeRebootFacts{}, err
	}
	var f PveNodeRebootFacts
	if f.Nodes, err = inv.ListNodes(ctx); err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	cr := pc // NewClient-built clients serve the cluster reads (#228)
	if f.Cluster, err = cr.ClusterStatus(ctx); err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	if f.Cluster.Available {
		if f.Votes, err = cr.ClusterNodeVotes(ctx); err != nil {
			return PveNodeRebootFacts{}, errPveMutationRead
		}
		if f.HA, err = cr.HAStatus(ctx); err != nil {
			return PveNodeRebootFacts{}, errPveMutationRead
		}
		var qd map[string]json.RawMessage
		if err := pveGetData(ctx, hc, base, read, "/cluster/config/qdevice", nil, &qd); err == nil && qd != nil {
			f.QDevice = PveQDevice{Known: true, Configured: len(qd) != 0}
		}
		if f.HAShutdownPolicy, err = pveHAShutdownPolicy(ctx, hc, base, read); err != nil {
			return PveNodeRebootFacts{}, err
		}
	}
	qemu, err := inv.ListQemu(ctx, node)
	if err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	lxc, err := inv.ListLxc(ctx, node)
	if err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	if len(qemu)+len(lxc) > maxPveRebootGuests {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	f.Guests = append(qemu, lxc...)
	if f.Cluster.Available && f.HA.Available {
		f.Placement = pveRebootPlacements(ctx, hc, base, read, pc, node, f)
	}
	return f, nil
}

// pveRebootPlacements reads the placement of every HA-managed guest on
// node with requested state "started". A read that fails or returns
// something not modelled leaves that guest's placement unknown (not
// provably movable); a failed trust check is still seen by the caller's
// trust watch.
func pveRebootPlacements(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, pc *pveapi.Client, node string, f PveNodeRebootFacts) map[PveRebootGuestRef]PveRebootPlacement {
	out := map[PveRebootGuestRef]PveRebootPlacement{}
	var refs []PveRebootGuestRef
	for _, g := range f.Guests {
		ref := PveRebootGuestRef{Kind: string(g.Kind), VMID: uint64(max(g.VMID, 0))}
		if r, ok := haResourceOf(f.HA, ref); ok && g.Node == node && r.DesiredState == "started" {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return out
	}
	var shared map[string]bool
	if list, err := pc.ListStorages(ctx, node); err == nil && list.Complete {
		shared = make(map[string]bool, len(list.Storages))
		for _, st := range list.Storages {
			shared[st.ID] = st.Shared && st.Active
		}
	}
	ha := pveReadHAPlacement(ctx, hc, base, read)
	for _, ref := range refs {
		p := PveRebootPlacement{}
		if shared != nil && ha.known {
			cfg, err := pveGuestConfigStrings(ctx, hc, base, read, ref.Kind, node, ref.VMID, pveRebootPlacementKey)
			if err == nil {
				p.Restricted, p.AllowedNodes, p.Known = ha.placement(haSIDType(ref.Kind) + ":" + strconv.FormatUint(ref.VMID, 10))
				p.LocalResources = rebootLocalResources(ref.Kind, cfg, shared)
			}
		}
		out[ref] = p
	}
	return out
}

var (
	pveRebootLocalDeviceRe = regexp.MustCompile(`^(?:hostpci|usb|virtiofs|ivshmem)[0-9]*$`)
	pveRebootLXCDeviceRe   = regexp.MustCompile(`^dev[0-9]+$`)
	// pveRebootCharDeviceRe matches the QEMU serial and parallel ports: a
	// parallel port and a serial port other than "socket" use a host
	// device, which PVE treats as a local resource.
	pveRebootCharDeviceRe = regexp.MustCompile(`^(?:serial|parallel)[0-9]+$`)
)

// pveRebootSerialSocket is the serial port value that uses no host device.
const pveRebootSerialSocket = "socket"

// pveRebootPlacementKey reports whether a config member matters to HA
// moving the guest; such a member must be a bounded string.
func pveRebootPlacementKey(k string) bool {
	return pveMigrateRelevantConfigKey(k) || pveRebootLocalDeviceRe.MatchString(k) || pveRebootLXCDeviceRe.MatchString(k) ||
		pveRebootCharDeviceRe.MatchString(k)
}

// rebootLocalResources reports whether the guest configuration ties the
// guest to its node: a passthrough or local device, a CD image or a volume
// (disk or unused) on storage that is not shared and active, a serial port
// on a host device or a parallel port, a passthrough disk or bind mount, or
// a config the disk parser does not accept.
func rebootLocalResources(kind string, cfg map[string]string, shared map[string]bool) bool {
	for k, v := range cfg {
		if pveRebootLocalDeviceRe.MatchString(k) || (kind == permit.ProviderKindLXC && pveRebootLXCDeviceRe.MatchString(k)) {
			return true
		}
		if kind == permit.ProviderKindQemu && pveRebootCharDeviceRe.MatchString(k) &&
			(strings.HasPrefix(k, "parallel") || v != pveRebootSerialSocket) {
			return true
		}
		if kind == permit.ProviderKindQemu && pveQemuDiskKeyRe.MatchString(k) && slices.Contains(strings.Split(v, ","), "media=cdrom") {
			vol, _, _ := strings.Cut(v, ",")
			if vol == "none" || vol == "cdrom" {
				continue
			}
			storage, _, ok := strings.Cut(vol, ":")
			if !ok || !shared[storage] {
				return true
			}
		}
	}
	disks, err := migrateDiskSet(kind, cfg, nil)
	if err != nil {
		return true
	}
	for _, d := range disks {
		if !shared[d.Storage] {
			return true
		}
	}
	return false
}

// pveHAPlacementRule is one HA group (PVE 8) or HA rule (PVE 9) as far as
// it limits where HA may place a resource.
type pveHAPlacementRule struct {
	// nodeAffinity is set for a group or a node-affinity rule; any other
	// rule type naming a resource makes its placement unknown.
	nodeAffinity bool
	// strict is set for a restricted group or a strict rule: HA places the
	// resource only on nodes.
	strict bool
	nodes  []string
}

// pveHAPlacement is the HA configuration that limits placement.
type pveHAPlacement struct {
	known bool
	// groupOf maps a resource SID to its HA group ("" for none).
	groupOf map[string]string
	groups  map[string]pveHAPlacementRule
	// rules maps a resource SID to the enabled HA rules naming it.
	rules map[string][]pveHAPlacementRule
}

// placement returns whether HA may place sid only on allowed, and whether
// that is known.
func (h pveHAPlacement) placement(sid string) (restricted bool, allowed []string, known bool) {
	if !h.known {
		return false, nil, false
	}
	var rules []pveHAPlacementRule
	if g := h.groupOf[sid]; g != "" {
		grp, ok := h.groups[g]
		if !ok {
			return false, nil, false
		}
		rules = append(rules, grp)
	}
	rules = append(rules, h.rules[sid]...)
	for _, r := range rules {
		if !r.nodeAffinity {
			return false, nil, false
		}
		if !r.strict {
			continue
		}
		if !restricted {
			restricted, allowed = true, slices.Clone(r.nodes)
			continue
		}
		allowed = slices.DeleteFunc(allowed, func(n string) bool { return !slices.Contains(r.nodes, n) })
	}
	return restricted, allowed, true
}

// pveReadHAPlacement reads GET /cluster/ha/resources (group of each
// resource), GET /cluster/ha/groups when a resource names a group, and GET
// /cluster/ha/rules (PVE 9; absent on PVE 8). Anything unreadable or
// malformed leaves it unknown.
func pveReadHAPlacement(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier) pveHAPlacement {
	h := pveHAPlacement{groupOf: map[string]string{}, groups: map[string]pveHAPlacementRule{}, rules: map[string][]pveHAPlacementRule{}}
	var res []map[string]json.RawMessage
	if err := pveGetData(ctx, hc, base, read, "/cluster/ha/resources", nil, &res); err != nil || len(res) > maxPveHARules {
		return pveHAPlacement{}
	}
	needGroups := false
	for _, r := range res {
		sid, ok := haString(r, "sid")
		if !ok || sid == "" {
			return pveHAPlacement{}
		}
		group, ok := haString(r, "group")
		if !ok {
			return pveHAPlacement{}
		}
		h.groupOf[sid] = group
		needGroups = needGroups || group != ""
	}
	if needGroups {
		var groups []map[string]json.RawMessage
		if err := pveGetData(ctx, hc, base, read, "/cluster/ha/groups", nil, &groups); err != nil || len(groups) > maxPveHARules {
			return pveHAPlacement{}
		}
		for _, g := range groups {
			name, ok1 := haString(g, "group")
			nodes, ok2 := haNodeList(g)
			restricted, ok3 := haFlag(g, "restricted")
			if !ok1 || !ok2 || !ok3 || name == "" {
				return pveHAPlacement{}
			}
			h.groups[name] = pveHAPlacementRule{nodeAffinity: true, strict: restricted, nodes: nodes}
		}
	}
	var rules []map[string]json.RawMessage
	found, err := pveGetOptionalData(ctx, hc, base, read, "/cluster/ha/rules", &rules)
	if err != nil || len(rules) > maxPveHARules {
		return pveHAPlacement{}
	}
	if found {
		for _, r := range rules {
			typ, ok1 := haString(r, "type")
			resources, ok2 := haString(r, "resources")
			disabled, ok3 := haFlag(r, "disable")
			strict, ok4 := haFlag(r, "strict")
			if !ok1 || !ok2 || !ok3 || !ok4 {
				return pveHAPlacement{}
			}
			if disabled {
				continue
			}
			rule := pveHAPlacementRule{nodeAffinity: typ == "node-affinity", strict: strict}
			if rule.nodeAffinity {
				nodes, ok := haNodeList(r)
				if !ok {
					return pveHAPlacement{}
				}
				rule.nodes = nodes
			}
			for _, sid := range strings.Split(resources, ",") {
				if sid = strings.TrimSpace(sid); sid != "" {
					h.rules[sid] = append(h.rules[sid], rule)
				}
			}
		}
	}
	h.known = true
	return h
}

// haString returns the string member key of m; absent is "".
func haString(m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := m[key]
	if !ok {
		return "", true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || len(s) > 4096 {
		return "", false
	}
	return s, true
}

// haFlag returns the 0/1 (or boolean) member key of m; absent is false.
func haFlag(m map[string]json.RawMessage, key string) (bool, bool) {
	raw, ok := m[key]
	if !ok {
		return false, true
	}
	switch strings.TrimSpace(string(raw)) {
	case "0", "false", `"0"`:
		return false, true
	case "1", "true", `"1"`:
		return true, true
	}
	return false, false
}

// haNodeList parses the "nodes" member ("pve1:2,pve2") into node names.
func haNodeList(m map[string]json.RawMessage) ([]string, bool) {
	s, ok := haString(m, "nodes")
	if !ok || s == "" {
		return nil, false
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		name, prio, hasPrio := strings.Cut(strings.TrimSpace(part), ":")
		if !permit.ValidPveNodeName(name) {
			return nil, false
		}
		if hasPrio {
			if _, err := strconv.ParseUint(prio, 10, 16); err != nil {
				return nil, false
			}
		}
		out = append(out, name)
	}
	return out, true
}

// pveHAShutdownPolicy reads the datacenter HA shutdown_policy from
// GET /cluster/options ("conditional" when the ha option is not set).
func pveHAShutdownPolicy(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier) (string, error) {
	var opts map[string]json.RawMessage
	if err := pveGetData(ctx, hc, base, read, "/cluster/options", nil, &opts); err != nil {
		return "", err
	}
	raw, ok := opts["ha"]
	if !ok {
		return pveHAPolicyConditional, nil
	}
	return decodeHAOption(raw)
}

// maxPveHAOptionBytes bounds the datacenter ha option.
const maxPveHAOptionBytes = 256

// decodeHAOption reads the shutdown policy from the ha option, which PVE
// renders as a property string or as its parsed object; anything else is
// refused.
func decodeHAOption(raw json.RawMessage) (string, error) {
	if len(raw) > maxPveHAOptionBytes {
		return "", errPveMutationRead
	}
	var ha string
	if err := json.Unmarshal(raw, &ha); err == nil {
		return parseHAShutdownPolicy(ha)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return "", errPveMutationRead
	}
	sp, ok := obj["shutdown_policy"]
	if !ok {
		return pveHAPolicyConditional, nil
	}
	var policy string
	if err := json.Unmarshal(sp, &policy); err != nil || !validHAPolicy(policy) {
		return "", errPveMutationRead
	}
	return policy, nil
}

func validHAPolicy(p string) bool {
	switch p {
	case "freeze", "failover", pveHAPolicyConditional, pveHAPolicyMigrate:
		return true
	}
	return false
}

// parseHAShutdownPolicy reads shutdown_policy from a PVE property string
// ("shutdown_policy=migrate"); absent means conditional.
func parseHAShutdownPolicy(ha string) (string, error) {
	policy := pveHAPolicyConditional
	seen := false
	for _, part := range strings.Split(ha, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return "", errPveMutationRead
		}
		if k != "shutdown_policy" {
			continue
		}
		if seen {
			return "", errPveMutationRead
		}
		seen = true
		if !validHAPolicy(v) {
			return "", errPveMutationRead
		}
		policy = v
	}
	return policy, nil
}

// NodeBoot implements PveNodeRebootClient with the read token.
func (c *pveMutationClient) NodeBoot(ctx context.Context, rm executordb.PveRemote, node string, read pveapi.TokenSupplier) (PveNodeBoot, error) {
	if !permit.ValidPveNodeName(node) || read == nil {
		return PveNodeBoot{}, ErrPveMutationRequest
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return PveNodeBoot{}, err
	}
	nb, err := pveNodeBoot(ctx, hc, base, read, node)
	if err = c.checkTrust(rm, watch, err); err != nil {
		return PveNodeBoot{}, err
	}
	return nb, nil
}

func pveNodeBoot(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, node string) (PveNodeBoot, error) {
	inv, pc, err := pveRebootInventory(hc, base, read)
	if err != nil {
		return PveNodeBoot{}, err
	}
	nodes, err := inv.ListNodes(ctx)
	if err != nil {
		return PveNodeBoot{}, errPveMutationRead
	}
	cs, err := pc.ClusterStatus(ctx)
	if err != nil {
		return PveNodeBoot{}, errPveMutationRead
	}
	n, ok := uniqueNode(nodes, node)
	return PveNodeBoot{Online: ok && n.Status == "online", UptimeSeconds: n.UptimeSeconds, Cluster: cs}, nil
}

// DispatchNodeReboot implements PveNodeRebootClient:
// DispatchNodeRebootStep with a writer that carries only action and a
// reader that carries only read, over the remote's pinned transport.
func (c *pveMutationClient) DispatchNodeReboot(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action, read pveapi.TokenSupplier) error {
	if step.Method != pveNodeRebootMethod || action == nil || read == nil || !permit.ValidPveNodeName(node) {
		return fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
	}
	if err := checkRebootSite(rm); err != nil {
		return fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, err)
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, err)
	}
	w, err := pveapi.NewWriter(base, hc, action, pveMutationRequestTimeout)
	if err != nil {
		return fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
	}
	err = DispatchNodeRebootStep(ctx, w, pveRebootFactReader{hc: hc, base: base, read: read}, rm.Kind, node, step)
	if watch.failed.Load() {
		c.blockRemote(rm)
		return fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, errPveReadTrust)
	}
	return err
}

// pveRebootFactReader is the production PveNodeRebootReader.
type pveRebootFactReader struct {
	hc   *http.Client
	base string
	read pveapi.TokenSupplier
}

func (r pveRebootFactReader) NodeRebootFacts(ctx context.Context, node string) (PveNodeRebootFacts, error) {
	return pveNodeRebootFacts(ctx, r.hc, r.base, r.read, node)
}

// nodeRebootStep reports whether step is the reboot step.
func nodeRebootStep(step PveMutationStep) bool { return step.Method == pveNodeRebootMethod }

// awaitNodeReboot waits, bounded by RebootMaxWait from the intent, for the
// node of a sent (or possibly sent) reboot step to return. A node that does
// not return in time leaves the step unknown; a cancelled ctx leaves it
// open for Reconcile.
func (m *PveMutations) awaitNodeReboot(ctx context.Context, rm executordb.PveRemote, job executordb.PveJob, read pveapi.TokenSupplier) error {
	interval := m.rebootPollInterval()
	for {
		done, err := m.observeNodeReboot(ctx, rm, job, read)
		if done || err != nil {
			return err
		}
		if timedOut, err := m.nodeRebootTimedOut(job); timedOut || err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ErrPveStepRunning
		case <-time.After(interval):
		}
	}
}

func (m *PveMutations) rebootMaxWait() time.Duration {
	if m.RebootMaxWait > 0 {
		return m.RebootMaxWait
	}
	return pveNodeRebootMaxWait
}

// nodeRebootTimedOut marks the step unknown once the wait bound passed.
func (m *PveMutations) nodeRebootTimedOut(job executordb.PveJob) (bool, error) {
	if !m.now().After(job.CreatedAt.Add(m.rebootMaxWait())) {
		return false, nil
	}
	if err := m.DB.FinishPveJob(job.ExecutionID, job.Step, executordb.PveJobUnknown, ""); err != nil {
		return true, ErrPveJobStore
	}
	m.log().Warn("audit", "kind", "pve_mutation_unknown", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step, "reason", "node did not return")
	return true, ErrPveDispatchUncertain
}

// observeNodeReboot reads the node once and records success when it is
// back online with a boot after the step's intent (and, for a cluster, the
// cluster is quorate with the node online). Unreadable state keeps
// waiting.
func (m *PveMutations) observeNodeReboot(ctx context.Context, rm executordb.PveRemote, job executordb.PveJob, read pveapi.TokenSupplier) (bool, error) {
	rc, ok := m.Client.(PveNodeRebootClient)
	if !ok {
		return false, nil
	}
	st, err := rc.NodeBoot(ctx, rm, job.Node, read)
	if err != nil || !st.Online || st.UptimeSeconds == 0 || st.UptimeSeconds > maxPveNodeUptime {
		return false, nil
	}
	bootAt := m.now().Add(-time.Duration(st.UptimeSeconds) * time.Second)
	if !bootAt.After(job.CreatedAt) {
		return false, nil
	}
	if st.Cluster.Available || rm.Kind == pvecontract.KindCluster {
		member := false
		for _, mb := range st.Cluster.Members {
			member = member || (mb.Name == job.Node && mb.Online)
		}
		if !st.Cluster.Available || !st.Cluster.Quorum || !member {
			return false, nil
		}
	}
	if job.UPID == "" {
		if err := m.DB.RecordPveJobUPID(job.ExecutionID, job.Step, pveNodeRebootRecord(job, bootAt), job.Node); err != nil {
			return true, ErrPveJobStore
		}
	}
	if err := m.DB.FinishPveJob(job.ExecutionID, job.Step, executordb.PveJobSucceeded, pveTaskOK); err != nil {
		return true, ErrPveJobStore
	}
	m.log().Info("audit", "kind", "pve_mutation_step", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step,
		"state", executordb.PveJobSucceeded, "boot", strconv.FormatInt(bootAt.Unix(), 10))
	return true, nil
}

// reconcileNodeReboot observes one open reboot step once: success when the
// node is back, unknown once the wait bound passed. Nothing is sent.
func (m *PveMutations) reconcileNodeReboot(ctx context.Context, rm executordb.PveRemote, job executordb.PveJob, read pveapi.TokenSupplier) error {
	if job.State == executordb.PveJobDispatching {
		if err := m.DB.MarkPveJobReconciling(job.ExecutionID, job.Step); err != nil {
			return ErrPveJobStore
		}
	}
	done, err := m.observeNodeReboot(ctx, rm, job, read)
	if done || err != nil {
		return err
	}
	_, err = m.nodeRebootTimedOut(job)
	return err
}

// openNodeReboot refuses while any reboot step of the remote is open, or
// unknown (its node did not return in time) while its node was not seen
// in f with a boot after the step's intent and pveRebootUnknownHold has
// not passed: the node may still be going down.
func (m *PveMutations) openNodeReboot(remoteID string, f PveNodeRebootFacts) error {
	open, err := m.DB.OpenPveJobs()
	if err != nil {
		return ErrPveJobStore
	}
	for _, j := range open {
		if j.RemoteID == remoteID && j.Action == PveNodeRebootAction {
			return ErrPveRebootBusy
		}
	}
	unknown, err := m.DB.UnknownPveJobs(PveNodeRebootAction)
	if err != nil {
		return ErrPveJobStore
	}
	now := m.now()
	for _, j := range unknown {
		if j.RemoteID != remoteID || !now.Before(j.CreatedAt.Add(pveRebootUnknownHold)) {
			continue
		}
		n, ok := uniqueNode(f.Nodes, j.Node)
		if !ok || n.Status != "online" || n.UptimeSeconds == 0 || n.UptimeSeconds > maxPveNodeUptime ||
			!now.Add(-time.Duration(n.UptimeSeconds)*time.Second).After(j.CreatedAt) {
			return ErrPveRebootBusy
		}
	}
	return nil
}
