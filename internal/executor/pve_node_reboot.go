// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
// action refuses:
//
//   - a read-only remote (no action credential; offsite remotes such as
//     ProxmoxOFS1 are registered that way) with ErrPveReadOnly, before
//     anything is read;
//   - a node that is not listed online exactly once;
//   - in a cluster: a cluster without quorum; any other member offline or
//     booted less than pveRebootSettle ago (it is rebooting or settling);
//     an open pve.node.reboot step or a running reboot on the same remote
//     (at most one node at a time); remaining corosync votes that are not a
//     strict majority of all configured votes; a configured or unknown
//     QDevice (its votes are not modelled); unknown HA state;
//   - a cluster remote whose cluster status cannot be read, or a standalone
//     remote that does not list exactly one node;
//   - any running guest on the node that HA does not evacuate and that the
//     request does not list as accepted downtime, and an accepted entry that
//     names no running guest of the node. HA evacuates a guest only when it
//     is HA-managed with requested state "started" and either the
//     cluster-wide HA shutdown_policy is "migrate" or the node's LRM is in
//     maintenance mode; under the PVE default (conditional) a reboot freezes
//     HA guests in place, so they count as downtime.
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
// unknown. A lost response is never sent again: it is observed the same
// way, and Reconcile does so after a restart.

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
	// maxPveRebootAccepted bounds the accepted-downtime list.
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
)

func pveNodeRebootArtifact() []byte {
	return []byte(PveNodeRebootAction + " " + pveNodeRebootVersion + "\n" +
		"Reboot the exact node; in a cluster only while the remaining nodes keep quorum, no other node is offline or rebooting, and every running guest is HA-evacuated or accepted downtime.\n")
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
	// the approval accepts. Every running guest HA does not evacuate must
	// be listed; an entry for a guest that is not running on the node is
	// refused.
	AcceptedDowntime []PveRebootGuestRef
}

func (r PveNodeRebootRequest) validate() error {
	if !permit.ValidPveNodeName(r.Node) || len(r.AcceptedDowntime) > maxPveRebootAccepted {
		return ErrPveRebootRequest
	}
	seen := map[PveRebootGuestRef]bool{}
	for _, g := range r.AcceptedDowntime {
		if (g.Kind != permit.ProviderKindQemu && g.Kind != permit.ProviderKindLXC) || !validVMID(g.VMID) || seen[g] {
			return ErrPveRebootRequest
		}
		seen[g] = true
	}
	return nil
}

// accepted returns the accepted-downtime list sorted by kind and VMID.
func (r PveNodeRebootRequest) accepted() []PveRebootGuestRef {
	out := slices.Clone(r.AcceptedDowntime)
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

// pveRebootParams are the action parameters bound in the approval.
type pveRebootParams struct {
	Node             string              `json:"node"`
	Risk             canonical.Risk      `json:"risk"`
	AcceptedDowntime []PveRebootGuestRef `json:"accepted_downtime"`
	Bound            pveRebootBound      `json:"bound"`
	Steps            []PveMutationStep   `json:"steps"`
}

// pveRebootStepArgs are the arguments of the reboot step: what the
// dispatcher needs to bind the facts again and compare them.
type pveRebootStepArgs struct {
	Node        string              `json:"node"`
	Clustered   bool                `json:"clustered"`
	Accepted    []PveRebootGuestRef `json:"accepted_downtime"`
	BoundSHA256 string              `json:"bound_sha256"`
}

// bindNodeReboot derives the bound facts of a reboot of node with the
// accepted list from live facts, refusing whatever the reboot does not
// allow. remoteKind is the registered kind of the remote.
func bindNodeReboot(node string, accepted []PveRebootGuestRef, remoteKind pvecontract.Kind, f PveNodeRebootFacts) (pveRebootBound, error) {
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
	} else if err := bindRebootCluster(node, f, &b); err != nil {
		return pveRebootBound{}, err
	}
	guests, err := bindRebootGuests(node, accepted, f, b)
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

// bindRebootGuests binds every guest on the node and requires each running
// guest to be HA-evacuated or accepted downtime.
func bindRebootGuests(node string, accepted []PveRebootGuestRef, f PveNodeRebootFacts, b pveRebootBound) ([]PveRebootGuest, error) {
	if len(f.Guests) > maxPveRebootGuests {
		return nil, ErrPveRebootState
	}
	evacuation := b.Clustered && (b.HAShutdownPolicy == pveHAPolicyMigrate || b.Maintenance)
	haStarted := map[uint64]bool{}
	if b.Clustered && f.HA.Available {
		for _, res := range f.HA.Resources {
			if res.VMID > 0 && res.Managed && res.DesiredState == "started" {
				haStarted[uint64(res.VMID)] = true
			}
		}
	}
	want := map[PveRebootGuestRef]bool{}
	for _, a := range accepted {
		want[a] = true
	}
	used := map[PveRebootGuestRef]bool{}
	seen := map[uint64]bool{}
	out := make([]PveRebootGuest, 0, len(f.Guests))
	for _, g := range f.Guests {
		kind := string(g.Kind)
		if g.Node != node || (kind != permit.ProviderKindQemu && kind != permit.ProviderKindLXC) || g.VMID <= 0 ||
			!validVMID(uint64(g.VMID)) || seen[uint64(g.VMID)] || !validPveStatus(g.Status) {
			return nil, ErrPveRebootState
		}
		vmid := uint64(g.VMID)
		seen[vmid] = true
		ref := PveRebootGuestRef{Kind: kind, VMID: vmid}
		bg := PveRebootGuest{Kind: kind, VMID: vmid, Status: g.Status}
		if g.Status != "stopped" {
			bg.HAEvacuates = evacuation && haStarted[vmid]
			bg.AcceptedDowntime = want[ref]
			if !bg.HAEvacuates && !bg.AcceptedDowntime {
				return nil, ErrPveRebootGuests
			}
			if bg.AcceptedDowntime {
				used[ref] = true
			}
		}
		out = append(out, bg)
	}
	for _, a := range accepted {
		if !used[a] {
			// The approval would accept downtime of a guest that is not
			// running on the node: it would not describe the reboot.
			return nil, ErrPveRebootGuests
		}
	}
	slices.SortFunc(out, func(x, y PveRebootGuest) int {
		return cmpGuestRef(PveRebootGuestRef{Kind: x.Kind, VMID: x.VMID}, PveRebootGuestRef{Kind: y.Kind, VMID: y.VMID})
	})
	return out, nil
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

func (g *PveNodeReboot) prepare(ctx context.Context, rc PveNodeRebootClient, req PveNodeRebootRequest) (PveMutationRequest, error) {
	m := g.Mutations
	rm, err := m.activeRemote(req.RemoteID)
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
	accepted := req.accepted()
	b, err := bindNodeReboot(req.Node, accepted, rm.Kind, f)
	if err != nil {
		return PveMutationRequest{}, err
	}
	if err := m.openNodeReboot(rm.RemoteID); err != nil {
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
	rawArgs, err := json.Marshal(pveRebootStepArgs{Node: req.Node, Clustered: b.Clustered, Accepted: accepted, BoundSHA256: hash})
	if err != nil || len(rawArgs) > maxPveRebootStepArgs {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	params, err := json.Marshal(pveRebootParams{Node: req.Node, Risk: risk, AcceptedDowntime: accepted, Bound: b,
		Steps: []PveMutationStep{{Method: pveNodeRebootMethod, Args: rawArgs}}})
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	base.Digest, base.ActionID, base.ModuleVersion, base.Artifact, base.Parameters = req.Digest, PveNodeRebootAction, pveNodeRebootVersion, pveNodeRebootArtifact(), params
	base.liveCheck = func(ctx context.Context, rm executordb.PveRemote, live PveTargetState, read pveapi.TokenSupplier) error {
		if live.Node != req.Node {
			return ErrPveTargetChanged
		}
		f, err := rc.NodeRebootFacts(ctx, rm, req.Node, read)
		if err != nil {
			return ErrPveRebootState
		}
		again, err := bindNodeReboot(req.Node, accepted, rm.Kind, f)
		if err != nil {
			return err
		}
		if h, err := pveRebootBoundHash(again); err != nil || h != hash {
			return ErrPveRebootChanged
		}
		// One node at a time, also across restarts: no reboot step of the
		// remote may still be open.
		return m.openNodeReboot(rm.RemoteID)
	}
	return base, nil
}

// Propose proposes req for the exact node, binding the cluster membership
// snapshot and every guest on the node. The risk is HIGH for a standalone
// node and CRITICAL in a cluster, raised by Criticality and Floor.
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
	mreq, err := g.prepare(ctx, rc, req)
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
		"guests", len(doc.Bound.Guests), "risk", string(res.Permit.Request.RiskClass), "execution", executionID)
	return res.Permit, nil
}

// Run runs the approved reboot req.Digest. At most one reboot per remote
// runs at a time. Every bound fact is read again before authorization,
// immediately before the step's intent and by the dispatcher before the
// reboot is sent; the risk is derived again and is part of the bound
// parameters. Run then waits (bounded) for the node to return.
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
	mreq, err := g.prepare(ctx, rc, req)
	if err != nil {
		return PveMutationResult{}, err
	}
	return g.Mutations.Run(ctx, mreq)
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
	req := PveNodeRebootRequest{Node: a.Node, AcceptedDowntime: a.Accepted}
	if a.Node != node || req.validate() != nil || !slices.IsSortedFunc(a.Accepted, cmpGuestRef) {
		return reject("arguments")
	}
	f, err := rd.NodeRebootFacts(ctx, node)
	if err != nil {
		return reject("facts")
	}
	b, err := bindNodeReboot(node, a.Accepted, remoteKind, f)
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

func pveNodeRebootFacts(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, node string) (PveNodeRebootFacts, error) {
	pc, err := pveapi.NewClient(hc, base+"/api2/json", read)
	if err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	var f PveNodeRebootFacts
	if f.Nodes, err = pc.ListNodes(ctx); err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	cr := pveClusterReader(hc, base, read)
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
	qemu, err := pc.ListQemu(ctx, node)
	if err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	lxc, err := pc.ListLxc(ctx, node)
	if err != nil {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	if len(qemu)+len(lxc) > maxPveRebootGuests {
		return PveNodeRebootFacts{}, errPveMutationRead
	}
	f.Guests = append(qemu, lxc...)
	return f, nil
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
	pc, err := pveapi.NewClient(hc, base+"/api2/json", read)
	if err != nil {
		return PveNodeBoot{}, errPveMutationRead
	}
	nodes, err := pc.ListNodes(ctx)
	if err != nil {
		return PveNodeBoot{}, errPveMutationRead
	}
	cs, err := pveClusterReader(hc, base, read).ClusterStatus(ctx)
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
	interval := m.RebootPollInterval
	if interval <= 0 {
		interval = pveNodeRebootPollInterval
	}
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

// openNodeReboot refuses while any reboot step of the remote is open.
func (m *PveMutations) openNodeReboot(remoteID string) error {
	open, err := m.DB.OpenPveJobs()
	if err != nil {
		return ErrPveJobStore
	}
	for _, j := range open {
		if j.RemoteID == remoteID && j.Action == PveNodeRebootAction {
			return ErrPveRebootBusy
		}
	}
	return nil
}
