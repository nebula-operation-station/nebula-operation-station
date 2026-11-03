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
)

// Typed "backup now" action (ADR 0006 "Phase 2 actions, permits and
// reconciliation", P2-01 backup profile): pve.guest.backup, base MEDIUM.
//
// The approval binds the exact guest, the target storage (which must be
// listed on the guest's node, active and accept backup content), the vzdump
// mode, the bandwidth limit and the fixed compression. The step never
// carries pruning or deletion flags: pveapi.Writer.BackupNow sends exactly
// one vmid with remove=0 and never all, exclude, prune-backups, mailto,
// script, dumpdir or stdout. The bound facts are read again before
// authorization and immediately before the step's intent is recorded; any
// drift sends nothing. Intent, UPID, lost-response identification and
// restart reconciliation are the PveMutations engine's.

// PveGuestBackupAction is the action ID of the guest backup action.
const PveGuestBackupAction = "pve.guest.backup"

// Guest backup modes (vzdump --mode).
const (
	PveBackupModeSnapshot = "snapshot"
	PveBackupModeSuspend  = "suspend"
	PveBackupModeStop     = "stop"
)

// Guest backup limits and fixed values.
const (
	// pveGuestBackupVersion is the module version of the backup artifact.
	pveGuestBackupVersion = "1.0.0"
	// maxPveBackupStepArgs bounds the arguments of one backup step.
	maxPveBackupStepArgs = 512
	// pveBackupCompress is the fixed vzdump compression of every backup.
	pveBackupCompress = "zstd"
	// pveBackupContent is the storage content type a backup target needs.
	pveBackupContent = "backup"
	// maxPveBackupConfigKeys bounds the members of a guest config read.
	maxPveBackupConfigKeys = 1024
)

var (
	// ErrPveBackupRequest is returned for an unknown kind or mode, a
	// malformed storage ID or a bandwidth out of range. Nothing is read or
	// sent.
	ErrPveBackupRequest = errors.New("executor: unsupported pve guest backup request")
	// ErrPveBackupStorage is returned when the target storage is not
	// listed on the guest's node, not active or does not accept backups.
	// Nothing is sent.
	ErrPveBackupStorage = errors.New("executor: the backup storage does not accept backups on the guest's node")
	// ErrPveBackupState is returned when the guest is locked or its
	// configuration or the storage list could not be read completely.
	// Nothing is sent.
	ErrPveBackupState = errors.New("executor: pve guest state does not allow a backup")
	// ErrPveBackupChanged is returned when the storage or guest state bound
	// in the approval changed. Nothing is sent.
	ErrPveBackupChanged = errors.New("executor: pve backup storage or guest state changed; the action needs a new approval")
	// ErrPveBackupUnavailable is returned when the engine's client has no
	// backup surface (PveBackupClient).
	ErrPveBackupUnavailable = errors.New("executor: pve guest backup is not available")
	// ErrPveGuestOpRisk is returned when the risk floor of a backup or
	// migration proposal cannot be evaluated. Nothing is proposed.
	ErrPveGuestOpRisk = errors.New("executor: pve guest backup/migration risk floor unavailable")
)

var pveBackupModes = map[string]bool{PveBackupModeSnapshot: true, PveBackupModeSuspend: true, PveBackupModeStop: true}

// pveBackupMethods is the backup step allowlist (method → guest kind).
var pveBackupMethods = map[string]string{
	"backup.qemu.vzdump": permit.ProviderKindQemu,
	"backup.lxc.vzdump":  permit.ProviderKindLXC,
}

// pveBackupArtifact is the fixed artifact of the backup action; its hash
// names the action in the canonical request.
func pveBackupArtifact() []byte {
	return []byte(PveGuestBackupAction + " " + pveGuestBackupVersion + "\n" +
		"Back up the exact guest once to the exact storage with the exact mode, bandwidth limit and zstd compression; never prunes or deletes backups.\n")
}

var pveBackupStagePlan = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"pve-guest-backup-v1"}`))
	return s
}()

// PveBackupFacts are the live facts a backup binds, read with the read
// token (untrusted; validated by the action).
type PveBackupFacts struct {
	// Config holds the string-valued members of the guest configuration
	// (only "lock" is used).
	Config map[string]string
	// Storages is the guest node's storage list; StoragesComplete is false
	// when it was truncated.
	Storages         []pveapi.Storage
	StoragesComplete bool
}

// PveBackupClient is the backup surface of a PveMutationClient. The engine
// routes the backup step methods only to a client implementing it.
type PveBackupClient interface {
	// BackupFacts reads the guest's config and the node's storages with
	// the read token.
	BackupFacts(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (PveBackupFacts, error)
	// DispatchBackup sends one backup step with the action token (see
	// DispatchGuestBackupStep). An error wrapping ErrPveRejected means
	// nothing was sent or the remote refused it.
	DispatchBackup(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action pveapi.TokenSupplier) (string, error)
}

// PveGuestBackupRequest names one backup of one exact guest.
type PveGuestBackupRequest struct {
	// Digest is the approved permit (Run only).
	Digest   canonical.Digest
	RemoteID string
	Kind     string
	Node     string
	VMID     uint64
	// Storage is the exact target storage ID.
	Storage string
	// Mode is the vzdump mode: snapshot, suspend or stop.
	Mode string
	// BandwidthKiB is the bandwidth limit in KiB/s; 0 means no limit.
	BandwidthKiB int
}

func (r PveGuestBackupRequest) validate() error {
	if r.Kind != permit.ProviderKindQemu && r.Kind != permit.ProviderKindLXC {
		return ErrPveBackupRequest
	}
	if !pveBackupModes[r.Mode] || !pveStorageIDRe.MatchString(r.Storage) ||
		r.BandwidthKiB < 0 || r.BandwidthKiB > pveapi.MaxBackupBandwidthKiB {
		return ErrPveBackupRequest
	}
	if err := permit.ValidateProviderMutationShape(r.Kind, r.Node, r.VMID); err != nil || !validVMID(r.VMID) {
		return ErrPveMutationRequest
	}
	return nil
}

// pveBackupStepArgs are the arguments of one backup step.
type pveBackupStepArgs struct {
	VMID         uint64 `json:"vmid"`
	Storage      string `json:"storage"`
	Mode         string `json:"mode"`
	BandwidthKiB int    `json:"bwlimit_kib"`
	Compress     string `json:"compress"`
}

// pveBackupParams are the action parameters bound in the approval.
type pveBackupParams struct {
	Kind         string `json:"kind"`
	Storage      string `json:"storage"`
	StorageType  string `json:"storage_type"`
	Mode         string `json:"mode"`
	BandwidthKiB int    `json:"bwlimit_kib"`
	Compress     string `json:"compress"`
	// Prune is always false: the action never prunes or deletes backups.
	Prune bool `json:"prune"`
	// StatusBefore is the guest's power status at proposal; suspend and
	// stop modes pause or stop a running guest. It must be unchanged at
	// the run.
	StatusBefore string            `json:"status_before"`
	Steps        []PveMutationStep `json:"steps"`
}

// pveBackupBound are the live facts a backup binds.
type pveBackupBound struct {
	storageType  string
	statusBefore string
}

func (r PveGuestBackupRequest) bind(live PveTargetState, f PveBackupFacts) (pveBackupBound, error) {
	if live.Kind != r.Kind {
		return pveBackupBound{}, ErrPveTargetChanged
	}
	if len(f.Config) == 0 || len(f.Config) > maxPveBackupConfigKeys || !f.StoragesComplete {
		return pveBackupBound{}, ErrPveBackupState
	}
	if _, locked := f.Config["lock"]; locked {
		// Another backup, a migration or a snapshot holds the guest.
		return pveBackupBound{}, ErrPveBackupState
	}
	if !validPveStatus(live.Status) {
		return pveBackupBound{}, ErrPveBackupState
	}
	st, ok := findStorage(f.Storages, r.Storage)
	if !ok || !st.Active || !slices.Contains(st.Content, pveBackupContent) || !pveStorageTypeRe.MatchString(st.Type) {
		return pveBackupBound{}, ErrPveBackupStorage
	}
	return pveBackupBound{storageType: st.Type, statusBefore: live.Status}, nil
}

var pveStorageTypeRe = pveVolFormatRe

func (r PveGuestBackupRequest) mutation(bc PveBackupClient, b pveBackupBound) (PveMutationRequest, error) {
	method := "backup." + r.Kind + ".vzdump"
	if pveBackupMethods[method] != r.Kind {
		return PveMutationRequest{}, ErrPveBackupRequest
	}
	args, err := json.Marshal(pveBackupStepArgs{VMID: r.VMID, Storage: r.Storage, Mode: r.Mode, BandwidthKiB: r.BandwidthKiB, Compress: pveBackupCompress})
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	params, err := json.Marshal(pveBackupParams{Kind: r.Kind, Storage: r.Storage, StorageType: b.storageType, Mode: r.Mode,
		BandwidthKiB: r.BandwidthKiB, Compress: pveBackupCompress, StatusBefore: b.statusBefore,
		Steps: []PveMutationStep{{Method: method, Args: args}}})
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	return PveMutationRequest{
		Digest: r.Digest, RemoteID: r.RemoteID, Kind: r.Kind, Node: r.Node, VMID: r.VMID,
		ActionID: PveGuestBackupAction, ModuleVersion: pveGuestBackupVersion, Artifact: pveBackupArtifact(),
		Parameters: params,
		precheck: func(live PveTargetState) error {
			if live.Kind != r.Kind {
				return ErrPveTargetChanged
			}
			if live.Status != b.statusBefore {
				return ErrPveBackupChanged
			}
			return nil
		},
		liveCheck: func(ctx context.Context, rm executordb.PveRemote, live PveTargetState, read pveapi.TokenSupplier) error {
			f, err := bc.BackupFacts(ctx, rm, r.Kind, r.Node, r.VMID, read)
			if err != nil {
				return ErrPveBackupState
			}
			again, err := r.bind(live, f)
			if err != nil {
				return err
			}
			if again != b {
				return ErrPveBackupChanged
			}
			return nil
		},
	}, nil
}

// PveGuestBackup proposes and runs guest backups on the executor's single
// PVE mutation engine.
type PveGuestBackup struct {
	Mutations *PveMutations
	// Bindings maps bound parameters hashes to the exact target for
	// GuestOpRiskFloor; it must be the instance the authority's policy
	// reads.
	Bindings *PveGuestPowerBindings
	// Floor, if set, is evaluated by Propose (with the binding held) and
	// raises the proposed risk to it; it can only raise the risk.
	Floor permit.RiskPolicy
}

func (g *PveGuestBackup) client() (PveBackupClient, error) {
	if g.Mutations == nil || g.Bindings == nil {
		return nil, errors.New("executor: pve guest backup: Mutations and Bindings are required")
	}
	if err := g.Mutations.checkDeps(); err != nil {
		return nil, err
	}
	bc, ok := g.Mutations.Client.(PveBackupClient)
	if !ok {
		return nil, ErrPveBackupUnavailable
	}
	return bc, nil
}

func (g *PveGuestBackup) prepare(ctx context.Context, bc PveBackupClient, req PveGuestBackupRequest) (PveMutationRequest, error) {
	m := g.Mutations
	rm, err := m.activeRemote(req.RemoteID)
	if err != nil {
		return PveMutationRequest{}, err
	}
	_, live, err := m.targetLive(ctx, rm, PveMutationRequest{RemoteID: req.RemoteID, Kind: req.Kind, Node: req.Node, VMID: req.VMID})
	if err != nil {
		return PveMutationRequest{}, err
	}
	read, err := m.readToken(rm)
	if err != nil {
		return PveMutationRequest{}, err
	}
	f, err := bc.BackupFacts(ctx, rm, req.Kind, req.Node, req.VMID, read)
	if err != nil {
		return PveMutationRequest{}, ErrPveBackupState
	}
	b, err := req.bind(live, f)
	if err != nil {
		return PveMutationRequest{}, err
	}
	return req.mutation(bc, b)
}

// Propose proposes req for the guest's current exact target, binding the
// storage, mode, bandwidth and the guest's power state. The risk is
// MEDIUM raised by the executor floor.
func (g *PveGuestBackup) Propose(ctx context.Context, req PveGuestBackupRequest, executionID string, expiry time.Time) (permit.Permit, error) {
	if err := req.validate(); err != nil {
		return permit.Permit{}, err
	}
	bc, err := g.client()
	if err != nil {
		return permit.Permit{}, err
	}
	mreq, err := g.prepare(ctx, bc, req)
	if err != nil {
		return permit.Permit{}, err
	}
	return proposeGuestOp(ctx, g.Mutations, g.Bindings, g.Floor, mreq, pveGuestOpBackup, canonical.RiskMedium, pveBackupStagePlan, executionID, expiry)
}

// Run runs the approved backup req.Digest. The exact target and the bound
// facts are read again before authorization and immediately before the
// step's intent; any drift sends nothing.
func (g *PveGuestBackup) Run(ctx context.Context, req PveGuestBackupRequest) (PveMutationResult, error) {
	if err := req.validate(); err != nil {
		return PveMutationResult{}, err
	}
	bc, err := g.client()
	if err != nil {
		return PveMutationResult{}, err
	}
	mreq, err := g.prepare(ctx, bc, req)
	if err != nil {
		return PveMutationResult{}, err
	}
	return runGuestOp(ctx, g.Mutations, g.Bindings, mreq, pveGuestOpBackup)
}

// proposeGuestOp proposes mreq at base raised by floor, with the exact
// target bound to the parameters hash as op for the risk floor while the
// permit lives.
func proposeGuestOp(ctx context.Context, m *PveMutations, bindings *PveGuestPowerBindings, floor permit.RiskPolicy, mreq PveMutationRequest, op string, base canonical.Risk, stagePlan, executionID string, expiry time.Time) (permit.Permit, error) {
	rq, params, err := m.ProposalRequest(ctx, mreq, executionID, base, stagePlan, expiry)
	if err != nil {
		return permit.Permit{}, err
	}
	t, err := boundTarget(params)
	if err != nil {
		return permit.Permit{}, err
	}
	release, err := bindings.hold(rq.ParametersHash, t, op)
	if err != nil {
		return permit.Permit{}, err
	}
	defer release()
	if floor != nil {
		f, _, err := floor.MinimumRisk(rq, rq.ResolvedTargets)
		if err != nil {
			return permit.Permit{}, fmt.Errorf("%w: %w", ErrPveGuestOpRisk, err)
		}
		if f.Rank() > rq.RiskClass.Rank() {
			rq.RiskClass = f
		}
	}
	res, err := m.Auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return permit.Permit{}, err
	}
	bindings.keep(rq.ParametersHash, time.Unix(res.Permit.Request.ExpiryUnix, 0))
	m.log().Info("audit", "kind", "pve_guest_op_proposed", "action", mreq.ActionID, "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID,
		"risk", string(res.Permit.Request.RiskClass), "execution", executionID)
	return res.Permit, nil
}

// runGuestOp runs the approved mreq with its exact target bound as op for
// the risk floor during authorization.
func runGuestOp(ctx context.Context, m *PveMutations, bindings *PveGuestPowerBindings, mreq PveMutationRequest, op string) (PveMutationResult, error) {
	rm, err := m.activeRemote(mreq.RemoteID)
	if err != nil {
		return PveMutationResult{}, err
	}
	t, live, err := m.targetLive(ctx, rm, mreq)
	if err != nil {
		return PveMutationResult{}, err
	}
	if err := mreq.precheck(live); err != nil {
		return PveMutationResult{}, err
	}
	binding, err := mutationOf(mreq, t).BindingJSON()
	if err != nil {
		return PveMutationResult{}, ErrPveTargetChanged
	}
	hash, err := canonical.HashParameters(binding)
	if err != nil {
		return PveMutationResult{}, ErrPveMutationPlan
	}
	release, err := bindings.hold(hash, t, op)
	if err != nil {
		return PveMutationResult{}, err
	}
	defer release()
	return m.Run(ctx, mreq)
}

// GuestBackupStepTaskType returns the PVE task type of a backup step
// method.
func GuestBackupStepTaskType(method string) (string, bool) {
	if _, ok := pveBackupMethods[method]; !ok {
		return "", false
	}
	return pveBackupTaskType, true
}

// GuestBackupStepTaskID returns the ID field (the VMID) of the vzdump task
// a backup step creates.
func GuestBackupStepTaskID(step PveMutationStep) (string, bool) {
	if _, ok := pveBackupMethods[step.Method]; !ok {
		return "", false
	}
	var a pveBackupStepArgs
	if decodeStepArgsMax(step.Args, &a, maxPveBackupStepArgs) != nil || !validVMID(a.VMID) {
		return "", false
	}
	return strconv.FormatUint(a.VMID, 10), true
}

// PveGuestBackupWriter is the part of pveapi.Writer the backup step uses
// (action token).
type PveGuestBackupWriter interface {
	BackupNow(ctx context.Context, r pveapi.BackupRequest) (string, error)
}

// DispatchGuestBackupStep decodes one backup step strictly and sends it
// with w.BackupNow: exactly one guest, the bound storage, mode, bandwidth
// and the fixed compression. The writer never sends pruning or deletion
// flags. Any refusal before sending, or by PVE, wraps ErrPveRejected.
func DispatchGuestBackupStep(ctx context.Context, w PveGuestBackupWriter, node string, step PveMutationStep) (string, error) {
	if _, ok := pveBackupMethods[step.Method]; !ok || w == nil {
		return "", fmt.Errorf("dispatch backup step: %w", ErrPveRejected)
	}
	var a pveBackupStepArgs
	if err := decodeStepArgsMax(step.Args, &a, maxPveBackupStepArgs); err != nil {
		return "", err
	}
	if !validVMID(a.VMID) || !pveStorageIDRe.MatchString(a.Storage) || !pveBackupModes[a.Mode] ||
		a.BandwidthKiB < 0 || a.BandwidthKiB > pveapi.MaxBackupBandwidthKiB || a.Compress != pveBackupCompress {
		return "", fmt.Errorf("dispatch %s: arguments: %w", step.Method, ErrPveRejected)
	}
	upid, err := w.BackupNow(ctx, pveapi.BackupRequest{Node: node, VMID: int64(a.VMID), Storage: a.Storage, Mode: a.Mode,
		BandwidthKiB: a.BandwidthKiB, Compress: a.Compress})
	return pveWriteResult(step.Method, upid, err)
}

var _ PveBackupClient = (*pveMutationClient)(nil)

// BackupFacts implements PveBackupClient with the read token over the
// remote's pinned transport.
func (c *pveMutationClient) BackupFacts(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (PveBackupFacts, error) {
	if err := permit.ValidateProviderMutationShape(kind, node, vmid); err != nil || kind == permit.ProviderKindNode || read == nil {
		return PveBackupFacts{}, ErrPveMutationRequest
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return PveBackupFacts{}, err
	}
	f, err := pveBackupFacts(ctx, hc, base, read, kind, node, vmid)
	if err = c.checkTrust(rm, watch, err); err != nil {
		return PveBackupFacts{}, err
	}
	return f, nil
}

func pveBackupFacts(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, kind, node string, vmid uint64) (PveBackupFacts, error) {
	cfg, err := pveGuestConfigStrings(ctx, hc, base, read, kind, node, vmid, func(string) bool { return false })
	if err != nil {
		return PveBackupFacts{}, err
	}
	pc, err := pveapi.NewClient(hc, base+"/api2/json", read)
	if err != nil {
		return PveBackupFacts{}, errPveMutationRead
	}
	sl, err := pc.ListStorages(ctx, node)
	if err != nil {
		return PveBackupFacts{}, errPveMutationRead
	}
	return PveBackupFacts{Config: cfg, Storages: sl.Storages, StoragesComplete: sl.Complete}, nil
}

// pveGuestConfigStrings reads a guest config and keeps its bounded string
// members. A "lock" that is not a string is kept as "?"; any other member
// for which relevant reports true and that is not a bounded string fails
// the read rather than being dropped.
func pveGuestConfigStrings(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, kind, node string, vmid uint64, relevant func(string) bool) (map[string]string, error) {
	var raw map[string]json.RawMessage
	if err := pveGetData(ctx, hc, base, read, "/nodes/"+node+"/"+kind+"/"+strconv.FormatUint(vmid, 10)+"/config", nil, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxPveBackupConfigKeys {
		return nil, errPveMutationRead
	}
	cfg := make(map[string]string, len(raw))
	for k, v := range raw {
		var s string
		if len(v) > 0 && v[0] == '"' && json.Unmarshal(v, &s) == nil && len(s) <= maxPveSnapshotConfigValue {
			cfg[k] = s
			continue
		}
		switch {
		case k == "lock":
			cfg[k] = "?"
		case relevant(k):
			return nil, errPveMutationRead
		}
	}
	return cfg, nil
}

// DispatchBackup implements PveBackupClient: DispatchGuestBackupStep with a
// writer that carries only action, over the remote's pinned transport.
func (c *pveMutationClient) DispatchBackup(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action pveapi.TokenSupplier) (string, error) {
	if _, ok := pveBackupMethods[step.Method]; !ok || action == nil || !permit.ValidPveNodeName(node) {
		return "", fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return "", fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, err)
	}
	w, err := pveapi.NewWriter(base, hc, action, pveMutationRequestTimeout)
	if err != nil {
		return "", fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
	}
	upid, err := DispatchGuestBackupStep(ctx, w, node, step)
	if watch.failed.Load() {
		c.blockRemote(rm)
		return "", fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, errPveReadTrust)
	}
	return upid, err
}

// Guest op names under which backup and migration targets are bound for
// GuestOpRiskFloor. A migration binds "migrate>" plus the exact target
// node, so the floor can score the destination node too.
const (
	pveGuestOpBackup        = "backup"
	pveGuestOpMigratePrefix = "migrate>"
)

// NewGuestOpRiskFloor returns the executor's production floor of the
// backup and migration actions: next for everything else and for artifact
// trust, the criticality records of crit, the executor registry's linked
// hosts and bindings.
func NewGuestOpRiskFloor(next permit.RiskPolicy, crit PveCriticality, bindings *PveGuestPowerBindings) GuestOpRiskFloor {
	return GuestOpRiskFloor{Next: next, Criticality: crit, Linked: PveRegistryLinkedHosts, Bindings: bindings}
}

// GuestOpRiskFloor is the executor floor of pve.guest.backup (base MEDIUM)
// and pve.guest.migrate (base HIGH) requests: the maximum of the base, the
// criticality of the guest, its node, the remote and (migration) the
// destination node, and of every host Linked returns for the guest or a
// node (no exact record: at least HIGH), and Next's floor. Anything it
// cannot establish is HIGH. Other requests get Next's floor (HIGH without
// Next).
type GuestOpRiskFloor struct {
	Next        permit.RiskPolicy
	Criticality PveCriticality
	Linked      PveLinkedHosts
	Bindings    *PveGuestPowerBindings
}

// MinimumRisk implements permit.RiskPolicy.
func (p GuestOpRiskFloor) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	if r.ActionID != PveGuestBackupAction && r.ActionID != PveGuestMigrateAction {
		if p.Next == nil {
			return canonical.RiskHigh, "no risk policy configured", nil
		}
		return p.Next.MinimumRisk(r, targets)
	}
	high := func(why string) (canonical.Risk, string, error) {
		return canonical.RiskHigh, r.ActionID + ": " + why + ": unknown criticality is HIGH", nil
	}
	if p.Next == nil || p.Criticality == nil || p.Linked == nil || p.Bindings == nil {
		return high("risk sources not configured")
	}
	t, op, ok := p.Bindings.lookup(r.ParametersHash)
	if !ok {
		return high("no exact target bound to the parameters")
	}
	var base canonical.Risk
	var dest string
	switch {
	case r.ActionID == PveGuestBackupAction && op == pveGuestOpBackup && r.ArtifactSHA256 == sha256Hex(pveBackupArtifact()):
		base = canonical.RiskMedium
	case r.ActionID == PveGuestMigrateAction && strings.HasPrefix(op, pveGuestOpMigratePrefix) && r.ArtifactSHA256 == sha256Hex(pveMigrateArtifact()):
		base, dest = canonical.RiskHigh, strings.TrimPrefix(op, pveGuestOpMigratePrefix)
		if !permit.ValidPveNodeName(dest) || dest == t.Node {
			return high("destination node not bound")
		}
	default:
		return high("artifact does not match the action")
	}
	guest, node, remote, err := PveGuestRiskTargets(t)
	if err != nil || len(targets) != 1 || targets[0] != guest {
		return high("targets do not match the bound guest")
	}
	risk, reasons := base, []string{fmt.Sprintf("%s is %s (ADR 0006)", r.ActionID, base)}
	ext := []canonical.Target{guest, node, remote}
	nodes := []canonical.Target{guest, node}
	if dest != "" {
		_, dn, _, err := PveGuestRiskTargets(permit.ProviderMutationTarget{RemoteID: t.RemoteID, TrustPin: t.TrustPin, Kind: t.Kind, Node: dest, VMID: t.VMID})
		if err != nil {
			return high("destination node target")
		}
		ext = append(ext, dn)
		nodes = append(nodes, dn)
	}
	for _, at := range nodes {
		hosts, err := p.Linked(r, at)
		if err != nil {
			return "", "", fmt.Errorf("guest op risk floor: linked hosts: %w", err)
		}
		ext = append(ext, hosts...)
	}
	for _, at := range ext {
		c, exact, err := p.Criticality.HostCriticality(at.HostID, at.HostKeyFingerprint)
		if err != nil {
			return "", "", fmt.Errorf("guest op risk floor: criticality: %w", err)
		}
		if !exact && c.Rank() < canonical.RiskHigh.Rank() {
			c = canonical.RiskHigh
		}
		if c.Rank() > risk.Rank() {
			risk = c
			reasons = append(reasons, fmt.Sprintf("target %s criticality %s (exact record: %t)", at.HostID, c, exact))
		}
	}
	nr, why, err := p.Next.MinimumRisk(r, ext)
	if err != nil {
		return "", "", fmt.Errorf("guest op risk floor: %w", err)
	}
	if nr.Rank() > risk.Rank() {
		risk = nr
		if why != "" {
			reasons = append(reasons, why)
		}
	}
	return risk, strings.Join(reasons, "; "), nil
}
