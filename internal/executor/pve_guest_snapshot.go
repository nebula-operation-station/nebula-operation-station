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
)

// Typed guest snapshot actions (ADR 0006 "Phase 2 actions, permits and
// reconciliation", P2-01 snapshot profile): one action, pve.guest.snapshot,
// with an op.
//
//   - create (MEDIUM) binds the exact name, the RAM (vmstate) choice and the
//     guest's current disk set; every disk must be on storage whose snapshot
//     capability is verified "yes" (unknown refuses), read before proposing.
//   - delete (HIGH) binds the exact snapshot: name plus generation
//     (snaptime, parent) and RAM flag from the snapshot list read at
//     proposal. There is no age-based, pattern or bulk deletion: one
//     request names one snapshot.
//   - rollback (HIGH) binds the exact snapshot like delete, the explicit
//     start flag, the RAM side effect (a RAM snapshot resumes the guest
//     regardless of start) and the guest's power state before the rollback
//     (a running guest is stopped and loses its state since the snapshot).
//
// The bound facts are read again before authorization, immediately before
// the step's intent is recorded and, by the dispatcher, with the read token
// immediately before the request is sent; any drift sends nothing. Each
// run is one step on the PveMutations engine (intent, UPID, lost-response
// identification and restart reconciliation are the engine's).

// PveGuestSnapshotAction is the action ID of the guest snapshot actions.
const PveGuestSnapshotAction = "pve.guest.snapshot"

// Guest snapshot ops.
const (
	PveSnapshotCreate   = "create"
	PveSnapshotDelete   = "delete"
	PveSnapshotRollback = "rollback"
)

// Guest snapshot limits and fixed values.
const (
	// pveGuestSnapshotVersion is the module version of the snapshot
	// artifacts.
	pveGuestSnapshotVersion = "1.0.0"
	// maxPveSnapshotStepArgs bounds the arguments of one snapshot step.
	maxPveSnapshotStepArgs = 512
	// maxPveSnapshotDisks bounds the disk set of one guest.
	maxPveSnapshotDisks = 64
	// maxPveSnapshotConfigValue bounds one guest config value the disk set
	// is parsed from.
	maxPveSnapshotConfigValue = 4096
	// maxPveSnapshotConfigKeys bounds the members of a guest config read.
	maxPveSnapshotConfigKeys = 1024
)

var (
	// ErrPveSnapshotRequest is returned for an unknown op, a malformed name,
	// a flag the op or guest kind does not take (RAM on LXC, start on
	// create) or a run without the bound snapshot identity. Nothing is
	// read or sent.
	ErrPveSnapshotRequest = errors.New("executor: unsupported pve guest snapshot request")
	// ErrPveSnapshotChanged is returned when the exact snapshot (name,
	// snaptime, parent, RAM flag) is missing or differs from the bound one,
	// when the name to create already exists, or when the disk set or power
	// state bound in the approval changed. Nothing is sent.
	ErrPveSnapshotChanged = errors.New("executor: pve guest snapshot or disk set changed; the action needs a new approval")
	// ErrPveSnapshotStorage is returned when a disk of the guest is not on
	// storage with a verified snapshot capability (unsupported, unknown,
	// inactive, unlisted or a passthrough/bind volume). Nothing is sent.
	ErrPveSnapshotStorage = errors.New("executor: a guest disk is not on snapshot-capable storage")
	// ErrPveSnapshotState is returned when the guest is locked, its
	// snapshot or storage list could not be read completely, or a RAM
	// snapshot is asked of a guest that is not running. Nothing is sent.
	ErrPveSnapshotState = errors.New("executor: pve guest state does not allow the snapshot action")
	// ErrPveSnapshotUnavailable is returned when the engine's client has no
	// snapshot surface (PveSnapshotClient).
	ErrPveSnapshotUnavailable = errors.New("executor: pve guest snapshot actions are not available")
	// ErrPveSnapshotRisk is returned when the risk floor of a snapshot
	// proposal cannot be evaluated. Nothing is proposed.
	ErrPveSnapshotRisk = errors.New("executor: pve guest snapshot risk floor unavailable")
)

// pveSnapshotOps maps each op to its base risk (ADR 0006 risk table).
var pveSnapshotOps = map[string]canonical.Risk{
	PveSnapshotCreate:   canonical.RiskMedium,
	PveSnapshotDelete:   canonical.RiskHigh,
	PveSnapshotRollback: canonical.RiskHigh,
}

var pveSnapshotText = map[string]string{
	PveSnapshotCreate:   "Create one snapshot with the exact name and RAM choice of the exact guest; every disk on verified snapshot-capable storage.",
	PveSnapshotDelete:   "Delete the one exact snapshot (name, time and parent) of the exact guest; never by age, pattern or in bulk; no force.",
	PveSnapshotRollback: "Roll the exact guest back to the one exact snapshot (destructive: state since the snapshot is lost); explicit start flag and RAM side effect.",
}

// pveSnapshotArtifact is the fixed artifact of op; its hash names the op in
// the canonical request. nil for an unknown op.
func pveSnapshotArtifact(op string) []byte {
	text, ok := pveSnapshotText[op]
	if !ok {
		return nil
	}
	return []byte(PveGuestSnapshotAction + " " + pveGuestSnapshotVersion + "\nop: " + op + "\n" + text + "\n")
}

var pveSnapshotStagePlan = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"pve-guest-snapshot-v1"}`))
	return s
}()

type pveSnapshotMethod struct {
	kind, op, taskType string
}

// pveSnapshotMethods is the snapshot step allowlist with the PVE task type
// each creates.
var pveSnapshotMethods = map[string]pveSnapshotMethod{
	"snapshot.qemu.create":   {permit.ProviderKindQemu, PveSnapshotCreate, "qmsnapshot"},
	"snapshot.qemu.delete":   {permit.ProviderKindQemu, PveSnapshotDelete, "qmdelsnapshot"},
	"snapshot.qemu.rollback": {permit.ProviderKindQemu, PveSnapshotRollback, "qmrollback"},
	"snapshot.lxc.create":    {permit.ProviderKindLXC, PveSnapshotCreate, "vzsnapshot"},
	"snapshot.lxc.delete":    {permit.ProviderKindLXC, PveSnapshotDelete, "vzdelsnapshot"},
	"snapshot.lxc.rollback":  {permit.ProviderKindLXC, PveSnapshotRollback, "vzrollback"},
}

// pveSnapshotNameRe is PVE's snapshot name rule as the pveapi writer
// enforces it: a letter, then letters, digits, '_' or '-', at most 40.
var pveSnapshotNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,39}$`)

func validSnapshotWriteName(name string) bool {
	return name != "current" && len(name) <= pveapi.MaxSnapshotNameLen && pveSnapshotNameRe.MatchString(name)
}

// PveSnapshotIdentity is the exact identity of one existing snapshot: its
// name, generation (snaptime and parent) and RAM flag, as read from the
// guest's snapshot list.
type PveSnapshotIdentity struct {
	Name         string `json:"name"`
	SnapTimeUnix int64  `json:"snaptime"`
	Parent       string `json:"parent"`
	VMState      bool   `json:"vmstate"`
}

// PveSnapshotDisk is one volume of a guest's disk set bound by a create.
type PveSnapshotDisk struct {
	Key         string `json:"key"`
	Volume      string `json:"volume"`
	Storage     string `json:"storage"`
	StorageType string `json:"storage_type"`
	Format      string `json:"format"`
}

// pveSnapshotStepArgs are the arguments of one snapshot step. For delete
// and rollback they carry the exact bound snapshot (SnapTime, Parent,
// VMState), which the dispatcher compares with a fresh read right before
// sending; for create VMState is the RAM choice and SnapTime/Parent are
// zero. Start is the rollback start flag.
type pveSnapshotStepArgs struct {
	VMID     uint64 `json:"vmid"`
	Name     string `json:"name"`
	VMState  bool   `json:"vmstate"`
	SnapTime int64  `json:"snaptime"`
	Parent   string `json:"parent"`
	Start    bool   `json:"start"`
}

// pveSnapshotRollbackEffects are the side effects of a rollback bound in
// the approval.
type pveSnapshotRollbackEffects struct {
	// Start is the explicit start flag sent with the rollback.
	Start bool `json:"start"`
	// RestoresRAM: the snapshot includes RAM; PVE resumes the guest from it
	// whatever Start says.
	RestoresRAM bool `json:"restores_ram"`
	// GuestRunsAfter: the guest runs after a successful rollback.
	GuestRunsAfter bool `json:"guest_runs_after"`
	// StatusBefore is the guest's power status at proposal; a running
	// guest is stopped by the rollback. It must be unchanged at the run.
	StatusBefore string `json:"status_before"`
}

// pveSnapshotParams are the action parameters bound in the approval.
type pveSnapshotParams struct {
	Op   string `json:"op"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	// VMState is the RAM choice of a create.
	VMState bool `json:"vmstate"`
	// Disks is the disk set of a create.
	Disks []PveSnapshotDisk `json:"disks,omitempty"`
	// Snapshot is the exact snapshot of a delete or rollback.
	Snapshot *PveSnapshotIdentity `json:"snapshot,omitempty"`
	// Rollback holds a rollback's side effects.
	Rollback *pveSnapshotRollbackEffects `json:"rollback,omitempty"`
	Steps    []PveMutationStep           `json:"steps"`
}

// PveSnapshotFacts are the live facts a snapshot action binds, read with
// the read token (untrusted; validated by the action).
type PveSnapshotFacts struct {
	// Config holds the string-valued members of the guest's current
	// configuration (disk entries, lock, vmstatestorage, ...).
	Config map[string]string
	// Storages is the node's storage list; StoragesComplete is false when
	// it was truncated.
	Storages         []pveapi.Storage
	StoragesComplete bool
	// Snapshots is the guest's snapshot list; SnapshotsComplete is false
	// when it was truncated.
	Snapshots         []pveapi.Snapshot
	SnapshotsComplete bool
}

// PveSnapshotClient is the snapshot surface of a PveMutationClient. The
// engine routes the snapshot step methods only to a client implementing
// it; others refuse them.
type PveSnapshotClient interface {
	// SnapshotFacts reads the guest's config, the node's storages and the
	// guest's snapshot list with the read token.
	SnapshotFacts(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (PveSnapshotFacts, error)
	// DispatchSnapshot sends one snapshot step with the action token after
	// rechecking the bound snapshot with the read token (see
	// DispatchGuestSnapshotStep). An error wrapping ErrPveRejected means
	// nothing was sent or the remote refused it.
	DispatchSnapshot(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action, read pveapi.TokenSupplier) (string, error)
}

// PveGuestSnapshotRequest names one snapshot action on one exact guest.
type PveGuestSnapshotRequest struct {
	// Digest is the approved permit (Run only).
	Digest   canonical.Digest
	RemoteID string
	Kind     string
	Node     string
	VMID     uint64
	Op       string
	// Name is the snapshot to create, delete or roll back to.
	Name string
	// VMState asks a create for a RAM snapshot (QEMU, running guest only).
	VMState bool
	// Start is the rollback start flag (rollback only).
	Start bool
	// Expect is the exact snapshot of a delete or rollback as shown in the
	// approval. Run requires it; Propose checks it when set. It must be
	// nil for create.
	Expect *PveSnapshotIdentity
}

// validate checks r's shape without I/O.
func (r PveGuestSnapshotRequest) validate(run bool) error {
	if _, ok := pveSnapshotOps[r.Op]; !ok || (r.Kind != permit.ProviderKindQemu && r.Kind != permit.ProviderKindLXC) {
		return ErrPveSnapshotRequest
	}
	if !validSnapshotWriteName(r.Name) {
		return ErrPveSnapshotRequest
	}
	switch r.Op {
	case PveSnapshotCreate:
		if r.Start || r.Expect != nil || (r.VMState && r.Kind != permit.ProviderKindQemu) {
			return ErrPveSnapshotRequest
		}
	case PveSnapshotDelete:
		if r.Start || r.VMState {
			return ErrPveSnapshotRequest
		}
	case PveSnapshotRollback:
		if r.VMState {
			return ErrPveSnapshotRequest
		}
	}
	if r.Op != PveSnapshotCreate {
		if run && r.Expect == nil {
			return ErrPveSnapshotRequest
		}
		if r.Expect != nil && (r.Expect.Name != r.Name || r.Expect.SnapTimeUnix < 0 ||
			len(r.Expect.Parent) > pveapi.MaxSnapshotNameBytes ||
			(r.Expect.VMState && r.Kind != permit.ProviderKindQemu)) {
			return ErrPveSnapshotRequest
		}
	}
	if err := permit.ValidateProviderMutationShape(r.Kind, r.Node, r.VMID); err != nil || !validVMID(r.VMID) {
		return ErrPveMutationRequest
	}
	return nil
}

// pveSnapshotBound are the live facts a request binds.
type pveSnapshotBound struct {
	disks    []PveSnapshotDisk
	snapshot *PveSnapshotIdentity
	rollback *pveSnapshotRollbackEffects
}

// bind derives the bound facts of r from live state and facts, refusing
// whatever the op does not allow.
func (r PveGuestSnapshotRequest) bind(live PveTargetState, f PveSnapshotFacts) (pveSnapshotBound, error) {
	if live.Kind != r.Kind {
		return pveSnapshotBound{}, ErrPveTargetChanged
	}
	if len(f.Config) > maxPveSnapshotConfigKeys || !f.SnapshotsComplete {
		return pveSnapshotBound{}, ErrPveSnapshotState
	}
	if _, locked := f.Config["lock"]; locked {
		// A backup, migration or another snapshot holds the guest.
		return pveSnapshotBound{}, ErrPveSnapshotState
	}
	var found *PveSnapshotIdentity
	for _, s := range f.Snapshots {
		if s.Name == r.Name {
			if found != nil {
				return pveSnapshotBound{}, ErrPveSnapshotState
			}
			found = &PveSnapshotIdentity{Name: s.Name, SnapTimeUnix: s.SnapTimeUnix, Parent: s.Parent, VMState: s.HasVMState}
		}
	}
	if r.Op == PveSnapshotCreate {
		if found != nil {
			return pveSnapshotBound{}, ErrPveSnapshotChanged
		}
		if r.VMState && (live.Status != pveGuestRunning || live.QMPStatus != pveGuestRunning) {
			return pveSnapshotBound{}, ErrPveSnapshotState
		}
		disks, err := snapshotDiskSet(r.Kind, f)
		if err != nil {
			return pveSnapshotBound{}, err
		}
		if r.VMState {
			if err := snapshotStateStorage(f); err != nil {
				return pveSnapshotBound{}, err
			}
		}
		return pveSnapshotBound{disks: disks}, nil
	}
	if found == nil || (r.Expect != nil && *found != *r.Expect) {
		return pveSnapshotBound{}, ErrPveSnapshotChanged
	}
	if found.VMState && r.Kind != permit.ProviderKindQemu {
		return pveSnapshotBound{}, ErrPveSnapshotState
	}
	b := pveSnapshotBound{snapshot: found}
	if r.Op == PveSnapshotRollback {
		if !validPveStatus(live.Status) {
			return pveSnapshotBound{}, ErrPveSnapshotState
		}
		b.rollback = &pveSnapshotRollbackEffects{Start: r.Start, RestoresRAM: found.VMState,
			GuestRunsAfter: r.Start || found.VMState, StatusBefore: live.Status}
	}
	return b, nil
}

var (
	pveQemuDiskKeyRe = regexp.MustCompile(`^(?:(?:ide|sata|scsi|virtio)[0-9]{1,2}|efidisk0|tpmstate0)$`)
	pveLXCDiskKeyRe  = regexp.MustCompile(`^(?:rootfs|mp[0-9]{1,3})$`)
	pveVolNameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+/-]{0,254}$`)
	pveVolFormatRe   = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// snapshotDiskSet parses the guest's disk set from its config and checks
// every disk's storage: listed (complete list), active and with a verified
// snapshot capability. CD-ROM drives are not part of the set; passthrough
// devices and bind mounts are refused. The set is sorted by key.
func snapshotDiskSet(kind string, f PveSnapshotFacts) ([]PveSnapshotDisk, error) {
	if !f.StoragesComplete {
		return nil, ErrPveSnapshotState
	}
	keyRe := pveQemuDiskKeyRe
	if kind == permit.ProviderKindLXC {
		keyRe = pveLXCDiskKeyRe
	}
	var disks []PveSnapshotDisk
	for key, val := range f.Config {
		if !keyRe.MatchString(key) {
			continue
		}
		d, skip, err := parseSnapshotDisk(kind, key, val)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		if len(disks) >= maxPveSnapshotDisks {
			return nil, ErrPveSnapshotState
		}
		st, ok := findStorage(f.Storages, d.Storage)
		if !ok || !st.Active {
			return nil, ErrPveSnapshotStorage
		}
		format := d.Format
		if format == "" {
			format = st.Format
		}
		if pveapi.SnapshotCapability(st.Type, format) != pveapi.TriYes {
			// Unknown capability blocks the action like "no" does.
			return nil, ErrPveSnapshotStorage
		}
		d.StorageType, d.Format = st.Type, format
		disks = append(disks, d)
	}
	slices.SortFunc(disks, func(a, b PveSnapshotDisk) int { return strings.Compare(a.Key, b.Key) })
	return disks, nil
}

// snapshotStateStorage checks the explicit RAM state storage of a QEMU
// guest, if configured: listed and active.
func snapshotStateStorage(f PveSnapshotFacts) error {
	id, ok := f.Config["vmstatestorage"]
	if !ok {
		return nil
	}
	st, ok := findStorage(f.Storages, id)
	if !ok || !st.Active {
		return ErrPveSnapshotStorage
	}
	return nil
}

func findStorage(list []pveapi.Storage, id string) (pveapi.Storage, bool) {
	var out pveapi.Storage
	n := 0
	for _, s := range list {
		if s.ID == id {
			out = s
			n++
		}
	}
	return out, n == 1
}

// parseSnapshotDisk parses one disk config value. skip is set for a CD-ROM.
func parseSnapshotDisk(kind, key, val string) (PveSnapshotDisk, bool, error) {
	if val == "" || len(val) > maxPveSnapshotConfigValue {
		return PveSnapshotDisk{}, false, ErrPveSnapshotState
	}
	parts := strings.Split(val, ",")
	volume, format, media := "", "", ""
	for i, p := range parts {
		k, v, hasEq := strings.Cut(p, "=")
		switch {
		case !hasEq && i == 0:
			volume = p
		case !hasEq:
			return PveSnapshotDisk{}, false, ErrPveSnapshotState
		case k == "file" || k == "volume":
			if volume != "" {
				return PveSnapshotDisk{}, false, ErrPveSnapshotState
			}
			volume = v
		case k == "format":
			format = v
		case k == "media":
			media = v
		}
	}
	if kind == permit.ProviderKindQemu && media == "cdrom" {
		return PveSnapshotDisk{}, true, nil
	}
	if volume == "" || volume == "none" || strings.HasPrefix(volume, "/") {
		// Passthrough device or bind mount: no verified snapshot capability.
		return PveSnapshotDisk{}, false, ErrPveSnapshotStorage
	}
	storage, volname, ok := strings.Cut(volume, ":")
	if !ok || !pveStorageIDRe.MatchString(storage) || !pveVolNameRe.MatchString(volname) {
		return PveSnapshotDisk{}, false, ErrPveSnapshotStorage
	}
	if format == "" {
		switch {
		case strings.HasSuffix(volname, ".qcow2"):
			format = "qcow2"
		case strings.HasSuffix(volname, ".raw"):
			format = "raw"
		case strings.HasSuffix(volname, ".vmdk"):
			format = "vmdk"
		}
	}
	if format != "" && !pveVolFormatRe.MatchString(format) {
		return PveSnapshotDisk{}, false, ErrPveSnapshotState
	}
	return PveSnapshotDisk{Key: key, Volume: volume, Storage: storage, Format: format}, false, nil
}

// mutation builds the engine request of r with the bound facts b. The
// precheck and liveCheck (facts read through sc) re-derive b from fresh
// reads and refuse any difference.
func (r PveGuestSnapshotRequest) mutation(sc PveSnapshotClient, b pveSnapshotBound) (PveMutationRequest, error) {
	method := "snapshot." + r.Kind + "." + r.Op
	if m, ok := pveSnapshotMethods[method]; !ok || m.kind != r.Kind || m.op != r.Op {
		return PveMutationRequest{}, ErrPveSnapshotRequest
	}
	args := pveSnapshotStepArgs{VMID: r.VMID, Name: r.Name}
	params := pveSnapshotParams{Op: r.Op, Kind: r.Kind, Name: r.Name}
	switch r.Op {
	case PveSnapshotCreate:
		args.VMState, params.VMState = r.VMState, r.VMState
		params.Disks = b.disks
		if params.Disks == nil {
			params.Disks = []PveSnapshotDisk{}
		}
	default:
		if b.snapshot == nil || (r.Op == PveSnapshotRollback) != (b.rollback != nil) {
			return PveMutationRequest{}, ErrPveMutationPlan
		}
		s := *b.snapshot
		args.VMState, args.SnapTime, args.Parent = s.VMState, s.SnapTimeUnix, s.Parent
		params.Snapshot = &s
		if b.rollback != nil {
			e := *b.rollback
			args.Start = e.Start
			params.Rollback = &e
		}
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	params.Steps = []PveMutationStep{{Method: method, Args: rawArgs}}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	kind := r.Kind
	return PveMutationRequest{
		Digest: r.Digest, RemoteID: r.RemoteID, Kind: r.Kind, Node: r.Node, VMID: r.VMID,
		ActionID: PveGuestSnapshotAction, ModuleVersion: pveGuestSnapshotVersion, Artifact: pveSnapshotArtifact(r.Op),
		Parameters: rawParams,
		precheck: func(live PveTargetState) error {
			if live.Kind != kind {
				return ErrPveTargetChanged
			}
			if b.rollback != nil && live.Status != b.rollback.StatusBefore {
				// The power state the rollback's side effects were approved
				// for changed.
				return ErrPveSnapshotChanged
			}
			return nil
		},
		liveCheck: func(ctx context.Context, rm executordb.PveRemote, live PveTargetState, read pveapi.TokenSupplier) error {
			f, err := sc.SnapshotFacts(ctx, rm, r.Kind, r.Node, r.VMID, read)
			if err != nil {
				return ErrPveSnapshotState
			}
			again, err := r.bind(live, f)
			if err != nil {
				return err
			}
			if !sameSnapshotBound(again, b) {
				return ErrPveSnapshotChanged
			}
			return nil
		},
	}, nil
}

func sameSnapshotBound(a, b pveSnapshotBound) bool {
	x, errA := json.Marshal(struct {
		D []PveSnapshotDisk
		S *PveSnapshotIdentity
		R *pveSnapshotRollbackEffects
	}{a.disks, a.snapshot, a.rollback})
	y, errB := json.Marshal(struct {
		D []PveSnapshotDisk
		S *PveSnapshotIdentity
		R *pveSnapshotRollbackEffects
	}{b.disks, b.snapshot, b.rollback})
	return errA == nil && errB == nil && string(x) == string(y)
}

// PveGuestSnapshot proposes and runs guest snapshot actions on the
// executor's single PVE mutation engine.
type PveGuestSnapshot struct {
	Mutations *PveMutations
	// Bindings maps bound parameters hashes to the exact target and op for
	// GuestSnapshotRiskFloor.
	Bindings *PveGuestPowerBindings
	// Floor, if set, is evaluated by Propose (with the binding held) and
	// raises the proposed risk to it; it can only raise the risk.
	Floor permit.RiskPolicy
}

func (g *PveGuestSnapshot) client() (PveSnapshotClient, error) {
	if g.Mutations == nil || g.Bindings == nil {
		return nil, errors.New("executor: pve guest snapshot: Mutations and Bindings are required")
	}
	if err := g.Mutations.checkDeps(); err != nil {
		return nil, err
	}
	sc, ok := g.Mutations.Client.(PveSnapshotClient)
	if !ok {
		return nil, ErrPveSnapshotUnavailable
	}
	return sc, nil
}

// prepare reads the live target and facts and builds the engine request
// with the bound facts.
func (g *PveGuestSnapshot) prepare(ctx context.Context, sc PveSnapshotClient, req PveGuestSnapshotRequest) (PveMutationRequest, error) {
	m := g.Mutations
	rm, err := m.activeRemote(req.RemoteID)
	if err != nil {
		return PveMutationRequest{}, err
	}
	probe := PveMutationRequest{RemoteID: req.RemoteID, Kind: req.Kind, Node: req.Node, VMID: req.VMID}
	_, live, err := m.targetLive(ctx, rm, probe)
	if err != nil {
		return PveMutationRequest{}, err
	}
	read, err := m.readToken(rm)
	if err != nil {
		return PveMutationRequest{}, err
	}
	f, err := sc.SnapshotFacts(ctx, rm, req.Kind, req.Node, req.VMID, read)
	if err != nil {
		return PveMutationRequest{}, ErrPveSnapshotState
	}
	b, err := req.bind(live, f)
	if err != nil {
		return PveMutationRequest{}, err
	}
	return req.mutation(sc, b)
}

// Propose proposes req for the guest's current exact target and the live
// facts it binds (disk set, or the exact snapshot and rollback side
// effects). The risk is the op's base raised by the executor floor.
func (g *PveGuestSnapshot) Propose(ctx context.Context, req PveGuestSnapshotRequest, executionID string, expiry time.Time) (permit.Permit, error) {
	if err := req.validate(false); err != nil {
		return permit.Permit{}, err
	}
	sc, err := g.client()
	if err != nil {
		return permit.Permit{}, err
	}
	mreq, err := g.prepare(ctx, sc, req)
	if err != nil {
		return permit.Permit{}, err
	}
	rq, params, err := g.Mutations.ProposalRequest(ctx, mreq, executionID, pveSnapshotOps[req.Op], pveSnapshotStagePlan, expiry)
	if err != nil {
		return permit.Permit{}, err
	}
	t, err := boundTarget(params)
	if err != nil {
		return permit.Permit{}, err
	}
	release, err := g.Bindings.hold(rq.ParametersHash, t, req.Op)
	if err != nil {
		return permit.Permit{}, err
	}
	defer release()
	if g.Floor != nil {
		f, _, err := g.Floor.MinimumRisk(rq, rq.ResolvedTargets)
		if err != nil {
			return permit.Permit{}, fmt.Errorf("%w: %w", ErrPveSnapshotRisk, err)
		}
		if f.Rank() > rq.RiskClass.Rank() {
			rq.RiskClass = f
		}
	}
	res, err := g.Mutations.Auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return permit.Permit{}, err
	}
	g.Bindings.keep(rq.ParametersHash, time.Unix(res.Permit.Request.ExpiryUnix, 0))
	g.Mutations.log().Info("audit", "kind", "pve_guest_snapshot_proposed", "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID,
		"op", req.Op, "risk", string(res.Permit.Request.RiskClass), "execution", executionID)
	return res.Permit, nil
}

// Run runs the approved snapshot action req.Digest. req must carry the
// approved snapshot identity for delete and rollback. The exact target and
// the bound facts are read again before authorization, immediately before
// the step's intent and by the dispatcher before sending; any drift sends
// nothing.
func (g *PveGuestSnapshot) Run(ctx context.Context, req PveGuestSnapshotRequest) (PveMutationResult, error) {
	if err := req.validate(true); err != nil {
		return PveMutationResult{}, err
	}
	sc, err := g.client()
	if err != nil {
		return PveMutationResult{}, err
	}
	mreq, err := g.prepare(ctx, sc, req)
	if err != nil {
		return PveMutationResult{}, err
	}
	m := g.Mutations
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
	release, err := g.Bindings.hold(hash, t, req.Op)
	if err != nil {
		return PveMutationResult{}, err
	}
	defer release()
	return m.Run(ctx, mreq)
}

// GuestSnapshotRiskFloor is the executor floor of pve.guest.snapshot
// requests: the maximum of the op's base (create MEDIUM, delete and
// rollback HIGH), the criticality of the guest, its node and remote and of
// every host Linked returns for the guest or node (no exact record: at
// least HIGH), and Next's floor. Anything it cannot establish is HIGH.
// Other requests get Next's floor (HIGH without Next).
type GuestSnapshotRiskFloor struct {
	Next        permit.RiskPolicy
	Criticality PveCriticality
	Linked      PveLinkedHosts
	Bindings    *PveGuestPowerBindings
}

// MinimumRisk implements permit.RiskPolicy.
func (p GuestSnapshotRiskFloor) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	if r.ActionID != PveGuestSnapshotAction {
		if p.Next == nil {
			return canonical.RiskHigh, "no risk policy configured", nil
		}
		return p.Next.MinimumRisk(r, targets)
	}
	high := func(why string) (canonical.Risk, string, error) {
		return canonical.RiskHigh, "pve.guest.snapshot: " + why + ": unknown criticality is HIGH", nil
	}
	if p.Next == nil || p.Criticality == nil || p.Linked == nil || p.Bindings == nil {
		return high("risk sources not configured")
	}
	t, op, ok := p.Bindings.lookup(r.ParametersHash)
	if !ok {
		return high("no exact target bound to the parameters")
	}
	base, ok := pveSnapshotOps[op]
	if !ok || r.ArtifactSHA256 != sha256Hex(pveSnapshotArtifact(op)) {
		return high("artifact does not match the op")
	}
	guest, node, remote, err := PveGuestRiskTargets(t)
	if err != nil || len(targets) != 1 || targets[0] != guest {
		return high("targets do not match the bound guest")
	}
	risk, reasons := base, []string{fmt.Sprintf("pve.guest.snapshot %s is %s (ADR 0006)", op, base)}
	ext := []canonical.Target{guest, node, remote}
	for _, at := range []canonical.Target{guest, node} {
		hosts, err := p.Linked(r, at)
		if err != nil {
			return "", "", fmt.Errorf("guest snapshot risk floor: linked hosts: %w", err)
		}
		ext = append(ext, hosts...)
	}
	for _, at := range ext {
		c, exact, err := p.Criticality.HostCriticality(at.HostID, at.HostKeyFingerprint)
		if err != nil {
			return "", "", fmt.Errorf("guest snapshot risk floor: criticality: %w", err)
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
		return "", "", fmt.Errorf("guest snapshot risk floor: %w", err)
	}
	if nr.Rank() > risk.Rank() {
		risk = nr
		if why != "" {
			reasons = append(reasons, why)
		}
	}
	return risk, strings.Join(reasons, "; "), nil
}

// GuestSnapshotStepTaskType returns the PVE task type of a snapshot step
// method.
func GuestSnapshotStepTaskType(method string) (string, bool) {
	m, ok := pveSnapshotMethods[method]
	return m.taskType, ok
}

// GuestSnapshotStepTaskID returns the ID field (the VMID) of the PVE task
// a snapshot step creates.
func GuestSnapshotStepTaskID(step PveMutationStep) (string, bool) {
	if _, ok := pveSnapshotMethods[step.Method]; !ok {
		return "", false
	}
	var a pveSnapshotStepArgs
	if decodeStepArgsMax(step.Args, &a, maxPveSnapshotStepArgs) != nil || !validVMID(a.VMID) {
		return "", false
	}
	return strconv.FormatUint(a.VMID, 10), true
}

// PveGuestSnapshotWriter is the part of pveapi.Writer the snapshot steps
// use (action token).
type PveGuestSnapshotWriter interface {
	CreateSnapshot(ctx context.Context, r pveapi.SnapshotRequest) (string, error)
	DeleteSnapshot(ctx context.Context, kind pveapi.GuestKind, node string, vmid int64, name string) (string, error)
	RollbackSnapshot(ctx context.Context, plan pveapi.SnapshotRollbackPlan) (pveapi.RollbackResult, error)
}

// PveGuestSnapshotReader is the part of pveapi.Client the snapshot steps
// use to recheck the bound snapshot right before sending (read token).
type PveGuestSnapshotReader interface {
	ListSnapshots(ctx context.Context, node, guestKind string, vmid int64) (pveapi.SnapshotList, error)
	PlanSnapshotRollback(ctx context.Context, kind pveapi.GuestKind, node string, vmid int64, name string, start bool) (pveapi.SnapshotRollbackPlan, error)
}

// DispatchGuestSnapshotStep decodes one snapshot step strictly, rechecks
// the guest's snapshot list with rd and sends the step with w:
//
//   - create: the name must still be absent (complete list);
//   - delete and rollback: the exact snapshot (name, snaptime, parent, RAM
//     flag) must still be present; a rollback's plan must report the bound
//     RAM flag, and the bound start flag is sent.
//
// Any refusal before sending, or by PVE, wraps ErrPveRejected.
func DispatchGuestSnapshotStep(ctx context.Context, w PveGuestSnapshotWriter, rd PveGuestSnapshotReader, node string, step PveMutationStep) (string, error) {
	m, ok := pveSnapshotMethods[step.Method]
	if !ok || w == nil || rd == nil {
		return "", fmt.Errorf("dispatch snapshot step: %w", ErrPveRejected)
	}
	var a pveSnapshotStepArgs
	if err := decodeStepArgsMax(step.Args, &a, maxPveSnapshotStepArgs); err != nil {
		return "", err
	}
	reject := func(why string) (string, error) {
		return "", fmt.Errorf("dispatch %s: %s: %w", step.Method, why, ErrPveRejected)
	}
	if !validVMID(a.VMID) || !validSnapshotWriteName(a.Name) || a.SnapTime < 0 {
		return reject("arguments")
	}
	if m.kind != permit.ProviderKindQemu && a.VMState {
		return reject("vmstate")
	}
	if m.op == PveSnapshotCreate && (a.SnapTime != 0 || a.Parent != "" || a.Start) {
		return reject("arguments")
	}
	if m.op == PveSnapshotDelete && a.Start {
		return reject("arguments")
	}
	kind, vmid := pveapi.GuestKind(m.kind), int64(a.VMID)
	list, err := rd.ListSnapshots(ctx, node, m.kind, vmid)
	if err != nil || !list.Complete {
		return reject("snapshot list unavailable")
	}
	var found *pveapi.Snapshot
	for i := range list.Snapshots {
		if list.Snapshots[i].Name == a.Name {
			found = &list.Snapshots[i]
		}
	}
	if m.op == PveSnapshotCreate {
		if found != nil {
			return reject("name exists")
		}
		upid, err := w.CreateSnapshot(ctx, pveapi.SnapshotRequest{Kind: kind, Node: node, VMID: vmid, Name: a.Name, VMState: a.VMState})
		return pveWriteResult(step.Method, upid, err)
	}
	if found == nil || found.SnapTimeUnix != a.SnapTime || found.Parent != a.Parent || found.HasVMState != a.VMState {
		return reject("snapshot changed")
	}
	if m.op == PveSnapshotDelete {
		upid, err := w.DeleteSnapshot(ctx, kind, node, vmid, a.Name)
		return pveWriteResult(step.Method, upid, err)
	}
	plan, err := rd.PlanSnapshotRollback(ctx, kind, node, vmid, a.Name, a.Start)
	if err != nil || plan.HasVMState() != a.VMState || plan.Start() != a.Start || plan.Name() != a.Name {
		return reject("rollback plan differs")
	}
	res, err := w.RollbackSnapshot(ctx, plan)
	return pveWriteResult(step.Method, res.UPID, err)
}

var _ PveSnapshotClient = (*pveMutationClient)(nil)

// SnapshotFacts implements PveSnapshotClient with the read token over the
// remote's pinned transport.
func (c *pveMutationClient) SnapshotFacts(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (PveSnapshotFacts, error) {
	if err := permit.ValidateProviderMutationShape(kind, node, vmid); err != nil || kind == permit.ProviderKindNode || read == nil {
		return PveSnapshotFacts{}, ErrPveMutationRequest
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return PveSnapshotFacts{}, err
	}
	f, err := pveSnapshotFacts(ctx, hc, base, read, kind, node, vmid)
	if err = c.checkTrust(rm, watch, err); err != nil {
		return PveSnapshotFacts{}, err
	}
	return f, nil
}

func pveSnapshotFacts(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, kind, node string, vmid uint64) (PveSnapshotFacts, error) {
	var cfg map[string]json.RawMessage
	if err := pveGetData(ctx, hc, base, read, "/nodes/"+node+"/"+kind+"/"+strconv.FormatUint(vmid, 10)+"/config", nil, &cfg); err != nil {
		return PveSnapshotFacts{}, err
	}
	if len(cfg) == 0 || len(cfg) > maxPveSnapshotConfigKeys {
		return PveSnapshotFacts{}, errPveMutationRead
	}
	f := PveSnapshotFacts{Config: make(map[string]string, len(cfg))}
	for k, raw := range cfg {
		var s string
		if json.Unmarshal(raw, &s) == nil && len(s) <= maxPveSnapshotConfigValue {
			f.Config[k] = s
		} else if k == "lock" {
			f.Config[k] = "?"
		}
	}
	pc, err := pveapi.NewClient(hc, base+"/api2/json", read)
	if err != nil {
		return PveSnapshotFacts{}, errPveMutationRead
	}
	sl, err := pc.ListStorages(ctx, node)
	if err != nil {
		return PveSnapshotFacts{}, errPveMutationRead
	}
	snaps, err := pc.ListSnapshots(ctx, node, kind, int64(vmid))
	if err != nil {
		return PveSnapshotFacts{}, errPveMutationRead
	}
	f.Storages, f.StoragesComplete = sl.Storages, sl.Complete
	f.Snapshots, f.SnapshotsComplete = snaps.Snapshots, snaps.Complete
	return f, nil
}

// DispatchSnapshot implements PveSnapshotClient: DispatchGuestSnapshotStep
// with a writer that carries only action and a reader that carries only
// read, over the remote's pinned transport.
func (c *pveMutationClient) DispatchSnapshot(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action, read pveapi.TokenSupplier) (string, error) {
	if _, ok := pveSnapshotMethods[step.Method]; !ok || action == nil || read == nil || !permit.ValidPveNodeName(node) {
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
	rd, err := pveapi.NewClient(hc, base+"/api2/json", read)
	if err != nil {
		return "", fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
	}
	upid, err := DispatchGuestSnapshotStep(ctx, w, rd, node, step)
	if watch.failed.Load() {
		c.blockRemote(rm)
		return "", fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, errPveReadTrust)
	}
	return upid, err
}
