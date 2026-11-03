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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
)

// Typed intra-cluster migration (ADR 0006 "Phase 2 actions, permits and
// reconciliation", P2-01 migration profile): pve.guest.migrate, base HIGH.
//
// The approval binds the exact source node (the guest's node) and the exact
// destination node of the same cluster, the explicit mode (QEMU: online or
// offline; LXC: restart or offline, as the guest's power state requires),
// the guest's complete disk set and a complete storage mapping: every
// storage holding a disk (including unused volumes) maps to a storage of
// the destination node that is active and takes the guest's disk content;
// shared storage maps to itself. The action refuses:
//
//   - destination == source, a destination that is not an online member of
//     the remote's quorate cluster, or a remote without a cluster;
//   - a guest under HA management (no HA-aware migration path exists yet;
//     ADR 0006 forbids bypassing HA), or HA state that cannot be read;
//   - a live migration of a guest with any hostpci passthrough device;
//   - a storage mapping that misses a disk's storage or names one the guest
//     does not use;
//   - a locked guest, or a guest whose power state does not fit the mode.
//
// The bound facts and the guest's node, state and configuration digest are
// read again before authorization and immediately before the step's intent
// is recorded; the dispatcher re-reads cluster membership and HA state with
// the read token right before sending. Any drift sends nothing. Intent,
// UPID, lost-response identification and restart reconciliation are the
// PveMutations engine's: the qmigrate/vzmigrate task runs on the source
// node and carries the VMID.

// PveGuestMigrateAction is the action ID of the intra-cluster migration.
const PveGuestMigrateAction = "pve.guest.migrate"

// Migration limits and fixed values.
const (
	// pveGuestMigrateVersion is the module version of the migration
	// artifact.
	pveGuestMigrateVersion = "1.0.0"
	// maxPveMigrateStepArgs bounds the arguments of one migration step.
	maxPveMigrateStepArgs = 1024
	// maxPveMigrateDisks bounds the disk set of one guest.
	maxPveMigrateDisks = 64
	// pveHANotEnabled is the pveapi.HAStatus reason of a remote whose HA
	// endpoints do not exist: HA is known to be absent. Every other
	// unavailable reason means the HA state is unknown.
	pveHANotEnabled = "HA not enabled"
)

var (
	// ErrPveMigrateRequest is returned for an unknown kind, a malformed or
	// equal destination node, a mode flag the guest kind does not take, a
	// timeout without an LXC restart migration or a malformed storage
	// mapping. Nothing is read or sent.
	ErrPveMigrateRequest = errors.New("executor: unsupported pve guest migration request")
	// ErrPveMigrateTarget is returned when the remote has no quorate
	// cluster or the destination node is not an online member of it.
	// Nothing is sent.
	ErrPveMigrateTarget = errors.New("executor: the destination node is not an online member of the guest's quorate cluster")
	// ErrPveMigrateHA is returned for a guest under HA management:
	// migration through the HA manager is not supported yet, and NOS never
	// bypasses HA. Nothing is sent.
	ErrPveMigrateHA = errors.New("executor: the guest is HA-managed; NOS has no HA-aware migration path yet, migrate it through the HA manager")
	// ErrPveMigratePassthrough is returned for a live migration of a guest
	// with a hostpci passthrough device. Nothing is sent.
	ErrPveMigratePassthrough = errors.New("executor: live migration of a guest with PCI passthrough is refused")
	// ErrPveMigrateStorage is returned when the storage mapping does not
	// cover exactly the guest's disk storages, or a source or destination
	// storage is not usable (not listed, inactive, wrong content, shared
	// storage mapped elsewhere, passthrough or bind volumes). Nothing is
	// sent.
	ErrPveMigrateStorage = errors.New("executor: the storage mapping does not cover the guest's disks on usable storage")
	// ErrPveMigrateState is returned when the guest is locked, its power
	// state does not fit the requested mode, or the configuration, storage,
	// cluster or HA state could not be read completely. Nothing is sent.
	ErrPveMigrateState = errors.New("executor: pve guest state does not allow the migration")
	// ErrPveMigrateChanged is returned when facts bound in the approval
	// (disks, mapping, power state, cluster) changed. Nothing is sent.
	ErrPveMigrateChanged = errors.New("executor: pve guest, storage or cluster changed; the migration needs a new approval")
	// ErrPveMigrateUnavailable is returned when the engine's client has no
	// migration surface (PveMigrateClient).
	ErrPveMigrateUnavailable = errors.New("executor: pve guest migration is not available")
)

// pveMigrateMethods is the migration step allowlist with the PVE task type
// each creates.
var pveMigrateMethods = map[string]struct{ kind, taskType string }{
	"migrate.qemu": {permit.ProviderKindQemu, "qmigrate"},
	"migrate.lxc":  {permit.ProviderKindLXC, "vzmigrate"},
}

func pveMigrateArtifact() []byte {
	return []byte(PveGuestMigrateAction + " " + pveGuestMigrateVersion + "\n" +
		"Migrate the exact guest from the exact source node to the exact destination node of the same cluster with the explicit mode and the complete storage mapping; never HA-managed guests, never live with PCI passthrough.\n")
}

var pveMigrateStagePlan = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"pve-guest-migrate-v1"}`))
	return s
}()

var (
	pveUnusedDiskKeyRe = regexp.MustCompile(`^unused[0-9]{1,3}$`)
	pveHostPCIKeyRe    = regexp.MustCompile(`^hostpci[0-9]+$`)
)

// pveMigrateRelevantConfigKey reports whether a config member matters to a
// migration (a disk, unused volume or passthrough device); such a member
// must be a bounded string.
func pveMigrateRelevantConfigKey(k string) bool {
	return pveSnapshotRelevantConfigKey(k) || strings.HasPrefix(k, "unused") || strings.HasPrefix(k, "hostpci")
}

// PveMigrateFacts are the live facts a migration binds, read with the read
// token (untrusted; validated by the action).
type PveMigrateFacts struct {
	// Config holds the string-valued members of the guest configuration.
	Config map[string]string
	// SourceStorages and TargetStorages are the storage lists of the
	// source and destination nodes; the Complete flags are false when a
	// list was truncated.
	SourceStorages         []pveapi.Storage
	SourceStoragesComplete bool
	TargetStorages         []pveapi.Storage
	TargetStoragesComplete bool
	// Cluster is the remote's cluster status.
	Cluster pveapi.ClusterStatus
	// HA is the remote's HA state.
	HA pveapi.HAStatus
}

// PveMigrateClient is the migration surface of a PveMutationClient. The
// engine routes the migration step methods only to a client implementing
// it.
type PveMigrateClient interface {
	// MigrateFacts reads the guest's config, the storages of the source
	// and destination nodes, the cluster status and the HA state with the
	// read token.
	MigrateFacts(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, target string, read pveapi.TokenSupplier) (PveMigrateFacts, error)
	// DispatchMigrate sends one migration step with the action token after
	// rechecking cluster membership and HA state with the read token (see
	// DispatchGuestMigrateStep). An error wrapping ErrPveRejected means
	// nothing was sent or the remote refused it.
	DispatchMigrate(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action, read pveapi.TokenSupplier) (string, error)
}

// PveGuestMigrateRequest names one migration of one exact guest.
type PveGuestMigrateRequest struct {
	// Digest is the approved permit (Run only).
	Digest   canonical.Digest
	RemoteID string
	Kind     string
	// Node is the exact source node (the guest's node).
	Node string
	VMID uint64
	// Target is the exact destination node.
	Target string
	// Online asks for a live QEMU migration (required for a running QEMU
	// guest, refused for a stopped one).
	Online bool
	// Restart asks for an LXC restart migration (required for a running
	// container, refused for a stopped one); TimeoutSec is its shutdown
	// timeout.
	Restart    bool
	TimeoutSec int
	// StorageMap maps every source storage holding a disk of the guest to
	// its destination storage; shared storage maps to itself.
	StorageMap map[string]string
}

func (r PveGuestMigrateRequest) validate() error {
	switch r.Kind {
	case permit.ProviderKindQemu:
		if r.Restart || r.TimeoutSec != 0 {
			return ErrPveMigrateRequest
		}
	case permit.ProviderKindLXC:
		if r.Online || (r.Restart != (r.TimeoutSec != 0)) ||
			(r.Restart && (r.TimeoutSec < pveapi.MinPowerTimeoutSec || r.TimeoutSec > pveapi.MaxPowerTimeoutSec)) {
			return ErrPveMigrateRequest
		}
	default:
		return ErrPveMigrateRequest
	}
	if !permit.ValidPveNodeName(r.Target) || r.Target == r.Node {
		return ErrPveMigrateRequest
	}
	if len(r.StorageMap) > pveapi.MaxStorageMappingPairs {
		return ErrPveMigrateRequest
	}
	for src, dst := range r.StorageMap {
		if !pveStorageIDRe.MatchString(src) || !pveStorageIDRe.MatchString(dst) {
			return ErrPveMigrateRequest
		}
	}
	if err := permit.ValidateProviderMutationShape(r.Kind, r.Node, r.VMID); err != nil || !validVMID(r.VMID) {
		return ErrPveMutationRequest
	}
	return nil
}

// PveMigrateDisk is one volume of the disk set a migration binds.
type PveMigrateDisk struct {
	Key     string `json:"key"`
	Volume  string `json:"volume"`
	Storage string `json:"storage"`
	Shared  bool   `json:"shared"`
	// TargetStorage is the destination storage the mapping assigns.
	TargetStorage string `json:"target_storage"`
}

// pveMigrateStepArgs are the arguments of one migration step.
type pveMigrateStepArgs struct {
	VMID           uint64 `json:"vmid"`
	Target         string `json:"target"`
	Online         bool   `json:"online"`
	Restart        bool   `json:"restart"`
	TimeoutSec     int    `json:"timeout"`
	TargetStorage  string `json:"targetstorage"`
	WithLocalDisks bool   `json:"with_local_disks"`
}

// pveMigrateBound are the live facts a migration binds.
type pveMigrateBound struct {
	Disks          []PveMigrateDisk `json:"disks"`
	Mapping        string           `json:"mapping"`
	WithLocalDisks bool             `json:"with_local_disks"`
	SendMapping    bool             `json:"send_mapping"`
	StatusBefore   string           `json:"status_before"`
	QMPBefore      string           `json:"qmp_status_before"`
	Cluster        string           `json:"cluster"`
}

// pveMigrateParams are the action parameters bound in the approval.
type pveMigrateParams struct {
	Kind       string            `json:"kind"`
	Source     string            `json:"source_node"`
	Target     string            `json:"target_node"`
	Online     bool              `json:"online"`
	Restart    bool              `json:"restart"`
	TimeoutSec int               `json:"timeout"`
	StorageMap map[string]string `json:"storage_map"`
	Bound      pveMigrateBound   `json:"bound"`
	Steps      []PveMutationStep `json:"steps"`
}

// bind derives the bound facts of r from live state and facts, refusing
// whatever the migration does not allow.
func (r PveGuestMigrateRequest) bind(live PveTargetState, f PveMigrateFacts) (pveMigrateBound, error) {
	if live.Kind != r.Kind || live.Node != r.Node {
		return pveMigrateBound{}, ErrPveTargetChanged
	}
	if len(f.Config) == 0 || len(f.Config) > maxPveBackupConfigKeys || !f.SourceStoragesComplete || !f.TargetStoragesComplete {
		return pveMigrateBound{}, ErrPveMigrateState
	}
	if _, locked := f.Config["lock"]; locked {
		return pveMigrateBound{}, ErrPveMigrateState
	}
	if err := migrateClusterCheck(f.Cluster, r.Node, r.Target); err != nil {
		return pveMigrateBound{}, err
	}
	if err := migrateHACheck(f.HA, r.VMID); err != nil {
		return pveMigrateBound{}, err
	}
	if err := r.modeCheck(live); err != nil {
		return pveMigrateBound{}, err
	}
	if r.Online {
		for k := range f.Config {
			if pveHostPCIKeyRe.MatchString(k) {
				return pveMigrateBound{}, ErrPveMigratePassthrough
			}
		}
	}
	disks, err := migrateDiskSet(r.Kind, f.Config)
	if err != nil {
		return pveMigrateBound{}, err
	}
	b := pveMigrateBound{StatusBefore: live.Status, QMPBefore: live.QMPStatus, Cluster: f.Cluster.Name}
	used := map[string]bool{}
	local := false
	for i := range disks {
		d := &disks[i]
		src, ok := findStorage(f.SourceStorages, d.Storage)
		if !ok || !src.Active {
			return pveMigrateBound{}, ErrPveMigrateStorage
		}
		dst, mapped := r.StorageMap[d.Storage]
		if !mapped {
			// The mapping misses a disk: PVE would pick a default.
			return pveMigrateBound{}, ErrPveMigrateStorage
		}
		ts, ok := findStorage(f.TargetStorages, dst)
		if !ok || !ts.Active || !slices.Contains(ts.Content, pveMigrateContent(r.Kind)) {
			return pveMigrateBound{}, ErrPveMigrateStorage
		}
		if src.Shared && (dst != d.Storage || !ts.Shared) {
			// Shared volumes stay where they are.
			return pveMigrateBound{}, ErrPveMigrateStorage
		}
		d.Shared, d.TargetStorage = src.Shared, dst
		local = local || !src.Shared
		used[d.Storage] = true
	}
	for src := range r.StorageMap {
		if !used[src] {
			// A mapping entry for a storage the guest does not use: the
			// approval would show a mapping that does not describe it.
			return pveMigrateBound{}, ErrPveMigrateStorage
		}
	}
	pairs := make([]string, 0, len(r.StorageMap))
	for src, dst := range r.StorageMap {
		pairs = append(pairs, src+":"+dst)
	}
	sort.Strings(pairs)
	b.Disks = disks
	if b.Disks == nil {
		b.Disks = []PveMigrateDisk{}
	}
	b.Mapping = strings.Join(pairs, ",")
	b.SendMapping = local && b.Mapping != ""
	b.WithLocalDisks = local && r.Kind == permit.ProviderKindQemu
	if len(b.Mapping) > pveapi.MaxStorageTargetBytes {
		return pveMigrateBound{}, ErrPveMigrateRequest
	}
	return b, nil
}

func pveMigrateContent(kind string) string {
	if kind == permit.ProviderKindLXC {
		return "rootdir"
	}
	return "images"
}

// modeCheck requires the explicit mode to fit the guest's power state.
func (r PveGuestMigrateRequest) modeCheck(live PveTargetState) error {
	switch live.Status {
	case pveGuestRunning:
		if r.Kind == permit.ProviderKindQemu && (!r.Online || live.QMPStatus != pveGuestRunning) {
			return ErrPveMigrateState
		}
		if r.Kind == permit.ProviderKindLXC && !r.Restart {
			return ErrPveMigrateState
		}
	case "stopped":
		if r.Online || r.Restart {
			return ErrPveMigrateState
		}
	default:
		return ErrPveMigrateState
	}
	return nil
}

// migrateClusterCheck requires a quorate cluster with source and target as
// distinct, online, unique members.
func migrateClusterCheck(c pveapi.ClusterStatus, source, target string) error {
	if !c.Available || !c.Quorum || source == target {
		return ErrPveMigrateTarget
	}
	member := func(name string) bool {
		n, online := 0, false
		for _, m := range c.Members {
			if m.Name == name {
				n++
				online = m.Online
			}
		}
		return n == 1 && online
	}
	if !member(source) || !member(target) {
		return ErrPveMigrateTarget
	}
	return nil
}

// migrateHACheck refuses an HA-managed guest and unknown HA state.
func migrateHACheck(ha pveapi.HAStatus, vmid uint64) error {
	if !ha.Available {
		if ha.Reason == pveHANotEnabled {
			return nil
		}
		return ErrPveMigrateState
	}
	for _, res := range ha.Resources {
		if res.VMID >= 0 && uint64(res.VMID) == vmid {
			return ErrPveMigrateHA
		}
	}
	return nil
}

// migrateDiskSet parses every volume of the guest (disks and unused
// volumes; CD-ROM drives are not migrated volumes) sorted by key.
// Passthrough devices, bind mounts and disk-like keys this code does not
// know are refused rather than left out.
func migrateDiskSet(kind string, cfg map[string]string) ([]PveMigrateDisk, error) {
	keyRe := pveQemuDiskKeyRe
	if kind == permit.ProviderKindLXC {
		keyRe = pveLXCDiskKeyRe
	}
	var disks []PveMigrateDisk
	for key, val := range cfg {
		unused := pveUnusedDiskKeyRe.MatchString(key)
		if !keyRe.MatchString(key) && !unused {
			if key != "vmstatestorage" && pveMigrateRelevantConfigKey(key) && !pveHostPCIKeyRe.MatchString(key) {
				return nil, ErrPveMigrateState
			}
			continue
		}
		d, skip, err := parseSnapshotDisk(kind, key, val)
		if errors.Is(err, ErrPveSnapshotStorage) {
			return nil, ErrPveMigrateStorage
		}
		if err != nil {
			return nil, ErrPveMigrateState
		}
		if skip {
			continue
		}
		if len(disks) >= maxPveMigrateDisks {
			return nil, ErrPveMigrateState
		}
		disks = append(disks, PveMigrateDisk{Key: d.Key, Volume: d.Volume, Storage: d.Storage})
	}
	slices.SortFunc(disks, func(a, b PveMigrateDisk) int { return strings.Compare(a.Key, b.Key) })
	return disks, nil
}

func (r PveGuestMigrateRequest) mutation(mc PveMigrateClient, b pveMigrateBound) (PveMutationRequest, error) {
	method := "migrate." + r.Kind
	if pveMigrateMethods[method].kind != r.Kind {
		return PveMutationRequest{}, ErrPveMigrateRequest
	}
	args := pveMigrateStepArgs{VMID: r.VMID, Target: r.Target, Online: r.Online, Restart: r.Restart, TimeoutSec: r.TimeoutSec,
		WithLocalDisks: b.WithLocalDisks}
	if b.SendMapping {
		args.TargetStorage = b.Mapping
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	sm := map[string]string{}
	for k, v := range r.StorageMap {
		sm[k] = v
	}
	params, err := json.Marshal(pveMigrateParams{Kind: r.Kind, Source: r.Node, Target: r.Target, Online: r.Online, Restart: r.Restart,
		TimeoutSec: r.TimeoutSec, StorageMap: sm, Bound: b, Steps: []PveMutationStep{{Method: method, Args: rawArgs}}})
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	return PveMutationRequest{
		Digest: r.Digest, RemoteID: r.RemoteID, Kind: r.Kind, Node: r.Node, VMID: r.VMID,
		ActionID: PveGuestMigrateAction, ModuleVersion: pveGuestMigrateVersion, Artifact: pveMigrateArtifact(),
		Parameters: params,
		precheck: func(live PveTargetState) error {
			if live.Kind != r.Kind || live.Node != r.Node {
				return ErrPveTargetChanged
			}
			if live.Status != b.StatusBefore || live.QMPStatus != b.QMPBefore {
				return ErrPveMigrateChanged
			}
			return nil
		},
		liveCheck: func(ctx context.Context, rm executordb.PveRemote, live PveTargetState, read pveapi.TokenSupplier) error {
			f, err := mc.MigrateFacts(ctx, rm, r.Kind, r.Node, r.VMID, r.Target, read)
			if err != nil {
				return ErrPveMigrateState
			}
			again, err := r.bind(live, f)
			if err != nil {
				return err
			}
			if !sameMigrateBound(again, b) {
				return ErrPveMigrateChanged
			}
			return nil
		},
	}, nil
}

func sameMigrateBound(a, b pveMigrateBound) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

// PveGuestMigrate proposes and runs intra-cluster migrations on the
// executor's single PVE mutation engine.
type PveGuestMigrate struct {
	Mutations *PveMutations
	// Bindings maps bound parameters hashes to the exact target and
	// destination node for GuestOpRiskFloor; it must be the instance the
	// authority's policy reads.
	Bindings *PveGuestPowerBindings
	// Floor, if set, is evaluated by Propose (with the binding held) and
	// raises the proposed risk to it; it can only raise the risk.
	Floor permit.RiskPolicy
}

func (g *PveGuestMigrate) client() (PveMigrateClient, error) {
	if g.Mutations == nil || g.Bindings == nil {
		return nil, errors.New("executor: pve guest migrate: Mutations and Bindings are required")
	}
	if err := g.Mutations.checkDeps(); err != nil {
		return nil, err
	}
	mc, ok := g.Mutations.Client.(PveMigrateClient)
	if !ok {
		return nil, ErrPveMigrateUnavailable
	}
	return mc, nil
}

func (g *PveGuestMigrate) prepare(ctx context.Context, mc PveMigrateClient, req PveGuestMigrateRequest) (PveMutationRequest, error) {
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
	f, err := mc.MigrateFacts(ctx, rm, req.Kind, req.Node, req.VMID, req.Target, read)
	if err != nil {
		return PveMutationRequest{}, ErrPveMigrateState
	}
	b, err := req.bind(live, f)
	if err != nil {
		return PveMutationRequest{}, err
	}
	return req.mutation(mc, b)
}

// Propose proposes req for the guest's current exact target, binding the
// source and destination nodes, the mode, the disk set and the complete
// storage mapping. The risk is HIGH raised by the executor floor.
func (g *PveGuestMigrate) Propose(ctx context.Context, req PveGuestMigrateRequest, executionID string, expiry time.Time) (permit.Permit, error) {
	if err := req.validate(); err != nil {
		return permit.Permit{}, err
	}
	mc, err := g.client()
	if err != nil {
		return permit.Permit{}, err
	}
	mreq, err := g.prepare(ctx, mc, req)
	if err != nil {
		return permit.Permit{}, err
	}
	return proposeGuestOp(ctx, g.Mutations, g.Bindings, g.Floor, mreq, pveGuestOpMigratePrefix+req.Target, canonical.RiskHigh, pveMigrateStagePlan, executionID, expiry)
}

// Run runs the approved migration req.Digest. The guest's node, state and
// configuration digest and every bound fact are read again before
// authorization and immediately before the step's intent; the dispatcher
// rechecks cluster membership and HA state before sending. Any drift sends
// nothing.
func (g *PveGuestMigrate) Run(ctx context.Context, req PveGuestMigrateRequest) (PveMutationResult, error) {
	if err := req.validate(); err != nil {
		return PveMutationResult{}, err
	}
	mc, err := g.client()
	if err != nil {
		return PveMutationResult{}, err
	}
	mreq, err := g.prepare(ctx, mc, req)
	if err != nil {
		return PveMutationResult{}, err
	}
	return runGuestOp(ctx, g.Mutations, g.Bindings, mreq, pveGuestOpMigratePrefix+req.Target)
}

// GuestMigrateStepTaskType returns the PVE task type of a migration step
// method.
func GuestMigrateStepTaskType(method string) (string, bool) {
	m, ok := pveMigrateMethods[method]
	return m.taskType, ok
}

// GuestMigrateStepTaskID returns the ID field (the VMID) of the PVE task a
// migration step creates.
func GuestMigrateStepTaskID(step PveMutationStep) (string, bool) {
	if _, ok := pveMigrateMethods[step.Method]; !ok {
		return "", false
	}
	var a pveMigrateStepArgs
	if decodeStepArgsMax(step.Args, &a, maxPveMigrateStepArgs) != nil || !validVMID(a.VMID) {
		return "", false
	}
	return strconv.FormatUint(a.VMID, 10), true
}

// PveGuestMigrateWriter is the part of pveapi.Writer the migration step
// uses (action token).
type PveGuestMigrateWriter interface {
	MigrateGuest(ctx context.Context, r pveapi.MigrateRequest) (string, error)
}

// PveGuestMigrateReader is the part of pveapi.Client the migration step
// uses to recheck cluster membership and HA state right before sending
// (read token).
type PveGuestMigrateReader interface {
	ClusterStatus(ctx context.Context) (pveapi.ClusterStatus, error)
	HAStatus(ctx context.Context) (pveapi.HAStatus, error)
}

// DispatchGuestMigrateStep decodes one migration step strictly, rechecks
// with rd that source and destination are online members of a quorate
// cluster and that the guest is not HA-managed, and sends the step with
// w. Any refusal before sending, or by PVE, wraps ErrPveRejected.
func DispatchGuestMigrateStep(ctx context.Context, w PveGuestMigrateWriter, rd PveGuestMigrateReader, node string, step PveMutationStep) (string, error) {
	m, ok := pveMigrateMethods[step.Method]
	if !ok || w == nil || rd == nil {
		return "", fmt.Errorf("dispatch migrate step: %w", ErrPveRejected)
	}
	var a pveMigrateStepArgs
	if err := decodeStepArgsMax(step.Args, &a, maxPveMigrateStepArgs); err != nil {
		return "", err
	}
	reject := func(why string) (string, error) {
		return "", fmt.Errorf("dispatch %s: %s: %w", step.Method, why, ErrPveRejected)
	}
	if !validVMID(a.VMID) || !permit.ValidPveNodeName(a.Target) || a.Target == node {
		return reject("arguments")
	}
	if m.kind == permit.ProviderKindQemu && (a.Restart || a.TimeoutSec != 0) {
		return reject("arguments")
	}
	if m.kind == permit.ProviderKindLXC && (a.Online || a.WithLocalDisks) {
		return reject("arguments")
	}
	cs, err := rd.ClusterStatus(ctx)
	if err != nil || migrateClusterCheck(cs, node, a.Target) != nil {
		return reject("cluster membership")
	}
	ha, err := rd.HAStatus(ctx)
	if err != nil || migrateHACheck(ha, a.VMID) != nil {
		return reject("ha state")
	}
	upid, err := w.MigrateGuest(ctx, pveapi.MigrateRequest{Kind: pveapi.GuestKind(m.kind), Node: node, VMID: int64(a.VMID),
		Target: a.Target, Online: a.Online, Restart: a.Restart, TimeoutSec: a.TimeoutSec,
		TargetStorage: a.TargetStorage, WithLocalDisks: a.WithLocalDisks})
	return pveWriteResult(step.Method, upid, err)
}

var _ PveMigrateClient = (*pveMutationClient)(nil)

// MigrateFacts implements PveMigrateClient with the read token over the
// remote's pinned transport.
func (c *pveMutationClient) MigrateFacts(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, target string, read pveapi.TokenSupplier) (PveMigrateFacts, error) {
	if err := permit.ValidateProviderMutationShape(kind, node, vmid); err != nil || kind == permit.ProviderKindNode ||
		!permit.ValidPveNodeName(target) || read == nil {
		return PveMigrateFacts{}, ErrPveMutationRequest
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return PveMigrateFacts{}, err
	}
	f, err := pveMigrateFacts(ctx, hc, base, read, kind, node, vmid, target)
	if err = c.checkTrust(rm, watch, err); err != nil {
		return PveMigrateFacts{}, err
	}
	return f, nil
}

func pveMigrateFacts(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, kind, node string, vmid uint64, target string) (PveMigrateFacts, error) {
	cfg, err := pveGuestConfigStrings(ctx, hc, base, read, kind, node, vmid, pveMigrateRelevantConfigKey)
	if err != nil {
		return PveMigrateFacts{}, err
	}
	pc, err := pveapi.NewClient(hc, base+"/api2/json", read)
	if err != nil {
		return PveMigrateFacts{}, errPveMutationRead
	}
	src, err := pc.ListStorages(ctx, node)
	if err != nil {
		return PveMigrateFacts{}, errPveMutationRead
	}
	dst, err := pc.ListStorages(ctx, target)
	if err != nil {
		return PveMigrateFacts{}, errPveMutationRead
	}
	cs, err := pc.ClusterStatus(ctx)
	if err != nil {
		return PveMigrateFacts{}, errPveMutationRead
	}
	ha, err := pc.HAStatus(ctx)
	if err != nil {
		return PveMigrateFacts{}, errPveMutationRead
	}
	return PveMigrateFacts{Config: cfg, SourceStorages: src.Storages, SourceStoragesComplete: src.Complete,
		TargetStorages: dst.Storages, TargetStoragesComplete: dst.Complete, Cluster: cs, HA: ha}, nil
}

// DispatchMigrate implements PveMigrateClient: DispatchGuestMigrateStep
// with a writer that carries only action and a reader that carries only
// read, over the remote's pinned transport.
func (c *pveMutationClient) DispatchMigrate(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action, read pveapi.TokenSupplier) (string, error) {
	if _, ok := pveMigrateMethods[step.Method]; !ok || action == nil || read == nil || !permit.ValidPveNodeName(node) {
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
	upid, err := DispatchGuestMigrateStep(ctx, w, rd, node, step)
	if watch.failed.Load() {
		c.blockRemote(rm)
		return "", fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, errPveReadTrust)
	}
	return upid, err
}
