// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Preview mode, part two: the Proxmox inventory, a batch, read grants, a
// deploy profile and one finished deployment, so /pve, /batches, /leases
// and /deployments show content for the README screenshots. It is test-only
// like the rest of this binary: the executor sides that the real server
// reaches over gRPC are fakes here, and every name and address is invented
// (pve-a/pve-b/pve-c in 10.20.0.0/24).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Demo Proxmox remotes: a two-node cluster and one standalone node.
const (
	previewClusterID = "pve-lab"
	previewEdgeID    = "pve-edge"
	// previewTemplate is the stopped template the deployment clones.
	previewTemplate = 9000
	// previewDeployVMID is the VMID the fake provisioner assigns.
	previewDeployVMID = 110
	// previewDeployName is the deployed guest's name and host ID.
	previewDeployName = "app-01"
	// previewProfile is the demo deploy profile.
	previewProfile = "debian_app"
)

// errPreview is what every mutating fake executor call answers: the
// preview shows pages, it changes nothing.
var errPreview = errors.New("preview mode: the executor is not connected")

// previewRemotes are the registry records of the demo remotes.
func previewRemotes() []pvecontract.Remote {
	return []pvecontract.Remote{
		{RemoteID: previewClusterID, Name: "Lab cluster", Kind: pvecontract.KindCluster,
			Endpoints: []pvecontract.Endpoint{{Host: "10.20.0.11", Port: 8006}, {Host: "10.20.0.12", Port: 8006}},
			TrustPin:  strings.Repeat("5a", 32), TrustGeneration: 2},
		{RemoteID: previewEdgeID, Name: "Edge node", Kind: pvecontract.KindStandalone,
			Endpoints: []pvecontract.Endpoint{{Host: "10.20.0.13", Port: 8006}},
			TrustPin:  strings.Repeat("e7", 32), TrustGeneration: 1},
	}
}

// previewRemoteMetas serves ui.Options.PVERemotes like the executor's
// ListPVERemotes would: both remotes active.
func previewRemoteMetas(context.Context) ([]ui.PVERemoteMeta, error) {
	var out []ui.PVERemoteMeta
	for _, r := range previewRemotes() {
		m := ui.PVERemoteMeta{RemoteID: r.RemoteID, Name: r.Name, Kind: string(r.Kind), TrustPin: r.TrustPin,
			TrustGeneration: r.TrustGeneration, State: "active"}
		for _, ep := range r.Endpoints {
			m.Endpoints = append(m.Endpoints, ui.PVEEndpoint{Host: ep.Host, Port: int(ep.Port)})
		}
		out = append(out, m)
	}
	return out, nil
}

func previewPin(remoteID string) string {
	for _, r := range previewRemotes() {
		if r.RemoteID == remoteID {
			return r.TrustPin
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Fake executor sides.

// previewExec is the operations executor in preview mode: the in-process
// executor plus a fixed read-grant registry (ListReadGrants), which the
// harness executor cannot fill without a real approval.
type previewExec struct {
	direct
	grants []*pb.ReadGrant
}

// ListReadGrants returns the demo grants.
func (p previewExec) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	return &pb.ListReadGrantsResponse{Grants: p.grants}, nil
}

// RevokeReadGrant refuses: the demo grants are fixed.
func (p previewExec) RevokeReadGrant(context.Context, *pb.RevokeReadGrantRequest, ...grpc.CallOption) (*pb.RevokeReadGrantResponse, error) {
	return nil, errPreview
}

// previewBatchExec is the batch planner's executor: host keys come from
// the in-process executor, proposing and running are refused.
type previewBatchExec struct{ direct }

func (previewBatchExec) ProposeBatch(context.Context, *pb.ProposeBatchRequest, ...grpc.CallOption) (*pb.ProposeBatchResponse, error) {
	return nil, errPreview
}

func (previewBatchExec) CommitBatch(context.Context, *pb.CommitBatchRequest, ...grpc.CallOption) (*pb.CommitBatchResponse, error) {
	return nil, errPreview
}

func (previewBatchExec) GetBatchStatus(context.Context, *pb.GetBatchStatusRequest, ...grpc.CallOption) (*pb.GetBatchStatusResponse, error) {
	return nil, errPreview
}

// previewSnapshots backs the guest snapshot page; every action is refused.
type previewSnapshots struct{}

func (previewSnapshots) ProposePVEGuestSnapshot(context.Context, *pb.ProposePVEGuestSnapshotRequest, ...grpc.CallOption) (*pb.ProposePVEGuestSnapshotResponse, error) {
	return nil, errPreview
}

func (previewSnapshots) SubmitAssertion(context.Context, *pb.SubmitAssertionRequest, ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	return nil, errPreview
}

func (previewSnapshots) CommitPVEGuestSnapshot(context.Context, *pb.CommitPVEGuestSnapshotRequest, ...grpc.CallOption) (*pb.CommitPVEGuestSnapshotResponse, error) {
	return nil, errPreview
}

// previewProvision is the executor's provisioning side for the one seeded
// deployment: it binds the proposed spec, accepts the (seeded) approval
// and reports the clone, configure, resize and start steps as succeeded.
type previewProvision struct{}

func (previewProvision) ProposePVEGuestProvision(_ context.Context, in *pb.ProposePVEGuestProvisionRequest, _ ...grpc.CallOption) (*pb.ProposePVEGuestProvisionResponse, error) {
	spec := in.GetSpec()
	target, err := permit.ProviderMutationTarget{RemoteID: spec.GetRemoteId(), TrustPin: previewPin(spec.GetRemoteId()), Kind: "node", Node: spec.GetNode()}.RiskTarget()
	if err != nil {
		return nil, err
	}
	const execID = "preview-provision-1"
	digest, c, err := previewRequest(canonical.Request{RequestVersion: 1, ExecutionID: execID, ActionID: "pve.guest.provision", ModuleVersion: "1.0.0",
		ArtifactSHA256: sha256Hex("pve.guest.provision"), ParametersHash: sha256Hex(spec.String()), CredentialRefs: []string{"pve-lab-action"},
		RiskClass: canonical.RiskHigh, StagePlanHash: sha256Hex("stages"), ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		ResolvedTargets: []canonical.Target{target}})
	if err != nil {
		return nil, err
	}
	return &pb.ProposePVEGuestProvisionResponse{ExecutionId: execID, Vmid: previewDeployVMID,
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: digest, CanonicalRequest: c,
			ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED, RiskClass: pb.RiskClass_RISK_CLASS_HIGH,
			ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix(), RequestOptionsJson: []byte(`{"challenge":"cHJldmlldw"}`)}}, nil
}

func (previewProvision) SubmitAssertion(context.Context, *pb.SubmitAssertionRequest, ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	return &pb.SubmitAssertionResponse{}, nil
}

func (previewProvision) CommitPVEGuestProvision(_ context.Context, in *pb.CommitPVEGuestProvisionRequest, _ ...grpc.CallOption) (*pb.CommitPVEGuestProvisionResponse, error) {
	out := &pb.CommitPVEGuestProvisionResponse{ExecutionId: "preview-provision-1", Vmid: in.GetSpec().GetVmid(), GuestConfigDigest: sha256Hex("guest config")}
	for _, typ := range []string{"qmclone", "qmconfig", "qmresize", "qmstart"} {
		out.Steps = append(out.Steps, &pb.PVEGuestPowerStep{State: "succeeded", TaskType: typ, Upid: "UPID:pve-b:0000" + typ + ":"})
	}
	return out, nil
}

// previewJoin is the executor's guest join side: it reports a host key
// for the new guest and pins exactly the approved binding.
type previewJoin struct{}

// previewDeployFingerprint is the invented host key fingerprint of app-01.
func previewDeployFingerprint() string {
	sum := sha256.Sum256([]byte("app-01 demo host key"))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func (previewJoin) ProposeGuestJoin(_ context.Context, in *pb.ProposeGuestJoinRequest, _ ...grpc.CallOption) (*pb.ProposeGuestJoinResponse, error) {
	h := in.GetHost()
	digest, c, err := previewRequest(canonical.Request{RequestVersion: 1, ExecutionID: "preview-join-1", ActionID: "core.enroll", ModuleVersion: "1.0.0",
		ArtifactSHA256: sha256Hex("core.enroll"), ParametersHash: sha256Hex(h.GetHostId()), CredentialRefs: []string{h.GetCredentialRef()},
		RiskClass: canonical.RiskMedium, StagePlanHash: sha256Hex("join"), ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		ResolvedTargets: []canonical.Target{{HostID: h.GetHostId(), HostKeyFingerprint: previewDeployFingerprint()}}})
	if err != nil {
		return nil, err
	}
	return &pb.ProposeGuestJoinResponse{JoinMethod: pveinventory.JoinMethodReview, AgentDetail: "the guest agent is not used",
		Host: &pb.EnrollHost{HostId: h.GetHostId(), Endpoint: h.GetEndpoint() + ":22", SshUser: h.GetSshUser(),
			CredentialRef: h.GetCredentialRef(), Fingerprint: previewDeployFingerprint(), KeyType: "ssh-ed25519"},
		Guest: in.GetGuest(),
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: digest, CanonicalRequest: c,
			RiskClass: pb.RiskClass_RISK_CLASS_MEDIUM, ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE,
			RequestOptionsJson: []byte(`{"challenge":"am9pbg"}`), ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix()},
	}, nil
}

func (previewJoin) CommitGuestJoin(_ context.Context, in *pb.CommitGuestJoinRequest, _ ...grpc.CallOption) (*pb.CommitGuestJoinResponse, error) {
	return &pb.CommitGuestJoinResponse{
		Result:          &pb.EnrollResult{HostId: in.GetHost().GetHostId(), Pinned: true, Fingerprint: in.GetHost().GetFingerprint()},
		ExecutionDigest: in.GetExecutionDigest(), Guest: in.GetGuest(), Host: in.GetHost(), JoinMethod: in.GetJoinMethod(),
	}, nil
}

// previewRequest encodes a canonical request and returns its digest.
func previewRequest(rq canonical.Request) (string, []byte, error) {
	c, err := canonical.Encode(rq)
	if err != nil {
		return "", nil, fmt.Errorf("encode preview request: %w", err)
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), c, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// newUUID4 returns a random version-4 UUID (read grant IDs must be one).
func newUUID4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ---------------------------------------------------------------------------
// Read grants.

// previewReadGrants returns one active and one expired read grant over
// the demo hosts, shaped like the executor's registry entries.
func previewReadGrants(now time.Time) []*pb.ReadGrant {
	grant := func(hosts, acts []string, created, expiry time.Time) *pb.ReadGrant {
		doc := permit.ReadGrantDoc{Grant: schedgrant.ReadFormat, ID: newUUID4(), Issuer: "nebula-server",
			CreatedUnix: created.Unix(), ExpiryUnix: expiry.Unix(), Trigger: permit.TriggerBoth,
			MinIntervalS: 900, RunBudget: 96, RateProfile: schedgrant.OrdinaryReadProfile}
		for _, id := range acts {
			a, ok := actions.Lookup(id)
			if !ok {
				panic("no action " + id)
			}
			doc.Actions = append(doc.Actions, permit.ReadGrantAction{ActionID: a.ID, ModuleVersion: a.Version,
				ArtifactSHA256: a.SHA256(), ParametersHash: sha256Hex("{}")})
		}
		for _, h := range hosts {
			doc.Targets = append(doc.Targets, canonical.Target{HostID: h, HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat(h, 32))[:32])})
		}
		raw, err := json.Marshal(doc)
		must(err)
		sum := sha256.Sum256(raw)
		return &pb.ReadGrant{GrantId: doc.ID, GrantDigest: hex.EncodeToString(sum[:]), CanonicalGrant: raw,
			ApprovedBy: "webauthn:" + sha256Hex("YubiKey 5C NFC")[:32], CreatedUnix: created.Unix(), ExpiryUnix: expiry.Unix()}
	}
	return []*pb.ReadGrant{
		grant([]string{"web", "nas", "db", "cache"}, []string{"core.facts", "host.metrics", "filesystem.list", "service.list"},
			now.Add(-2*24*time.Hour), now.Add(5*24*time.Hour)),
		grant([]string{"ci"}, []string{"core.facts", "package.list_updates"},
			now.Add(-10*24*time.Hour), now.Add(-3*24*time.Hour)),
	}
}

// ---------------------------------------------------------------------------
// Proxmox inventory.

// previewGuest is one demo guest; links names the managed host it is
// linked to ("" for none).
type previewGuest struct {
	vmid    uint64
	kind    pvecontract.GuestKind
	node    string
	name    string
	running bool
	cpus    uint32
	ramGiB  uint64
	diskGiB uint64
	storage string
	ip      string
	snaps   []pvecontract.Snapshot
	backup  time.Duration // age of the last backup; 0 for none
	link    string
}

func previewGuestsLab(now time.Time, withDeployed bool) []previewGuest {
	ts := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	g := []previewGuest{
		{vmid: 101, kind: pvecontract.GuestQEMU, node: "pve-a", name: "gitea", running: true, cpus: 2, ramGiB: 4, diskGiB: 64, storage: "local-lvm", ip: "10.20.0.101/24",
			snaps:  []pvecontract.Snapshot{{Name: "before-upgrade", TimeUnix: ts(9 * 24 * time.Hour)}, {Name: "weekly-1", TimeUnix: ts(2 * 24 * time.Hour), Parent: "before-upgrade"}},
			backup: 7 * time.Hour},
		{vmid: 102, kind: pvecontract.GuestQEMU, node: "pve-a", name: "web", running: true, cpus: 2, ramGiB: 2, diskGiB: 32, storage: "local-lvm", ip: "10.20.0.102/24",
			snaps: []pvecontract.Snapshot{{Name: "pre-nginx-1-25", TimeUnix: ts(30 * 24 * time.Hour)}}, backup: 7 * time.Hour, link: "web"},
		{vmid: 103, kind: pvecontract.GuestQEMU, node: "pve-b", name: "db", running: true, cpus: 4, ramGiB: 8, diskGiB: 128, storage: "local-lvm", ip: "10.20.0.103/24",
			snaps: []pvecontract.Snapshot{{Name: "pg16-migration", TimeUnix: ts(12 * 24 * time.Hour), HasRAM: true}}, backup: 6 * time.Hour, link: "db"},
		{vmid: 104, kind: pvecontract.GuestLXC, node: "pve-b", name: "cache", running: true, cpus: 1, ramGiB: 1, diskGiB: 8, storage: "local-lvm", ip: "10.20.0.104/24",
			backup: 31 * time.Hour, link: "cache"},
		{vmid: 105, kind: pvecontract.GuestLXC, node: "pve-a", name: "pihole", running: true, cpus: 1, ramGiB: 1, diskGiB: 8, storage: "local-lvm", ip: "10.20.0.105/24",
			backup: 7 * time.Hour},
		{vmid: 106, kind: pvecontract.GuestQEMU, node: "pve-b", name: "win11-test", running: false, cpus: 4, ramGiB: 8, diskGiB: 96, storage: "local-lvm",
			snaps: []pvecontract.Snapshot{{Name: "clean-install", TimeUnix: ts(60 * 24 * time.Hour)}}},
		{vmid: previewTemplate, kind: pvecontract.GuestQEMU, node: "pve-b", name: "debian-12-tpl", running: false, cpus: 1, ramGiB: 1, diskGiB: 16, storage: "local-lvm"},
	}
	if withDeployed {
		g = append(g, previewGuest{vmid: previewDeployVMID, kind: pvecontract.GuestQEMU, node: "pve-b", name: previewDeployName, running: true,
			cpus: 2, ramGiB: 2, diskGiB: 32, storage: "local-lvm", ip: "10.20.0.50/24"})
	}
	return g
}

func previewGuestsEdge() []previewGuest {
	return []previewGuest{
		{vmid: 201, kind: pvecontract.GuestLXC, node: "pve-c", name: "wireguard", running: true, cpus: 1, ramGiB: 1, diskGiB: 4, storage: "local-zfs", ip: "10.20.0.201/24",
			backup: 20 * time.Hour},
		{vmid: 202, kind: pvecontract.GuestQEMU, node: "pve-c", name: "ci", running: true, cpus: 4, ramGiB: 8, diskGiB: 100, storage: "local-zfs", ip: "10.20.0.202/24",
			backup: 4 * 24 * time.Hour, link: "ci"},
		{vmid: 203, kind: pvecontract.GuestLXC, node: "pve-c", name: "backup-proxy", running: false, cpus: 1, ramGiB: 1, diskGiB: 8, storage: "local-zfs"},
	}
}

// observation converts a demo guest into a guest observation.
func (g previewGuest) observation(now time.Time) pvecontract.GuestObservation {
	st := pvecontract.GuestStopped
	if g.running {
		st = pvecontract.GuestRunning
	}
	disk := "scsi0"
	if g.kind == pvecontract.GuestLXC {
		disk = "rootfs"
	}
	o := pvecontract.GuestObservation{VMID: g.vmid, Kind: g.kind, Node: g.node, Name: g.name, Status: st, Generation: 1,
		Config: pvecontract.AvailableDataset(pvecontract.GuestConfig{CPUCount: g.cpus, RAMBytes: g.ramGiB << 30,
			Disks:     []pvecontract.Disk{{Storage: g.storage, Volume: fmt.Sprintf("%s:vm-%d-disk-0", g.storage, g.vmid), Format: "raw", SizeBytes: g.diskGiB << 30}},
			BootOrder: []string{disk}, Tags: []string{"demo"},
			Capabilities: pvecontract.GuestCapabilities{Snapshots: pvecontract.Yes, LiveMigration: pvecontract.Unknown, RAMSnapshots: pvecontract.Unknown}}),
		Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("the guest is stopped"),
		Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("no guest agent"),
		Snapshots:  pvecontract.AvailableDataset(append([]pvecontract.Snapshot{}, g.snaps...)),
		Backups:    pvecontract.AvailableDataset([]pvecontract.BackupEvidence{}),
	}
	if g.ip != "" && g.running {
		src := pvecontract.SourceQEMUAgent
		if g.kind == pvecontract.GuestLXC {
			src = pvecontract.SourceLXCAPI
		}
		o.Interfaces = pvecontract.AvailableDataset([]pvecontract.GuestInterface{{Name: "net0",
			MAC: fmt.Sprintf("bc:24:11:00:%02x:%02x", g.vmid/256, g.vmid%256), Bridge: "vmbr0", IPs: []string{g.ip}, Source: src}})
	}
	if g.kind == pvecontract.GuestQEMU && g.running {
		used := g.diskGiB << 30 / 100 * uint64(35+g.vmid%50)
		o.Agent = pvecontract.AvailableDataset(pvecontract.GuestAgent{Hostname: g.name, OS: "Debian GNU/Linux 12 (bookworm)",
			Filesystems: []pvecontract.Filesystem{{MountPoint: "/", FSType: "ext4", SizeBytes: g.diskGiB << 30, UsedBytes: used}}})
	}
	if g.backup > 0 {
		end := now.Add(-g.backup)
		o.Backups = pvecontract.AvailableDataset([]pvecontract.BackupEvidence{
			{Source: pvecontract.BackupVZDump, Kind: pvecontract.BackupKindTask, Status: "success", Name: fmt.Sprintf("vzdump-%d", g.vmid),
				StartedUnix: end.Add(-6 * time.Minute).Unix(), FinishedUnix: end.Unix(), Verified: pvecontract.Unknown},
			{Source: pvecontract.BackupPBS, Kind: pvecontract.BackupKindCatalog, Status: "present", Name: fmt.Sprintf("vm/%d/%s", g.vmid, end.UTC().Format("2006-01-02T15:04:05Z")),
				StartedUnix: end.Add(-6 * time.Minute).Unix(), FinishedUnix: end.Unix(), Verified: pvecontract.Yes},
		})
	}
	return o
}

func previewNode(name string, cpus uint32, ramGiB, usedGiB uint64, uptime time.Duration) pvecontract.NodeObservation {
	return pvecontract.NodeObservation{Node: name, Status: pvecontract.NodeOnline, UptimeSeconds: uint64(uptime / time.Second), CPUCount: cpus,
		RAMTotalBytes: ramGiB << 30, RAMUsedBytes: usedGiB << 30,
		Details: pvecontract.AvailableDataset(pvecontract.NodeDetails{PVEVersion: "8.2.4", KernelVersion: "6.8.12-1-pve"})}
}

func previewStorage(node, name, typ string, content []string, sizeGiB, freeGiB uint64, shared bool) pvecontract.StorageObservation {
	return pvecontract.StorageObservation{Name: name, Type: typ, Content: content, Active: true,
		SizeBytes: sizeGiB << 30, FreeBytes: freeGiB << 30, Node: node, Shared: shared}
}

// previewObservation builds one complete collection of a remote.
func previewObservation(remoteID string, gen uint64, now time.Time, nodes []pvecontract.NodeObservation, guests []previewGuest,
	storages []pvecontract.StorageObservation, cluster *pvecontract.ClusterObservation, tasks []pvecontract.TaskObservation) pvecontract.Observation {
	obs := make([]pvecontract.GuestObservation, 0, len(guests))
	for _, g := range guests {
		obs = append(obs, g.observation(now))
	}
	o := pvecontract.Observation{RemoteID: remoteID, ObservedAt: now.Add(-90 * time.Second), Source: "pve-collector", CollectionGeneration: gen, Complete: true,
		Nodes: pvecontract.AvailableDataset(nodes), Guests: pvecontract.AvailableDataset(obs), Storages: pvecontract.AvailableDataset(storages),
		Cluster: pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("standalone node"),
		Tasks:   pvecontract.AvailableDataset(tasks)}
	if cluster != nil {
		o.Cluster = pvecontract.AvailableDataset(*cluster)
	}
	return o
}

// previewLabObservation is the cluster's collection; withDeployed adds
// the deployed guest (after the provisioning ran).
func previewLabObservation(gen uint64, now time.Time, withDeployed bool) pvecontract.Observation {
	return previewObservation(previewClusterID, gen, now,
		[]pvecontract.NodeObservation{previewNode("pve-a", 16, 64, 38, 41*24*time.Hour), previewNode("pve-b", 12, 48, 31, 41*24*time.Hour)},
		previewGuestsLab(now, withDeployed),
		[]pvecontract.StorageObservation{
			previewStorage("pve-a", "local-lvm", "lvmthin", []string{"images", "container"}, 900, 340, false),
			previewStorage("pve-b", "local-lvm", "lvmthin", []string{"images", "container"}, 900, 95, false),
			previewStorage("pve-a", "nas-backup", "nfs", []string{"backup", "iso"}, 4000, 1450, true),
			previewStorage("pve-b", "nas-backup", "nfs", []string{"backup", "iso"}, 4000, 1450, true),
		},
		&pvecontract.ClusterObservation{Quorum: "quorate", Nodes: []pvecontract.ClusterNode{
			{Node: "pve-a", Status: pvecontract.NodeOnline, Vote: true}, {Node: "pve-b", Status: pvecontract.NodeOnline, Vote: true}}},
		[]pvecontract.TaskObservation{
			{Node: "pve-a", Actor: "root@pam", Type: "vzdump", Target: "101", StartedUnix: now.Add(-7 * time.Hour).Unix(), ExitStatus: "success"},
			{Node: "pve-b", Actor: "root@pam", Type: "vzdump", Target: "103", StartedUnix: now.Add(-6 * time.Hour).Unix(), ExitStatus: "success"},
		})
}

// seedPreviewPVE stores the two demo remotes, their collections, and
// links the guests that are managed hosts.
func seedPreviewPVE(ctx context.Context, pve *pveinventory.Store, now time.Time) {
	for _, r := range previewRemotes() {
		must(pve.UpsertRemote(ctx, r))
	}
	_, err := pve.IngestObservation(ctx, previewLabObservation(1, now, false))
	must(err)
	_, err = pve.IngestObservation(ctx, previewObservation(previewEdgeID, 1, now,
		[]pvecontract.NodeObservation{previewNode("pve-c", 8, 32, 12, 9*24*time.Hour)},
		previewGuestsEdge(),
		[]pvecontract.StorageObservation{
			previewStorage("pve-c", "local-zfs", "zfspool", []string{"images", "container"}, 1800, 1210, false),
			previewStorage("pve-c", "usb-backup", "dir", []string{"backup"}, 2000, 160, false),
		}, nil,
		[]pvecontract.TaskObservation{{Node: "pve-c", Actor: "root@pam", Type: "vzdump", Target: "201", StartedUnix: now.Add(-20 * time.Hour).Unix(), ExitStatus: "success"}}))
	must(err)
	for remote, guests := range map[string][]previewGuest{previewClusterID: previewGuestsLab(now, false), previewEdgeID: previewGuestsEdge()} {
		for _, g := range guests {
			if g.link != "" {
				_, err := pve.CreateLink(ctx, remote, g.vmid, 1, g.link, "demo")
				must(err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Host metrics (org chart CPU/RAM/disk).

func hostMetricsResult(cpu float64, memUsedGiB, memTotalGiB, diskUsedGiB, diskTotalGiB uint64) []byte {
	return jsonDoc(map[string]any{"format": "host-metrics-v1", "phase": "done",
		"cpu":  b64(fmt.Sprintf("%.1f", cpu)),
		"load": b64("0.42 0.38 0.33"),
		"mem":  b64(fmt.Sprintf("%d %d", memUsedGiB<<30, memTotalGiB<<30)),
		"disk": b64(fmt.Sprintf("/\t%d\t%d", diskUsedGiB<<30, diskTotalGiB<<30))})
}

func filesystemsResult(mounts ...string) []byte {
	return jsonDoc(map[string]any{"format": "fs-list-v1", "phase": "done", "mounts": b64(strings.Join(mounts, "\n"))})
}

func fsLine(fstype, mount string, sizeGiB, usedGiB uint64) string {
	return fmt.Sprintf("%s\t%s\t%d\t%d", fstype, mount, sizeGiB<<30, usedGiB<<30)
}

// seedPreviewMetrics stores host.metrics and filesystem.list results for
// the reachable demo hosts, so the chart shows numbers.
func seedPreviewMetrics(ctx context.Context, sdb *sql.DB, now time.Time) {
	type m struct {
		host               string
		cpu                float64
		memUsed, memTotal  uint64
		rootUsed, rootSize uint64
		extra              string
		age                time.Duration
	}
	for _, h := range []m{
		{"web", 12.5, 1, 2, 11, 32, "", 6 * time.Minute},
		{"nas", 34.0, 6, 16, 40, 64, fsLine("zfs", "/tank", 8000, 6900), 9 * time.Minute},
		{"pve", 41.2, 38, 64, 21, 94, fsLine("ext4", "/var/lib/vz", 900, 560), 12 * time.Minute},
		{"db", 63.8, 7, 8, 71, 128, "", 15 * time.Minute},
		{"cache", 4.1, 1, 1, 3, 8, "", 20 * time.Minute},
	} {
		at := now.Add(-h.age)
		seedExec(ctx, sdb, "host.metrics", h.host, hostMetricsResult(h.cpu, h.memUsed, h.memTotal, h.rootUsed, h.rootSize), at, "finished", "finished", "success")
		mounts := []string{fsLine("ext4", "/", h.rootSize, h.rootUsed), fsLine("tmpfs", "/run", 1, 0)}
		if h.extra != "" {
			mounts = append(mounts, h.extra)
		}
		seedExec(ctx, sdb, "filesystem.list", h.host, filesystemsResult(mounts...), at, "finished", "finished", "success")
	}
}

// ---------------------------------------------------------------------------
// Batch.

// seedPreviewBatch stores one approved two-stage batch (canary first) of
// security updates with mixed member outcomes.
func seedPreviewBatch(ctx context.Context, sdb *sql.DB, svc direct, now time.Time) {
	keys, err := svc.ListHostKeys(ctx, &pb.ListHostKeysRequest{})
	must(err)
	fp := map[string]string{}
	for _, k := range keys.GetHosts() {
		fp[k.GetHostId()] = k.GetFingerprint()
	}
	a, ok := actions.Lookup("package.install_security")
	if !ok {
		panic("no action package.install_security")
	}
	id := newID36()
	created := now.Add(-3 * time.Hour)
	type member struct {
		host, outcome, detail string
		stage                 int
		unreachable           bool
	}
	members := []member{
		{"web", "success", "", 1, false},
		{"nas", "success", "", 2, false},
		{"db", "failed", "dpkg: error processing package postgresql-16 (--configure)", 2, false},
		{"backup", "success", "", 2, false},
		{"cache", "skipped", "skipped by demo before the stage opened", 2, false},
		{"ci", "not_executed", "no answer on 10.20.0.202:22", 2, true},
	}
	_, err = sdb.ExecContext(ctx, `INSERT INTO batches (id, digest, state, risk, requirement, member_count, stage_count, canonical, options,
		approval_expiry, expiry, approved_by, detail, created_by, created_at)
		VALUES (?, ?, 'approved', 'MEDIUM', 'assertion', ?, 2, ?, NULL, ?, ?, ?, ?, 'demo', ?)`,
		id, sha256Hex(id), len(members), []byte(`{"batch":"demo"}`), created.Add(5*time.Minute).Unix(), created.Add(24*time.Hour).Unix(),
		"webauthn:"+sha256Hex("YubiKey 5C NFC")[:32], "Security updates, canary first", created.Unix())
	must(err)
	_, err = sdb.ExecContext(ctx, `INSERT INTO batch_stages (batch_id, stage, stage_id, gate, failure_threshold, unreachable_threshold) VALUES
		(?, 1, 'canary', 'automatic', 0, 0), (?, 2, 'rest', 'manual', 1, 1)`, id, id)
	must(err)
	for i, m := range members {
		unr := 0
		if m.unreachable {
			unr = 1
		}
		_, err = sdb.ExecContext(ctx, `INSERT INTO batch_members (batch_id, idx, member_id, execution_id, stage, action_id, module_version,
			artifact_sha256, parameters_hash, params, risk, host_id, fingerprint, credential_ref, outcome, unreachable, detail, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', 'MEDIUM', ?, ?, 'nebula-default', ?, ?, ?, ?)`,
			id, i, fmt.Sprintf("m%d-%s", i+1, m.host), newID36(), m.stage, a.ID, a.Version, a.SHA256(), sha256Hex("{}"),
			m.host, fp[m.host], m.outcome, unr, m.detail, created.Add(time.Duration(10+i*3)*time.Minute).Unix())
		must(err)
	}
}

// ---------------------------------------------------------------------------
// Deploy profile and one finished deployment.

// seedPreviewDeployNetwork stores the server network the deployment takes
// its address from.
func seedPreviewDeployNetwork(ctx context.Context, ipamStore *ipam.Store) {
	must(ipamStore.SaveNetwork(ctx, ipam.Network{ID: "servers", Name: "Server VLAN", Prefix: netip.MustParsePrefix("10.20.0.0/24"), VLAN: 20,
		Gateway: netip.MustParseAddr("10.20.0.1"), Notes: "Proxmox nodes and guests",
		Pools: []ipam.Pool{{Name: "apps", First: netip.MustParseAddr("10.20.0.50"), Last: netip.MustParseAddr("10.20.0.79")}}}))
}

// seedPreviewProfile stores the demo deploy profile.
func seedPreviewProfile(ctx context.Context, profiles *deployprofile.Store) {
	_, err := profiles.Save(ctx, "demo", deployprofile.Profile{Slug: previewProfile, Title: "Debian app server",
		Description: "Debian 12 guest for small web apps, address from the server pool.", Image: "debian-12",
		Size: deployprofile.Size{Preset: "M"}, StorageClass: "local-lvm",
		Network:   deployprofile.Network{Bridge: "vmbr0", IPAMPool: "apps"},
		DNS:       deployprofile.DNS{Nameservers: []string{"10.20.0.1"}, SearchDomain: "lab.example"},
		Bootstrap: []deployprofile.BootstrapModule{}, Runbooks: []deployprofile.RunbookRef{}, VaultRefs: []deployprofile.VaultRef{}})
	must(err)
}

// seedPreviewDeployment drives one deployment through the real handlers
// with the fake provisioner and join: propose, approve, boot (a new
// collection shows the guest running), join and approve the join. The
// run ends "done" (the profile has no staged plan).
func seedPreviewDeployment(ctx context.Context, h http.Handler, pve *pveinventory.Store, log *slog.Logger) {
	do := func(method, path, ct, body string) (int, string, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get("Location")
	}
	wait := func(path, state string) {
		deadline := time.Now().Add(10 * time.Second)
		for {
			_, body, _ := do(http.MethodGet, path, "", "")
			if strings.Contains(body, `id="deploy-state">`+state+`<`) {
				return
			}
			if time.Now().After(deadline) {
				panic("preview deployment never reached " + state)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	const form = "application/x-www-form-urlencoded"
	f := url.Values{
		"remote": {previewClusterID}, "node": {"pve-b"}, "storage": {"local-lvm"}, "profile": {previewProfile}, "profile_version": {"1"},
		"image": {"debian-12"}, "template_vmid": {fmt.Sprint(previewTemplate)}, "template_sha256": {sha256Hex("debian-12-genericcloud-amd64.qcow2")},
		"size": {"M"}, "name": {previewDeployName}, "environment": {"PROD"}, "bridge": {"vmbr0"}, "ip_mode": {"ipam"}, "network": {"servers"},
		"pool": {"apps"}, "address": {"10.20.0.50"}, "nameservers": {"10.20.0.1"}, "search_domain": {"lab.example"},
		"ci_user": {"nebula"}, "password": {"none"},
	}
	code, body, run := do(http.MethodPost, "/deployments/propose", form, f.Encode())
	if code != http.StatusSeeOther {
		panic(fmt.Sprintf("preview deployment: propose = %d %s", code, body))
	}
	id := strings.TrimPrefix(run, "/deployments/")
	approve := `{"id":"` + id + `","assertion":{"id":"cHJldmlldw"}}`
	if code, body, _ := do(http.MethodPost, "/deployments/approve", "application/json", approve); code != http.StatusOK {
		panic(fmt.Sprintf("preview deployment: approve = %d %s", code, body))
	}
	wait(run, "booting")
	// The run's background writes may still hold the database (SQLITE_BUSY);
	// retry like the collector's next round would.
	var err error
	for range 100 {
		if _, err = pve.IngestObservation(ctx, previewLabObservation(2, time.Now(), true)); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	must(err)
	if code, body, _ := do(http.MethodPost, "/deployments/join", form, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther {
		panic(fmt.Sprintf("preview deployment: join = %d %s", code, body))
	}
	if code, body, _ := do(http.MethodPost, "/deployments/join/approve", "application/json", approve); code != http.StatusOK {
		panic(fmt.Sprintf("preview deployment: join approve = %d %s", code, body))
	}
	wait(run, "done")
	log.Info("preview: seeded deployment", "run", id, "guest", previewDeployName)
}

// previewBatches builds the batch planner and pages over sdb.
func previewBatches(sdb *sql.DB, svc direct, inv *inventory.Store, ops *executions.Service, log *slog.Logger) (*executions.Batches, *ui.BatchPages) {
	b, err := executions.NewBatches(executions.BatchOptions{Exec: previewBatchExec{svc}, DB: sdb, Hosts: inv, Log: log, Actions: ops,
		CredentialVersion: func(context.Context, string) (uint64, error) { return 0, errPreview }})
	must(err)
	pages, err := ui.NewBatchPages(b, log)
	must(err)
	return b, pages
}
