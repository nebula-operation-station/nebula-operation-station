// SPDX-License-Identifier: AGPL-3.0-or-later
package pvecollect

import (
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// maxReasonBytes bounds a carried dataset reason. Reasons come from the
// executor (itself sanitizing PVE output) but are still untrusted text, so
// they are truncated before spooling.
const maxReasonBytes = 512

// available is the PVE dataset state that carries a value.
const available = pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE

// boundedReason truncates a carried reason to maxReasonBytes.
func boundedReason(s string) string {
	if len(s) > maxReasonBytes {
		return s[:maxReasonBytes]
	}
	return s
}

// datasetUnavailable reports whether a read result carries no usable value:
// either the call errored or the executor marked the dataset unavailable.
func datasetUnavailable(res readResult) bool {
	if res.err != nil || res.resp == nil {
		return true
	}
	switch res.req.method {
	case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
		return res.resp.GetNodes() == nil || res.resp.GetNodes().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
		return res.resp.GetGuests() == nil || res.resp.GetGuests().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_STORAGE:
		return res.resp.GetStorages() == nil || res.resp.GetStorages().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER:
		return res.resp.GetCluster() == nil || res.resp.GetCluster().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_TASKS:
		return res.resp.GetTasks() == nil || res.resp.GetTasks().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG:
		return res.resp.GetGuestConfig() == nil || res.resp.GetGuestConfig().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT:
		return res.resp.GetGuestAgent() == nil || res.resp.GetGuestAgent().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS:
		return res.resp.GetSnapshots() == nil || res.resp.GetSnapshots().State != available
	case pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS:
		return res.resp.GetBackups() == nil || res.resp.GetBackups().State != available
	}
	return true
}

// readReason returns the executor's reason for an unavailable dataset, or a
// fixed message when the call itself failed.
func readReason(res readResult, fallback string) string {
	if res.err != nil {
		return fallback
	}
	if res.resp != nil {
		if r := reasonOf(res); r != "" {
			return boundedReason(r)
		}
	}
	return fallback
}

// reasonOf extracts the carried reason for a read result's dataset.
func reasonOf(res readResult) string {
	switch res.req.method {
	case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
		return res.resp.GetNodes().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
		return res.resp.GetGuests().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_STORAGE:
		return res.resp.GetStorages().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER:
		return res.resp.GetCluster().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_TASKS:
		return res.resp.GetTasks().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG:
		return res.resp.GetGuestConfig().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT:
		return res.resp.GetGuestAgent().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS:
		return res.resp.GetSnapshots().GetReason()
	case pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS:
		return res.resp.GetBackups().GetReason()
	}
	return ""
}

// convertNodes converts the NODES payload.
func convertNodes(res readResult) pvecontract.Dataset[[]pvecontract.NodeObservation] {
	p := res.resp.GetNodes()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[[]pvecontract.NodeObservation](readReason(res, "nodes unavailable"))
	}
	out := make([]pvecontract.NodeObservation, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		out = append(out, convertNode(n))
	}
	return pvecontract.AvailableDataset(out)
}

// convertNode converts one node and its nested details dataset.
func convertNode(n *pb.PVENode) pvecontract.NodeObservation {
	nd := pvecontract.NodeObservation{
		Node:          n.Node,
		Status:        pvecontract.NodeStatus(n.Status),
		UptimeSeconds: n.UptimeSeconds,
		CPUCount:      n.CpuCount,
		RAMTotalBytes: n.RamTotalBytes,
		RAMUsedBytes:  n.RamUsedBytes,
	}
	d := n.GetDetails()
	if d != nil && d.State == available {
		nd.Details = pvecontract.AvailableDataset(pvecontract.NodeDetails{
			PVEVersion:    d.PveVersion,
			KernelVersion: d.KernelVersion,
		})
	} else {
		reason := "node details unavailable"
		if d != nil && d.Reason != "" {
			reason = boundedReason(d.Reason)
		}
		nd.Details = pvecontract.UnavailableDataset[pvecontract.NodeDetails](reason)
	}
	return nd
}

// convertGuests converts the GUESTS payload. Per-guest detail datasets start
// unavailable; applyGuestDetail fills the ones that were read.
func convertGuests(res readResult) pvecontract.Dataset[[]pvecontract.GuestObservation] {
	p := res.resp.GetGuests()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[[]pvecontract.GuestObservation](readReason(res, "guests unavailable"))
	}
	out := make([]pvecontract.GuestObservation, 0, len(p.Guests))
	for _, g := range p.Guests {
		out = append(out, pvecontract.GuestObservation{
			VMID:       g.Vmid,
			Kind:       pvecontract.GuestKind(g.Kind),
			Node:       g.Node,
			Name:       g.Name,
			Status:     pvecontract.GuestStatus(g.Status),
			Generation: g.Generation,
			UUID:       g.Uuid,
			Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
			Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("interfaces not collected in phase 1"),
			Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
			Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
			Backups:    pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("not read"),
		})
	}
	return pvecontract.AvailableDataset(out)
}

// convertGuestConfig converts one GUEST_CONFIG payload.
func convertGuestConfig(res readResult) pvecontract.Dataset[pvecontract.GuestConfig] {
	p := res.resp.GetGuestConfig()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[pvecontract.GuestConfig](readReason(res, "guest config unavailable"))
	}
	cfg := pvecontract.GuestConfig{
		CPUCount:  p.CpuCount,
		RAMBytes:  p.RamBytes,
		BootOrder: p.BootOrder,
		Tags:      p.Tags,
		Pool:      p.Pool,
	}
	for _, d := range p.Disks {
		cfg.Disks = append(cfg.Disks, pvecontract.Disk{
			Storage:   d.Storage,
			Volume:    d.Volume,
			Format:    d.Format,
			SizeBytes: d.SizeBytes,
		})
	}
	for _, h := range p.Hostpci {
		cfg.HostPCI = append(cfg.HostPCI, pvecontract.HostPCI{ID: h.Id, Device: h.Device, Target: h.Target})
	}
	if c := p.GetCloudInitIp(); c != nil {
		cfg.CloudInitIP = &pvecontract.CloudInitIP{IP: c.Ip, Gateway: c.Gateway, Nameservers: c.Nameservers}
	}
	if cap := p.GetCapabilities(); cap != nil {
		cfg.Capabilities = pvecontract.GuestCapabilities{
			Snapshots:     pvecontract.TriState(cap.Snapshots),
			LiveMigration: pvecontract.TriState(cap.LiveMigration),
			RAMSnapshots:  pvecontract.TriState(cap.RamSnapshots),
		}
	} else {
		cfg.Capabilities = pvecontract.GuestCapabilities{
			Snapshots:     pvecontract.Unknown,
			LiveMigration: pvecontract.Unknown,
			RAMSnapshots:  pvecontract.Unknown,
		}
	}
	return pvecontract.AvailableDataset(cfg)
}

// convertGuestAgent converts one GUEST_AGENT payload.
func convertGuestAgent(res readResult) pvecontract.Dataset[pvecontract.GuestAgent] {
	p := res.resp.GetGuestAgent()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[pvecontract.GuestAgent](readReason(res, "guest agent unavailable"))
	}
	agent := pvecontract.GuestAgent{Hostname: p.Hostname, OS: p.Os}
	for _, fs := range p.Filesystems {
		agent.Filesystems = append(agent.Filesystems, pvecontract.Filesystem{
			MountPoint: fs.MountPoint,
			FSType:     fs.Fstype,
			SizeBytes:  fs.SizeBytes,
			UsedBytes:  fs.UsedBytes,
		})
	}
	return pvecontract.AvailableDataset(agent)
}

// convertSnapshots converts one SNAPSHOTS payload.
func convertSnapshots(res readResult) pvecontract.Dataset[[]pvecontract.Snapshot] {
	p := res.resp.GetSnapshots()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[[]pvecontract.Snapshot](readReason(res, "snapshots unavailable"))
	}
	out := make([]pvecontract.Snapshot, 0, len(p.Snapshots))
	for _, s := range p.Snapshots {
		out = append(out, pvecontract.Snapshot{
			Name:     s.Name,
			TimeUnix: s.TimeUnix,
			Parent:   s.Parent,
			HasRAM:   s.HasRam,
		})
	}
	return pvecontract.AvailableDataset(out)
}

// convertBackups converts one BACKUPS payload.
func convertBackups(res readResult) pvecontract.Dataset[[]pvecontract.BackupEvidence] {
	p := res.resp.GetBackups()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence](readReason(res, "backups unavailable"))
	}
	out := make([]pvecontract.BackupEvidence, 0, len(p.Backups))
	for _, b := range p.Backups {
		out = append(out, pvecontract.BackupEvidence{
			Source:       b.Source,
			Kind:         b.Kind,
			Status:       b.Status,
			Name:         b.Name,
			StartedUnix:  b.StartedUnix,
			FinishedUnix: b.FinishedUnix,
			Verified:     pvecontract.TriState(b.Verified),
		})
	}
	return pvecontract.AvailableDataset(out)
}

// convertStorages converts the STORAGE payload.
func convertStorages(res readResult) pvecontract.Dataset[[]pvecontract.StorageObservation] {
	p := res.resp.GetStorages()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[[]pvecontract.StorageObservation](readReason(res, "storages unavailable"))
	}
	out := make([]pvecontract.StorageObservation, 0, len(p.Storages))
	for _, s := range p.Storages {
		out = append(out, pvecontract.StorageObservation{
			Name:      s.Name,
			Type:      s.Type,
			Format:    s.Format,
			Content:   s.Content,
			Active:    s.Active,
			SizeBytes: s.SizeBytes,
			FreeBytes: s.FreeBytes,
		})
	}
	return pvecontract.AvailableDataset(out)
}

// convertCluster converts the CLUSTER payload.
func convertCluster(res readResult) pvecontract.Dataset[pvecontract.ClusterObservation] {
	p := res.resp.GetCluster()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[pvecontract.ClusterObservation](readReason(res, "cluster unavailable"))
	}
	cluster := pvecontract.ClusterObservation{Quorum: p.Quorum}
	for _, n := range p.Nodes {
		cluster.Nodes = append(cluster.Nodes, pvecontract.ClusterNode{
			Node:        n.Node,
			Status:      pvecontract.NodeStatus(n.Status),
			Vote:        n.Vote,
			Maintenance: n.Maintenance,
		})
	}
	for _, h := range p.HaResources {
		cluster.HAResources = append(cluster.HAResources, pvecontract.HAResource{
			ID:       h.Id,
			Kind:     pvecontract.GuestKind(h.Kind),
			VMID:     h.Vmid,
			Desired:  h.Desired,
			Observed: h.Observed,
			Node:     h.Node,
		})
	}
	return pvecontract.AvailableDataset(cluster)
}

// convertTasks converts the TASKS payload.
func convertTasks(res readResult) pvecontract.Dataset[[]pvecontract.TaskObservation] {
	p := res.resp.GetTasks()
	if p == nil || p.State != available {
		return pvecontract.UnavailableDataset[[]pvecontract.TaskObservation](readReason(res, "tasks unavailable"))
	}
	out := make([]pvecontract.TaskObservation, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		out = append(out, pvecontract.TaskObservation{
			Node:        t.Node,
			Actor:       t.Actor,
			Type:        t.Type,
			Target:      t.Target,
			StartedUnix: t.StartedUnix,
			ExitStatus:  t.ExitStatus,
		})
	}
	return pvecontract.AvailableDataset(out)
}
