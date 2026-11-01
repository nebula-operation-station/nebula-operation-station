// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Guest-detail and task read limits (spec 07 "Provider profile").
const (
	// pveMaxGuestVMID is the largest VMID the PVE API accepts (31 bits).
	pveMaxGuestVMID = uint64(1)<<31 - 1
	// pveTaskWindow is how far back a TASKS read looks.
	pveTaskWindow = 24 * time.Hour
	// pveTasksPerNode bounds the task summaries read from one node; the
	// per-node share of MaxObjectsPerPage is used when it is smaller.
	pveTasksPerNode = 100
)

// Fixed reasons for guest-detail reads; raw PVE text never reaches the caller.
const (
	pveReasonGuestNotFound = "guest not found on any online node"
	pveReasonAgentQEMUOnly = "the guest agent exists only for QEMU guests"
	pveReasonAgentDown     = "guest agent not running or not responding"
	pveReasonTruncated     = "the list exceeded its limit"
)

// pveGuestRef is a resolved guest: the VMID a caller named, plus the node
// and kind PVE reports for it right now.
type pveGuestRef struct {
	guest pveapi.Guest
}

// resolvePveGuest finds vmid on the online nodes of the remote. A guest
// that is not found while some online node could not be listed is reported
// as a partial read, never as absent.
func resolvePveGuest(ctx context.Context, c *pveapi.Client, vmid uint64) (pveGuestRef, string) {
	if vmid < pvecontract.MinVMID || vmid > pveMaxGuestVMID {
		return pveGuestRef{}, pveReasonGuestNotFound
	}
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		return pveGuestRef{}, pveReasonRead
	}
	partial := false
	for _, n := range nodes {
		if n.Status != "online" {
			continue
		}
		for _, list := range []func(context.Context, string) ([]pveapi.Guest, error){c.ListQemu, c.ListLxc} {
			guests, err := list(ctx, n.Name)
			if err != nil {
				partial = true
				continue
			}
			for _, g := range guests {
				if g.VMID >= 0 && uint64(g.VMID) == vmid {
					return pveGuestRef{guest: g}, ""
				}
			}
		}
	}
	if partial {
		return pveGuestRef{}, pveReasonPartial
	}
	return pveGuestRef{}, pveReasonGuestNotFound
}

// observation returns a contract guest whose detail datasets are all
// unavailable; the caller sets the one it read before validation.
func (r pveGuestRef) observation() pvecontract.GuestObservation {
	st := pvecontract.GuestStatus(r.guest.Status)
	switch st {
	case pvecontract.GuestRunning, pvecontract.GuestStopped, pvecontract.GuestPaused:
	default:
		st = pvecontract.GuestUnknown
	}
	return pvecontract.GuestObservation{
		VMID: uint64(r.guest.VMID), Kind: pvecontract.GuestKind(r.guest.Kind), Node: r.guest.Node,
		Status: st, Generation: 1,
		Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
		Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("not read"),
		Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
		Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
		Backups:    pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("not read"),
	}
}

// pveGuestValid validates one guest detail with the pvecontract rules.
func pveGuestValid(remoteID string, at time.Time, g pvecontract.GuestObservation) bool {
	return pveReadValid(remoteID, at, func(o *pvecontract.Observation) {
		o.Guests = pvecontract.AvailableDataset([]pvecontract.GuestObservation{g})
	})
}

func readPveGuestConfig(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, vmid uint64, at time.Time) *pb.PVEGuestConfig {
	unavailable := func(reason string) *pb.PVEGuestConfig {
		return &pb.PVEGuestConfig{State: pveUnavailable, Reason: reason, Vmid: vmid}
	}
	c, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return unavailable(pveReasonRead)
	}
	ref, reason := resolvePveGuest(ctx, c, vmid)
	if reason != "" {
		return unavailable(reason)
	}
	read := c.GetQemuConfig
	if ref.guest.Kind == pveapi.KindLxc {
		read = c.GetLxcConfig
	}
	raw, err := read(ctx, ref.guest.Node, ref.guest.VMID)
	if err != nil {
		return unavailable(pveReasonRead)
	}
	if raw.Truncated {
		return unavailable(pveReasonTruncated)
	}
	cfg := pveGuestConfig(raw)
	if len(raw.HostPCI) > 0 {
		cfg.HostPCI = pveHostPCI(ctx, base, hc, token, ref.guest.Node, raw.HostPCI)
	}
	g := ref.observation()
	g.Config = pvecontract.AvailableDataset(cfg)
	if !pveGuestValid(remoteID, at, g) {
		return unavailable(pveReasonInvalid)
	}
	out := &pb.PVEGuestConfig{State: pveAvailable, Vmid: vmid, CpuCount: cfg.CPUCount, RamBytes: cfg.RAMBytes,
		BootOrder: cfg.BootOrder, Tags: cfg.Tags, Pool: cfg.Pool,
		Capabilities: &pb.PVEGuestCapabilities{Snapshots: string(cfg.Capabilities.Snapshots),
			LiveMigration: string(cfg.Capabilities.LiveMigration), RamSnapshots: string(cfg.Capabilities.RAMSnapshots)}}
	for _, d := range cfg.Disks {
		out.Disks = append(out.Disks, &pb.PVEDisk{Storage: d.Storage, Volume: d.Volume, Format: d.Format, SizeBytes: d.SizeBytes})
	}
	if ip := cfg.CloudInitIP; ip != nil {
		out.CloudInitIp = &pb.PVECloudInitIP{Ip: ip.IP, Gateway: ip.Gateway, Nameservers: ip.Nameservers}
	}
	for _, h := range cfg.HostPCI {
		out.Hostpci = append(out.Hostpci, &pb.PVEHostPCI{Id: h.ID, Device: h.Device, Target: h.Target})
	}
	return out
}

// pveHostPCI resolves the guest's passthrough entries against the node's
// PCI device list (GET /nodes/{node}/hardware/pci) into the contract's
// device identity "PCI-vendor:device:bus:slot.fn" with the host address as
// target. The list is all or nothing: if any entry names no single exact
// function (all functions, a device list, a resource mapping) or is not in
// the node's list, or the list cannot be read, no entry is reported, so a
// partial device list never looks complete. Passthrough itself stays
// visible through the capabilities (live migration and RAM snapshots "no").
func pveHostPCI(ctx context.Context, base string, hc *http.Client, token pveapi.TokenSupplier, node string, entries []pveapi.HostPCI) []pvecontract.HostPCI {
	none := []pvecontract.HostPCI{}
	if len(entries) > pvecontract.MaxPCIDevicesPerGuest {
		return none
	}
	c := &pveapi.Client{HTTP: hc, BaseURL: base + "/api2/json", Token: token, Timeout: pveReadRequestTimeout}
	list, err := c.NodePCIDevices(ctx, node)
	if err != nil || !list.Available {
		return none
	}
	byAddr := make(map[string]pveapi.PCIDevice, len(list.Devices))
	for _, d := range list.Devices {
		byAddr[d.Address] = d
	}
	out := make([]pvecontract.HostPCI, 0, len(entries))
	for _, e := range entries {
		addr, ok := pveapi.NormalizePCIAddress(e.PCIAddress)
		d, found := byAddr[addr]
		if !ok || !found || e.Mapping != "" {
			return none
		}
		out = append(out, pvecontract.HostPCI{ID: e.Device, Device: "PCI-" + d.Vendor + ":" + d.Device + ":" + addr[5:], Target: addr})
	}
	return out
}

// pveVolumeFormats are the image formats a volume name's extension names.
var pveVolumeFormats = map[string]bool{"raw": true, "qcow2": true, "vmdk": true, "iso": true}

// pveGuestConfig maps a sanitized PVE config onto the contract. Disks that
// reference no storage volume (empty CD drives, physical pass-through
// paths, bind mounts) are omitted; a volume attached twice is listed once.
// A volume without an explicit format takes it from its file extension,
// "subvol" for container subvolumes, and otherwise "raw" (block storages
// keep raw images without an extension). PCI passthrough sets the
// capabilities here; the device list needs the node's PCI identity
// (vendor:device), which pveHostPCI resolves separately.
func pveGuestConfig(raw *pveapi.GuestConfig) pvecontract.GuestConfig {
	cfg := pvecontract.GuestConfig{
		CPUCount: uint32(min(max(raw.CPUs, 0), pvecontract.MaxCPUCores+1)),
		RAMBytes: uint64(max(raw.Memory, 0)),
		Disks:    []pvecontract.Disk{}, BootOrder: []string{}, HostPCI: []pvecontract.HostPCI{},
		Tags: []string{}, Pool: raw.Pool,
		Capabilities: pvecontract.GuestCapabilities{
			Snapshots: pvecontract.Unknown, LiveMigration: pvecontract.Unknown, RAMSnapshots: pvecontract.Unknown,
		},
	}
	seen := map[string]bool{}
	add := func(volume, format string, size int64) {
		i := strings.LastIndex(volume, ":")
		if i <= 0 || seen[volume] {
			return
		}
		seen[volume] = true
		if format == "" {
			name := path.Base(volume[i+1:])
			switch ext := strings.TrimPrefix(path.Ext(name), "."); {
			case pveVolumeFormats[ext]:
				format = ext
			case strings.HasPrefix(name, "subvol-"):
				format = "subvol"
			default:
				format = "raw"
			}
		}
		cfg.Disks = append(cfg.Disks, pvecontract.Disk{Storage: volume[:i], Volume: volume, Format: format, SizeBytes: uint64(max(size, 0))})
	}
	for _, d := range raw.Disks {
		add(d.Volume, d.Format, d.Size)
	}
	for _, m := range raw.Mounts {
		add(m.Volume, "", m.Size)
	}
	if order, ok := strings.CutPrefix(raw.Boot, "order="); ok {
		for _, dev := range strings.Split(order, ";") {
			if dev != "" {
				cfg.BootOrder = append(cfg.BootOrder, dev)
			}
		}
	}
	tags := map[string]bool{}
	for _, field := range raw.Tags {
		// PVE separates tags with ';' (older releases also ',' or ' ').
		for _, t := range strings.FieldsFunc(field, func(r rune) bool { return r == ';' || r == ',' || r == ' ' }) {
			t = strings.ToLower(t)
			if !tags[t] {
				tags[t] = true
				cfg.Tags = append(cfg.Tags, t)
			}
		}
	}
	if len(raw.CloudInitIP) > 0 {
		cfg.CloudInitIP = pveCloudInitIP(raw.CloudInitIP[0])
	}
	if len(raw.HostPCI) > 0 {
		cfg.Capabilities.LiveMigration = pvecontract.No
		cfg.Capabilities.RAMSnapshots = pvecontract.No
	}
	return cfg
}

// pveCloudInitIP maps the first ipconfig entry ("ip=…,gw=…") onto the
// contract. Entries without an IPv4 setting are omitted.
func pveCloudInitIP(v string) *pvecontract.CloudInitIP {
	var out pvecontract.CloudInitIP
	for _, part := range strings.Split(v, ",") {
		k, val, _ := strings.Cut(part, "=")
		switch k {
		case "ip":
			out.IP = val
		case "gw":
			out.Gateway = val
		}
	}
	if out.IP == "" {
		return nil
	}
	return &out
}

func readPveGuestAgent(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, vmid uint64, at time.Time) *pb.PVEGuestAgent {
	unavailable := func(reason string) *pb.PVEGuestAgent {
		return &pb.PVEGuestAgent{State: pveUnavailable, Reason: reason, Vmid: vmid}
	}
	c, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return unavailable(pveReasonRead)
	}
	ref, reason := resolvePveGuest(ctx, c, vmid)
	if reason != "" {
		return unavailable(reason)
	}
	if ref.guest.Kind != pveapi.KindQemu {
		return unavailable(pveReasonAgentQEMUOnly)
	}
	osinfo, err := c.AgentOSInfo(ctx, ref.guest.Node, ref.guest.VMID)
	if err != nil {
		return unavailable(pveReasonRead)
	}
	if !osinfo.Available {
		return unavailable(pveReasonAgentDown)
	}
	fsinfo, err := c.AgentFSInfo(ctx, ref.guest.Node, ref.guest.VMID)
	if err != nil {
		return unavailable(pveReasonRead)
	}
	if !fsinfo.Available {
		return unavailable(pveReasonAgentDown)
	}
	agent := pvecontract.GuestAgent{OS: strings.TrimSpace(osinfo.Name + " " + osinfo.Version), Filesystems: []pvecontract.Filesystem{}}
	for _, fs := range fsinfo.Filesystems {
		if fs.Size < 0 || fs.Used < 0 {
			return unavailable(pveReasonInvalid)
		}
		agent.Filesystems = append(agent.Filesystems, pvecontract.Filesystem{
			MountPoint: fs.Mountpoint, FSType: strings.ToLower(fs.Type), SizeBytes: uint64(fs.Size), UsedBytes: uint64(fs.Used),
		})
	}
	g := ref.observation()
	g.Agent = pvecontract.AvailableDataset(agent)
	if !pveGuestValid(remoteID, at, g) {
		return unavailable(pveReasonInvalid)
	}
	out := &pb.PVEGuestAgent{State: pveAvailable, Vmid: vmid, Hostname: agent.Hostname, Os: agent.OS}
	for _, fs := range agent.Filesystems {
		out.Filesystems = append(out.Filesystems, &pb.PVEFilesystem{MountPoint: fs.MountPoint, Fstype: fs.FSType,
			SizeBytes: fs.SizeBytes, UsedBytes: fs.UsedBytes})
	}
	return out
}

func readPveSnapshots(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, vmid uint64, at time.Time) *pb.PVESnapshots {
	unavailable := func(reason string) *pb.PVESnapshots {
		return &pb.PVESnapshots{State: pveUnavailable, Reason: reason, Vmid: vmid}
	}
	inv, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return unavailable(pveReasonRead)
	}
	ref, reason := resolvePveGuest(ctx, inv, vmid)
	if reason != "" {
		return unavailable(reason)
	}
	c, err := pveapi.NewClient(hc, base+"/api2/json", token)
	if err != nil {
		return unavailable(pveReasonRead)
	}
	list, err := c.ListSnapshots(ctx, ref.guest.Node, string(ref.guest.Kind), int64(ref.guest.VMID))
	if err != nil {
		return unavailable(pveReasonRead)
	}
	if !list.Complete {
		return unavailable(pveReasonTruncated)
	}
	snaps := make([]pvecontract.Snapshot, 0, len(list.Snapshots))
	for _, s := range list.Snapshots {
		snaps = append(snaps, pvecontract.Snapshot{Name: s.Name, TimeUnix: s.SnapTimeUnix, Parent: s.Parent, HasRAM: s.HasVMState})
	}
	g := ref.observation()
	g.Snapshots = pvecontract.AvailableDataset(snaps)
	if !pveGuestValid(remoteID, at, g) {
		return unavailable(pveReasonInvalid)
	}
	out := &pb.PVESnapshots{State: pveAvailable, Vmid: vmid}
	for _, s := range snaps {
		out.Snapshots = append(out.Snapshots, &pb.PVESnapshot{Name: s.Name, TimeUnix: s.TimeUnix, Parent: s.Parent, HasRam: s.HasRAM})
	}
	return out
}

// readPveTasks reads the task metadata of the last pveTaskWindow from every
// online node, newest first per node, at most pveTasksPerNode per node and
// MaxObjectsPerPage in total; a node with more tasks in the window keeps
// its newest and sets PVETasks.truncated. It never reads task logs or
// status detail.
func readPveTasks(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, at time.Time) *pb.PVETasks {
	inv, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return &pb.PVETasks{State: pveUnavailable, Reason: pveReasonRead}
	}
	nodes, err := inv.ListNodes(ctx)
	if err != nil {
		return &pb.PVETasks{State: pveUnavailable, Reason: pveReasonRead}
	}
	var online []string
	for _, n := range nodes {
		if n.Status == "online" {
			online = append(online, n.Name)
		}
	}
	perNode := pveTasksPerNode
	if len(online) > 0 {
		perNode = max(1, min(perNode, pvecontract.MaxObjectsPerPage/len(online)))
	}
	c := &pveapi.Client{HTTP: hc, BaseURL: base + "/api2/json", Token: token, Timeout: pveReadRequestTimeout}
	obs := []pvecontract.TaskObservation{}
	truncated := false
	for _, node := range online {
		list, err := c.NodeTasks(ctx, node, pveapi.TaskFilter{Since: at.Add(-pveTaskWindow), Limit: perNode})
		if err != nil || !list.Available {
			return &pb.PVETasks{State: pveUnavailable, Reason: pveReasonPartial}
		}
		// A busy node keeps its newest tasks; the flag marks that the
		// window is not the node's complete task history.
		truncated = truncated || list.Truncated
		for _, t := range list.Tasks {
			obs = append(obs, pveTaskObservation(t))
		}
	}
	if !pveReadValid(remoteID, at, func(o *pvecontract.Observation) { o.Tasks = pvecontract.AvailableDataset(obs) }) {
		return &pb.PVETasks{State: pveUnavailable, Reason: pveReasonInvalid}
	}
	out := &pb.PVETasks{State: pveAvailable, Truncated: truncated}
	for _, t := range obs {
		out.Tasks = append(out.Tasks, &pb.PVETask{Node: t.Node, Actor: t.Actor, Type: t.Type, Target: t.Target,
			StartedUnix: t.StartedUnix, ExitStatus: t.ExitStatus})
	}
	return out
}

// pveTaskObservation maps one task summary. A task without a target (for
// example a node update) targets its node. A task with an end time but no
// "OK" result failed; a task without an end time has no exit status yet.
func pveTaskObservation(t pveapi.TaskSummary) pvecontract.TaskObservation {
	o := pvecontract.TaskObservation{Node: t.Node, Actor: t.User, Type: t.Type, Target: t.ID, StartedUnix: t.Start.Unix()}
	if o.Target == "" {
		o.Target = t.Node
	}
	switch {
	case t.End.IsZero():
	case t.Status == pveapi.TaskExitOK, strings.HasPrefix(t.Status, "WARNINGS:"):
		// PVE ends a task that completed with warnings as "WARNINGS: n".
		o.ExitStatus = "success"
	default:
		o.ExitStatus = "error"
	}
	return o
}
