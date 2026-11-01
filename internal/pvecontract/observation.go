// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Dataset sources.
const (
	// SourcePVEAPI is data read through the PVE API.
	SourcePVEAPI = "pve-api"
	// SourceQEMUAgent is data reported by the QEMU guest agent.
	SourceQEMUAgent = "qemu-agent"
	// SourceLXCAPI is data read from the LXC typed API.
	SourceLXCAPI = "lxc-api"
)

// Guest kinds.
type GuestKind string

// Guest kinds.
const (
	GuestQEMU GuestKind = "qemu"
	GuestLXC  GuestKind = "lxc"
)

// NodeStatus is the state of a PVE node.
type NodeStatus string

// Node states.
const (
	NodeOnline  NodeStatus = "online"
	NodeOffline NodeStatus = "offline"
)

// GuestStatus is the state of a guest.
type GuestStatus string

// Guest states.
const (
	GuestRunning GuestStatus = "running"
	GuestStopped GuestStatus = "stopped"
	GuestPaused  GuestStatus = "paused"
	GuestUnknown GuestStatus = "unknown"
)

// TriState is a yes/no/unknown hint.
type TriState string

// TriState values.
const (
	Yes     TriState = "yes"
	No      TriState = "no"
	Unknown TriState = "unknown"
)

// Backup evidence kinds and sources.
const (
	// BackupVZDump is vzdump task evidence.
	BackupVZDump = "vzdump"
	// BackupPBS is Proxmox Backup Server evidence.
	BackupPBS = "pbs"
	// BackupVeeam is Veeam evidence, unknown or unavailable when undetected.
	BackupVeeam = "veeam"

	// BackupKindTask is a recent backup task summary.
	BackupKindTask = "task"
	// BackupKindCatalog is a detectable backup catalog entry.
	BackupKindCatalog = "catalog"
)

// Availability is the state of one dataset in an observation.
type Availability string

// Dataset states.
const (
	// Available means the dataset was read. Value may be empty, which is a
	// complete enumeration that found nothing.
	Available Availability = "available"
	// Unavailable means the dataset could not be read; Reason is required.
	Unavailable Availability = "unavailable"
)

// Dataset distinguishes a present value (which may be empty) from an
// unavailable one. Missing data is never represented as zero or an empty
// value: an empty Value with State Available means "nothing found", while
// State Unavailable with a Reason means "could not be read".
type Dataset[T any] struct {
	State  Availability `json:"state"`
	Value  T            `json:"value"`
	Reason string       `json:"reason,omitempty"`
}

// AvailableDataset wraps a present value, which may be empty.
func AvailableDataset[T any](v T) Dataset[T] {
	return Dataset[T]{State: Available, Value: v}
}

// UnavailableDataset wraps a missing value with its reason.
func UnavailableDataset[T any](reason string) Dataset[T] {
	return Dataset[T]{State: Unavailable, Reason: reason}
}

// IsAvailable reports whether the dataset was read.
func (d Dataset[T]) IsAvailable() bool { return d.State == Available }

// MarshalJSON renders an available dataset with its value and an
// unavailable one with its reason only. It refuses to emit a
// structurally inconsistent dataset instead of silently dropping fields.
func (d Dataset[T]) MarshalJSON() ([]byte, error) {
	switch d.State {
	case Available:
		if d.Reason != "" {
			return nil, fmt.Errorf("available dataset must not carry a reason")
		}
		var env struct {
			State Availability `json:"state"`
			Value T            `json:"value"`
		}
		env.State = Available
		env.Value = d.Value
		return json.Marshal(env)
	case Unavailable:
		if d.Reason == "" {
			return nil, fmt.Errorf("unavailable dataset requires a reason")
		}
		if !reflect.ValueOf(d.Value).IsZero() {
			return nil, fmt.Errorf("unavailable dataset must not carry a value")
		}
		var env struct {
			State  Availability `json:"state"`
			Reason string       `json:"reason"`
		}
		env.State = Unavailable
		env.Reason = d.Reason
		return json.Marshal(env)
	default:
		return nil, fmt.Errorf("dataset state %q is unknown", d.State)
	}
}

// UnmarshalJSON decodes a dataset, rejecting unknown keys. Duplicate keys
// were already rejected by the document walk.
func (d *Dataset[T]) UnmarshalJSON(raw []byte) error {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return fmt.Errorf("dataset: %w", err)
	}
	for k := range keys {
		switch k {
		case "state", "value", "reason":
		default:
			return fmt.Errorf("dataset: unknown key %q", k)
		}
	}
	var state Availability
	if rawState, ok := keys["state"]; ok {
		if err := json.Unmarshal(rawState, &state); err != nil {
			return fmt.Errorf("dataset: state: %w", err)
		}
	}
	var reason string
	if rawReason, ok := keys["reason"]; ok {
		if err := json.Unmarshal(rawReason, &reason); err != nil {
			return fmt.Errorf("dataset: reason: %w", err)
		}
	}
	var value T
	rawValue, hasValue := keys["value"]
	if state == Available && (!hasValue || bytes.Equal(bytes.TrimSpace(rawValue), []byte("null"))) {
		return fmt.Errorf("dataset: available dataset requires a non-null value")
	}
	if hasValue {
		dec := json.NewDecoder(bytes.NewReader(rawValue))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&value); err != nil {
			return fmt.Errorf("dataset: value: %w", err)
		}
	}
	*d = Dataset[T]{State: state, Value: value, Reason: reason}
	return nil
}

// Observation is one validated page of normalized observations for one
// remote: the unit the collector writes to the spool and the server
// ingests. Raw task logs, command output, credentials and image or backup
// contents never appear in it.
type Observation struct {
	RemoteID             string    `json:"remote_id"`
	ObservedAt           time.Time `json:"observed_at"`
	Source               string    `json:"source"`
	CollectionGeneration uint64    `json:"collection_generation"`
	Complete             bool      `json:"complete"`
	Reason               string    `json:"reason,omitempty"`

	Nodes    Dataset[[]NodeObservation]    `json:"nodes"`
	Guests   Dataset[[]GuestObservation]   `json:"guests"`
	Storages Dataset[[]StorageObservation] `json:"storages"`
	Cluster  Dataset[ClusterObservation]   `json:"cluster"`
	Tasks    Dataset[[]TaskObservation]    `json:"tasks"`
}

// NodeObservation is one PVE node with its 60-second inventory values and
// the slower node-details dataset.
type NodeObservation struct {
	Node          string               `json:"node"`
	Status        NodeStatus           `json:"status"`
	UptimeSeconds uint64               `json:"uptime_seconds"`
	CPUCount      uint32               `json:"cpu_count"`
	RAMTotalBytes uint64               `json:"ram_total_bytes"`
	RAMUsedBytes  uint64               `json:"ram_used_bytes"`
	Details       Dataset[NodeDetails] `json:"details"`
}

// NodeDetails is the 15-minute node detail read.
type NodeDetails struct {
	PVEVersion    string `json:"pve_version"`
	KernelVersion string `json:"kernel_version"`
}

// GuestObservation is one QEMU or LXC guest of one remote. Identity is
// (remote_id, vmid); Generation is the local guest incarnation generation
// used for tombstones.
type GuestObservation struct {
	VMID       uint64                    `json:"vmid"`
	Kind       GuestKind                 `json:"kind"`
	Node       string                    `json:"node"`
	Name       string                    `json:"name"`
	Status     GuestStatus               `json:"status"`
	Generation uint64                    `json:"generation"`
	UUID       string                    `json:"uuid,omitempty"`
	Config     Dataset[GuestConfig]      `json:"config"`
	Interfaces Dataset[[]GuestInterface] `json:"interfaces"`
	Agent      Dataset[GuestAgent]       `json:"agent"`
	Snapshots  Dataset[[]Snapshot]       `json:"snapshots"`
	Backups    Dataset[[]BackupEvidence] `json:"backups"`
}

// GuestConfig is the 5-minute guest configuration read.
type GuestConfig struct {
	CPUCount     uint32            `json:"cpu_count"`
	RAMBytes     uint64            `json:"ram_bytes"`
	Disks        []Disk            `json:"disks"`
	BootOrder    []string          `json:"boot_order"`
	HostPCI      []HostPCI         `json:"hostpci"`
	CloudInitIP  *CloudInitIP      `json:"cloud_init_ip"`
	Tags         []string          `json:"tags"`
	Pool         string            `json:"pool"`
	Capabilities GuestCapabilities `json:"capabilities"`
}

// Disk is one storage reference of a guest.
type Disk struct {
	Storage   string `json:"storage"`
	Volume    string `json:"volume"`
	Format    string `json:"format"`
	SizeBytes uint64 `json:"size_bytes"`
}

// HostPCI is one hostpci device/target mapping.
type HostPCI struct {
	ID     string `json:"id"`
	Device string `json:"device"`
	Target string `json:"target,omitempty"`
}

// CloudInitIP is the nonsecret Cloud-Init IP configuration.
type CloudInitIP struct {
	IP          string   `json:"ip"`
	Gateway     string   `json:"gateway,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
}

// GuestCapabilities are yes/no/unknown hints computed from all attached
// disks, formats, storage support, passthrough and guest state. Phase 1
// treats passthrough guests as ineligible for live migration and RAM
// snapshots.
type GuestCapabilities struct {
	Snapshots     TriState `json:"snapshots"`
	LiveMigration TriState `json:"live_migration"`
	RAMSnapshots  TriState `json:"ram_snapshots"`
}

// GuestInterface is one guest network interface, labeled by the source that
// reported it.
type GuestInterface struct {
	Name   string   `json:"name"`
	MAC    string   `json:"mac"`
	Bridge string   `json:"bridge,omitempty"`
	VLAN   uint16   `json:"vlan"`
	IPs    []string `json:"ips"`
	Source string   `json:"source"`
}

// GuestAgent is the QEMU guest agent summary: hostname, OS and filesystem
// summary.
type GuestAgent struct {
	Hostname    string       `json:"hostname"`
	OS          string       `json:"os"`
	Filesystems []Filesystem `json:"filesystems"`
}

// Filesystem is one filesystem summary from the guest agent.
type Filesystem struct {
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fstype"`
	SizeBytes  uint64 `json:"size_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
}

// Snapshot is one guest snapshot. Parent references another snapshot in the
// same list, or is empty for a root snapshot.
type Snapshot struct {
	Name     string `json:"name"`
	TimeUnix int64  `json:"time_unix"`
	Parent   string `json:"parent,omitempty"`
	HasRAM   bool   `json:"has_ram"`
}

// BackupEvidence is one nonsecret backup observation: a recent task summary
// or a detectable catalog entry. Task success is evidence of a past run,
// never proof that a backup is currently present or restorable.
type BackupEvidence struct {
	Source       string   `json:"source"`
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	Name         string   `json:"name,omitempty"`
	StartedUnix  int64    `json:"started_unix"`
	FinishedUnix int64    `json:"finished_unix"`
	Verified     TriState `json:"verified"`
}

// StorageObservation is one PVE storage with its supported features.
type StorageObservation struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Format    string   `json:"format,omitempty"`
	Content   []string `json:"content"`
	Active    bool     `json:"active"`
	SizeBytes uint64   `json:"size_bytes"`
	FreeBytes uint64   `json:"free_bytes"`
	// Node is the node that reported this storage and its usage. Empty
	// only in observations from sources that predate per-node storage.
	Node string `json:"node,omitempty"`
	// Shared is PVE's authoritative shared flag: the same storage is
	// reported by every node that can use it and must be counted once.
	Shared bool `json:"shared,omitempty"`
}

// ClusterObservation is the 60-second cluster and HA read.
type ClusterObservation struct {
	Nodes       []ClusterNode `json:"nodes"`
	Quorum      string        `json:"quorum"`
	HAResources []HAResource  `json:"ha_resources"`
}

// ClusterNode is one cluster member.
type ClusterNode struct {
	Node        string     `json:"node"`
	Status      NodeStatus `json:"status"`
	Vote        bool       `json:"vote"`
	Maintenance bool       `json:"maintenance"`
}

// HAResource is one HA resource with its desired and observed state.
type HAResource struct {
	ID       string    `json:"id"`
	Kind     GuestKind `json:"kind"`
	VMID     uint64    `json:"vmid"`
	Desired  string    `json:"desired"`
	Observed string    `json:"observed"`
	Node     string    `json:"node,omitempty"`
}

// TaskObservation is bounded task metadata: actor, type, time, target and
// exit status. Never raw task logs or command output.
type TaskObservation struct {
	Node        string `json:"node"`
	Actor       string `json:"actor"`
	Type        string `json:"type"`
	Target      string `json:"target"`
	StartedUnix int64  `json:"started_unix"`
	ExitStatus  string `json:"exit_status,omitempty"`
}

var (
	slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	// volumeRe is a PVE volume ID: storage[:name], where the name may carry
	// one directory component (dir storages: "100/vm-100-disk-0.qcow2",
	// "iso/debian-12.iso") and keeps PVE's case. Components start with an
	// alphanumeric, so "." and ".." components cannot occur.
	volumeRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,254}(?::[A-Za-z0-9][A-Za-z0-9._+-]{0,254}(?:/[A-Za-z0-9][A-Za-z0-9._+-]{0,254})?)?$`)
	macRe            = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
	uuidRe           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	versionRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	pciDeviceRe      = regexp.MustCompile(`^PCI-[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$`)
	pciTargetRe      = regexp.MustCompile(`^(?:[0-9a-f]{4}:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$`)
	printableNoSpace = regexp.MustCompile(`^[\x21-\x7e]+$`)
	// snapshotNameRe is a PVE snapshot name, which keeps its case.
	snapshotNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	// poolIDRe is a PVE pool ID, which keeps its case; PVE 8.1+ nests
	// pools up to three levels ("dev/team1/ci").
	poolIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,63}){0,2}$`)
	// windowsMountRe is a Windows drive root or path as the guest agent
	// reports it ("C:\\", "D:\\data").
	windowsMountRe = regexp.MustCompile(`^[A-Za-z]:\\`)
)

// ValidNodeName reports whether s is a valid PVE node name (DNS host name).
func ValidNodeName(s string) bool { return validNodeName(s) }

// validNodeName reports whether s is a valid PVE node name (DNS host name).
func validNodeName(s string) bool {
	if s == "" || len(s) > MaxNodeNameBytes {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !dnsLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// validCIDR reports whether s is a valid CIDR address.
func validCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

var storageContent = map[string]struct{}{
	"images":    {},
	"iso":       {},
	"backup":    {},
	"vztmpl":    {},
	"snippets":  {},
	"container": {},
}

// checkDataset validates the state/reason/value consistency of one dataset.
func checkDataset[T any](name string, d Dataset[T], add func(format string, args ...any)) {
	switch d.State {
	case Available:
		if d.Reason != "" {
			add("%s: available dataset must not carry a reason", name)
		}
	case Unavailable:
		if d.Reason == "" {
			add("%s: unavailable dataset requires a reason", name)
		}
		if !reflect.ValueOf(d.Value).IsZero() {
			add("%s: unavailable dataset must not carry a value", name)
		}
	default:
		add("%s: state %q is unknown", name, d.State)
	}
}

// ValidateObservation validates o and returns a copy with the top-level
// record lists cloned. It never mutates o.
func ValidateObservation(o Observation) (Observation, error) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if !remoteIDRe.MatchString(o.RemoteID) {
		add("remote_id %q is malformed", o.RemoteID)
	}
	if o.ObservedAt.IsZero() {
		add("observed_at is required")
	}
	if !slugRe.MatchString(o.Source) {
		add("source %q is malformed", o.Source)
	}
	switch {
	case o.CollectionGeneration == 0:
		add("collection_generation must be at least 1")
	case o.CollectionGeneration > MaxCollectionGeneration:
		add("collection_generation out of range")
	}
	switch {
	case o.Complete && o.Reason != "":
		add("complete observation must not carry a reason")
	case !o.Complete && o.Reason == "":
		add("incomplete observation requires a reason")
	}

	checkDataset("nodes", o.Nodes, add)
	if o.Nodes.State == Available {
		if len(o.Nodes.Value) > MaxObjectsPerPage {
			add("too many nodes (%d > %d)", len(o.Nodes.Value), MaxObjectsPerPage)
		}
		seen := map[string]struct{}{}
		for i, nd := range o.Nodes.Value {
			validateNodeObservation(fmt.Sprintf("nodes[%d]", i), nd, seen, add)
		}
	}

	checkDataset("guests", o.Guests, add)
	if o.Guests.State == Available {
		if len(o.Guests.Value) > MaxObjectsPerPage {
			add("too many guests (%d > %d)", len(o.Guests.Value), MaxObjectsPerPage)
		}
		seenGuest := map[string]struct{}{}
		for i, g := range o.Guests.Value {
			validateGuestObservation(fmt.Sprintf("guests[%d]", i), g, add)
			k := g.Node + "/" + fmt.Sprint(g.VMID)
			if _, dup := seenGuest[k]; dup {
				add("guests[%d]: %s is duplicated", i, k)
			}
			seenGuest[k] = struct{}{}
		}
	}

	checkDataset("storages", o.Storages, add)
	if o.Storages.State == Available {
		if len(o.Storages.Value) > MaxStorageReportsPerRemote {
			add("too many storage reports (%d > %d)", len(o.Storages.Value), MaxStorageReportsPerRemote)
		}
		seen := map[string]struct{}{}
		// shared records each storage ID's shared flag: PVE derives it
		// from storage.cfg, so every node must report the same value.
		shared := map[string]bool{}
		for i, s := range o.Storages.Value {
			where := fmt.Sprintf("storages[%d]", i)
			validateStorageObservation(where, s, seen, add)
			if prev, ok := shared[s.Name]; ok && prev != s.Shared {
				add("%s: storage %q has an inconsistent shared flag", where, s.Name)
			}
			shared[s.Name] = s.Shared
		}
		if len(shared) > MaxStoragesPerRemote {
			add("too many storages (%d > %d)", len(shared), MaxStoragesPerRemote)
		}
	}

	checkDataset("cluster", o.Cluster, add)
	if o.Cluster.State == Available {
		validateClusterObservation("cluster.value", o.Cluster.Value, add)
	}

	checkDataset("tasks", o.Tasks, add)
	if o.Tasks.State == Available {
		if len(o.Tasks.Value) > MaxObjectsPerPage {
			add("too many tasks (%d > %d)", len(o.Tasks.Value), MaxObjectsPerPage)
		}
		for i, tk := range o.Tasks.Value {
			validateTaskObservation(fmt.Sprintf("tasks[%d]", i), tk, add)
		}
	}

	if len(p) > 0 {
		return Observation{}, &ValidationError{Problems: p}
	}
	n := o
	n.Nodes.Value = slices.Clone(o.Nodes.Value)
	n.Guests.Value = slices.Clone(o.Guests.Value)
	n.Storages.Value = slices.Clone(o.Storages.Value)
	n.Tasks.Value = slices.Clone(o.Tasks.Value)
	return n, nil
}

// DecodeObservation strictly decodes and validates one observation page.
func DecodeObservation(raw []byte) (Observation, error) {
	var o Observation
	if err := decodeStrict(raw, &o); err != nil {
		return Observation{}, err
	}
	return ValidateObservation(o)
}

// MarshalObservation validates o and returns its strict JSON encoding.
func MarshalObservation(o Observation) ([]byte, error) {
	v, err := ValidateObservation(o)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func validateNodeObservation(where string, nd NodeObservation, seen map[string]struct{}, add func(format string, args ...any)) {
	if !validNodeName(nd.Node) {
		add("%s: node %q is malformed", where, nd.Node)
	}
	if _, dup := seen[nd.Node]; dup {
		add("%s: node %q is duplicated", where, nd.Node)
	}
	seen[nd.Node] = struct{}{}
	switch nd.Status {
	case NodeOnline, NodeOffline:
	default:
		add("%s: status %q is unknown", where, nd.Status)
	}
	if nd.CPUCount == 0 || nd.CPUCount > MaxCPUCores {
		add("%s: cpu_count %d out of range", where, nd.CPUCount)
	}
	if nd.RAMUsedBytes > nd.RAMTotalBytes {
		add("%s: ram_used_bytes exceeds ram_total_bytes", where)
	}
	checkDataset(where+".details", nd.Details, add)
	if nd.Details.State == Available {
		if !versionRe.MatchString(nd.Details.Value.PVEVersion) {
			add("%s: pve_version %q is malformed", where, nd.Details.Value.PVEVersion)
		}
		if !versionRe.MatchString(nd.Details.Value.KernelVersion) {
			add("%s: kernel_version %q is malformed", where, nd.Details.Value.KernelVersion)
		}
	}
}

func validateGuestObservation(where string, g GuestObservation, add func(format string, args ...any)) {
	if g.VMID < MinVMID || g.VMID > MaxVMID {
		add("%s: vmid %d out of range %d..%d", where, g.VMID, MinVMID, MaxVMID)
	}
	switch g.Kind {
	case GuestQEMU, GuestLXC:
	default:
		add("%s: kind %q is unknown", where, g.Kind)
	}
	if !validNodeName(g.Node) {
		add("%s: node %q is malformed", where, g.Node)
	}
	if len(g.Name) > MaxLabelBytes {
		add("%s: name exceeds %d bytes", where, MaxLabelBytes)
	}
	switch g.Status {
	case GuestRunning, GuestStopped, GuestPaused, GuestUnknown:
	default:
		add("%s: status %q is unknown", where, g.Status)
	}
	switch {
	case g.Generation == 0:
		add("%s: generation must be at least 1", where)
	case g.Generation > MaxGuestGeneration:
		add("%s: generation out of range", where)
	}
	if g.UUID != "" && !uuidRe.MatchString(g.UUID) {
		add("%s: uuid %q is malformed", where, g.UUID)
	}

	checkDataset(where+".config", g.Config, add)
	if g.Config.State == Available {
		validateGuestConfig(where+".config.value", g.Config.Value, add)
	}

	checkDataset(where+".interfaces", g.Interfaces, add)
	if g.Interfaces.State == Available {
		if len(g.Interfaces.Value) > MaxInterfacesPerGuest {
			add("%s: too many interfaces (%d > %d)", where, len(g.Interfaces.Value), MaxInterfacesPerGuest)
		}
		seen := map[string]struct{}{}
		for i, itf := range g.Interfaces.Value {
			validateGuestInterface(fmt.Sprintf("%s.interfaces[%d]", where, i), itf, seen, add)
		}
	}

	checkDataset(where+".agent", g.Agent, add)
	if g.Agent.State == Available {
		validateGuestAgent(where+".agent.value", g.Agent.Value, add)
	}

	checkDataset(where+".snapshots", g.Snapshots, add)
	if g.Snapshots.State == Available {
		validateSnapshots(where+".snapshots.value", g.Snapshots.Value, add)
	}

	checkDataset(where+".backups", g.Backups, add)
	if g.Backups.State == Available {
		if len(g.Backups.Value) > MaxBackupsPerGuest {
			add("%s: too many backup records (%d > %d)", where, len(g.Backups.Value), MaxBackupsPerGuest)
		}
		for i, b := range g.Backups.Value {
			validateBackupEvidence(fmt.Sprintf("%s.backups[%d]", where, i), b, add)
		}
	}
}

func validateGuestConfig(where string, c GuestConfig, add func(format string, args ...any)) {
	if c.CPUCount == 0 || c.CPUCount > MaxCPUCores {
		add("%s: cpu_count %d out of range", where, c.CPUCount)
	}
	if len(c.Disks) > MaxDisksPerGuest {
		add("%s: too many disks (%d > %d)", where, len(c.Disks), MaxDisksPerGuest)
	}
	seenVol := map[string]struct{}{}
	for i, d := range c.Disks {
		if !slugRe.MatchString(d.Storage) {
			add("%s: disks[%d]: storage %q is malformed", where, i, d.Storage)
		}
		if len(d.Volume) > MaxVolumeBytes || !volumeRe.MatchString(d.Volume) {
			add("%s: disks[%d]: volume %q is malformed", where, i, d.Volume)
		}
		if _, dup := seenVol[d.Volume]; dup {
			add("%s: disks[%d]: volume %q is duplicated", where, i, d.Volume)
		}
		seenVol[d.Volume] = struct{}{}
		if !slugRe.MatchString(d.Format) {
			add("%s: disks[%d]: format %q is malformed", where, i, d.Format)
		}
	}
	if len(c.BootOrder) > MaxBootOrderEntries {
		add("%s: too many boot order entries (%d > %d)", where, len(c.BootOrder), MaxBootOrderEntries)
	}
	for i, b := range c.BootOrder {
		if !slugRe.MatchString(b) {
			add("%s: boot_order[%d] %q is malformed", where, i, b)
		}
	}
	if len(c.HostPCI) > MaxPCIDevicesPerGuest {
		add("%s: too many hostpci devices (%d > %d)", where, len(c.HostPCI), MaxPCIDevicesPerGuest)
	}
	for i, h := range c.HostPCI {
		if !slugRe.MatchString(h.ID) {
			add("%s: hostpci[%d]: id %q is malformed", where, i, h.ID)
		}
		if !pciDeviceRe.MatchString(h.Device) {
			add("%s: hostpci[%d]: device %q is malformed", where, i, h.Device)
		}
		if h.Target != "" && !pciTargetRe.MatchString(h.Target) {
			add("%s: hostpci[%d]: target %q is malformed", where, i, h.Target)
		}
	}
	if c.CloudInitIP != nil {
		validateCloudInitIP(where+".cloud_init_ip", *c.CloudInitIP, add)
	}
	if len(c.Tags) > MaxTagsPerGuest {
		add("%s: too many tags (%d > %d)", where, len(c.Tags), MaxTagsPerGuest)
	}
	seenTag := map[string]struct{}{}
	for i, t := range c.Tags {
		if !slugRe.MatchString(t) {
			add("%s: tags[%d] %q is malformed", where, i, t)
		}
		if _, dup := seenTag[t]; dup {
			add("%s: tags[%d] %q is duplicated", where, i, t)
		}
		seenTag[t] = struct{}{}
	}
	if c.Pool != "" && !poolIDRe.MatchString(c.Pool) {
		add("%s: pool %q is malformed", where, c.Pool)
	}
	validateCapabilities(where+".capabilities", c.Capabilities, add)
}

func validateCloudInitIP(where string, c CloudInitIP, add func(format string, args ...any)) {
	if c.IP != "dhcp" && !validCIDR(c.IP) {
		add("%s: ip %q must be \"dhcp\" or a CIDR", where, c.IP)
	}
	if c.Gateway != "" && net.ParseIP(c.Gateway) == nil {
		add("%s: gateway %q is not an IP address", where, c.Gateway)
	}
	if len(c.Nameservers) > MaxNameservers {
		add("%s: too many nameservers (%d > %d)", where, len(c.Nameservers), MaxNameservers)
	}
	for i, ns := range c.Nameservers {
		if net.ParseIP(ns) == nil {
			add("%s: nameservers[%d] %q is not an IP address", where, i, ns)
		}
	}
}

func validateCapabilities(where string, c GuestCapabilities, add func(format string, args ...any)) {
	for name, v := range map[string]TriState{
		"snapshots":      c.Snapshots,
		"live_migration": c.LiveMigration,
		"ram_snapshots":  c.RAMSnapshots,
	} {
		switch v {
		case Yes, No, Unknown:
		default:
			add("%s: %s %q is unknown", where, name, v)
		}
	}
}

func validateGuestInterface(where string, itf GuestInterface, seen map[string]struct{}, add func(format string, args ...any)) {
	if !slugRe.MatchString(itf.Name) {
		add("%s: name %q is malformed", where, itf.Name)
	}
	if _, dup := seen[itf.Name]; dup {
		add("%s: name %q is duplicated", where, itf.Name)
	}
	seen[itf.Name] = struct{}{}
	if !macRe.MatchString(itf.MAC) {
		add("%s: mac %q is malformed", where, itf.MAC)
	}
	if itf.Bridge != "" && !slugRe.MatchString(itf.Bridge) {
		add("%s: bridge %q is malformed", where, itf.Bridge)
	}
	if itf.VLAN > MaxVLAN {
		add("%s: vlan %d out of range", where, itf.VLAN)
	}
	if len(itf.IPs) > MaxIPsPerInterface {
		add("%s: too many ips (%d > %d)", where, len(itf.IPs), MaxIPsPerInterface)
	}
	for i, ip := range itf.IPs {
		if ip != "dhcp" && !validCIDR(ip) {
			add("%s: ips[%d] %q must be \"dhcp\" or a CIDR", where, i, ip)
		}
	}
	switch itf.Source {
	case SourceQEMUAgent, SourceLXCAPI:
	default:
		add("%s: source %q is unknown", where, itf.Source)
	}
}

func validateGuestAgent(where string, a GuestAgent, add func(format string, args ...any)) {
	if a.Hostname != "" && !validEndpointHost(a.Hostname) {
		add("%s: hostname %q is malformed", where, a.Hostname)
	}
	if len(a.OS) > MaxLabelBytes {
		add("%s: os exceeds %d bytes", where, MaxLabelBytes)
	}
	if len(a.Filesystems) > MaxFilesystemsPerGuest {
		add("%s: too many filesystems (%d > %d)", where, len(a.Filesystems), MaxFilesystemsPerGuest)
	}
	for i, fs := range a.Filesystems {
		if !(strings.HasPrefix(fs.MountPoint, "/") || windowsMountRe.MatchString(fs.MountPoint)) || len(fs.MountPoint) > MaxLabelBytes {
			add("%s: filesystems[%d]: mount_point %q is malformed", where, i, fs.MountPoint)
		}
		if !slugRe.MatchString(fs.FSType) {
			add("%s: filesystems[%d]: fstype %q is malformed", where, i, fs.FSType)
		}
		if fs.UsedBytes > fs.SizeBytes {
			add("%s: filesystems[%d]: used_bytes exceeds size_bytes", where, i)
		}
	}
}

func validateSnapshots(where string, ss []Snapshot, add func(format string, args ...any)) {
	if len(ss) > MaxSnapshotsPerGuest {
		add("%s: too many snapshots (%d > %d)", where, len(ss), MaxSnapshotsPerGuest)
	}
	names := map[string]struct{}{}
	for i, s := range ss {
		if !snapshotNameRe.MatchString(s.Name) {
			add("%s[%d]: name %q is malformed", where, i, s.Name)
		}
		names[s.Name] = struct{}{}
	}
	for i, s := range ss {
		if s.TimeUnix < 0 {
			add("%s[%d]: time_unix must not be negative", where, i)
		}
		if s.Parent != "" {
			if _, ok := names[s.Parent]; !ok {
				add("%s[%d]: parent %q is not a snapshot in this list", where, i, s.Parent)
			}
		}
	}
}

func validateBackupEvidence(where string, b BackupEvidence, add func(format string, args ...any)) {
	switch b.Source {
	case BackupVZDump, BackupPBS, BackupVeeam:
	default:
		add("%s: source %q is unknown", where, b.Source)
	}
	switch b.Kind {
	case BackupKindTask, BackupKindCatalog:
	default:
		add("%s: kind %q is unknown", where, b.Kind)
	}
	switch b.Kind {
	case BackupKindTask:
		switch b.Status {
		case "success", "failed", "running", "unknown":
		default:
			add("%s: task status %q is unknown", where, b.Status)
		}
	case BackupKindCatalog:
		switch b.Status {
		case "present", "unknown":
		default:
			add("%s: catalog status %q is unknown", where, b.Status)
		}
	}
	if len(b.Name) > MaxLabelBytes {
		add("%s: name exceeds %d bytes", where, MaxLabelBytes)
	}
	if b.StartedUnix < 0 || b.FinishedUnix < 0 {
		add("%s: timestamps must not be negative", where)
	}
	if b.StartedUnix > 0 && b.FinishedUnix > 0 && b.FinishedUnix < b.StartedUnix {
		add("%s: finished before started", where)
	}
	switch b.Verified {
	case Yes, No, Unknown:
	default:
		add("%s: verified %q is unknown", where, b.Verified)
	}
}

func validateStorageObservation(where string, s StorageObservation, seen map[string]struct{}, add func(format string, args ...any)) {
	if !slugRe.MatchString(s.Name) {
		add("%s: name %q is malformed", where, s.Name)
	}
	if s.Node != "" && !validNodeName(s.Node) {
		add("%s: node %q is malformed", where, s.Node)
	}
	key := s.Node + "/" + s.Name
	if _, dup := seen[key]; dup {
		add("%s: storage %q on node %q is duplicated", where, s.Name, s.Node)
	}
	seen[key] = struct{}{}
	if !slugRe.MatchString(s.Type) {
		add("%s: type %q is malformed", where, s.Type)
	}
	if s.Format != "" && !slugRe.MatchString(s.Format) {
		add("%s: format %q is malformed", where, s.Format)
	}
	if len(s.Content) > MaxContentFeatures {
		add("%s: too many content features (%d > %d)", where, len(s.Content), MaxContentFeatures)
	}
	seenC := map[string]struct{}{}
	for i, c := range s.Content {
		if _, ok := storageContent[c]; !ok {
			add("%s: content[%d] %q is unknown", where, i, c)
		}
		if _, dup := seenC[c]; dup {
			add("%s: content[%d] %q is duplicated", where, i, c)
		}
		seenC[c] = struct{}{}
	}
}

func validateClusterObservation(where string, c ClusterObservation, add func(format string, args ...any)) {
	if len(c.Nodes) > MaxObjectsPerPage {
		add("%s: too many nodes (%d > %d)", where, len(c.Nodes), MaxObjectsPerPage)
	}
	seen := map[string]struct{}{}
	for i, n := range c.Nodes {
		if !validNodeName(n.Node) {
			add("%s: nodes[%d]: node %q is malformed", where, i, n.Node)
		}
		if _, dup := seen[n.Node]; dup {
			add("%s: nodes[%d]: node %q is duplicated", where, i, n.Node)
		}
		seen[n.Node] = struct{}{}
		switch n.Status {
		case NodeOnline, NodeOffline:
		default:
			add("%s: nodes[%d]: status %q is unknown", where, i, n.Status)
		}
	}
	switch c.Quorum {
	case "quorate", "not-quorate", "unknown":
	default:
		add("%s: quorum %q is unknown", where, c.Quorum)
	}
	if len(c.HAResources) > MaxObjectsPerPage {
		add("%s: too many HA resources (%d > %d)", where, len(c.HAResources), MaxObjectsPerPage)
	}
	seenHA := map[string]struct{}{}
	for i, h := range c.HAResources {
		if !slugRe.MatchString(h.ID) {
			add("%s: ha_resources[%d]: id %q is malformed", where, i, h.ID)
		}
		if _, dup := seenHA[h.ID]; dup {
			add("%s: ha_resources[%d]: id %q is duplicated", where, i, h.ID)
		}
		seenHA[h.ID] = struct{}{}
		switch h.Kind {
		case GuestQEMU, GuestLXC:
		default:
			add("%s: ha_resources[%d]: kind %q is unknown", where, i, h.Kind)
		}
		if h.VMID < MinVMID || h.VMID > MaxVMID {
			add("%s: ha_resources[%d]: vmid %d out of range", where, i, h.VMID)
		}
		for name, v := range map[string]string{"desired": h.Desired, "observed": h.Observed} {
			switch v {
			case "started", "stopped", "migrating", "unknown":
			default:
				add("%s: ha_resources[%d]: %s %q is unknown", where, i, name, v)
			}
		}
		if h.Node != "" && !validNodeName(h.Node) {
			add("%s: ha_resources[%d]: node %q is malformed", where, i, h.Node)
		}
	}
}

func validateTaskObservation(where string, t TaskObservation, add func(format string, args ...any)) {
	if !validNodeName(t.Node) {
		add("%s: node %q is malformed", where, t.Node)
	}
	if !printableNoSpace.MatchString(t.Actor) || len(t.Actor) > MaxRefBytes {
		add("%s: actor %q is malformed", where, t.Actor)
	}
	if !slugRe.MatchString(t.Type) {
		add("%s: type %q is malformed", where, t.Type)
	}
	if !printableNoSpace.MatchString(t.Target) || len(t.Target) > MaxLabelBytes {
		add("%s: target %q is malformed", where, t.Target)
	}
	if t.StartedUnix < 0 {
		add("%s: started_unix must not be negative", where)
	}
	switch t.ExitStatus {
	case "", "success", "error", "unknown":
	default:
		add("%s: exit_status %q is unknown", where, t.ExitStatus)
	}
}
