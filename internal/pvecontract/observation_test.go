// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// baseObservation returns a valid, complete observation with every dataset
// available and populated.
func baseObservation() Observation {
	return Observation{
		RemoteID:             "poxmox",
		ObservedAt:           time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		Source:               "collector-1",
		CollectionGeneration: 7,
		Complete:             true,
		Nodes: AvailableDataset([]NodeObservation{{
			Node:          "poxmox",
			Status:        NodeOnline,
			UptimeSeconds: 123456,
			CPUCount:      16,
			RAMTotalBytes: 64 << 30,
			RAMUsedBytes:  32 << 30,
			Details: AvailableDataset(NodeDetails{
				PVEVersion:    "9.0.1",
				KernelVersion: "6.8.0-147-generic",
			}),
		}}),
		Guests: AvailableDataset([]GuestObservation{{
			VMID:       101,
			Kind:       GuestQEMU,
			Node:       "poxmox",
			Name:       "web-1",
			Status:     GuestRunning,
			Generation: 3,
			UUID:       "123e4567-e89b-12d3-a456-426614174000",
			Config: AvailableDataset(GuestConfig{
				CPUCount: 4,
				RAMBytes: 8 << 30,
				Disks: []Disk{{
					Storage:   "local-lvm",
					Volume:    "local-lvm:vm-101-disk-0",
					Format:    "raw",
					SizeBytes: 100 << 30,
				}},
				BootOrder: []string{"scsi0", "net0"},
				HostPCI: []HostPCI{{
					ID:     "0",
					Device: "PCI-10de:2204:00:00.0",
					Target: "0000:01:00.0",
				}},
				CloudInitIP: &CloudInitIP{
					IP:          "10.77.10.101/24",
					Gateway:     "10.77.10.1",
					Nameservers: []string{"10.77.10.1"},
				},
				Tags:         []string{"web", "prod"},
				Pool:         "web",
				Capabilities: GuestCapabilities{Snapshots: Yes, LiveMigration: No, RAMSnapshots: No},
			}),
			Interfaces: AvailableDataset([]GuestInterface{{
				Name:   "net0",
				MAC:    "02:00:00:11:22:33",
				Bridge: "vmbr0",
				VLAN:   0,
				IPs:    []string{"10.77.10.101/24"},
				Source: SourceQEMUAgent,
			}}),
			Agent: AvailableDataset(GuestAgent{
				Hostname: "web-1",
				OS:       "Debian 13",
				Filesystems: []Filesystem{{
					MountPoint: "/",
					FSType:     "ext4",
					SizeBytes:  50 << 30,
					UsedBytes:  20 << 30,
				}},
			}),
			Snapshots: AvailableDataset([]Snapshot{{
				Name:     "before-upgrade",
				TimeUnix: 1761734400,
			}}),
			Backups: AvailableDataset([]BackupEvidence{{
				Source:       BackupPBS,
				Kind:         BackupKindTask,
				Status:       "success",
				Name:         "101-2026-10-28",
				StartedUnix:  1761648000,
				FinishedUnix: 1761648600,
				Verified:     Unknown,
			}}),
		}}),
		Storages: AvailableDataset([]StorageObservation{{
			Name:      "local-lvm",
			Type:      "lvmthin",
			Format:    "raw",
			Content:   []string{"images", "backup"},
			Active:    true,
			SizeBytes: 500 << 30,
			FreeBytes: 200 << 30,
		}}),
		Cluster: AvailableDataset(ClusterObservation{
			Nodes: []ClusterNode{{
				Node:        "poxmox",
				Status:      NodeOnline,
				Vote:        true,
				Maintenance: false,
			}},
			Quorum: "quorate",
			HAResources: []HAResource{{
				ID:       "web-1",
				Kind:     GuestQEMU,
				VMID:     101,
				Desired:  "started",
				Observed: "started",
				Node:     "poxmox",
			}},
		}),
		Tasks: AvailableDataset([]TaskObservation{{
			Node:        "poxmox",
			Actor:       "root@pam",
			Type:        "vzdump",
			Target:      "101",
			StartedUnix: 1761648000,
			ExitStatus:  "success",
		}}),
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeObservation(t *testing.T) {
	structCases := []struct {
		name    string
		mutate  func(*Observation)
		wantErr string
	}{
		{"valid base", func(o *Observation) {}, ""},
		{"valid lxc guest", func(o *Observation) {
			g := &o.Guests.Value[0]
			g.Kind = GuestLXC
			g.UUID = ""
			g.Config.Value.HostPCI = nil
			g.Interfaces.Value[0].Source = SourceLXCAPI
			g.Agent = UnavailableDataset[GuestAgent]("lxc has no qemu agent")
		}, ""},
		{"valid all datasets unavailable", func(o *Observation) {
			o.Nodes = UnavailableDataset[[]NodeObservation]("api timeout")
			o.Guests = UnavailableDataset[[]GuestObservation]("api timeout")
			o.Storages = UnavailableDataset[[]StorageObservation]("api timeout")
			o.Cluster = UnavailableDataset[ClusterObservation]("standalone remote")
			o.Tasks = UnavailableDataset[[]TaskObservation]("api timeout")
		}, ""},
		{"valid same storage on several nodes", func(o *Observation) {
			mk := func(node, name string, shared bool) StorageObservation {
				return StorageObservation{Name: name, Node: node, Type: "dir", Content: []string{"images"}, Active: true, Shared: shared}
			}
			o.Storages = AvailableDataset([]StorageObservation{
				mk("pve1", "local", false), mk("pve2", "local", false),
				mk("pve1", "nfs", true), mk("pve2", "nfs", true), mk("pve3", "nfs", true),
			})
		}, ""},
		{"valid empty available lists", func(o *Observation) {
			o.Nodes = AvailableDataset([]NodeObservation{})
			o.Guests = AvailableDataset([]GuestObservation{})
			o.Storages = AvailableDataset([]StorageObservation{})
			o.Tasks = AvailableDataset([]TaskObservation{})
		}, ""},
		{"valid incomplete with reason", func(o *Observation) {
			o.Complete = false
			o.Reason = "guest enumeration incomplete"
		}, ""},
		{"malformed remote_id", func(o *Observation) { o.RemoteID = "Poxmox" }, "remote_id"},
		{"remote_id with underscore", func(o *Observation) { o.RemoteID = "pox_mox" }, "remote_id"},
		{"malformed source", func(o *Observation) { o.Source = "collector 1" }, "source"},
		{"collection_generation zero", func(o *Observation) { o.CollectionGeneration = 0 }, "collection_generation"},
		{"collection_generation too large", func(o *Observation) { o.CollectionGeneration = MaxCollectionGeneration + 1 }, "collection_generation"},
		{"complete with reason", func(o *Observation) { o.Reason = "x" }, "must not carry a reason"},
		{"incomplete without reason", func(o *Observation) { o.Complete = false }, "requires a reason"},
		{"guest vmid below range", func(o *Observation) { o.Guests.Value[0].VMID = 99 }, "vmid"},
		{"guest vmid above range", func(o *Observation) { o.Guests.Value[0].VMID = MaxVMID + 1 }, "vmid"},
		{"guest kind unknown", func(o *Observation) { o.Guests.Value[0].Kind = "vm" }, "kind"},
		{"guest node malformed", func(o *Observation) { o.Guests.Value[0].Node = "Poxmox" }, "node"},
		{"guest name oversize", func(o *Observation) { o.Guests.Value[0].Name = strings.Repeat("a", MaxLabelBytes+1) }, "name exceeds"},
		{"guest status unknown", func(o *Observation) { o.Guests.Value[0].Status = "hosed" }, "status"},
		{"guest generation zero", func(o *Observation) { o.Guests.Value[0].Generation = 0 }, "generation"},
		{"guest uuid malformed", func(o *Observation) { o.Guests.Value[0].UUID = "not-a-uuid" }, "uuid"},
		{"config cpu_count zero", func(o *Observation) { o.Guests.Value[0].Config.Value.CPUCount = 0 }, "cpu_count"},
		{"disk volume malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.Disks[0].Volume = "LOCAL-LVM:vm" }, "volume"},
		{"disk volume parent component", func(o *Observation) { o.Guests.Value[0].Config.Value.Disks[0].Volume = "local:../etc/shadow" }, "volume"},
		{"disk volume two components", func(o *Observation) { o.Guests.Value[0].Config.Value.Disks[0].Volume = "local:iso/a/b.iso" }, "volume"},
		{"disk volume absolute", func(o *Observation) { o.Guests.Value[0].Config.Value.Disks[0].Volume = "local:/etc/shadow" }, "volume"},
		{"disk volume dot component", func(o *Observation) { o.Guests.Value[0].Config.Value.Disks[0].Volume = "local:iso/.hidden" }, "volume"},
		{"disk volume oversize", func(o *Observation) {
			o.Guests.Value[0].Config.Value.Disks[0].Volume = "local:" + strings.Repeat("a", 200) + "/" + strings.Repeat("b", 60)
		}, "volume"},
		{"disk volume duplicated", func(o *Observation) {
			o.Guests.Value[0].Config.Value.Disks = append(o.Guests.Value[0].Config.Value.Disks, o.Guests.Value[0].Config.Value.Disks[0])
		}, "duplicated"},
		{"boot order malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.BootOrder[0] = "scsi 0" }, "boot_order"},
		{"hostpci device malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.HostPCI[0].Device = "PCI-10de:22:00.0" }, "device"},
		{"hostpci target malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.HostPCI[0].Target = "01:00.00" }, "target"},
		{"cloud init ip malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.CloudInitIP.IP = "10.77.10.101" }, "dhcp"},
		{"cloud init gateway malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.CloudInitIP.Gateway = "gateway" }, "gateway"},
		{"nameserver malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.CloudInitIP.Nameservers[0] = "ns1" }, "nameservers"},
		{"tag duplicated", func(o *Observation) {
			o.Guests.Value[0].Config.Value.Tags = append(o.Guests.Value[0].Config.Value.Tags, "web")
		}, "duplicated"},
		{"pool malformed", func(o *Observation) { o.Guests.Value[0].Config.Value.Pool = "Web Pool" }, "pool"},
		{"capability unknown", func(o *Observation) { o.Guests.Value[0].Config.Value.Capabilities.Snapshots = "maybe" }, "unknown"},
		{"interface mac uppercase", func(o *Observation) { o.Guests.Value[0].Interfaces.Value[0].MAC = "02:00:00:11:22:3A" }, "mac"},
		{"interface mac short", func(o *Observation) { o.Guests.Value[0].Interfaces.Value[0].MAC = "02:00:00:11:22" }, "mac"},
		{"interface name duplicated", func(o *Observation) {
			o.Guests.Value[0].Interfaces.Value = append(o.Guests.Value[0].Interfaces.Value, o.Guests.Value[0].Interfaces.Value[0])
		}, "duplicated"},
		{"interface vlan out of range", func(o *Observation) { o.Guests.Value[0].Interfaces.Value[0].VLAN = 4095 }, "vlan"},
		{"interface ip malformed", func(o *Observation) { o.Guests.Value[0].Interfaces.Value[0].IPs[0] = "10.77.10.101" }, "dhcp"},
		{"interface source unknown", func(o *Observation) { o.Guests.Value[0].Interfaces.Value[0].Source = "guess" }, "source"},
		{"agent hostname malformed", func(o *Observation) { o.Guests.Value[0].Agent.Value.Hostname = "web 1" }, "hostname"},
		{"filesystem mount malformed", func(o *Observation) { o.Guests.Value[0].Agent.Value.Filesystems[0].MountPoint = "root" }, "mount_point"},
		{"filesystem used exceeds size", func(o *Observation) {
			o.Guests.Value[0].Agent.Value.Filesystems[0].UsedBytes = o.Guests.Value[0].Agent.Value.Filesystems[0].SizeBytes + 1
		}, "used_bytes"},
		{"snapshot parent unknown", func(o *Observation) { o.Guests.Value[0].Snapshots.Value[0].Parent = "ghost" }, "parent"},
		{"snapshot name malformed", func(o *Observation) { o.Guests.Value[0].Snapshots.Value[0].Name = "before upgrade" }, "name"},
		{"snapshot name with dot", func(o *Observation) { o.Guests.Value[0].Snapshots.Value[0].Name = "v1.2" }, "name"},
		{"pool with space", func(o *Observation) { o.Guests.Value[0].Config.Value.Pool = "a b" }, "pool"},
		{"pool nested four levels", func(o *Observation) { o.Guests.Value[0].Config.Value.Pool = "a/b/c/d" }, "pool"},
		{"pool empty level", func(o *Observation) { o.Guests.Value[0].Config.Value.Pool = "a//b" }, "pool"},
		{"windows mount without drive", func(o *Observation) { o.Guests.Value[0].Agent.Value.Filesystems[0].MountPoint = `\\server\share` }, "mount_point"},
		{"windows mount drive only", func(o *Observation) { o.Guests.Value[0].Agent.Value.Filesystems[0].MountPoint = "C:" }, "mount_point"},
		{"backup source unknown", func(o *Observation) { o.Guests.Value[0].Backups.Value[0].Source = "borg" }, "source"},
		{"backup kind unknown", func(o *Observation) { o.Guests.Value[0].Backups.Value[0].Kind = "image" }, "kind"},
		{"backup task status unknown", func(o *Observation) { o.Guests.Value[0].Backups.Value[0].Status = "ok" }, "status"},
		{"backup finished before started", func(o *Observation) {
			o.Guests.Value[0].Backups.Value[0].FinishedUnix = o.Guests.Value[0].Backups.Value[0].StartedUnix - 1
		}, "finished before started"},
		{"backup verified unknown", func(o *Observation) { o.Guests.Value[0].Backups.Value[0].Verified = "maybe" }, "verified"},
		{"node status unknown", func(o *Observation) { o.Nodes.Value[0].Status = "half" }, "status"},
		{"node cpu_count zero", func(o *Observation) { o.Nodes.Value[0].CPUCount = 0 }, "cpu_count"},
		{"node ram used exceeds total", func(o *Observation) {
			o.Nodes.Value[0].RAMUsedBytes = o.Nodes.Value[0].RAMTotalBytes + 1
		}, "ram_used_bytes"},
		{"node details version malformed", func(o *Observation) { o.Nodes.Value[0].Details.Value.PVEVersion = "9.0.1; rm -rf" }, "pve_version"},
		{"storage name duplicated", func(o *Observation) {
			o.Storages.Value = append(o.Storages.Value, o.Storages.Value[0])
		}, "duplicated"},
		{"storage content unknown", func(o *Observation) { o.Storages.Value[0].Content = []string{"images", "exec"} }, "content"},
		{"cluster quorum unknown", func(o *Observation) { o.Cluster.Value.Quorum = "fine" }, "quorum"},
		{"cluster node duplicated", func(o *Observation) {
			o.Cluster.Value.Nodes = append(o.Cluster.Value.Nodes, o.Cluster.Value.Nodes[0])
		}, "duplicated"},
		{"ha vmid out of range", func(o *Observation) { o.Cluster.Value.HAResources[0].VMID = 50 }, "vmid"},
		{"ha desired unknown", func(o *Observation) { o.Cluster.Value.HAResources[0].Desired = "running" }, "desired"},
		{"task actor with space", func(o *Observation) { o.Tasks.Value[0].Actor = "root @pam" }, "actor"},
		{"task exit status unknown", func(o *Observation) { o.Tasks.Value[0].ExitStatus = "done" }, "exit_status"},
		{"too many nodes", func(o *Observation) {
			nds := make([]NodeObservation, MaxObjectsPerPage+1)
			for i := range nds {
				nds[i] = NodeObservation{Node: fmt.Sprintf("node%04d", i), Status: NodeOnline, CPUCount: 1,
					RAMTotalBytes: 1 << 30, Details: AvailableDataset(NodeDetails{PVEVersion: "9.0.1", KernelVersion: "6.8.0"})}
			}
			o.Nodes = AvailableDataset(nds)
		}, "too many nodes"},
		{"too many guests", func(o *Observation) {
			gs := make([]GuestObservation, MaxObjectsPerPage+1)
			for i := range gs {
				gs[i] = GuestObservation{
					VMID:       uint64(MinVMID + i),
					Kind:       GuestQEMU,
					Node:       "node1",
					Status:     GuestStopped,
					Generation: 1,
					Config: AvailableDataset(GuestConfig{
						CPUCount:     1,
						Capabilities: GuestCapabilities{Snapshots: Unknown, LiveMigration: Unknown, RAMSnapshots: Unknown},
					}),
					Interfaces: AvailableDataset([]GuestInterface{}),
					Agent:      UnavailableDataset[GuestAgent]("not read"),
					Snapshots:  AvailableDataset([]Snapshot{}),
					Backups:    AvailableDataset([]BackupEvidence{}),
				}
			}
			o.Guests = AvailableDataset(gs)
		}, "too many guests"},
		{"too many interfaces", func(o *Observation) {
			itfs := make([]GuestInterface, MaxInterfacesPerGuest+1)
			for i := range itfs {
				itfs[i] = GuestInterface{Name: fmt.Sprintf("if%03d", i), MAC: fmt.Sprintf("02:00:00:%02x:%02x:%02x", i/256/256, i/256, i%256), Source: SourceQEMUAgent}
			}
			o.Guests.Value[0].Interfaces = AvailableDataset(itfs)
		}, "too many interfaces"},
		{"too many snapshots", func(o *Observation) {
			ss := make([]Snapshot, MaxSnapshotsPerGuest+1)
			for i := range ss {
				ss[i] = Snapshot{Name: fmt.Sprintf("snap%03d", i), TimeUnix: int64(i)}
			}
			o.Guests.Value[0].Snapshots = AvailableDataset(ss)
		}, "too many snapshots"},
		{"too many storages", func(o *Observation) {
			ss := make([]StorageObservation, MaxStoragesPerRemote+1)
			for i := range ss {
				ss[i] = StorageObservation{Name: fmt.Sprintf("st%02d", i), Type: "dir", Content: []string{"images"}, Active: true}
			}
			o.Storages = AvailableDataset(ss)
		}, "too many storages"},
		{"too many storage reports", func(o *Observation) {
			ss := make([]StorageObservation, MaxStorageReportsPerRemote+1)
			for i := range ss {
				ss[i] = StorageObservation{Name: fmt.Sprintf("st%02d", i%8), Node: fmt.Sprintf("n%04d", i/8), Type: "dir", Content: []string{"images"}, Active: true}
			}
			o.Storages = AvailableDataset(ss)
		}, "too many storage reports"},
		{"storage node malformed", func(o *Observation) {
			o.Storages = AvailableDataset([]StorageObservation{{Name: "local", Node: "bad node\n", Type: "dir", Content: []string{"images"}, Active: true}})
		}, "node"},
		{"storage duplicated on one node", func(o *Observation) {
			st := StorageObservation{Name: "local", Node: "pve1", Type: "dir", Content: []string{"images"}, Active: true}
			o.Storages = AvailableDataset([]StorageObservation{st, st})
		}, "duplicated"},
		{"storage shared flag inconsistent", func(o *Observation) {
			a := StorageObservation{Name: "nfs", Node: "pve1", Type: "nfs", Content: []string{"images"}, Active: true, Shared: true}
			b := a
			b.Node, b.Shared = "pve2", false
			o.Storages = AvailableDataset([]StorageObservation{a, b})
		}, "inconsistent shared flag"},
		{"too many tasks", func(o *Observation) {
			tks := make([]TaskObservation, MaxObjectsPerPage+1)
			for i := range tks {
				tks[i] = TaskObservation{Node: "node1", Actor: "root@pam", Type: "vzdump", Target: "101", StartedUnix: int64(i)}
			}
			o.Tasks = AvailableDataset(tks)
		}, "too many tasks"},
		{"oversize guest name field", func(o *Observation) { o.Guests.Value[0].Name = strings.Repeat("a", MaxTextFieldBytes+1) }, "exceeds"},
	}
	for _, tc := range structCases {
		t.Run(tc.name, func(t *testing.T) {
			o := baseObservation()
			tc.mutate(&o)
			got, err := DecodeObservation(mustMarshal(t, o))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !reflect.DeepEqual(o, got) {
					t.Fatal("decoded observation differs from input")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestDecodeObservationRaw(t *testing.T) {
	valid := `{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"collector-1","collection_generation":7,"complete":true,` +
		`"nodes":{"state":"available","value":[]},` +
		`"guests":{"state":"unavailable","reason":"api timeout"},` +
		`"storages":{"state":"available","value":[]},` +
		`"cluster":{"state":"unavailable","reason":"standalone remote"},` +
		`"tasks":{"state":"available","value":[]}}`

	cases := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{"valid with unavailable datasets", []byte(valid), ""},
		{"available list missing value", []byte(strings.Replace(valid, `"nodes":{"state":"available","value":[]}`, `"nodes":{"state":"available"}`, 1)), "requires a non-null value"},
		{"available list null value", []byte(strings.Replace(valid, `"nodes":{"state":"available","value":[]}`, `"nodes":{"state":"available","value":null}`, 1)), "requires a non-null value"},
		{"available object missing value", []byte(strings.Replace(valid, `"cluster":{"state":"unavailable","reason":"standalone remote"}`, `"cluster":{"state":"available"}`, 1)), "requires a non-null value"},
		{"available object null value", []byte(strings.Replace(valid, `"cluster":{"state":"unavailable","reason":"standalone remote"}`, `"cluster":{"state":"available","value":null}`, 1)), "requires a non-null value"},
		{"unknown top level field", []byte(`{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"available","value":[]},"guests":{"state":"available","value":[]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]},"extra":1}`), "unknown field"},
		{"unknown field in guest", []byte(`{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"available","value":[]},"guests":{"state":"available","value":[{"vmid":101,"kind":"qemu","node":"n","status":"stopped","generation":1,"extra":1,"config":{"state":"available","value":{"cpu_count":1,"capabilities":{"snapshots":"unknown","live_migration":"unknown","ram_snapshots":"unknown"}}},"interfaces":{"state":"available","value":[]},"agent":{"state":"unavailable","reason":"x"},"snapshots":{"state":"available","value":[]},"backups":{"state":"available","value":[]}}]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]}}`), "unknown field"},
		{"duplicate key", []byte(`{"remote_id":"poxmox","remote_id":"other"}`), "duplicate key"},
		{"invalid utf8", []byte("{\"remote_id\":\"po\xffxmox\"}"), "UTF-8"},
		{"unknown dataset key", []byte(`{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"available","value":[],"bogus":1},"guests":{"state":"available","value":[]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]}}`), "unknown key"},
		{"dataset unknown state", []byte(`{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"lost","value":[]},"guests":{"state":"available","value":[]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]}}`), "unknown"},
		{"unavailable without reason", []byte(`{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"unavailable"},"guests":{"state":"available","value":[]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]}}`), "requires a reason"},
		{"available with reason", []byte(`{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"available","value":[],"reason":"boom"},"guests":{"state":"available","value":[]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]}}`), "must not carry a reason"},
		{"unavailable with value", []byte(`{"remote_id":"poxmox","observed_at":"2026-10-29T12:00:00Z","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"unavailable","reason":"x","value":[{"node":"n","status":"online","cpu_count":1,"ram_total_bytes":1,"details":{"state":"unavailable","reason":"y"}}]},"guests":{"state":"available","value":[]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]}}`), "must not carry a value"},
		{"missing observed_at", []byte(`{"remote_id":"poxmox","source":"c","collection_generation":1,"complete":true,"nodes":{"state":"available","value":[]},"guests":{"state":"available","value":[]},"storages":{"state":"available","value":[]},"cluster":{"state":"available","value":{"nodes":[],"quorum":"unknown","ha_resources":[]}},"tasks":{"state":"available","value":[]}}`), "observed_at"},
		{"deep nesting", []byte(`{"remote_id":` + strings.Repeat(`{"k":`, MaxNesting+5) + `1` + strings.Repeat(`}`, MaxNesting+5) + `}`), "nesting"},
		{"too many objects", []byte("[" + strings.Repeat(`{},`, MaxObjectsPerDocument+1) + `{}` + "]"), "objects"},
		{"oversize document", []byte(strings.Repeat(" ", MaxResponseBytes+1)), "exceeds"},
		{"trailing data", []byte(valid + " {}"), "trailing"},
		{"top level array", []byte(`[1]`), "decode"},
		{"empty input", []byte(``), "malformed JSON"},
		{"malformed json", []byte(`{"remote_id":`), "malformed JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeObservation(tc.raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestObservationRoundTrip(t *testing.T) {
	o := baseObservation()
	b, err := MarshalObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeObservation(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(o, got) {
		t.Fatalf("round trip mismatch:\ninput:  %+v\ndecoded: %+v", o, got)
	}
}

func TestDatasetSemantics(t *testing.T) {
	t.Run("available empty keeps value", func(t *testing.T) {
		d := AvailableDataset([]NodeObservation{})
		b := mustMarshal(t, d)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m["state"] != "available" {
			t.Fatalf("state = %v", m["state"])
		}
		v, ok := m["value"].([]any)
		if !ok || len(v) != 0 {
			t.Fatalf("value = %v", m["value"])
		}
		if _, has := m["reason"]; has {
			t.Fatal("available dataset must not carry a reason")
		}
		var back Dataset[[]NodeObservation]
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if !back.IsAvailable() || len(back.Value) != 0 {
			t.Fatalf("round trip = %+v", back)
		}
	})
	t.Run("unavailable carries reason only", func(t *testing.T) {
		d := UnavailableDataset[[]NodeObservation]("insufficient read privileges")
		b := mustMarshal(t, d)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m["state"] != "unavailable" || m["reason"] != "insufficient read privileges" {
			t.Fatalf("document = %v", m)
		}
		if _, has := m["value"]; has {
			t.Fatal("unavailable dataset must not carry a value")
		}
		var back Dataset[[]NodeObservation]
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.IsAvailable() || back.Reason != "insufficient read privileges" {
			t.Fatalf("round trip = %+v", back)
		}
	})
	t.Run("marshal rejects inconsistent dataset", func(t *testing.T) {
		o := baseObservation()
		o.Nodes = Dataset[[]NodeObservation]{State: Unavailable} // no reason
		if _, err := MarshalObservation(o); err == nil {
			t.Fatal("MarshalObservation must not emit an unavailable dataset without a reason")
		}
	})
}

func TestValidateObservationClones(t *testing.T) {
	o := baseObservation()
	v, err := ValidateObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	o.Nodes.Value[0].Node = "mutated"
	o.Guests.Value[0].Name = "mutated"
	o.Storages.Value[0].Name = "mutated"
	o.Tasks.Value[0].Actor = "mutated"
	if v.Nodes.Value[0].Node == "mutated" || v.Guests.Value[0].Name == "mutated" ||
		v.Storages.Value[0].Name == "mutated" || v.Tasks.Value[0].Actor == "mutated" {
		t.Fatal("validated copy shares backing arrays with input")
	}
}

func TestValidationErrorIsErrInvalid(t *testing.T) {
	_, err := DecodeObservation([]byte(`{"remote_id":"Poxmox"}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("errors.Is(err, ErrInvalid) = false for %v", err)
	}
}

// PVE keeps the case of snapshot names and pool IDs, and Windows guests
// report drive-letter mount points; all are valid observations.
func TestValidateObservationAcceptsPVEStyleNames(t *testing.T) {
	cases := map[string]func(o *Observation){
		"mixed-case snapshot": func(o *Observation) {
			o.Guests.Value[0].Snapshots.Value = []Snapshot{{Name: "Pre-Upgrade", TimeUnix: 1}, {Name: "After_Fix", TimeUnix: 2, Parent: "Pre-Upgrade"}}
		},
		"mixed-case pool":       func(o *Observation) { o.Guests.Value[0].Config.Value.Pool = "Prod.Web" },
		"nested pool":           func(o *Observation) { o.Guests.Value[0].Config.Value.Pool = "dev/Team1/ci" },
		"windows drive root":    func(o *Observation) { o.Guests.Value[0].Agent.Value.Filesystems[0].MountPoint = `C:\` },
		"windows drive subpath": func(o *Observation) { o.Guests.Value[0].Agent.Value.Filesystems[0].MountPoint = `D:\data` },
	}
	for name, mutate := range cases {
		o := baseObservation()
		mutate(&o)
		if _, err := ValidateObservation(o); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateObservationAcceptsDirStorageVolumes(t *testing.T) {
	for _, vol := range []string{"local:100/vm-100-disk-0.qcow2", "local:iso/Debian-12.4_amd64+netinst.iso", "local-lvm:vm-100-disk-0", "rbd"} {
		o := baseObservation()
		o.Guests.Value[0].Config.Value.Disks[0].Volume = vol
		if _, err := ValidateObservation(o); err != nil {
			t.Errorf("%s: %v", vol, err)
		}
	}
}
