// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// PVE snapshot names and pool IDs keep their case; an uppercase name must
// not invalidate the guest's whole dataset.
func TestReadPVESnapshotAndPoolNamesPreserveCase(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/snapshot", `{"data":[
		{"name":"Base","snaptime":1700000000},
		{"name":"Pre-Upgrade","parent":"Base","snaptime":1700000100},
		{"name":"current","parent":"Pre-Upgrade","running":1}]}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 100)
	if err != nil {
		t.Fatal(err)
	}
	s := got.GetSnapshots()
	if s.GetState() != pveAvail || len(s.GetSnapshots()) != 2 || s.GetSnapshots()[1].GetName() != "Pre-Upgrade" || s.GetSnapshots()[1].GetParent() != "Base" {
		t.Fatalf("snapshots = %v", s)
	}
	e.pve.set("/api2/json/nodes/pve1/qemu/100/config", `{"data":{"cores":1,"memory":512,"pool":"Prod-Pool"}}`)
	got, err = e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100)
	if err != nil {
		t.Fatal(err)
	}
	if c := got.GetGuestConfig(); c.GetState() != pveAvail || c.GetPool() != "Prod-Pool" {
		t.Fatalf("config = %v", c)
	}
}

func TestReadPVESnapshotHostileNamesStayInvalid(t *testing.T) {
	for name, snap := range map[string]string{
		"script":    `<script>`,
		"traversal": `../x`,
		"space":     `a b`,
		"leading -": `-x`,
	} {
		t.Run(name, func(t *testing.T) {
			e := guestPveEnv(t)
			e.pve.set("/api2/json/nodes/pve1/qemu/100/snapshot", `{"data":[{"name":"`+snap+`","snaptime":1}]}`)
			got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 100)
			if err != nil {
				t.Fatal(err)
			}
			if s := got.GetSnapshots(); s.GetState() != pveUnav || len(s.GetSnapshots()) != 0 {
				t.Fatalf("snapshots = %v", s)
			}
		})
	}
}

// Windows guests report drive mount points; they are valid, relative or
// control-character paths are not.
func TestReadPVEGuestAgentAcceptsWindowsMountPoints(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/agent/get-osinfo", `{"data":{"result":{"name":"Microsoft Windows Server 2022"}}}`)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/agent/get-fsinfo", `{"data":{"result":[
		{"name":"C:","mountpoint":"C:\\","type":"NTFS","total-bytes":1000,"used-bytes":400},
		{"name":"D:","mountpoint":"D:\\Data","type":"NTFS","total-bytes":10,"used-bytes":1}]}}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, 100)
	if err != nil {
		t.Fatal(err)
	}
	a := got.GetGuestAgent()
	if a.GetState() != pveAvail || len(a.GetFilesystems()) != 2 || a.GetFilesystems()[0].GetMountPoint() != `C:\` || a.GetFilesystems()[0].GetFstype() != "ntfs" {
		t.Fatalf("agent = %v", a)
	}
	for name, mp := range map[string]string{"relative": "data", "drive without slash": "C:", "bare letter": `CC:\\x`} {
		t.Run(name, func(t *testing.T) {
			e := guestPveEnv(t)
			e.pve.set("/api2/json/nodes/pve1/qemu/100/agent/get-osinfo", `{"data":{"result":{"name":"x"}}}`)
			e.pve.set("/api2/json/nodes/pve1/qemu/100/agent/get-fsinfo", `{"data":{"result":[{"mountpoint":"`+mp+`","type":"ntfs","total-bytes":1,"used-bytes":1}]}}`)
			got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, 100)
			if err != nil {
				t.Fatal(err)
			}
			if a := got.GetGuestAgent(); a.GetState() != pveUnav {
				t.Fatalf("agent = %v", a)
			}
		})
	}
}
