// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	pveAvail = pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE
	pveUnav  = pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE
)

func (e *pveReadEnv) readGuest(method pb.PVEReadMethod, vmid uint64) (*pb.ReadPVEResponse, error) {
	return e.svc.ReadPVE(context.Background(), &pb.ReadPVERequest{RemoteId: pveReadRemote, Method: method,
		Params: &pb.ReadPVERequest_Guest{Guest: &pb.PVEReadGuestParams{Vmid: vmid}}})
}

// guestPveEnv is a standalone remote with a grant for every wired method.
func guestPveEnv(t *testing.T) *pveReadEnv {
	t.Helper()
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodGuestConfig, permit.ProviderMethodGuestAgent,
		permit.ProviderMethodSnapshots, permit.ProviderMethodTasks, permit.ProviderMethodBackups))
	return e
}

// upid builds a PVE task ID for node that started at start.
func upid(node string, start time.Time, typ, id string) string {
	return fmt.Sprintf("UPID:%s:0000ABCD:00012345:%08X:%s:%s:root@pam:", node, start.Unix(), typ, id)
}

func TestReadPVEGuestConfigMapsSanitizedConfig(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/config", `{"data":{
		"name":"web","cores":2,"sockets":2,"memory":"2048",
		"scsi0":"local-lvm:vm-100-disk-0,size=32G",
		"ide2":"local:iso/Debian-12.iso,media=cdrom",
		"ide0":"none,media=cdrom",
		"virtio1":"local:100/vm-100-disk-1.qcow2,size=1G",
		"boot":"order=scsi0;ide2;net0","tags":"Web;prod",
		"ipconfig0":"ip=10.0.0.5/24,gw=10.0.0.1",
		"hostpci0":"0000:01:00.0,pcie=1",
		"cipassword":"s3cr3t-cloud-init","description":"private notes"}}`)

	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100)
	if err != nil {
		t.Fatal(err)
	}
	c := got.GetGuestConfig()
	if c.GetState() != pveAvail || c.GetVmid() != 100 || c.GetCpuCount() != 4 || c.GetRamBytes() != 2<<30 {
		t.Fatalf("config = %v", c)
	}
	var disks []string
	for _, d := range c.GetDisks() {
		disks = append(disks, fmt.Sprintf("%s|%s|%s|%d", d.GetStorage(), d.GetVolume(), d.GetFormat(), d.GetSizeBytes()))
	}
	want := "local|local:iso/Debian-12.iso|iso|0 local-lvm|local-lvm:vm-100-disk-0|raw|34359738368 local|local:100/vm-100-disk-1.qcow2|qcow2|1073741824"
	if strings.Join(disks, " ") != want {
		t.Fatalf("disks = %v\nwant    %s", disks, want)
	}
	if strings.Join(c.GetBootOrder(), ",") != "scsi0,ide2,net0" || strings.Join(c.GetTags(), ",") != "web,prod" {
		t.Fatalf("boot/tags = %v %v", c.GetBootOrder(), c.GetTags())
	}
	if ip := c.GetCloudInitIp(); ip.GetIp() != "10.0.0.5/24" || ip.GetGateway() != "10.0.0.1" {
		t.Fatalf("cloud-init = %v", ip)
	}
	// Passthrough rules out live migration and RAM snapshots; the node's
	// PCI identity is not in the guest config, so no device is invented.
	if cp := c.GetCapabilities(); cp.GetLiveMigration() != "no" || cp.GetRamSnapshots() != "no" || cp.GetSnapshots() != "unknown" ||
		len(c.GetHostpci()) != 0 {
		t.Fatalf("capabilities = %v hostpci = %v", cp, c.GetHostpci())
	}
	if s := fmt.Sprint(got); strings.Contains(s, "s3cr3t") || strings.Contains(s, "private notes") {
		t.Fatal("secret or description reached the result")
	}
}

func TestReadPVEGuestConfigResolvesContainers(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/lxc/200/config", `{"data":{"cores":1,"memory":512,
		"rootfs":"local-zfs:subvol-200-disk-0,size=8G","mp0":"/srv/data,mp=/data"}}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 200)
	if err != nil {
		t.Fatal(err)
	}
	c := got.GetGuestConfig()
	// The bind mount names no storage volume and is not a disk.
	if c.GetState() != pveAvail || len(c.GetDisks()) != 1 || c.GetDisks()[0].GetFormat() != "subvol" || c.GetDisks()[0].GetStorage() != "local-zfs" {
		t.Fatalf("config = %v", c)
	}
}

func TestReadPVEGuestAgentSummarizesQEMUAgent(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/agent/get-osinfo", `{"data":{"result":{"name":"Debian GNU/Linux","version":"12 (bookworm)"}}}`)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/agent/get-fsinfo", `{"data":{"result":[
		{"name":"sda1","mountpoint":"/","type":"EXT4","total-bytes":1000,"used-bytes":400}]}}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, 100)
	if err != nil {
		t.Fatal(err)
	}
	a := got.GetGuestAgent()
	if a.GetState() != pveAvail || a.GetOs() != "Debian GNU/Linux 12 (bookworm)" || len(a.GetFilesystems()) != 1 {
		t.Fatalf("agent = %v", a)
	}
	if fs := a.GetFilesystems()[0]; fs.GetMountPoint() != "/" || fs.GetFstype() != "ext4" || fs.GetSizeBytes() != 1000 || fs.GetUsedBytes() != 400 {
		t.Fatalf("filesystem = %v", fs)
	}
}

func TestReadPVEGuestAgentUnavailableStates(t *testing.T) {
	t.Run("container", func(t *testing.T) {
		e := guestPveEnv(t)
		got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, 200)
		if err != nil {
			t.Fatal(err)
		}
		if a := got.GetGuestAgent(); a.GetState() != pveUnav || a.GetReason() != pveReasonAgentQEMUOnly {
			t.Fatalf("agent = %v", a)
		}
	})
	t.Run("agent not running", func(t *testing.T) {
		e := guestPveEnv(t) // the agent endpoints answer 404
		got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, 100)
		if err != nil {
			t.Fatal(err)
		}
		if a := got.GetGuestAgent(); a.GetState() != pveUnav || a.GetReason() != pveReasonAgentDown {
			t.Fatalf("agent = %v", a)
		}
	})
}

func TestReadPVESnapshotsDropsDescriptions(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/snapshot", `{"data":[
		{"name":"base","snaptime":1700000000,"description":"private notes"},
		{"name":"pre-upgrade","parent":"base","snaptime":1700000100,"vmstate":1},
		{"name":"current","parent":"pre-upgrade","running":1}]}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 100)
	if err != nil {
		t.Fatal(err)
	}
	s := got.GetSnapshots()
	if s.GetState() != pveAvail || s.GetVmid() != 100 || len(s.GetSnapshots()) != 2 {
		t.Fatalf("snapshots = %v", s)
	}
	var names []string
	for _, sn := range s.GetSnapshots() {
		names = append(names, fmt.Sprintf("%s<%s@%d/%v", sn.GetName(), sn.GetParent(), sn.GetTimeUnix(), sn.GetHasRam()))
	}
	if strings.Join(names, " ") != "base<@1700000000/false pre-upgrade<base@1700000100/true" {
		t.Fatalf("snapshots = %v", names)
	}
	if strings.Contains(fmt.Sprint(got), "private notes") {
		t.Fatal("description reached the result")
	}
}

func TestReadPVETasksReadsBoundedMetadata(t *testing.T) {
	e := guestPveEnv(t)
	now := e.clock.Now()
	e.pve.set("/api2/json/nodes/pve1/tasks", fmt.Sprintf(`{"data":[
		{"upid":%q,"status":"RUNNING","user":"root@pam"},
		{"upid":%q,"endtime":%d,"status":"OK","user":"root@pam"},
		{"upid":%q,"endtime":%d,"status":"command 'apt-get update' failed: exit code 100","user":"root@pam"}]}`,
		upid("pve1", now.Add(-time.Minute), "vzdump", "100"),
		upid("pve1", now.Add(-time.Hour), "qmstart", "100"), now.Add(-time.Hour+time.Second).Unix(),
		upid("pve1", now.Add(-2*time.Hour), "aptupdate", ""), now.Add(-2*time.Hour+time.Minute).Unix()))
	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_TASKS)
	if err != nil {
		t.Fatal(err)
	}
	tk := got.GetTasks()
	if tk.GetState() != pveAvail || len(tk.GetTasks()) != 3 {
		t.Fatalf("tasks = %v", tk)
	}
	var rows []string
	for _, x := range tk.GetTasks() {
		rows = append(rows, fmt.Sprintf("%s/%s/%s/%s/%s", x.GetNode(), x.GetActor(), x.GetType(), x.GetTarget(), x.GetExitStatus()))
	}
	if strings.Join(rows, " ") != "pve1/root@pam/vzdump/100/ pve1/root@pam/qmstart/100/success pve1/root@pam/aptupdate/pve1/error" {
		t.Fatalf("tasks = %v", rows)
	}
	if strings.Contains(fmt.Sprint(got), "apt-get") {
		t.Fatal("raw task status text reached the result")
	}
}

func TestReadPVEGuestDetailRejectsHostileOrMissingData(t *testing.T) {
	cases := map[string]struct {
		method pb.PVEReadMethod
		vmid   uint64
		bodies map[string]string
		reason string
	}{
		"unknown guest": {pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 999, nil, pveReasonGuestNotFound},
		"guest list unreadable": {pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 999,
			map[string]string{"/api2/json/nodes/pve1/lxc": `{"data":`}, pveReasonPartial},
		"dangling snapshot parent": {pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 100,
			map[string]string{"/api2/json/nodes/pve1/qemu/100/snapshot": `{"data":[{"name":"a","parent":"gone","snaptime":1}]}`}, pveReasonInvalid},
		"relative mount point": {pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, 100, map[string]string{
			"/api2/json/nodes/pve1/qemu/100/agent/get-osinfo": `{"data":{"result":{"name":"x"}}}`,
			"/api2/json/nodes/pve1/qemu/100/agent/get-fsinfo": `{"data":{"result":[{"mountpoint":"data","type":"ext4","total-bytes":1,"used-bytes":1}]}}`,
		}, pveReasonInvalid},
		"used above size": {pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, 100, map[string]string{
			"/api2/json/nodes/pve1/qemu/100/agent/get-osinfo": `{"data":{"result":{"name":"x"}}}`,
			"/api2/json/nodes/pve1/qemu/100/agent/get-fsinfo": `{"data":{"result":[{"mountpoint":"/","type":"ext4","total-bytes":1,"used-bytes":2}]}}`,
		}, pveReasonInvalid},
		"malformed tag": {pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100,
			map[string]string{"/api2/json/nodes/pve1/qemu/100/config": `{"data":{"cores":1,"tags":"<script>"}}`}, pveReasonInvalid},
		"path traversal volume": {pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100,
			map[string]string{"/api2/json/nodes/pve1/qemu/100/config": `{"data":{"cores":1,"scsi0":"local:../../etc/shadow"}}`}, pveReasonInvalid},
		"config unreadable": {pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100, nil, pveReasonRead},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := guestPveEnv(t)
			for p, b := range tc.bodies {
				e.pve.set(p, b)
			}
			got, err := e.readGuest(tc.method, tc.vmid)
			if err != nil {
				t.Fatal(err)
			}
			var state pb.PVEDatasetState
			var reason string
			switch p := got.GetPayload().(type) {
			case *pb.ReadPVEResponse_GuestConfig:
				state, reason = p.GuestConfig.GetState(), p.GuestConfig.GetReason()
			case *pb.ReadPVEResponse_GuestAgent:
				state, reason = p.GuestAgent.GetState(), p.GuestAgent.GetReason()
			case *pb.ReadPVEResponse_Snapshots:
				state, reason = p.Snapshots.GetState(), p.Snapshots.GetReason()
			default:
				t.Fatalf("payload = %T", p)
			}
			if state != pveUnav || reason != tc.reason {
				t.Fatalf("state = %v reason = %q, want %q", state, reason, tc.reason)
			}
		})
	}
}

func TestReadPVEGuestVMIDBeyondPVERangeMakesNoRequest(t *testing.T) {
	e := guestPveEnv(t)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 1<<31)
	if err != nil {
		t.Fatal(err)
	}
	if s := got.GetSnapshots(); s.GetState() != pveUnav || s.GetReason() != pveReasonGuestNotFound {
		t.Fatalf("snapshots = %v", s)
	}
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("%d requests reached PVE", n)
	}
}

func TestReadPVETasksPartialWhenAnOnlineNodeFails(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes", `{"data":[{"node":"pve1","status":"online"},{"node":"pve2","status":"online"},{"node":"pve3","status":"offline"}]}`)
	e.pve.set("/api2/json/nodes/pve1/tasks", `{"data":[]}`)
	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_TASKS)
	if err != nil {
		t.Fatal(err)
	}
	if tk := got.GetTasks(); tk.GetState() != pveUnav || tk.GetReason() != pveReasonPartial {
		t.Fatalf("tasks = %v", tk)
	}
}

func TestReadPVEGuestDetailNeedsItsOwnMethodGrant(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodGuestConfig))
	_, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 100)
	wantPveCode(t, err, codes.PermissionDenied)
	_, err = e.read(pb.PVEReadMethod_PVE_READ_METHOD_TASKS)
	wantPveCode(t, err, codes.PermissionDenied)
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("%d requests reached PVE without authority", n)
	}
}

func TestReadPVEGuestDetailIntervalIsPerGuest(t *testing.T) {
	e := guestPveEnv(t)
	for _, vmid := range []uint64{100, 200} {
		got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, vmid)
		if err != nil {
			t.Fatalf("guest %d: %v", vmid, err)
		}
		if got.GetSnapshots().GetVmid() != vmid {
			t.Fatalf("snapshots = %v", got.GetSnapshots())
		}
	}
	_, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, 100)
	wantPveCode(t, err, codes.ResourceExhausted)
}
