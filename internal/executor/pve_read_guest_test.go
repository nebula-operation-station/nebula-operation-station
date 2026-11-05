// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	pveAvail = pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE
	pveUnav  = pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE
)

func TestReadPVEGuestConfigCarriesNICsUsingOnlyGET(t *testing.T) {
	for _, kind := range []string{"qemu", "lxc"} {
		t.Run(kind, func(t *testing.T) {
			configPath := "/api2/json/nodes/pve1/" + kind + "/100/config"
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.RawQuery != "" {
					t.Errorf("unexpected request method or query")
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				switch r.URL.Path {
				case "/api2/json/nodes":
					fmt.Fprint(w, `{"data":[{"node":"pve1","status":"online"}]}`)
				case "/api2/json/nodes/pve1/" + kind:
					fmt.Fprint(w, `{"data":[{"vmid":100,"status":"running"}]}`)
				case "/api2/json/nodes/pve1/qemu", "/api2/json/nodes/pve1/lxc":
					fmt.Fprint(w, `{"data":[]}`)
				case configPath:
					fmt.Fprint(w, `{"data":{"cores":1,"memory":512,
						"net0":"virtio=AA:BB:CC:DD:EE:01,hwaddr=AA:BB:CC:DD:EE:01,bridge=vmbr0,tag=42",
						"net31":"macaddr=02:00:00:00:00:31,bridge=vnet_1,tag=4094"}}`)
				default:
					t.Errorf("unexpected path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			got := readPveGuestConfig(context.Background(), "remote-a", srv.URL, srv.Client(),
				func(context.Context) (string, error) { return "", nil }, 100, time.Now())
			if got.State != pveAvail || len(got.Nics) != 2 {
				t.Fatalf("config state=%v NIC count=%d", got.State, len(got.Nics))
			}
			wire, err := proto.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var decoded pb.PVEGuestConfig
			if err := proto.Unmarshal(wire, &decoded); err != nil || !proto.Equal(got, &decoded) {
				t.Fatalf("NIC config did not survive protobuf round trip: %v", err)
			}
			if n := got.Nics[0]; n.Device != "net0" || n.Bridge != "vmbr0" || n.Vlan != 42 || n.Mac != "aa:bb:cc:dd:ee:01" {
				t.Fatalf("NIC fields were not preserved: %v", n)
			}
			if n := got.Nics[1]; n.Device != "net31" || n.Bridge != "vnet_1" || n.Vlan != 4094 || n.Mac != "02:00:00:00:00:31" {
				t.Fatalf("boundary NIC fields were not preserved: %v", n)
			}
			wantRequests := 3
			if kind == "lxc" {
				wantRequests++
			}
			if requests.Load() != int64(wantRequests) {
				t.Fatalf("requests=%d want=%d", requests.Load(), wantRequests)
			}
		})
	}
}

func TestPVEGuestNICsDropsOnlyInvalidEntries(t *testing.T) {
	valid := pveapi.NIC{Device: "net0", Bridge: "vmbr0", VLAN: 42, MAC: "02:00:00:00:00:01"}
	cases := map[string]func(*pveapi.NIC){
		"negative index":     func(n *pveapi.NIC) { n.Device = "net-1" },
		"index above limit":  func(n *pveapi.NIC) { n.Device = "net32" },
		"noncanonical index": func(n *pveapi.NIC) { n.Device = "net00" },
		"oversized device":   func(n *pveapi.NIC) { n.Device = "net" + strings.Repeat("1", 1024) },
		"hostile bridge":     func(n *pveapi.NIC) { n.Bridge = "<script>" },
		"bridge slash":       func(n *pveapi.NIC) { n.Bridge = "br/0" },
		"bridge space":       func(n *pveapi.NIC) { n.Bridge = "br 0" },
		"bridge dot":         func(n *pveapi.NIC) { n.Bridge = "." },
		"bridge dotdot":      func(n *pveapi.NIC) { n.Bridge = ".." },
		"oversized bridge":   func(n *pveapi.NIC) { n.Bridge = strings.Repeat("a", 16) },
		"invalid utf8":       func(n *pveapi.NIC) { n.Bridge = "br\xff" },
		"negative vlan":      func(n *pveapi.NIC) { n.VLAN = -1 },
		"vlan above limit":   func(n *pveapi.NIC) { n.VLAN = 4095 },
		"missing mac":        func(n *pveapi.NIC) { n.MAC = "" },
		"malformed mac":      func(n *pveapi.NIC) { n.MAC = "<script>" },
		"oversized mac":      func(n *pveapi.NIC) { n.MAC = strings.Repeat("a", 1024) },
		"zero mac":           func(n *pveapi.NIC) { n.MAC = "00:00:00:00:00:00" },
		"multicast mac":      func(n *pveapi.NIC) { n.MAC = "01:00:00:00:00:01" },
		"uppercase mac":      func(n *pveapi.NIC) { n.MAC = "AA:BB:CC:DD:EE:01" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			first := valid
			first.Device = "net1"
			n := valid
			mutate(&n)
			got, complete := pveGuestNICs([]pveapi.NIC{first, n})
			if complete || len(got) != 1 || got[0].Device != "net1" {
				t.Fatalf("complete=%v nics=%v; want only net1 and incomplete", complete, got)
			}
		})
	}
	t.Run("duplicate device", func(t *testing.T) {
		dup := valid
		dup.Bridge = "vmbr1"
		got, complete := pveGuestNICs([]pveapi.NIC{valid, dup})
		if complete || len(got) != 1 || got[0].Bridge != "vmbr0" {
			t.Fatalf("complete=%v nics=%v; want first net0 only", complete, got)
		}
	})
	t.Run("count limit", func(t *testing.T) {
		nics := make([]pveapi.NIC, 32)
		for i := range nics {
			nics[i] = valid
			nics[i].Device = fmt.Sprintf("net%d", i)
		}
		if got, complete := pveGuestNICs(nics); !complete || len(got) != 32 {
			t.Fatal("maximum NIC list rejected")
		}
		// Distinct devices only: without the count guard the 32 valid
		// entries would be kept and only net32 dropped.
		extra := valid
		extra.Device = "net32"
		if got, complete := pveGuestNICs(append(nics, extra)); complete || len(got) != 0 {
			t.Fatalf("oversized NIC list kept %d entries", len(got))
		}
	})
	t.Run("no NICs", func(t *testing.T) {
		if got, complete := pveGuestNICs(nil); !complete || len(got) != 0 {
			t.Fatal("empty NIC list rejected")
		}
	})
	t.Run("untagged without bridge", func(t *testing.T) {
		n := valid
		n.Bridge, n.VLAN = "", 0
		if got, complete := pveGuestNICs([]pveapi.NIC{n}); !complete || len(got) != 1 || got[0].Bridge != "" || got[0].Vlan != 0 {
			t.Fatal("untagged NIC without a bridge was not preserved")
		}
	})
	for _, bridge := range []string{strings.Repeat("a", 15), "vmbr0.100", "br-lan", "vnet_1"} {
		t.Run("bridge "+bridge, func(t *testing.T) {
			n := valid
			n.Bridge = bridge
			if got, complete := pveGuestNICs([]pveapi.NIC{n}); !complete || len(got) != 1 || got[0].Bridge != bridge {
				t.Fatal("valid PVE bridge name was not preserved")
			}
		})
	}
}

func TestReadPVEGuestConfigAcceptsPVEBridgeNames(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/config", `{"data":{"cores":2,"memory":512,
		"net0":"virtio=02:00:00:00:00:01,bridge=vmbr0.100",
		"net1":"virtio=02:00:00:00:00:02,bridge=br-lan,tag=7"}}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100)
	if err != nil {
		t.Fatal(err)
	}
	cfg := got.GetGuestConfig()
	if cfg.State != pveAvail || cfg.NicsIncomplete || len(cfg.Nics) != 2 ||
		cfg.Nics[0].Bridge != "vmbr0.100" || cfg.Nics[1].Bridge != "br-lan" || cfg.Nics[1].Vlan != 7 {
		t.Fatalf("config = %v", cfg)
	}
}

func TestReadPVEGuestConfigInvalidNICDropsOnlyThatNIC(t *testing.T) {
	for _, nic := range []string{
		`"net0":"virtio=02:00:00:00:00:01,bridge=<script>"`,
		`"net0":"virtio=02:00:00:00:00:01,bridge=br/0"`,
		`"net32":"virtio=02:00:00:00:00:01,bridge=vmbr0"`,
		`"net0":"virtio=invalid,bridge=vmbr0"`,
		`"net0":"virtio=02:00:00:00:00:01,bridge=vmbr0,tag=4095"`,
		`"net0":"virtio=02:00:00:00:00:01,bridge=vmbr0,tag=abc"`,
		`"net0":"virtio=02:00:00:00:00:01,bridge=vmbr\u001b0"`,
	} {
		t.Run(nic, func(t *testing.T) {
			e := guestPveEnv(t)
			e.pve.set("/api2/json/nodes/pve1/qemu/100/config", `{"data":{"cores":2,"memory":512,"tags":"web",`+nic+
				`,"net5":"virtio=02:00:00:00:00:05,bridge=vmbr0.100"}}`)
			got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100)
			if err != nil {
				t.Fatal(err)
			}
			cfg := got.GetGuestConfig()
			if cfg.State != pveAvail || cfg.CpuCount != 2 || cfg.RamBytes != 512<<20 || len(cfg.Tags) != 1 {
				t.Fatalf("invalid NIC hid the guest config: %v", cfg)
			}
			if !cfg.NicsIncomplete || len(cfg.Nics) != 1 || cfg.Nics[0].Device != "net5" {
				t.Fatalf("NICs = %v incomplete=%v; want only net5, incomplete", cfg.Nics, cfg.NicsIncomplete)
			}
			if strings.Contains(cfg.String(), "script") || strings.Contains(cfg.String(), "br/0") {
				t.Fatal("hostile NIC text crossed the RPC boundary")
			}
		})
	}
}

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
		{"upid":%q,"endtime":%d,"status":"WARNINGS: 2","user":"root@pam"},
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

// A busy node keeps its newest pveTasksPerNode tasks and the result is
// flagged truncated, so the cut window never looks complete.
func TestReadPVETasksTruncatedWindowFlagged(t *testing.T) {
	e := guestPveEnv(t)
	now := e.clock.Now()
	var rows []string
	// The fake serves the same full page for every offset, so the second page
	// pushes the node past pveTasksPerNode.
	for i := range pveTasksPerNode {
		rows = append(rows, fmt.Sprintf(`{"upid":%q,"status":"RUNNING","user":"root@pam"}`,
			upid("pve1", now.Add(-time.Duration(i+1)*time.Second), "qmstart", "100")))
	}
	e.pve.set("/api2/json/nodes/pve1/tasks", `{"data":[`+strings.Join(rows, ",")+`]}`)
	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_TASKS)
	if err != nil {
		t.Fatal(err)
	}
	tk := got.GetTasks()
	if tk.GetState() != pveAvail || !tk.GetTruncated() || len(tk.GetTasks()) != pveTasksPerNode {
		t.Fatalf("tasks = state %v truncated %v len %d", tk.GetState(), tk.GetTruncated(), len(tk.GetTasks()))
	}
	if tk.GetTasks()[0].GetStartedUnix() != now.Add(-time.Second).Unix() {
		t.Fatalf("newest task not kept first: %v", tk.GetTasks()[0])
	}
}

// A node within its limit is not flagged.
func TestReadPVETasksCompleteWindowNotFlagged(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/tasks", `{"data":[]}`)
	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_TASKS)
	if err != nil {
		t.Fatal(err)
	}
	if tk := got.GetTasks(); tk.GetState() != pveAvail || tk.GetTruncated() {
		t.Fatalf("tasks = %v", tk)
	}
}

func TestReadPVEBackupsReportsTaskEvidenceAndUnavailableCatalog(t *testing.T) {
	e := guestPveEnv(t)
	now := e.clock.Now()
	e.pve.set("/api2/json/nodes/pve1/tasks", fmt.Sprintf(`{"data":[
		{"upid":%q,"status":"RUNNING","user":"root@pam"},
		{"upid":%q,"endtime":%d,"status":"OK","user":"root@pam"},
		{"upid":%q,"endtime":%d,"status":"WARNINGS: 1","user":"root@pam"},
		{"upid":%q,"endtime":%d,"status":"job errors: s3cr3t <script>","user":"root@pam"},
		{"upid":%q,"endtime":%d,"status":"OK","user":"root@pam"},
		{"upid":%q,"endtime":%d,"status":"OK","user":"root@pam"}]}`,
		upid("pve1", now.Add(-time.Minute), "vzdump", "100"),
		upid("pve1", now.Add(-time.Hour), "vzdump", "100"), now.Add(-time.Hour+time.Minute).Unix(),
		upid("pve1", now.Add(-2*time.Hour), "vzdump", "100"), now.Add(-2*time.Hour+time.Minute).Unix(),
		upid("pve1", now.Add(-3*time.Hour), "vzdump", "100"), now.Add(-3*time.Hour+time.Minute).Unix(),
		// Another guest and another task type never count for 100.
		upid("pve1", now.Add(-4*time.Hour), "vzdump", "1000"), now.Add(-4*time.Hour+time.Minute).Unix(),
		upid("pve1", now.Add(-5*time.Hour), "qmstart", "100"), now.Add(-5*time.Hour+time.Minute).Unix()))
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
	if err != nil {
		t.Fatal(err)
	}
	b := got.GetBackups()
	if b.GetState() != pveAvail || b.GetVmid() != 100 {
		t.Fatalf("backups = %v", b)
	}
	// The catalog is never an empty "no backups" list.
	if b.GetCatalogState() != pveUnav || b.GetCatalogReason() != pveReasonCatalogScope {
		t.Fatalf("catalog = %v %q", b.GetCatalogState(), b.GetCatalogReason())
	}
	var rows []string
	for _, x := range b.GetBackups() {
		if x.GetKind() != "task" || x.GetSource() != "vzdump" || x.GetVerified() != "unknown" {
			t.Fatalf("evidence = %v", x)
		}
		rows = append(rows, x.GetStatus())
	}
	if strings.Join(rows, ",") != "running,success,unknown,failed" {
		t.Fatalf("statuses = %v", rows)
	}
	if s := fmt.Sprint(got); strings.Contains(s, "s3cr3t") || strings.Contains(s, "<script>") {
		t.Fatal("raw task status reached the result")
	}
}

func TestReadPVEBackupsUnavailableWhenANodeFails(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes", `{"data":[{"node":"pve1","status":"online"},{"node":"pve2","status":"online"}]}`)
	e.pve.set("/api2/json/nodes/pve1/tasks", `{"data":[]}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
	if err != nil {
		t.Fatal(err)
	}
	b := got.GetBackups()
	if b.GetState() != pveUnav || b.GetReason() != pveReasonPartial || len(b.GetBackups()) != 0 || b.GetCatalogState() != pveUnav {
		t.Fatalf("backups = %v", b)
	}
}

func TestReadPVEBackupsHostileTaskListUnavailable(t *testing.T) {
	for name, body := range map[string]string{
		"not a list":       `{"data":"<script>"}`,
		"node mismatch":    fmt.Sprintf(`{"data":[{"upid":%q,"status":"OK","endtime":2}]}`, upid("evil", time.Unix(1, 0), "vzdump", "100")),
		"end before start": fmt.Sprintf(`{"data":[{"upid":%q,"status":"OK","endtime":1}]}`, upid("pve1", time.Unix(1000, 0), "vzdump", "100")),
	} {
		t.Run(name, func(t *testing.T) {
			e := guestPveEnv(t)
			e.pve.set("/api2/json/nodes/pve1/tasks", body)
			got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
			if err != nil {
				t.Fatal(err)
			}
			if b := got.GetBackups(); b.GetState() != pveUnav || b.GetReason() != pveReasonPartial || len(b.GetBackups()) != 0 {
				t.Fatalf("backups = %v", b)
			}
		})
	}
}

func TestReadPVEBackupsNeedsBackupsGrant(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 240, permit.ProviderMethodTasks, permit.ProviderMethodSnapshots))
	_, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
	wantPveCode(t, err, codes.PermissionDenied)
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("%d requests reached PVE without authority", n)
	}
}

// The backups interval is per guest and the budget is shared per remote.
func TestReadPVEBackupsIntervalAndBudget(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.approve(e.grantDoc(pveReadGrantID, 2, permit.ProviderMethodBackups))
	e.pve.set("/api2/json/nodes/pve1/tasks", `{"data":[]}`)
	if _, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100); err != nil {
		t.Fatal(err)
	}
	_, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
	wantPveCode(t, err, codes.ResourceExhausted)
	if _, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 200); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(2 * time.Minute)
	_, err = e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
	wantPveCode(t, err, codes.ResourceExhausted)
}

func TestReadPVEBackupsTrustChangeBlocksRemote(t *testing.T) {
	e := guestPveEnv(t)
	impostor := makeTestChain(t)
	e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
	e.pve.srv.CloseClientConnections()
	_, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, 100)
	wantPveCode(t, err, codes.FailedPrecondition)
	if e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
		t.Fatal("a request reached the impostor")
	}
}
