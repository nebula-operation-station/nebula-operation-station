// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetQemuConfigPVE8(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/qemu/100/config": "pve8/qemu_config_100.json",
	})
	c := clientFor(t, ts)
	cfg, err := c.GetQemuConfig(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatalf("GetQemuConfig: %v", err)
	}
	if cfg.Name != "web1" || cfg.Kind != KindQemu || cfg.VMID != 100 || cfg.Node != "pve1" {
		t.Errorf("identity = %+v", cfg)
	}
	if cfg.CPUs != 4 {
		t.Errorf("CPUs = %d, want 4 (2 cores x 2 sockets)", cfg.CPUs)
	}
	if cfg.Memory != 4<<30 || cfg.Balloon != 1<<30 {
		t.Errorf("Memory/Balloon = %d/%d", cfg.Memory, cfg.Balloon)
	}
	if cfg.Boot != "order=scsi0;ide2" || cfg.Pool != "web" {
		t.Errorf("Boot/Pool = %q/%q", cfg.Boot, cfg.Pool)
	}
	if len(cfg.Tags) != 2 || cfg.Tags[0] != "web" || cfg.Tags[1] != "production" {
		t.Errorf("Tags = %v", cfg.Tags)
	}
	if len(cfg.NICs) != 2 {
		t.Fatalf("NICs = %+v, want 2", cfg.NICs)
	}
	if cfg.NICs[0].Device != "net0" || cfg.NICs[0].Bridge != "vmbr0" || cfg.NICs[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("NICs[0] = %+v", cfg.NICs[0])
	}
	if cfg.NICs[1].VLAN != 5 || cfg.NICs[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("NICs[1] = %+v", cfg.NICs[1])
	}
	if len(cfg.Disks) != 3 {
		t.Fatalf("Disks = %+v, want 3", cfg.Disks)
	}
	d := cfg.Disks[0]
	if d.Device != "scsi0" || d.Volume != "local-lvm:vm-100-disk-0" || d.Storage != "local-lvm" || d.Size != 32<<30 {
		t.Errorf("Disks[0] = %+v", d)
	}
	if len(cfg.HostPCI) != 2 {
		t.Fatalf("HostPCI = %+v, want 2", cfg.HostPCI)
	}
	if cfg.HostPCI[0].PCIAddress != "0000:01:00.0" || cfg.HostPCI[0].Extras["rom"] != "disabled" {
		t.Errorf("HostPCI[0] = %+v", cfg.HostPCI[0])
	}
	if cfg.HostPCI[1].Mapping != "gpu0" {
		t.Errorf("HostPCI[1] = %+v", cfg.HostPCI[1])
	}
	if len(cfg.CloudInitIP) != 1 || cfg.CloudInitIP[0] != "ip=192.168.1.10/24,gw=192.168.1.1" {
		t.Errorf("CloudInitIP = %v", cfg.CloudInitIP)
	}
	if cfg.SSHKeyCount != 3 {
		t.Errorf("SSHKeyCount = %d, want 3", cfg.SSHKeyCount)
	}
	if cfg.DroppedSecrets != 3 {
		t.Errorf("DroppedSecrets = %d, want 3 (cipassword, mysecret, apitoken)", cfg.DroppedSecrets)
	}
	if cfg.Ctime == nil || cfg.Ctime.Unix() != 1750000000 {
		t.Errorf("Ctime = %v", cfg.Ctime)
	}
	if cfg.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("UUID = %q", cfg.UUID)
	}
	for _, k := range []string{"nameserver", "searchdomain", "onboot", "bootdisk"} {
		if _, ok := cfg.Extras[k]; !ok {
			t.Errorf("Extras missing %q", k)
		}
	}
	for _, k := range []string{"cipassword", "sshkeys", "snippets", "description", "mysecret", "apitoken"} {
		if _, ok := cfg.Extras[k]; ok {
			t.Errorf("Extras contains forbidden key %q", k)
		}
	}
	marshaled, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"S3cr3tPassword!", "fakekeyone", "should-be-dropped", "also-dropped", "secret note"} {
		if strings.Contains(string(marshaled), secret) {
			t.Errorf("marshaled config contains secret material %q", secret)
		}
	}
}

func TestGetQemuConfigPVE9(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/qemu/100/config": "pve9/qemu_config_100.json",
	})
	c := clientFor(t, ts)
	cfg, err := c.GetQemuConfig(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatalf("GetQemuConfig: %v", err)
	}
	if cfg.CPUs != 4 || cfg.Memory != 4<<30 || cfg.SSHKeyCount != 1 || cfg.DroppedSecrets != 1 {
		t.Errorf("cfg = CPUs %d, Memory %d, SSHKeyCount %d, DroppedSecrets %d",
			cfg.CPUs, cfg.Memory, cfg.SSHKeyCount, cfg.DroppedSecrets)
	}
	for _, k := range []string{"machine", "vga", "tablet", "tun0", "agent"} {
		if _, ok := cfg.Extras[k]; !ok {
			t.Errorf("Extras missing PVE 9 key %q", k)
		}
	}
	if cfg.Extras["machine"] != "q35" {
		t.Errorf("machine = %q", cfg.Extras["machine"])
	}
}

func TestGetLxcConfig(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/lxc/200/config": "pve8/lxc_config_200.json",
	})
	c := clientFor(t, ts)
	cfg, err := c.GetLxcConfig(context.Background(), "pve1", 200)
	if err != nil {
		t.Fatalf("GetLxcConfig: %v", err)
	}
	if cfg.Kind != KindLxc || cfg.Name != "cache1" || cfg.CPUs != 2 {
		t.Errorf("identity = %+v", cfg)
	}
	if cfg.Memory != 2<<30 || cfg.Swap != 512<<20 {
		t.Errorf("Memory/Swap = %d/%d", cfg.Memory, cfg.Swap)
	}
	if cfg.OSType != "linux" || cfg.Hostname != "cache1.lab.example" {
		t.Errorf("OSType/Hostname = %q/%q", cfg.OSType, cfg.Hostname)
	}
	if len(cfg.Disks) != 1 || cfg.Disks[0].Device != "rootfs" ||
		cfg.Disks[0].Storage != "local-lvm" || cfg.Disks[0].Size != 8<<30 {
		t.Errorf("Disks = %+v", cfg.Disks)
	}
	if len(cfg.Mounts) != 1 || cfg.Mounts[0].Volume != "local:200" || cfg.Mounts[0].Mount != "/var/cache" {
		t.Errorf("Mounts = %+v", cfg.Mounts)
	}
	if len(cfg.NICs) != 1 || cfg.NICs[0].Bridge != "vmbr0" ||
		cfg.NICs[0].MAC != "aa:bb:cc:dd:ee:20" || cfg.NICs[0].VLAN != 3 {
		t.Errorf("NICs = %+v", cfg.NICs)
	}
	if cfg.Features["nesting"] != "1" || cfg.Features["keys"] != "0" {
		t.Errorf("Features = %v", cfg.Features)
	}
	if cfg.SSHKeyCount != 1 || cfg.DroppedSecrets != 0 {
		t.Errorf("SSHKeyCount/DroppedSecrets = %d/%d", cfg.SSHKeyCount, cfg.DroppedSecrets)
	}
	if _, ok := cfg.Extras["description"]; ok {
		t.Error("Extras contains description")
	}
}

func TestSecretKeysDropped(t *testing.T) {
	secrets := map[string]string{
		"cipassword":   "pw1",
		"db_password":  "pw2",
		"foo_secret":   "s1",
		"api_token":    "t1",
		"sessiontoken": "t2",
		"sshkeys":      "keyline",
		"snippets":     "cloud-init",
		"description":  "desc",
		"cores":        "2",
	}
	body, err := json.Marshal(secrets)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data":%s}`, body)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	cfg, err := c.GetQemuConfig(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatalf("GetQemuConfig: %v", err)
	}
	// cipassword, db_password, foo_secret, api_token, sessiontoken
	if cfg.DroppedSecrets != 5 {
		t.Errorf("DroppedSecrets = %d, want 5", cfg.DroppedSecrets)
	}
	if cfg.SSHKeyCount != 1 {
		t.Errorf("SSHKeyCount = %d, want 1", cfg.SSHKeyCount)
	}
	if cfg.CPUs != 2 {
		t.Errorf("CPUs = %d, want 2", cfg.CPUs)
	}
	for k := range secrets {
		if k == "cores" {
			continue
		}
		if _, ok := cfg.Extras[k]; ok {
			t.Errorf("Extras contains dropped key %q", k)
		}
	}
}

func TestConfigTextLimit(t *testing.T) {
	longName := strings.Repeat("a", 5000)
	body := fmt.Sprintf(`{"name":%q,"cores":"1"}`, longName)
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data":%s}`, body)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	cfg, err := c.GetQemuConfig(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatalf("GetQemuConfig: %v", err)
	}
	if len(cfg.Name) > MaxTextFieldBytes {
		t.Errorf("Name length = %d, want <= %d", len(cfg.Name), MaxTextFieldBytes)
	}
}

func TestConfigBadSize(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"memory":"abc"}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	if _, err := c.GetQemuConfig(context.Background(), "pve1", 100); err == nil {
		t.Fatal("GetQemuConfig: expected error for bad memory size")
	}
}

func TestGetConfigRejectsBadArgs(t *testing.T) {
	ts := fixtureServer(t, map[string]string{})
	c := clientFor(t, ts)
	if _, err := c.GetQemuConfig(context.Background(), "../x", 100); err == nil {
		t.Error("GetQemuConfig: expected error for bad node name")
	}
	if _, err := c.GetLxcConfig(context.Background(), "pve1", 0); err == nil {
		t.Error("GetLxcConfig: expected error for vmid 0")
	}
}

func TestParseSizeBytes(t *testing.T) {
	cases := []struct {
		in      string
		plain   int64
		want    int64
		wantErr bool
	}{
		{"32G", 1, 32 << 30, false},
		{"1024M", 1, 1 << 30, false},
		{"512K", 1, 512 << 10, false},
		{"1T", 1, 1 << 40, false},
		{"1048576", 1024, 1 << 30, false}, // plain KiB memory
		{"", 1024, 0, false},
		{"abc", 1, 0, true},
		{"-1G", 1, 0, true},
		{"10X", 1, 0, true},
	}
	for _, tc := range cases {
		got, err := parseSizeBytes(tc.in, tc.plain)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseSizeBytes(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseSizeBytes(%q, %d) = %d, %v; want %d", tc.in, tc.plain, got, err, tc.want)
		}
	}
}
