// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const testPassword = "s3cret-Pa55word!"

// testAuthorizedKey returns a deterministic ed25519 authorized_keys line.
func testAuthorizedKey(t *testing.T, seed byte) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(append(make([]byte, 31), seed))
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func fullConfigRequest(t *testing.T) ConfigRequest {
	agent := true
	return ConfigRequest{
		Node: "pve1", VMID: 120,
		Name: "web-01", Cores: 2, MemoryMiB: 4096, Agent: &agent,
		Net0:          &NetConfig{Bridge: "vmbr0", Tag: 30, MAC: "bc:24:11:00:00:01"},
		IPConfig0:     &IPConfig{Address: netip.MustParsePrefix("10.0.30.5/24"), Gateway: netip.MustParseAddr("10.0.30.1")},
		CIUser:        "nos",
		SSHKeys:       []string{testAuthorizedKey(t, 1) + " nos@automation", `command="x" ` + testAuthorizedKey(t, 2)},
		CIPassword:    NewSecret(testPassword),
		Nameservers:   []netip.Addr{netip.MustParseAddr("10.0.30.1"), netip.MustParseAddr("2001:db8::53")},
		SearchDomains: []string{"lab.example", "example"},
	}
}

func TestSetConfigSendsOnlyAllowlistedFields(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidConfig)}
	w := newTestWriter(t, f)
	got, err := w.SetConfig(context.Background(), fullConfigRequest(t))
	if err != nil || got != upidConfig {
		t.Fatalf("SetConfig = %q, %v", got, err)
	}
	r := f.only(t)
	if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/qemu/120/config" {
		t.Errorf("request = %s %s", r.method, r.path)
	}
	keys := strings.Join([]string{testAuthorizedKey(t, 1), testAuthorizedKey(t, 2)}, "\n")
	want := map[string]string{
		"name":         "web-01",
		"cores":        "2",
		"memory":       "4096",
		"agent":        "enabled=1",
		"net0":         "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=30",
		"ipconfig0":    "ip=10.0.30.5/24,gw=10.0.30.1",
		"ciuser":       "nos",
		"sshkeys":      strings.ReplaceAll(url.QueryEscape(keys), "+", "%20"),
		"cipassword":   testPassword,
		"nameserver":   "10.0.30.1 2001:db8::53",
		"searchdomain": "lab.example example",
	}
	if len(r.form) != len(want) {
		t.Errorf("form has %d keys, want %d: %v", len(r.form), len(want), r.form)
	}
	for k, v := range want {
		if got := r.form[k]; len(got) != 1 || got[0] != v {
			t.Errorf("form[%s] = %q, want %q", k, got, v)
		}
	}
	// The PVE-side decoding of sshkeys yields canonical keys without
	// options or comments.
	dec, err := url.QueryUnescape(r.form.Get("sshkeys"))
	if err != nil || dec != keys {
		t.Errorf("decoded sshkeys = %q, %v", dec, err)
	}
}

func TestSetConfigMinimalAndDHCP(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidConfig)}
	w := newTestWriter(t, f)
	off := false
	_, err := w.SetConfig(context.Background(), ConfigRequest{
		Node: "pve1", VMID: 120, Agent: &off,
		Net0:      &NetConfig{Model: NICE1000, Bridge: "vnet10"},
		IPConfig0: &IPConfig{DHCP: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.only(t)
	want := url.Values{"agent": {"enabled=0"}, "net0": {"e1000,bridge=vnet10"}, "ipconfig0": {"ip=dhcp"}}
	if r.form.Encode() != want.Encode() {
		t.Errorf("form = %v, want %v", r.form, want)
	}
}

func TestSetConfigRejectsInvalidFields(t *testing.T) {
	cases := map[string]func(*ConfigRequest){
		"no fields":            func(r *ConfigRequest) { *r = ConfigRequest{Node: "pve1", VMID: 120} },
		"node":                 func(r *ConfigRequest) { r.Node = "pve1/../x" },
		"vmid":                 func(r *ConfigRequest) { r.VMID = 1 },
		"name":                 func(r *ConfigRequest) { r.Name = "web_01" },
		"cores low":            func(r *ConfigRequest) { r.Cores = -1 },
		"cores high":           func(r *ConfigRequest) { r.Cores = MaxCores + 1 },
		"memory low":           func(r *ConfigRequest) { r.MemoryMiB = MinMemoryMiB - 1 },
		"memory high":          func(r *ConfigRequest) { r.MemoryMiB = MaxMemoryMiB + 1 },
		"net model":            func(r *ConfigRequest) { r.Net0.Model = "virtio,firewall=0" },
		"net bridge comma":     func(r *ConfigRequest) { r.Net0.Bridge = "vmbr0,rate=1" },
		"net bridge empty":     func(r *ConfigRequest) { r.Net0.Bridge = "" },
		"net bridge long":      func(r *ConfigRequest) { r.Net0.Bridge = "vmbr0123456789ab" },
		"net tag high":         func(r *ConfigRequest) { r.Net0.Tag = MaxVLANTag + 1 },
		"net tag negative":     func(r *ConfigRequest) { r.Net0.Tag = -1 },
		"net mac multicast":    func(r *ConfigRequest) { r.Net0.MAC = "01:00:5e:00:00:01" },
		"net mac zero":         func(r *ConfigRequest) { r.Net0.MAC = "00:00:00:00:00:00" },
		"net mac eui64":        func(r *ConfigRequest) { r.Net0.MAC = "02:00:00:00:00:00:00:01" },
		"net mac garbage":      func(r *ConfigRequest) { r.Net0.MAC = "bc:24:11:00:00:01,x" },
		"ip dhcp plus static":  func(r *ConfigRequest) { r.IPConfig0.DHCP = true },
		"ip unset":             func(r *ConfigRequest) { r.IPConfig0 = &IPConfig{} },
		"ip v6":                func(r *ConfigRequest) { r.IPConfig0 = &IPConfig{Address: netip.MustParsePrefix("2001:db8::5/64")} },
		"ip loopback":          func(r *ConfigRequest) { r.IPConfig0.Address = netip.MustParsePrefix("127.0.0.2/8") },
		"ip zero bits":         func(r *ConfigRequest) { r.IPConfig0.Address = netip.MustParsePrefix("10.0.0.5/0") },
		"gw outside":           func(r *ConfigRequest) { r.IPConfig0.Gateway = netip.MustParseAddr("10.0.31.1") },
		"gw equals ip":         func(r *ConfigRequest) { r.IPConfig0.Gateway = netip.MustParseAddr("10.0.30.5") },
		"ciuser":               func(r *ConfigRequest) { r.CIUser = "Root;x" },
		"ciuser long":          func(r *ConfigRequest) { r.CIUser = strings.Repeat("a", 33) },
		"sshkeys empty":        func(r *ConfigRequest) { r.SSHKeys = []string{} },
		"sshkeys garbage":      func(r *ConfigRequest) { r.SSHKeys = []string{"ssh-ed25519 AAAA notakey"} },
		"sshkeys newline":      func(r *ConfigRequest) { r.SSHKeys = []string{testAuthorizedKey(t, 1) + "\n" + testAuthorizedKey(t, 2)} },
		"sshkeys too many":     func(r *ConfigRequest) { r.SSHKeys = make([]string, MaxSSHKeys+1) },
		"password short":       func(r *ConfigRequest) { r.CIPassword = NewSecret("short") },
		"password control":     func(r *ConfigRequest) { r.CIPassword = NewSecret("password\nwith-newline") },
		"password long":        func(r *ConfigRequest) { r.CIPassword = NewSecret(strings.Repeat("p", MaxPasswordBytes+1)) },
		"password utf8":        func(r *ConfigRequest) { r.CIPassword = NewSecret("password\xff\xfe") },
		"nameserver empty":     func(r *ConfigRequest) { r.Nameservers = []netip.Addr{} },
		"nameserver too many":  func(r *ConfigRequest) { r.Nameservers = make([]netip.Addr, MaxNameservers+1) },
		"nameserver invalid":   func(r *ConfigRequest) { r.Nameservers = []netip.Addr{{}} },
		"nameserver zone":      func(r *ConfigRequest) { r.Nameservers = []netip.Addr{netip.MustParseAddr("fe80::1%eth0")} },
		"searchdomain invalid": func(r *ConfigRequest) { r.SearchDomains = []string{"lab example"} },
		"searchdomain many":    func(r *ConfigRequest) { r.SearchDomains = make([]string, MaxSearchDomains+1) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidConfig)}
			w := newTestWriter(t, f)
			r := fullConfigRequest(t)
			mut(&r)
			_, err := w.SetConfig(context.Background(), r)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Errorf("error leaks password: %v", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

// TestSetConfigPasswordNeverInErrors drives every failure path with a
// password set and checks the password never appears in the error.
func TestSetConfigPasswordNeverInErrors(t *testing.T) {
	bodies := []struct {
		status int
		body   string
	}{
		{400, `{"errors":{"cipassword":"invalid: ` + testPassword + `"},"data":null}`},
		{500, `{"message":"` + testPassword + `"}`},
		{200, `{"data":"` + testPassword + `"}`},
		{200, `{"data":null,"message":"` + testPassword + `"}`},
	}
	for i, b := range bodies {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := &fakeWriteServer{status: b.status, body: b.body}
			w := newTestWriter(t, f)
			_, err := w.SetConfig(context.Background(), fullConfigRequest(t))
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), testPassword) || strings.Contains(fmt.Sprintf("%+v", err), testPassword) {
				t.Errorf("error leaks password: %v", err)
			}
		})
	}
	// Invalid argument errors carry no password either.
	r := fullConfigRequest(t)
	r.CIPassword = NewSecret("bad\x01" + testPassword)
	_, err := newTestWriter(t, &fakeWriteServer{}).SetConfig(context.Background(), r)
	if err == nil || strings.Contains(err.Error(), testPassword) {
		t.Errorf("err = %v", err)
	}
}

func TestSecretNeverFormatsValue(t *testing.T) {
	r := fullConfigRequest(t)
	j, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		fmt.Sprint(r), fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r),
		fmt.Sprintf("%s", r.CIPassword), fmt.Sprintf("%q", r.CIPassword), string(j),
	} {
		if strings.Contains(s, testPassword) {
			t.Errorf("formatted request leaks password: %s", s)
		}
	}
}
