// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentNetworkInterfaces(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/qemu/100/agent/network-get-interfaces": "pve8/agent_net_100.json",
	})
	c := clientFor(t, ts)
	res, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatalf("AgentNetworkInterfaces: %v", err)
	}
	if !res.Available || len(res.Interfaces) != 2 {
		t.Fatalf("res = %+v", res)
	}
	eth0 := res.Interfaces[0]
	if eth0.Name != "eth0" || eth0.MAC != "aa:bb:cc:dd:ee:01" || eth0.MTU != 1500 {
		t.Errorf("eth0 = %+v", eth0)
	}
	if len(eth0.IPs) != 2 || eth0.IPs[0].IP != "192.168.1.10" || eth0.IPs[0].Prefix != 24 ||
		eth0.IPs[1].IP != "fe80::aabb:ccdd:ee01" || eth0.IPs[1].Prefix != 64 {
		t.Errorf("eth0.IPs = %+v", eth0.IPs)
	}
	if len(eth0.Flags) != 3 || eth0.Flags[0] != "up" {
		t.Errorf("eth0.Flags = %v", eth0.Flags)
	}
	if res.Interfaces[1].Name != "eth1" || len(res.Interfaces[1].IPs) != 1 {
		t.Errorf("eth1 = %+v", res.Interfaces[1])
	}
}

func TestAgentOSInfo(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/qemu/100/agent/get-osinfo": "pve8/agent_osinfo_100.json",
	})
	c := clientFor(t, ts)
	res, err := c.AgentOSInfo(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatalf("AgentOSInfo: %v", err)
	}
	if !res.Available || res.Version != "12.6" || res.Name != "Debian GNU/Linux" {
		t.Errorf("res = %+v", res)
	}
}

func TestAgentFSInfo(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/qemu/100/agent/get-fsinfo": "pve8/agent_fsinfo_100.json",
	})
	c := clientFor(t, ts)
	res, err := c.AgentFSInfo(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatalf("AgentFSInfo: %v", err)
	}
	if !res.Available || len(res.Filesystems) != 2 {
		t.Fatalf("res = %+v", res)
	}
	root := res.Filesystems[0]
	if root.Name != "/dev/sda1" || root.Mountpoint != "/" || root.Type != "ext4" ||
		root.Size != 34359738368 || root.Used != 8589934592 {
		t.Errorf("root = %+v", root)
	}
}

func agentErrorServer(t *testing.T, status int, message string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"errors":{"%s":%q}}`, r.URL.Path, message)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestAgentUnavailable(t *testing.T) {
	cases := []struct {
		name   string
		status int
		msg    string
	}{
		{"agent not running", http.StatusInternalServerError, "agent is not running"},
		{"guest stopped", http.StatusInternalServerError, "VM 100 is not running"},
		{"node down", http.StatusInternalServerError, "node is down"},
		{"not found", http.StatusNotFound, "no such guest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := clientFor(t, agentErrorServer(t, tc.status, tc.msg))
			res, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
			if err != nil {
				t.Fatalf("AgentNetworkInterfaces: expected unavailable, got error %v", err)
			}
			if res.Available {
				t.Fatal("res.Available = true, want false")
			}
			if res.Reason == "" {
				t.Error("res.Reason empty")
			}
		})
	}
}

func TestAgentServerErrorIsError(t *testing.T) {
	c := clientFor(t, agentErrorServer(t, http.StatusInternalServerError, "internal error"))
	_, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
	if err == nil {
		t.Fatal("expected error for unrelated 500")
	}
	if errors.Is(err, ErrAgentUnavailable) {
		t.Error("unrelated 500 must not be agent-unavailable")
	}
}

func TestAgentMalformed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"data":{"result":[{"name":"eth0","ip-addresses":[{"ip-address":"not-an-ip","prefix":24}]}]}}`))
		})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	_, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
	if err == nil || !errors.Is(err, ErrAgentMalformed) {
		t.Errorf("err = %v, want ErrAgentMalformed", err)
	}
}

func TestAgentInterfaceLimit(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < MaxAgentInterfaces+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"if%d","ip-addresses":[]}`, i)
	}
	b.WriteByte(']')
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"data":{"result":%s}}`, b.String())
		})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := clientFor(t, ts)
	_, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
	if err == nil || !errors.Is(err, ErrAgentMalformed) {
		t.Errorf("err = %v, want ErrAgentMalformed", err)
	}
}

func TestAgentRejectsBadArgs(t *testing.T) {
	ts := fixtureServer(t, map[string]string{})
	c := clientFor(t, ts)
	if _, err := c.AgentOSInfo(context.Background(), "../x", 100); err == nil {
		t.Error("AgentOSInfo: expected error for bad node name")
	}
	if _, err := c.AgentFSInfo(context.Background(), "pve1", -5); err == nil {
		t.Error("AgentFSInfo: expected error for bad vmid")
	}
}

func TestAgentPVE9ResultWrappers(t *testing.T) {
	ts := fixtureServer(t, map[string]string{
		"/nodes/pve1/qemu/100/agent/network-get-interfaces": "pve9/agent_net_100.json",
		"/nodes/pve1/qemu/100/agent/get-osinfo":             "pve9/agent_osinfo_100.json",
		"/nodes/pve1/qemu/100/agent/get-fsinfo":             "pve9/agent_fsinfo_100.json",
	})
	c := clientFor(t, ts)
	net, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !net.Available || len(net.Interfaces) != 1 {
		t.Fatalf("network = %+v", net)
	}
	iface := net.Interfaces[0]
	if iface.Name != "Ethernet" || iface.MAC != "aa:bb:cc:dd:ee:09" || len(iface.IPs) != 1 ||
		iface.IPs[0].IP != "192.0.2.9" || iface.IPs[0].Prefix != 24 {
		t.Errorf("interface = %+v", iface)
	}
	os, err := c.AgentOSInfo(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !os.Available || os.Name != "Microsoft Windows" || os.Version != "10.0" {
		t.Errorf("os = %+v", os)
	}
	fs, err := c.AgentFSInfo(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !fs.Available || len(fs.Filesystems) != 1 {
		t.Fatalf("filesystems = %+v", fs)
	}
	if fs.Filesystems[0].Mountpoint != `C:\` || fs.Filesystems[0].Type != "NTFS" ||
		fs.Filesystems[0].Size != 64<<30 || fs.Filesystems[0].Used != 16<<30 {
		t.Errorf("filesystem = %+v", fs.Filesystems[0])
	}
}

func TestAgentRejectsMalformedResultWrappers(t *testing.T) {
	for _, payload := range []string{`null`, `{}`, `[]`, `{"result":null}`, `{"result":"bad"}`} {
		t.Run(payload, func(t *testing.T) {
			c := newTestClient(t, serveData(t, payload), nil)
			if _, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100); !errors.Is(err, ErrAgentMalformed) {
				t.Errorf("network: err = %v, want ErrAgentMalformed", err)
			}
			if _, err := c.AgentOSInfo(context.Background(), "pve1", 100); !errors.Is(err, ErrAgentMalformed) {
				t.Errorf("osinfo: err = %v, want ErrAgentMalformed", err)
			}
			if _, err := c.AgentFSInfo(context.Background(), "pve1", 100); !errors.Is(err, ErrAgentMalformed) {
				t.Errorf("fsinfo: err = %v, want ErrAgentMalformed", err)
			}
		})
	}
}

func TestAgentActualFieldsStillEnforceLimits(t *testing.T) {
	for _, tc := range []struct {
		command string
		result  string
	}{
		{"network-get-interfaces", `[{"name":"eth0","hardware-address":"AA:BB:CC:DD:EE:01","ip-addresses":[{"ip-address":"invalid","prefix":24}]}]`},
		{"network-get-interfaces", `[{"name":"eth0","ip-addresses":[{"ip-address":"192.0.2.1","prefix":129}]}]`},
		{"get-fsinfo", `[{"name":"sda1","total-bytes":-1}]`},
		{"get-fsinfo", `[{"name":"sda1","used-bytes":-1}]`},
		{"get-fsinfo", `[{"name":"sda1","total-bytes":9223372036854775808}]`},
	} {
		c := newTestClient(t, serveData(t, `{"result":`+tc.result+`}`), nil)
		var err error
		if tc.command == "get-fsinfo" {
			_, err = c.AgentFSInfo(context.Background(), "pve1", 100)
		} else {
			_, err = c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
		}
		if !errors.Is(err, ErrAgentMalformed) {
			t.Errorf("%s: err = %v, want ErrAgentMalformed", tc.command, err)
		}
	}
}

func TestAgentPVEErrorMessages(t *testing.T) {
	for _, tc := range []struct {
		message     string
		status      int
		unavailable bool
	}{
		{"QEMU guest agent is not running", http.StatusInternalServerError, true},
		{"QEMU guest agent is not enabled", http.StatusInternalServerError, true},
		{"No QEMU guest agent configured", http.StatusInternalServerError, true},
		{"VM 100 is not running", http.StatusInternalServerError, true},
		{"node is down", http.StatusInternalServerError, true},
		{"internal storage error", http.StatusInternalServerError, false},
		{"QEMU guest agent command failed: permission denied", http.StatusInternalServerError, false},
		{"guest agent command not supported", http.StatusInternalServerError, false},
		{"permission check failed (VM.GuestAgent.Audit)", http.StatusForbidden, false},
	} {
		t.Run(tc.message, func(t *testing.T) {
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"data":null,"message":%q,"errors":null}`, tc.message)
			}), nil)
			checks := []func() (bool, string, error){
				func() (bool, string, error) {
					r, err := c.AgentNetworkInterfaces(context.Background(), "pve1", 100)
					if err != nil {
						return false, "", err
					}
					return r.Available, r.Reason, nil
				},
				func() (bool, string, error) {
					r, err := c.AgentOSInfo(context.Background(), "pve1", 100)
					if err != nil {
						return false, "", err
					}
					return r.Available, r.Reason, nil
				},
				func() (bool, string, error) {
					r, err := c.AgentFSInfo(context.Background(), "pve1", 100)
					if err != nil {
						return false, "", err
					}
					return r.Available, r.Reason, nil
				},
			}
			for i, check := range checks {
				available, reason, err := check()
				if tc.unavailable {
					if err != nil || available || reason != tc.message {
						t.Errorf("method %d: available=%v reason=%q err=%v", i, available, reason, err)
					}
				} else {
					var se *StatusError
					if !errors.As(err, &se) || se.Code != tc.status || se.Message != tc.message {
						t.Errorf("method %d: err=%v, want original StatusError", i, err)
					}
				}
			}
		})
	}
}
