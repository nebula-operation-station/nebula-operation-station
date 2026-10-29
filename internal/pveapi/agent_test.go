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
			w.Write([]byte(`{"data":[{"name":"eth0","ip-address":[{"ip-address":"not-an-ip","prefix":24}]}]}`))
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
		fmt.Fprintf(&b, `{"name":"if%d","ip-address":[]}`, i)
	}
	b.WriteByte(']')
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"data":%s}`, b.String())
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
