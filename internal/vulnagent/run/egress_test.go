// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
)

// dialLog records every address the LLM dialer actually connects to and
// sends lab addresses to the fake LLM.
type dialLog struct {
	mu     sync.Mutex
	addrs  []string
	target string // the fake LLM's listener address
}

func (d *dialLog) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

func (d *dialLog) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// proxyListener stands in for a proxy and counts connections.
func proxyListener(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	return "http://" + l.Addr().String(), &n
}

func setProxyEnv(t *testing.T, proxy string) {
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, proxy)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
}

func resolveTo(addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, len(addrs))
		for i, a := range addrs {
			out[i] = netip.MustParseAddr(a)
		}
		return out, nil
	}
}

func assertSentWithoutText(t *testing.T, e *env, rep *Report) {
	t.Helper()
	if rep.LLM.Assessed != 0 {
		t.Errorf("assessed = %d", rep.LLM.Assessed)
	}
	recs := e.nos.sentRecords(t)
	if len(recs) != 1 || recs[0].Assessment.Text != "" {
		t.Errorf("finding not sent without text: %+v", recs)
	}
	e.assertNoSecrets(t)
}

func TestLLMEndpointRefusesNonLabAddress(t *testing.T) {
	type tc struct {
		served  string
		mutate  func(*Config, *dialLog)
		preseed bool // the endpoint passes the start check, the dialer refuses later
	}
	cases := map[string]tc{
		"public ip literal": {served: "https://203.0.113.7/v1"},
		"host name to public address": {served: "https://llm.lab/v1", mutate: func(c *Config, _ *dialLog) {
			c.LLMNet.Resolve = resolveTo("198.51.100.9")
		}},
		"host name with one public address": {served: "https://llm.lab/v1", mutate: func(c *Config, _ *dialLog) {
			c.LLMNet.Resolve = resolveTo("10.0.0.5", "198.51.100.9")
		}},
		"dns change after the start check": {served: "https://example.com/v1", preseed: true, mutate: func(c *Config, _ *dialLog) {
			var n atomic.Int64
			c.LLMNet.Resolve = func(context.Context, string) ([]netip.Addr, error) {
				if n.Add(1) == 1 {
					return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
			}
		}},
		"ipv4-mapped public":         {served: "https://[::ffff:203.0.113.7]/v1"},
		"nat64 with rfc1918":         {served: "https://[64:ff9b::a00:5]/v1"},
		"local-use nat64":            {served: "https://[64:ff9b:1::a00:5]/v1"},
		"cgnat without allowed list": {served: "https://100.64.1.2/v1"},
		"link-local":                 {served: "https://[fe80::1]/v1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			d := &dialLog{target: e.llm.srv.Listener.Addr().String()}
			e.nos.setLLM(true, c.served, "nos-model")
			r := e.runner(t, func(cfg *Config) {
				cfg.LLMNet.Dial = d.dial
				if c.mutate != nil {
					c.mutate(cfg, d)
				}
			})
			rep, err := r.Run(context.Background(), ModeRun)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := d.dialed(); len(got) != 0 {
				t.Errorf("dialed %v", got)
			}
			if e.llm.callCount() != 0 {
				t.Errorf("llm called %d times", e.llm.callCount())
			}
			if !c.preseed && (rep.LLM.Enabled || !rep.LLM.Failed || !strings.Contains(rep.LLM.Reason, "not a lab address")) {
				t.Errorf("llm evidence = %+v", rep.LLM)
			}
			if !rep.Degraded() && !c.preseed {
				t.Error("refused endpoint did not degrade the run")
			}
			assertSentWithoutText(t, e, rep)
		})
	}

	t.Run("redirect to public address", func(t *testing.T) {
		e := newEnv(t)
		redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://203.0.113.7/v1/chat/completions", http.StatusTemporaryRedirect)
		}))
		t.Cleanup(redir.Close)
		e.llm.srv = redir // trusted roots come from this server
		d := &dialLog{target: redir.Listener.Addr().String()}
		e.nos.setLLM(true, redir.URL+"/v1", "nos-model")
		rep, err := e.runner(t, func(c *Config) { c.LLMNet.Dial = d.dial }).Run(context.Background(), ModeRun)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		for _, a := range d.dialed() {
			if !strings.HasPrefix(a, "127.0.0.1:") {
				t.Errorf("redirect followed to %s", a)
			}
		}
		assertSentWithoutText(t, e, rep)
	})

	t.Run("proxy variables set", func(t *testing.T) {
		proxy, hits := proxyListener(t)
		setProxyEnv(t, proxy)
		e := newEnv(t)
		e.nos.setLLM(true, "https://203.0.113.7/v1", "nos-model")
		rep, err := e.runner(t).Run(context.Background(), ModeRun)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if hits.Load() != 0 {
			t.Errorf("proxy saw %d connections", hits.Load())
		}
		if rep.LLM.Enabled || !rep.LLM.Failed {
			t.Errorf("llm evidence = %+v", rep.LLM)
		}
		assertSentWithoutText(t, e, rep)
	})

	for name, nets := range map[string][]string{
		"allowed network outside ranges": {"203.0.113.0/24"},
		"allowed network too wide":       {"10.0.0.0/7"},
		"allowed network nat64":          {"64:ff9b::/96"},
		"allowed network inside nat64":   {"64:ff9b::a00:0/120"},
		"allowed network mapped":         {"::ffff:10.0.0.0/104"},
		"allowed network not a prefix":   {"10.0.0.1"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			cfg := e.config(t)
			cfg.LLM.AllowedNetworks = nets
			if _, err := New(cfg); !errors.Is(err, ErrConfig) {
				t.Errorf("New = %v, want ErrConfig", err)
			}
			if e.llm.callCount() != 0 || e.nos.postCount() != 0 {
				t.Error("request left with a refused configuration")
			}
		})
	}
}

func TestLLMEndpointAcceptsLabAddress(t *testing.T) {
	assessed := func(t *testing.T, e *env, rep *Report, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if !rep.LLM.Enabled || rep.LLM.Failed || rep.LLM.Assessed != 1 {
			t.Errorf("llm evidence = %+v", rep.LLM)
		}
		e.assertNoSecrets(t)
	}

	t.Run("loopback", func(t *testing.T) {
		e := newEnv(t)
		e.nos.setLLM(true, e.llm.srv.URL+"/v1", "nos-model")
		rep, err := e.runner(t).Run(context.Background(), ModeRun)
		assessed(t, e, rep, err)
	})

	t.Run("unix socket", func(t *testing.T) {
		e := newEnv(t)
		dir, err := os.MkdirTemp("", "llm")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		sock := filepath.Join(dir, "s")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewUnstartedServer(e.llm.handler())
		_ = srv.Listener.Close()
		srv.Listener = l
		srv.StartTLS()
		t.Cleanup(srv.Close)
		e.llm.srv = srv
		// The host only names the certificate; the socket is what is dialed.
		e.nos.setLLM(true, "https://example.com/v1", "nos-model")
		rep, err := e.runner(t, func(c *Config) {
			c.LLM.UnixSocket = sock
			c.LLMNet.Resolve = func(context.Context, string) ([]netip.Addr, error) {
				t.Error("resolver used with a Unix socket")
				return nil, errors.New("no")
			}
		}).Run(context.Background(), ModeRun)
		assessed(t, e, rep, err)
	})

	for name, addr := range map[string]string{
		"rfc1918 via injected dialer": "10.20.30.40",
		"ipv4-mapped rfc1918":         "::ffff:10.20.30.40",
		"ula":                         "fd00::5",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			d := &dialLog{target: e.llm.srv.Listener.Addr().String()}
			e.nos.setLLM(true, "https://example.com:8443/v1", "nos-model")
			rep, err := e.runner(t, func(c *Config) {
				c.LLMNet.Resolve = resolveTo(addr)
				c.LLMNet.Dial = d.dial
			}).Run(context.Background(), ModeRun)
			assessed(t, e, rep, err)
			want := netip.AddrPortFrom(netip.MustParseAddr(addr).Unmap(), 8443).String()
			for _, a := range d.dialed() {
				if a != want {
					t.Errorf("dialed %s, want %s", a, want)
				}
			}
		})
	}

	t.Run("allowed overlay network", func(t *testing.T) {
		e := newEnv(t)
		d := &dialLog{target: e.llm.srv.Listener.Addr().String()}
		e.nos.setLLM(true, "https://example.com/v1", "nos-model")
		rep, err := e.runner(t, func(c *Config) {
			c.LLM.AllowedNetworks = []string{"100.64.0.0/16"}
			c.LLMNet.Resolve = resolveTo("100.64.3.4")
			c.LLMNet.Dial = d.dial
		}).Run(context.Background(), ModeRun)
		assessed(t, e, rep, err)
	})

	t.Run("plain http", func(t *testing.T) {
		plain := func(t *testing.T) *env {
			e := newEnv(t)
			srv := httptest.NewServer(e.llm.handler())
			t.Cleanup(srv.Close)
			e.nos.setLLM(true, srv.URL+"/v1", "nos-model")
			return e
		}
		// Refused without llm.allow_plain_http.
		e := plain(t)
		rep, err := e.runner(t).Run(context.Background(), ModeRun)
		if err != nil || rep.LLM.Enabled || !rep.LLM.Failed || e.llm.callCount() != 0 {
			t.Errorf("plain http without permission: %v %+v calls %d", err, rep.LLM, e.llm.callCount())
		}
		// Refused with a configured credential.
		e = plain(t)
		rep, err = e.runner(t, func(c *Config) { c.LLM.AllowPlainHTTP = true }).Run(context.Background(), ModeRun)
		if err != nil || rep.LLM.Enabled || !rep.LLM.Failed || e.llm.callCount() != 0 {
			t.Errorf("plain http with key: %v %+v calls %d", err, rep.LLM, e.llm.callCount())
		}
		e.assertNoSecrets(t)
		// Accepted with permission and without a key.
		e = plain(t)
		rep, err = e.runner(t, func(c *Config) { c.LLM.AllowPlainHTTP, c.LLM.APIKeyFile = true, "" }).Run(context.Background(), ModeRun)
		assessed(t, e, rep, err)
	})

	t.Run("proxy ignored", func(t *testing.T) {
		proxy, hits := proxyListener(t)
		setProxyEnv(t, proxy)
		e := newEnv(t)
		e.nos.setLLM(true, e.llm.srv.URL+"/v1", "nos-model")
		var tr http.RoundTripper
		rep, err := e.runner(t, func(c *Config) {
			c.NewLLM = func(cc agent.ClientConfig) (agent.LLM, error) {
				tr = cc.Transport
				return agent.NewHTTPClient(cc)
			}
		}).Run(context.Background(), ModeRun)
		assessed(t, e, rep, err)
		if e.llm.callCount() == 0 || hits.Load() != 0 {
			t.Errorf("llm calls %d, proxy connections %d", e.llm.callCount(), hits.Load())
		}
		ht, ok := tr.(*http.Transport)
		if !ok || ht.Proxy != nil {
			t.Errorf("transport %T has a proxy function", tr)
		}
	})
}

func TestLabAddressRanges(t *testing.T) {
	allowed, err := ParseAllowedNetworks([]string{"100.64.0.0/10", "10.1.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for a, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "10.9.9.9": true, "172.31.0.1": true, "192.168.1.1": true,
		"fd12::1": true, "::ffff:192.168.1.1": true, "100.100.1.1": true,
		"172.32.0.1": false, "8.8.8.8": false, "::ffff:8.8.8.8": false, "64:ff9b::a00:5": false,
		"64:ff9b:1::c0a8:101": false, "fe80::1": false, "2001:db8::1": false, "0.0.0.0": false, "::": false,
		"169.254.1.1": false, "224.0.0.1": false,
	} {
		if got := labAddress(netip.MustParseAddr(a), allowed); got != want {
			t.Errorf("labAddress(%s) = %v, want %v", a, got, want)
		}
	}
	if labAddress(netip.MustParseAddr("100.64.0.1"), nil) {
		t.Error("100.64.0.0/10 permitted without llm.allowed_networks")
	}
	if _, err := ParseAllowedNetworks(make([]string, MaxAllowedNetworks+1)); !errors.Is(err, ErrConfig) {
		t.Errorf("too many networks = %v", err)
	}
}
