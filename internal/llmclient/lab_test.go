// SPDX-License-Identifier: AGPL-3.0-or-later

package llmclient

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
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
	"time"
)

// okHandler answers every chat call with one content string.
func okHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
}

// dialLog records every address the lab dialer actually connects to and
// sends the connection to target instead (the fake endpoint).
type dialLog struct {
	mu     sync.Mutex
	addrs  []string
	target string
}

func (d *dialLog) dial(ctx context.Context, _ string, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.target)
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
	t.Helper()
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

func poolOf(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

// labOpts are lab-only options for a TLS endpoint served by srv.
func labOpts(srv *httptest.Server, base string, net Network) Options {
	if net.RootCAs == nil {
		net.RootCAs = poolOf(srv)
	}
	return Options{BaseURL: base, Model: "m", Timeout: 5 * time.Second, LabOnly: true, Network: net}
}

func TestLabAddressRanges(t *testing.T) {
	allowed, err := ParseNetworks([]string{"100.64.0.0/10", "10.1.0.0/16"})
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
		t.Error("100.64.0.0/10 permitted without a configured network")
	}
	if _, err := ParseNetworks(make([]string, MaxNetworks+1)); !errors.Is(err, ErrConfig) {
		t.Errorf("too many networks = %v", err)
	}
}

func TestParseNetworksRefusesOutsideLabRanges(t *testing.T) {
	for name, nets := range map[string][]string{
		"outside ranges":    {"203.0.113.0/24"},
		"too wide":          {"10.0.0.0/7"},
		"nat64":             {"64:ff9b::/96"},
		"inside nat64":      {"64:ff9b::a00:0/120"},
		"mapped":            {"::ffff:10.0.0.0/104"},
		"not a prefix":      {"10.0.0.1"},
		"zone":              {"fe80::1%eth0/64"},
		"public inside 100": {"100.128.0.0/16"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNetworks(nets); !errors.Is(err, ErrConfig) {
				t.Errorf("ParseNetworks(%v) = %v, want ErrConfig", nets, err)
			}
		})
	}
	got, err := ParseNetworks([]string{"10.1.2.3/16"})
	if err != nil || len(got) != 1 || got[0].String() != "10.1.0.0/16" {
		t.Errorf("ParseNetworks masks: %v %v", got, err)
	}
}

// TestLabEndpointRefusesNonLabAddress: the endpoint is refused at the start
// check and, when DNS changes later, by the dialer on the connection.
func TestLabEndpointRefusesNonLabAddress(t *testing.T) {
	type tc struct {
		base    string
		network func(*dialLog) Network
	}
	cases := map[string]tc{
		"public ip literal":           {base: "https://203.0.113.7/v1"},
		"host name to public address": {base: "https://llm.lab/v1", network: func(*dialLog) Network { return Network{Resolve: resolveTo("198.51.100.9")} }},
		"host name with one public address": {base: "https://llm.lab/v1", network: func(*dialLog) Network {
			return Network{Resolve: resolveTo("10.0.0.5", "198.51.100.9")}
		}},
		"ipv4-mapped public": {base: "https://[::ffff:203.0.113.7]/v1"},
		"nat64 with rfc1918": {base: "https://[64:ff9b::a00:5]/v1"},
		"local-use nat64":    {base: "https://[64:ff9b:1::a00:5]/v1"},
		"cgnat unlisted":     {base: "https://100.64.1.2/v1"},
		"link-local":         {base: "https://[fe80::1]/v1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(okHandler))
			t.Cleanup(srv.Close)
			d := &dialLog{target: srv.Listener.Addr().String()}
			var n Network
			if c.network != nil {
				n = c.network(d)
			}
			n.Dial = d.dial
			n.RootCAs = poolOf(srv)
			o := labOpts(srv, c.base, n)
			err := CheckEndpoint(context.Background(), o)
			if !errors.Is(err, ErrNotLabAddress) {
				t.Fatalf("CheckEndpoint = %v, want ErrNotLabAddress", err)
			}
			if !strings.Contains(err.Error(), "not a lab address") {
				t.Errorf("message %q", err)
			}
			if got := d.dialed(); len(got) != 0 {
				t.Errorf("dialed %v", got)
			}
		})
	}
}

func TestLabEndpointRefusesDNSChangeOnConnection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(okHandler))
	t.Cleanup(srv.Close)
	d := &dialLog{target: srv.Listener.Addr().String()}
	var n atomic.Int64
	res := func(context.Context, string) ([]netip.Addr, error) {
		if n.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
	}
	o := labOpts(srv, "https://example.com/v1", Network{Resolve: res, Dial: d.dial})
	if err := CheckEndpoint(context.Background(), o); err != nil {
		t.Fatalf("start check: %v", err)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Chat(context.Background(), Request{MaxTokens: 1}); !errors.Is(err, ErrCall) {
		t.Fatalf("Chat after DNS change = %v, want ErrCall", err)
	}
	// The dialer resolves again on the connection; the public answer must
	// never be connected to.
	for _, a := range d.dialed() {
		if strings.HasPrefix(a, "198.51.100.9:") {
			t.Fatalf("dialed public address %s", a)
		}
	}
}

func TestLabEndpointDoesNotFollowRedirect(t *testing.T) {
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://203.0.113.7/v1/chat/completions", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)
	d := &dialLog{target: redir.Listener.Addr().String()}
	o := labOpts(redir, redir.URL+"/v1", Network{Dial: d.dial})
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Chat(context.Background(), Request{MaxTokens: 1}); !errors.Is(err, ErrCall) {
		t.Fatalf("redirect = %v, want ErrCall", err)
	}
	for _, a := range d.dialed() {
		if !strings.HasPrefix(a, "127.0.0.1:") {
			t.Errorf("redirect followed to %s", a)
		}
	}
}

func TestLabEndpointIgnoresProxyVariables(t *testing.T) {
	proxy, hits := proxyListener(t)
	setProxyEnv(t, proxy)
	srv := httptest.NewTLSServer(http.HandlerFunc(okHandler))
	t.Cleanup(srv.Close)
	c, err := New(labOpts(srv, srv.URL+"/v1", Network{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Chat(context.Background(), Request{MaxTokens: 1}); err != nil {
		t.Fatalf("chat: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("proxy saw %d connections", hits.Load())
	}
	if c.http.Transport.(*http.Transport).Proxy != nil {
		t.Error("transport has a proxy function")
	}
}

func TestLabEndpointAcceptsLabAddress(t *testing.T) {
	chatOK := func(t *testing.T, c *Client) {
		t.Helper()
		resp, err := c.Chat(context.Background(), Request{MaxTokens: 1})
		if err != nil || resp.Content != "ok" {
			t.Fatalf("chat = %+v, %v", resp, err)
		}
	}

	t.Run("loopback", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(okHandler))
		t.Cleanup(srv.Close)
		o := labOpts(srv, srv.URL+"/v1", Network{})
		if err := CheckEndpoint(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		c, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		chatOK(t, c)
	})

	t.Run("unix socket", func(t *testing.T) {
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
		srv := httptest.NewUnstartedServer(http.HandlerFunc(okHandler))
		_ = srv.Listener.Close()
		srv.Listener = l
		srv.StartTLS()
		t.Cleanup(srv.Close)
		// The host only names the certificate; the socket is what is dialed.
		o := labOpts(srv, "https://example.com/v1", Network{Resolve: func(context.Context, string) ([]netip.Addr, error) {
			t.Error("resolver used with a Unix socket")
			return nil, errors.New("no")
		}})
		o.UnixSocket = sock
		if err := CheckEndpoint(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		c, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		chatOK(t, c)
	})

	for name, addr := range map[string]string{
		"rfc1918 via injected dialer": "10.20.30.40",
		"ipv4-mapped rfc1918":         "::ffff:10.20.30.40",
		"ula":                         "fd00::5",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(okHandler))
			t.Cleanup(srv.Close)
			d := &dialLog{target: srv.Listener.Addr().String()}
			o := labOpts(srv, "https://example.com:8443/v1", Network{Resolve: resolveTo(addr), Dial: d.dial})
			if err := CheckEndpoint(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			c, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			chatOK(t, c)
			want := netip.AddrPortFrom(netip.MustParseAddr(addr).Unmap(), 8443).String()
			got := d.dialed()
			if len(got) == 0 {
				t.Fatal("no connection through the injected dialer")
			}
			for _, a := range got {
				if a != want {
					t.Errorf("dialed %s, want %s", a, want)
				}
			}
		})
	}

	t.Run("allowed overlay network", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(okHandler))
		t.Cleanup(srv.Close)
		d := &dialLog{target: srv.Listener.Addr().String()}
		nets, err := ParseNetworks([]string{"100.64.0.0/16"})
		if err != nil {
			t.Fatal(err)
		}
		o := labOpts(srv, "https://example.com/v1", Network{Resolve: resolveTo("100.64.3.4"), Dial: d.dial})
		o.LabNetworks = nets
		c, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		chatOK(t, c)
	})
}

func TestPlainHTTPNeedsPermissionAndNoCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(okHandler))
	t.Cleanup(srv.Close)
	key := writeKeyFile(t, testKey)
	if _, err := New(Options{BaseURL: srv.URL + "/v1", Model: "m", Timeout: time.Second}); !errors.Is(err, ErrConfig) {
		t.Errorf("plain http without permission = %v", err)
	}
	if _, err := New(Options{BaseURL: srv.URL + "/v1", Model: "m", Timeout: time.Second, CredentialFile: key, AllowPlainHTTP: true}); !errors.Is(err, ErrConfig) {
		t.Errorf("plain http with credential = %v", err)
	}
	c, err := New(Options{BaseURL: srv.URL + "/v1", Model: "m", Timeout: 5 * time.Second, AllowPlainHTTP: true, LabOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := c.Chat(context.Background(), Request{MaxTokens: 1}); err != nil || resp.Content != "ok" {
		t.Fatalf("plain http accepted: %+v %v", resp, err)
	}
}

func TestUnixSocketNeedsLabOnly(t *testing.T) {
	_, err := New(Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, UnixSocket: "/tmp/s"})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("unix socket without lab-only = %v", err)
	}
}
