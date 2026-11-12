// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// LLM egress (ADR 0011 A1.4 trust rule, A1.5): every connection to the
// LLM endpoint goes to a lab address. The check runs in the dialer on the
// address actually connected to, for every connection.
const (
	// MaxAllowedNetworks bounds llm.allowed_networks.
	MaxAllowedNetworks = 32
	// maxResolvedAddrs bounds the addresses one host name may resolve to.
	maxResolvedAddrs = 16
	// llmDialTimeout bounds one connection attempt.
	llmDialTimeout = 15 * time.Second
)

// ErrNotLabAddress: the LLM endpoint is (or resolves to) an address
// outside the lab ranges; no connection was made.
var ErrNotLabAddress = errors.New("vulnagent/run: llm endpoint is not a lab address")

var (
	// labRanges are always permitted: loopback, RFC 1918, IPv6 ULA.
	labRanges = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	}
	// overlayRange may be named in llm.allowed_networks only.
	overlayRange = netip.MustParsePrefix("100.64.0.0/10")
	// nat64Ranges are always refused: a translator forwards them to
	// arbitrary IPv4 hosts.
	nat64Ranges = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
	}
)

// ParseAllowedNetworks parses llm.allowed_networks. Each entry must be a
// subnet of loopback, RFC 1918, IPv6 ULA or 100.64.0.0/10; anything else,
// including NAT64 prefixes and IPv4-mapped forms, is refused.
func ParseAllowedNetworks(ss []string) ([]netip.Prefix, error) {
	if len(ss) > MaxAllowedNetworks {
		return nil, fmt.Errorf("llm allowed networks: more than %d entries: %w", MaxAllowedNetworks, ErrConfig)
	}
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return nil, fmt.Errorf("llm allowed networks: %q is not a CIDR prefix: %w", cleanText(s, 64), ErrConfig)
		}
		p = p.Masked()
		if !permittedSubnet(p) {
			return nil, fmt.Errorf("llm allowed networks: %s is outside loopback, RFC 1918, ULA and 100.64.0.0/10: %w", p, ErrConfig)
		}
		out = append(out, p)
	}
	return out, nil
}

func permittedSubnet(p netip.Prefix) bool {
	for _, n := range nat64Ranges {
		if n.Overlaps(p) {
			return false
		}
	}
	for _, base := range append(labRanges[:len(labRanges):len(labRanges)], overlayRange) {
		if base.Bits() <= p.Bits() && base.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// labAddress reports whether a may be connected to: an IPv4-mapped IPv6
// address is judged as its IPv4 address, NAT64 is always refused.
func labAddress(a netip.Addr, allowed []netip.Prefix) bool {
	a = a.WithZone("").Unmap()
	if !a.IsValid() {
		return false
	}
	for _, n := range nat64Ranges {
		if n.Contains(a) {
			return false
		}
	}
	for _, p := range labRanges {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// LLMNetwork overrides how the LLM endpoint is reached. The zero value
// uses the system resolver, a plain TCP dialer and the system roots;
// tests inject fakes. The lab-address check applies in every case.
type LLMNetwork struct {
	// Resolve maps a host name to addresses; nil uses net.DefaultResolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Dial connects to an already checked address; nil uses net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs verifies the endpoint's TLS certificate; nil uses the
	// system roots.
	RootCAs *x509.CertPool
}

// labDialer dials only lab addresses, or the configured Unix socket.
type labDialer struct {
	allowed []netip.Prefix
	socket  string
	net     LLMNetwork
}

func (d *labDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.socket != "" {
		return d.rawDial(ctx, "unix", d.socket)
	}
	addrs, port, err := d.resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	var last error
	for _, a := range addrs {
		c, err := d.rawDial(ctx, network, netip.AddrPortFrom(a, port).String())
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, fmt.Errorf("llm endpoint: connect: %w", last)
}

// resolve returns the addresses of addr's host, all of them lab
// addresses, or ErrNotLabAddress if any is not.
func (d *labDialer) resolve(ctx context.Context, addr string) ([]netip.Addr, uint16, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, fmt.Errorf("llm endpoint: address: %w", err)
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil || p == 0 {
		return nil, 0, fmt.Errorf("llm endpoint: port %q invalid", cleanText(ps, 16))
	}
	port := uint16(p)
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		res := d.net.Resolve
		if res == nil {
			res = func(ctx context.Context, h string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
			}
		}
		addrs, err = res(ctx, host)
		if err != nil {
			return nil, 0, fmt.Errorf("llm endpoint: resolve: %w", err)
		}
		if len(addrs) == 0 || len(addrs) > maxResolvedAddrs {
			return nil, 0, fmt.Errorf("llm endpoint: resolve: %d addresses", len(addrs))
		}
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !labAddress(a, d.allowed) {
			return nil, 0, ErrNotLabAddress
		}
		out = append(out, a.WithZone("").Unmap())
	}
	return out, port, nil
}

func (d *labDialer) rawDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.net.Dial != nil {
		return d.net.Dial(ctx, network, addr)
	}
	nd := net.Dialer{Timeout: llmDialTimeout}
	return nd.DialContext(ctx, network, addr)
}

// checkEndpoint resolves the effective endpoint once before the assessor
// starts and refuses it unless every address is a lab address (or the
// Unix socket is configured). The dialer repeats the check on every
// connection, so a later DNS change is refused too.
func (r *Runner) checkEndpoint(ctx context.Context, eff LLMConfig) error {
	if r.llmDial.socket != "" {
		return nil
	}
	u, err := url.Parse(eff.BaseURL)
	if err != nil {
		return errors.New("llm base url: does not parse")
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	_, _, err = r.llmDial.resolve(ctx, net.JoinHostPort(u.Hostname(), port))
	return err
}

// llmTransport is the only transport the LLM client gets: no proxy, the
// lab dialer, verified TLS.
func llmTransport(d *labDialer) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.net.RootCAs},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}
